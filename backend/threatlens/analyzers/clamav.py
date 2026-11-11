"""ClamAV adapter. Results are never simulated: if the engine or its database is missing, say so."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from ..config import Settings
from ..models import EngineResult, EngineStatus, f

SRC = "CLAMAV"
DEFAULT_DB_DIRS = ["/var/lib/clamav", "/usr/local/share/clamav", "/opt/homebrew/var/lib/clamav",
                   r"C:\Program Files\ClamAV\database", r"C:\ProgramData\ClamAV\db"]
DB_SUFFIXES = (".cvd", ".cld", ".hdb", ".hsb", ".ndb", ".ldb", ".cud", ".yar", ".yara")


def _db_dir(cfg: Settings) -> Path | None:
    cands = [cfg.clamav_db_dir] if cfg.clamav_db_dir else DEFAULT_DB_DIRS
    for d in cands:
        p = Path(d)
        if p.is_dir() and any(x.suffix.lower() in DB_SUFFIXES for x in p.iterdir()):
            return p
    return None


def _version(binary: str, db: Path | None) -> str | None:
    try:
        cmd = [binary, "--version"] + ([f"--database={db}"] if db and "clamdscan" not in binary else [])
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout.strip()
        return out or None  # e.g. "ClamAV 1.4.3/27820/Tue Nov 10 2026" = engine/db version/db date
    except (OSError, subprocess.SubprocessError):
        return None


def scan(path: Path, cfg: Settings) -> tuple[EngineResult, list[dict]]:
    name = "clamdscan" if cfg.clamav_mode == "clamdscan" else "clamscan"
    binary = shutil.which(name)
    res = EngineResult(name="ClamAV", status=EngineStatus.NOT_INSTALLED, required=True,
                       detail=f"'{name}' was not found on PATH. No antivirus scan was performed.")
    if not binary:
        return res, []
    db = None
    if name == "clamscan":
        db = _db_dir(cfg)
        if db is None:
            res.status = EngineStatus.DB_MISSING
            res.detail = "ClamAV is installed but no signature database was found (run freshclam). No scan was performed."
            res.version = _version(binary, None)
            return res, []
        cmd = [binary, "--no-summary", "--stdout", f"--database={db}", "--alert-exceeds-max=yes",
               f"--max-filesize={cfg.max_upload_bytes // (1024 * 1024) + 1}M",
               f"--max-scansize={cfg.archive_max_total_bytes // (1024 * 1024)}M",
               f"--max-files={cfg.archive_max_entries}", f"--max-recursion={cfg.archive_max_depth + 4}", str(path)]
    else:
        cmd = [binary, "--no-summary", "--stdout", "--fdpass", str(path)]
    res.version = _version(binary, db)
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=cfg.clamav_timeout_s,
                              env={**os.environ, "LC_ALL": "C"})
    except subprocess.TimeoutExpired:
        res.status, res.detail = EngineStatus.TIMEOUT, f"ClamAV did not finish within {cfg.clamav_timeout_s}s."
        res.duration_ms = int((time.time() - t0) * 1000)
        return res, []
    except OSError as e:
        res.status, res.detail = EngineStatus.ERROR, f"ClamAV could not be started: {type(e).__name__}"
        return res, []
    res.duration_ms = int((time.time() - t0) * 1000)
    sigs = re.findall(r":\s(.+?)\sFOUND\s*$", proc.stdout, flags=re.M)
    limit_hits = [s for s in sigs if s.startswith("Heuristics.Limits.Exceeded")]
    real = [s for s in sigs if s not in limit_hits]
    if proc.returncode == 1 and real:
        res.status, res.detail = EngineStatus.COMPLETED, f"Signature match: {', '.join(real)}"
        return res, [f("MALWARE_SIGNATURE", "CRITICAL", f"ClamAV signature match: {s}",
                       "The file matches a known-malware signature in the ClamAV database.", SRC, "HIGH",
                       signature=s, engine_version=res.version) for s in real]
    if limit_hits:
        res.status = EngineStatus.PARTIAL
        res.detail = f"Scan limits were exceeded ({', '.join(limit_hits)}); part of the file was NOT scanned."
        return res, []
    if proc.returncode == 0:
        res.status, res.detail = EngineStatus.COMPLETED, "No detection in completed scan."
        return res, []
    res.status = EngineStatus.ERROR
    res.detail = "ClamAV reported an error; the file was not scanned. " + (proc.stderr or proc.stdout).strip()[-300:]
    return res, []
