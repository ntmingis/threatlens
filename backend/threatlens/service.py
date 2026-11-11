"""Orchestration: store upload -> isolated worker -> hash reputation -> verdict -> report."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import Settings
from .db import Store
from .intel.base import build_providers
from .models import EngineResult, EngineStatus
from .risk import assess
from .urlscan.impersonation import load_brands
from .urlscan.parse import analyze_url
from .urlscan.ssrf import SsrfBlocked, resolve_and_check


class UploadTooLarge(Exception):
    pass


def safe_display_name(name: str | None) -> str:
    """The client's filename is display-only; it is never used as a path."""
    n = (name or "unnamed").replace("\\", "/").rsplit("/", 1)[-1]
    n = re.sub(r"[\x00-\x1f\x7f]", "", n).strip() or "unnamed"
    return n[:200]


def store_upload(stream, cfg: Settings) -> tuple[Path, str, int]:
    """Stream to quarantine under a random name while hashing. Enforces the size limit during the copy."""
    q = cfg.quarantine_dir
    q.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(q, 0o700)
    except OSError:
        pass
    path = q / (uuid.uuid4().hex + ".upload")
    h, size = hashlib.sha256(), 0
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # no execute bit, owner only
    try:
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > cfg.max_upload_bytes:
                    raise UploadTooLarge()
                h.update(chunk)
                out.write(chunk)
    except BaseException:
        remove_quietly(path)
        raise
    return path, h.hexdigest(), size


def remove_quietly(path: Path) -> None:
    try:
        Path(path).unlink(missing_ok=True)
    except OSError:
        pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _cache(store: Store, cfg: Settings):
    return (store.cache_get, lambda k, v: store.cache_put(k, v, cfg.intel_cache_ttl_s))


def run_worker(path: Path, name: str, cfg: Settings) -> dict:
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])}
    try:
        proc = subprocess.run([sys.executable, "-m", "threatlens.worker", str(path), name],
                              capture_output=True, timeout=cfg.scan_timeout_s, env=env,
                              cwd=str(Path(__file__).resolve().parents[1]))
    except subprocess.TimeoutExpired:
        return {"worker_error": f"analysis exceeded {cfg.scan_timeout_s}s"}
    try:
        return json.loads(proc.stdout.decode("utf-8", "replace"))
    except ValueError:
        return {"worker_error": f"worker ended abnormally (exit {proc.returncode})"}


def scan_file_job(job_id: str, path: Path, name: str, sha256: str, size: int, cfg: Settings, store: Store,
                  transport=None) -> None:
    store.job_update(job_id, "RUNNING")
    t0 = time.time()
    try:
        prev = store.previous_by_hash(sha256)
        w = run_worker(path, name, cfg)
        findings = w.get("findings", [])
        engines = w.get("engines", [])
        skipped = w.get("skipped", [])
        if "worker_error" in w:
            engines.append(EngineResult(name="Analysis worker", status=EngineStatus.ERROR, required=True,
                                        detail=f"The isolated worker failed: {w['worker_error']}. No analysis result is available.").model_dump(mode="json"))
            skipped.append("all file analysis (worker failure)")
        for p in build_providers(cfg, transport, _cache(store, cfg)):
            r, fs = p.lookup_hash(sha256)  # hash only: file content never leaves this machine
            if r.status != EngineStatus.SKIPPED:
                engines.append({**r.model_dump(mode="json"), "group": "intel"})
                findings += fs
        rep = {"report_id": uuid.uuid4().hex, "kind": "file", "created_at": _now(), "tool_version": __version__,
               "target": {"filename": name, "size_bytes": size, "sha256": sha256, **w.get("file", {})},
               "previous_reports_same_hash": prev, "analysis": w.get("analysis", {}),
               "indicators": w.get("indicators", {}), "findings": findings, "engines": engines,
               "items_skipped": skipped, "duration_ms": int((time.time() - t0) * 1000),
               "retention": "The uploaded file was deleted from the server when this scan finished."}
        rep.update(assess(findings, engines, "file"))
        store.report_save(rep)
        store.job_update(job_id, "COMPLETED", rep["report_id"])
    except Exception as e:  # noqa: BLE001
        store.job_update(job_id, "FAILED", error=f"Internal error ({type(e).__name__})")
    finally:
        remove_quietly(path)  # retention policy: never keep the original after the scan


def scan_url(url: str, cfg: Settings, store: Store, transport=None, resolver=None) -> dict:
    """Raises UrlError for invalid input. Performs no request to the submitted URL."""
    brands = load_brands(cfg.brands_file)
    p, findings = analyze_url(url, brands)
    engines = [EngineResult(name="Static URL analysis", status=EngineStatus.COMPLETED, required=True,
                            detail="Structure, hostname and brand-similarity checks.").model_dump(mode="json")]
    resolution = None
    if cfg.resolve_dns and not p["ip"]:
        try:
            ips = resolve_and_check(p["normalized"], resolver) if resolver else resolve_and_check(p["normalized"])
            resolution = {"ips": ips, "public": True}
        except SsrfBlocked as e:
            resolution = {"error": str(e), "public": False}
        engines.append(EngineResult(name="DNS resolution", status=EngineStatus.COMPLETED, detail=json.dumps(resolution)).model_dump(mode="json"))
    else:
        engines.append(EngineResult(name="DNS resolution", status=EngineStatus.SKIPPED,
                                    detail="Disabled (THREATLENS_RESOLVE_DNS=false) or host is an IP literal.").model_dump(mode="json"))
    engines.append(EngineResult(name="Redirect / content fetch", status=EngineStatus.SKIPPED,
                                detail="Not implemented: ThreatLens does not connect to submitted URLs.").model_dump(mode="json"))
    for prov in build_providers(cfg, transport, _cache(store, cfg)):
        r, fs = prov.lookup_url(p["normalized"])
        engines.append({**r.model_dump(mode="json"), "group": "intel"})
        findings += fs
    rep = {"report_id": uuid.uuid4().hex, "kind": "url", "created_at": _now(), "tool_version": __version__,
           "target": {"submitted_url": p["submitted"][:2000], "normalized_url": p["normalized"], "scheme": p["scheme"],
                      "host": p["host"], "host_unicode": p["host_unicode"], "registrable_domain": p["registrable_domain"],
                      "port": p["port"], "path": p["path"], "query": p["query"], "https": p["scheme"] == "https",
                      "ip_literal": p["ip"], "dns": resolution},
           "findings": findings, "engines": engines,
           "items_skipped": ["page content", "redirect chain", "TLS certificate"]}
    rep.update(assess(findings, engines, "url"))
    store.report_save(rep)
    return rep
