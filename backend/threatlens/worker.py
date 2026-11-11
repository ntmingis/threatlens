"""Isolated analysis worker: `python -m threatlens.worker <stored_path> <original_name>`.

Runs in its own process with CPU/memory limits (POSIX) so that a parser crash or resource bomb in a hostile
file cannot take down the API. It performs NO network access and never executes the uploaded file.
Prints one JSON object on stdout.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from .analyzers import archive, clamav, office
from .config import get_settings
from .filetype import describe
from .models import EngineResult, EngineStatus
from .urlscan.impersonation import load_brands
from .urlscan.parse import UrlError, analyze_url


def _limits(cfg) -> None:
    try:
        import resource
    except ImportError:  # Windows: no rlimits; the parent still enforces a wall-clock timeout
        return
    mem = cfg.worker_memory_mb * 1024 * 1024
    for res_id, val in ((resource.RLIMIT_CPU, cfg.scan_timeout_s), (resource.RLIMIT_CORE, 0)):
        try:
            resource.setrlimit(res_id, (val, val))
        except (ValueError, OSError):
            pass
    return mem  # RLIMIT_AS is applied after ClamAV (see run): clamscan maps a large signature DB


def run(path: Path, original_name: str, apply_limits: bool = False) -> dict:
    cfg = get_settings()
    mem = _limits(cfg) if apply_limits else None
    brands = load_brands(cfg.brands_file)
    info, findings = describe(path, original_name)
    engines: list[dict] = []
    skipped: list[str] = []
    analysis: dict = {}
    indicators = {"urls": [], "emails": [], "domains": [], "phones": []}
    fmt = info["format"]

    def add(res: EngineResult, **extra) -> None:
        engines.append({**res.model_dump(mode="json"), **extra})

    if fmt == "empty":
        add(EngineResult(name="Content checks", status=EngineStatus.SKIPPED, required=True,
                         detail="The file is empty; there was nothing to analyse."))
        skipped.append("all content checks (empty file)")
        return {"file": info, "findings": findings, "engines": engines, "skipped": skipped,
                "analysis": analysis, "indicators": indicators, "empty": True}

    av, av_f = clamav.scan(path, cfg)
    add(av)
    findings += av_f
    if mem:
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
        except (ImportError, ValueError, OSError):
            pass

    if fmt == "pdf":
        from .analyzers import pdf
        r, fs, sk, pinfo, ind = pdf.analyze(path, cfg, brands)
        add(r)
        findings += fs
        skipped += sk
        analysis["pdf"] = pinfo
        indicators = ind
    elif fmt in ("docx", "xlsx", "pptx"):
        r, fs, sk, links = office.analyze(path, fmt, cfg)
        add(r)
        findings += fs
        skipped += sk
        for ln in links[:500]:
            try:
                p, uf = analyze_url(ln["url"], brands, {"document_part": ln["part"], "found_as": "hyperlink relationship"})
            except UrlError:
                continue
            indicators["urls"].append({"url": p["normalized"], "found_as": "hyperlink relationship", "part": ln["part"]})
            if p["host"] not in indicators["domains"]:
                indicators["domains"].append(p["host"])
            findings += uf
    elif fmt == "zip":
        r, fs, sk = archive.analyze(path, cfg)
        add(r)
        findings += fs
        skipped += sk
    elif fmt == "ole":
        add(EngineResult(name="Office document analysis", status=EngineStatus.SKIPPED, required=True,
                         detail="Legacy OLE formats (.doc/.xls/.ppt/.msi) are not parsed in this version; "
                                "macros and embedded objects were NOT inspected."))
        skipped.append("legacy Office structure (macros, embedded objects)")
    elif fmt in ("gzip", "7z", "rar"):
        add(EngineResult(name="Archive analysis", status=EngineStatus.SKIPPED, required=True,
                         detail=f"'{fmt}' archives are not unpacked by ThreatLens; only the antivirus engine examined the file."))
        skipped.append(f"{fmt} archive contents (structure not inspected)")
    else:
        add(EngineResult(name="Format-specific analysis", status=EngineStatus.SKIPPED,
                         detail=f"No structural analyzer exists for '{fmt}'; only file validation and antivirus apply."))
    return {"file": info, "findings": findings, "engines": engines, "skipped": skipped,
            "analysis": analysis, "indicators": indicators}


if __name__ == "__main__":
    try:
        out = run(Path(sys.argv[1]), sys.argv[2], apply_limits=True)
    except MemoryError:
        out = {"worker_error": "memory limit exceeded"}
    except Exception as e:  # noqa: BLE001 - report type only; never leak file content or paths
        out = {"worker_error": type(e).__name__}
    sys.stdout.write(json.dumps(out))
