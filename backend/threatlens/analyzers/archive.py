"""ZIP inspection without extracting anything to disk (so path traversal cannot write files)."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

from ..config import Settings
from ..models import EngineResult, EngineStatus, f

SRC = "ARCHIVE_ANALYZER"
EXEC_EXT = {"exe", "dll", "scr", "com", "pif", "msi", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta",
            "lnk", "jar", "sh", "elf", "apk", "iso", "img", "reg", "cpl"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "txt", "zip"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "bz2", "xz", "cab", "iso"}


def analyze(path: Path, cfg: Settings) -> tuple[EngineResult, list[dict], list[str]]:
    res = EngineResult(name="Archive analysis", status=EngineStatus.COMPLETED, required=True)
    findings: list[dict] = []
    skipped: list[str] = []
    state = {"entries": 0, "bytes": 0}
    try:
        with zipfile.ZipFile(path) as z:
            _walk(z, "", 0, cfg, findings, skipped, state)
    except zipfile.BadZipFile:
        res.status, res.detail = EngineStatus.ERROR, "Archive is malformed and could not be read."
        return res, findings, ["whole archive (malformed)"]
    except (OSError, RuntimeError, ValueError, NotImplementedError) as e:
        res.status, res.detail = EngineStatus.ERROR, f"Archive could not be inspected: {type(e).__name__}"
        return res, findings, ["whole archive"]
    if skipped:
        res.status = EngineStatus.PARTIAL
        res.detail = f"{len(skipped)} component(s) were not inspected because a safety limit was reached."
    else:
        res.detail = f"Inspected {state['entries']} entries without extraction."
    return res, findings, skipped


def _walk(z: zipfile.ZipFile, prefix: str, depth: int, cfg: Settings, findings, skipped, state) -> None:
    infos = z.infolist()
    for zi in infos:
        full = f"{prefix}{zi.filename}"
        state["entries"] += 1
        if state["entries"] > cfg.archive_max_entries:
            skipped.append(f"entries after #{cfg.archive_max_entries} (entry-count limit)")
            findings.append(f("ARCHIVE_LIMIT", "MEDIUM", "Archive has more entries than the inspection limit",
                              "Very large entry counts are used by archive bombs. Remaining entries were not inspected.",
                              SRC, "MEDIUM", limit=cfg.archive_max_entries, archive=prefix or "(top level)"))
            return
        if zi.is_dir():
            continue
        name = zi.filename.replace("\\", "/")
        if name.startswith("/") or ".." in name.split("/") or (len(name) > 1 and name[1] == ":"):
            findings.append(f("ARCHIVE_PATH_TRAVERSAL", "HIGH", "Entry name tries to escape the extraction folder",
                              "Extracting this archive with a vulnerable tool could overwrite files elsewhere.",
                              SRC, "HIGH", entry=full))
        parts = name.rsplit("/", 1)[-1].lower().split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        if ext in EXEC_EXT:
            dbl = len(parts) >= 3 and parts[-2] in DOC_EXT
            findings.append(f("ARCHIVE_EXECUTABLE", "HIGH" if dbl else "MEDIUM",
                              "Archive contains an executable with a document-like double extension" if dbl
                              else "Archive contains an executable or script file",
                              "Executables delivered inside archives are a common malware delivery method. "
                              "Presence alone does not prove the file is malicious.", SRC, "HIGH", entry=full, extension=ext))
        if zi.flag_bits & 0x1:
            skipped.append(f"{full} (password-protected entry)")
            findings.append(f("ARCHIVE_ENCRYPTED", "MEDIUM", "Archive entry is password-protected",
                              "Encrypted entries cannot be inspected or signature-scanned.", SRC, "HIGH", entry=full))
            continue
        ratio = zi.file_size / max(zi.compress_size, 1)
        if zi.file_size > 1024 * 1024 and ratio > cfg.archive_max_ratio:
            findings.append(f("ARCHIVE_BOMB", "HIGH", "Extremely high compression ratio",
                              "The entry expands far beyond its compressed size, as in decompression bombs.",
                              SRC, "MEDIUM", entry=full, compressed=zi.compress_size, uncompressed=zi.file_size,
                              ratio=round(ratio, 1), limit=cfg.archive_max_ratio))
        state["bytes"] += zi.file_size
        if state["bytes"] > cfg.archive_max_total_bytes:
            skipped.append(f"{full} and later entries (total-size limit)")
            return
        if ext in ARCHIVE_EXT:
            if ext != "zip":
                skipped.append(f"{full} (nested {ext} archive: format not supported)")
            elif depth + 1 > cfg.archive_max_depth:
                skipped.append(f"{full} (nesting deeper than {cfg.archive_max_depth})")
                findings.append(f("ARCHIVE_NESTING", "MEDIUM", "Archive nesting exceeds the inspection depth",
                                  "Deep nesting is used to hide content from scanners.", SRC, "MEDIUM",
                                  entry=full, max_depth=cfg.archive_max_depth))
            elif zi.file_size > 50 * 1024 * 1024 or ratio > cfg.archive_max_ratio:
                skipped.append(f"{full} (nested archive too large or too compressed to open safely)")
            else:
                try:
                    with z.open(zi) as fh:
                        data = fh.read(50 * 1024 * 1024 + 1)
                    with zipfile.ZipFile(io.BytesIO(data)) as inner:
                        _walk(inner, full + "!/", depth + 1, cfg, findings, skipped, state)
                except (zipfile.BadZipFile, OSError, RuntimeError, ValueError, NotImplementedError):
                    skipped.append(f"{full} (nested archive could not be read)")
