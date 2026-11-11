"""Content-based file type detection (magic bytes). The client's extension and Content-Type are untrusted.

A small built-in signature table is used instead of libmagic so the tool installs the same way on
Windows and Linux. Limitation: formats outside this table are reported as 'unknown'.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

from .models import f

EXT_FORMATS = {
    "pdf": {"pdf"}, "docx": {"docx"}, "docm": {"docx"}, "xlsx": {"xlsx"}, "xlsm": {"xlsx"},
    "pptx": {"pptx"}, "pptm": {"pptx"}, "zip": {"zip"}, "png": {"png"}, "jpg": {"jpeg"}, "jpeg": {"jpeg"},
    "gif": {"gif"}, "txt": {"text"}, "csv": {"text"}, "log": {"text"}, "md": {"text"}, "json": {"text"},
    "exe": {"pe"}, "dll": {"pe"}, "scr": {"pe"}, "doc": {"ole"}, "xls": {"ole"}, "ppt": {"ole"}, "msi": {"ole"},
    "gz": {"gzip"}, "7z": {"7z"}, "rar": {"rar"}, "jar": {"zip"}, "apk": {"zip"},
}
MIME = {
    "pdf": "application/pdf", "zip": "application/zip", "png": "image/png", "jpeg": "image/jpeg",
    "gif": "image/gif", "text": "text/plain", "pe": "application/vnd.microsoft.portable-executable",
    "elf": "application/x-elf", "macho": "application/x-mach-binary", "ole": "application/x-ole-storage",
    "gzip": "application/gzip", "7z": "application/x-7z-compressed", "rar": "application/vnd.rar",
    "script": "text/x-script",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "empty": "application/x-empty", "unknown": "application/octet-stream",
}
EXECUTABLE_FORMATS = {"pe", "elf", "macho", "script"}


def detect_format(path: Path) -> str:
    size = path.stat().st_size
    if size == 0:
        return "empty"
    with path.open("rb") as fh:
        head = fh.read(4096)
    if b"%PDF-" in head[:1024]:
        return "pdf"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return _zip_subtype(path)
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "macho"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"#!"):
        return "script"
    if b"\x00" not in head:
        try:
            head.decode("utf-8")
            return "text"
        except UnicodeDecodeError:
            # may have cut a multi-byte char at the 4096 boundary
            try:
                head[:-3].decode("utf-8")
                return "text"
            except UnicodeDecodeError:
                pass
    return "unknown"


def _zip_subtype(path: Path) -> str:
    try:
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist()[:5000])
    except (zipfile.BadZipFile, OSError, ValueError):
        return "zip"
    if "[Content_Types].xml" in names:
        if any(n.startswith("word/") for n in names):
            return "docx"
        if any(n.startswith("xl/") for n in names):
            return "xlsx"
        if any(n.startswith("ppt/") for n in names):
            return "pptx"
    return "zip"


def describe(path: Path, original_name: str) -> tuple[dict, list[dict]]:
    """Return (type info, findings) for a stored upload."""
    fmt = detect_format(path)
    ext = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else ""
    info = {"format": fmt, "mime": MIME.get(fmt, MIME["unknown"]), "claimed_extension": ext,
            "extension_matches_content": None}
    findings: list[dict] = []
    expected = EXT_FORMATS.get(ext)
    if expected is not None and fmt != "empty":
        ok = fmt in expected
        info["extension_matches_content"] = ok
        if not ok:
            sev = "HIGH" if fmt in EXECUTABLE_FORMATS else "MEDIUM"
            findings.append(f("FILE_TYPE_MISMATCH", sev, "File extension does not match content",
                              f"The name ends in .{ext} but the content is detected as '{fmt}'. "
                              "A mismatched extension can be used to disguise a file.",
                              "FILE_VALIDATION", "HIGH", claimed_extension=ext, detected_format=fmt,
                              detected_mime=info["mime"]))
    if fmt in EXECUTABLE_FORMATS:
        findings.append(f("EXECUTABLE_CONTENT", "MEDIUM", "File is an executable or script",
                          "Executable content can run code when opened. ThreatLens does not execute it; "
                          "only signature scanning is applied to this format.",
                          "FILE_VALIDATION", "HIGH", detected_format=fmt))
    parts = original_name.lower().split(".")
    if len(parts) >= 3 and parts[-1] in {"exe", "scr", "bat", "cmd", "js", "vbs", "ps1", "lnk", "com", "pif", "hta", "jar", "msi"} \
            and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "zip"}:
        findings.append(f("DOUBLE_EXTENSION", "HIGH", "Double extension in file name",
                          "The name imitates a document but ends with an executable extension.",
                          "FILE_VALIDATION", "HIGH", filename=original_name))
    return info, findings
