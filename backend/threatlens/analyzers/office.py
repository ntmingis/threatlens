"""OOXML (docx/xlsx/pptx) static inspection. Macros are reported by PRESENCE only.

Three different states are kept apart on purpose:
  macro present      -> reported here (OFFICE_MACRO_PRESENT)
  macro suspicious   -> NOT assessed in v0.1 (needs VBA decompression, e.g. oletools)
  macro malicious    -> only ever asserted by an antivirus signature (ClamAV)
XML is searched with bounded regexes rather than an XML parser, so entity-expansion attacks do not apply.
"""
from __future__ import annotations

import re
import zipfile
from pathlib import Path

from ..config import Settings
from ..models import EngineResult, EngineStatus, f

SRC = "OFFICE_ANALYZER"
MAX_PART = 5 * 1024 * 1024
REL_RE = re.compile(rb"<Relationship\b[^>]{0,4000}>")
ATTR_RE = lambda n: re.compile(rb'\b' + n + rb'="([^"]{0,3000})"')  # noqa: E731
RISKY_REL = ("attachedTemplate", "oleObject", "frame", "subDocument", "externalLink", "package")


def analyze(path: Path, fmt: str, cfg: Settings) -> tuple[EngineResult, list[dict], list[str], list[dict]]:
    """Return (engine result, findings, skipped, links[{url, part}])."""
    res = EngineResult(name="Office document analysis", status=EngineStatus.COMPLETED, required=True)
    findings, skipped, links = [], [], []
    try:
        with zipfile.ZipFile(path) as z:
            infos = z.infolist()
            if len(infos) > cfg.archive_max_entries:
                skipped.append("document parts beyond the entry-count limit")
                infos = infos[: cfg.archive_max_entries]
            names = [i.filename for i in infos]
            vba = [n for n in names if n.lower().endswith("vbaproject.bin")]
            if vba:
                findings.append(f("OFFICE_MACRO_PRESENT", "MEDIUM", "Document contains a VBA macro project",
                                  "Macros can run code when enabled. ThreatLens reports presence only; it has not "
                                  "analysed what the macro does, so this is not evidence that it is malicious.",
                                  SRC, "HIGH", parts=vba, macro_content_analysed=False))
            emb = [n for n in names if "/embeddings/" in n.lower() or n.lower().endswith((".bin", ".exe", ".dll", ".scr", ".js", ".vbs", ".ps1", ".lnk"))
                   and not n.lower().endswith("vbaproject.bin") and "printersettings" not in n.lower()]
            if emb:
                findings.append(f("OFFICE_EMBEDDED_OBJECT", "MEDIUM", "Document contains embedded objects",
                                  "Embedded objects can carry other files, including executables. They were not opened.",
                                  SRC, "MEDIUM", parts=emb[:20], count=len(emb)))
            for zi in infos:
                if not zi.filename.endswith(".rels"):
                    continue
                if zi.file_size > MAX_PART:
                    skipped.append(f"{zi.filename} (relationship part larger than {MAX_PART} bytes)")
                    continue
                with z.open(zi) as fh:
                    data = fh.read(MAX_PART)
                for rel in REL_RE.findall(data):
                    if b'TargetMode="External"' not in rel:
                        continue
                    t = ATTR_RE(rb"Target").search(rel)
                    ty = ATTR_RE(rb"Type").search(rel)
                    target = t.group(1).decode("utf-8", "replace").replace("&amp;", "&") if t else ""
                    rtype = ty.group(1).decode("utf-8", "replace").rsplit("/", 1)[-1] if ty else ""
                    if rtype == "hyperlink":
                        links.append({"url": target, "part": zi.filename})
                    elif rtype in RISKY_REL or target.lower().startswith(("http", "file:", "\\\\", "smb:")):
                        sev = "HIGH" if rtype in ("attachedTemplate", "oleObject", "frame", "subDocument") else "MEDIUM"
                        findings.append(f("OFFICE_EXTERNAL_REFERENCE", sev,
                                          f"Document loads external content ({rtype or 'unknown type'})",
                                          "Opening the document can make Office fetch this resource. Remote templates "
                                          "and OLE links are used to deliver macros or leak credentials.",
                                          SRC, "HIGH", relationship_type=rtype, target=target[:500], part=zi.filename))
    except zipfile.BadZipFile:
        res.status, res.detail = EngineStatus.ERROR, "Document container is malformed."
        return res, findings, ["whole document (malformed)"], links
    except (OSError, RuntimeError, ValueError, NotImplementedError) as e:
        res.status, res.detail = EngineStatus.ERROR, f"Document could not be inspected: {type(e).__name__}"
        return res, findings, ["whole document"], links
    if skipped:
        res.status, res.detail = EngineStatus.PARTIAL, "Some document parts were not inspected."
    else:
        res.detail = f"Inspected container structure and relationships ({fmt}). Macro behaviour was not analysed."
    return res, findings, skipped, links
