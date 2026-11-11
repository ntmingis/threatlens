"""PDF static analysis with PyMuPDF. Nothing in the PDF is executed and no link is opened."""
from __future__ import annotations

import re
import time
from pathlib import Path

from ..config import Settings
from ..models import EngineResult, EngineStatus, f
from ..urlscan.parse import UrlError, analyze_url, parse_url, registrable_domain

SRC = "PDF_STATIC_ANALYZER"
URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'\)\]]{3,2000})""")
DOMAIN_RE = re.compile(r"(?i)\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b")
EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]{1,64}@(?:[a-z0-9-]+\.)+[a-z]{2,24}\b")
PHONE_RE = re.compile(r"(?<![\w.])\+?\d[\d\s().-]{7,16}\d(?![\w.])")
PRESSURE = ["verify your account", "account verification", "confirm your identity", "password reset", "reset your password",
            "urgent payment", "immediately", "within 24 hours", "account will be suspended", "account has been suspended",
            "unusual activity", "final notice", "xác minh tài khoản", "đặt lại mật khẩu", "khóa tài khoản", "thanh toán gấp"]
CREDENTIAL = ["enter your password", "login credentials", "card number", "cvv", "social security", "bank account number",
              "one-time password", "otp", "nhập mật khẩu", "số thẻ", "mã otp"]
ACTIVE_KEYS = [  # (pattern, category, severity, title, description)
    (rb"/JavaScript\b|/JS\b", "PDF_JAVASCRIPT", "MEDIUM", "PDF contains a JavaScript action",
     "JavaScript in a PDF can run when the file is opened in some readers. It is an indicator that needs review, "
     "not proof of malware. The script was not executed."),
    (rb"/Launch\b", "PDF_LAUNCH_ACTION", "HIGH", "PDF contains a Launch action",
     "A Launch action asks the reader to start a program or open a file."),
    (rb"/OpenAction\b", "PDF_OPEN_ACTION", "LOW", "PDF defines an action that runs on open",
     "OpenAction is often benign (for example setting the zoom), but it is also how scripts auto-start."),
    (rb"/AA\b", "PDF_ADDITIONAL_ACTION", "LOW", "PDF defines additional (event-triggered) actions",
     "Actions bound to events such as page open or field focus."),
    (rb"/EmbeddedFile\b", "PDF_EMBEDDED_FILE", "MEDIUM", "PDF contains an embedded file",
     "Embedded files can be anything, including executables. They were not extracted or opened."),
    (rb"/SubmitForm\b", "PDF_SUBMIT_FORM", "MEDIUM", "PDF form submits data to an external address",
     "Data typed into the form can be sent to a remote server."),
    (rb"/GoToR\b|/GoToE\b", "PDF_REMOTE_GOTO", "LOW", "PDF links to another (remote or embedded) document", ""),
    (rb"/RichMedia\b|/Flash\b", "PDF_RICH_MEDIA", "MEDIUM", "PDF contains rich media content", ""),
    (rb"/XFA\b", "PDF_XFA_FORM", "LOW", "PDF uses XFA forms", "XFA forms can contain scripts."),
]


def _host_of(text: str) -> str | None:
    t = text.strip().strip(".,;:")
    m = URL_RE.search(t)
    cand = m.group(1) if m else (DOMAIN_RE.search(t).group(1) if DOMAIN_RE.search(t) else None)
    if not cand:
        return None
    try:
        return parse_url(cand)["host"]
    except UrlError:
        return None


def analyze(path: Path, cfg: Settings, brands: list[dict]) -> tuple[EngineResult, list[dict], list[str], dict, dict]:
    """Return (engine result, findings, skipped, pdf_info, indicators)."""
    import pymupdf

    try:
        pymupdf.TOOLS.mupdf_display_errors(False)
    except Exception:  # noqa: BLE001 - cosmetic only
        pass
    res = EngineResult(name="PDF static analysis", status=EngineStatus.COMPLETED, required=True)
    findings: list[dict] = []
    skipped: list[str] = []
    ind = {"urls": [], "emails": set(), "domains": set(), "phones": set()}
    info: dict = {}
    t0 = time.time()
    try:
        doc = pymupdf.open(str(path), filetype="pdf")
    except Exception as e:  # noqa: BLE001 - PyMuPDF raises several types for corrupt input
        res.status, res.detail = EngineStatus.ERROR, f"PDF could not be parsed ({type(e).__name__}); it may be corrupt."
        return res, [f("PDF_MALFORMED", "LOW", "PDF could not be parsed",
                       "The file starts like a PDF but its structure could not be read. Corruption can be accidental "
                       "or a deliberate attempt to confuse parsers.", SRC, "MEDIUM")], ["whole PDF (unparseable)"], info, _fin(ind)
    try:
        encrypted = bool(doc.needs_pass)
        info["encrypted"] = bool(doc.is_encrypted) or encrypted
        if encrypted and not doc.authenticate(""):
            res.status = EngineStatus.PARTIAL
            res.detail = "PDF is password-protected; its content could not be inspected."
            findings.append(f("PDF_ENCRYPTED", "MEDIUM", "PDF is password-protected",
                              "Content, links and actions could not be inspected. Encryption is also used to evade scanners.",
                              SRC, "HIGH"))
            return res, findings, ["all pages (encrypted)"], info, _fin(ind)
        md = doc.metadata or {}
        info.update({"title": md.get("title") or None, "author": md.get("author") or None,
                     "creator": md.get("creator") or None, "producer": md.get("producer") or None,
                     "creation_date": md.get("creationDate") or None, "modification_date": md.get("modDate") or None,
                     "page_count": doc.page_count, "is_form": bool(doc.is_form_pdf)})
        # --- active content: scan object dictionaries (not stream bodies) ---
        n_obj = doc.xref_length()
        limit = min(n_obj, cfg.pdf_max_objects)
        if n_obj > limit:
            skipped.append(f"PDF objects {limit}..{n_obj - 1} (object-count limit)")
        hits: dict[str, list[int]] = {}
        for xref in range(1, limit):
            try:
                src = doc.xref_object(xref, compressed=True).encode("latin-1", "replace")
            except Exception:  # noqa: BLE001
                continue
            for pat, cat, *_ in ACTIVE_KEYS:
                if re.search(pat, src):
                    hits.setdefault(cat, []).append(xref)
        for pat, cat, sev, title, desc in ACTIVE_KEYS:
            if cat in hits:
                findings.append(f(cat, sev, title, desc, SRC, "MEDIUM", object_numbers=hits[cat][:20],
                                  occurrences=len(hits[cat])))
        try:
            n_emb = doc.embfile_count()
            if n_emb:
                info["embedded_files"] = [doc.embfile_info(i).get("filename") for i in range(min(n_emb, 20))]
        except Exception:  # noqa: BLE001
            pass
        if info["is_form"]:
            findings.append(f("PDF_FORM", "INFO", "PDF contains form fields",
                              "Forms are common in legitimate documents; relevant mainly when combined with requests "
                              "for credentials or a SubmitForm action.", SRC, "HIGH"))
        # --- pages: links, text indicators ---
        pages = min(doc.page_count, cfg.pdf_max_pages)
        if doc.page_count > pages:
            skipped.append(f"pages {pages + 1}..{doc.page_count} (page limit)")
        text_chars, seen_urls = 0, set()
        for pno in range(pages):
            page = doc[pno]
            try:
                text = page.get_text("text") or ""
            except Exception:  # noqa: BLE001
                skipped.append(f"page {pno + 1} text (extraction failed)")
                text = ""
            text_chars += len(text.strip())
            low = " ".join(text.lower().split())
            for phrase_set, cat, sev, title in ((PRESSURE, "PDF_PRESSURE_LANGUAGE", "LOW", "Text uses urgency or account-verification language"),
                                                (CREDENTIAL, "PDF_CREDENTIAL_REQUEST", "MEDIUM", "Text asks for credentials or payment details")):
                found = [p for p in phrase_set if re.search(r"(?<!\w)" + re.escape(p) + r"(?!\w)", low)]
                if found:
                    findings.append(f(cat, sev, title, "Wording typical of phishing lures. Legitimate notices use it too, "
                                      "so weigh it together with the link findings.", SRC, "LOW", page=pno + 1, phrases=found))
            ind["emails"].update(EMAIL_RE.findall(text))
            ind["phones"].update(m.strip() for m in PHONE_RE.findall(text) if sum(c.isdigit() for c in m) >= 9)
            link_targets = []
            try:
                links = page.get_links()
            except Exception:  # noqa: BLE001
                links = []
                skipped.append(f"page {pno + 1} links (extraction failed)")
            for ln in links:
                uri = ln.get("uri")
                if not uri:
                    continue
                shown = ""
                try:
                    shown = " ".join((page.get_textbox(ln["from"]) or "").split())
                except Exception:  # noqa: BLE001
                    pass
                link_targets.append((uri, shown, ln.get("xref")))
            for m in URL_RE.findall(text):
                link_targets.append((m.rstrip(".,;:"), None, None))
            for uri, shown, xref in link_targets:
                if uri.lower().startswith("mailto:"):
                    ind["emails"].add(uri[7:].split("?")[0])
                    continue
                kind = "hyperlink annotation" if shown is not None else "text"
                ctx = {"page": pno + 1, "found_as": kind}
                if xref:
                    ctx["annotation_object"] = xref
                if not uri.lower().startswith(("http://", "https://", "www.")):
                    if shown is not None:
                        findings.append(f("PDF_NON_WEB_LINK", "MEDIUM", "Link uses a non-web scheme",
                                          "Schemes such as file:, javascript: or smb: can trigger local actions.",
                                          SRC, "MEDIUM", target=uri[:300], **ctx))
                    continue
                try:
                    p, uf = analyze_url(uri, brands, ctx)
                except UrlError:
                    continue
                key = (p["normalized"], pno, kind)
                if key in seen_urls:
                    continue
                seen_urls.add(key)
                ind["urls"].append({"url": p["normalized"], "page": pno + 1, "found_as": kind,
                                    "displayed_text": shown or None})
                ind["domains"].add(p["host"])
                findings.extend(uf)
                if shown:
                    shown_host = _host_of(shown)
                    if shown_host and p["ip"] is None and registrable_domain(shown_host) != p["registrable_domain"]:
                        findings.append(f("PDF_PHISHING", "HIGH", "Hyperlink destination mismatch",
                                          "The visible text shows one site but the link goes to a different domain.",
                                          SRC, "HIGH", page=pno + 1, displayed_text=shown[:300],
                                          displayed_domain=shown_host, actual_url=p["normalized"],
                                          actual_domain=p["host"], annotation_object=xref))
        info["extracted_text_chars"] = text_chars
        if pages and text_chars == 0:
            findings.append(f("PDF_NO_TEXT", "INFO", "No text could be extracted",
                              "The PDF is probably a scan or image. Text-based phishing checks did not apply; "
                              "OCR and QR-code decoding are not implemented in this version.", SRC, "HIGH"))
            skipped.append("text-based checks (no extractable text; OCR not implemented)")
        if skipped and res.status == EngineStatus.COMPLETED:
            res.status = EngineStatus.PARTIAL
        res.detail = res.detail or f"Parsed {pages} page(s), {limit - 1} object(s), {len(ind['urls'])} link(s)."
    except Exception as e:  # noqa: BLE001 - never let a hostile PDF crash the report
        res.status, res.detail = EngineStatus.ERROR, f"PDF analysis stopped early ({type(e).__name__})."
        skipped.append("remaining PDF content (analysis error)")
    finally:
        doc.close()
        res.duration_ms = int((time.time() - t0) * 1000)
    return res, findings, skipped, info, _fin(ind)


def _fin(ind: dict) -> dict:
    return {"urls": ind["urls"][:500], "emails": sorted(ind["emails"])[:200],
            "domains": sorted(ind["domains"])[:200], "phones": sorted(ind["phones"])[:100]}
