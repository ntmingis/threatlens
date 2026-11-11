"""Static URL analysis. No network request is made by this module."""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit

from ..models import f

SRC = "URL_STATIC_ANALYZER"
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly", "cutt.ly",
              "shorturl.at", "tiny.cc", "rb.gy", "s.id", "t.ly", "lnkd.in"}
TWO_LEVEL_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "co.kr", "com.br",
                      "com.cn", "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn", "co.in", "com.sg", "com.tr",
                      "com.mx", "co.nz", "co.za", "com.hk", "com.tw", "co.id", "com.my", "co.th", "com.ph"}
GENERIC_KEYWORDS = {"login", "signin", "secure", "account", "verify", "update", "password", "billing", "support"}


class UrlError(ValueError):
    pass


def registrable_domain(host: str) -> str:
    """Approximate registrable domain. Limitation: uses a short suffix list, not the full Public Suffix List."""
    labels = host.strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _ip_literal(host: str):
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    # Legacy forms browsers accept: decimal (2130706433), hex (0x7f000001), dotted octal/hex
    try:
        if re.fullmatch(r"\d+", h):
            n = int(h)
        elif re.fullmatch(r"0[xX][0-9a-fA-F]+", h):
            n = int(h, 16)
        elif re.fullmatch(r"(0[xX][0-9a-fA-F]+|0[0-7]*|\d+)(\.(0[xX][0-9a-fA-F]+|0[0-7]*|\d+)){1,3}", h) and \
                re.search(r"(^|\.)0[xX0-7]", h):
            parts = [int(p, 0) if p.lower().startswith("0x") else (int(p, 8) if p.startswith("0") and len(p) > 1 else int(p))
                     for p in h.split(".")]
            if any(p > 255 for p in parts[:-1]):
                return None
            n = 0
            for p in parts[:-1]:
                n = (n << 8) | p
            n = (n << (8 * (5 - len(parts)))) | parts[-1]
        else:
            return None
        if 0 <= n <= 0xFFFFFFFF:
            return ipaddress.ip_address(n)
    except ValueError:
        return None
    return None


def _scripts(label: str) -> set[str]:
    out = set()
    for ch in label:
        if ch.isalpha():
            try:
                out.add(unicodedata.name(ch).split()[0])
            except ValueError:
                out.add("UNKNOWN")
    return out


def parse_url(raw: str) -> dict:
    """Validate and decompose a URL. Raises UrlError for anything that is not a usable http(s) URL."""
    if not isinstance(raw, str):
        raise UrlError("URL must be a string")
    s = raw.strip()
    if not s or len(s) > 4096:
        raise UrlError("URL is empty or longer than 4096 characters")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in s) or " " in s:
        raise UrlError("URL contains whitespace or control characters")
    if "://" not in s:
        s = "http://" + s  # bare domains are accepted and analysed as http
    try:
        parts = urlsplit(s)
        port = parts.port
    except ValueError as e:
        raise UrlError(f"URL cannot be parsed: {e}") from e
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise UrlError("Only http and https URLs are accepted")
    host_raw = parts.hostname or ""
    if not host_raw:
        raise UrlError("URL has no hostname")
    # urlsplit lower-cases hostname; recover original case for homoglyph checks such as paypaI
    netloc_host = parts.netloc.rsplit("@", 1)[-1]
    host_original = netloc_host.split(":")[0] if not netloc_host.startswith("[") else netloc_host
    host = host_raw.rstrip(".")
    ip = _ip_literal(host)
    host_ascii, host_unicode = host, host
    if ip is None:
        try:
            host_ascii = host.encode("idna").decode("ascii")
        except UnicodeError:
            host_ascii = host
        try:
            host_unicode = host_ascii.encode("ascii").decode("idna")
        except UnicodeError:
            host_unicode = host
    netloc = host_ascii if ":" not in host_ascii else f"[{host_ascii}]"
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc += f":{port}"
    normalized = f"{scheme}://{netloc}{parts.path or '/'}" + (f"?{parts.query}" if parts.query else "")
    return {"submitted": raw, "normalized": normalized, "scheme": scheme, "host": host_ascii,
            "host_unicode": host_unicode, "host_original": host_original, "port": port, "path": parts.path,
            "query": parts.query, "fragment": parts.fragment, "userinfo": parts.username is not None,
            "username": parts.username, "ip": str(ip) if ip else None,
            "registrable_domain": None if ip else registrable_domain(host_ascii)}


def analyze_url(raw: str, brands: list[dict] | None = None, context: dict | None = None) -> tuple[dict, list[dict]]:
    """Return (parsed url, findings). `context` (e.g. PDF page) is merged into every finding's evidence."""
    from .impersonation import check_impersonation

    ctx = context or {}
    p = parse_url(raw)
    out: list[dict] = []

    def add(sev, title, desc, conf="MEDIUM", cat="URL_STRUCTURE", **ev):
        out.append(f(cat, sev, title, desc, SRC, conf, url=p["normalized"], **ev, **ctx))

    if p["userinfo"]:
        add("HIGH", "URL contains userinfo before '@'",
            "Everything before '@' is a username, not the destination. This form is used to make a URL look like "
            "it points to a trusted site.", "HIGH", shown_before_at=p["username"], real_host=p["host"])
    if p["ip"]:
        ipobj = ipaddress.ip_address(p["ip"])
        add("MEDIUM", "URL uses an IP address instead of a domain name",
            "Legitimate public services rarely ask users to open raw IP addresses.", "MEDIUM",
            ip=p["ip"], written_as=p["host_original"], is_global=ipobj.is_global)
        if p["host_original"].strip("[]") != p["ip"]:
            add("HIGH", "IP address is written in an obfuscated numeric form",
                "Decimal, hexadecimal or octal notation hides the real address from readers and simple filters.",
                "HIGH", written_as=p["host_original"], decoded_ip=p["ip"])
    else:
        labels = p["host_unicode"].split(".")
        if any(l.startswith("xn--") for l in p["host"].split(".")):
            add("MEDIUM", "Hostname uses punycode (internationalised domain)",
                "Punycode domains can render as look-alikes of well-known names. Compare the decoded form carefully.",
                "MEDIUM", cat="URL_HOMOGLYPH", ascii_form=p["host"], unicode_form=p["host_unicode"])
        for lab in labels:
            sc = _scripts(lab)
            if len(sc) > 1:
                chars = [{"char": c, "name": unicodedata.name(c, "?")} for c in lab if ord(c) > 127]
                add("HIGH", "Hostname label mixes writing systems",
                    "A single label combining scripts (for example Latin and Cyrillic) is a common homoglyph technique.",
                    "HIGH", cat="URL_HOMOGLYPH", label=lab, scripts=sorted(sc), non_ascii_characters=chars)
        if p["registrable_domain"] in SHORTENERS:
            add("LOW", "URL shortener hides the final destination",
                "The real destination cannot be determined without following the redirect, which ThreatLens does not do.",
                "HIGH", cat="URL_SHORTENER", shortener=p["registrable_domain"])
        sub = p["host"][: -len(p["registrable_domain"])].strip(".") if p["registrable_domain"] else ""
        if sub.count(".") >= 3:
            add("INFO", "Hostname has many subdomain levels", "Weak signal on its own.", "LOW", subdomain=sub)
        kw = sorted({k for k in GENERIC_KEYWORDS if k in re.split(r"[.\-_]", p["host"])})
        if kw:
            add("INFO", "Hostname contains generic account-related words",
                "Words such as 'login' or 'secure' are common on legitimate sites too. Weak signal on its own.",
                "LOW", keywords=kw)
        out.extend(check_impersonation(p, brands or [], ctx))
    if p["scheme"] == "http":
        add("LOW", "URL uses unencrypted HTTP", "Data sent to this URL is not protected in transit.", "HIGH")
    if p["port"] and p["port"] not in (80, 443):
        add("LOW", "URL uses a non-standard port", "Weak signal on its own.", "LOW", port=p["port"])
    if len(p["normalized"]) > 300:
        add("INFO", "URL is unusually long", "Weak signal on its own.", "LOW", length=len(p["normalized"]))
    if re.search(r"%25[0-9a-fA-F]{2}", p["path"] + "?" + p["query"]):
        add("LOW", "URL contains double percent-encoding",
            "Double encoding can be used to slip content past filters.", "MEDIUM")
    m = re.search(r"https?(%3A|:)(%2F|/){2}[^&]+", p["query"], re.I)
    if m:
        add("LOW", "Query string embeds another URL",
            "May indicate an open redirect; the embedded destination was not followed.", "LOW",
            embedded=m.group(0)[:200])
    return p, out
