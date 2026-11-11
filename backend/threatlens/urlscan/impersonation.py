"""Brand look-alike detection against a configurable brand list (config/brands.json)."""
from __future__ import annotations

import json
import unicodedata
from pathlib import Path

from ..models import f

SRC = "DOMAIN_SIMILARITY"
DIGIT_MAP = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "$": "s"}
# Small confusables table (subset of Unicode TR39). Limitation: not the full confusables.txt.
CONFUSABLES = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s",
               "һ": "h", "ԁ": "d", "ɡ": "g", "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "ı": "i", "ɩ": "i",
               "ł": "l", "ö": "o", "ó": "o", "é": "e", "á": "a", "í": "i", "ú": "u", "ü": "u"}


def load_brands(path: Path) -> list[dict]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return [b for b in data.get("brands", []) if b.get("name") and b.get("domains")]
    except (OSError, ValueError):
        return []


def skeleton(token: str, mixed_case_source: bool) -> str:
    out = []
    for ch in token:
        if mixed_case_source and ch == "I":
            out.append("l")       # capital I rendered like lowercase L
            continue
        c = ch.lower()
        c = CONFUSABLES.get(c, c)
        c = DIGIT_MAP.get(c, c)
        out.append(c)
    return "".join(out).replace("rn", "m").replace("vv", "w")


def _edit_distance_le1(a: str, b: str) -> bool:
    if a == b:
        return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:
        diff = [i for i in range(la) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    if la > lb:
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


def _diff(raw: str, brand: str) -> list[dict]:
    if len(raw) != len(brand):
        return [{"note": "length differs", "seen": raw, "expected": brand}]
    return [{"position": i + 1, "seen": raw[i], "seen_name": unicodedata.name(raw[i], "?"), "expected": brand[i]}
            for i in range(len(raw)) if raw[i] != brand[i]]


def check_impersonation(p: dict, brands: list[dict], ctx: dict | None = None) -> list[dict]:
    ctx = ctx or {}
    reg = p["registrable_domain"] or ""
    official = {d.lower() for b in brands for d in b["domains"]}
    if reg in official:
        return []
    host_u = p["host_unicode"]
    orig = p.get("host_original") or host_u
    # keep original case only when lengths line up (ASCII hosts); needed for the I/l trick
    src = orig if len(orig) == len(host_u) and orig.lower() == host_u.lower() else host_u
    mixed = any(c.isupper() for c in src) and any(c.islower() for c in src)
    suffix_labels = reg.count(".")  # labels belonging to the public suffix (approximation)
    labels = src.split(".")
    name_labels = labels[: len(labels) - suffix_labels] if suffix_labels else labels
    tokens: list[tuple[str, str]] = []  # (token, where)
    for i, lab in enumerate(name_labels):
        where = "registrable domain" if i == len(name_labels) - 1 else "subdomain"
        tokens.append((lab, where))
        if "-" in lab:
            tokens.extend((t, where) for t in lab.split("-") if t)
            tokens.append((lab.replace("-", ""), where))
    out, seen = [], set()
    for b in brands:
        name = b["name"].lower()
        if len(name) < 4:
            continue
        for tok, where in tokens:
            raw = tok.lower()
            sk = skeleton(tok, mixed)
            key = (name, raw)
            if key in seen:
                continue
            ev = dict(url=p["normalized"], hostname=p["host"], brand=b["name"], official_domains=b["domains"],
                      matched_part=tok, found_in=where, registrable_domain=reg, **ctx)
            if raw == name and not (mixed and "I" in tok and sk != raw):
                seen.add(key)
                out.append(f("BRAND_IMPERSONATION", "MEDIUM", f"Brand name '{b['name']}' used on a non-official domain",
                             f"The hostname contains '{b['name']}' in its {where}, but the registrable domain "
                             f"'{reg}' is not in the configured official list. This alone does not prove fraud.",
                             SRC, "MEDIUM", **ev))
            elif sk == name:
                seen.add(key)
                out.append(f("BRAND_IMPERSONATION", "HIGH", f"Look-alike of '{b['name']}' using substituted characters",
                             "Replacing characters with visually similar ones is a typical phishing-domain technique.",
                             SRC, "HIGH", differences=_diff(tok if mixed else raw, name), **ev))
            elif len(name) >= 5 and _edit_distance_le1(sk, name):
                seen.add(key)
                out.append(f("BRAND_IMPERSONATION", "MEDIUM", f"Possible typosquat of '{b['name']}'",
                             "The name differs from the brand by one edit (insert, delete, replace or swap).",
                             SRC, "LOW", differences=_diff(raw, name), **ev))
    return out
