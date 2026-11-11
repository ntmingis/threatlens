"""Deterministic verdict from findings and engine states. No model, no guessing.

Precedence: MALICIOUS > SUSPICIOUS > INCONCLUSIVE > CLEAN_WITHIN_CHECKED_SCOPE.
'Clean' is only reachable when every REQUIRED engine completed over the whole input.
"""
from __future__ import annotations

from .models import SEVERITY_ORDER

MALICIOUS_CATEGORIES = {"MALWARE_SIGNATURE", "THREAT_INTEL_MALICIOUS"}
DISCLAIMER = ("ThreatLens supports risk assessment. It cannot establish that a file or website is safe: "
              "new or targeted threats may not match any signature, heuristic or reputation source.")
RECS = {
    "MALWARE_SIGNATURE": "Do not open the file. Delete it or hand it to your security team, and tell the sender's organisation through a separate channel.",
    "THREAT_INTEL_MALICIOUS": "Do not open or visit it. If you already did, change affected passwords from a different device and review recent account activity.",
    "PDF_PHISHING": "Do not click the link. Reach the organisation by typing its known address yourself.",
    "BRAND_IMPERSONATION": "Compare the domain character by character with the organisation's official domain before trusting it.",
    "URL_HOMOGLYPH": "Treat look-alike characters as a warning sign; open the site only from a bookmark or by typing the address.",
    "URL_SHORTENER": "Ask the sender for the full destination, or expand the short link with a preview service before visiting.",
    "PDF_JAVASCRIPT": "Open the PDF only in a reader with JavaScript disabled, or in a browser's built-in viewer.",
    "PDF_LAUNCH_ACTION": "Do not allow the reader to launch external programs if it prompts you.",
    "PDF_EMBEDDED_FILE": "Do not open attachments embedded in the PDF unless you expected them.",
    "PDF_CREDENTIAL_REQUEST": "Never type passwords, OTP codes or card details into a document or a site reached from it.",
    "PDF_ENCRYPTED": "Password-protected attachments from unexpected senders are a common evasion technique; verify with the sender first.",
    "OFFICE_MACRO_PRESENT": "Keep macros disabled unless you have confirmed with the sender why the document needs them.",
    "OFFICE_EXTERNAL_REFERENCE": "Open the document in Protected View and do not enable editing or content.",
    "OFFICE_EMBEDDED_OBJECT": "Do not double-click embedded objects inside the document.",
    "ARCHIVE_EXECUTABLE": "Do not run programs extracted from this archive unless you trust and expected them.",
    "ARCHIVE_ENCRYPTED": "The protected content could not be checked; scan it again after extraction on an isolated machine.",
    "ARCHIVE_PATH_TRAVERSAL": "Do not extract this archive with ordinary tools.",
    "ARCHIVE_BOMB": "Do not extract this archive; it may exhaust disk or memory.",
    "FILE_TYPE_MISMATCH": "The file is not what its name claims. Do not open it by double-clicking.",
    "DOUBLE_EXTENSION": "This is an executable disguised as a document. Do not run it.",
    "EXECUTABLE_CONTENT": "Run executables only from sources you trust; signature scanning alone cannot clear them.",
    "URL_STRUCTURE": "Check the real hostname (the part right before the first single '/') before entering any information.",
}


def assess(findings: list[dict], engines: list[dict], kind: str) -> dict:
    max_sev = max((SEVERITY_ORDER[x["severity"]] for x in findings), default=-1)
    incomplete = [e for e in engines if e.get("required") and e["status"] != "COMPLETED"]
    intel = [e for e in engines if e.get("group") == "intel"]
    intel_ok = [e for e in intel if e["status"] == "COMPLETED"]
    reasons: list[str] = []
    if any(x["category"] in MALICIOUS_CATEGORIES for x in findings):
        verdict = "MALICIOUS"
        reasons.append("A malware signature or a reputation source identifies this item as malicious.")
    elif max_sev >= SEVERITY_ORDER["MEDIUM"]:
        verdict = "SUSPICIOUS"
        reasons.append("Suspicious indicators were found, but none of them is proof of malware.")
    elif incomplete:
        verdict = "INCONCLUSIVE"
        reasons.append("Required checks did not complete: " + "; ".join(f"{e['name']} ({e['status']})" for e in incomplete) + ".")
    elif kind == "url" and not intel_ok:
        verdict = "INCONCLUSIVE"
        reasons.append("Only static URL structure was analysed. No reputation source answered, so nothing is known "
                       "about what the site actually serves.")
    else:
        verdict = "CLEAN_WITHIN_CHECKED_SCOPE"
        reasons.append("The checks listed as COMPLETED found no problem. Checks listed as not available were not performed.")
    if verdict in ("MALICIOUS", "SUSPICIOUS") and incomplete:
        reasons.append("Note: some checks did not complete (" + ", ".join(e["name"] for e in incomplete) + ").")
    recs, seen = [], set()
    for x in sorted(findings, key=lambda x: -SEVERITY_ORDER[x["severity"]]):
        r = RECS.get(x["category"])
        if r and r not in seen and SEVERITY_ORDER[x["severity"]] >= SEVERITY_ORDER["LOW"]:
            seen.add(r)
            recs.append(r)
    if verdict == "INCONCLUSIVE":
        recs.append("Treat the item as unverified. Fix the unavailable checks (see 'Engines') and scan again.")
    if verdict == "CLEAN_WITHIN_CHECKED_SCOPE":
        recs.append("No issue was found by the completed checks. Stay cautious if the item was unexpected.")
    return {"verdict": verdict, "verdict_reasons": reasons, "recommendations": recs, "disclaimer": DISCLAIMER,
            "engines_not_available": [f"{e['name']}: {e['status']} - {e.get('detail', '')}".strip(" -")
                                      for e in engines if e["status"] not in ("COMPLETED", "SKIPPED")]}
