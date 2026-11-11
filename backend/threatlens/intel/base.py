"""Threat-intelligence provider adapters. A provider that did not answer is never treated as 'clean'."""
from __future__ import annotations

import base64
import time
from typing import Callable

import httpx

from ..config import Settings
from ..models import EngineResult, EngineStatus, f

Cache = tuple[Callable[[str], dict | None], Callable[[str, dict], None]]  # (get, put)


class Provider:
    name = "provider"

    def __init__(self, cfg: Settings, transport: httpx.BaseTransport | None = None, cache: Cache | None = None):
        self.cfg, self.transport, self.cache = cfg, transport, cache

    def configured(self) -> bool:
        raise NotImplementedError

    def _client(self) -> httpx.Client:
        return httpx.Client(timeout=self.cfg.intel_timeout_s, transport=self.transport, follow_redirects=False)

    def _run(self, key: str, call: Callable[[httpx.Client], tuple[EngineResult, list[dict]]]) -> tuple[EngineResult, list[dict]]:
        res = EngineResult(name=self.name, status=EngineStatus.NOT_CONFIGURED,
                           detail="No API key configured; this source was not queried.")
        if not self.configured():
            return res, []
        ck = f"{self.name}:{key}"
        if self.cache:
            hit = self.cache[0](ck)
            if hit:
                r = EngineResult(**hit["result"])
                r.detail += " (cached)"
                return r, hit["findings"]
        t0 = time.time()
        try:
            with self._client() as c:
                res, findings = call(c)
        except httpx.TimeoutException:
            res.status, res.detail, findings = EngineStatus.TIMEOUT, "Provider did not answer in time.", []
        except httpx.HTTPError as e:
            res.status, res.detail, findings = EngineStatus.UNAVAILABLE, f"Provider unreachable ({type(e).__name__}).", []
        res.name = self.name
        res.duration_ms = int((time.time() - t0) * 1000)
        if self.cache and res.status == EngineStatus.COMPLETED:
            self.cache[1](ck, {"result": res.model_dump(mode="json"), "findings": findings})
        return res, findings

    def lookup_url(self, url: str) -> tuple[EngineResult, list[dict]]:
        return EngineResult(name=self.name, status=EngineStatus.SKIPPED, detail="URL lookup not supported."), []

    def lookup_hash(self, sha256: str) -> tuple[EngineResult, list[dict]]:
        return EngineResult(name=self.name, status=EngineStatus.SKIPPED, detail="Hash lookup not supported."), []


def _http_status(res: EngineResult, r: httpx.Response) -> bool:
    """Map non-200 responses to a status. Returns True if the caller should stop."""
    if r.status_code == 200:
        return False
    if r.status_code == 429:
        res.status, res.detail = EngineStatus.QUOTA_EXCEEDED, "Provider quota or rate limit exceeded."
    elif r.status_code in (401, 403):
        res.status, res.detail = EngineStatus.ERROR, "Provider rejected the API key."
    elif r.status_code >= 500:
        res.status, res.detail = EngineStatus.UNAVAILABLE, f"Provider error (HTTP {r.status_code})."
    else:
        res.status, res.detail = EngineStatus.ERROR, f"Unexpected provider response (HTTP {r.status_code})."
    return True


class VirusTotalProvider(Provider):
    """VirusTotal API v3. Looks up an EXISTING report by hash or URL id; never uploads file content."""
    name = "VirusTotal"
    base = "https://www.virustotal.com/api/v3"

    def configured(self) -> bool:
        return bool(self.cfg.virustotal_api_key)

    def _get(self, c: httpx.Client, path: str, subject: dict) -> tuple[EngineResult, list[dict]]:
        res = EngineResult(name=self.name, status=EngineStatus.COMPLETED)
        r = c.get(self.base + path, headers={"x-apikey": self.cfg.virustotal_api_key})
        if r.status_code == 404:
            res.detail = "Not present in the VirusTotal dataset (unknown is not the same as clean)."
            return res, []
        if _http_status(res, r):
            return res, []
        try:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
            total = sum(int(v) for v in stats.values())
        except (KeyError, TypeError, ValueError):
            res.status, res.detail = EngineStatus.ERROR, "Provider response had an unexpected shape."
            return res, []
        res.detail = f"{mal} malicious / {sus} suspicious out of {total} engines."
        findings = []
        if mal >= self.cfg.vt_malicious_threshold:
            findings.append(f("THREAT_INTEL_MALICIOUS", "CRITICAL", f"VirusTotal: {mal} engines flag this as malicious",
                              "Multiple independent engines report this item as malicious.", "VIRUSTOTAL", "HIGH",
                              malicious=mal, suspicious=sus, engines=total, threshold=self.cfg.vt_malicious_threshold, **subject))
        elif mal or sus:
            findings.append(f("THREAT_INTEL_SUSPICIOUS", "MEDIUM", f"VirusTotal: {mal} malicious / {sus} suspicious detections",
                              "A small number of detections can be false positives; treat as a signal to investigate.",
                              "VIRUSTOTAL", "LOW", malicious=mal, suspicious=sus, engines=total, **subject))
        return res, findings

    def lookup_hash(self, sha256: str):
        return self._run("h:" + sha256, lambda c: self._get(c, f"/files/{sha256}", {"sha256": sha256}))

    def lookup_url(self, url: str):
        uid = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return self._run("u:" + url, lambda c: self._get(c, f"/urls/{uid}", {"url": url}))


class GoogleSafeBrowsingProvider(Provider):
    """Google Safe Browsing Lookup API v4 (threatMatches:find). Check Google's terms before any commercial use."""
    name = "Google Safe Browsing"
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    def configured(self) -> bool:
        return bool(self.cfg.gsb_api_key)

    def lookup_url(self, url: str):
        def call(c: httpx.Client):
            res = EngineResult(name=self.name, status=EngineStatus.COMPLETED)
            body = {"client": {"clientId": "threatlens", "clientVersion": "0.1.0"},
                    "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                                                   "POTENTIALLY_HARMFUL_APPLICATION"],
                                   "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                                   "threatEntries": [{"url": url}]}}
            r = c.post(self.endpoint, params={"key": self.cfg.gsb_api_key}, json=body)
            if _http_status(res, r):
                return res, []
            try:
                matches = r.json().get("matches", [])
            except ValueError:
                res.status, res.detail = EngineStatus.ERROR, "Provider response was not JSON."
                return res, []
            if not matches:
                res.detail = "No match in Safe Browsing lists (absence of a match is not proof of safety)."
                return res, []
            types = sorted({m.get("threatType", "?") for m in matches})
            res.detail = "Listed: " + ", ".join(types)
            return res, [f("THREAT_INTEL_MALICIOUS", "CRITICAL", "URL is on a Google Safe Browsing threat list",
                           "Google currently lists this URL as unsafe.", "GOOGLE_SAFE_BROWSING", "HIGH",
                           url=url, threat_types=types)]
        return self._run("u:" + url, call)


def build_providers(cfg: Settings, transport=None, cache=None) -> list[Provider]:
    return [GoogleSafeBrowsingProvider(cfg, transport, cache), VirusTotalProvider(cfg, transport, cache)]
