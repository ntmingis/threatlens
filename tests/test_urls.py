import httpx
import pytest

from threatlens.intel.base import GoogleSafeBrowsingProvider, VirusTotalProvider
from threatlens.models import EngineStatus
from threatlens.risk import assess
from threatlens.urlscan.impersonation import load_brands
from threatlens.urlscan.parse import UrlError, analyze_url, parse_url
from threatlens.urlscan.ssrf import SsrfBlocked, is_public_ip, resolve_and_check


@pytest.fixture
def brands(cfg):
    return load_brands(cfg.brands_file)


def titles(fs):
    return " | ".join(x["title"] for x in fs)


def test_valid_https_official_domain_has_no_findings(brands):
    p, fs = analyze_url("https://www.paypal.com/signin", brands)
    assert p["registrable_domain"] == "paypal.com" and fs == []


def test_http_is_low_only(brands):
    _, fs = analyze_url("http://plain.example.test/", brands)
    assert [x["severity"] for x in fs] == ["LOW"]


@pytest.mark.parametrize("bad", ["ftp://x.example/", "javascript:alert(1)", "file:///etc/passwd", "https://", "http://a b.example/", ""])
def test_rejects_non_http(bad):
    with pytest.raises(UrlError):
        parse_url(bad)


def test_shortener(brands):
    _, fs = analyze_url("https://bit.ly/3abcd", brands)
    assert any(x["category"] == "URL_SHORTENER" for x in fs)


def test_punycode_and_homoglyph(brands):
    _, fs = analyze_url("https://gооgle.com/", brands)  # Cyrillic o
    assert any(x["category"] == "URL_HOMOGLYPH" and x["severity"] == "HIGH" for x in fs)
    mixed = next(x for x in fs if x["title"].startswith("Hostname label mixes"))
    assert {"LATIN", "CYRILLIC"} <= set(mixed["evidence"]["scripts"])
    assert any(x["category"] == "BRAND_IMPERSONATION" and x["severity"] == "HIGH" for x in fs)


@pytest.mark.parametrize("url,ip", [("http://192.168.1.10/", "192.168.1.10"), ("http://2130706433/", "127.0.0.1"),
                                    ("http://0x7f.0.0.1/", "127.0.0.1"), ("http://[::1]/", "::1")])
def test_ip_literals(url, ip, brands):
    p, fs = analyze_url(url, brands)
    assert p["ip"] == ip and "IP address" in titles(fs)


def test_userinfo_trick(brands):
    p, fs = analyze_url("https://trusted.example@evil.example.test/login", brands)
    u = next(x for x in fs if "userinfo" in x["title"])
    assert u["severity"] == "HIGH" and u["evidence"]["real_host"] == "evil.example.test"


@pytest.mark.parametrize("url,sev,diffpos", [("https://paypaI.example.test/", "HIGH", 6), ("http://micros0ft.example.test/", "HIGH", 7),
                                             ("https://g00gle.example.test/", "HIGH", 2)])
def test_character_substitution_explains_difference(url, sev, diffpos, brands):
    _, fs = analyze_url(url, brands)
    b = next(x for x in fs if x["category"] == "BRAND_IMPERSONATION")
    assert b["severity"] == sev and b["evidence"]["differences"][0]["position"] == diffpos


def test_brand_in_non_official_domain_is_medium(brands):
    for u in ("https://paypal-security.example.test/", "https://paypal.com.evil.example.test/"):
        _, fs = analyze_url(u, brands)
        assert [x["severity"] for x in fs if x["category"] == "BRAND_IMPERSONATION"] == ["MEDIUM"]


def test_generic_keywords_alone_are_info_only(brands):
    _, fs = analyze_url("https://login-account.example.test/", brands)
    assert fs and all(x["severity"] == "INFO" for x in fs)


# ---------- SSRF guard ----------
@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "172.16.3.1", "192.168.0.1", "169.254.169.254", "100.64.0.1",
                                "0.0.0.0", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "224.0.0.1"])
def test_non_public_ips(ip):
    assert is_public_ip(ip) is False


def test_public_ip():
    assert is_public_ip("93.184.216.34") and is_public_ip("2606:4700:4700::1111")


@pytest.mark.parametrize("url", ["http://localhost/", "http://127.0.0.1:8000/", "http://169.254.169.254/latest/meta-data/",
                                 "http://2130706433/", "http://[::1]/", "http://printer.local/", "http://10.1.2.3/"])
def test_ssrf_blocks_internal_targets(url):
    with pytest.raises(SsrfBlocked):
        resolve_and_check(url, resolver=lambda h: ["93.184.216.34"])


def test_ssrf_blocks_hostname_resolving_to_private():
    with pytest.raises(SsrfBlocked):
        resolve_and_check("https://innocent.example.test/", resolver=lambda h: ["10.0.0.7"])
    with pytest.raises(SsrfBlocked):  # mixed answers: one private record is enough to refuse
        resolve_and_check("https://innocent.example.test/", resolver=lambda h: ["93.184.216.34", "127.0.0.1"])


def test_dns_rebinding_simulation_pins_first_answer():
    answers = iter([["93.184.216.34"], ["127.0.0.1"]])
    resolver = lambda h: next(answers)  # noqa: E731
    pinned = resolve_and_check("https://rebind.example.test/", resolver=resolver)
    assert pinned == ["93.184.216.34"]      # caller must connect to this IP, not resolve again
    with pytest.raises(SsrfBlocked):        # and a re-check (e.g. on a redirect hop) sees the flip and refuses
        resolve_and_check("https://rebind.example.test/", resolver=resolver)


# ---------- providers (mocked HTTP; no real service is contacted) ----------
def _vt(cfg, handler, cache=None):
    cfg.virustotal_api_key = "test-key"
    return VirusTotalProvider(cfg, httpx.MockTransport(handler), cache)


def test_provider_not_configured_is_not_clean(cfg):
    for P in (VirusTotalProvider, GoogleSafeBrowsingProvider):
        res, fs = P(cfg).lookup_url("https://a.example.test/")
        assert res.status == EngineStatus.NOT_CONFIGURED and fs == []


def test_vt_malicious_and_key_sent_in_header_only(cfg):
    seen = {}

    def h(req):
        seen["url"], seen["key"] = str(req.url), req.headers.get("x-apikey")
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 9, "suspicious": 1, "harmless": 60}}}})
    res, fs = _vt(cfg, h).lookup_url("https://bad.example.test/")
    assert res.status == EngineStatus.COMPLETED and fs[0]["category"] == "THREAT_INTEL_MALICIOUS"
    assert seen["key"] == "test-key" and "test-key" not in seen["url"]


def test_vt_unknown_404_is_completed_without_clean_claim(cfg):
    res, fs = _vt(cfg, lambda r: httpx.Response(404)).lookup_hash("a" * 64)
    assert res.status == EngineStatus.COMPLETED and "unknown is not the same as clean" in res.detail and fs == []


@pytest.mark.parametrize("code,status", [(429, EngineStatus.QUOTA_EXCEEDED), (503, EngineStatus.UNAVAILABLE), (401, EngineStatus.ERROR)])
def test_vt_failures(cfg, code, status):
    res, fs = _vt(cfg, lambda r: httpx.Response(code)).lookup_url("https://a.example.test/")
    assert res.status == status and fs == []


def test_provider_timeout_and_unreachable(cfg):
    def t(req):
        raise httpx.ReadTimeout("slow")

    def u(req):
        raise httpx.ConnectError("down")
    assert _vt(cfg, t).lookup_url("https://a.example.test/")[0].status == EngineStatus.TIMEOUT
    cfg.gsb_api_key = "k"
    assert GoogleSafeBrowsingProvider(cfg, httpx.MockTransport(u)).lookup_url("https://a.example.test/")[0].status == EngineStatus.UNAVAILABLE


def test_gsb_match(cfg):
    cfg.gsb_api_key = "k"
    h = lambda r: httpx.Response(200, json={"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})  # noqa: E731
    res, fs = GoogleSafeBrowsingProvider(cfg, httpx.MockTransport(h)).lookup_url("https://phish.example.test/")
    assert fs[0]["evidence"]["threat_types"] == ["SOCIAL_ENGINEERING"]


def test_cache_prevents_repeat_calls(cfg):
    calls, mem = [], {}

    def h(req):
        calls.append(1)
        return httpx.Response(404)
    cache = (mem.get, mem.__setitem__)
    p = _vt(cfg, h, cache)
    p.lookup_hash("b" * 64)
    r2, _ = p.lookup_hash("b" * 64)
    assert len(calls) == 1 and "(cached)" in r2.detail


# ---------- verdict rules ----------
def test_url_without_reputation_is_inconclusive_not_clean():
    eng = [{"name": "Static URL analysis", "status": "COMPLETED", "required": True},
           {"name": "VirusTotal", "status": "NOT_CONFIGURED", "group": "intel"}]
    a = assess([], eng, "url")
    assert a["verdict"] == "INCONCLUSIVE" and any("VirusTotal" in e for e in a["engines_not_available"])
    eng[1]["status"] = "UNAVAILABLE"
    assert assess([], eng, "url")["verdict"] == "INCONCLUSIVE"
    eng[1]["status"] = "COMPLETED"
    assert assess([], eng, "url")["verdict"] == "CLEAN_WITHIN_CHECKED_SCOPE"
