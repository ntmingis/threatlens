import io
import time

import httpx
import pytest
from conftest import make_pdf
from fastapi.testclient import TestClient

from threatlens.main import create_app


@pytest.fixture
def client(cfg):
    return TestClient(create_app(cfg), raise_server_exceptions=False)


def wait(client, job_id, timeout=120):
    t0 = time.time()
    while time.time() - t0 < timeout:
        j = client.get(f"/api/scanner/jobs/{job_id}").json()
        if j["status"] in ("COMPLETED", "FAILED"):
            return j
        time.sleep(0.2)
    raise AssertionError("job did not finish")


def upload(client, data: bytes, name="a.pdf", ctype="application/pdf"):
    return client.post("/api/scanner/files", files={"file": (name, io.BytesIO(data), ctype)})


def test_end_to_end_pdf_report_history_export_delete(client, cfg, tmp_path):
    data = make_pdf(tmp_path / "src.pdf", mismatch=True, pages=2).read_bytes()
    r = upload(client, data, name="../../etc/invoice.pdf", ctype="image/png")  # hostile name + lying Content-Type
    assert r.status_code == 202
    j = wait(client, r.json()["job_id"])
    assert j["status"] == "COMPLETED"
    rep = client.get(f"/api/scanner/reports/{j['report_id']}").json()
    assert rep["target"]["filename"] == "invoice.pdf"          # path stripped
    assert rep["target"]["format"] == "pdf" and rep["target"]["mime"] == "application/pdf"  # from content
    assert len(rep["target"]["sha256"]) == 64
    assert rep["verdict"] in ("SUSPICIOUS", "MALICIOUS")
    assert any(x["category"] == "PDF_PHISHING" and x["evidence"]["page"] == 2 for x in rep["findings"])
    assert all(x["evidence"] or x["severity"] == "INFO" or x["source"] for x in rep["findings"])
    assert rep["recommendations"] and "cannot establish" in rep["disclaimer"]
    # the original upload is gone and there is no way to download it
    assert list(cfg.quarantine_dir.glob("*")) == []
    hist = client.get("/api/scanner/history", params={"q": rep["target"]["sha256"][:12]}).json()["items"]
    assert [h["id"] for h in hist] == [rep["report_id"]]
    assert client.get("/api/scanner/history", params={"verdict": "CLEAN_WITHIN_CHECKED_SCOPE"}).json()["items"] == []
    assert client.delete(f"/api/scanner/reports/{rep['report_id']}").status_code == 200
    assert client.get(f"/api/scanner/reports/{rep['report_id']}").status_code == 404


def test_duplicate_hash_is_reported(client, tmp_path):
    data = make_pdf(tmp_path / "s.pdf").read_bytes()
    first = wait(client, upload(client, data).json()["job_id"])
    second = wait(client, upload(client, data).json()["job_id"])
    rep = client.get(f"/api/scanner/reports/{second['report_id']}").json()
    assert rep["previous_reports_same_hash"][0]["id"] == first["report_id"]


def test_oversized_upload_rejected_and_cleaned(client, cfg):
    cfg.max_upload_bytes = 1024
    r = upload(client, b"A" * 5000, name="big.txt")
    assert r.status_code == 413 and r.json()["error"]["code"] == "FILE_TOO_LARGE"
    assert list(cfg.quarantine_dir.glob("*")) == []


def test_benign_file_never_clean_when_antivirus_unavailable(client, tmp_path, monkeypatch):
    monkeypatch.setenv("THREATLENS_CLAMAV_DB", str(tmp_path / "missing-db"))
    monkeypatch.setenv("PATH", "/nonexistent")
    j = wait(client, upload(client, make_pdf(tmp_path / "s.pdf").read_bytes()).json()["job_id"])
    rep = client.get(f"/api/scanner/reports/{j['report_id']}").json()
    assert rep["verdict"] == "INCONCLUSIVE"
    assert any("ClamAV" in e for e in rep["engines_not_available"])


def test_url_scan_and_invalid_url(client):
    r = client.post("/api/scanner/urls", json={"url": "https://paypaI.example.test/login"})
    assert r.status_code == 200
    rep = r.json()
    assert rep["verdict"] == "SUSPICIOUS" and rep["target"]["host"] == "paypai.example.test"
    assert any(e["name"] == "VirusTotal" and e["status"] == "NOT_CONFIGURED" for e in rep["engines"])
    bad = client.post("/api/scanner/urls", json={"url": "file:///etc/passwd"})
    assert bad.status_code == 400 and bad.json()["error"]["code"] == "INVALID_URL"
    plain = client.post("/api/scanner/urls", json={"url": "https://docs.example.test/"}).json()
    assert plain["verdict"] == "INCONCLUSIVE"   # no reputation source answered


def test_secrets_never_reach_client(cfg, tmp_path):
    cfg.virustotal_api_key = "SECRET-VT-KEY-123"
    cfg.gsb_api_key = "SECRET-GSB-KEY-456"
    mock = httpx.MockTransport(lambda req: httpx.Response(500))
    c = TestClient(create_app(cfg, intel_transport=mock), raise_server_exceptions=False)
    bodies = [c.post("/api/scanner/urls", json={"url": "https://a.example.test/"}).text,
              c.get("/api/scanner/capabilities").text, c.get("/scanner").text,
              c.get("/scanner/static/app.js").text, c.get("/api/scanner/history").text]
    assert all("SECRET-" not in b for b in bodies)
    assert '"virustotal":"CONFIGURED"' in bodies[1].replace(" ", "")


def test_rate_limit(cfg):
    cfg.rate_limit_per_min = 3
    c = TestClient(create_app(cfg))
    codes = [c.post("/api/scanner/urls", json={"url": "https://a.example.test/"}).status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]


def test_errors_are_structured_and_headers_set(client):
    r = client.get("/api/scanner/reports/does-not-exist")
    assert r.status_code == 404 and r.json() == {"error": {"code": "NOT_FOUND", "message": "Report not found."}}
    assert client.post("/api/scanner/urls", json={}).json()["error"]["code"] == "INVALID_REQUEST"
    assert "Traceback" not in r.text
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    cap = client.get("/api/scanner/capabilities").json()
    assert cap["engines"]["url_fetch"] == "NOT_IMPLEMENTED" and cap["providers"]["virustotal"] == "NOT_CONFIGURED"


import shutil  # noqa: E402

from conftest import EICAR  # noqa: E402

need_clam = pytest.mark.skipif(shutil.which("clamscan") is None, reason="clamscan is not installed on this machine")


@need_clam
def test_api_eicar_is_malicious_and_benign_is_clean_within_scope(client, tmp_path, test_sig_db):
    j = wait(client, upload(client, EICAR, name="eicar.com", ctype="application/octet-stream").json()["job_id"])
    rep = client.get(f"/api/scanner/reports/{j['report_id']}").json()
    assert rep["verdict"] == "MALICIOUS"
    assert any(x["category"] == "MALWARE_SIGNATURE" for x in rep["findings"])
    j = wait(client, upload(client, make_pdf(tmp_path / "ok.pdf").read_bytes(), name="ok.pdf").json()["job_id"])
    rep = client.get(f"/api/scanner/reports/{j['report_id']}").json()
    assert rep["verdict"] == "CLEAN_WITHIN_CHECKED_SCOPE"
    assert "cannot establish" in rep["disclaimer"]
