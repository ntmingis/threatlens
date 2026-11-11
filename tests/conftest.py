import io
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from threatlens.config import Settings  # noqa: E402

# Standard EICAR antivirus test string (harmless by design), assembled at runtime so that this
# repository does not itself contain the pattern and get quarantined by desktop antivirus.
EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + "$H+H*").encode()
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    for k in ("VIRUSTOTAL_API_KEY", "GOOGLE_SAFE_BROWSING_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("THREATLENS_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("THREATLENS_RATE_LIMIT_PER_MIN", "1000")
    return Settings()


@pytest.fixture
def test_sig_db(tmp_path, monkeypatch):
    """A ClamAV database holding ONE hash signature for EICAR, so detection is exercised by the real
    engine without downloading the official database. This is a test signature, not real coverage."""
    d = tmp_path / "clamdb"
    d.mkdir()
    (d / "test.hdb").write_text(f"{EICAR_MD5}:{len(EICAR)}:ThreatLens.Test.EICAR\n")
    monkeypatch.setenv("THREATLENS_CLAMAV_DB", str(d))
    return d


def make_pdf(path: Path, *, mismatch=False, js=False, text="Quarterly report.", encrypt=False, link=None, pages=1):
    import pymupdf
    doc = pymupdf.open()
    for i in range(pages):
        page = doc.new_page()
        page.insert_text((72, 72), text if i == 0 else f"Page {i + 1}")
    page = doc[min(1, pages - 1)]
    if mismatch:
        r = pymupdf.Rect(72, 190, 300, 210)
        page.insert_text((74, 204), "https://microsoft.com", fontsize=11)
        page.insert_link({"kind": pymupdf.LINK_URI, "from": r, "uri": "https://micros0ft-login.example.test/verify"})
    if link:
        r = pymupdf.Rect(72, 290, 300, 310)
        page.insert_text((74, 304), "Open the portal", fontsize=11)
        page.insert_link({"kind": pymupdf.LINK_URI, "from": r, "uri": link})
    if js:
        x = doc.get_new_xref()
        doc.update_object(x, "<</S/JavaScript/JS(app.alert\\('test'\\);)>>")
        doc.xref_set_key(doc.pdf_catalog(), "OpenAction", f"{x} 0 R")
    if encrypt:
        doc.save(str(path), encryption=pymupdf.PDF_ENCRYPT_AES_256, user_pw="secret", owner_pw="owner")
    else:
        doc.save(str(path))
    doc.close()
    return path


def make_zip(path: Path, entries: dict, nested: int = 0) -> Path:
    data = _zip_bytes(entries)
    for _ in range(nested):
        data = _zip_bytes({"inner.zip": data})
    path.write_bytes(data)
    return path


def _zip_bytes(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in entries.items():
            z.writestr(name, content)
    return buf.getvalue()


def make_docx(path: Path, *, external_template=None, hyperlink=None, macro=False) -> Path:
    rels = ""
    if external_template:
        rels += ('<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
                 f'attachedTemplate" Target="{external_template}" TargetMode="External"/>')
    if hyperlink:
        rels += ('<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/'
                 f'hyperlink" Target="{hyperlink}" TargetMode="External"/>')
    entries = {
        "[Content_Types].xml": '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        "word/document.xml": "<w:document/>",
        "word/_rels/document.xml.rels": f'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{rels}</Relationships>',
    }
    if macro:
        entries["word/vbaProject.bin"] = b"\x00" * 64
    return make_zip(path, entries)
