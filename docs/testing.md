# Testing

Run: `uv run pytest -q`. Result recorded on 2026-11-11 (Linux, Python 3.13, ClamAV 1.5.4, PyMuPDF 2.1): **85 passed**.

| File | Covers |
|---|---|
| `tests/test_files.py` | Type detection and mismatch, double extension, empty file; ClamAV: EICAR detection, benign file, database missing, not installed, timeout; PDF: metadata, links, mismatch with page evidence, JavaScript, encrypted, corrupt, page limit, injected text; DOCX external template and macro presence; ZIP executables, traversal names, nesting, bomb ratio, entry limit, malformed; worker never executes an upload |
| `tests/test_urls.py` | Scheme rejection, shortener, punycode/homoglyph, IP literals, userinfo, substitution with explained differences, brand on non-official domain, keyword-only hosts; SSRF guard incl. metadata address and a DNS-rebinding simulation; providers: not configured, malicious, 404, 429/503/401, timeout, cache; URL verdict rule |
| `tests/test_api.py` | Upload → job → report → history → delete; hostile file name and false Content-Type; duplicate hash; oversize rejection and cleanup; antivirus unavailable → INCONCLUSIVE; structured errors and headers; rate limit; secrets absent from every client-visible response; EICAR → MALICIOUS and benign → CLEAN_WITHIN_CHECKED_SCOPE through the API |

## How the ClamAV tests work

The official database could not be downloaded in the development sandbox, so tests create a database
containing one hash signature for the EICAR string and run the **real** `clamscan` against it. This proves the
integration (invocation, parsing, statuses). It says nothing about real-world detection coverage, which
depends on the official database on your machine. The EICAR string is assembled at runtime so the repository
does not contain it.

## Not tested

- Live VirusTotal / Safe Browsing calls; `clamdscan` mode; Docker image; Windows; the official ClamAV database.
- AI/LLM tests from the specification, because no LLM component exists. One test checks that instruction-like text inside a PDF cannot change the verdict.
- Performance, concurrency, and detection accuracy on real phishing samples.
- The UI was exercised once in headless Chromium (upload, URL scan, history; no console errors); there are no automated UI tests.
