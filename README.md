# ThreatLens

File & URL threat-intelligence scanner. Upload a file or paste a URL and get an evidence-based risk
report before you open it. Defensive tool; static analysis only.

> ThreatLens supports risk assessment. It **cannot** establish that a file or website is safe.

**Status: v0.1 MVP.** See [Known limitations](#known-limitations) for what is and is not verified.

## Features

| Area | What it does |
|---|---|
| File validation | Detects the real type from magic bytes (ignores the browser's Content-Type and the extension), SHA-256, size limit, extension/content mismatch, double extensions |
| Antivirus | Runs the local **ClamAV** engine. Missing engine, missing database, timeout or exceeded limits are reported as such and block a "clean" result |
| PDF | Metadata, JavaScript / OpenAction / Launch / embedded files / forms, every hyperlink with its page, **displayed text vs. real destination mismatch**, urgency and credential wording |
| Office (OOXML) | Macro project presence, embedded objects, external relationships (remote templates, OLE links), hyperlinks |
| ZIP | Inspects without extracting: executables, double extensions, path-traversal names, compression-bomb ratio, nesting, encrypted entries, with hard limits |
| URL | Structure checks (userinfo trick, IP literals incl. decimal/hex forms, punycode, mixed scripts, shorteners), brand look-alike detection with an explanation of which characters differ |
| Reputation | Optional VirusTotal (hash and URL lookup) and Google Safe Browsing adapters, cached, with explicit `NOT_CONFIGURED` / `QUOTA_EXCEEDED` / `UNAVAILABLE` states |
| Reports | Verdict, findings with evidence, engines that ran, what was skipped, recommendations; history, JSON export, delete |

Verdicts: `MALICIOUS`, `SUSPICIOUS`, `INCONCLUSIVE`, `CLEAN_WITHIN_CHECKED_SCOPE` (rules in [docs/risk-scoring.md](docs/risk-scoring.md)).
No language model takes part in detection.

## Architecture

```
Browser (/scanner, vanilla JS, strict CSP)
   │  multipart upload / JSON
FastAPI app ── rate limit ── quarantine dir (random name, 0600, deleted after scan)
   │  subprocess, timeout + rlimits, no network use
Worker ── file type ── ClamAV ── PDF | Office | ZIP analyzers ── URL heuristics on extracted links
   │  findings (JSON)
API process ── hash/URL reputation (optional) ── risk engine ── SQLite report
```

Details: [docs/architecture.md](docs/architecture.md), [docs/threat-model.md](docs/threat-model.md).

## Installation

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync                      # creates .venv and installs dependencies
```

### ClamAV

| OS | Install | Signature database |
|---|---|---|
| Ubuntu/Debian | `sudo apt install clamav` | `sudo freshclam` |
| Windows | Installer from clamav.net; add its folder to `PATH` | run `freshclam.exe` (needs `freshclam.conf`) |
| macOS | `brew install clamav` | `freshclam` |

Check `GET /api/scanner/capabilities`: `clamav.status` must be `READY`. Until then every file scan is `INCONCLUSIVE` by design.

### Environment variables

Copy `.env.example` to `.env`. All settings are optional; API keys stay on the server and are never sent to the browser.

## Running locally

```bash
cd backend
uv run uvicorn threatlens.main:app --host 127.0.0.1 --port 8000
# open http://127.0.0.1:8000/scanner     API docs: /api/scanner/docs
```

Keep it bound to `127.0.0.1`: v0.1 has no authentication.

## Running with Docker

`Dockerfile` and `docker-compose.yml` are provided (non-root user, read-only root, all capabilities dropped,
loopback-only port) but were **not built or tested** during v0.1 development.

## Running tests

```bash
uv run pytest -q
```

Tests use generated fixtures, `.test` domains, mocked reputation providers and the EICAR test string with a
one-line local ClamAV signature. No real malware and no external service is involved. Tests that need
`clamscan` are skipped when it is not installed. See [docs/testing.md](docs/testing.md).

## Known limitations

- **No dynamic analysis.** Files are never executed; behaviour is unknown.
- **URLs are never fetched.** Page content, redirects and TLS certificates are not examined. Without a reputation key a URL can only be `SUSPICIOUS` or `INCONCLUSIVE`.
- **Macros: presence only.** Macro code is not decompressed or judged.
- **Not implemented:** OCR, QR-code decoding, legacy `.doc/.xls/.ppt` parsing, RAR/7z/gzip unpacking, LLM explanations, authentication.
- **Reputation adapters are tested against mocks only**, never against the live VirusTotal or Safe Browsing services.
- **`clamdscan` mode, Docker and Windows** were not exercised; development and tests ran on Linux with `clamscan` 1.5.4.
- **Registrable-domain logic** uses a short suffix list, not the full Public Suffix List; the confusable-character table is a small subset of Unicode TR39.
- **Process isolation is not a sandbox.** The worker is a separate process with CPU/memory limits (POSIX only); a parser exploit would still run with the service account's rights. Use the container for stronger isolation.
- Rate limiting is in-memory and per process.

## Security disclaimers

ThreatLens parses hostile input. Run it on a machine you can afford to rebuild, keep PyMuPDF and ClamAV
updated, and do not expose it to the internet without authentication in front of it.
A `CLEAN_WITHIN_CHECKED_SCOPE` result means only that the completed checks found nothing.

## Licence and attribution

AGPL-3.0-or-later, because PyMuPDF is AGPL-licensed. Scaffolding was written with AI assistance;
see the commit history and `docs/` for what was reviewed and tested.
