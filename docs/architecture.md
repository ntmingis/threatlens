# Architecture

## Components

| Component | Path | Responsibility |
|---|---|---|
| UI | `frontend/` | Static HTML/CSS/JS served at `/scanner`. Renders all server data with `textContent`. |
| API | `backend/threatlens/main.py` | FastAPI app: validation, rate limit, security headers, structured errors. |
| Orchestration | `service.py` | Quarantine storage, worker launch, reputation lookups, report assembly, cleanup. |
| Worker | `worker.py` | Separate process per file: type detection, ClamAV, format analyzers. No network use. |
| Analyzers | `analyzers/` | `clamav.py`, `pdf.py`, `office.py`, `archive.py`. |
| URL analysis | `urlscan/` | `parse.py` (structure), `impersonation.py` (brands), `ssrf.py` (guard for a future fetcher). |
| Reputation | `intel/base.py` | Provider adapters with shared timeout, status mapping and cache. |
| Risk engine | `risk.py` | Deterministic verdict and recommendations from findings and engine states. |
| Storage | `db.py` | SQLite: jobs, reports, provider cache. |

## File scan sequence

1. `POST /api/scanner/files`: the upload is streamed to `data/quarantine/<random>.upload` (mode 0600) while SHA-256 is computed; the copy aborts as soon as the size limit is passed.
2. A job row is created (`QUEUED`) and a background task starts.
3. The task launches `python -m threatlens.worker <path> <display name>` with a wall-clock timeout. Inside, CPU and core-dump limits apply from the start and the address-space limit after ClamAV has run.
4. The worker prints one JSON object: file info, engine results, findings, indicators, skipped items.
5. The API process asks configured providers about the **hash only**, runs the risk engine, stores the report, marks the job `COMPLETED`.
6. The quarantined file is deleted in a `finally` block, whatever happened.

## Why these choices

- **Static frontend, no framework:** matches the portfolio site and keeps a strict CSP (`script-src 'self'`) trivial.
- **Built-in magic-byte table instead of libmagic:** identical install on Windows and Linux; the cost is a smaller format list.
- **Subprocess per scan instead of a job queue:** enough for a single-user MVP; a queue (and a network-less container per job) is the next step for multi-user use.
- **Separate repository from the portfolio:** GitHub Pages serves static files only and the portfolio's CSP forbids network calls, so a backend cannot live there.
