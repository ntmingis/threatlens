# API reference

Base path `/api/scanner`. Interactive schema: `/api/scanner/docs`. Errors: `{"error": {"code": "...", "message": "..."}}`.

| Method | Path | Purpose | Notes |
|---|---|---|---|
| POST | `/files` | Upload a file (multipart field `file`) | 202 → `{job_id, kind, status}`; 413 `FILE_TOO_LARGE`; 429 `RATE_LIMITED` |
| POST | `/urls` | Analyse `{ "url": "..." }` | 200 → full report (synchronous); 400 `INVALID_URL` |
| GET | `/jobs/{job_id}` | Job state | `QUEUED`, `RUNNING`, `COMPLETED` (+`report_id`), `FAILED` (+`error`) |
| GET | `/reports/{report_id}` | Full report JSON | 404 `NOT_FOUND` |
| DELETE | `/reports/{report_id}` | Delete a report | |
| GET | `/history` | List reports | `verdict`, `kind`, `q` (name/URL/hash), `limit`, `offset` |
| GET | `/health` | Liveness | |
| GET | `/capabilities` | Engine and provider readiness | never includes keys |

## Report fields

`report_id`, `kind`, `created_at`, `tool_version`, `target`, `verdict`, `verdict_reasons[]`, `findings[]`,
`engines[]`, `engines_not_available[]`, `items_skipped[]`, `recommendations[]`, `disclaimer`;
files add `analysis.pdf`, `indicators`, `previous_reports_same_hash[]`, `retention`.

Finding: `category`, `severity`, `title`, `description`, `evidence{}`, `source`, `confidence`.
Engine: `name`, `status`, `detail`, `version`, `duration_ms`, `required`.
