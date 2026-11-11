# Threat model

Scope: ThreatLens v0.1 running on one machine, bound to loopback, used by its owner.

## Assets

- The host running the scanner (integrity, availability).
- API keys for reputation providers.
- Report history (file names, hashes, URLs: may reveal what the user receives).

## Trust boundaries

| Boundary | Untrusted side | Control |
|---|---|---|
| Browser → API | Upload bytes, file name, Content-Type, URL string | Size cap during streaming, name used for display only, type from content, Pydantic validation, rate limit |
| API → worker | The stored file | Separate process, timeout, rlimits (POSIX), random file name, no execute bit, never executed |
| Worker → parsers | PDF / ZIP / OOXML structure | Object, page, entry, depth, size and ratio limits; ZIP inspected in memory, nothing extracted to disk; regex instead of XML parser |
| File content → report | Text, links and metadata inside the file | Treated as data: rendered with `textContent`, never interpreted; no LLM in the loop |
| API → providers | Provider responses | Timeout, status mapping, shape checks; a failed provider never yields "clean" |

## Threats and status

| Threat | Mitigation | Residual risk |
|---|---|---|
| Parser exploit in PyMuPDF/ClamAV | Process isolation, limits, optional hardened container | **High impact if it happens**: code would run as the service user. Process isolation is not a sandbox |
| Decompression bomb | Entry/size/ratio/depth limits; ClamAV limits; memory limit | Limits are heuristics; tune for your host |
| Path traversal via archive names | Nothing is extracted | None for ThreatLens itself; a finding warns the user |
| Stored XSS via file name / PDF text | `textContent` everywhere, strict CSP | Low |
| SSRF | URLs are not fetched. `ssrf.py` guard is tested for a future fetcher | DNS lookup (off by default) discloses the domain to the resolver |
| Secret leakage | Keys read from env on the server; never in responses or UI; VT key sent as header | Keys could appear in a proxy's logs for Safe Browsing (key is a query parameter by API design) |
| Abuse / DoS | Per-IP rate limit, upload cap, timeouts | In-memory limiter; no auth |
| Re-distribution of malware | No download endpoint; upload deleted after scan | None |
| Prompt injection | No LLM component exists | Applies if an explanation layer is added: it must receive findings only |
| False reassurance | `INCONCLUSIVE` when a required engine is missing; `CLEAN_WITHIN_CHECKED_SCOPE` wording; disclaimer on every report | Users may still over-trust a green result |

## Out of scope in v0.1

Authentication and multi-tenancy, TLS termination, audit logging, dynamic analysis.
