# URL analysis

No request is sent to the submitted URL.

## Parsing

Only `http` and `https` are accepted; whitespace and control characters are rejected. A bare domain is treated as `http://`.
The report shows scheme, host (ASCII and Unicode forms), registrable domain, port, path, query.

## Structural findings

| Signal | Severity | Note |
|---|---|---|
| Userinfo before `@` | HIGH | `trusted.example@evil.example` goes to `evil.example` |
| IP literal | MEDIUM | |
| IP in decimal / hex / octal form | HIGH | `http://2130706433/` is `127.0.0.1` |
| Punycode host | MEDIUM | decoded form shown |
| One label mixing scripts | HIGH | each non-ASCII character is named |
| Known shortener | LOW | destination unknown |
| HTTP, odd port, double encoding, embedded URL in query | LOW | |
| Many subdomains, long URL, words like "login" | INFO | weak signals, never decisive |

## Brand impersonation

`config/brands.json` lists brands and their official domains. For other domains, each hostname token is compared with each brand:

1. **Skeleton equals brand, raw text differs** (digit swaps `0→o 1→l 3→e 5→s`, capital `I` for `l`, `rn→m`, Cyrillic/Greek look-alikes) → HIGH, with the position and Unicode name of each differing character.
2. **Exact brand name on a non-official domain** (`paypal-security.example`, `paypal.com.evil.example`) → MEDIUM.
3. **One edit away** (insert, delete, replace, swap; brands of 5+ letters) → MEDIUM, low confidence.

## Reputation

Providers implement `lookup_url` / `lookup_hash` and return an engine status plus findings.
VirusTotal: `GET /api/v3/urls/{base64url(url)}` and `/files/{sha256}`; `malicious >= 3` engines (configurable) → MALICIOUS; 404 means "unknown", stated as such.
Google Safe Browsing: `threatMatches:find` (v4). Results are cached for 6 hours.
Both adapters were written from the public API documentation and tested with mocked HTTP only.

## SSRF guard

`urlscan/ssrf.py` resolves a host and refuses loopback, private, link-local (incl. `169.254.169.254`), CGNAT, multicast, reserved and IPv4-mapped addresses; one bad DNS answer is enough to refuse. It returns the validated IPs so a fetcher can pin them. No fetcher exists yet.
