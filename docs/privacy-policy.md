# Privacy

- **Uploads** are written to `data/quarantine/` under a random name and deleted when the scan ends, including on failure. They are not retrievable through the API.
- **Reports** (file name, size, SHA-256, extracted links, email addresses and phone-like numbers found in the document, findings) are kept in `data/threatlens.sqlite3` until deleted from the UI or API. There is no automatic expiry in v0.1.
- **Third parties:** nothing is sent anywhere unless an API key is configured. With a key, VirusTotal receives the file's SHA-256 or the submitted URL; Google Safe Browsing receives the submitted URL. File content is never uploaded.
- **DNS:** off by default. If `THREATLENS_RESOLVE_DNS=true`, your resolver sees the domains you check.
- **Logs:** the application does not log file contents or keys. The web server's access log records paths, not bodies.
- The provider cache stores provider verdicts keyed by hash/URL for 6 hours.
