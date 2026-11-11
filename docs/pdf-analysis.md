# PDF analysis

Library: PyMuPDF. The document is opened read-only; no action, script or link is triggered.

## What is extracted

- **Metadata:** title, author, creator, producer, creation/modification dates, page count, encryption, form flag, embedded file names.
- **Active content:** each object dictionary (up to 50,000) is searched for `/JavaScript` `/JS`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`, `/SubmitForm`, `/GoToR` `/GoToE`, `/RichMedia`, `/XFA`. Findings carry the object numbers.
- **Links:** every URI annotation with its page, annotation object number and the text under its rectangle; plus URLs written in the page text.
- **Indicators:** email addresses, phone-like numbers, domains.

## Phishing checks

| Check | Finding | Severity |
|---|---|---|
| Visible text names one domain, link goes to another registrable domain | `PDF_PHISHING` "Hyperlink destination mismatch" | HIGH |
| Link host imitates a configured brand | `BRAND_IMPERSONATION` | HIGH / MEDIUM |
| Punycode, mixed scripts, userinfo, IP literal, shortener | URL findings with page context | varies |
| Requests for password / OTP / card data | `PDF_CREDENTIAL_REQUEST` | MEDIUM |
| Urgency / verification wording | `PDF_PRESSURE_LANGUAGE` | LOW |

JavaScript and forms are indicators, not verdicts: JavaScript alone yields `SUSPICIOUS`, never `MALICIOUS`.

## Limits and gaps

- Password-protected PDFs: engine PARTIAL, `PDF_ENCRYPTED`, nothing else inspected.
- More than 300 pages: the rest is listed as not inspected.
- Image-only PDFs: `PDF_NO_TEXT`; OCR and QR decoding are not implemented.
- Stream contents (for example the body of a script) are not decoded; only object dictionaries are searched, so obfuscated names (`/J#61vaScript`) may be missed unless MuPDF normalises them.
- The mismatch check needs the visible text to contain a URL or domain; "Click here" links are judged only by their destination.
