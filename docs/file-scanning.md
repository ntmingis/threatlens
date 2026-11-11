# File scanning

## Validation

- **Type:** `filetype.py` reads the first 4 KB and matches signatures: PDF, ZIP (then OOXML by member names), OLE, PNG, JPEG, GIF, PE, ELF, Mach-O, gzip, 7z, RAR, `#!` scripts, UTF-8 text. Anything else is `unknown`.
- **Mismatch:** if the extension maps to a known format and the content differs → `FILE_TYPE_MISMATCH` (HIGH when the content is executable, else MEDIUM).
- **Double extension:** `name.pdf.exe` style → `DOUBLE_EXTENSION` (HIGH).
- **Storage:** `data/quarantine/<uuid>.upload`, directory 0700, file 0600, deleted after the scan. There is no endpoint that returns the file.

## ClamAV

`clamscan --no-summary --stdout --database=<dir> --alert-exceeds-max=yes --max-filesize … --max-scansize … --max-files … --max-recursion … <file>`

| Situation | Engine status | Effect on verdict |
|---|---|---|
| Exit 1 with a signature | COMPLETED + `MALWARE_SIGNATURE` (CRITICAL) | MALICIOUS |
| Exit 0 | COMPLETED, "No detection in completed scan." | no effect |
| `Heuristics.Limits.Exceeded` | PARTIAL | cannot be clean |
| Binary not on PATH | NOT_INSTALLED | cannot be clean |
| No database files | DB_MISSING | cannot be clean |
| Timeout | TIMEOUT | cannot be clean |
| Exit 2 | ERROR | cannot be clean |

The version string (engine / database version / database date) is stored in the report.

## Office (OOXML)

Reports `OFFICE_MACRO_PRESENT` (presence of `vbaProject.bin`), `OFFICE_EMBEDDED_OBJECT`, and
`OFFICE_EXTERNAL_REFERENCE` for relationships with `TargetMode="External"` (HIGH for attached templates,
OLE objects, frames, sub-documents). Hyperlink relationships go through the URL analyzer.
"Macro suspicious" is not assessed; "macro malicious" is only ever stated by an antivirus signature.

## ZIP

Inspected through the central directory and in-memory nested reads; no file is written to disk.
Limits: entries (2000), nesting depth (2), total uncompressed size (200 MB), compression ratio (100:1), configurable.
Exceeding a limit sets the engine to PARTIAL, lists the uninspected component, and prevents a clean verdict.
