# Risk scoring

The verdict is a pure function of findings and engine states (`risk.py`). First matching rule wins.

| # | Condition | Verdict |
|---|---|---|
| 1 | Any finding in `MALWARE_SIGNATURE` or `THREAT_INTEL_MALICIOUS` | MALICIOUS |
| 2 | Any finding with severity MEDIUM or higher | SUSPICIOUS |
| 3 | Any **required** engine not `COMPLETED` (ClamAV, the format analyzer, the worker) | INCONCLUSIVE |
| 4 | URL scan and no reputation provider answered | INCONCLUSIVE |
| 5 | Otherwise | CLEAN_WITHIN_CHECKED_SCOPE |

Consequences:

- A missing antivirus engine can never produce a clean file verdict.
- A URL can only be clean-within-scope when at least one reputation source answered and found nothing.
- LOW and INFO findings never change the verdict by themselves; they are context.
- When rule 1 or 2 fires while some engine was incomplete, the report says so.

There is no numeric score: a number would suggest a precision the heuristics do not have.

## Severity guide

| Severity | Meaning | Examples |
|---|---|---|
| CRITICAL | Direct evidence of malice | Signature match, reputation listing |
| HIGH | Strong deception indicator | Link mismatch, look-alike domain, userinfo trick, disguised executable |
| MEDIUM | Capability that is often abused | PDF JavaScript, macro present, executable in archive, IP-literal URL |
| LOW | Weak signal | Urgency wording, HTTP, shortener |
| INFO | Context | Form fields, generic keywords |

Severity thresholds were chosen by judgement, not calibrated on a labelled dataset. False-positive and false-negative rates are **not measured** in v0.1.
