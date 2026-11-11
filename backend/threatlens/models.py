"""Shared data contracts. Findings are produced ONLY by deterministic engines, never by an LLM."""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


SEVERITY_ORDER = {s: i for i, s in enumerate(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])}


class Verdict(str, Enum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN_WITHIN_CHECKED_SCOPE = "CLEAN_WITHIN_CHECKED_SCOPE"
    INCONCLUSIVE = "INCONCLUSIVE"


class EngineStatus(str, Enum):
    COMPLETED = "COMPLETED"          # ran to the end over the whole input
    PARTIAL = "PARTIAL"              # ran, but part of the input was not inspected
    SKIPPED = "SKIPPED"              # not applicable or deliberately not run
    NOT_INSTALLED = "NOT_INSTALLED"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    DB_MISSING = "DB_MISSING"
    TIMEOUT = "TIMEOUT"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"


class Finding(BaseModel):
    category: str
    severity: Severity
    title: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    source: str
    confidence: str = "MEDIUM"  # LOW | MEDIUM | HIGH


class EngineResult(BaseModel):
    name: str
    status: EngineStatus
    detail: str = ""
    version: str | None = None
    duration_ms: int | None = None
    required: bool = False  # if True, a non-COMPLETED status forbids a CLEAN verdict


class UrlScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)


class JobOut(BaseModel):
    job_id: str
    kind: str
    status: str
    report_id: str | None = None
    error: str | None = None


def f(category: str, severity: str, title: str, description: str, source: str,
      confidence: str = "MEDIUM", **evidence: Any) -> dict:
    """Build a validated finding dict."""
    return Finding(category=category, severity=Severity(severity), title=title, description=description,
                   evidence=evidence, source=source, confidence=confidence).model_dump(mode="json")
