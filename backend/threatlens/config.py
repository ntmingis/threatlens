"""Runtime configuration. Every value comes from environment variables (see .env.example)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.environ.get("THREATLENS_DATA_DIR", ROOT / "data")))
    max_upload_bytes: int = field(default_factory=lambda: _int("THREATLENS_MAX_UPLOAD_MB", 20) * 1024 * 1024)
    scan_timeout_s: int = field(default_factory=lambda: _int("THREATLENS_SCAN_TIMEOUT_S", 120))
    worker_memory_mb: int = field(default_factory=lambda: _int("THREATLENS_WORKER_MEMORY_MB", 1024))
    # ClamAV
    clamav_mode: str = field(default_factory=lambda: os.environ.get("THREATLENS_CLAMAV_MODE", "clamscan"))
    clamav_db_dir: str = field(default_factory=lambda: os.environ.get("THREATLENS_CLAMAV_DB", ""))
    clamav_timeout_s: int = field(default_factory=lambda: _int("THREATLENS_CLAMAV_TIMEOUT_S", 90))
    # Archive limits
    archive_max_entries: int = field(default_factory=lambda: _int("THREATLENS_ARCHIVE_MAX_ENTRIES", 2000))
    archive_max_depth: int = field(default_factory=lambda: _int("THREATLENS_ARCHIVE_MAX_DEPTH", 2))
    archive_max_total_bytes: int = field(default_factory=lambda: _int("THREATLENS_ARCHIVE_MAX_TOTAL_MB", 200) * 1024 * 1024)
    archive_max_ratio: int = field(default_factory=lambda: _int("THREATLENS_ARCHIVE_MAX_RATIO", 100))
    # PDF limits
    pdf_max_pages: int = field(default_factory=lambda: _int("THREATLENS_PDF_MAX_PAGES", 300))
    pdf_max_objects: int = field(default_factory=lambda: _int("THREATLENS_PDF_MAX_OBJECTS", 50000))
    # Threat intelligence (backend only; never sent to the browser)
    virustotal_api_key: str = field(default_factory=lambda: os.environ.get("VIRUSTOTAL_API_KEY", ""))
    gsb_api_key: str = field(default_factory=lambda: os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", ""))
    intel_timeout_s: int = field(default_factory=lambda: _int("THREATLENS_INTEL_TIMEOUT_S", 10))
    intel_cache_ttl_s: int = field(default_factory=lambda: _int("THREATLENS_INTEL_CACHE_TTL_S", 6 * 3600))
    vt_malicious_threshold: int = field(default_factory=lambda: _int("THREATLENS_VT_MALICIOUS_THRESHOLD", 3))
    # URL scanning
    resolve_dns: bool = field(default_factory=lambda: _bool("THREATLENS_RESOLVE_DNS", False))
    brands_file: Path = field(default_factory=lambda: Path(os.environ.get("THREATLENS_BRANDS_FILE", ROOT / "config" / "brands.json")))
    # API
    cors_origins: list[str] = field(default_factory=lambda: [o.strip() for o in os.environ.get("THREATLENS_CORS_ORIGINS", "").split(",") if o.strip()])
    rate_limit_per_min: int = field(default_factory=lambda: _int("THREATLENS_RATE_LIMIT_PER_MIN", 20))

    @property
    def quarantine_dir(self) -> Path:
        return self.data_dir / "quarantine"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "threatlens.sqlite3"


def get_settings() -> Settings:
    return Settings()
