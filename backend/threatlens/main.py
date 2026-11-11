"""ThreatLens API and UI server (FastAPI). Run: uvicorn threatlens.main:app --host 127.0.0.1 --port 8000"""
from __future__ import annotations

import shutil
import threading
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import __version__, service
from .analyzers import clamav
from .config import ROOT, Settings, get_settings
from .db import Store
from .models import JobOut, UrlScanRequest, Verdict
from .urlscan.parse import UrlError

FRONTEND = ROOT / "frontend"
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class RateLimiter:
    """In-memory sliding window per client IP. Limitation: per process, and trusts the socket peer address."""

    def __init__(self, per_min: int):
        self.per_min, self.hits, self.lock = per_min, defaultdict(deque), threading.Lock()

    def check(self, key: str) -> bool:
        now = time.time()
        with self.lock:
            q = self.hits[key]
            while q and q[0] < now - 60:
                q.popleft()
            if len(q) >= self.per_min:
                return False
            q.append(now)
            return True


def create_app(cfg: Settings | None = None, intel_transport=None) -> FastAPI:
    cfg = cfg or get_settings()
    store = Store(cfg.db_path)
    limiter = RateLimiter(cfg.rate_limit_per_min)
    app = FastAPI(title="ThreatLens", version=__version__, docs_url="/api/scanner/docs", redoc_url=None,
                  openapi_url="/api/scanner/openapi.json")
    app.state.cfg, app.state.store = cfg, store
    if cfg.cors_origins:
        app.add_middleware(CORSMiddleware, allow_origins=cfg.cors_origins, allow_methods=["GET", "POST", "DELETE"],
                           allow_headers=["Content-Type"], allow_credentials=False)

    def err(status: int, code: str, message: str) -> JSONResponse:
        return JSONResponse(status_code=status, content={"error": {"code": code, "message": message}})

    @app.exception_handler(HTTPException)
    async def _http(_: Request, e: HTTPException):
        d = e.detail if isinstance(e.detail, dict) else {"code": "HTTP_ERROR", "message": str(e.detail)}
        return JSONResponse(status_code=e.status_code, content={"error": d})

    @app.exception_handler(RequestValidationError)
    async def _val(_: Request, e: RequestValidationError):
        return err(422, "INVALID_REQUEST", "Request body or parameters are invalid.")

    @app.exception_handler(Exception)
    async def _any(_: Request, e: Exception):  # no stack trace or exception text reaches the client
        return err(500, "INTERNAL_ERROR", "An internal error occurred.")

    @app.middleware("http")
    async def _headers(request: Request, call_next):
        resp = await call_next(request)
        if not request.url.path.startswith("/api/scanner/docs"):
            resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        if request.url.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def limited(request: Request) -> None:
        if not limiter.check(request.client.host if request.client else "unknown"):
            raise HTTPException(429, {"code": "RATE_LIMITED", "message": "Too many scan requests. Try again in a minute."})

    def fail(status: int, code: str, message: str):
        raise HTTPException(status, {"code": code, "message": message})

    # ---------- UI ----------
    @app.get("/", include_in_schema=False)
    def _root():
        return RedirectResponse("/scanner")

    @app.get("/scanner", include_in_schema=False)
    def _ui():
        return FileResponse(FRONTEND / "index.html", media_type="text/html")

    app.mount("/scanner/static", StaticFiles(directory=FRONTEND), name="static")

    # ---------- API ----------
    @app.post("/api/scanner/files", response_model=JobOut, status_code=202, dependencies=[Depends(limited)])
    def scan_file(background: BackgroundTasks, file: UploadFile = File(...)):
        name = service.safe_display_name(file.filename)
        try:
            path, sha256, size = service.store_upload(file.file, cfg)
        except service.UploadTooLarge:
            fail(413, "FILE_TOO_LARGE", f"File exceeds the {cfg.max_upload_bytes // (1024 * 1024)} MB limit.")
        job_id = uuid.uuid4().hex
        store.job_create(job_id, "file")
        background.add_task(service.scan_file_job, job_id, path, name, sha256, size, cfg, store, intel_transport)
        return JobOut(job_id=job_id, kind="file", status="QUEUED")

    @app.post("/api/scanner/urls", dependencies=[Depends(limited)])
    def scan_url(body: UrlScanRequest):
        try:
            return service.scan_url(body.url, cfg, store, intel_transport)
        except UrlError as e:
            fail(400, "INVALID_URL", str(e))

    @app.get("/api/scanner/jobs/{job_id}", response_model=JobOut)
    def job(job_id: str):
        j = store.job_get(job_id)
        if not j:
            fail(404, "NOT_FOUND", "Job not found.")
        return JobOut(job_id=j["id"], kind=j["kind"], status=j["status"], report_id=j["report_id"], error=j["error"])

    @app.get("/api/scanner/reports/{report_id}")
    def report(report_id: str):
        r = store.report_get(report_id)
        if not r:
            fail(404, "NOT_FOUND", "Report not found.")
        return r

    @app.delete("/api/scanner/reports/{report_id}")
    def delete_report(report_id: str):
        if not store.report_delete(report_id):
            fail(404, "NOT_FOUND", "Report not found.")
        return {"deleted": report_id}

    @app.get("/api/scanner/history")
    def history(verdict: Verdict | None = None, q: str | None = Query(None, max_length=200),
                kind: str | None = Query(None, pattern="^(file|url)$"),
                limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
        return {"items": store.history(verdict.value if verdict else None, q, kind, limit, offset)}

    @app.get("/api/scanner/health")
    def health():
        return {"status": "ok", "version": __version__}

    @app.get("/api/scanner/capabilities")
    def capabilities():
        binary = shutil.which("clamdscan" if cfg.clamav_mode == "clamdscan" else "clamscan")
        db = clamav._db_dir(cfg) if binary else None
        av = "NOT_INSTALLED" if not binary else ("READY" if (db or cfg.clamav_mode == "clamdscan") else "DB_MISSING")
        return {"version": __version__, "max_upload_mb": cfg.max_upload_bytes // (1024 * 1024),
                "engines": {"clamav": {"status": av, "mode": cfg.clamav_mode,
                                       "version": clamav._version(binary, db) if binary else None},
                            "pdf_static_analysis": "READY", "office_ooxml_analysis": "READY", "zip_analysis": "READY",
                            "legacy_office_analysis": "NOT_IMPLEMENTED", "ocr": "NOT_IMPLEMENTED",
                            "qr_decoding": "NOT_IMPLEMENTED", "url_fetch": "NOT_IMPLEMENTED",
                            "llm_explanation": "NOT_IMPLEMENTED"},
                "providers": {"virustotal": "CONFIGURED" if cfg.virustotal_api_key else "NOT_CONFIGURED",
                              "google_safe_browsing": "CONFIGURED" if cfg.gsb_api_key else "NOT_CONFIGURED"},
                "dns_resolution": cfg.resolve_dns}

    return app


app = create_app()
