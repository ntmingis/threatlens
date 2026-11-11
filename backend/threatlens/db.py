"""SQLite persistence: jobs, reports, provider cache. Reports store findings, never the uploaded file."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, kind TEXT, status TEXT, report_id TEXT, error TEXT, created REAL);
CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY, kind TEXT, name TEXT, sha256 TEXT, verdict TEXT, created REAL, body TEXT);
CREATE INDEX IF NOT EXISTS reports_sha ON reports(sha256);
CREATE TABLE IF NOT EXISTS cache(key TEXT PRIMARY KEY, body TEXT, expires REAL);
"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._c = sqlite3.connect(str(path), check_same_thread=False)
        self._c.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._c.executescript(SCHEMA)

    def _x(self, sql: str, args=()) -> list[sqlite3.Row]:
        with self._lock:
            cur = self._c.execute(sql, args)
            rows = cur.fetchall()
            self._c.commit()
            return rows

    # jobs
    def job_create(self, job_id: str, kind: str) -> None:
        self._x("INSERT INTO jobs VALUES(?,?,?,?,?,?)", (job_id, kind, "QUEUED", None, None, time.time()))

    def job_update(self, job_id: str, status: str, report_id: str | None = None, error: str | None = None) -> None:
        self._x("UPDATE jobs SET status=?, report_id=COALESCE(?,report_id), error=? WHERE id=?", (status, report_id, error, job_id))

    def job_get(self, job_id: str) -> dict | None:
        r = self._x("SELECT * FROM jobs WHERE id=?", (job_id,))
        return dict(r[0]) if r else None

    # reports
    def report_save(self, rep: dict) -> None:
        t = rep["target"]
        self._x("INSERT INTO reports VALUES(?,?,?,?,?,?,?)",
                (rep["report_id"], rep["kind"], t.get("filename") or t.get("normalized_url"), t.get("sha256"),
                 rep["verdict"], time.time(), json.dumps(rep)))

    def report_get(self, rid: str) -> dict | None:
        r = self._x("SELECT body FROM reports WHERE id=?", (rid,))
        return json.loads(r[0]["body"]) if r else None

    def report_delete(self, rid: str) -> bool:
        if not self._x("SELECT 1 FROM reports WHERE id=?", (rid,)):
            return False
        self._x("DELETE FROM reports WHERE id=?", (rid,))
        self._x("UPDATE jobs SET report_id=NULL WHERE report_id=?", (rid,))
        return True

    def history(self, verdict: str | None, q: str | None, kind: str | None, limit: int, offset: int) -> list[dict]:
        sql, args = "SELECT id,kind,name,sha256,verdict,created FROM reports WHERE 1=1", []
        if verdict:
            sql += " AND verdict=?"
            args.append(verdict)
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        if q:
            sql += " AND (name LIKE ? ESCAPE '\\' OR sha256 LIKE ? ESCAPE '\\')"
            like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            args += [like, like]
        sql += " ORDER BY created DESC LIMIT ? OFFSET ?"
        return [dict(r) for r in self._x(sql, (*args, limit, offset))]

    def previous_by_hash(self, sha256: str) -> list[dict]:
        return [dict(r) for r in self._x("SELECT id,verdict,created FROM reports WHERE sha256=? ORDER BY created DESC LIMIT 5", (sha256,))]

    # provider cache
    def cache_get(self, key: str) -> dict | None:
        r = self._x("SELECT body FROM cache WHERE key=? AND expires>?", (key, time.time()))
        return json.loads(r[0]["body"]) if r else None

    def cache_put(self, key: str, body: dict, ttl: int) -> None:
        self._x("INSERT OR REPLACE INTO cache VALUES(?,?,?)", (key, json.dumps(body), time.time() + ttl))
