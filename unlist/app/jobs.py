"""One background worker for the slow things (scans, sends, polls, monitor runs).

Jobs run one at a time so the database and the per-host rate limiters behave as they
do from the MCP tools. Each job gets its own connection and a log() the Jobs page
shows while it runs. Nothing queued survives a restart: on start-up anything still
queued or running is marked abandoned.
"""

from __future__ import annotations

import json
import queue
import sqlite3
import threading
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from unlist.core.timeutil import now_iso
from unlist.db import open_db


@dataclass
class JobContext:
    job_id: int
    conn: sqlite3.Connection
    _lines: list[str] = field(default_factory=list)

    def log(self, line: str) -> None:
        self._lines.append(line.rstrip("\n"))
        self.conn.execute(
            "UPDATE app_jobs SET log = ? WHERE id = ?", ("\n".join(self._lines), self.job_id)
        )
        self.conn.commit()


JobFn = Callable[[JobContext], str | None]


class JobRunner:
    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = db_path
        self._queue: queue.Queue[tuple[int, JobFn]] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        conn = self.connect()
        conn.execute(
            "UPDATE app_jobs SET status = 'abandoned', finished_at = ? "
            "WHERE status IN ('queued', 'running')",
            (now_iso(),),
        )
        conn.commit()
        conn.close()

    def connect(self) -> sqlite3.Connection:
        return open_db(self.db_path)

    def start(self) -> None:
        if self._thread is None or not self._thread.is_alive():
            self._stop.clear()
            self._thread = threading.Thread(target=self._worker, name="unlist-jobs", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def submit(self, name: str, fn: JobFn, params: dict | None = None) -> int:
        conn = self.connect()
        cur = conn.execute(
            "INSERT INTO app_jobs(name, params_json, status, created_at) VALUES (?,?,?,?)",
            (name, json.dumps(params or {}, ensure_ascii=False), "queued", now_iso()),
        )
        job_id = int(cur.lastrowid)
        conn.commit()
        conn.close()
        self._queue.put((job_id, fn))
        return job_id

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                job_id, fn = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            conn = self.connect()
            conn.execute(
                "UPDATE app_jobs SET status='running', started_at=? WHERE id=?",
                (now_iso(), job_id),
            )
            conn.commit()
            ctx = JobContext(job_id=job_id, conn=conn)
            try:
                result = fn(ctx) or ""
                status = "done"
            except Exception:
                result = traceback.format_exc()[-2000:]
                status = "failed"
            conn.execute(
                "UPDATE app_jobs SET status=?, finished_at=?, result=? WHERE id=?",
                (status, now_iso(), result, job_id),
            )
            conn.commit()
            conn.close()

    @staticmethod
    def get(conn: sqlite3.Connection, job_id: int) -> sqlite3.Row | None:
        return conn.execute("SELECT * FROM app_jobs WHERE id=?", (job_id,)).fetchone()

    @staticmethod
    def recent(conn: sqlite3.Connection, limit: int = 40) -> list[sqlite3.Row]:
        return conn.execute("SELECT * FROM app_jobs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
