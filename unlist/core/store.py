"""SQLite helpers: connection, plain-SQL migrations, raw and text file storage, captures."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from unlist import paths
from unlist.core.timeutil import now_iso, parse_dt

CORE_MIGRATIONS = Path(__file__).parent / "migrations"

_EXT_BY_TYPE = {
    "text/html": "html",
    "application/xhtml+xml": "html",
    "text/plain": "txt",
    "application/json": "json",
    "application/pdf": "pdf",
    "application/xml": "xml",
    "text/xml": "xml",
    "image/png": "png",
}


def connect(db: Path | str | None = None) -> sqlite3.Connection:
    path = Path(db) if db else paths.db_path()
    memory = str(path) == ":memory:"
    if not memory:
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if not memory:
        conn.execute("PRAGMA journal_mode = WAL")
        paths.make_private(path)
    return conn


def migrate(conn: sqlite3.Connection, extra_dirs: Iterable[Path] = ()) -> list[str]:
    """Apply every .sql file (sorted by name) from core plus the given directories.

    Each file is applied at most once, tracked in schema_migrations by
    '<package>/<filename>'. Returns the names applied in this call.
    """
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations "
        "(name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    done = {r[0] for r in conn.execute("SELECT name FROM schema_migrations")}
    applied: list[str] = []
    for directory in (CORE_MIGRATIONS, *extra_dirs):
        directory = Path(directory)
        key_prefix = directory.parent.name if directory.name == "migrations" else directory.name
        for sql_file in sorted(directory.glob("*.sql")):
            name = f"{key_prefix}/{sql_file.name}"
            if name in done:
                continue
            conn.executescript(sql_file.read_text(encoding="utf-8"))
            conn.execute(
                "INSERT INTO schema_migrations(name, applied_at) VALUES (?, ?)", (name, now_iso())
            )
            applied.append(name)
    conn.commit()
    return applied


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ext_for(content_type: str | None, url: str = "") -> str:
    ct = (content_type or "").split(";")[0].strip().lower()
    if ct in _EXT_BY_TYPE:
        return _EXT_BY_TYPE[ct]
    tail = url.split("?")[0].rsplit(".", 1)
    if len(tail) == 2 and 1 < len(tail[1]) <= 5 and tail[1].isalnum():
        return tail[1].lower()
    return "bin"


def raw_path_for(
    tool: str, sha256: str, ext: str, captured_at: str, data_dir: Path | None = None
) -> Path:
    """<data>/raw/<tool>/<yyyy>/<mm>/<dd>/<sha256>.<ext>, dated by the capture time (UTC)."""
    base = data_dir or paths.data_dir()
    dt = parse_dt(captured_at)
    if dt is None:
        raise ValueError(f"captured_at not parseable: {captured_at!r}")
    return base / "raw" / tool / f"{dt:%Y}" / f"{dt:%m}" / f"{dt:%d}" / f"{sha256}.{ext}"


def write_raw(path: Path, data: bytes) -> Path:
    """Write raw bytes once. An existing file is never touched (rule: never modify raw)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        existing = path.read_bytes()
        if sha256_hex(existing) != sha256_hex(data):
            raise RuntimeError(f"raw file exists with different content: {path}")
        return path
    tmp = path.with_suffix(path.suffix + ".part")
    tmp.write_bytes(data)
    tmp.replace(path)
    paths.make_private(path)
    return path


def text_path_for(raw_path: Path) -> Path:
    """Mirror of the raw path under <data>/text with a .txt suffix."""
    parts = list(raw_path.parts)
    try:
        idx = len(parts) - 1 - parts[::-1].index("raw")
    except ValueError:
        return raw_path.with_suffix(".txt")
    parts[idx] = "text"
    return Path(*parts).with_suffix(".txt")


def write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    paths.make_private(path)
    return path


@dataclass
class CaptureRow:
    tool: str
    requested_url: str
    final_url: str
    status: int | None
    captured_at: str
    sha256: str
    raw_path: str
    text_path: str | None = None
    shot_path: str | None = None
    kind: str = "fetch"  # fetch | refusal | error | browser | manual_import
    headers_json: str | None = None
    note: str | None = None


def insert_capture(conn: sqlite3.Connection, row: CaptureRow) -> int:
    cur = conn.execute(
        """INSERT INTO captures(tool, requested_url, final_url, status, captured_at, sha256,
                                raw_path, text_path, shot_path, kind, headers_json, note)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            row.tool,
            row.requested_url,
            row.final_url,
            row.status,
            row.captured_at,
            row.sha256,
            row.raw_path,
            row.text_path,
            row.shot_path,
            row.kind,
            row.headers_json,
            row.note,
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def get_capture(conn: sqlite3.Connection, capture_id: int) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM captures WHERE id = ?", (capture_id,)).fetchone()


def headers_to_json(headers) -> str:
    """Serialise headers (mapping or list of pairs) as a sorted JSON object of lists."""
    out: dict[str, list[str]] = {}
    items = headers.multi_items() if hasattr(headers, "multi_items") else dict(headers).items()
    for k, v in items:
        out.setdefault(str(k).lower(), []).append(str(v))
    return json.dumps(out, ensure_ascii=False, sort_keys=True)
