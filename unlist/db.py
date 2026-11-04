"""One database for everything. open_db() connects and applies every package's migrations."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from unlist.core import store

PACKAGE_DIR = Path(__file__).parent

# Order matters: later packages reference earlier tables.
MIGRATION_DIRS = [
    PACKAGE_DIR / "subjects" / "migrations",
    PACKAGE_DIR / "scanners" / "migrations",
    PACKAGE_DIR / "requests" / "migrations",
    PACKAGE_DIR / "monitor" / "migrations",
]


def open_db(path: Path | str | None = None) -> sqlite3.Connection:
    conn = store.connect(path)
    store.migrate(conn, [d for d in MIGRATION_DIRS if d.is_dir()])
    return conn
