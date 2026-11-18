"""Locate the data directory: UNLIST_DATA_DIR, else ~/.unlist. Never inside the repo.

Everything personal lives here: the database, raw captures, screenshots, the audit
log and reports. The directory is created with mode 0700 and files are written 0600.
"""

from __future__ import annotations

import contextlib
import os
import stat
from pathlib import Path

DEFAULT_DIR = Path.home() / ".unlist"


def data_dir() -> Path:
    env = os.environ.get("UNLIST_DATA_DIR")
    base = Path(env).expanduser().resolve() if env else DEFAULT_DIR
    if not base.exists():
        base.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            base.chmod(stat.S_IRWXU)
    return base


def db_path() -> Path:
    return data_dir() / "unlist.db"


def audit_path() -> Path:
    return data_dir() / "audit.jsonl"


def shots_dir() -> Path:
    return data_dir() / "shots"


def browser_profile_dir() -> Path:
    return data_dir() / "browser"


def reports_dir() -> Path:
    return data_dir() / "reports"


def catalog_overrides_dir() -> Path:
    """Operator-written broker YAML that overrides or extends the shipped catalog."""
    return data_dir() / "catalog"


def make_private(path: Path) -> None:
    """Best-effort chmod 0600 on a file (0700 on a directory)."""
    try:
        if path.is_dir():
            path.chmod(stat.S_IRWXU)
        elif path.exists():
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
