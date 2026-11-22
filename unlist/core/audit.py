"""Append-only, hash-chained audit log of everything the tool did on your behalf.

Every scan, confirmation, approval, send and submission writes a line here. Each
entry carries the hash of the previous one, so a deleted or edited line is
detectable. This is tamper-evidence against the realistic case (a line quietly
dropped later), not protection against someone who can rewrite the whole file.

Copied from casework (same author, MIT).
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

try:
    import fcntl
except ImportError:  # pragma: no cover - not available on Windows
    fcntl = None  # type: ignore[assignment]

from unlist import paths

GENESIS = "0" * 64
_TAIL_BYTES = 65536
_LOCK = threading.Lock()


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


class AuditLog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or paths.audit_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self, fh: IO[bytes]) -> str:
        """Hash of the last entry, read from the tail so an append does not scan the log."""
        size = fh.seek(0, os.SEEK_END)
        window = _TAIL_BYTES
        while True:
            start = max(0, size - window)
            fh.seek(start)
            lines = fh.read(size - start).split(b"\n")
            if start > 0:
                lines = lines[1:]  # the first piece may be the end of a longer line
            for raw in reversed(lines):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    found = json.loads(raw).get("hash")
                except (json.JSONDecodeError, AttributeError):
                    continue
                if found:
                    return found
            if start == 0:
                return GENESIS
            window *= 8

    def append(self, event: str, **data: Any) -> dict[str, Any]:
        # Reading the last hash and writing the entry that names it must be one step:
        # two writers that both read the same predecessor fork the chain for good.
        # _LOCK covers threads in this process; flock covers the CLI, the dashboard
        # and the scheduled monitor writing to the same file.
        with _LOCK, self.path.open("a+b") as fh:
            if fcntl is not None:
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                entry = {
                    "ts": datetime.now(UTC).isoformat(),
                    "event": event,
                    "actor": os.environ.get("UNLIST_ACTOR") or os.environ.get("USER", "unknown"),
                    "data": data,
                    "prev": self._last_hash(fh),
                }
                entry["hash"] = hashlib.sha256(_canonical(entry)).hexdigest()
                fh.seek(0, os.SEEK_END)
                fh.write((json.dumps(entry, default=str) + "\n").encode("utf-8"))
                fh.flush()
            finally:
                if fcntl is not None:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        paths.make_private(self.path)
        return entry

    def entries(self, limit: int | None = None) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        rows = []
        with self.path.open("r", encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    rows.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue
        return rows[-limit:] if limit else rows

    def verify(self) -> tuple[bool, str]:
        """Recompute the chain. Returns (ok, human-readable detail)."""
        prev = GENESIS
        for i, entry in enumerate(self.entries(), start=1):
            claimed = entry.get("hash")
            body = {k: v for k, v in entry.items() if k != "hash"}
            if body.get("prev") != prev:
                return False, f"Entry {i} does not chain to its predecessor (log was edited)."
            if hashlib.sha256(_canonical(body)).hexdigest() != claimed:
                return False, f"Entry {i} hash does not match its contents."
            prev = claimed
        return True, f"Chain intact across {len(self.entries())} entries."
