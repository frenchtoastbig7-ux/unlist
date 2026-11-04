"""Turn a FetchResult into a captures row plus raw file. Shared by every scanner."""

from __future__ import annotations

import sqlite3

from unlist import paths
from unlist.core import store
from unlist.core.fetch import FetchResult


def record_fetch(
    conn: sqlite3.Connection, tool: str, result: FetchResult, note: str | None = None
) -> int:
    """Store the response bytes (write-once, hashed) and a captures row, and return its id.

    kind is 'fetch' for a normal answer, 'refusal' when the site declined automated access
    (robots, 401, 403, 429, 451), 'error' when nothing came back.
    """
    if result.blocked:
        kind = "refusal"
    elif result.status is None:
        kind = "error"
    else:
        kind = "fetch"
    data_dir = paths.data_dir()
    ext = store.ext_for(result.content_type, result.final_url)
    raw_abs = store.raw_path_for(tool, result.sha256, ext, result.captured_at, data_dir)
    store.write_raw(raw_abs, result.body)
    parts = [p for p in (note, result.reason, result.error) if p]
    row = store.CaptureRow(
        tool=tool,
        requested_url=result.requested_url,
        final_url=result.final_url,
        status=result.status,
        captured_at=result.captured_at,
        sha256=result.sha256,
        raw_path=str(raw_abs.relative_to(data_dir)),
        kind=kind,
        headers_json=store.headers_to_json(result.headers),
        note="; ".join(parts) or None,
    )
    return store.insert_capture(conn, row)
