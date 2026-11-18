"""Turn a FetchResult into a captures row plus raw file. Shared by every scanner."""

from __future__ import annotations

import sqlite3

from unlist import paths
from unlist.core import store
from unlist.core.fetch import FetchResult


def record_fetch(
    conn: sqlite3.Connection,
    tool: str,
    result: FetchResult,
    note: str | None = None,
    body_override: bytes | None = None,
) -> int:
    """Store the response bytes (write-once, hashed) and a captures row, and return its id.

    body_override stores a redacted copy instead of what came over the wire, for sources
    that return leaked values the tool refuses to keep; the hash is of what is stored.

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
    body = result.body if body_override is None else body_override
    sha = result.sha256 if body_override is None else store.sha256_hex(body)
    raw_abs = store.raw_path_for(tool, sha, ext, result.captured_at, data_dir)
    store.write_raw(raw_abs, body)
    parts = [p for p in (note, result.reason, result.error) if p]
    row = store.CaptureRow(
        tool=tool,
        requested_url=result.requested_url,
        final_url=result.final_url,
        status=result.status,
        captured_at=result.captured_at,
        sha256=sha,
        raw_path=str(raw_abs.relative_to(data_dir)),
        kind=kind,
        headers_json=store.headers_to_json(result.headers),
        note="; ".join(parts) or None,
    )
    return store.insert_capture(conn, row)


def record_browser(
    conn: sqlite3.Connection, tool: str, cap, note: str | None = None
) -> int:
    """A browser capture: HTML as the raw file, the screenshot beside it under shots/."""
    data_dir = paths.data_dir()
    sha = store.sha256_hex(cap.html)
    raw_abs = store.raw_path_for(tool, sha, "html", cap.captured_at, data_dir)
    store.write_raw(raw_abs, cap.html)
    shot_rel = None
    if cap.png:
        shot_abs = store.raw_path_for(tool, sha, "png", cap.captured_at, data_dir)
        shot_abs = data_dir / "shots" / shot_abs.relative_to(data_dir / "raw")
        store.write_raw(shot_abs, cap.png)
        shot_rel = str(shot_abs.relative_to(data_dir))
    parts = [p for p in (note, cap.note, "challenged" if cap.challenged else None) if p]
    row = store.CaptureRow(
        tool=tool,
        requested_url=cap.requested_url,
        final_url=cap.final_url,
        status=cap.status,
        captured_at=cap.captured_at,
        sha256=sha,
        raw_path=str(raw_abs.relative_to(data_dir)),
        shot_path=shot_rel,
        kind="refusal" if cap.challenged else "browser",
        note="; ".join(parts) or None,
    )
    return store.insert_capture(conn, row)
