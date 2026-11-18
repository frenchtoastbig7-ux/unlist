"""Exposures: accounts found by username, web mentions the operator confirmed, findings
about domains they own. Like listings, an account is a candidate until confirmed."""

from __future__ import annotations

import json
import sqlite3

from unlist.core.audit import AuditLog
from unlist.core.timeutil import now_iso

STATUSES = ("candidate", "confirmed", "rejected", "resolved")
KINDS = ("account", "mention", "domain")


def upsert(
    conn: sqlite3.Connection,
    subject_id: str,
    identifier_value: str,
    kind: str,
    source: str,
    key: str,
    *,
    title: str | None = None,
    url: str | None = None,
    detail: dict | None = None,
    capture_id: int | None = None,
    status: str = "candidate",
) -> tuple[int, str]:
    """Insert or refresh. Returns (id, 'new' | 'seen' | 'reopened')."""
    now = now_iso()
    row = conn.execute(
        "SELECT id, status FROM exposures WHERE subject_id=? AND kind=? AND source=? AND key=? "
        "AND identifier_value=?",
        (subject_id, kind, source, key, identifier_value),
    ).fetchone()
    detail_json = json.dumps(detail or {}, ensure_ascii=False, sort_keys=True)
    if row is None:
        cur = conn.execute(
            """INSERT INTO exposures(subject_id, identifier_value, kind, source, key, title, url,
                 detail_json, status, capture_id, first_seen, last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (subject_id, identifier_value, kind, source, key, title, url, detail_json, status,
             capture_id, now, now),
        )  # fmt: skip
        return int(cur.lastrowid), "new"
    how = "seen"
    new_status = row["status"]
    if row["status"] == "resolved":
        new_status, how = status, "reopened"
    conn.execute(
        "UPDATE exposures SET last_seen=?, detail_json=?, status=?, "
        "capture_id=COALESCE(?, capture_id), title=COALESCE(?, title), url=COALESCE(?, url) "
        "WHERE id=?",
        (now, detail_json, new_status, capture_id, title, url, row["id"]),
    )
    return int(row["id"]), how


def get(conn: sqlite3.Connection, exposure_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM exposures WHERE id=?", (exposure_id,)).fetchone()
    if row is None:
        raise KeyError(f"no exposure {exposure_id}")
    return row


def set_status(
    conn: sqlite3.Connection, exposure_id: int, status: str, note: str | None = None
) -> sqlite3.Row:
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    row = get(conn, exposure_id)
    conn.execute(
        "UPDATE exposures SET status=?, status_changed_at=?, note=COALESCE(?, note) WHERE id=?",
        (status, now_iso(), note, exposure_id),
    )
    conn.commit()
    AuditLog().append(
        "exposure.status", exposure_id=exposure_id, subject=row["subject_id"],
        kind=row["kind"], source=row["source"], from_status=row["status"], to_status=status,
    )  # fmt: skip
    return get(conn, exposure_id)


def list_for(
    conn: sqlite3.Connection,
    subject_id: str,
    kind: str | None = None,
    status: str | None = None,
) -> list[sqlite3.Row]:
    sql = "SELECT * FROM exposures WHERE subject_id=?"
    args: list[object] = [subject_id]
    if kind:
        sql += " AND kind=?"
        args.append(kind)
    if status:
        sql += " AND status=?"
        args.append(status)
    sql += " ORDER BY kind, CASE status WHEN 'candidate' THEN 0 ELSE 1 END, source, key"
    return conn.execute(sql, args).fetchall()
