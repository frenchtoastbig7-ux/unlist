"""Findings: listings tied to a subject, with the operator's verdict."""

from __future__ import annotations

import sqlite3

from unlist.core.audit import AuditLog
from unlist.core.timeutil import now_iso
from unlist.scanners.brokers.matcher import Candidate

STATUSES = ("candidate", "confirmed", "rejected", "requested", "removed", "reappeared")


def upsert_candidate(
    conn: sqlite3.Connection, subject_id: str, broker_id: str, cand: Candidate, capture_id: int
) -> tuple[int, str]:
    """Insert a new candidate or refresh last_seen. Returns (id, 'new'|'seen'|'reappeared')."""
    now = now_iso()
    row = conn.execute(
        "SELECT id, status FROM findings WHERE subject_id=? AND broker_id=? AND listing_url=?",
        (subject_id, broker_id, cand.listing_url),
    ).fetchone()
    if row is None:
        cur = conn.execute(
            """INSERT INTO findings(subject_id, broker_id, listing_url, score, extract_json,
                 status, capture_id, first_seen, last_seen)
               VALUES (?,?,?,?,?,'candidate',?,?,?)""",
            (
                subject_id,
                broker_id,
                cand.listing_url,
                cand.score,
                cand.extract_json(),
                capture_id,
                now,
                now,
            ),
        )
        return int(cur.lastrowid), "new"
    if row["status"] == "removed":
        conn.execute(
            "UPDATE findings SET status='reappeared', status_changed_at=?, last_seen=?, "
            "capture_id=?, score=? WHERE id=?",
            (now, now, capture_id, cand.score, row["id"]),
        )
        return int(row["id"]), "reappeared"
    conn.execute(
        "UPDATE findings SET last_seen=?, capture_id=?, score=MAX(score, ?) WHERE id=?",
        (now, capture_id, cand.score, row["id"]),
    )
    return int(row["id"]), "seen"


def set_status(
    conn: sqlite3.Connection, finding_id: int, status: str, note: str | None = None
) -> sqlite3.Row:
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    row = get(conn, finding_id)
    conn.execute(
        "UPDATE findings SET status=?, status_changed_at=?, note=COALESCE(?, note) WHERE id=?",
        (status, now_iso(), note, finding_id),
    )
    conn.commit()
    AuditLog().append(
        "finding.status", finding_id=finding_id, subject=row["subject_id"],
        broker=row["broker_id"], from_status=row["status"], to_status=status, note=note,
    )
    return get(conn, finding_id)


def get(conn: sqlite3.Connection, finding_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    if row is None:
        raise KeyError(f"no finding {finding_id}")
    return row


def list_for(
    conn: sqlite3.Connection,
    subject_id: str,
    status: str | None = None,
    broker_id: str | None = None,
) -> list[sqlite3.Row]:
    sql = "SELECT * FROM findings WHERE subject_id=?"
    args: list[object] = [subject_id]
    if status:
        sql += " AND status=?"
        args.append(status)
    if broker_id:
        sql += " AND broker_id=?"
        args.append(broker_id)
    sql += (
        " ORDER BY CASE status WHEN 'reappeared' THEN 0 WHEN 'candidate' THEN 1 ELSE 2 END,"
        " score DESC, id"
    )
    return conn.execute(sql, args).fetchall()
