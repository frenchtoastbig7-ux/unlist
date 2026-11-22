"""California DROP: the state's one-stop deletion platform. No consumer API exists, so the
tool prepares exactly what to enter and tracks the 45-day cycle once you have a DROP ID."""

from __future__ import annotations

import json
import sqlite3
from datetime import timedelta

from unlist.core.audit import AuditLog
from unlist.core.timeutil import iso_z, now_iso, parse_dt, utcnow
from unlist.requests import engine
from unlist.requests.basis import deadline_for
from unlist.subjects import SubjectRepo

DROP_URL = "https://consumer.drop.privacy.ca.gov/"
DROP_INFO = "https://privacy.ca.gov/drop/"


def drop_profile(conn: sqlite3.Connection, subject_id: str) -> str:
    """What to paste into DROP. Brokers match on hashed name+DOB+ZIP, email, phone and
    ad identifiers, so the more of these you give DROP the more records it reaches."""
    subject = SubjectRepo(conn).require(subject_id)
    if not subject.is_california:
        return (
            f"Subject `{subject_id}` is not a California resident; DROP is for Californians only."
        )
    names = [i.value for i in subject.identifiers if i.kind in ("name", "alias")]
    dob = [i.value for i in subject.identifiers if i.kind == "dob"]
    emails = [i.value for i in subject.identifiers if i.kind == "email"]
    phones = [i.value for i in subject.identifiers if i.kind == "phone"]
    zips = sorted({str(i.meta.get("zip")) for i in subject.identifiers if i.meta.get("zip")})
    lines = [
        f"# DROP profile for {subject.label}",
        "",
        f"1. Go to {DROP_URL} and verify California residency through the Identity Gateway (direct entry or Login.gov). The tool cannot do this step.",
        "2. Create the profile with these values (every one you add widens the match):",
        "",
    ]
    lines.append(f"- Names: {'; '.join(names) or '(add a name identifier first)'}")
    lines.append(
        f"- Date of birth: {dob[0] if dob else '(add a dob identifier: brokers match on name + DOB + ZIP)'}"
    )
    lines.append(
        f"- ZIP codes (current and past): {', '.join(zips) or '(add zip to your address identifiers)'}"
    )
    lines.append(f"- Email addresses: {'; '.join(emails) or '(none recorded)'}")
    lines.append(f"- Phone numbers: {'; '.join(phones) or '(none recorded)'}")
    lines.append(
        "- Mobile advertising IDs, CTV IDs, VIN: from your devices and car, if you want ad-tech brokers covered"
    )
    lines += [
        "",
        "3. Submit. DROP gives an 8-digit DROP ID; record it with drop_record so the tool tracks the cycle.",
        "",
        "Brokers must check DROP at least every 45 days, delete within 45 days of seeing you, and re-delete every 45 days; "
        "they may not contact you to verify (11 CCR § 7616(c)). Status: "
        + DROP_URL
        + "dropstatus. "
        f"More: {DROP_INFO}",
    ]
    return "\n".join(lines)


def _submitted_time(submitted_at: str | None) -> str | None:
    if submitted_at is None or not str(submitted_at).strip():
        return None
    when = parse_dt(submitted_at)
    if when is None:
        raise ValueError(f"submission date {submitted_at!r} is not a date")
    if when > utcnow() + timedelta(days=1):
        raise ValueError(f"submission date {submitted_at!r} is in the future")
    return iso_z(when)


def record_drop(
    conn: sqlite3.Connection, subject_id: str, drop_id: str, submitted_at: str | None = None
) -> sqlite3.Row:
    """Record (or correct) the DROP ID. submitted_at is when the profile was submitted at
    DROP, if that was not just now; the reminder to check DROP counts from it."""
    subject = SubjectRepo(conn).require(subject_id)
    if not subject.is_california:
        raise ValueError(
            f"subject {subject_id!r} is not a California resident; DROP is for Californians only"
        )
    drop_id = drop_id.strip()
    if not drop_id.isdigit() or len(drop_id) != 8:
        raise ValueError("a DROP ID is 8 digits")
    given = _submitted_time(submitted_at)
    existing = conn.execute(
        "SELECT * FROM requests WHERE subject_id=? AND channel='drop' "
        "AND state NOT IN ('cancelled','failed') ORDER BY id DESC LIMIT 1",
        (subject_id,),
    ).fetchone()
    if existing:
        # A new date, or a row an interrupted earlier run left without its dates.
        sent = given or existing["sent_at"] or now_iso()
        if given or not existing["sent_at"] or not existing["deadline"]:
            reminder = iso_z(deadline_for(existing["basis"], sent))
        else:
            reminder = existing["deadline"]
        conn.execute(
            "UPDATE requests SET drop_id=?, sent_at=?, deadline=? WHERE id=?",
            (drop_id, sent, reminder, existing["id"]),
        )
        engine.add_event(conn, existing["id"], "drop_id", drop_id)
        conn.commit()
        return engine.get(conn, existing["id"])
    tag = engine._new_tag(conn)
    sent = given or now_iso()
    reminder = iso_z(deadline_for("ccpa_delete", sent))
    # One transaction: a submitted tracker never exists without its dates.
    cur = conn.execute(
        """INSERT INTO requests(subject_id, broker_id, channel, basis, state, tag, drop_id,
             subject_line, body, listings_json, finding_ids_json, created_at, sent_at,
             deadline, note)
           VALUES (?,'california-drop','drop','ccpa_delete','submitted',?,?,?,?,'[]','[]',?,?,?,?)""",
        (
            subject_id,
            tag,
            drop_id,
            "California DROP deletion request",
            f"DROP ID {drop_id}",
            now_iso(),
            sent,
            reminder,
            f"submitted by {subject.label} at DROP",
        ),
    )
    rid = int(cur.lastrowid)
    engine.add_event(conn, rid, "drafted", "drop")
    engine.add_event(conn, rid, "state:submitted", f"DROP ID {drop_id}")
    conn.commit()
    audit = AuditLog()
    audit.append(
        "request.sent",
        request_id=rid,
        subject=subject_id,
        broker="california-drop",
        channel="drop",
        state="submitted",
        deadline=reminder,
    )
    audit.append("request.drop", request_id=rid, subject=subject_id, drop_id=drop_id)
    return engine.get(conn, rid)


def drop_status_summary(conn: sqlite3.Connection, subject_id: str) -> str:
    rows = [r for r in engine.list_for(conn, subject_id) if r["channel"] == "drop"]
    if not rows:
        return "No DROP submission recorded. Use drop_prepare, submit at DROP, then drop_record."
    r = rows[-1]
    # The stored date is this tool's own 45-day reminder to look at the DROP status page,
    # not a date by which any broker must have acted.
    return json.dumps(
        {
            "request_id": r["id"],
            "drop_id": r["drop_id"],
            "state": r["state"],
            "submitted": r["sent_at"],
            "check_drop_status_on": r["deadline"],
        }
    )
