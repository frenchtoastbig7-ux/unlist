"""Draft, approve, send and track removal requests."""

from __future__ import annotations

import json
import secrets
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from unlist import paths
from unlist.catalog import Broker, load_catalog
from unlist.core.audit import AuditLog
from unlist.core.timeutil import iso_z, now_iso
from unlist.requests.basis import basis_for, channel_for, deadline_for, get_basis
from unlist.scanners.brokers import findings as F
from unlist.scanners.brokers.urls import STATE_NAMES
from unlist.subjects import SubjectRepo
from unlist.subjects.models import STATE_PRIVACY_LAWS, Subject

TEMPLATES = Path(__file__).parent / "templates"
STATES = (
    "drafted", "approved", "sent", "submitted", "awaiting_verification", "acknowledged",
    "completed", "verified_removed", "failed", "reappeared", "cancelled", "overdue",
)  # fmt: skip
OPEN_STATES = (
    "drafted", "approved", "sent", "submitted", "awaiting_verification", "acknowledged", "overdue",
)  # fmt: skip
SENT_STATES = ("sent", "submitted", "awaiting_verification", "acknowledged", "overdue")

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES)),
    autoescape=select_autoescape([]),
    trim_blocks=False,
    lstrip_blocks=False,
)


@dataclass
class Draft:
    to_address: str | None
    subject_line: str
    body: str


def _places(subject: Subject) -> tuple[list[str], list[str]]:
    current: list[str] = []
    past: list[str] = []
    for i in subject.identifiers:
        if i.kind not in ("name", "alias", "address"):
            continue
        city = str(i.meta.get("city") or "").strip()
        state = str(i.meta.get("state") or "").strip().upper()
        if not (city or state):
            continue
        label = ", ".join(p for p in (city, state) if p)
        target = current if i.current else past
        if label not in current and label not in past:
            target.append(label)
    return current, past


def render(
    basis_key: str,
    subject: Subject,
    broker: Broker,
    listings: Iterable[str],
    tag: str,
    from_address: str | None,
    *,
    include_contact: bool = True,
) -> Draft:
    """The letter. Only what a broker needs to find the record: names, places, the
    request address, listing URLs; phones only for blind requests; never a date of birth."""
    basis = get_basis(basis_key)
    names = [i.value for i in subject.identifiers if i.kind in ("name", "alias")]
    current, past = _places(subject)
    listings = list(listings)
    emails: list[str] = []
    phones: list[str] = []
    if include_contact:
        emails = [i.value for i in subject.identifiers if i.kind == "email" and i.current]
        if not listings:
            phones = [
                _fmt_phone(i.value) for i in subject.identifiers if i.kind == "phone" and i.current
            ]
    if from_address and from_address not in emails:
        emails.insert(0, from_address)
    state = subject.residency_state or ""
    law = STATE_PRIVACY_LAWS.get(state, ("", "", 45))
    ctx = {
        "broker_name": broker.name,
        "names": names or [subject.label],
        "current_places": current,
        "past_places": past,
        "emails": emails,
        "phones": phones,
        "listings": listings,
        "tag": tag,
        "agent": subject.kind == "household",
        "agent_instrument": subject.consent.instrument if subject.consent else "",
        "signature": subject.label,
        "state_name": STATE_NAMES.get(state, state),
        "law_name": law[0],
        "cite": law[1],
        "window": basis.window,
        "uk": subject.residency_country == "GB",
    }
    body = _env.get_template(basis.template).render(**ctx).strip() + "\n"
    subject_line = f"{basis.title} [{tag}]"
    return Draft(
        to_address=broker.opt_out.email or broker.contact.privacy_email,
        subject_line=subject_line,
        body=body,
    )


def _fmt_phone(digits: str) -> str:
    if len(digits) == 11 and digits.startswith("1"):
        return f"({digits[1:4]}) {digits[4:7]}-{digits[7:]}"
    return digits


def _new_tag(conn: sqlite3.Connection) -> str:
    while True:
        tag = "UNLIST-" + secrets.token_hex(3).upper()
        if not conn.execute("SELECT 1 FROM requests WHERE tag=?", (tag,)).fetchone():
            return tag


def add_event(
    conn: sqlite3.Connection,
    request_id: int,
    kind: str,
    detail: str | None = None,
    capture_id: int | None = None,
) -> None:
    conn.execute(
        "INSERT INTO request_events(request_id, at, kind, detail, capture_id) VALUES (?,?,?,?,?)",
        (request_id, now_iso(), kind, detail, capture_id),
    )


def get(conn: sqlite3.Connection, request_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM requests WHERE id=?", (request_id,)).fetchone()
    if row is None:
        raise KeyError(f"no request {request_id}")
    return row


def list_for(
    conn: sqlite3.Connection,
    subject_id: str | None = None,
    state: str | None = None,
    broker_id: str | None = None,
) -> list[sqlite3.Row]:
    sql = "SELECT * FROM requests WHERE 1=1"
    args: list[object] = []
    if subject_id:
        sql += " AND subject_id=?"
        args.append(subject_id)
    if state:
        if state == "open":
            sql += " AND state IN ({})".format(",".join("?" * len(OPEN_STATES)))
            args.extend(OPEN_STATES)
        else:
            sql += " AND state=?"
            args.append(state)
    if broker_id:
        sql += " AND broker_id=?"
        args.append(broker_id)
    sql += " ORDER BY id"
    return conn.execute(sql, args).fetchall()


def open_for_broker(
    conn: sqlite3.Connection, subject_id: str, broker_id: str
) -> sqlite3.Row | None:
    rows = list_for(conn, subject_id, "open", broker_id)
    return rows[0] if rows else None


def events_for(conn: sqlite3.Connection, request_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM request_events WHERE request_id=? ORDER BY id", (request_id,)
    ).fetchall()


def set_state(
    conn: sqlite3.Connection,
    request_id: int,
    state: str,
    note: str | None = None,
    capture_id: int | None = None,
) -> sqlite3.Row:
    if state not in STATES:
        raise ValueError(f"state must be one of {STATES}")
    row = get(conn, request_id)
    now = now_iso()
    closed = now if state in ("completed", "verified_removed", "failed", "cancelled") else None
    conn.execute(
        "UPDATE requests SET state=?, note=COALESCE(?, note), "
        "closed_at=COALESCE(?, closed_at) WHERE id=?",
        (state, note, closed, request_id),
    )
    add_event(conn, request_id, f"state:{state}", note, capture_id)
    conn.commit()
    AuditLog().append(
        "request.state",
        request_id=request_id,
        subject=row["subject_id"],
        broker=row["broker_id"],
        from_state=row["state"],
        to_state=state,
        note=note,
    )
    if state in ("completed", "verified_removed"):
        for fid in json.loads(row["finding_ids_json"] or "[]"):
            try:
                if F.get(conn, fid)["status"] in ("requested", "confirmed"):
                    F.set_status(
                        conn, fid, "removed" if state == "verified_removed" else "requested"
                    )
            except KeyError:
                pass
    return get(conn, request_id)


def draft_request(
    conn: sqlite3.Connection,
    subject_id: str,
    broker_id: str,
    finding_ids: Iterable[int] = (),
    *,
    channel: str | None = None,
    basis: str | None = None,
    from_address: str | None = None,
    prefer_optout: bool = False,
) -> sqlite3.Row:
    """One request for one broker. Consent is checked. Listings come from the findings."""
    subject = SubjectRepo(conn).require(subject_id)
    catalog = load_catalog()
    broker = catalog.get(broker_id)
    if broker.status != "active":
        raise ValueError(f"{broker.name} is {broker.status}; nothing to send")
    fids = [int(f) for f in finding_ids]
    listings: list[str] = []
    for fid in fids:
        row = F.get(conn, fid)
        if row["subject_id"] != subject_id:
            raise ValueError(f"finding {fid} belongs to another subject")
        if row["status"] not in ("confirmed", "reappeared", "requested"):
            raise ValueError(f"finding {fid} is {row['status']}; confirm it first")
        listings.append(row["listing_url"])
    basis_key = basis or basis_for(subject, broker, prefer_optout)
    get_basis(basis_key)
    chan = channel or channel_for(broker)
    if chan not in ("email", "form", "drop", "mail", "manual"):
        raise ValueError(f"unknown channel {chan!r}")
    from_address = from_address or _from_address()
    tag = _new_tag(conn)
    draft = render(basis_key, subject, broker, listings, tag, from_address)
    if chan == "email" and not draft.to_address:
        raise ValueError(
            f"{broker.name} has no email address in the catalog; use channel=form or mail"
        )
    form_url = broker.opt_out.url or broker.contact.privacy_url if chan == "form" else None
    cur = conn.execute(
        """INSERT INTO requests(subject_id, broker_id, channel, basis, state, tag, to_address,
             subject_line, body, form_url, listings_json, finding_ids_json, created_at)
           VALUES (?,?,?,?,'drafted',?,?,?,?,?,?,?,?)""",
        (
            subject_id,
            broker_id,
            chan,
            basis_key,
            tag,
            draft.to_address if chan == "email" else None,
            draft.subject_line,
            draft.body,
            form_url,
            json.dumps(listings),
            json.dumps(fids),
            now_iso(),
        ),
    )
    rid = int(cur.lastrowid)
    add_event(conn, rid, "drafted", f"{chan} / {basis_key}")
    conn.commit()
    AuditLog().append(
        "request.draft",
        request_id=rid,
        subject=subject_id,
        broker=broker_id,
        channel=chan,
        basis=basis_key,
        findings=fids,
    )
    return get(conn, rid)


def _from_address() -> str | None:
    import os

    return os.environ.get("UNLIST_SMTP_USER") or None


def draft_for_confirmed(conn: sqlite3.Connection, subject_id: str, **kw) -> list[sqlite3.Row]:
    """One request per broker that has confirmed or reappeared findings and no open request."""
    by_broker: dict[str, list[int]] = {}
    for row in F.list_for(conn, subject_id):
        if row["status"] in ("confirmed", "reappeared"):
            by_broker.setdefault(row["broker_id"], []).append(row["id"])
    out = []
    for broker_id, fids in by_broker.items():
        if open_for_broker(conn, subject_id, broker_id):
            continue
        out.append(draft_request(conn, subject_id, broker_id, fids, **kw))
    return out


def draft_blind(
    conn: sqlite3.Connection,
    subject_id: str,
    *,
    category: str | None = None,
    only_registry: bool = False,
    limit: int | None = None,
    **kw,
) -> list[sqlite3.Row]:
    """Email requests to brokers you have no listing for: the Incogni approach. Every
    active catalog broker with an email address and no open request, optionally one
    category, optionally only those in the California registry."""
    catalog = load_catalog()
    out = []
    for b in catalog:
        if b.status != "active":
            continue
        if category and b.category != category:
            continue
        if only_registry and not b.registry.ca:
            continue
        if not (b.opt_out.email or b.contact.privacy_email):
            continue
        if open_for_broker(conn, subject_id, b.id):
            continue
        out.append(draft_request(conn, subject_id, b.id, (), channel="email", **kw))
        if limit and len(out) >= limit:
            break
    return out


def approve(conn: sqlite3.Connection, request_ids: Iterable[int]) -> list[sqlite3.Row]:
    out = []
    now = now_iso()
    for rid in request_ids:
        row = get(conn, rid)
        if row["state"] != "drafted":
            continue
        conn.execute("UPDATE requests SET state='approved', approved_at=? WHERE id=?", (now, rid))
        add_event(conn, rid, "state:approved")
        conn.commit()
        AuditLog().append(
            "request.approve", request_id=rid, subject=row["subject_id"], broker=row["broker_id"]
        )
        out.append(get(conn, rid))
    return out


def mark_sent(
    conn: sqlite3.Connection,
    request_id: int,
    state: str = "sent",
    detail: str | None = None,
    capture_id: int | None = None,
) -> sqlite3.Row:
    row = get(conn, request_id)
    now = now_iso()
    deadline = iso_z(deadline_for(row["basis"], now))
    conn.execute(
        "UPDATE requests SET state=?, sent_at=?, deadline=?, "
        "capture_after=COALESCE(?, capture_after) WHERE id=?",
        (state, now, deadline, capture_id, request_id),
    )
    add_event(conn, request_id, f"state:{state}", detail, capture_id)
    for fid in json.loads(row["finding_ids_json"] or "[]"):
        try:
            if F.get(conn, fid)["status"] in ("confirmed", "reappeared"):
                F.set_status(conn, fid, "requested")
        except KeyError:
            pass
    conn.commit()
    AuditLog().append(
        "request.sent",
        request_id=request_id,
        subject=row["subject_id"],
        broker=row["broker_id"],
        channel=row["channel"],
        state=state,
        deadline=deadline,
    )
    return get(conn, request_id)


def send_approved(
    conn: sqlite3.Connection, mailer, request_ids: Iterable[int] | None = None
) -> list[tuple[int, bool, str]]:
    """Send every approved email request (or the given ones). Nothing else is ever sent."""
    if request_ids is None:
        rows = [r for r in list_for(conn, None, "approved") if r["channel"] == "email"]
    else:
        rows = [get(conn, rid) for rid in request_ids]
    out: list[tuple[int, bool, str]] = []
    for row in rows:
        rid = row["id"]
        if row["state"] != "approved":
            out.append((rid, False, f"not approved (state {row['state']})"))
            continue
        if row["channel"] != "email":
            out.append((rid, False, f"channel {row['channel']} is not sent by email"))
            continue
        try:
            msg_id = mailer.send(row["to_address"], row["subject_line"], row["body"], row["tag"])
        except Exception as exc:
            add_event(conn, rid, "send_failed", str(exc))
            conn.commit()
            out.append((rid, False, f"send failed: {exc}"))
            continue
        _store_sent_copy(conn, row)
        mark_sent(conn, rid, "sent", f"to {row['to_address']}; message id {msg_id}")
        out.append((rid, True, f"sent to {row['to_address']}"))
    return out


def _store_sent_copy(conn: sqlite3.Connection, row: sqlite3.Row) -> None:
    """Keep the exact text that went out under the data directory, like any evidence."""
    out_dir = paths.data_dir() / "sent"
    out_dir.mkdir(parents=True, exist_ok=True)
    paths.make_private(out_dir)
    p = out_dir / f"{row['id']:05d}_{row['tag']}.txt"
    p.write_text(
        f"To: {row['to_address']}\nSubject: {row['subject_line']}\n\n{row['body']}",
        encoding="utf-8",
    )
    paths.make_private(p)
