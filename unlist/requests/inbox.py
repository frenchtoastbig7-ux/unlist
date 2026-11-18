"""Read the opt-out mailbox, classify replies, follow verification links on broker hosts."""

from __future__ import annotations

import contextlib
import email
import imaplib
import os
import re
import sqlite3
from dataclasses import dataclass, field
from email.header import decode_header, make_header
from email.utils import parseaddr, parsedate_to_datetime
from urllib.parse import urlsplit

from unlist.catalog import Catalog, load_catalog
from unlist.core.audit import AuditLog
from unlist.core.fetch import Fetcher
from unlist.core.timeutil import iso_z, now_iso
from unlist.requests import engine
from unlist.scanners.evidence import record_fetch

_TAG = re.compile(r"\[?(UNLIST-[0-9A-F]{6})\]?")
_LINK = re.compile(r"https?://[^\s<>\"')\]]+")
_VERIFY_PATH = re.compile(
    r"confirm|verif|optout|opt-out|removal|remove|suppress|unsubscribe|token|activate", re.I
)

KINDS = ("verification", "completed", "acknowledged", "id_demand", "refusal", "bounce", "unknown")

_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "bounce",
        re.compile(
            r"undeliverable|delivery (?:status notification|has failed)|mailer-daemon|address rejected|does not exist",
            re.I,
        ),
    ),
    (
        "id_demand",
        re.compile(
            r"government[- ]issued|photo id|driver.s licen[cs]e|passport|identification document|proof of identity|copy of your id|notari",
            re.I,
        ),
    ),
    (
        "completed",
        re.compile(
            r"has been (?:removed|deleted|suppressed|processed|completed)|we have (?:removed|deleted|opted)|(?:removal|deletion|opt[- ]out) (?:is|was) (?:complete|successful|processed)|successfully (?:removed|opted|deleted|suppressed)|no longer (?:appear|display|publish)",
            re.I,
        ),
    ),
    (
        "refusal",
        re.compile(
            r"unable to (?:process|locate|comply|complete)|cannot (?:process|locate|comply|complete)|we (?:do not|don.t) have|not (?:able to|possible to) (?:remove|delete)|request (?:has been )?(?:denied|rejected)|exempt from",
            re.I,
        ),
    ),
    (
        "verification",
        re.compile(
            r"click (?:the|this) (?:link|button)|confirm your (?:request|email)|verify your (?:request|email)|to complete your (?:request|opt[- ]out|removal)|confirmation link|verification link",
            re.I,
        ),
    ),
    (
        "acknowledged",
        re.compile(
            r"received your (?:request|message|email)|we have received|thank you for (?:contacting|your request|reaching out)|ticket|case (?:number|id)|is being processed|within \d+ (?:business )?days",
            re.I,
        ),
    ),
]


@dataclass
class Message:
    uid: str
    from_addr: str
    subject: str
    date: str | None
    text: str
    links: list[str] = field(default_factory=list)

    @property
    def tag(self) -> str | None:
        m = _TAG.search(self.subject) or _TAG.search(self.text)
        return m.group(1) if m else None

    @property
    def sender_domain(self) -> str:
        return self.from_addr.split("@")[-1].lower().strip(">")


@dataclass
class ImapSettings:
    host: str
    port: int
    user: str
    password: str
    folder: str = "INBOX"

    @classmethod
    def from_env(cls) -> ImapSettings | None:
        host = os.environ.get("UNLIST_IMAP_HOST")
        user = os.environ.get("UNLIST_IMAP_USER") or os.environ.get("UNLIST_SMTP_USER")
        password = os.environ.get("UNLIST_IMAP_PASSWORD") or os.environ.get("UNLIST_SMTP_PASSWORD")
        if not (host and user and password):
            return None
        return cls(
            host,
            int(os.environ.get("UNLIST_IMAP_PORT") or 993),
            user,
            password,
            os.environ.get("UNLIST_IMAP_FOLDER") or "INBOX",
        )


def _decode(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def parse_message(uid: str, raw: bytes) -> Message:
    msg = email.message_from_bytes(raw)
    text_parts: list[str] = []
    html_parts: list[str] = []
    for part in msg.walk():
        ct = part.get_content_type()
        if part.get_content_disposition() == "attachment":
            continue
        if ct == "text/plain":
            text_parts.append(_payload(part))
        elif ct == "text/html":
            html_parts.append(_payload(part))
    text = "\n".join(text_parts)
    html = "\n".join(html_parts)
    if not text.strip() and html:
        text = re.sub(r"<[^>]+>", " ", html)
    links = sorted(set(_LINK.findall(text + "\n" + html)))
    date = None
    if msg.get("Date"):
        try:
            date = iso_z(parsedate_to_datetime(msg["Date"]))
        except Exception:
            date = None
    return Message(
        uid=uid,
        from_addr=parseaddr(_decode(msg.get("From")))[1].lower(),
        subject=_decode(msg.get("Subject")),
        date=date,
        text=text,
        links=links,
    )


def _payload(part) -> str:
    data = part.get_payload(decode=True) or b""
    charset = part.get_content_charset() or "utf-8"
    try:
        return data.decode(charset, "replace")
    except LookupError:
        return data.decode("utf-8", "replace")


class ImapInbox:
    def __init__(self, settings: ImapSettings) -> None:
        self.s = settings
        self._conn: imaplib.IMAP4_SSL | None = None

    def __enter__(self) -> ImapInbox:
        self._conn = imaplib.IMAP4_SSL(self.s.host, self.s.port)
        self._conn.login(self.s.user, self.s.password)
        self._conn.select(self.s.folder)
        return self

    def __exit__(self, *exc) -> None:
        if self._conn is not None:
            with contextlib.suppress(Exception):
                self._conn.logout()

    def fetch_unseen(self, limit: int = 50) -> list[Message]:
        assert self._conn is not None
        status, data = self._conn.uid("search", None, "UNSEEN")
        if status != "OK":
            return []
        uids = data[0].split()[-limit:]
        out = []
        for uid in uids:
            status, parts = self._conn.uid("fetch", uid, "(BODY.PEEK[])")
            if status != "OK" or not parts or not isinstance(parts[0], tuple):
                continue
            out.append(parse_message(uid.decode(), parts[0][1]))
        return out

    def mark_seen(self, uid: str) -> None:
        assert self._conn is not None
        self._conn.uid("store", uid, "+FLAGS", "(\\Seen)")


def classify(msg: Message) -> tuple[str, str]:
    text = f"{msg.subject}\n{msg.text}"
    for kind, pat in _PATTERNS:
        m = pat.search(text)
        if m:
            return kind, m.group(0)[:80]
    if any(
        _VERIFY_PATH.search(urlsplit(link).path + "?" + urlsplit(link).query) for link in msg.links
    ):
        return "verification", "link that looks like a confirmation"
    return "unknown", ""


def match_request(conn: sqlite3.Connection, msg: Message, catalog: Catalog) -> sqlite3.Row | None:
    tag = msg.tag
    if tag:
        row = conn.execute("SELECT * FROM requests WHERE tag=?", (tag,)).fetchone()
        if row:
            return row
    broker = catalog.by_host(msg.sender_domain)
    if broker is None:
        return None
    open_rows = [
        r
        for r in engine.list_for(conn, None, "open", broker.id)
        if r["state"] in engine.SENT_STATES
    ]
    return open_rows[-1] if open_rows else None


def verification_links(msg: Message, broker_hosts: list[str]) -> tuple[list[str], list[str]]:
    """(links on the broker's own hosts that look like confirmations, every other link)."""
    ok, other = [], []
    for link in msg.links:
        host = urlsplit(link).netloc.lower().removeprefix("www.")
        on_broker = any(host == h or host.endswith("." + h) for h in broker_hosts)
        path = urlsplit(link).path + "?" + urlsplit(link).query
        if on_broker and _VERIFY_PATH.search(path):
            ok.append(link)
        else:
            other.append(link)
    return ok, other


def process_messages(
    conn: sqlite3.Connection,
    messages: list[Message],
    *,
    fetcher: Fetcher | None = None,
    catalog: Catalog | None = None,
) -> list[dict]:
    """Classify each message, tie it to a request, follow safe verification links, move the
    request's state. Returns one dict per message with what was done."""
    from unlist.scanners.brokers.run import make_fetcher

    catalog = catalog or load_catalog()
    fetcher = fetcher or make_fetcher()
    audit = AuditLog()
    out = []
    for msg in messages:
        if conn.execute("SELECT 1 FROM inbox_messages WHERE message_uid=?", (msg.uid,)).fetchone():
            continue
        kind, detail = classify(msg)
        row = match_request(conn, msg, catalog)
        action = "surfaced"
        capture_id = None
        if row is not None:
            rid = row["id"]
            broker = catalog.get(row["broker_id"]) if row["broker_id"] in catalog else None
            hosts = broker.hosts if broker else []
            conn.execute(
                "UPDATE requests SET last_reply_at=? WHERE id=?", (msg.date or now_iso(), rid)
            )
            if kind == "verification":
                safe, other = verification_links(msg, hosts)
                if safe:
                    link = safe[0]
                    r = fetcher.get(link, check_robots=False)
                    capture_id = record_fetch(
                        conn, "inbox", r, note=f"verification link for request {rid}"
                    )
                    if r.ok:
                        engine.set_state(
                            conn,
                            rid,
                            "acknowledged",
                            f"confirmation link followed: {link}",
                            capture_id,
                        )
                        action = f"followed {link}"
                    else:
                        engine.set_state(
                            conn,
                            rid,
                            "awaiting_verification",
                            f"confirmation link refused: {r.reason or r.error}",
                            capture_id,
                        )
                        action = f"link refused ({r.status}); open it yourself: {link}"
                else:
                    if row["state"] in ("sent", "submitted"):
                        engine.set_state(
                            conn,
                            rid,
                            "awaiting_verification",
                            "verification email with no link on the broker's hosts",
                        )
                    else:
                        engine.add_event(conn, rid, "verification_unsafe", ", ".join(other[:3]))
                    action = (
                        "verification link is not on the broker's hosts; check it yourself: "
                        + ", ".join(other[:3])
                    )
            elif kind == "completed":
                engine.set_state(conn, rid, "completed", f"broker says done: {detail}")
                action = "marked completed; verify the listing"
            elif kind == "acknowledged":
                if row["state"] in ("sent", "submitted"):
                    engine.set_state(conn, rid, "acknowledged", detail)
                action = "acknowledged"
            elif kind == "id_demand":
                engine.add_event(conn, rid, "id_demand", detail)
                action = "broker demands identification; reply yourself citing the regulation, never upload ID"
            elif kind == "refusal":
                engine.set_state(conn, rid, "failed", f"broker refused: {detail}")
                action = "marked failed; consider escalation"
            elif kind == "bounce":
                engine.set_state(conn, rid, "failed", "address bounced")
                action = "address bounced; find another contact in the catalog"
            else:
                engine.add_event(conn, rid, "reply", msg.subject[:120])
                action = "reply recorded; read it"
        conn.execute(
            """INSERT INTO inbox_messages(message_uid, request_id, from_addr, subject, received_at,
                 classification, detail, links_json, capture_id, action, seen_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                msg.uid,
                row["id"] if row else None,
                msg.from_addr,
                msg.subject[:200],
                msg.date,
                kind,
                detail,
                __import__("json").dumps(msg.links[:20]),
                capture_id,
                action,
                now_iso(),
            ),
        )
        conn.commit()
        audit.append(
            "inbox.message",
            uid=msg.uid,
            request_id=row["id"] if row else None,
            kind=kind,
            action=action,
        )
        out.append(
            {
                "uid": msg.uid,
                "from": msg.from_addr,
                "subject": msg.subject,
                "kind": kind,
                "request_id": row["id"] if row else None,
                "action": action,
            }
        )
    return out
