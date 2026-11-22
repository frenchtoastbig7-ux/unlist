"""Read the opt-out mailbox, classify replies, follow verification links on broker hosts."""

from __future__ import annotations

import contextlib
import email
import html as html_lib
import imaplib
import json
import os
import re
import sqlite3
import ssl
from dataclasses import dataclass, field
from email.header import decode_header, make_header
from email.utils import parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import SplitResult, urlsplit

from unlist.catalog import Catalog, load_catalog
from unlist.core.audit import AuditLog
from unlist.core.fetch import Fetcher
from unlist.core.timeutil import iso_z, now_iso
from unlist.requests import engine
from unlist.requests.mailer import env_port
from unlist.scanners.evidence import record_fetch
from unlist.subjects import ConsentError, SubjectRepo

IMAP_TIMEOUT_S = 30

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


_PATTERNS_BY_KIND = dict(_PATTERNS)


@dataclass
class Message:
    uid: str
    from_addr: str
    subject: str
    date: str | None
    text: str
    links: list[str] = field(default_factory=list)
    # Where the UID is valid: server, account, folder and UIDVALIDITY. A UID alone repeats
    # across folders and after the server renumbers, so deduplication uses both.
    scope: str = ""

    @property
    def key(self) -> str:
        return f"{self.scope}/{self.uid}" if self.scope else self.uid

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
            env_port("UNLIST_IMAP_PORT", 993),
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


def split_url(link: str) -> SplitResult | None:
    """The parsed link, or None when it is not a URL this tool will reason about: mail can
    carry anything, and one malformed link must not stop the rest of the poll."""
    try:
        parts = urlsplit(link)
        host = parts.hostname
        _ = parts.port
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not host:
        return None
    return parts


class _Hrefs(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.found: list[str] = []

    def handle_starttag(self, tag, attrs) -> None:
        if tag == "a":
            # The parser has already decoded entities, so "&amp;token=" arrives as "&token=".
            self.found += [v.strip() for k, v in attrs if k == "href" and v]


def html_links(html: str) -> list[str]:
    parser = _Hrefs()
    with contextlib.suppress(Exception):
        parser.feed(html)
        parser.close()
    return [u for u in parser.found if u.lower().startswith(("http://", "https://"))]


def parse_message(uid: str, raw: bytes, scope: str = "") -> Message:
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
        text = html_lib.unescape(re.sub(r"<[^>]+>", " ", html))
    candidates = set(_LINK.findall(text)) | set(html_links(html))
    links = sorted(u for u in candidates if split_url(u) is not None)
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
        scope=scope,
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
        self._scope = ""

    def __enter__(self) -> ImapInbox:
        # An explicit context: on Python 3.11 the default one checks neither the
        # certificate nor the host name, and the next thing sent is the password. The
        # timeout bounds the connection and every later read on the socket.
        self._conn = imaplib.IMAP4_SSL(
            self.s.host,
            self.s.port,
            ssl_context=ssl.create_default_context(),
            timeout=IMAP_TIMEOUT_S,
        )
        try:
            self._conn.login(self.s.user, self.s.password)
            status, _ = self._conn.select(self.s.folder)
            if status != "OK":
                raise RuntimeError(f"cannot open mailbox folder {self.s.folder!r}")
            _, data = self._conn.response("UIDVALIDITY")
            validity = data[0].decode() if data and data[0] else "0"
        except BaseException:
            self.__exit__()
            raise
        self._scope = f"{self.s.host}/{self.s.user}/{self.s.folder}/{validity}"
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
            out.append(parse_message(uid.decode(), parts[0][1], self._scope))
        return out

    def mark_seen(self, uid: str) -> None:
        """Flag one message seen; a server that says no is a mailbox error, not success."""
        assert self._conn is not None
        status, data = self._conn.uid("store", uid, "+FLAGS", "(\\Seen)")
        if status != "OK":
            said = b" ".join(d for d in data or [] if isinstance(d, bytes)).decode(errors="replace")
            raise RuntimeError(
                f"server refused to mark message {uid} seen: {status} {said}".strip()
            )

    def mark_seen_all(self, uids: list[str]) -> list[str]:
        """Flag every message, carrying on past refusals; returns one line per failure."""
        failures = []
        for uid in uids:
            try:
                self.mark_seen(uid)
            except Exception as exc:
                failures.append(str(exc))
        return failures


def _verify_looking(link: str) -> bool:
    parts = split_url(link)
    return parts is not None and bool(_VERIFY_PATH.search(parts.path + "?" + parts.query))


def classify(msg: Message) -> tuple[str, str]:
    text = f"{msg.subject}\n{msg.text}"
    for kind, pat in _PATTERNS:
        m = pat.search(text)
        if m:
            if kind == "completed":
                # "Your request has been processed; click the link to confirm" is not done
                # yet: the confirmation still has to happen.
                pending = _PATTERNS_BY_KIND["verification"].search(text)
                if pending:
                    return "verification", pending.group(0)[:80]
            return kind, m.group(0)[:80]
    if any(_verify_looking(link) for link in msg.links):
        return "verification", "link that looks like a confirmation"
    return "unknown", ""


def _candidates(conn: sqlite3.Connection, msg: Message, catalog: Catalog) -> list[sqlite3.Row]:
    """The request a message is about: the one its tag names, else the sent requests still
    open with the sending broker (more than one means it cannot be told which)."""
    tag = msg.tag
    if tag:
        row = conn.execute("SELECT * FROM requests WHERE tag=?", (tag,)).fetchone()
        if row:
            return [row]
    broker = catalog.by_host(msg.sender_domain)
    if broker is None:
        return []
    return [
        r
        for r in engine.list_for(conn, None, "open", broker.id)
        if r["state"] in engine.SENT_STATES
    ]


def match_request(conn: sqlite3.Connection, msg: Message, catalog: Catalog) -> sqlite3.Row | None:
    """The one request this message is about, or None when there is none or several: an
    untagged reply that could belong to two requests is for the operator to assign."""
    rows = _candidates(conn, msg, catalog)
    return rows[0] if len(rows) == 1 else None


def verification_links(msg: Message, broker_hosts: list[str]) -> tuple[list[str], list[str]]:
    """(https links on the broker's own hosts that look like confirmations, every other
    link). Plain http is never followed: the token in the link would travel in the clear."""
    ok, other = [], []
    for link in msg.links:
        parts = split_url(link)
        if parts is None or "@" in parts.netloc:
            other.append(link)
            continue
        host = (parts.hostname or "").lower().removeprefix("www.")
        on_broker = any(host == h or host.endswith("." + h) for h in broker_hosts)
        path = parts.path + "?" + parts.query
        if parts.scheme.lower() == "https" and on_broker and _VERIFY_PATH.search(path):
            ok.append(link)
        else:
            other.append(link)
    return ok, other


_INSERT = """INSERT INTO inbox_messages(message_uid, request_id, from_addr, subject, received_at,
                 classification, detail, links_json, capture_id, action, seen_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)"""
CLAIM_ACTION = (
    "following the confirmation link was interrupted; it may or may not have been "
    "opened: check the request with the broker"
)


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
    live = engine.SENT_STATES
    out = []

    def move(rid: int, state: str, note: str, allowed=live, cap: int | None = None) -> bool:
        # Only from a state the reply can still act on, and inside the transaction that
        # records the message, so neither is ever stored without the other.
        return engine.transition(conn, rid, state, allowed, note, cap, commit=False)

    for msg in messages:
        key = msg.key
        if conn.execute("SELECT 1 FROM inbox_messages WHERE message_uid=?", (key,)).fetchone():
            continue
        kind, detail = classify(msg)
        candidates = _candidates(conn, msg, catalog)
        row = candidates[0] if len(candidates) == 1 else None
        rid = row["id"] if row else None
        record = [
            key, rid, msg.from_addr, msg.subject[:200], msg.date, kind, detail,
            json.dumps(msg.links[:20]),
        ]  # fmt: skip
        action = "surfaced"
        capture_id = None
        claimed = False

        if len(candidates) > 1:
            ids = ", ".join(str(r["id"]) for r in candidates)
            action = f"could belong to requests {ids}; nothing changed, assign it yourself"
        elif row is not None:
            state = row["state"]
            broker = catalog.get(row["broker_id"]) if row["broker_id"] in catalog else None
            hosts = broker.hosts if broker else []
            unchanged = f"request is {state}; reply recorded, nothing changed"
            actionable = state in live
            safe, other = verification_links(msg, hosts) if kind == "verification" else ([], [])
            consent_problem = None
            if safe and actionable:
                # Following the link acts for the subject, so consent must be in force now,
                # not only when the request went out.
                try:
                    SubjectRepo(conn).require(row["subject_id"])
                except ConsentError as exc:
                    consent_problem = str(exc)
            result = None
            if safe and actionable and consent_problem is None:
                # The message is recorded before the link is opened. If the run dies in
                # between, the next poll finds this row and does not open the link again.
                conn.execute(_INSERT, (*record, None, CLAIM_ACTION, now_iso()))
                conn.commit()
                claimed = True
                result = fetcher.get(safe[0], check_robots=False)
                capture_id = record_fetch(
                    conn, "inbox", result, note=f"verification link for request {rid}"
                )
            conn.execute(
                "UPDATE requests SET last_reply_at=? WHERE id=?", (msg.date or now_iso(), rid)
            )
            if not actionable:
                # A late reply to a request that is closed (or was never sent) stays tied
                # to it for the record, and changes nothing.
                engine.add_event(conn, rid, "reply", msg.subject[:120])
                action = unchanged
            elif consent_problem is not None:
                engine.add_event(conn, rid, "verification_not_followed", consent_problem)
                action = f"confirmation link not followed: {consent_problem}"
            elif result is not None:
                link = safe[0]
                if result.ok:
                    moved = move(
                        rid, "acknowledged", f"confirmation link followed: {link}", cap=capture_id
                    )
                    action = f"followed {link}"
                else:
                    moved = move(
                        rid,
                        "awaiting_verification",
                        f"confirmation link refused: {result.reason or result.error}",
                        cap=capture_id,
                    )
                    action = f"link refused ({result.status}); open it yourself: {link}"
                if not moved:
                    action += "; the request changed meanwhile and was left as it is"
            elif kind == "verification":
                if not move(
                    rid,
                    "awaiting_verification",
                    "verification email with no link on the broker's hosts",
                    ("sent", "submitted"),
                ):
                    engine.add_event(conn, rid, "verification_unsafe", ", ".join(other[:3]))
                action = (
                    "verification link is not on the broker's hosts over https; "
                    "check it yourself: " + ", ".join(other[:3])
                )
            elif kind == "completed":
                if move(rid, "completed", f"broker says done: {detail}"):
                    action = "marked completed; verify the listing"
                else:
                    engine.add_event(conn, rid, "reply", msg.subject[:120])
                    action = unchanged
            elif kind == "acknowledged":
                move(rid, "acknowledged", detail, ("sent", "submitted"))
                action = "acknowledged"
            elif kind == "id_demand":
                engine.add_event(conn, rid, "id_demand", detail)
                action = "broker demands identification; reply yourself citing the regulation, never upload ID"
            elif kind in ("refusal", "bounce"):
                note = f"broker refused: {detail}" if kind == "refusal" else "address bounced"
                if not move(rid, "failed", note):
                    engine.add_event(conn, rid, "reply", msg.subject[:120])
                    action = unchanged
                elif kind == "refusal":
                    action = "marked failed; consider escalation"
                else:
                    action = "address bounced; find another contact in the catalog"
            else:
                engine.add_event(conn, rid, "reply", msg.subject[:120])
                action = "reply recorded; read it"
        if claimed:
            conn.execute(
                "UPDATE inbox_messages SET capture_id=?, action=?, seen_at=? WHERE message_uid=?",
                (capture_id, action, now_iso(), key),
            )
        else:
            conn.execute(_INSERT, (*record, capture_id, action, now_iso()))
        conn.commit()
        audit.append("inbox.message", uid=msg.uid, request_id=rid, kind=kind, action=action)
        out.append(
            {
                "uid": msg.uid,
                "from": msg.from_addr,
                "subject": msg.subject,
                "kind": kind,
                "request_id": rid,
                "action": action,
            }
        )
    return out
