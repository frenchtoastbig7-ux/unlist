"""Plain functions behind the MCP tools. Each opens its own database connection and
returns Markdown, never JSON, so the reader in Claude gets an answer.

Every function is a thin wrapper over a package's Python API; nothing here changes
how evidence is stored or what the consent gate allows.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import date

from unlist import __version__, paths
from unlist.catalog import load_catalog
from unlist.core.audit import AuditLog
from unlist.core.report import table
from unlist.db import open_db
from unlist.subjects import Consent, ConsentError, Identifier, SubjectRepo

# helpers ----------------------------------------------------------------------------


def _conn() -> sqlite3.Connection:
    return open_db()


def _count(conn: sqlite3.Connection, sql: str) -> int:
    try:
        return int(conn.execute(sql).fetchone()[0])
    except sqlite3.OperationalError:
        return 0


def _env_state(*names: str) -> str:
    return ", ".join(f"{n}: {'set' if os.environ.get(n) else 'missing'}" for n in names)


# status -----------------------------------------------------------------------------


def status() -> str:
    """What is on this machine: subjects, identifiers, catalog size, credentials present."""
    conn = _conn()
    catalog = load_catalog()
    repo = SubjectRepo(conn)
    subjects = repo.list()
    ok, detail = AuditLog().verify()
    lines = [
        f"# unlist {__version__}",
        "",
        f"- Data directory: `{paths.data_dir()}` (database, evidence, audit log, reports)",
        f"- Subjects: {len(subjects)}; identifiers: {_count(conn, 'SELECT COUNT(*) FROM identifiers')}",
        f"- Catalog: {len(catalog)} brokers ({', '.join(f'{k} {v}' for k, v in sorted(catalog.by_origin().items()))}); "
        f"{len(catalog.searchable())} searchable people-search sites",
        f"- Captures: {_count(conn, 'SELECT COUNT(*) FROM captures')}; "
        f"findings: {_count(conn, 'SELECT COUNT(*) FROM findings')}; "
        f"requests: {_count(conn, 'SELECT COUNT(*) FROM requests')}",
        f"- Audit log: {'intact' if ok else 'PROBLEM'} ({detail})",
        f"- Credentials: {_env_state('HIBP_API_KEY', 'UNLIST_SMTP_PASSWORD')}",
        "",
    ]
    today = date.today()
    for s in subjects:
        if s.consent is None:
            consent = "no consent recorded"
        else:
            try:
                s.consent.check(today)
                consent = f"consent in force until {s.consent.expires} ({s.consent.days_left(today)} days)"
            except ConsentError:
                consent = f"CONSENT EXPIRED {s.consent.expires}"
        lines.append(
            f"- **{s.id}** ({s.kind}, {s.label}): {len(s.identifiers)} identifiers, "
            f"residency {s.residency_state or s.residency_country}, {consent}"
        )
    return "\n".join(lines)


# subjects ---------------------------------------------------------------------------


def subject_add(
    id: str,
    label: str,
    kind: str = "self",
    residency_state: str = "",
    residency_country: str = "US",
    note: str = "",
) -> str:
    """Create a subject (you, or a consenting household member). kind: self or household.
    residency_state is a two-letter US state code (drives which law requests cite).
    No scanning or sending happens until consent_grant has been recorded for the subject."""
    from unlist.subjects import Subject

    repo = SubjectRepo(_conn())
    if repo.exists(id):
        return f"Subject `{id}` already exists. Use subject_show or identifier_add."
    subject = Subject(
        id=id,
        label=label,
        kind=kind,  # type: ignore[arg-type]
        residency_state=residency_state or None,
        residency_country=residency_country,
        note=note,
    )
    repo.add(subject)
    AuditLog().append("subject.add", subject=id, kind=kind)
    return (
        f"Created subject `{id}` ({kind}, {label}), residency "
        f"{subject.residency_state or subject.residency_country}, legal regime "
        f"`{subject.legal_regime}`.\n\nNext: consent_grant, then identifier_add for each "
        "name, email, phone, address and date of birth a broker might list."
    )


def subject_list() -> str:
    """List subjects with identifier counts and consent state."""
    repo = SubjectRepo(_conn())
    rows = []
    for s in repo.list():
        consent = "none"
        if s.consent:
            consent = f"{s.consent.granted} to {s.consent.expires}"
        rows.append(
            [
                s.id,
                s.kind,
                s.label,
                s.residency_state or s.residency_country,
                len(s.identifiers),
                consent,
            ]
        )
    if not rows:
        return "No subjects yet. Use subject_add."
    return table(["id", "kind", "label", "residency", "identifiers", "consent"], rows)


def subject_show(subject_id: str) -> str:
    """Show one subject: consent in force, every identifier with its metadata."""
    repo = SubjectRepo(_conn())
    try:
        s = repo.get(subject_id)
    except KeyError as exc:
        return str(exc)
    lines = [f"# {s.label} (`{s.id}`, {s.kind})", ""]
    lines.append(
        f"- Residency: {s.residency_state or ''} {s.residency_country}; regime `{s.legal_regime}`"
    )
    if s.consent:
        lines.append(
            f'- Consent: {s.consent.holder}, "{s.consent.instrument}", {s.consent.granted} to '
            f"{s.consent.expires}"
            + (f"; scope: {s.consent.scope_note}" if s.consent.scope_note else "")
        )
    else:
        lines.append("- Consent: **none recorded** (consent_grant needed before any scan)")
    if s.note:
        lines.append(f"- Note: {s.note}")
    lines.append("")
    rows = [
        [
            i.id,
            i.kind,
            i.value,
            "yes" if i.current else "past",
            json.dumps(i.meta) if i.meta else "",
            i.note,
        ]
        for i in s.identifiers
    ]
    lines.append(
        table(["id", "kind", "value", "current", "meta", "note"], rows)
        if rows
        else "No identifiers yet."
    )
    return "\n".join(lines)


def consent_grant(
    subject_id: str,
    holder: str,
    instrument: str,
    expires: str,
    granted: str = "",
    scope_note: str = "",
) -> str:
    """Record consent for a subject. For yourself: holder is you, instrument e.g.
    "self-declaration: my own data". For a household member: their words. expires is
    YYYY-MM-DD; every action for the subject refuses to run after that date until renewed."""
    repo = SubjectRepo(_conn())
    try:
        consent = Consent(
            holder=holder,
            instrument=instrument,
            granted=date.fromisoformat(granted) if granted else date.today(),
            expires=date.fromisoformat(expires),
            scope_note=scope_note,
        )
        repo.grant_consent(subject_id, consent)
    except (KeyError, ValueError) as exc:
        return f"Not recorded: {exc}"
    AuditLog().append(
        "consent.grant", subject=subject_id, holder=holder, instrument=instrument, expires=expires
    )
    return f"Consent recorded for `{subject_id}`: {holder}, until {consent.expires} ({consent.days_left()} days)."


def identifier_add(
    subject_id: str,
    kind: str,
    value: str,
    current: bool = True,
    city: str = "",
    state: str = "",
    zip: str = "",
    from_year: str = "",
    to_year: str = "",
    relation: str = "",
    note: str = "",
) -> str:
    """Add an identifier to a subject. kind: name, alias, email, phone, address, dob
    (YYYY-MM-DD), username, relative, domain. For name/alias/address give city and state (and zip,
    from_year, to_year for addresses) because brokers index by location. current=false
    marks a past name, address or number, which still matters for finding old listings.
    Also: username (handles you use online) and domain (domains you own)."""
    repo = SubjectRepo(_conn())
    meta: dict[str, str] = {}
    for k, v in (
        ("city", city),
        ("state", state),
        ("zip", zip),
        ("from_year", from_year),
        ("to_year", to_year),
        ("relation", relation),
    ):
        if v:
            meta[k] = v
    try:
        ident = Identifier(
            subject_id=subject_id, kind=kind, value=value, current=current, meta=meta, note=note
        )  # type: ignore[arg-type]
        ident = repo.add_identifier(subject_id, ident)
    except (KeyError, ValueError) as exc:
        return f"Not added: {exc}"
    AuditLog().append("identifier.add", subject=subject_id, kind=kind, identifier_id=ident.id)
    return f"Added {kind} `{ident.value}` to `{subject_id}` (id {ident.id}{', ' + json.dumps(ident.meta) if ident.meta else ''})."


def identifier_remove(identifier_id: int) -> str:
    """Remove an identifier by its numeric id (from subject_show)."""
    repo = SubjectRepo(_conn())
    repo.remove_identifier(identifier_id)
    AuditLog().append("identifier.remove", identifier_id=identifier_id)
    return f"Removed identifier {identifier_id}."


# catalog ----------------------------------------------------------------------------


def catalog_list(category: str = "", searchable_only: bool = False, limit: int = 100) -> str:
    """List catalog brokers. category: people-search, background-check, marketing, credit,
    other. searchable_only=true lists only sites the scanner can query by name."""
    catalog = load_catalog()
    brokers = list(catalog)
    if category:
        brokers = [b for b in brokers if b.category == category]
    if searchable_only:
        brokers = [b for b in brokers if b.searchable]
    # what the scanner can search first, then hand-curated entries, then the registries
    brokers.sort(key=lambda b: (not b.searchable, b.origin != "curated", b.id))
    rows = [
        [
            b.id,
            b.name[:40],
            b.category,
            b.status,
            "yes" if b.searchable else "",
            b.opt_out.method,
            ",".join(b.opt_out.requires),
            b.origin,
        ]
        for b in brokers[:limit]
    ]
    head = f"{len(brokers)} brokers" + (f" (showing {limit})" if len(brokers) > limit else "")
    return (
        head
        + "\n\n"
        + table(
            ["id", "name", "category", "status", "search", "opt-out", "requires", "origin"], rows
        )
    )


def catalog_show(broker_id: str) -> str:
    """Everything the catalog knows about one broker, including how to opt out."""
    catalog = load_catalog()
    try:
        b = catalog.get(broker_id)
    except KeyError as exc:
        return str(exc)
    lines = [f"# {b.name} (`{b.id}`)", ""]
    lines.append(f"- Category: {b.category}; status: {b.status}; origin: {b.origin}")
    if b.aka:
        lines.append(f"- Also known as: {', '.join(b.aka)}")
    lines.append(f"- Hosts: {', '.join(b.hosts) or '(none)'}")
    reg = [
        k
        for k, v in (
            ("CA", b.registry.ca),
            ("VT", b.registry.vt),
            ("TX", b.registry.tx),
            ("OR", b.registry.or_),
        )
        if v
    ]
    lines.append(f"- Registered: {', '.join(reg) or 'not in a state registry we import'}")
    c = b.contact
    lines.append(
        f"- Contact: email {c.privacy_email or '-'}; privacy page {c.privacy_url or '-'}; phone {c.phone or '-'}"
    )
    if c.postal:
        lines.append(f"- Postal: {c.postal}")
    lines.append(
        f"- Search: {b.search.method}"
        + (f" `{b.search.template}` via {b.search.fetch}" if b.search.method == "url" else "")
    )
    o = b.opt_out
    lines.append(
        f"- Opt-out: {o.method} {o.url or o.email or ''}; requires {', '.join(o.requires) or 'nothing special'}; captcha {o.captcha}"
    )
    if o.notes:
        lines.append(f"  - {o.notes}")
    if b.disclosures:
        lines.append(f"- Registry disclosures: {', '.join(b.disclosures)}")
    if b.notes:
        lines.append(f"- Notes: {b.notes}")
    lines.append(f"- Last verified: {b.last_verified or 'not verified'}")
    if b.sources:
        lines.append("- Sources: " + ", ".join(b.sources))
    return "\n".join(lines)


def catalog_search(text: str) -> str:
    """Find brokers by name, alias, id or host substring."""
    hits = load_catalog().search(text)
    if not hits:
        return f"No broker matches {text!r}."
    return table(
        ["id", "name", "category", "hosts", "opt-out"],
        [
            [b.id, b.name[:40], b.category, ", ".join(b.hosts[:3]), b.opt_out_channel[:60]]
            for b in hits
        ],
    )


# audit ------------------------------------------------------------------------------


def audit_tail(limit: int = 30) -> str:
    """Last entries of the hash-chained audit log, and whether the chain verifies."""
    log = AuditLog()
    ok, detail = log.verify()
    rows = [
        [e["ts"][:19], e["event"], e.get("actor", ""), json.dumps(e.get("data", {}))[:100]]
        for e in log.entries(limit)
    ]
    return f"{'Chain intact' if ok else 'CHAIN BROKEN'}: {detail}\n\n" + (
        table(["time", "event", "actor", "data"], rows) if rows else "No entries yet."
    )


# breaches ---------------------------------------------------------------------------


def scan_breaches(subject_id: str, sources: str = "") -> str:
    """Look up the subject's current emails, usernames and phones in breach sources.
    Emails: HIBP breaches, pastes and stealer logs (as far as the key's plan allows),
    LeakCheck, XposedOrNot analytics. Usernames: LeakCheck. Phones: LeakCheck Pro, only
    with LEAKCHECK_API_KEY, values dropped and field names kept. sources: comma-separated
    subset of hibp, leakcheck, xposedornot. Slow because of rate limits. Needs consent."""
    from unlist.scanners.breaches import scan_breaches as run_scan
    from unlist.scanners.breaches.run import SOURCES

    chosen = tuple(s.strip() for s in sources.split(",") if s.strip()) or SOURCES
    bad = set(chosen) - set(SOURCES)
    if bad:
        return f"Unknown sources {sorted(bad)}; choose from {', '.join(SOURCES)}."
    conn = _conn()
    try:
        res = run_scan(conn, subject_id, sources=chosen)
    except ConsentError as exc:
        return f"Refused: {exc}"
    checked = f"{len(res.emails)} address(es), {len(res.usernames)} username(s), {len(res.phones)} phone(s)"
    kinds = ", ".join(f"{v} {k}" for k, v in sorted(res.new_by_kind.items())) or "none"
    lines = [
        f"Breach scan run {res.run_id} for `{subject_id}`: {checked}; "
        f"**{res.new_hits} new** hit(s) ({kinds}), {res.seen_hits} already known.",
    ]
    if res.plan:
        lines.append(f"- HIBP plan: {res.plan.get('name')} ({res.plan.get('rpm')} requests a minute)")
    for src, why in res.skipped.items():
        lines.append(f"- skipped {src}: {why}")
    for err in res.errors:
        lines.append(f"- problem: {err}")
    if res.new_hits:
        lines.append("")
        lines.append(breaches_list(subject_id))
    return "\n".join(lines)


def breaches_list(subject_id: str, since: str = "") -> str:
    """Breach hits recorded for a subject, newest breach first. since: ISO date to show
    only hits first seen on or after it."""
    from unlist.scanners.breaches.run import hits_for

    rows = hits_for(_conn(), subject_id, since or None)
    if not rows:
        return "No breach hits recorded for this subject."
    return table(
        ["kind", "breach", "date", "identifier", "data exposed", "source", "first seen"],
        [
            [
                r["kind"],
                r["title"] or r["breach_name"],
                r["breach_date"] or "",
                r["identifier_value"],
                ", ".join(json.loads(r["data_classes_json"] or "[]"))[:100],
                r["source"],
                r["first_seen"][:10],
            ]
            for r in rows
        ],
    )


def password_checks_list() -> str:
    """Results of Pwned Passwords checks run from the terminal with `unlist password-check`.
    Passwords are typed at a hidden prompt there, never in chat; only a label and the
    number of times the password appears in breaches are stored."""
    rows = (
        _conn()
        .execute("SELECT * FROM password_checks ORDER BY checked_at DESC LIMIT 50")
        .fetchall()
    )
    if not rows:
        return "No password checks yet. Run `uv run unlist password-check` in a terminal."
    return table(
        ["label", "seen in breaches", "checked"],
        [[r["label"], r["pwned_count"], r["checked_at"]] for r in rows],
    )


def report_exposure(subject_id: str) -> str:
    """Markdown exposure report for a subject: breaches by name with data classes,
    people-search listings by status, removal requests, password checks. Also written to
    the reports directory."""
    from unlist.reports.exposure import write_exposure_report

    conn = _conn()
    try:
        path, body = write_exposure_report(conn, subject_id)
    except KeyError as exc:
        return str(exc)
    return f"# Exposure report: `{subject_id}`\n\n{body}\n\nWritten to {path}"


# brokers ----------------------------------------------------------------------------


def _catalog_brokers(ids: list[str]):
    catalog = load_catalog()
    if not ids:
        return catalog.searchable()
    out = []
    for i in ids:
        out.append(catalog.get(i))
    return out


def _browser(use_browser: bool):
    if not use_browser:
        return None
    from unlist.scanners.brokers.browser import BrowserSession

    return BrowserSession()


def scan_brokers(subject_id: str, brokers: str = "", use_browser: bool = True) -> str:
    """Search people-search sites for the subject's names and places. brokers: comma-
    separated catalog ids, default every searchable site. Plain HTTP first; when a site
    refuses, a visible Chromium window opens and does what you would do by hand (if it
    shows a CAPTCHA, deal with it there; the tool waits). Listings become candidate
    findings for you to confirm. Slow: several seconds per site. Needs consent."""
    from unlist.scanners.brokers import scan_brokers as run_scan
    from unlist.scanners.brokers.browser import BrowserUnavailable

    ids = [b.strip() for b in brokers.split(",") if b.strip()]
    try:
        chosen = _catalog_brokers(ids)
    except KeyError as exc:
        return str(exc)
    conn = _conn()
    browser = None
    note = ""
    try:
        try:
            browser = _browser(use_browser)
            if browser is not None:
                browser.start()
        except BrowserUnavailable as exc:
            browser = None
            note = f"\n- browser unavailable, HTTP only: {exc}"
        try:
            res = run_scan(conn, subject_id, brokers=chosen, browser=browser)
        except ConsentError as exc:
            return f"Refused: {exc}"
    finally:
        if browser is not None:
            browser.close()
    c = res.counts
    lines = [
        f"Broker scan run {res.run_id} for `{subject_id}`: {c['brokers']} site(s), {c['urls']} search(es); "
        f"**{c['new_candidates']} new candidate(s)**, {c['seen']} already known, {c['reappeared']} reappeared, "
        f"{c['below_threshold']} weak match(es) ignored.",
        f"- fetched {c['fetched']}, via browser {c['browser']}, refused {c['refused']}, challenged {c['challenged']}, "
        f"no results {c['no_results']}, errors {c['errors']}{note}",
    ]
    for n in res.notes:
        lines.append(f"- {n}")
    if c["new_candidates"] or c["reappeared"]:
        lines.append("")
        lines.append("Review with findings_list, then findings_confirm or findings_reject each id.")
        lines.append(findings_list(subject_id, status="candidate"))
    return "\n".join(lines)


def findings_list(subject_id: str, status: str = "", broker: str = "") -> str:
    """Listings found for a subject. status: candidate, confirmed, rejected, requested,
    removed, reappeared (default all). Candidates need your verdict before any request."""
    from unlist.scanners.brokers import findings as F

    rows = F.list_for(_conn(), subject_id, status or None, broker or None)
    if not rows:
        return "No findings" + (f" with status {status}" if status else "") + " for this subject."
    out = []
    for r in rows:
        ex = json.loads(r["extract_json"] or "{}")
        out.append(
            [
                r["id"],
                r["broker_id"],
                r["status"],
                r["score"],
                ex.get("name_text", ""),
                ex.get("age") or "",
                ", ".join(ex.get("places", [])[:3]),
                r["listing_url"][:80],
                r["last_seen"][:10],
            ]
        )
    return table(
        ["id", "broker", "status", "score", "name shown", "age", "places", "listing", "last seen"],
        out,
    )


def findings_show(finding_id: int) -> str:
    """One finding in full: what the page showed, why it scored as it did, the evidence file."""
    from unlist.scanners.brokers import findings as F

    conn = _conn()
    try:
        r = F.get(conn, finding_id)
    except KeyError as exc:
        return str(exc)
    ex = json.loads(r["extract_json"] or "{}")
    cap = (
        conn.execute("SELECT * FROM captures WHERE id=?", (r["capture_id"],)).fetchone()
        if r["capture_id"]
        else None
    )
    lines = [
        f"# Finding {r['id']}: {r['broker_id']} ({r['status']}, score {r['score']})",
        "",
        f"- Listing: {r['listing_url']}",
        f"- Name shown: {ex.get('name_text', '')}; age {ex.get('age') or '-'}",
        f"- Places: {', '.join(ex.get('places', [])) or '-'}",
        f"- Phones: {', '.join(ex.get('phones', [])) or '-'}",
        f"- Score reasons: {', '.join(ex.get('reasons', []))}",
        f"- First seen {r['first_seen']}, last seen {r['last_seen']}"
        + (f", verified {r['verified_at']}" if r["verified_at"] else ""),
    ]
    if r["note"]:
        lines.append(f"- Note: {r['note']}")
    if cap:
        lines.append(
            f"- Evidence: {paths.data_dir() / cap['raw_path']}"
            + (f"; screenshot {paths.data_dir() / cap['shot_path']}" if cap["shot_path"] else "")
        )
    if ex.get("snippet"):
        lines += ["", "> " + ex["snippet"][:400]]
    return "\n".join(lines)


def _ids(text: str) -> list[int]:
    return [int(x) for x in text.replace(",", " ").split() if x.strip().isdigit()]


def findings_confirm(finding_ids: str, note: str = "") -> str:
    """Mark findings (comma-separated ids) as yours. Only confirmed findings get requests."""
    from unlist.scanners.brokers import findings as F

    conn = _conn()
    done = []
    for fid in _ids(finding_ids):
        try:
            F.set_status(conn, fid, "confirmed", note or None)
            done.append(fid)
        except KeyError:
            pass
    return f"Marked confirmed: {done or 'nothing (ids not found)'}."


def findings_reject(finding_ids: str, note: str = "") -> str:
    """Mark findings (comma-separated ids) as someone else's. They are kept so the same
    listing is not offered again."""
    from unlist.scanners.brokers import findings as F

    conn = _conn()
    done = []
    for fid in _ids(finding_ids):
        try:
            F.set_status(conn, fid, "rejected", note or None)
            done.append(fid)
        except KeyError:
            pass
    return f"Marked rejected: {done or 'nothing (ids not found)'}."


def findings_verify(finding_ids: str, use_browser: bool = True) -> str:
    """Open each listing again to see whether it is still there. gone moves the finding to
    removed; a removed listing that is back becomes reappeared."""
    from unlist.scanners.brokers import verify_finding
    from unlist.scanners.brokers.browser import BrowserUnavailable

    conn = _conn()
    browser = None
    try:
        try:
            browser = _browser(use_browser)
        except BrowserUnavailable:
            browser = None
        rows = []
        for fid in _ids(finding_ids):
            try:
                verdict, detail = verify_finding(conn, fid, browser=browser)
            except (KeyError, ConsentError) as exc:
                verdict, detail = "error", str(exc)
            rows.append([fid, verdict, detail])
    finally:
        if browser is not None:
            browser.close()
    return table(["finding", "verdict", "detail"], rows) if rows else "No ids given."


# requests ---------------------------------------------------------------------------


def _request_row(r) -> list[object]:
    return [
        r["id"],
        r["broker_id"],
        r["channel"],
        r["basis"],
        r["state"],
        (r["deadline"] or "")[:10],
        r["tag"],
    ]


def requests_draft(
    subject_id: str,
    broker: str = "",
    finding_ids: str = "",
    channel: str = "",
    basis: str = "",
    prefer_optout: bool = False,
) -> str:
    """Draft removal requests. With no broker: one request per broker that has confirmed or
    reappeared findings and no open request. With broker (catalog id): one request for
    it, over the given finding ids (comma-separated) or blind. channel: email, form, mail
    (default from the catalog). basis: ccpa_delete, ccpa_optout, gdpr_art17, state_xx,
    plain (default from residency). Drafts are not sent until requests_approve."""
    from unlist.requests import draft_for_confirmed, draft_request

    conn = _conn()
    try:
        if broker:
            rows = [
                draft_request(
                    conn,
                    subject_id,
                    broker,
                    _ids(finding_ids),
                    channel=channel or None,
                    basis=basis or None,
                    prefer_optout=prefer_optout,
                )
            ]
        else:
            rows = draft_for_confirmed(
                conn,
                subject_id,
                channel=channel or None,
                basis=basis or None,
                prefer_optout=prefer_optout,
            )
    except (ConsentError, KeyError, ValueError) as exc:
        return f"Not drafted: {exc}"
    if not rows:
        return "Nothing to draft: no confirmed or reappeared findings without an open request."
    out = [
        f"Drafted {len(rows)} request(s). Read each with requests_show, then requests_approve the ids you want sent.",
        "",
    ]
    out.append(
        table(
            ["id", "broker", "channel", "basis", "state", "deadline", "tag"],
            [_request_row(r) for r in rows],
        )
    )
    return "\n".join(out)


def requests_draft_blind(
    subject_id: str, category: str = "", only_registry: bool = True, limit: int = 50
) -> str:
    """Draft email deletion requests to brokers you have no listing for (every active
    catalog broker with an email address and no open request). category: people-search,
    marketing, background-check, credit, other; only_registry limits to California
    registrants. limit caps the batch. Review and approve before anything is sent."""
    from unlist.requests import draft_blind

    conn = _conn()
    try:
        rows = draft_blind(
            conn, subject_id, category=category or None, only_registry=only_registry, limit=limit
        )
    except (ConsentError, KeyError, ValueError) as exc:
        return f"Not drafted: {exc}"
    if not rows:
        return "Nothing to draft: every matching broker already has an open request."
    return f"Drafted {len(rows)} blind request(s): ids {rows[0]['id']} to {rows[-1]['id']}. Use requests_list state=drafted, then requests_approve."


def requests_list(subject_id: str = "", state: str = "", broker: str = "") -> str:
    """Removal requests. state: drafted, approved, sent, submitted, awaiting_verification,
    acknowledged, completed, verified_removed, failed, reappeared, cancelled, overdue, or
    open (everything not closed)."""
    from unlist.requests.engine import list_for

    rows = list_for(_conn(), subject_id or None, state or None, broker or None)
    if not rows:
        return "No requests match."
    return table(
        ["id", "broker", "channel", "basis", "state", "deadline", "tag"],
        [_request_row(r) for r in rows],
    )


def requests_show(request_id: int) -> str:
    """One request in full: the letter as it will go (or went), listings, events, replies."""
    from unlist.requests.engine import events_for, get

    conn = _conn()
    try:
        r = get(conn, request_id)
    except KeyError as exc:
        return str(exc)
    lines = [
        f"# Request {r['id']}: {r['broker_id']} ({r['channel']}, {r['basis']}, **{r['state']}**)",
        "",
        f"- Tag: {r['tag']}; created {r['created_at']}"
        + (f"; sent {r['sent_at']}" if r["sent_at"] else "")
        + (f"; deadline {r['deadline']}" if r["deadline"] else ""),
        f"- To: {r['to_address'] or r['form_url'] or r['drop_id'] or '-'}",
        f"- Listings: {', '.join(json.loads(r['listings_json'] or '[]')) or 'none (blind request)'}",
    ]
    if r["note"]:
        lines.append(f"- Note: {r['note']}")
    ev = events_for(conn, request_id)
    if ev:
        lines += [
            "",
            "Events:",
            table(
                ["at", "kind", "detail"],
                [[e["at"][:16], e["kind"], (e["detail"] or "")[:100]] for e in ev],
            ),
        ]
    replies = conn.execute(
        "SELECT * FROM inbox_messages WHERE request_id=? ORDER BY id", (request_id,)
    ).fetchall()
    if replies:
        lines += [
            "",
            "Replies:",
            table(
                ["received", "from", "subject", "class", "action"],
                [
                    [
                        (m["received_at"] or "")[:16],
                        m["from_addr"],
                        m["subject"][:60],
                        m["classification"],
                        (m["action"] or "")[:80],
                    ]
                    for m in replies
                ],
            ),
        ]
    if r["body"]:
        lines += ["", f"Subject: {r['subject_line']}", "", "```", r["body"].rstrip(), "```"]
    return "\n".join(lines)


def requests_approve(request_ids: str) -> str:
    """Approve drafted requests (comma-separated ids, or 'all' for every draft). Email
    requests are then sent by requests_send; form requests are opened by form_open."""
    from unlist.requests import approve
    from unlist.requests.engine import list_for

    conn = _conn()
    ids = (
        [r["id"] for r in list_for(conn, None, "drafted")]
        if request_ids.strip().lower() == "all"
        else _ids(request_ids)
    )
    rows = approve(conn, ids)
    if not rows:
        return "Nothing approved (ids not found or not in drafted state)."
    by_channel: dict[str, list[int]] = {}
    for r in rows:
        by_channel.setdefault(r["channel"], []).append(r["id"])
    parts = [f"Approved {len(rows)}: " + "; ".join(f"{ch} {ids}" for ch, ids in by_channel.items())]
    if "email" in by_channel:
        parts.append("Send the email ones with requests_send.")
    if "form" in by_channel:
        parts.append("Open each form one with form_open.")
    if "mail" in by_channel:
        parts.append("Render letters with letter_write.")
    return " ".join(parts)


def requests_send(request_ids: str = "", dry_run: bool = False) -> str:
    """Send approved email requests from the opt-out mailbox (UNLIST_SMTP_* in .env).
    Default: every approved email request; or comma-separated ids. dry_run shows what
    would go without sending. Only approved requests are ever sent."""
    from unlist.requests import send_approved
    from unlist.requests.engine import list_for
    from unlist.requests.mailer import FakeMailer, Mailer, SmtpSettings

    conn = _conn()
    ids = _ids(request_ids) or None
    if dry_run:
        rows = list(list_for(conn, None, "approved")) if ids is None else []
        if ids:
            from unlist.requests.engine import get as _get

            rows = [_get(conn, i) for i in ids]
        rows = [r for r in rows if r["channel"] == "email"]
        return "Would send:\n" + (
            table(
                ["id", "to", "subject"],
                [[r["id"], r["to_address"], r["subject_line"]] for r in rows],
            )
            if rows
            else "nothing"
        )
    settings = SmtpSettings.from_env()
    if settings is None:
        return "No mailbox configured: set UNLIST_SMTP_HOST, UNLIST_SMTP_USER and UNLIST_SMTP_PASSWORD in .env (a mailbox created for opt-outs, never your main account)."
    mailer: object = Mailer(settings) if not isinstance(settings, FakeMailer) else settings
    results = send_approved(conn, mailer, ids)
    if not results:
        return "Nothing to send: no approved email requests."
    return table(
        ["id", "sent", "detail"],
        [[rid, "yes" if ok else "no", detail] for rid, ok, detail in results],
    )


def requests_mark(request_id: int, state: str, note: str = "") -> str:
    """Set a request's state by hand (e.g. completed after a reply you handled yourself,
    cancelled, failed, submitted after a form you finished). States: drafted, approved,
    sent, submitted, awaiting_verification, acknowledged, completed, verified_removed,
    failed, reappeared, cancelled, overdue."""
    from unlist.requests import set_state
    from unlist.requests.engine import get, mark_sent

    conn = _conn()
    try:
        if state in ("sent", "submitted") and not get(conn, request_id)["sent_at"]:
            r = mark_sent(conn, request_id, state, note or None)
        else:
            r = set_state(conn, request_id, state, note or None)
    except (KeyError, ValueError) as exc:
        return str(exc)
    return (
        f"Request {r['id']} is now {r['state']}"
        + (f" (deadline {r['deadline'][:10]})" if r["deadline"] else "")
        + "."
    )


def inbox_poll(limit: int = 50) -> str:
    """Read unseen mail in the opt-out mailbox (UNLIST_IMAP_* in .env), classify replies,
    tie them to requests, follow confirmation links that point at the broker's own hosts,
    and move request states. Anything else is surfaced for you."""
    from unlist.requests.inbox import ImapInbox, ImapSettings, process_messages

    settings = ImapSettings.from_env()
    if settings is None:
        return "No mailbox configured: set UNLIST_IMAP_HOST (and UNLIST_SMTP_USER/PASSWORD or UNLIST_IMAP_USER/PASSWORD) in .env."
    conn = _conn()
    try:
        with ImapInbox(settings) as inbox:
            messages = inbox.fetch_unseen(limit)
            results = process_messages(conn, messages)
            for m in messages:
                inbox.mark_seen(m.uid)
    except Exception as exc:
        return f"Mailbox error: {exc}"
    if not results:
        return "No new messages."
    return table(
        ["from", "subject", "class", "request", "action"],
        [
            [r["from"], r["subject"][:50], r["kind"], r["request_id"] or "", r["action"][:90]]
            for r in results
        ],
    )


def form_open(request_id: int) -> str:
    """Open an approved form request in a visible Chromium, prefilled from the broker's
    playbook, and stop before submit. You finish it (submit, CAPTCHA, email link) and
    close the window; the helper records before and after screenshots and marks the
    request submitted when the page moved on. Runs as its own process."""
    from unlist.requests.engine import get
    from unlist.requests.form import launch_form_assist

    conn = _conn()
    try:
        r = get(conn, request_id)
    except KeyError as exc:
        return str(exc)
    if r["channel"] != "form":
        return f"Request {request_id} is a {r['channel']} request."
    if r["state"] not in ("approved", "awaiting_verification"):
        return f"Request {request_id} is {r['state']}; approve it first."
    pid = launch_form_assist(request_id)
    return (
        f"Opened a browser for request {request_id} ({r['broker_id']}) at {r['form_url']} (helper pid {pid}). "
        "Finish the form there and close the window. Then requests_show to see what was recorded, "
        "or requests_mark if the helper could not tell."
    )


def letter_write(request_id: int) -> str:
    """Render a mail-channel request as a PDF letter under the data directory for printing."""
    from unlist.requests.pdf import write_letter

    try:
        p = write_letter(_conn(), request_id)
    except KeyError as exc:
        return str(exc)
    return f"Letter written to {p}. Post it, then requests_mark {request_id} sent."


def drop_prepare(subject_id: str) -> str:
    """For California residents: exactly what to enter at the state's DROP platform, which
    every registered broker must honour on a 45-day cycle. The tool cannot submit it."""
    from unlist.requests.drop import drop_profile

    try:
        return drop_profile(_conn(), subject_id)
    except ConsentError as exc:
        return f"Refused: {exc}"


def drop_record(subject_id: str, drop_id: str) -> str:
    """Record the 8-digit DROP ID after you submitted at DROP, so the cycle is tracked."""
    from unlist.requests.drop import record_drop

    try:
        r = record_drop(_conn(), subject_id, drop_id)
    except (ConsentError, ValueError) as exc:
        return f"Not recorded: {exc}"
    return f"DROP ID {r['drop_id']} recorded as request {r['id']}; brokers must act by {r['deadline'][:10]}."


# monitor ----------------------------------------------------------------------------


def monitor_run_due(force: bool = False, only: str = "", use_browser: bool = True) -> str:
    """Run every scheduled job that is due: breach rescans (weekly), listing verification
    (every 14 days), full people-search sweep (monthly), deadline checks, DROP cycle,
    follow-up drafts for reappeared listings, inbox poll (daily). force runs them all;
    only: comma-separated job names. Writes a monitor report and a macOS notification
    when something changed. Can take minutes."""
    from unlist.monitor import JOBS, run_due

    chosen = {x.strip() for x in only.split(",") if x.strip()} or None
    if chosen and (bad := chosen - set(JOBS)):
        return f"Unknown jobs {sorted(bad)}; choose from {', '.join(JOBS)}."
    s = run_due(_conn(), force=force, use_browser=use_browser, only=chosen)
    lines = [
        f"Ran: {', '.join(s.ran) or 'nothing was due'}; skipped: {', '.join(s.skipped) or 'none'}",
        "",
    ]
    lines += [f"- {c}" for c in s.changes] or ["- nothing changed"]
    if s.problems:
        lines += ["", "Problems:"] + [f"- {p}" for p in s.problems]
    lines += ["", f"Report: {s.report_path}"]
    return "\n".join(lines)


def monitor_status() -> str:
    """Each scheduled job: interval, last run, next due, last result."""
    from unlist.monitor.run import jobs_status

    return table(["job", "every", "last run", "next", "last result", "what"], jobs_status(_conn()))


def monitor_set_interval(job: str, interval: str) -> str:
    """Change a job's interval, e.g. verify_listings 7d, breaches 3d, brokers_full 2w."""
    from unlist.monitor.run import set_interval

    try:
        set_interval(_conn(), job, interval)
    except ValueError as exc:
        return str(exc)
    return f"{job} now runs every {interval}."


def reports_list(kind: str = "") -> str:
    """Markdown reports written so far (exposure, monitor), newest first."""
    base = paths.reports_dir()
    files = sorted(base.glob(f"{kind or '*'}/*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        return "No reports yet."
    return table(
        ["report", "written"],
        [
            [
                str(p.relative_to(base)),
                p.stat().st_mtime
                and __import__("datetime")
                .datetime.fromtimestamp(p.stat().st_mtime)
                .strftime("%Y-%m-%d %H:%M"),
            ]
            for p in files[:40]
        ],
    )


def report_read(name: str) -> str:
    """Read one report by its path from reports_list (e.g. monitor/2026-11-04_run.md)."""
    p = (paths.reports_dir() / name).resolve()
    if not str(p).startswith(str(paths.reports_dir().resolve())) or not p.is_file():
        return f"No report {name!r}."
    return p.read_text(encoding="utf-8")


# footprint --------------------------------------------------------------------------


def scan_usernames(subject_id: str, limit: int = 0, categories: str = "", include_nsfw: bool = False) -> str:
    """Check where the subject's usernames exist, one request per site, using the
    WhatsMyName dataset (about 700 sites; downloaded and cached locally). Hits become
    candidate account exposures to confirm or reject. limit caps the number of sites;
    categories (comma-separated, e.g. social,coding,gaming) narrows it. Takes several
    minutes per username at full size. Needs consent."""
    from unlist.scanners.usernames import scan_usernames as run
    from unlist.scanners.usernames.wmn import CREDIT

    cats = {c.strip() for c in categories.split(",") if c.strip()} or None
    try:
        res = run(_conn(), subject_id, limit=limit or None, categories=cats, include_nsfw=include_nsfw)
    except ConsentError as exc:
        return f"Refused: {exc}"
    except RuntimeError as exc:
        return str(exc)
    if not res.usernames:
        return "This subject has no username identifier. Add one with identifier_add kind=username."
    c = res.counts
    out = [
        f"Username scan run {res.run_id} for `{subject_id}` ({', '.join(res.usernames)}): {c['sites']} site(s) checked, "
        f"{c['skipped_sites']} skipped (challenge-protected or filtered); **{c['found']} account(s) found**, {c['new']} new, "
        f"{c['missing']} absent, {c['unknown']} unclear.",
        CREDIT,
    ]
    if res.found:
        out += ["", exposures_list(subject_id, kind="account", status="candidate")]
    return "\n".join(out)


def scan_mentions(subject_id: str) -> str:
    """Search the web (Brave Search API, needs BRAVE_API_KEY) for the subject's name with
    city, phone numbers and emails. Results are shown here and not stored (Brave's terms);
    pass the URLs that are about the subject to mentions_confirm. Results on a known
    broker's site are flagged. Needs consent."""
    from unlist.scanners.mentions import scan_mentions as run

    try:
        res = run(_conn(), subject_id)
    except ConsentError as exc:
        return f"Refused: {exc}"
    if res.skipped:
        return f"Not run: {res.skipped}."
    lines = [f"{len(res.queries)} quer(ies), {len(res.mentions)} result(s). Nothing below is stored until you confirm it."]
    lines += [f"- problem: {e}" for e in res.errors]
    if res.mentions:
        lines += ["", table(
            ["#", "site", "broker", "title", "url", "recorded"],
            [[i + 1, m.host, m.broker_id or "", m.title[:60], m.url, m.already or ""] for i, m in enumerate(res.mentions)],
        )]
    return "\n".join(lines)


def mentions_confirm(subject_id: str, urls: str, note: str = "") -> str:
    """Record web pages (URLs separated by spaces or new lines) as being about the subject.
    A URL on a known broker's site also becomes a confirmed listing, ready for
    requests_draft."""
    from unlist.scanners.mentions import confirm_mention

    conn = _conn()
    rows = []
    for url in urls.split():
        try:
            eid, fid = confirm_mention(conn, subject_id, url.strip(), note=note)
            rows.append([url, eid, fid or ""])
        except (ConsentError, ValueError) as exc:
            rows.append([url, "", str(exc)])
    return table(["url", "exposure", "finding"], rows) if rows else "No URLs given."


def scan_domains(subject_id: str) -> str:
    """For domains the subject owns (identifier kind domain): SPF and DMARC (can anyone
    send mail as this domain?), MX, and hostnames visible in certificate-transparency
    logs. Not a vulnerability scan. Needs consent."""
    from unlist.scanners.domains import scan_domains as run

    try:
        res = run(_conn(), subject_id)
    except ConsentError as exc:
        return f"Refused: {exc}"
    if not res.domains:
        return "This subject has no domain identifier. Add one with identifier_add kind=domain."
    lines = [f"Checked {', '.join(res.domains)}."]
    lines += [f"- issue: {i}" for i in res.issues] or ["- no email-spoofing issues"]
    lines += [f"- fixed: {i}" for i in res.resolved]
    lines += [f"- note: {i}" for i in res.info]
    lines += [f"- problem: {i}" for i in res.errors]
    return "\n".join(lines)


def exposures_list(subject_id: str, kind: str = "", status: str = "") -> str:
    """Accounts found by username, confirmed web mentions and owned-domain findings.
    kind: account, mention, domain. status: candidate, confirmed, rejected, resolved."""
    from unlist.scanners import exposures as X

    rows = X.list_for(_conn(), subject_id, kind or None, status or None)
    if not rows:
        return "No exposures match."
    return table(
        ["id", "kind", "status", "what", "identifier", "url", "detail", "last seen"],
        [
            [r["id"], r["kind"], r["status"], r["title"] or r["key"], r["identifier_value"], (r["url"] or "")[:70],
             (r["detail_json"] or "")[:60], r["last_seen"][:10]]
            for r in rows
        ],
    )


def exposures_confirm(exposure_ids: str, note: str = "") -> str:
    """Mark exposures (comma-separated ids) as the subject's own, e.g. accounts that are
    really theirs. Confirmed accounts feed accounts_cleanup and the exposure score."""
    from unlist.scanners import exposures as X

    conn = _conn()
    done = []
    for eid in _ids(exposure_ids):
        try:
            X.set_status(conn, eid, "confirmed", note or None)
            done.append(eid)
        except KeyError:
            pass
    return f"Marked confirmed: {done or 'nothing (ids not found)'}."


def exposures_reject(exposure_ids: str, note: str = "") -> str:
    """Mark exposures (comma-separated ids) as not the subject's (someone else's account
    with the same handle). 'resolved' is set with exposures_resolve once dealt with."""
    from unlist.scanners import exposures as X

    conn = _conn()
    done = []
    for eid in _ids(exposure_ids):
        try:
            X.set_status(conn, eid, "rejected", note or None)
            done.append(eid)
        except KeyError:
            pass
    return f"Marked rejected: {done or 'nothing (ids not found)'}."


def exposures_resolve(exposure_ids: str, note: str = "") -> str:
    """Mark exposures as dealt with (account deleted, page taken down, record fixed)."""
    from unlist.scanners import exposures as X

    conn = _conn()
    done = []
    for eid in _ids(exposure_ids):
        try:
            X.set_status(conn, eid, "resolved", note or None)
            done.append(eid)
        except KeyError:
            pass
    return f"Marked resolved: {done or 'nothing (ids not found)'}."
