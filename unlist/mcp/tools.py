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
        rows.append([s.id, s.kind, s.label, s.residency_state or s.residency_country, len(s.identifiers), consent])
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
    lines.append(f"- Residency: {s.residency_state or ''} {s.residency_country}; regime `{s.legal_regime}`")
    if s.consent:
        lines.append(
            f"- Consent: {s.consent.holder}, \"{s.consent.instrument}\", {s.consent.granted} to "
            f"{s.consent.expires}"
            + (f"; scope: {s.consent.scope_note}" if s.consent.scope_note else "")
        )
    else:
        lines.append("- Consent: **none recorded** (consent_grant needed before any scan)")
    if s.note:
        lines.append(f"- Note: {s.note}")
    lines.append("")
    rows = [
        [i.id, i.kind, i.value, "yes" if i.current else "past", json.dumps(i.meta) if i.meta else "", i.note]
        for i in s.identifiers
    ]
    lines.append(table(["id", "kind", "value", "current", "meta", "note"], rows) if rows else "No identifiers yet.")
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
    AuditLog().append("consent.grant", subject=subject_id, holder=holder, instrument=instrument, expires=expires)
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
    (YYYY-MM-DD), username, relative. For name/alias/address give city and state (and zip,
    from_year, to_year for addresses) because brokers index by location. current=false
    marks a past name, address or number, which still matters for finding old listings."""
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
        ident = Identifier(subject_id=subject_id, kind=kind, value=value, current=current, meta=meta, note=note)  # type: ignore[arg-type]
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
    rows = [
        [b.id, b.name[:40], b.category, b.status, "yes" if b.searchable else "", b.opt_out.method, ",".join(b.opt_out.requires), b.origin]
        for b in brokers[:limit]
    ]
    head = f"{len(brokers)} brokers" + (f" (showing {limit})" if len(brokers) > limit else "")
    return head + "\n\n" + table(["id", "name", "category", "status", "search", "opt-out", "requires", "origin"], rows)


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
    reg = [k for k, v in (("CA", b.registry.ca), ("VT", b.registry.vt), ("TX", b.registry.tx), ("OR", b.registry.or_)) if v]
    lines.append(f"- Registered: {', '.join(reg) or 'not in a state registry we import'}")
    c = b.contact
    lines.append(f"- Contact: email {c.privacy_email or '-'}; privacy page {c.privacy_url or '-'}; phone {c.phone or '-'}")
    if c.postal:
        lines.append(f"- Postal: {c.postal}")
    lines.append(f"- Search: {b.search.method}" + (f" `{b.search.template}` via {b.search.fetch}" if b.search.method == 'url' else ''))
    o = b.opt_out
    lines.append(f"- Opt-out: {o.method} {o.url or o.email or ''}; requires {', '.join(o.requires) or 'nothing special'}; captcha {o.captcha}")
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
        [[b.id, b.name[:40], b.category, ", ".join(b.hosts[:3]), b.opt_out_channel[:60]] for b in hits],
    )


# audit ------------------------------------------------------------------------------


def audit_tail(limit: int = 30) -> str:
    """Last entries of the hash-chained audit log, and whether the chain verifies."""
    log = AuditLog()
    ok, detail = log.verify()
    rows = [[e["ts"][:19], e["event"], e.get("actor", ""), json.dumps(e.get("data", {}))[:100]] for e in log.entries(limit)]
    return f"{'Chain intact' if ok else 'CHAIN BROKEN'}: {detail}\n\n" + (table(["time", "event", "actor", "data"], rows) if rows else "No entries yet.")


# breaches ---------------------------------------------------------------------------


def scan_breaches(subject_id: str, sources: str = "") -> str:
    """Look up every current email address of the subject in breach databases (HIBP with
    a key, LeakCheck public, XposedOrNot; all return breach names, never leaked values).
    sources: comma-separated subset of hibp, leakcheck, xposedornot. Takes a few seconds
    per address because of rate limits. Needs consent on record."""
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
    lines = [
        f"Breach scan run {res.run_id} for `{subject_id}`: {len(res.emails)} address(es), "
        f"**{res.new_hits} new** hit(s), {res.seen_hits} already known.",
    ]
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
        ["breach", "date", "address", "data exposed", "source", "first seen"],
        [
            [
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
    rows = _conn().execute(
        "SELECT * FROM password_checks ORDER BY checked_at DESC LIMIT 50"
    ).fetchall()
    if not rows:
        return "No password checks yet. Run `uv run unlist password-check` in a terminal."
    return table(["label", "seen in breaches", "checked"], [[r["label"], r["pwned_count"], r["checked_at"]] for r in rows])


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
