"""Run every breach source for a subject's emails, usernames and phones and store the hits."""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass, field

from unlist.core.audit import AuditLog
from unlist.core.fetch import Fetcher, RateLimiter
from unlist.core.timeutil import now_iso
from unlist.scanners.breaches import xposedornot
from unlist.scanners.breaches.hibp import Breach, HibpClient
from unlist.scanners.breaches.leakcheck import LeakCheckClient, LeakCheckProClient, redact
from unlist.scanners.breaches.xposedornot import XposedOrNotClient
from unlist.scanners.evidence import record_fetch
from unlist.subjects import SubjectRepo

TOOL = "breaches"
SOURCES = ("hibp", "leakcheck", "xposedornot")

# Documented limits: HIBP Core 1 is 10 requests a minute; LeakCheck public asks for one
# a second (Pro three); XposedOrNot allows two a second but only 25 an hour, so it is
# paced gently; Pwned Passwords has no limit.
HOST_INTERVALS = {
    "haveibeenpwned.com": 6.5,
    "leakcheck.io": 1.2,
    "api.xposedornot.com": 3.0,
    "api.pwnedpasswords.com": 0.2,
}


def make_fetcher() -> Fetcher:
    return Fetcher(limiter=RateLimiter(host_intervals=HOST_INTERVALS))


@dataclass
class ScanResult:
    run_id: int
    subject_id: str
    emails: list[str]
    usernames: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    new_hits: int = 0
    seen_hits: int = 0
    new_by_kind: dict[str, int] = field(default_factory=dict)
    skipped: dict[str, str] = field(default_factory=dict)  # source -> why
    errors: list[str] = field(default_factory=list)
    plan: dict | None = None

    @property
    def counts(self) -> dict[str, object]:
        return {
            "emails": len(self.emails),
            "usernames": len(self.usernames),
            "phones": len(self.phones),
            "new_hits": self.new_hits,
            "seen_hits": self.seen_hits,
            "new_by_kind": self.new_by_kind,
            "skipped": self.skipped,
            "errors": len(self.errors),
        }


def _enrich(b: Breach, c: Breach) -> Breach:
    """Fill a bare hit from another source with what HIBP knows about the same breach."""
    classes = list(c.data_classes)
    for x in b.data_classes:
        if x not in classes and x.lower() not in {y.lower() for y in classes}:
            classes.append(x)
    return Breach(
        name=b.name,
        title=c.title or b.title,
        domain=c.domain or b.domain,
        breach_date=c.breach_date or b.breach_date,
        added_date=c.added_date or b.added_date,
        data_classes=classes,
        pwn_count=c.pwn_count if c.pwn_count is not None else b.pwn_count,
        is_verified=c.is_verified if c.is_verified is not None else b.is_verified,
        is_sensitive=c.is_sensitive if c.is_sensitive is not None else b.is_sensitive,
    )


def _upsert_hit(
    conn: sqlite3.Connection,
    subject_id: str,
    identifier_id: int | None,
    value: str,
    source: str,
    b: Breach,
    capture_id: int | None,
    now: str,
    kind: str = "breach",
) -> bool:
    """Insert or refresh one hit. Returns True when it is new."""
    existing = conn.execute(
        "SELECT id FROM breach_hits WHERE subject_id=? AND identifier_value=? AND source=? "
        "AND breach_name=?",
        (subject_id, value, source, b.name),
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE breach_hits SET last_seen=?, data_classes_json=CASE WHEN ?='[]' THEN "
            "data_classes_json ELSE ? END WHERE id=?",
            (now, json.dumps(b.data_classes), json.dumps(b.data_classes), existing["id"]),
        )
        return False
    conn.execute(
        """INSERT INTO breach_hits(subject_id, identifier_id, identifier_value, source,
             breach_name, title, domain, breach_date, added_date, data_classes_json, pwn_count,
             is_verified, is_sensitive, capture_id, first_seen, last_seen, kind)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            subject_id,
            identifier_id,
            value,
            source,
            b.name,
            b.title,
            b.domain,
            b.breach_date,
            b.added_date,
            json.dumps(b.data_classes),
            b.pwn_count,
            None if b.is_verified is None else int(b.is_verified),
            None if b.is_sensitive is None else int(b.is_sensitive),
            capture_id,
            now,
            now,
            kind,
        ),
    )
    return True


def set_metric(conn: sqlite3.Connection, subject_id: str, source: str, metric: str, value) -> None:
    conn.execute(
        "INSERT INTO subject_metrics(subject_id, source, metric, value_json, updated_at) "
        "VALUES (?,?,?,?,?) ON CONFLICT(subject_id, source, metric) DO UPDATE SET "
        "value_json=excluded.value_json, updated_at=excluded.updated_at",
        (subject_id, source, metric, json.dumps(value), now_iso()),
    )


def metrics_for(conn: sqlite3.Connection, subject_id: str) -> dict[tuple[str, str], object]:
    return {
        (r["source"], r["metric"]): json.loads(r["value_json"])
        for r in conn.execute("SELECT * FROM subject_metrics WHERE subject_id=?", (subject_id,))
    }


def scan_breaches(
    conn: sqlite3.Connection,
    subject_id: str,
    *,
    fetcher: Fetcher | None = None,
    sources: tuple[str, ...] = SOURCES,
    hibp_api_key: str | None = None,
    leakcheck_api_key: str | None = None,
    audit: AuditLog | None = None,
) -> ScanResult:
    """Look the subject's current emails, usernames and phones up in each source.

    Emails: HIBP breaches, pastes and stealer logs (as the key's plan allows), LeakCheck,
    XposedOrNot analytics. Usernames: LeakCheck. Phones: LeakCheck Pro, only with a key,
    with every leaked value dropped before storage. Consent is checked first. Every
    answer is kept as evidence. Hits are upserted so a repeat run reports what is new.
    """
    repo = SubjectRepo(conn)
    subject = repo.require(subject_id)
    emails = [i for i in subject.of_kind("email") if i.current]
    usernames = [i for i in subject.of_kind("username") if i.current]
    phones = [i for i in subject.of_kind("phone") if i.current]
    fetcher = fetcher or make_fetcher()
    audit = audit or AuditLog()
    key = hibp_api_key if hibp_api_key is not None else os.environ.get("HIBP_API_KEY")
    lc_key = (
        leakcheck_api_key
        if leakcheck_api_key is not None
        else os.environ.get("LEAKCHECK_API_KEY")
    )
    cur = conn.execute(
        "INSERT INTO scan_runs(subject_id, kind, started_at, params_json) VALUES (?,?,?,?)",
        (subject_id, TOOL, now_iso(), json.dumps({"sources": list(sources)})),
    )
    res = ScanResult(
        run_id=int(cur.lastrowid),
        subject_id=subject_id,
        emails=[e.value for e in emails],
        usernames=[u.value for u in usernames],
        phones=[p.value for p in phones],
    )
    audit.append(
        "scan.breaches.start",
        subject=subject_id,
        run_id=res.run_id,
        emails=len(emails),
        usernames=len(usernames),
        phones=len(phones),
    )

    def store(ident, source: str, hits: list[Breach], capture_id: int | None, kind: str) -> None:
        now = now_iso()
        for b in hits:
            if source != "hibp" and kind == "breach" and b.name in catalog:
                b = _enrich(b, catalog[b.name])
            new = _upsert_hit(
                conn, subject_id, ident.id, ident.value, source, b, capture_id, now, kind
            )
            if new:
                res.new_hits += 1
                res.new_by_kind[kind] = res.new_by_kind.get(kind, 0) + 1
            else:
                res.seen_hits += 1
        conn.commit()

    def failed(source: str, what: str, r) -> None:
        why = r.reason or r.error or f"HTTP {r.status}"
        res.errors.append(f"{source} {what}: {why}")
        if r.status == 401:
            res.skipped[source] = "rejected the API key (401)"

    hibp = HibpClient(fetcher, key)
    # The public breach list is keyless and fills in dates and data classes for names the
    # other sources return bare, so it is fetched whatever sources were chosen.
    r, catalog = hibp.all_breaches()
    record_fetch(conn, TOOL, r, note="hibp breach list")
    if not r.ok:
        res.errors.append(f"hibp breach list: {r.reason or r.error or r.status}")
    use_hibp = "hibp" in sources and hibp.has_key
    stealer_ok = False
    if "hibp" in sources and not hibp.has_key:
        res.skipped["hibp"] = "no HIBP_API_KEY; per-address lookups and pastes need a Core plan key"
    if use_hibp:
        r, plan = hibp.subscription()
        record_fetch(conn, TOOL, r, note="hibp subscription status")
        if plan:
            res.plan = plan
            stealer_ok = bool(plan.get("stealer_logs"))
            set_metric(conn, subject_id, "hibp", "plan", plan)
            if plan.get("rpm"):
                fetcher.limiter.host_intervals["haveibeenpwned.com"] = max(
                    0.2, 60.0 / float(plan["rpm"]) + 0.3
                )
        if not stealer_ok:
            res.skipped["hibp-stealer"] = "stealer-log lookups need an HIBP Pro plan"

    leak = LeakCheckClient(fetcher)
    xon = XposedOrNotClient(fetcher)

    for ident in emails:
        email = ident.value
        if use_hibp:
            r, hits = hibp.breached_account(email)
            cid = record_fetch(conn, TOOL, r, note="hibp lookup")
            if hits is None:
                failed("hibp", email, r)
            else:
                store(ident, "hibp", hits, cid, "breach")
            r, hits = hibp.pastes(email)
            cid = record_fetch(conn, TOOL, r, note="hibp pastes")
            if hits is None:
                failed("hibp-pastes", email, r)
            else:
                store(ident, "hibp", hits, cid, "paste")
            if stealer_ok:
                r, hits = hibp.stealer_logs(email)
                cid = record_fetch(conn, TOOL, r, note="hibp stealer logs")
                if hits is None:
                    failed("hibp-stealer", email, r)
                else:
                    store(ident, "hibp", hits, cid, "stealer")
        if "leakcheck" in sources:
            r, hits = leak.check(email)
            cid = record_fetch(conn, TOOL, r, note="leakcheck lookup")
            if hits is None:
                failed("leakcheck", email, r)
            else:
                store(ident, "leakcheck", hits, cid, "breach")
        if "xposedornot" in sources:
            r, parsed = xposedornot.analytics(fetcher, email)
            cid = record_fetch(conn, TOOL, r, note="xposedornot analytics")
            if parsed is None:
                # analytics is rate-limited hard; the plain check still answers
                r, hits = xon.check(email)
                cid = record_fetch(conn, TOOL, r, note="xposedornot lookup")
                if hits is None:
                    failed("xposedornot", email, r)
                else:
                    store(ident, "xposedornot", hits, cid, "breach")
            else:
                hits, metrics = parsed
                store(ident, "xposedornot", hits, cid, "breach")
                if metrics:
                    set_metric(conn, subject_id, "xposedornot", f"risk:{email}", metrics)

    if "leakcheck" in sources:
        for ident in usernames:
            r, hits = leak.check(ident.value)
            cid = record_fetch(conn, TOOL, r, note="leakcheck username lookup")
            if hits is None:
                failed("leakcheck", f"username {ident.value}", r)
            else:
                store(ident, "leakcheck", hits, cid, "breach")
        if phones and not lc_key:
            res.skipped["leakcheck-phone"] = (
                "phone lookups need LEAKCHECK_API_KEY (Pro); values would be dropped, "
                "field names kept"
            )
        if phones and lc_key:
            pro = LeakCheckProClient(fetcher, lc_key)
            for ident in phones:
                r, hits = pro.query(ident.value[-10:], "phone")
                cid = record_fetch(
                    conn,
                    TOOL,
                    r,
                    note="leakcheck pro phone lookup; values redacted before storage",
                    body_override=redact(r.body) if r.body else None,
                )
                if hits is None:
                    failed("leakcheck-phone", "phone", r)
                else:
                    store(ident, "leakcheck-pro", hits, cid, "breach")

    conn.execute(
        "UPDATE scan_runs SET finished_at=?, counts_json=?, note=? WHERE id=?",
        (now_iso(), json.dumps(res.counts), "; ".join(res.errors) or None, res.run_id),
    )
    conn.commit()
    audit.append("scan.breaches.finish", subject=subject_id, run_id=res.run_id, **res.counts)
    return res


def record_password_check(
    conn: sqlite3.Connection, label: str, password: str, fetcher: Fetcher | None = None
) -> int | None:
    """Pwned Passwords range lookup. Stores the label and the count, nothing else."""
    hibp = HibpClient(fetcher or make_fetcher())
    _, count = hibp.pwned_password_count(password)
    if count is None:
        return None
    conn.execute(
        "INSERT INTO password_checks(label, pwned_count, checked_at) VALUES (?,?,?)",
        (label, count, now_iso()),
    )
    conn.commit()
    AuditLog().append("password.check", label=label, pwned_count=count)
    return count


def hits_for(
    conn: sqlite3.Connection, subject_id: str, since: str | None = None, kind: str | None = None
) -> list[sqlite3.Row]:
    sql = "SELECT * FROM breach_hits WHERE subject_id=?"
    args: list[object] = [subject_id]
    if since:
        sql += " AND first_seen >= ?"
        args.append(since)
    if kind:
        sql += " AND kind = ?"
        args.append(kind)
    sql += " ORDER BY COALESCE(breach_date, '') DESC, breach_name"
    return conn.execute(sql, args).fetchall()
