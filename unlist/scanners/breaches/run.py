"""Run every breach source for a subject's email addresses and store the hits."""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass, field

from unlist.core.audit import AuditLog
from unlist.core.fetch import Fetcher, RateLimiter
from unlist.core.timeutil import now_iso
from unlist.scanners.breaches.hibp import Breach, HibpClient
from unlist.scanners.breaches.leakcheck import LeakCheckClient
from unlist.scanners.breaches.xposedornot import XposedOrNotClient
from unlist.scanners.evidence import record_fetch
from unlist.subjects import SubjectRepo

TOOL = "breaches"
SOURCES = ("hibp", "leakcheck", "xposedornot")

# Documented limits: HIBP Core 1 is 10 requests a minute; LeakCheck public and
# XposedOrNot ask for one a second; Pwned Passwords has no limit.
HOST_INTERVALS = {
    "haveibeenpwned.com": 6.5,
    "leakcheck.io": 1.2,
    "api.xposedornot.com": 1.2,
    "api.pwnedpasswords.com": 0.2,
}


def make_fetcher() -> Fetcher:
    return Fetcher(limiter=RateLimiter(host_intervals=HOST_INTERVALS))


@dataclass
class ScanResult:
    run_id: int
    subject_id: str
    emails: list[str]
    new_hits: int = 0
    seen_hits: int = 0
    skipped: dict[str, str] = field(default_factory=dict)  # source -> why
    errors: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, object]:
        return {
            "emails": len(self.emails),
            "new_hits": self.new_hits,
            "seen_hits": self.seen_hits,
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
    email: str,
    source: str,
    b: Breach,
    capture_id: int | None,
    now: str,
) -> bool:
    """Insert or refresh one hit. Returns True when it is new."""
    existing = conn.execute(
        "SELECT id FROM breach_hits WHERE subject_id=? AND identifier_value=? AND source=? "
        "AND breach_name=?",
        (subject_id, email, source, b.name),
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
             is_verified, is_sensitive, capture_id, first_seen, last_seen)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            subject_id,
            identifier_id,
            email,
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
        ),
    )
    return True


def scan_breaches(
    conn: sqlite3.Connection,
    subject_id: str,
    *,
    fetcher: Fetcher | None = None,
    sources: tuple[str, ...] = SOURCES,
    hibp_api_key: str | None = None,
    audit: AuditLog | None = None,
) -> ScanResult:
    """Look every current email address of the subject up in each source.

    Consent is checked first and the run is refused without it. Every API answer is stored
    as evidence. Hits are upserted so a repeat run reports what is new.
    """
    repo = SubjectRepo(conn)
    subject = repo.require(subject_id)
    emails = [i for i in subject.of_kind("email") if i.current]
    fetcher = fetcher or make_fetcher()
    audit = audit or AuditLog()
    key = hibp_api_key if hibp_api_key is not None else os.environ.get("HIBP_API_KEY")
    started = now_iso()
    cur = conn.execute(
        "INSERT INTO scan_runs(subject_id, kind, started_at, params_json) VALUES (?,?,?,?)",
        (subject_id, TOOL, started, json.dumps({"sources": list(sources)})),
    )
    result = ScanResult(
        run_id=int(cur.lastrowid), subject_id=subject_id, emails=[e.value for e in emails]
    )
    audit.append(
        "scan.breaches.start", subject=subject_id, run_id=result.run_id, emails=len(emails)
    )

    hibp = HibpClient(fetcher, key)
    # The public breach list is keyless and fills in dates and data classes for names the
    # other sources return bare, so it is fetched whatever sources were chosen.
    r, catalog = hibp.all_breaches()
    record_fetch(conn, TOOL, r, note="hibp breach list")
    if not r.ok:
        result.errors.append(f"hibp breach list: {r.reason or r.error or r.status}")
    if "hibp" in sources and not hibp.has_key:
        result.skipped["hibp"] = "no HIBP_API_KEY; per-address lookups need a Core plan key"

    leak = LeakCheckClient(fetcher)
    xon = XposedOrNotClient(fetcher)

    for ident in emails:
        email = ident.value
        lookups: list[tuple[str, object]] = []
        if "hibp" in sources and hibp.has_key:
            lookups.append(("hibp", hibp.breached_account))
        if "leakcheck" in sources:
            lookups.append(("leakcheck", leak.check))
        if "xposedornot" in sources:
            lookups.append(("xposedornot", xon.check))
        for source, fn in lookups:
            r, hits = fn(email)  # type: ignore[operator]
            capture_id = record_fetch(conn, TOOL, r, note=f"{source} lookup")
            if hits is None:
                why = r.reason or r.error or f"HTTP {r.status}"
                result.errors.append(f"{source} {email}: {why}")
                if r.status == 401:
                    result.skipped[source] = "rejected the API key (401)"
                continue
            now = now_iso()
            for b in hits:
                if source != "hibp" and b.name in catalog:
                    b = _enrich(b, catalog[b.name])
                if _upsert_hit(conn, subject_id, ident.id, email, source, b, capture_id, now):
                    result.new_hits += 1
                else:
                    result.seen_hits += 1
            conn.commit()

    conn.execute(
        "UPDATE scan_runs SET finished_at=?, counts_json=?, note=? WHERE id=?",
        (now_iso(), json.dumps(result.counts), "; ".join(result.errors) or None, result.run_id),
    )
    conn.commit()
    audit.append("scan.breaches.finish", subject=subject_id, run_id=result.run_id, **result.counts)
    return result


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
    conn: sqlite3.Connection, subject_id: str, since: str | None = None
) -> list[sqlite3.Row]:
    sql = "SELECT * FROM breach_hits WHERE subject_id=?"
    args: list[object] = [subject_id]
    if since:
        sql += " AND first_seen >= ?"
        args.append(since)
    sql += " ORDER BY COALESCE(breach_date, '') DESC, breach_name"
    return conn.execute(sql, args).fetchall()
