"""Scan the searchable brokers for one subject, and re-check individual listings."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field

from unlist.catalog import Broker, load_catalog
from unlist.core.audit import AuditLog
from unlist.core.fetch import Fetcher, FetchResult, RateLimiter
from unlist.core.timeutil import now_iso
from unlist.scanners.brokers import findings as F
from unlist.scanners.brokers.browser import BrowserSession, BrowserUnavailable
from unlist.scanners.brokers.matcher import (
    CANDIDATE_THRESHOLD,
    extract_candidates,
    looks_like_challenge,
    looks_like_no_results,
    name_present,
)
from unlist.scanners.brokers.urls import Profile, build_search_urls
from unlist.scanners.evidence import record_browser, record_fetch
from unlist.subjects import SubjectRepo

TOOL = "brokers"


def make_fetcher() -> Fetcher:
    # People-search sites are slow to forgive; one request every four seconds per host.
    return Fetcher(limiter=RateLimiter(default_interval=4.0), retries=1)


@dataclass
class BrokerScanResult:
    run_id: int
    subject_id: str
    brokers: int = 0
    urls: int = 0
    fetched: int = 0
    refused: int = 0
    browser: int = 0
    challenged: int = 0
    no_results: int = 0
    errors: int = 0
    new_candidates: int = 0
    seen: int = 0
    reappeared: int = 0
    below_threshold: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, object]:
        return {
            k: getattr(self, k)
            for k in (
                "brokers", "urls", "fetched", "refused", "browser", "challenged", "no_results",
                "errors", "new_candidates", "seen", "reappeared", "below_threshold",
            )
        }  # fmt: skip


def _page(
    fetcher: Fetcher,
    browser: BrowserSession | None,
    conn: sqlite3.Connection,
    broker: Broker,
    url: str,
    res: BrokerScanResult | None,
) -> tuple[bytes | None, str, int | None, str, str | None]:
    """Fetch url for broker. Returns (body or None, final_url, capture_id, outcome, note).

    outcome: fetched | browser | refused | challenged | error.
    """
    use_browser_first = broker.search.fetch == "browser"
    result: FetchResult | None = None
    if not use_browser_first:
        result = fetcher.get(url)
        cid = record_fetch(conn, TOOL, result, note=f"search {broker.id}")
        if result.ok and not looks_like_challenge(result.body.decode("utf-8", "replace")):
            if res:
                res.fetched += 1
            return result.body, result.final_url, cid, "fetched", None
        if result.status is None and not result.refused:
            if res:
                res.errors += 1
            return None, url, cid, "error", result.error
    if browser is None:
        if res:
            res.refused += 1
        why = result.reason if result else "site needs a browser; none available"
        return None, url, (cid if result else None), "refused", why
    try:
        cap = browser.capture(url)
    except BrowserUnavailable as exc:
        if res:
            res.refused += 1
        return None, url, None, "refused", str(exc)
    except Exception as exc:  # a page that never loads must not end the run
        if res:
            res.errors += 1
        return None, url, None, "error", f"browser: {exc}"
    cid = record_browser(conn, TOOL, cap, note=f"search {broker.id}")
    if cap.challenged:
        if res:
            res.challenged += 1
        return None, cap.final_url, cid, "challenged", cap.note
    if res:
        res.browser += 1
    return cap.html, cap.final_url, cid, "browser", cap.note


def scan_brokers(
    conn: sqlite3.Connection,
    subject_id: str,
    *,
    brokers: Iterable[Broker] | None = None,
    fetcher: Fetcher | None = None,
    browser: BrowserSession | None = None,
    audit: AuditLog | None = None,
) -> BrokerScanResult:
    """Search every searchable broker (or the given ones) for the subject's names.

    Consent is checked first. Pages are kept as evidence. Listings scoring at or above
    the threshold become candidate findings for the operator to confirm.
    """
    repo = SubjectRepo(conn)
    subject = repo.require(subject_id)
    profile = Profile.from_subject(subject)
    audit = audit or AuditLog()
    fetcher = fetcher or make_fetcher()
    chosen = list(brokers) if brokers is not None else load_catalog().searchable()
    cur = conn.execute(
        "INSERT INTO scan_runs(subject_id, kind, started_at, params_json) VALUES (?,?,?,?)",
        (subject_id, TOOL, now_iso(), json.dumps({"brokers": [b.id for b in chosen]})),
    )
    res = BrokerScanResult(run_id=int(cur.lastrowid), subject_id=subject_id)
    conn.commit()
    audit.append("scan.brokers.start", subject=subject_id, run_id=res.run_id, brokers=len(chosen))
    if not profile.names:
        res.notes.append("subject has no name identifier; nothing to search")
    for broker in chosen:
        urls = build_search_urls(broker, profile)
        if not urls:
            res.notes.append(f"{broker.id}: template needs values the subject lacks (place?)")
            continue
        res.brokers += 1
        for url, _values in urls:
            res.urls += 1
            body, final_url, cid, outcome, note = _page(fetcher, browser, conn, broker, url, res)
            n_cands = 0
            if body is not None:
                text = body.decode("utf-8", "replace")
                cands = extract_candidates(body, final_url, profile, broker.hosts)
                if not cands and looks_like_no_results(text):
                    res.no_results += 1
                    outcome += ":none"
                for c in cands:
                    if c.score < CANDIDATE_THRESHOLD:
                        res.below_threshold += 1
                        continue
                    _, how = F.upsert_candidate(conn, subject_id, broker.id, c, cid)
                    n_cands += 1
                    if how == "new":
                        res.new_candidates += 1
                    elif how == "reappeared":
                        res.reappeared += 1
                    else:
                        res.seen += 1
            conn.execute(
                """INSERT INTO broker_checks(run_id, subject_id, broker_id, search_url, outcome,
                     capture_id, candidates, checked_at, note) VALUES (?,?,?,?,?,?,?,?,?)""",
                (res.run_id, subject_id, broker.id, url, outcome, cid, n_cands, now_iso(), note),
            )
            conn.commit()
    conn.execute(
        "UPDATE scan_runs SET finished_at=?, counts_json=?, note=? WHERE id=?",
        (now_iso(), json.dumps(res.counts), "; ".join(res.notes) or None, res.run_id),
    )
    conn.commit()
    audit.append("scan.brokers.finish", subject=subject_id, run_id=res.run_id, **res.counts)
    return res


def verify_finding(
    conn: sqlite3.Connection,
    finding_id: int,
    *,
    fetcher: Fetcher | None = None,
    browser: BrowserSession | None = None,
) -> tuple[str, str]:
    """Open the listing itself. Returns (verdict, detail): present | gone | unknown.

    gone: the page is a 404/410 or no longer shows the subject's name. The finding moves
    to removed (or stays removed); a listing that is present again after removal becomes
    reappeared. unknown: the site refused and no browser could help; nothing changes.
    """
    row = F.get(conn, finding_id)
    subject = SubjectRepo(conn).require(row["subject_id"])
    profile = Profile.from_subject(subject)
    catalog = load_catalog()
    if row["broker_id"] in catalog:
        broker = catalog.get(row["broker_id"])
    else:
        broker = Broker(id=row["broker_id"], name=row["broker_id"])
    fetcher = fetcher or make_fetcher()
    url = row["listing_url"]
    result = fetcher.get(url)
    cid = record_fetch(conn, TOOL, result, note=f"verify finding {finding_id}")
    body: bytes | None = None
    status = result.status
    if result.ok and not looks_like_challenge(result.body.decode("utf-8", "replace")):
        body = result.body
    elif result.status in (404, 410):
        body = b""
    elif browser is not None:
        try:
            cap = browser.capture(url)
            cid = record_browser(conn, TOOL, cap, note=f"verify finding {finding_id}")
            status = cap.status
            if not cap.challenged:
                body = cap.html if cap.status not in (404, 410) else b""
        except Exception as exc:
            return "unknown", f"browser: {exc}"
    if body is None:
        return "unknown", result.reason or result.error or f"HTTP {status}"
    present = bool(body) and name_present(body, profile) and _still_a_listing(body, broker)
    now = now_iso()
    if present:
        new_status = "reappeared" if row["status"] == "removed" else row["status"]
        conn.execute(
            "UPDATE findings SET last_seen=?, verified_at=?, capture_id=?, status=?, "
            "status_changed_at=CASE WHEN status<>? THEN ? ELSE status_changed_at END WHERE id=?",
            (now, now, cid, new_status, new_status, now, finding_id),
        )
        conn.commit()
        AuditLog().append(
            "finding.verify", finding_id=finding_id, verdict="present", status=new_status
        )
        return "present", f"listing still shows the name (HTTP {status})"
    if row["status"] != "removed":
        F.set_status(conn, finding_id, "removed", note=f"verified gone {now[:10]}")
    conn.execute(
        "UPDATE findings SET verified_at=?, capture_id=? WHERE id=?", (now, cid, finding_id)
    )
    conn.commit()
    AuditLog().append("finding.verify", finding_id=finding_id, verdict="gone", status="removed")
    return "gone", f"listing no longer shows the name (HTTP {status})"


def _still_a_listing(body: bytes, broker: Broker) -> bool:
    """A results page that merely echoes the searched name back is not a listing."""
    text = body.decode("utf-8", "replace")
    return not looks_like_no_results(text)
