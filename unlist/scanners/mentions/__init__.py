"""Web mentions through the Brave Search API (optional key).

Brave's terms forbid keeping a database of search results, so results are returned to
the caller and not written anywhere: no evidence file, no table. Only the URLs the
operator marks as theirs are recorded, as their own notes. A confirmed URL on a known
broker's site also becomes a confirmed listing so the removal flow applies to it.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass, field
from urllib.parse import quote, urlsplit

from unlist.catalog import load_catalog
from unlist.core.audit import AuditLog
from unlist.core.fetch import Fetcher, RateLimiter
from unlist.core.timeutil import now_iso
from unlist.scanners import exposures as X
from unlist.scanners.brokers import findings as F
from unlist.scanners.brokers.matcher import Candidate
from unlist.scanners.brokers.urls import Profile
from unlist.subjects import SubjectRepo

API = "https://api.search.brave.com/res/v1/web/search"
TOOL = "mentions"


def make_fetcher() -> Fetcher:
    return Fetcher(limiter=RateLimiter(default_interval=1.1), retries=1)


@dataclass
class Mention:
    query: str
    title: str
    url: str
    description: str
    host: str
    broker_id: str | None = None
    already: str | None = None  # status if this URL is already recorded for the subject


@dataclass
class MentionResult:
    subject_id: str
    queries: list[str] = field(default_factory=list)
    mentions: list[Mention] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped: str | None = None


def build_queries(profile: Profile, max_queries: int = 8) -> list[str]:
    out: list[str] = []
    for n in profile.names[:2]:
        full = f"{n.first} {n.last}"
        places = [p for p in profile.places if p.city][:2]
        if places:
            out += [f'"{full}" "{p.city}"' for p in places]
        else:
            out.append(f'"{full}"')
    for ph in profile.phones[:2]:
        d = ph[-10:]
        out.append(f'"{d[:3]}-{d[3:6]}-{d[6:]}" OR "({d[:3]}) {d[3:6]}-{d[6:]}"')
    out += [f'"{e}"' for e in profile.emails[:2]]
    seen: list[str] = []
    for q in out:
        if q not in seen:
            seen.append(q)
    return seen[:max_queries]


def scan_mentions(
    conn: sqlite3.Connection,
    subject_id: str,
    *,
    fetcher: Fetcher | None = None,
    api_key: str | None = None,
    count: int = 20,
) -> MentionResult:
    """Search the web for the subject's name with city, phone and email. Nothing is stored."""
    subject = SubjectRepo(conn).require(subject_id)
    res = MentionResult(subject_id=subject_id)
    key = api_key if api_key is not None else os.environ.get("BRAVE_API_KEY")
    if not key:
        res.skipped = "no BRAVE_API_KEY (Brave Search API; about 1,000 free queries a month)"
        return res
    fetcher = fetcher or make_fetcher()
    profile = Profile.from_subject(subject)
    catalog = load_catalog()
    known = {
        r["key"]: r["status"] for r in X.list_for(conn, subject_id, "mention")
    }
    res.queries = build_queries(profile)
    seen_urls: set[str] = set()
    for q in res.queries:
        url = f"{API}?q={quote(q, safe='')}&count={count}"
        r = fetcher.get(
            url, check_robots=False,
            headers={"X-Subscription-Token": key, "Accept": "application/json"},
        )  # fmt: skip
        if not r.ok:
            res.errors.append(f"{q}: {r.reason or r.error or f'HTTP {r.status}'}")
            continue
        try:
            items = (json.loads(r.body).get("web") or {}).get("results") or []
        except ValueError:
            res.errors.append(f"{q}: unreadable answer")
            continue
        for it in items:
            link = str(it.get("url") or "")
            if not link or link in seen_urls:
                continue
            seen_urls.add(link)
            host = urlsplit(link).netloc.lower().removeprefix("www.")
            broker = catalog.by_host(host)
            res.mentions.append(
                Mention(
                    query=q,
                    title=str(it.get("title") or "")[:160],
                    url=link,
                    description=str(it.get("description") or "")[:300],
                    host=host,
                    broker_id=broker.id if broker else None,
                    already=known.get(link),
                )
            )
    res.mentions.sort(key=lambda m: (m.broker_id is None, m.host))
    AuditLog().append(
        "scan.mentions", subject=subject_id, queries=len(res.queries), results=len(res.mentions)
    )
    conn.execute(
        "INSERT INTO scan_runs(subject_id, kind, started_at, finished_at, counts_json) "
        "VALUES (?,?,?,?,?)",
        (subject_id, TOOL, now_iso(), now_iso(),
         json.dumps({"queries": len(res.queries), "results": len(res.mentions)})),
    )  # fmt: skip
    conn.commit()
    return res


def confirm_mention(
    conn: sqlite3.Connection, subject_id: str, url: str, title: str = "", note: str = ""
) -> tuple[int, int | None]:
    """Record a URL as a page about the subject. Returns (exposure id, finding id or None)."""
    SubjectRepo(conn).require(subject_id)
    host = urlsplit(url).netloc.lower().removeprefix("www.")
    if not host:
        raise ValueError("not a URL")
    broker = load_catalog().by_host(host)
    eid, _ = X.upsert(
        conn, subject_id, host, "mention", "operator", url,
        title=title or host, url=url,
        detail={"broker": broker.id if broker else None, "note": note}, status="confirmed",
    )  # fmt: skip
    fid = None
    if broker is not None and broker.status == "active":
        fid, _ = F.upsert_candidate(
            conn, subject_id, broker.id,
            Candidate(listing_url=url, name_text=title or host, score=1.0,
                      reasons=["confirmed by you from a web search"]),
            None,
        )  # fmt: skip
        conn.commit()
        if F.get(conn, fid)["status"] == "candidate":
            F.set_status(conn, fid, "confirmed", "confirmed from a web mention")
    conn.commit()
    AuditLog().append(
        "mention.confirm", subject=subject_id, url=url, broker=broker.id if broker else None
    )
    return eid, fid
