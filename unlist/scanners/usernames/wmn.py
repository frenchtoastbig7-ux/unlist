"""WhatsMyName dataset loading and rule evaluation."""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

from unlist import paths
from unlist.core.audit import AuditLog
from unlist.core.fetch import Fetcher, FetchResult, RateLimiter
from unlist.core.timeutil import now_iso
from unlist.scanners import exposures as X
from unlist.scanners.evidence import record_fetch
from unlist.subjects import SubjectRepo

DATA_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
CREDIT = "Uses data from the WhatsMyName project (CC BY-SA 4.0)."
TOOL = "usernames"
NSFW_CATEGORIES = {"xx NSFW xx", "nsfw"}
CACHE_MAX_AGE = 7 * 86400


def make_fetcher() -> Fetcher:
    # one request per site, so the per-host interval rarely matters; no retries, short timeout
    return Fetcher(limiter=RateLimiter(default_interval=1.0), retries=0, timeout=12.0)


def cache_path() -> Path:
    return paths.data_dir() / "cache" / "wmn-data.json"


def load_sites(
    fetcher: Fetcher, *, max_age: int = CACHE_MAX_AGE, now: float | None = None
) -> list[dict]:
    """The dataset's site list, from the local cache when it is fresh enough."""
    p = cache_path()
    now = now if now is not None else time.time()
    if not p.is_file() or now - p.stat().st_mtime > max_age:
        r = fetcher.get(DATA_URL, check_robots=False)
        if r.ok:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(r.body)
            paths.make_private(p)
        elif not p.is_file():
            why = r.reason or r.error or r.status
            raise RuntimeError(f"could not download the WhatsMyName data: {why}")
    data = json.loads(p.read_text(encoding="utf-8"))
    return [s for s in data.get("sites", []) if s.get("valid", True) is not False]


def usable(site: dict, include_nsfw: bool = False) -> bool:
    if site.get("protection"):
        return False  # the dataset says a challenge guards it; not worked around
    if not include_nsfw and str(site.get("cat", "")) in NSFW_CATEGORIES:
        return False
    return bool(site.get("uri_check")) and "{account}" in (
        site["uri_check"] + str(site.get("post_body") or "")
    )


def check_site(fetcher: Fetcher, site: dict, username: str) -> tuple[str, FetchResult, str]:
    """('found' | 'missing' | 'unknown', response, profile URL) for one site."""
    account = username
    for ch in str(site.get("strip_bad_char") or ""):
        account = account.replace(ch, "")
    url = site["uri_check"].replace("{account}", account)
    headers = dict(site.get("headers") or {})
    if site.get("post_body"):
        body = str(site["post_body"]).replace("{account}", account).encode("utf-8")
        r = fetcher.post(url, content=body, headers=headers)
    else:
        r = fetcher.get(url, check_robots=False, headers=headers, retries=0)
    pretty = str(site.get("uri_pretty") or site["uri_check"]).replace("{account}", account)
    if r.status is None:
        return "unknown", r, pretty
    text = r.body.decode("utf-8", "replace")
    e_string = str(site.get("e_string") or "")
    m_string = str(site.get("m_string") or "")
    exists = r.status == site.get("e_code") and e_string and e_string in text
    also_missing = m_string and m_string in text and r.status == site.get("m_code")
    if exists and not also_missing:
        return "found", r, pretty
    if r.status == site.get("m_code") and (not m_string or m_string in text):
        return "missing", r, pretty
    return "unknown", r, pretty


@dataclass
class UsernameScanResult:
    run_id: int
    subject_id: str
    usernames: list[str]
    sites: int = 0
    skipped_sites: int = 0
    found: int = 0
    new: int = 0
    missing: int = 0
    unknown: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, object]:
        return {
            k: getattr(self, k)
            for k in ("sites", "skipped_sites", "found", "new", "missing", "unknown")
        }


def scan_usernames(
    conn: sqlite3.Connection,
    subject_id: str,
    *,
    fetcher: Fetcher | None = None,
    include_nsfw: bool = False,
    limit: int | None = None,
    categories: set[str] | None = None,
    audit: AuditLog | None = None,
) -> UsernameScanResult:
    """Check every current username of the subject against the dataset's sites.

    Hits become candidate account exposures; only responses that say "found" are kept as
    evidence. limit caps the number of sites (for a quick look); categories restricts to
    the dataset's categories (social, coding, gaming, ...).
    """
    subject = SubjectRepo(conn).require(subject_id)
    names = [i.value for i in subject.of_kind("username") if i.current]
    fetcher = fetcher or make_fetcher()
    audit = audit or AuditLog()
    cur = conn.execute(
        "INSERT INTO scan_runs(subject_id, kind, started_at, params_json) VALUES (?,?,?,?)",
        (subject_id, TOOL, now_iso(), json.dumps({"limit": limit, "include_nsfw": include_nsfw})),
    )
    res = UsernameScanResult(run_id=int(cur.lastrowid), subject_id=subject_id, usernames=names)
    conn.commit()
    if not names:
        res.notes.append("subject has no username identifier")
        conn.execute(
            "UPDATE scan_runs SET finished_at=?, counts_json=?, note=? WHERE id=?",
            (now_iso(), json.dumps(res.counts), res.notes[-1], res.run_id),
        )
        conn.commit()
        return res
    audit.append(
        "scan.usernames.start", subject=subject_id, run_id=res.run_id, usernames=len(names)
    )
    all_sites = load_sites(fetcher)
    sites = [s for s in all_sites if usable(s, include_nsfw)]
    if categories:
        sites = [s for s in sites if str(s.get("cat")) in categories]
    res.skipped_sites = len(all_sites) - len(sites)
    if limit:
        sites = sites[:limit]
    res.sites = len(sites)
    for username in names:
        for site in sites:
            verdict, r, pretty = check_site(fetcher, site, username)
            if verdict == "found":
                res.found += 1
                cid = record_fetch(conn, TOOL, r, note=f"{site['name']}: account exists")
                _, how = X.upsert(
                    conn, subject_id, username, "account", "whatsmyname", str(site["name"]),
                    title=str(site["name"]), url=pretty, detail={"category": site.get("cat")},
                    capture_id=cid,
                )  # fmt: skip
                if how == "new":
                    res.new += 1
                conn.commit()
            elif verdict == "missing":
                res.missing += 1
            else:
                res.unknown += 1
    conn.execute(
        "UPDATE scan_runs SET finished_at=?, counts_json=? WHERE id=?",
        (now_iso(), json.dumps(res.counts), res.run_id),
    )
    conn.commit()
    audit.append("scan.usernames.finish", subject=subject_id, run_id=res.run_id, **res.counts)
    return res
