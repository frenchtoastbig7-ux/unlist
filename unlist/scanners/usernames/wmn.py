"""WhatsMyName dataset loading and rule evaluation."""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

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
    sites = None
    why: object = None
    if not p.is_file() or now - p.stat().st_mtime > max_age:
        r = fetcher.get(DATA_URL, check_robots=False)
        sites = _parse_sites(r.body) if r.ok else None
        if sites is not None:
            # checked before it replaces the cache, and swapped in whole: a bad download
            # must not cost the last usable copy
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(p.suffix + ".part")
            tmp.write_bytes(r.body)
            paths.make_private(tmp)
            tmp.replace(p)
        else:
            why = (r.reason or r.error or r.status) if not r.ok else "the download is not valid"
    if sites is None and p.is_file():
        sites = _parse_sites(p.read_bytes())
        why = why or "the cached copy is not valid"
    if sites is None:
        raise RuntimeError(f"could not load the WhatsMyName data: {why or 'no cached copy'}")
    return [s for s in sites if s.get("valid", True) is not False]


def _parse_sites(body: bytes) -> list[dict] | None:
    """The site rules of a dataset file, or None when it is not a usable dataset."""
    try:
        data = json.loads(body)
    except ValueError:
        return None
    sites = data.get("sites") if isinstance(data, dict) else None
    if not isinstance(sites, list) or not sites:
        return None
    return [s for s in sites if isinstance(s, dict)]


def usable(site: dict, include_nsfw: bool = False) -> bool:
    if site.get("protection"):
        return False  # the dataset says a challenge guards it; not worked around
    if not include_nsfw and str(site.get("cat", "")) in NSFW_CATEGORIES:
        return False
    return bool(site.get("uri_check")) and "{account}" in (
        str(site["uri_check"]) + str(site.get("post_body") or "")
    )


def _in_body(template: str, account: str) -> str:
    """The post body with the username escaped for the body's own format."""
    try:
        json.loads(template)
    except ValueError:
        return template.replace("{account}", quote(account, safe=""))  # a form body
    return template.replace("{account}", json.dumps(account, ensure_ascii=False)[1:-1])


def check_site(fetcher: Fetcher, site: dict, username: str) -> tuple[str, FetchResult, str]:
    """('found' | 'missing' | 'unknown', response, profile URL) for one site."""
    account = username
    for ch in str(site.get("strip_bad_char") or ""):
        account = account.replace(ch, "")
    # Percent-encoded so a "/" or "?" in a username cannot change which resource is asked
    # for; the verdict has to be about this account.
    in_url = quote(account, safe="")
    url = str(site["uri_check"]).replace("{account}", in_url)
    headers = dict(site.get("headers") or {})
    if site.get("post_body"):
        body = _in_body(str(site["post_body"]), account).encode("utf-8")
        r = fetcher.post(url, content=body, headers=headers)
    else:
        r = fetcher.get(url, check_robots=False, headers=headers, retries=0)
    pretty = str(site.get("uri_pretty") or site["uri_check"]).replace("{account}", in_url)
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
    if limit is not None and limit < 0:
        raise ValueError("limit must be zero or more, or None for every site")
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
    if limit is not None:
        sites = sites[:limit]  # zero means no site is asked about the username
    res.sites = len(sites)
    broken = 0
    for username in names:
        for site in sites:
            try:
                verdict, r, pretty = check_site(fetcher, site, username)
            except Exception:
                # one rule the scanner cannot use (a malformed URL, a wrong type) is that
                # site's problem; the scan goes on and still closes its run
                broken += 1
                res.unknown += 1
                continue
            if verdict == "found":
                name = str(site.get("name") or pretty)
                res.found += 1
                cid = record_fetch(conn, TOOL, r, note=f"{name}: account exists")
                _, how = X.upsert(
                    conn, subject_id, username, "account", "whatsmyname", name,
                    title=name, url=pretty, detail={"category": site.get("cat")},
                    capture_id=cid,
                )  # fmt: skip
                if how == "new":
                    res.new += 1
                conn.commit()
            elif verdict == "missing":
                res.missing += 1
            else:
                res.unknown += 1
    if broken:
        res.notes.append(f"{broken} check(s) skipped: the site rule could not be used")
    conn.execute(
        "UPDATE scan_runs SET finished_at=?, counts_json=?, note=? WHERE id=?",
        (now_iso(), json.dumps(res.counts), "; ".join(res.notes) or None, res.run_id),
    )
    conn.commit()
    audit.append("scan.usernames.finish", subject=subject_id, run_id=res.run_id, **res.counts)
    return res
