"""Small checks on domains the subject owns: is email from the domain spoofable, and
what hostnames do public certificate logs reveal? Not a vulnerability scanner."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from urllib.parse import quote

from unlist.core.audit import AuditLog
from unlist.core.fetch import Fetcher, RateLimiter
from unlist.scanners import exposures as X
from unlist.scanners.evidence import record_fetch
from unlist.subjects import SubjectRepo

DOH = "https://cloudflare-dns.com/dns-query"
CRT = "https://crt.sh/"
TOOL = "domains"


def make_fetcher() -> Fetcher:
    return Fetcher(limiter=RateLimiter(default_interval=0.5), retries=1, timeout=40.0)


def _txt(fetcher: Fetcher, name: str, rtype: str = "TXT") -> tuple[list[str] | None, object]:
    r = fetcher.get(
        f"{DOH}?name={quote(name)}&type={rtype}", check_robots=False,
        headers={"Accept": "application/dns-json"},
    )  # fmt: skip
    if not r.ok:
        return None, r
    try:
        answers = json.loads(r.body).get("Answer") or []
    except ValueError:
        return None, r
    return [str(a.get("data", "")).strip('"').replace('" "', "") for a in answers], r


def assess_spf(records: list[str]) -> tuple[str, str]:
    spf = [t for t in records if t.lower().startswith("v=spf1")]
    if not spf:
        return "issue", "No SPF record: anyone can send mail that claims to be from this domain."
    if len(spf) > 1:
        return "issue", "More than one SPF record; receivers treat that as an error."
    rec = spf[0].lower()
    if "+all" in rec:
        return "issue", "SPF ends in +all, which authorises every sender."
    if "-all" in rec or "~all" in rec or "redirect=" in rec:
        return "ok", spf[0]
    return "issue", "SPF has no -all or ~all, so it does not restrict senders."


def assess_dmarc(records: list[str]) -> tuple[str, str]:
    d = [t for t in records if t.lower().startswith("v=dmarc1")]
    if not d:
        return "issue", "No DMARC record: receivers are not told to reject forged mail."
    rec = d[0].lower().replace(" ", "")
    if "p=none" in rec:
        return "issue", "DMARC policy is p=none: forged mail is reported but still delivered."
    return "ok", d[0]


@dataclass
class DomainResult:
    subject_id: str
    domains: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    resolved: list[str] = field(default_factory=list)
    info: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def scan_domains(
    conn: sqlite3.Connection, subject_id: str, *, fetcher: Fetcher | None = None
) -> DomainResult:
    subject = SubjectRepo(conn).require(subject_id)
    fetcher = fetcher or make_fetcher()
    res = DomainResult(subject_id=subject_id)
    res.domains = [i.value for i in subject.of_kind("domain") if i.current]
    for domain in res.domains:
        for check, name, assess in (
            ("spf", domain, assess_spf),
            ("dmarc", f"_dmarc.{domain}", assess_dmarc),
        ):
            records, r = _txt(fetcher, name)
            cid = record_fetch(conn, TOOL, r, note=f"{check} {domain}")
            if records is None:
                res.errors.append(f"{check} {domain}: lookup failed")
                continue
            verdict, text = assess(records)
            existing = [
                e for e in X.list_for(conn, subject_id, "domain")
                if e["key"] == check and e["identifier_value"] == domain
            ]  # fmt: skip
            if verdict == "issue":
                X.upsert(
                    conn, subject_id, domain, "domain", "dns", check,
                    title=f"{check.upper()} for {domain}", detail={"finding": text},
                    capture_id=cid, status="confirmed",
                )  # fmt: skip
                res.issues.append(f"{domain} {check.upper()}: {text}")
            elif existing and existing[0]["status"] != "resolved":
                X.set_status(conn, existing[0]["id"], "resolved", "record now in place")
                res.resolved.append(f"{domain} {check.upper()} fixed")
        mx, r = _txt(fetcher, domain, "MX")
        if mx is not None and not mx:
            res.info.append(f"{domain}: no MX record (the domain receives no mail)")
        r = fetcher.get(f"{CRT}?q={quote('%.' + domain)}&output=json", check_robots=False)
        cid = record_fetch(conn, TOOL, r, note=f"certificate transparency {domain}")
        if r.ok:
            try:
                names = sorted(
                    {
                        n.strip().lower()
                        for row in json.loads(r.body)
                        for n in str(row.get("name_value", "")).splitlines()
                        if n.strip() and "*" not in n
                    }
                )
            except ValueError:
                names = []
            if names:
                X.upsert(
                    conn, subject_id, domain, "domain", "crtsh", "hostnames",
                    title=f"{len(names)} hostnames in public certificate logs",
                    detail={"hostnames": names[:200]}, capture_id=cid, status="confirmed",
                )  # fmt: skip
                res.info.append(f"{domain}: {len(names)} hostnames visible in certificate logs")
        else:
            res.errors.append(f"crt.sh {domain}: {r.reason or r.error or r.status}")
        conn.commit()
    AuditLog().append(
        "scan.domains", subject=subject_id, domains=len(res.domains), issues=len(res.issues)
    )
    return res
