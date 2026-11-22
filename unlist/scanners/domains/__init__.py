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
_DNS_ANSWERED = (0, 3)  # NOERROR, NXDOMAIN


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
        d = json.loads(r.body)
    except ValueError:
        return None, r
    # Status is the DNS response code. Only NOERROR and NXDOMAIN say what the zone holds;
    # SERVFAIL, REFUSED and the rest mean the question was not answered.
    if not isinstance(d, dict) or d.get("Status") not in _DNS_ANSWERED:
        return None, r
    answers = d.get("Answer") or []
    if not isinstance(answers, list) or not all(isinstance(a, dict) for a in answers):
        return None, r
    return [str(a.get("data", "")).strip('"').replace('" "', "") for a in answers], r


def _own_hostname(name: str, domain: str) -> str:
    """A certificate name normalised, or '' unless it is the domain or a host under it."""
    n = name.strip().lower().rstrip(".")
    d = domain.strip().lower().rstrip(".")
    if not n or "*" in n:
        return ""
    return n if n == d or n.endswith("." + d) else ""


def assess_spf(records: list[str]) -> tuple[str, str]:
    spf = [t for t in records if t.lower().split()[:1] == ["v=spf1"]]
    if not spf:
        return "issue", "No SPF record: anyone can send mail that claims to be from this domain."
    if len(spf) > 1:
        return "issue", "More than one SPF record; receivers treat that as an error."
    terms = spf[0].lower().split()[1:]
    # Mechanisms are evaluated left to right and the first `all` ends evaluation, with
    # "+" as its qualifier when none is written. Anything after it is never reached.
    for term in terms:
        qualifier, mechanism = (term[0], term[1:]) if term[0] in "+-~?" else ("+", term)
        if mechanism != "all":
            continue
        if qualifier in "-~":
            return "ok", spf[0]
        if qualifier == "+":
            return "issue", "SPF has an all that passes (+all), which authorises every sender."
        return "issue", "SPF ends in ?all (neutral), so it does not restrict senders."
    if any(term.startswith("redirect=") for term in terms):
        return "ok", spf[0]
    return "issue", "SPF has no -all or ~all, so it does not restrict senders."


def assess_dmarc(records: list[str]) -> tuple[str, str]:
    d = [t for t in records if t.lower().replace(" ", "").startswith("v=dmarc1")]
    if not d:
        return "issue", "No DMARC record: receivers are not told to reject forged mail."
    if len(d) > 1:
        return "issue", "More than one DMARC record; receivers then apply none of them."
    tags = {}
    for part in d[0].split(";")[1:]:
        name, sep, value = part.partition("=")
        if sep:
            tags.setdefault(name.strip().lower(), value.strip().lower())
    policy = tags.get("p")
    if policy == "none":
        return "issue", "DMARC policy is p=none: forged mail is reported but still delivered."
    if policy not in ("quarantine", "reject"):
        return "issue", "DMARC record has no valid p= policy, so receivers do not enforce it."
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
            # no MX is not "no mail": delivery falls back to the domain's address record
            res.info.append(f"{domain}: no explicit MX record")
        r = fetcher.get(f"{CRT}?q={quote('%.' + domain)}&output=json", check_robots=False)
        cid = record_fetch(conn, TOOL, r, note=f"certificate transparency {domain}")
        if r.ok:
            try:
                rows = json.loads(r.body)
            except ValueError:
                rows = []
            names = sorted(
                {
                    name
                    for row in (rows if isinstance(rows, list) else [])
                    if isinstance(row, dict)
                    for n in str(row.get("name_value", "")).splitlines()
                    if (name := _own_hostname(n, domain))
                }
            )
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
