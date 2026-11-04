"""Which law a request cites, how long the recipient has, and which channel fits."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from unlist.catalog.models import Broker
from unlist.core.timeutil import parse_dt
from unlist.subjects.models import STATE_PRIVACY_LAWS, Subject


@dataclass(frozen=True)
class Basis:
    key: str
    title: str
    cite: str
    window: int
    unit: str = "days"  # days | business_days
    template: str = "plain_removal.txt.j2"


_FIXED = {
    "ccpa_delete": Basis(
        "ccpa_delete",
        "Request to delete personal information (CCPA)",
        "Cal. Civ. Code § 1798.105; 11 CCR § 7022",
        45,
        "days",
        "ccpa_delete.txt.j2",
    ),
    "ccpa_optout": Basis(
        "ccpa_optout",
        "Request to opt out of sale and sharing (CCPA)",
        "Cal. Civ. Code § 1798.120; 11 CCR § 7026",
        15,
        "business_days",
        "ccpa_optout.txt.j2",
    ),
    "gdpr_art17": Basis(
        "gdpr_art17",
        "Request for erasure (GDPR Article 17)",
        "Regulation (EU) 2016/679, Articles 12 and 17",
        30,
        "days",
        "gdpr_art17.txt.j2",
    ),
    "plain": Basis(
        "plain",
        "Request to remove my personal information",
        "the site's published opt-out policy",
        30,
        "days",
        "plain_removal.txt.j2",
    ),
}


def all_bases() -> dict[str, Basis]:
    out = dict(_FIXED)
    for code, (name, cite, days) in STATE_PRIVACY_LAWS.items():
        if code == "CA":
            continue
        key = f"state_{code.lower()}"
        out[key] = Basis(
            key,
            f"Request to delete personal data ({name})",
            cite,
            days,
            "days",
            "state_generic.txt.j2",
        )
    return out


def get_basis(key: str) -> Basis:
    try:
        return all_bases()[key]
    except KeyError:
        raise ValueError(f"unknown basis {key!r}; one of {', '.join(all_bases())}") from None


def basis_for(subject: Subject, broker: Broker | None = None, prefer_optout: bool = False) -> str:
    regime = subject.legal_regime
    if regime == "ccpa":
        return "ccpa_optout" if prefer_optout else "ccpa_delete"
    if regime == "gdpr":
        return "gdpr_art17"
    if regime != "none":
        return f"state_{regime}"
    return "plain"


def add_business_days(start: datetime, n: int) -> datetime:
    d = start
    added = 0
    while added < n:
        d += timedelta(days=1)
        if d.weekday() < 5:
            added += 1
    return d


def deadline_for(basis_key: str, sent_at: str | datetime) -> datetime:
    b = get_basis(basis_key)
    start = parse_dt(sent_at)
    if start is None:
        raise ValueError("sent_at not parseable")
    if b.unit == "business_days":
        return add_business_days(start, b.window)
    return start + timedelta(days=b.window)


def channel_for(broker: Broker) -> str:
    m = broker.opt_out.method
    if m == "email":
        return "email"
    if m in ("form", "account"):
        return "form"
    if m == "mail":
        return "mail"
    if m == "drop_only":
        return "drop"
    if broker.contact.privacy_email:
        return "email"
    if broker.opt_out.url or broker.contact.privacy_url:
        return "form"
    return "manual"
