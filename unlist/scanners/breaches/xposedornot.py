"""XposedOrNot: breach names for an email, no key."""

from __future__ import annotations

import json
from urllib.parse import quote

from unlist.core.fetch import Fetcher, FetchResult
from unlist.scanners.breaches.hibp import Breach

API = "https://api.xposedornot.com/v1/check-email/"


class XposedOrNotClient:
    def __init__(self, fetcher: Fetcher) -> None:
        self.fetcher = fetcher

    def check(self, email: str) -> tuple[FetchResult, list[Breach] | None]:
        r = self.fetcher.get(API + quote(email, safe=""), check_robots=False)
        if r.status == 404:
            return r, []
        if not r.ok:
            return r, None
        try:
            d = json.loads(r.body)
        except ValueError:
            return r, None
        if not isinstance(d, dict):
            return r, None
        if "Error" in d:
            return r, [] if "not found" in str(d["Error"]).lower() else None
        groups = d.get("breaches")
        if not isinstance(groups, list):
            return r, None
        names: list[str] = []
        for group in groups:
            if isinstance(group, list):
                names.extend(str(n) for n in group)
            elif isinstance(group, str):
                names.append(group)
        return r, [Breach(name=n, title=n) for n in names if n]


ANALYTICS = "https://api.xposedornot.com/v1/breach-analytics?email="
_ANALYTICS_KEYS = ("ExposedBreaches", "BreachesSummary", "BreachMetrics", "PastesSummary")


def parse_analytics(body: bytes) -> tuple[list[Breach], dict] | None:
    """(per-breach detail, metrics) from a breach-analytics answer, or None if unusable."""
    try:
        d = json.loads(body)
    except ValueError:
        return None
    if not isinstance(d, dict):
        return None
    if "Error" in d:
        return ([], {}) if "not found" in str(d["Error"]).lower() else None
    if not any(k in d for k in _ANALYTICS_KEYS):
        return None  # an object, but not an analytics answer: the caller falls back
    exposed = d.get("ExposedBreaches")
    details = exposed.get("breaches_details") if isinstance(exposed, dict) else None
    hits = []
    for b in details if isinstance(details, list) else []:
        if not isinstance(b, dict):
            continue
        name = str(b.get("breach") or "")
        if not name:
            continue
        classes = [c.strip() for c in str(b.get("xposed_data") or "").split(";") if c.strip()]
        hits.append(
            Breach(
                name=name,
                title=name,
                domain=b.get("domain") or None,
                breach_date=str(b.get("xposed_date") or "") or None,
                data_classes=classes,
                pwn_count=b.get("xposed_records"),
                is_verified=str(b.get("verified", "")).lower() in ("yes", "true", "1"),
            )
        )
    metrics_src = _obj(d.get("BreachMetrics"))
    risk = _first_obj(metrics_src.get("risk"))
    metrics = {
        "risk_label": risk.get("risk_label"),
        "risk_score": risk.get("risk_score"),
        "pastes": _obj(d.get("PastesSummary")).get("cnt") or 0,
        "password_strength": _first_obj(metrics_src.get("passwords_strength")),
    }
    return hits, metrics


def _obj(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _first_obj(value: object) -> dict:
    return _obj(value[0]) if isinstance(value, list) and value else {}


def analytics(fetcher: Fetcher, email: str) -> tuple[FetchResult, tuple[list[Breach], dict] | None]:
    """Richer than check-email: per-breach data classes and dates, a risk score, pastes."""
    r = fetcher.get(ANALYTICS + quote(email, safe=""), check_robots=False)
    if r.status == 404:
        return r, ([], {})
    if not r.ok:
        return r, None
    return r, parse_analytics(r.body)
