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
        if "Error" in d:
            return r, [] if "not found" in str(d["Error"]).lower() else None
        names: list[str] = []
        for group in d.get("breaches") or []:
            if isinstance(group, list):
                names.extend(str(n) for n in group)
            elif isinstance(group, str):
                names.append(group)
        return r, [Breach(name=n, title=n) for n in names if n]
