"""LeakCheck public API: breach source names and field types for an email, no key."""

from __future__ import annotations

import json
from urllib.parse import quote

from unlist.core.fetch import Fetcher, FetchResult
from unlist.scanners.breaches.hibp import Breach

API = "https://leakcheck.io/api/public?check="


class LeakCheckClient:
    def __init__(self, fetcher: Fetcher) -> None:
        self.fetcher = fetcher

    def check(self, email: str) -> tuple[FetchResult, list[Breach] | None]:
        r = self.fetcher.get(API + quote(email, safe=""), check_robots=False)
        if not r.ok:
            return r, None
        try:
            d = json.loads(r.body)
        except ValueError:
            return r, None
        if not d.get("success"):
            # {"success": false, "error": "Not found"} is the documented "nothing" answer
            err = str(d.get("error") or "").lower()
            return r, [] if "not found" in err else None
        fields = list(d.get("fields") or [])
        out = []
        for src in d.get("sources") or []:
            name = str(src.get("name") or "")
            if not name:
                continue
            out.append(
                Breach(
                    name=name,
                    title=name,
                    breach_date=src.get("date"),
                    data_classes=fields,
                )
            )
        return r, out
