"""LeakCheck.

Public API: breach source names and field types for an email or a username, no key.
Pro API (optional key): phone, email or username in combolists. It returns the leaked
values themselves; this client keeps the source and the *names* of the exposed fields
and drops every value before anything is stored.
"""

from __future__ import annotations

import json
from urllib.parse import quote

from unlist.core.fetch import Fetcher, FetchResult
from unlist.scanners.breaches.hibp import Breach

API = "https://leakcheck.io/api/public?check="
PRO_API = "https://leakcheck.io/api/v2/query/"
REDACTED = "[redacted by unlist]"


class LeakCheckClient:
    def __init__(self, fetcher: Fetcher) -> None:
        self.fetcher = fetcher

    def check(self, query: str) -> tuple[FetchResult, list[Breach] | None]:
        """query is an email address or a username."""
        r = self.fetcher.get(API + quote(query, safe=""), check_robots=False)
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
                Breach(name=name, title=name, breach_date=src.get("date"), data_classes=fields)
            )
        return r, out


def redact(body: bytes) -> bytes:
    """A copy of a Pro response with every leaked value replaced; structure and source kept."""
    try:
        d = json.loads(body)
    except ValueError:
        return b'{"redacted": "unparseable response dropped"}'

    def scrub(obj: object, keep: bool = False) -> object:
        if isinstance(obj, dict):
            return {k: scrub(v, keep or k == "source") for k, v in obj.items()}
        if isinstance(obj, list):
            return [scrub(v, keep) for v in obj]
        if isinstance(obj, str) and not keep:
            return REDACTED
        return obj

    if isinstance(d, dict) and isinstance(d.get("result"), list):
        d["result"] = [scrub(item) for item in d["result"]]
    return json.dumps(d, ensure_ascii=False, sort_keys=True).encode("utf-8")


class LeakCheckProClient:
    def __init__(self, fetcher: Fetcher, api_key: str) -> None:
        self.fetcher = fetcher
        self.api_key = api_key

    def query(self, value: str, kind: str) -> tuple[FetchResult, list[Breach] | None]:
        """kind: email, username or phone. Values are parsed for field names only."""
        url = f"{PRO_API}{quote(value, safe='')}?type={kind}"
        r = self.fetcher.get(url, check_robots=False, headers={"X-API-Key": self.api_key})
        if not r.ok:
            return r, None
        try:
            d = json.loads(r.body)
        except ValueError:
            return r, None
        if not d.get("success"):
            return r, [] if "not found" in str(d.get("error") or "").lower() else None
        by_source: dict[str, Breach] = {}
        for item in d.get("result") or []:
            src = item.get("source") or {}
            name = str(src.get("name") or "Unknown source")
            fields = sorted(k for k, v in item.items() if k not in ("source", "fields") and v)
            fields = sorted(set(fields) | {str(f) for f in item.get("fields") or []})
            b = by_source.setdefault(
                name,
                Breach(name=name, title=name, breach_date=src.get("breach_date"), data_classes=[]),
            )
            b.data_classes = sorted(set(b.data_classes) | set(fields))
        return r, list(by_source.values())
