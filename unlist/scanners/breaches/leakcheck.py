"""LeakCheck.

Public API: breach source names and field types for an email or a username, no key.
Pro API (optional key): phone, email or username in combolists. It returns the leaked
values themselves; this client keeps the source and the *names* of the exposed fields
and drops every value before anything is stored.
"""

from __future__ import annotations

import json
import re
from urllib.parse import quote

from unlist.core.fetch import Fetcher, FetchResult
from unlist.scanners.breaches.hibp import Breach

API = "https://leakcheck.io/api/public?check="
PRO_API = "https://leakcheck.io/api/v2/query/"
REDACTED = "[redacted by unlist]"


# What may be copied out of a Pro answer. Everything else in it is, or may be, a leaked value.
_FIELD_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_ -]{0,39}$")
_DATE = re.compile(r"^\d{4}(-\d{2}){0,2}$")
_SOURCE_NAME = re.compile(r"^[^\x00-\x1f]{1,120}$")
_SOURCE_FLAGS = ("unverified", "passwordless", "compilation")


def _not_found(d: dict) -> bool:
    # {"success": false, "error": "Not found"} is the documented "nothing" answer
    return "not found" in str(d.get("error") or "").lower()


def _date(value: object) -> str | None:
    return value if isinstance(value, str) and _DATE.match(value) else None


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
        if not isinstance(d, dict):
            return r, None
        if not d.get("success"):
            return r, [] if _not_found(d) else None
        fields, sources = d.get("fields") or [], d.get("sources") or []
        if not isinstance(fields, list) or not isinstance(sources, list):
            return r, None
        if not all(isinstance(src, dict) for src in sources):
            return r, None
        fields = [str(f) for f in fields if isinstance(f, str)]
        out = []
        for src in sources:
            name = str(src.get("name") or "")
            if not name:
                continue
            date = src.get("date") if isinstance(src.get("date"), str) else None
            out.append(Breach(name=name, title=name, breach_date=date, data_classes=list(fields)))
        return r, out


def _field_names(item: dict) -> list[str]:
    """Names of the fields a Pro result carries. Keys and the `fields` list only, never a value."""
    names = {k for k, v in item.items() if k not in ("source", "fields") and v}
    listed = item.get("fields")
    if isinstance(listed, list):
        names |= {f for f in listed if isinstance(f, str)}
    return sorted(n for n in names if isinstance(n, str) and _FIELD_NAME.match(n))


def _source(item: dict) -> dict:
    """The source metadata of a Pro result that is safe to keep: name, date, three flags."""
    src = item.get("source")
    src = src if isinstance(src, dict) else {}
    out: dict[str, object] = {}
    name = src.get("name")
    if isinstance(name, str) and _SOURCE_NAME.match(name):
        out["name"] = name
    if _date(src.get("breach_date")):
        out["breach_date"] = src["breach_date"]
    for flag in _SOURCE_FLAGS:
        if isinstance(src.get(flag), bool) or src.get(flag) in (0, 1):
            out[flag] = int(src[flag])
    return out


def _results(d: object) -> list[dict] | None:
    """The result items of a successful Pro answer, or None when the shape is not usable."""
    if not isinstance(d, dict) or not d.get("success"):
        return None
    items = d.get("result") or []
    if not isinstance(items, list) or not all(isinstance(i, dict) for i in items):
        return None
    return items


def redact(body: bytes) -> bytes:
    """What is kept of a Pro response: built from an allow-list, never copied from it.

    Per result, the source's name, date and flags and the names of the fields it holds.
    No value of any type survives, wherever it sits in the answer, and an answer that is
    not understood leaves only a note that it was dropped.
    """
    try:
        d = json.loads(body)
    except ValueError:
        return b'{"redacted": "unparseable response dropped"}'
    out: dict[str, object] = {"redacted": REDACTED}
    items = _results(d)
    if items is None:
        if isinstance(d, dict) and d.get("success") is False:
            out["success"] = False
            out["note"] = "not found" if _not_found(d) else "error answer; its text was dropped"
        else:
            out["note"] = "unrecognised response dropped"
    else:
        out["success"] = True
        out["result"] = [{"source": _source(i), "fields": _field_names(i)} for i in items]
    return json.dumps(out, ensure_ascii=False, sort_keys=True).encode("utf-8")


def _digits(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, str | int):
        return ""
    digits = re.sub(r"\D", "", str(value))
    return "1" + digits if len(digits) == 10 else digits  # as Identifier stores phones


class LeakCheckProClient:
    def __init__(self, fetcher: Fetcher, api_key: str) -> None:
        self.fetcher = fetcher
        self.api_key = api_key
        self.unattributed = 0  # results the last query left out because of `phone`

    def query(
        self, value: str, kind: str, *, phone: str | None = None
    ) -> tuple[FetchResult, list[Breach] | None]:
        """kind: email, username or phone. Values are parsed for field names only.

        phone is the subject's full number as stored (digits with country code). When
        given, a result counts only if the phone it reports is that number; the reported
        value is compared in memory and never kept.
        """
        self.unattributed = 0
        url = f"{PRO_API}{quote(value, safe='')}?type={kind}"
        r = self.fetcher.get(url, check_robots=False, headers={"X-API-Key": self.api_key})
        if not r.ok:
            return r, None
        try:
            d = json.loads(r.body)
        except ValueError:
            return r, None
        if not isinstance(d, dict):
            return r, None
        if not d.get("success"):
            return r, [] if _not_found(d) else None
        items = _results(d)
        if items is None:
            return r, None
        by_source: dict[str, Breach] = {}
        for item in items:
            if phone is not None and _digits(item.get("phone")) != phone:
                self.unattributed += 1
                continue
            src = _source(item)
            name = str(src.get("name") or "Unknown source")
            b = by_source.setdefault(
                name,
                Breach(name=name, title=name, breach_date=src.get("breach_date"), data_classes=[]),
            )
            b.data_classes = sorted(set(b.data_classes) | set(_field_names(item)))
        return r, list(by_source.values())
