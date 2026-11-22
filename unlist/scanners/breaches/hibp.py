"""Have I Been Pwned v3 and Pwned Passwords."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from urllib.parse import quote

from unlist.core.fetch import Fetcher, FetchResult

API = "https://haveibeenpwned.com/api/v3"
PWNED_RANGE = "https://api.pwnedpasswords.com/range/"
_RANGE_LINE = re.compile(r"^[0-9A-Fa-f]{35}:\d+$")


@dataclass
class Breach:
    name: str
    title: str | None = None
    domain: str | None = None
    breach_date: str | None = None
    added_date: str | None = None
    data_classes: list[str] = field(default_factory=list)
    pwn_count: int | None = None
    is_verified: bool | None = None
    is_sensitive: bool | None = None

    @classmethod
    def from_api(cls, d: dict) -> Breach:
        return cls(
            name=str(d.get("Name") or d.get("name") or ""),
            title=d.get("Title"),
            domain=d.get("Domain") or None,
            breach_date=d.get("BreachDate"),
            added_date=d.get("AddedDate"),
            data_classes=list(d.get("DataClasses") or []),
            pwn_count=d.get("PwnCount"),
            is_verified=d.get("IsVerified"),
            is_sensitive=d.get("IsSensitive"),
        )


class HibpClient:
    def __init__(self, fetcher: Fetcher, api_key: str | None = None) -> None:
        self.fetcher = fetcher
        self.api_key = api_key

    @property
    def has_key(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/json"}
        if self.api_key:
            h["hibp-api-key"] = self.api_key
        return h

    def all_breaches(self) -> tuple[FetchResult, dict[str, Breach]]:
        """Every breach HIBP knows about. Keyed by Name. Public, so the key is never sent."""
        r = self.fetcher.get(
            f"{API}/breaches", check_robots=False, headers={"Accept": "application/json"}
        )
        out: dict[str, Breach] = {}
        if r.ok:
            try:
                for d in json.loads(r.body):
                    if not isinstance(d, dict):
                        continue
                    b = Breach.from_api(d)
                    if b.name:
                        out[b.name] = b
            except (ValueError, TypeError):
                pass
        return r, out

    def breached_account(self, email: str) -> tuple[FetchResult, list[Breach] | None]:
        """Breaches for one address. None means the lookup could not be made (no key,
        refused, error); an empty list means HIBP has nothing for it."""
        url = f"{API}/breachedaccount/{quote(email, safe='')}?truncateResponse=false"
        r = self.fetcher.get(url, check_robots=False, headers=self._headers())
        if r.status == 404:
            return r, []
        if not r.ok:
            return r, None
        try:
            return r, [Breach.from_api(d) for d in json.loads(r.body)]
        except (ValueError, TypeError, AttributeError):
            return r, None

    def subscription(self) -> tuple[FetchResult, dict | None]:
        """What the key's plan allows: {'name': 'Core 1', 'rpm': 10, 'stealer_logs': False}."""
        r = self.fetcher.get(
            f"{API}/subscription/status", check_robots=False, headers=self._headers()
        )
        if not r.ok:
            return r, None
        try:
            d = json.loads(r.body)
        except (ValueError, TypeError):
            return r, None
        if not isinstance(d, dict):
            return r, None
        name = str(d.get("SubscriptionName") or "")
        return r, {
            "name": name,
            "rpm": d.get("Rpm"),
            "until": d.get("SubscribedUntil"),
            "stealer_logs": bool(d.get("IncludesStealerLogs")) or name.lower().startswith("pro"),
        }

    def pastes(self, email: str) -> tuple[FetchResult, list[Breach] | None]:
        """Pastes that contained the address. Each becomes a hit named '<Source>:<Id>'."""
        r = self.fetcher.get(
            f"{API}/pasteaccount/{quote(email, safe='')}",
            check_robots=False,
            headers=self._headers(),
        )
        if r.status == 404:
            return r, []
        if not r.ok:
            return r, None
        try:
            items = json.loads(r.body)
        except (ValueError, TypeError):
            return r, None
        if not isinstance(items, list) or not all(isinstance(p, dict) for p in items):
            return r, None
        out = []
        for p in items:
            source, pid = str(p.get("Source") or "paste"), str(p.get("Id") or "")
            out.append(
                Breach(
                    name=f"{source}:{pid}",
                    title=p.get("Title") or f"{source} paste",
                    domain=source.lower(),
                    breach_date=(p.get("Date") or "")[:10] or None,
                    data_classes=["Email addresses"],
                    pwn_count=p.get("EmailCount"),
                )
            )
        return r, out

    def stealer_logs(self, email: str) -> tuple[FetchResult, list[Breach] | None]:
        """Websites whose saved credentials for this address were captured by infostealer
        malware. Needs a Pro plan; returns domains only, never credentials."""
        r = self.fetcher.get(
            f"{API}/stealerlogsbyemail/{quote(email, safe='')}",
            check_robots=False,
            headers=self._headers(),
        )
        if r.status == 404:
            return r, []
        if not r.ok:
            return r, None
        try:
            domains = json.loads(r.body)
        except (ValueError, TypeError):
            return r, None
        if not isinstance(domains, list):
            return r, None
        return r, [
            Breach(
                name=str(d), title=f"Stealer log: {d}", domain=str(d), data_classes=["Passwords"]
            )
            for d in domains
            if d
        ]

    def pwned_password_count(self, password: str) -> tuple[FetchResult, int | None]:
        """k-anonymity: only the first five hex characters of the SHA-1 leave this machine."""
        digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]
        r = self.fetcher.get(
            PWNED_RANGE + prefix, check_robots=False, headers={"Add-Padding": "true"}
        )
        if not r.ok:
            return r, None
        # A range answer is lines of "<35 hex characters>:<count>" and nothing else. An
        # empty body or an HTML page is not "this password is unknown", so it is no answer.
        lines = [x.strip() for x in r.body.decode("utf-8", "replace").splitlines() if x.strip()]
        if not lines or not all(_RANGE_LINE.match(x) for x in lines):
            return r, None
        for line in lines:
            s, count = line.split(":", 1)
            if s.upper() == suffix:
                return r, int(count)
        return r, 0
