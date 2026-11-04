"""Have I Been Pwned v3 and Pwned Passwords."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from urllib.parse import quote

from unlist.core.fetch import Fetcher, FetchResult

API = "https://haveibeenpwned.com/api/v3"
PWNED_RANGE = "https://api.pwnedpasswords.com/range/"


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
        """Every breach HIBP knows about (no key needed). Keyed by Name."""
        r = self.fetcher.get(f"{API}/breaches", check_robots=False, headers=self._headers())
        out: dict[str, Breach] = {}
        if r.ok:
            try:
                for d in json.loads(r.body):
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
        except (ValueError, TypeError):
            return r, None

    def pwned_password_count(self, password: str) -> tuple[FetchResult, int | None]:
        """k-anonymity: only the first five hex characters of the SHA-1 leave this machine."""
        digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]
        r = self.fetcher.get(
            PWNED_RANGE + prefix, check_robots=False, headers={"Add-Padding": "true"}
        )
        if not r.ok:
            return r, None
        for line in r.body.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if ":" not in line:
                continue
            s, count = line.split(":", 1)
            if s.strip().upper() == suffix:
                try:
                    return r, int(count.strip())
                except ValueError:
                    return r, None
        return r, 0
