"""How to delete an account at a service, from the JustDeleteMe directory (MIT)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from unlist.catalog.models import normalise_host

DATA = Path(__file__).parent / "jdm.json"
DIFFICULTY_ORDER = {"easy": 0, "medium": 1, "hard": 2, "limited": 3, "impossible": 4}


@dataclass(frozen=True)
class AccountService:
    name: str
    url: str
    difficulty: str = "unknown"
    notes: str = ""
    email: str = ""
    domains: tuple[str, ...] = field(default_factory=tuple)


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", text.lower())


class AccountDirectory:
    def __init__(self, services: list[AccountService]) -> None:
        self.services = services
        # Several services can share a domain (Bolt and Bolt Driver on bolt.eu) with
        # different deletion instructions, so a domain keeps every candidate.
        self._by_domain: dict[str, list[AccountService]] = {}
        self._by_name: dict[str, AccountService] = {}
        for s in services:
            for d in s.domains:
                self._by_domain.setdefault(d, []).append(s)
            self._by_name.setdefault(_norm(s.name), s)

    def __len__(self) -> int:
        return len(self.services)

    def _domain_candidates(self, host: str) -> list[AccountService]:
        host = normalise_host(host)
        while host:
            if host in self._by_domain:
                return self._by_domain[host]
            if "." not in host:
                break
            host = host.split(".", 1)[1]
            if "." not in host:
                break
        return []

    def by_domain(self, host: str) -> AccountService | None:
        found = self._domain_candidates(host)
        return found[0] if found else None

    def by_name(self, name: str) -> AccountService | None:
        # The full name first: "Example (Business)" may be its own entry. Only when it
        # is not does the qualifier come off, so "GitHub (User)" still finds GitHub.
        return self._by_name.get(_norm(name)) or self._by_name.get(
            _norm(re.sub(r"\(.*?\)", "", name))
        )

    def find(self, name: str = "", host: str = "") -> AccountService | None:
        candidates = self._domain_candidates(host) if host else []
        if len(candidates) > 1 and name:
            key = _norm(name)
            for s in candidates:
                if _norm(s.name) == key:
                    return s
        if candidates:
            return candidates[0]
        return self.by_name(name) if name else None


@lru_cache(maxsize=1)
def load_accounts() -> AccountDirectory:
    if not DATA.is_file():
        return AccountDirectory([])
    payload = json.loads(DATA.read_text(encoding="utf-8"))
    return AccountDirectory(
        [
            AccountService(
                name=s["name"],
                url=s["url"],
                difficulty=s.get("difficulty", "unknown"),
                notes=s.get("notes", ""),
                email=s.get("email", ""),
                domains=tuple(s.get("domains", [])),
            )
            for s in payload.get("sites", [])
        ]
    )
