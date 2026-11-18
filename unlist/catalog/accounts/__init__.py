"""How to delete an account at a service, from the JustDeleteMe directory (MIT)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

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
        self._by_domain: dict[str, AccountService] = {}
        self._by_name: dict[str, AccountService] = {}
        for s in services:
            for d in s.domains:
                self._by_domain.setdefault(d, s)
            self._by_name.setdefault(_norm(s.name), s)

    def __len__(self) -> int:
        return len(self.services)

    def by_domain(self, host: str) -> AccountService | None:
        host = host.lower().removeprefix("www.")
        while host:
            if host in self._by_domain:
                return self._by_domain[host]
            if "." not in host:
                return None
            host = host.split(".", 1)[1]
            if "." not in host:
                return None
        return None

    def by_name(self, name: str) -> AccountService | None:
        key = _norm(re.sub(r"\(.*?\)", "", name))
        return self._by_name.get(key) or self._by_name.get(_norm(name))

    def find(self, name: str = "", host: str = "") -> AccountService | None:
        return (self.by_domain(host) if host else None) or (self.by_name(name) if name else None)


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
