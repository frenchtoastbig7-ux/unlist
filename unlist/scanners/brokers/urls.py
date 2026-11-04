"""Turn a broker's search template and a subject's identifiers into concrete URLs."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date
from urllib.parse import quote

from unlist.catalog.models import Broker
from unlist.subjects.models import Subject

STATE_NAMES = {
    "AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas", "CA": "California",
    "CO": "Colorado", "CT": "Connecticut", "DE": "Delaware", "DC": "District of Columbia",
    "FL": "Florida", "GA": "Georgia", "HI": "Hawaii", "ID": "Idaho", "IL": "Illinois",
    "IN": "Indiana", "IA": "Iowa", "KS": "Kansas", "KY": "Kentucky", "LA": "Louisiana",
    "ME": "Maine", "MD": "Maryland", "MA": "Massachusetts", "MI": "Michigan", "MN": "Minnesota",
    "MS": "Mississippi", "MO": "Missouri", "MT": "Montana", "NE": "Nebraska", "NV": "Nevada",
    "NH": "New Hampshire", "NJ": "New Jersey", "NM": "New Mexico", "NY": "New York",
    "NC": "North Carolina", "ND": "North Dakota", "OH": "Ohio", "OK": "Oklahoma", "OR": "Oregon",
    "PA": "Pennsylvania", "RI": "Rhode Island", "SC": "South Carolina", "SD": "South Dakota",
    "TN": "Tennessee", "TX": "Texas", "UT": "Utah", "VT": "Vermont", "VA": "Virginia",
    "WA": "Washington", "WV": "West Virginia", "WI": "Wisconsin", "WY": "Wyoming",
    "PR": "Puerto Rico",
}  # fmt: skip

_PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")


@dataclass(frozen=True)
class NameParts:
    first: str
    last: str
    middle: str = ""

    @classmethod
    def parse(cls, full: str) -> NameParts | None:
        tokens = [t for t in re.split(r"\s+", full.strip()) if t]
        tokens = [t for t in tokens if t.lower().strip(".") not in {"jr", "sr", "ii", "iii", "iv"}]
        if len(tokens) < 2:
            return None
        return cls(first=tokens[0], last=tokens[-1], middle=" ".join(tokens[1:-1]))


@dataclass(frozen=True)
class Place:
    city: str = ""
    state: str = ""
    zip: str = ""

    @property
    def state_full(self) -> str:
        return STATE_NAMES.get(self.state.upper(), "")


@dataclass
class Profile:
    """What the scanner searches for: names, places, age. Built from a subject."""

    names: list[NameParts] = field(default_factory=list)
    places: list[Place] = field(default_factory=list)
    age: int | None = None
    phones: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    relatives: list[str] = field(default_factory=list)

    @classmethod
    def from_subject(cls, subject: Subject, today: date | None = None) -> Profile:
        p = cls()
        seen_names: set[tuple[str, str]] = set()
        seen_places: set[tuple[str, str]] = set()
        # Current names and addresses first: the places they carry are searched first.
        order = {"name": 0, "alias": 1, "address": 2}
        idents = sorted(
            subject.identifiers,
            key=lambda i: (order.get(i.kind, 3), 0 if i.current else 1, i.id or 0),
        )
        for ident in idents:
            if ident.kind in ("name", "alias"):
                parts = NameParts.parse(ident.value)
                if parts and (parts.first.lower(), parts.last.lower()) not in seen_names:
                    seen_names.add((parts.first.lower(), parts.last.lower()))
                    p.names.append(parts)
            if ident.kind in ("name", "alias", "address"):
                city = str(ident.meta.get("city") or "").strip()
                state = str(ident.meta.get("state") or "").strip().upper()
                zip_ = str(ident.meta.get("zip") or "").strip()
                if (city or state) and (city.lower(), state) not in seen_places:
                    seen_places.add((city.lower(), state))
                    p.places.append(Place(city=city, state=state, zip=zip_))
            elif ident.kind == "dob":
                try:
                    born = date.fromisoformat(ident.value)
                except ValueError:
                    continue
                today = today or date.today()
                p.age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
            elif ident.kind == "phone":
                p.phones.append(ident.value)
            elif ident.kind == "email":
                p.emails.append(ident.value)
            elif ident.kind == "relative":
                p.relatives.append(ident.value)
        return p


def _joiner(template: str) -> str | None:
    """The character a template uses between name parts, e.g. '-' in '{first}-{last}'."""
    m = re.search(r"\{first\}([-_+])\{", template)
    return m.group(1) if m else None


def _encode(value: str, joiner: str | None) -> str:
    value = value.strip()
    if joiner:
        return re.sub(r"\s+", joiner, value)
    return quote(value, safe="")


def build_search_urls(broker: Broker, profile: Profile) -> list[tuple[str, dict[str, str]]]:
    """Every concrete search URL for this broker, with the values that filled it.

    Templates that need a place are expanded once per known place; those that need only
    a name once per name. Nothing is produced when a required value is missing.
    """
    if not broker.searchable or not broker.search.template:
        return []
    template = broker.search.template
    needed = set(_PLACEHOLDER.findall(template))
    joiner = _joiner(template)
    out: list[tuple[str, dict[str, str]]] = []
    seen: set[str] = set()
    place_slots = needed & {"city", "state", "state_full", "zip"}
    places = profile.places if place_slots else [Place()]
    for name in profile.names:
        for place in places:
            values = {
                "first": name.first,
                "last": name.last,
                "middle": name.middle,
                "city": place.city,
                "state": place.state,
                "state_full": place.state_full,
                "zip": place.zip,
                "age": str(profile.age or ""),
            }
            if any(not values[k] for k in needed):
                continue
            url = template
            for k in needed:
                url = url.replace("{" + k + "}", _encode(values[k], joiner))
            if url not in seen:
                seen.add(url)
                out.append((url, {k: values[k] for k in needed}))
    return out
