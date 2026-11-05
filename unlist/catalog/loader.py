"""Load the shipped catalog plus operator overrides into one Catalog."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import yaml

from unlist.catalog.models import GENERATED_ORIGINS, Broker

PACKAGE_DIR = Path(__file__).parent
BROKERS_DIR = PACKAGE_DIR / "brokers"
REGISTRY_DIR = PACKAGE_DIR / "registry"


class CatalogError(ValueError):
    pass


def _load_file(path: Path) -> list[Broker]:
    """A file holds one broker mapping, or a list of them, or {brokers: [...]}."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        return []
    if isinstance(data, dict) and "brokers" in data:
        data = data["brokers"]
    items = data if isinstance(data, list) else [data]
    out = []
    for i, item in enumerate(items):
        try:
            out.append(Broker.model_validate(item))
        except Exception as exc:
            raise CatalogError(f"{path.name}[{i}]: {exc}") from exc
    return out


def absorb(primary: Broker, registry_row: Broker) -> Broker:
    """Fold a generated registry row into a curated entry for the same company.

    The curated entry keeps everything it says; the registry supplies what it left blank:
    the CPPA broker id, contact details, postal address, disclosures, a trading name.
    """
    update: dict = {}
    reg = primary.registry.model_copy()
    if not reg.ca and registry_row.registry.ca:
        reg.ca = registry_row.registry.ca
    update["registry"] = reg
    contact = primary.contact.model_copy()
    for field in ("privacy_email", "privacy_url", "phone", "postal"):
        if getattr(contact, field) is None and getattr(registry_row.contact, field):
            setattr(contact, field, getattr(registry_row.contact, field))
    update["contact"] = contact
    opt_out = primary.opt_out.model_copy()
    if not opt_out.email:
        # A curated privacy address beats the registry's named contact person.
        opt_out.email = primary.contact.privacy_email or registry_row.opt_out.email
    if opt_out.method == "unknown" and primary.status == "active":
        # A curated entry that only describes how to search inherits the way out.
        r = registry_row.opt_out
        if r.method != "unknown":
            opt_out.method = r.method
            opt_out.url = opt_out.url or r.url
            opt_out.requires = opt_out.requires or list(r.requires)
            opt_out.notes = opt_out.notes or r.notes
    update["opt_out"] = opt_out
    update["disclosures"] = sorted(set(primary.disclosures) | set(registry_row.disclosures))
    aka = list(primary.aka)
    for name in (registry_row.name, *registry_row.aka):
        if name and name != primary.name and name not in aka:
            aka.append(name)
    update["aka"] = aka
    update["hosts"] = primary.hosts + [h for h in registry_row.hosts if h not in primary.hosts]
    update["sources"] = primary.sources + [
        s for s in registry_row.sources if s not in primary.sources
    ]
    return primary.model_copy(update=update)


def merge_generated(base: Broker, extra: Broker) -> Broker:
    """Two generated rows for the same company (same id or host) become one.

    The state registry row is the base: it keeps its id, name, registry number and
    postal address. The opt-out manual supplies what the registry lacks: a real opt-out
    link and method, what the site demands, and a category.
    """
    if base.origin != "cppa-registry" and extra.origin == "cppa-registry":
        base, extra = extra, base
    update: dict = {}
    if base.category == "other" and extra.category != "other":
        update["category"] = extra.category
    opt_out = base.opt_out.model_copy()
    e = extra.opt_out
    if e.method == "form" and e.url:
        opt_out.method, opt_out.url = "form", e.url
    elif opt_out.method == "unknown" and e.method != "unknown":
        opt_out.method, opt_out.url = e.method, e.url
    opt_out.email = opt_out.email or e.email
    opt_out.requires = sorted(set(opt_out.requires) | set(e.requires))
    opt_out.notes = " ".join(p for p in (opt_out.notes, e.notes) if p).strip()
    update["opt_out"] = opt_out
    contact = base.contact.model_copy()
    for f in ("privacy_email", "privacy_url", "phone", "postal"):
        if getattr(contact, f) is None and getattr(extra.contact, f):
            setattr(contact, f, getattr(extra.contact, f))
    update["contact"] = contact
    aka = list(base.aka)
    for name in (extra.name, *extra.aka):
        if name and name != base.name and name not in aka:
            aka.append(name)
    update["aka"] = aka
    update["hosts"] = base.hosts + [h for h in extra.hosts if h not in base.hosts]
    update["sources"] = base.sources + [s for s in extra.sources if s not in base.sources]
    update["disclosures"] = sorted(set(base.disclosures) | set(extra.disclosures))
    return base.model_copy(update=update)


class Catalog:
    def __init__(self, brokers: Iterable[Broker]) -> None:
        self._by_id: dict[str, Broker] = {}
        host_index: dict[str, str] = {}  # host -> id, generated rows only

        def index(b: Broker) -> None:
            for h in b.hosts:
                host_index[h] = b.id

        def unindex(b: Broker) -> None:
            for h in b.hosts:
                if host_index.get(h) == b.id:
                    del host_index[h]

        for b in brokers:
            if b.origin in GENERATED_ORIGINS:
                other_id = b.id if b.id in self._by_id else None
                if other_id is None:
                    other_id = next((host_index[h] for h in b.hosts if h in host_index), None)
                other = self._by_id.get(other_id) if other_id else None
                if other is not None and other.origin in GENERATED_ORIGINS:
                    unindex(other)
                    del self._by_id[other.id]
                    b = merge_generated(other, b)
                elif other is not None:
                    continue  # an id already taken by a curated or operator entry
                self._by_id[b.id] = b
                index(b)
                continue
            for other in list(self._by_id.values()):
                if other.origin not in GENERATED_ORIGINS:
                    continue
                if other.id == b.id or any(b.matches_host(h) for h in other.hosts):
                    b = absorb(b, other)
                    unindex(other)
                    del self._by_id[other.id]
            self._by_id[b.id] = b  # later wins: registry < curated < operator

    def __len__(self) -> int:
        return len(self._by_id)

    def __iter__(self):
        return iter(sorted(self._by_id.values(), key=lambda b: b.id))

    def __contains__(self, broker_id: str) -> bool:
        return broker_id in self._by_id

    def get(self, broker_id: str) -> Broker:
        try:
            return self._by_id[broker_id]
        except KeyError:
            raise KeyError(f"no broker {broker_id!r} in the catalog") from None

    def by_host(self, host: str) -> Broker | None:
        for b in self._by_id.values():
            if b.matches_host(host):
                return b
        return None

    def search(self, text: str, limit: int = 50) -> list[Broker]:
        q = text.lower().strip()
        hits = [
            b
            for b in self
            if q in b.id
            or q in b.name.lower()
            or any(q in a.lower() for a in b.aka)
            or any(q in h for h in b.hosts)
        ]
        return hits[:limit]

    def people_search(self) -> list[Broker]:
        return [b for b in self if b.category == "people-search"]

    def searchable(self) -> list[Broker]:
        return [b for b in self if b.searchable]

    def by_category(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for b in self:
            out[b.category] = out.get(b.category, 0) + 1
        return out

    def by_origin(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for b in self:
            out[b.origin] = out.get(b.origin, 0) + 1
        return out


def load_dir(directory: Path) -> list[Broker]:
    if not directory.is_dir():
        return []
    out: list[Broker] = []
    for path in sorted(directory.glob("*.yaml")):
        out.extend(_load_file(path))
    return out


def load_catalog(extra_dirs: Iterable[Path] = (), include_overrides: bool = True) -> Catalog:
    """Registry entries first, curated entries on top, then operator overrides."""
    from unlist import paths

    brokers: list[Broker] = []
    brokers += load_dir(REGISTRY_DIR)
    brokers += load_dir(BROKERS_DIR)
    for d in extra_dirs:
        brokers += load_dir(Path(d))
    if include_overrides:
        brokers += [
            b.model_copy(update={"origin": "operator"})
            for b in load_dir(paths.catalog_overrides_dir())
        ]
    return Catalog(brokers)
