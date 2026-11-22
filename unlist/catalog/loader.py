"""Load the shipped catalog plus operator overrides into one Catalog."""

from __future__ import annotations

import itertools
from collections.abc import Iterable
from pathlib import Path

import yaml

from unlist.catalog.models import GENERATED_ORIGINS, Broker, name_slug, normalise_host

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
            if r.method in ("form", "account") and r.url:
                # The method and its URL travel together: a general privacy page the
                # curated entry had here is not the form, so it moves to the contact.
                if opt_out.url and opt_out.url != r.url and contact.privacy_url is None:
                    contact.privacy_url = opt_out.url
                opt_out.url = r.url
            else:
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


def _owns_id(b: Broker) -> bool:
    """Whether the id says who the company is, rather than the order rows arrived in.

    A curated or operator id was chosen by hand. A generated id is the company's name,
    unless the importer had to add a counter ("acme-2"), and the two importers count
    separately, so the same counter can land on unrelated companies.
    """
    return b.origin not in GENERATED_ORIGINS or b.id == name_slug(b.name)


def _same_company(a: Broker, b: Broker) -> bool:
    """Two rows with one id are one company if they share a host or both own the id."""
    if any(a.matches_host(h) for h in b.hosts) or any(b.matches_host(h) for h in a.hosts):
        return True
    return _owns_id(a) and _owns_id(b)


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

        def free_id(base: str) -> str:
            for n in itertools.count(2):
                suffix = f"-{n}"
                candidate = base[: 64 - len(suffix)].rstrip("-") + suffix
                if candidate not in self._by_id:
                    return candidate
            raise AssertionError("unreachable")  # pragma: no cover

        for b in brokers:
            if b.origin in GENERATED_ORIGINS:
                same = self._by_id.get(b.id)
                if same is not None and not _same_company(same, b):
                    # Same generated id, nothing else in common: a different company.
                    b = b.model_copy(update={"id": free_id(b.id)})
                    same = None
                if same is not None and same.origin not in GENERATED_ORIGINS:
                    continue  # an id already taken by a curated or operator entry
                # Every generated row this one matches, by id or by any of its hosts, is
                # folded in, so no row is left behind holding a host the index gave away.
                matches = [same.id] if same is not None else []
                for h in b.hosts:
                    other_id = host_index.get(h)
                    if other_id is not None and other_id not in matches:
                        matches.append(other_id)
                for other_id in matches:
                    other = self._by_id.pop(other_id)
                    unindex(other)
                    b = merge_generated(other, b)
                self._by_id[b.id] = b
                index(b)
                continue
            for other in list(self._by_id.values()):
                if other.origin not in GENERATED_ORIGINS:
                    continue
                if any(b.matches_host(h) for h in other.hosts) or (
                    other.id == b.id and _owns_id(other)
                ):
                    b = absorb(b, other)
                    unindex(other)
                    del self._by_id[other.id]
                elif other.id == b.id:
                    # A counter-suffixed generated id that happens to equal this entry's:
                    # keep that company, under an id of its own.
                    unindex(other)
                    del self._by_id[other.id]
                    moved = other.model_copy(update={"id": free_id(other.id)})
                    self._by_id[moved.id] = moved
                    index(moved)
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
        """The broker listing this exact host, else the one with the longest parent domain."""
        host = normalise_host(host)
        if not host:
            return None
        best: Broker | None = None
        best_len = 0
        for b in self._by_id.values():
            for h in b.hosts:
                if host == h:
                    return b
                if host.endswith("." + h) and len(h) > best_len:
                    best, best_len = b, len(h)
        return best

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
