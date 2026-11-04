"""Load the shipped catalog plus operator overrides into one Catalog."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import yaml

from unlist.catalog.models import Broker

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


class Catalog:
    def __init__(self, brokers: Iterable[Broker]) -> None:
        self._by_id: dict[str, Broker] = {}
        for b in brokers:
            if b.origin != "cppa-registry":
                for other in list(self._by_id.values()):
                    if other.origin != "cppa-registry":
                        continue
                    if other.id == b.id or any(b.matches_host(h) for h in other.hosts):
                        b = absorb(b, other)
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
