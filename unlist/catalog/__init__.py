"""The broker catalog: who holds people's data, how to search them, how to opt out.

Shipped as YAML under brokers/ (curated, one file per broker) and registry/ (generated
from public registries by the importers). Operator overrides live in
~/.unlist/catalog/*.yaml and win on the same id. See CATALOG-SOURCES.md for licences.
"""

from unlist.catalog.loader import Catalog, load_catalog
from unlist.catalog.models import Broker

__all__ = ["Broker", "Catalog", "load_catalog"]
