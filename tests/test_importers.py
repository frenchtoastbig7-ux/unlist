import yaml

from unlist.catalog.importers import (
    build_registry,
    read_cppa,
    read_markup,
    slugify,
    write_registry_yaml,
)
from unlist.catalog.loader import load_dir


def test_slugify():
    assert slugify("Explorium Inc.") == "explorium"
    assert slugify("M1 Data & Analytics, LLC") == "m1-data-analytics"
    assert slugify("  ") == "broker"


def test_cppa_sample(fixtures):
    rows = read_cppa(fixtures / "cppa_sample.csv")
    assert len(rows) == 20
    first = rows[0]
    assert first["name"] and first["website"]
    assert "broker_id" in first and "disclosures" in first


def test_build_and_write_registry(fixtures, tmp_path):
    rows = read_cppa(fixtures / "cppa_sample.csv")
    markup = read_markup(fixtures / "markup_sample.csv")
    brokers = build_registry(rows, markup)
    assert len(brokers) == 20
    assert len({b.id for b in brokers}) == 20
    assert all(b.origin == "cppa-registry" for b in brokers)
    assert all(b.registry.ca for b in brokers)
    assert any(b.opt_out.method == "email" and b.opt_out.email for b in brokers)
    out = write_registry_yaml(brokers, tmp_path / "reg" / "cppa.yaml", "# header")
    text = out.read_text()
    assert text.startswith("# header\n")
    assert yaml.safe_load(text)["brokers"][0]["origin"] == "cppa-registry"
    reloaded = load_dir(tmp_path / "reg")
    assert [b.id for b in reloaded] == sorted(b.id for b in brokers)


def test_duplicate_names_get_suffixes():
    rows = [
        {"broker_id": "1", "name": "Acme Inc", "dba": "", "website": "acme.com", "email": "", "phone": "", "postal": "", "privacy_url": "", "disclosures": []},
        {"broker_id": "2", "name": "Acme LLC", "dba": "", "website": "", "email": "", "phone": "", "postal": "", "privacy_url": "", "disclosures": []},
    ]
    ids = [b.id for b in build_registry(rows)]
    assert ids == ["acme", "acme-2"]
