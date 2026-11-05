import yaml

from unlist.catalog.importers import (
    build_manual_registry,
    build_registry,
    read_cppa,
    read_markup,
    read_optout_manual,
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


def test_optout_manual_three_table_shapes(fixtures):
    rows = read_optout_manual(fixtures / "manual_sample.md")
    shapes = {r["shape"] for r in rows}
    assert shapes == {"main", "additional", "broker"}
    by_name = {r["name"]: r for r in rows}
    a = by_name["Addresses.com"]
    assert a["domain"] == "addresses.com" and a["link"] == "https://www.addresses.com/optout"
    assert a["method"] == "form" and "email_link" in a["requires"] and a["category"] == "people-search"
    assert by_name["FastPeopleSearch"]["requires"] == []
    b = by_name["33MileRadius"]
    assert b["method"] == "email" and b["email"] == "privacy@33mileradius.com" and b["category"] == "marketing"
    assert by_name["6sense"]["method"] == "unknown"  # a form with no link in the manual
    assert by_name["411"]["link"] == "https://www.whitepages.com/suppression-requests"
    assert "Category" not in by_name and "Tag" not in by_name  # the legend table is skipped


def test_manual_registry_brokers(fixtures, tmp_path):
    brokers = build_manual_registry(read_optout_manual(fixtures / "manual_sample.md"))
    assert all(b.origin == "optout-manual" for b in brokers)
    ids = [b.id for b in brokers]
    assert len(ids) == len(set(ids))
    hosts = [h for b in brokers for h in b.hosts]
    assert len(hosts) == len(set(hosts))  # a site listed in two tables appears once
    six = next(b for b in brokers if b.id == "6sense")
    assert six.opt_out.method == "unknown" and six.contact.privacy_url == "https://6sense.com"
    assert "privacy page" in six.opt_out.notes
    out = write_registry_yaml(brokers, tmp_path / "m.yaml")
    assert [b.id for b in load_dir(tmp_path)] == sorted(ids)
    assert out.read_text().count("origin: optout-manual") == len(brokers)
