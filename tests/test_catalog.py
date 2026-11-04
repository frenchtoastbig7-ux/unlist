from datetime import date

import pytest

from unlist.catalog import Broker, load_catalog
from unlist.catalog.loader import BROKERS_DIR, REGISTRY_DIR, load_dir
from unlist.catalog.models import Search


def test_every_shipped_file_validates():
    curated = load_dir(BROKERS_DIR)
    assert len(curated) >= 25
    ids = [b.id for b in curated]
    assert len(ids) == len(set(ids)), "duplicate curated ids"
    for b in curated:
        assert b.sources, f"{b.id} has no sources"
        if b.status == "active":
            assert b.opt_out.method != "unknown" or b.contact.privacy_url, f"{b.id} has no way out"


def test_registry_loads_if_present():
    reg = load_dir(REGISTRY_DIR)
    if reg:
        assert len(reg) > 500
        assert all(b.origin == "cppa-registry" for b in reg)
        assert all(b.registry.ca for b in reg)


def test_curated_overrides_registry(tmp_path, data_dir):
    cat = load_catalog()
    assert cat.get("spokeo").origin == "curated"
    # operator override wins on the same id
    (data_dir / "catalog").mkdir()
    (data_dir / "catalog" / "spokeo.yaml").write_text(
        "id: spokeo\nname: Spokeo (mine)\nhosts: [spokeo.com]\nopt_out: {method: email, email: x@y.z}\n"
    )
    cat2 = load_catalog()
    assert cat2.get("spokeo").origin == "operator"
    assert cat2.get("spokeo").opt_out.email == "x@y.z"


def test_lookup_helpers():
    cat = load_catalog(include_overrides=False)
    assert cat.by_host("www.truthfinder.com").id == "peopleconnect"
    assert cat.by_host("sub.spokeo.com").id == "spokeo"
    assert cat.by_host("example.invalid") is None
    assert any(b.id == "whitepages" for b in cat.search("411"))
    assert "spokeo" in cat
    assert cat.get("truepeoplesearch").searchable
    assert not cat.get("radaris").searchable


def test_schema_rules():
    with pytest.raises(ValueError):
        Search(method="url", template="https://x/{nope}")
    with pytest.raises(ValueError):
        Broker(id="Bad Id", name="x")
    with pytest.raises(ValueError):
        Broker(id="x", name="x", opt_out={"method": "form"})
    b = Broker(id="x", name="x", hosts=["https://WWW.Example.com/"], last_verified=date(2026, 1, 1))
    assert b.hosts == ["example.com"]
    assert b.matches_host("www.example.com") and b.matches_host("a.example.com")
    assert not b.matches_host("notexample.com")
