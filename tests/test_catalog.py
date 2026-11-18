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
    cppa = [b for b in reg if b.origin == "cppa-registry"]
    manual = [b for b in reg if b.origin == "optout-manual"]
    assert len(cppa) > 500 and all(b.registry.ca for b in cppa)
    assert len(manual) > 400 and all(b.sources for b in manual)
    assert {b.origin for b in reg} == {"cppa-registry", "optout-manual"}


def test_generated_rows_merge_and_feed_curated():
    cat = load_catalog(include_overrides=False)
    assert 800 < len(cat) < 1000
    # one company listed in both generated files becomes one entry, registry id kept
    merged = [
        b for b in cat
        if b.origin == "cppa-registry" and any("thumpersecure" in s for s in b.sources)
    ]
    assert len(merged) > 100 and all(b.registry.ca for b in merged)
    hosts = [h for b in cat for h in b.hosts]
    assert len(hosts) - len(set(hosts)) < 15  # near-unique hosts after merging
    # a curated entry that only describes search inherits its way out from the manual
    assert cat.get("idcrawl").origin == "curated"
    assert cat.get("idcrawl").opt_out.method == "form"
    # curated opt-outs are never overwritten
    assert cat.get("spokeo").opt_out.url == "https://www.spokeo.com/optout"
    kinds = {k for b in cat.searchable() for k in b.search.kinds}
    assert kinds == {"name", "phone", "address"}
    assert len(cat.searchable()) >= 25
    assert not cat.get("dataveria").searchable


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
        Search(method="url", phone_template="https://x/{first}")
    with pytest.raises(ValueError):
        Search(method="url")
    s = Search(method="url", phone_template="https://x/{phone_dashed}", verified=["phone"])
    assert s.kinds == ["phone"] and s.template_for("phone") and s.template_for("name") is None
    with pytest.raises(ValueError):
        Broker(id="Bad Id", name="x")
    with pytest.raises(ValueError):
        Broker(id="x", name="x", opt_out={"method": "form"})
    b = Broker(id="x", name="x", hosts=["https://WWW.Example.com/"], last_verified=date(2026, 1, 1))
    assert b.hosts == ["example.com"]
    assert b.matches_host("www.example.com") and b.matches_host("a.example.com")
    assert not b.matches_host("notexample.com")
