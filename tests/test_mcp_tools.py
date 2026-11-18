from click.testing import CliRunner

from unlist.cli import main
from unlist.mcp import tools
from unlist.mcp.server import build_server


def test_subject_flow(data_dir):
    out = tools.subject_add("me", "Operator", residency_state="ca")
    assert "ccpa" in out
    assert "already exists" in tools.subject_add("me", "Operator")
    assert "Not recorded" in tools.consent_grant("me", "Operator", "short", "2027-01-01")
    out = tools.consent_grant("me", "Operator", "self-declaration: my own data", "2027-11-04")
    assert "Consent recorded" in out
    out = tools.identifier_add("me", "name", "Jane Doe", city="Oakland", state="ca")
    assert "Added name" in out and '"state": "CA"' in out
    assert "Not added" in tools.identifier_add("me", "email", "nope")
    shown = tools.subject_show("me")
    assert "Jane Doe" in shown and "Oakland" in shown
    assert "me" in tools.subject_list()
    st = tools.status()
    assert "Subjects: 1" in st and "consent in force" in st
    tail = tools.audit_tail()
    assert "Chain intact" in tail and "consent.grant" in tail


def test_catalog_tools(data_dir):
    assert "spokeo" in tools.catalog_list(category="people-search")
    shown = tools.catalog_show("spokeo")
    assert "optout" in shown and "email_link" in shown
    assert "no broker" in tools.catalog_show("nope")
    assert "peopleconnect" in tools.catalog_search("truthfinder")


def test_server_builds():
    server = build_server()
    assert server.name == "unlist"


def test_cli_help_and_validate(data_dir):
    r = CliRunner().invoke(main, ["--help"])
    assert r.exit_code == 0 and "serve-mcp" in r.output
    r = CliRunner().invoke(main, ["catalog", "validate"])
    assert r.exit_code == 0 and "brokers" in r.output
