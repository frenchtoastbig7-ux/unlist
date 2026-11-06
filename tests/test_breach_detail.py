import json
from datetime import date

import pytest
from fastapi.testclient import TestClient

from unlist.core.testing import json_response, make_fetcher
from unlist.scanners.breaches import detail as D
from unlist.scanners.breaches import scan_breaches
from unlist.subjects import Consent, Identifier, Subject, SubjectRepo

EMAIL = "jane@example.com"
Q = "jane%40example.com"


def seed(conn):
    SubjectRepo(conn).add(
        Subject(
            id="me",
            label="Jane",
            residency_state="CA",
            consent=Consent(holder="Jane", instrument="self-declaration: my own data", granted=date(2026, 1, 1), expires=date(2027, 1, 1)),
            identifiers=[Identifier(subject_id="me", kind="email", value=EMAIL)],
        )
    )


def routes(fixtures):
    hibp = json.loads((fixtures / "hibp_breaches.json").read_bytes())
    for b in hibp:
        if b["Name"] == "LinkedIn":
            b["Description"] = 'In May 2012, LinkedIn <a href="https://news.example/linkedin" target="_blank">had 164 million addresses exposed</a>. <a href="javascript:alert(1)">bad</a><script>x()</script>'
            b["DisclosureUrl"] = "https://blog.linkedin.example/notice"
    xon = json.loads((fixtures / "xon_analytics.json").read_bytes())
    for b in xon["ExposedBreaches"]["breaches_details"]:
        if b["breach"] == "Adobe":
            b["details"] = "Adobe lost 152 million accounts in 2013."
            b["references"] = "https://krebs.example/adobe"
    return {
        "https://haveibeenpwned.com/api/v3/breaches": json_response(json.dumps(hibp).encode()),
        f"https://leakcheck.io/api/public?check={Q}": json_response((fixtures / "leakcheck_public.json").read_bytes()),
        f"https://api.xposedornot.com/v1/breach-analytics?email={Q}": json_response(json.dumps(xon).encode()),
    }


@pytest.fixture
def scanned(conn, fixtures, data_dir):
    seed(conn)
    scan_breaches(conn, "me", fetcher=make_fetcher(routes(fixtures)), hibp_api_key="")
    return conn


def by_title(groups):
    return {g.title: g for g in groups}


def test_groups_carry_source_links_and_scoped_data(scanned):
    groups = by_title(D.groups_for(scanned, "me"))
    assert len(groups) == 4 and {"LinkedIn", "Some Forum", "Adobe"} <= set(groups)

    li = groups["LinkedIn"]
    urls = [link.url for link in li.links]
    assert urls[0] == "https://haveibeenpwned.com/Breach/LinkedIn"
    assert "https://blog.linkedin.example/notice" in urls and "https://news.example/linkedin" in urls
    assert not any(u.startswith("javascript") for u in urls)
    assert "https://linkedin.com" in urls
    # the breach's own data classes come from HIBP; LeakCheck's list is kept apart
    assert li.classes_by_source[0][0] == "Have I Been Pwned" and li.classes
    assert li.identifier_fields == [(EMAIL, ["email", "password"])]
    assert "164 million addresses exposed" in li.descriptions[0][1] and "x()" not in li.descriptions[0][1]
    assert li.evidence and li.account is not None and "linkedin" in li.account.url

    forum = groups["Some Forum"]
    assert forum.links == [] and forum.classes == []
    assert "not per breach" in D.exposed_summary(forum)
    assert len(forum.advice) == 1 and "without saying which" in forum.advice[0]

    adobe = groups["Adobe"]
    urls = [link.url for link in adobe.links]
    assert "https://haveibeenpwned.com/Breach/Adobe" in urls and "https://xposedornot.com/breach/Adobe" in urls
    assert "https://krebs.example/adobe" in urls
    assert [s for s, _ in adobe.classes_by_source] == ["Have I Been Pwned", "XposedOrNot"]
    assert ("Passwords", D.PASSWORD_RISK["hardtocrack"]) in adobe.facts
    assert any("Change the password" in a and "without saying" not in a for a in adobe.advice)

    # nothing personal ever goes into a link
    for g in groups.values():
        assert all(EMAIL not in link.url and Q not in link.url for link in g.links)


def test_matching_needs_the_dates_to_agree():
    idx = D.HibpIndex(
        [
            {"Name": "Chegg", "Title": "Chegg", "Domain": "chegg.com", "BreachDate": "2018-04-28"},
            {"Name": "Neopets", "Title": "Neopets", "Domain": "neopets.com", "BreachDate": "2013-05-05"},
            {"Name": "Neopets2022", "Title": "Neopets (2022)", "Domain": "neopets.com", "BreachDate": "2022-07-19"},
            {"Name": "AllegedATT", "Title": "AT&T", "Domain": "", "BreachDate": "2021-08-20"},
        ]
    )
    m = idx.match("Chegg.com", "", "2018-03")
    assert m.entry["Name"] == "Chegg" and m.confident and m.basis == "domain"
    assert idx.match("forums.chegg.com", "", "2019").entry["Name"] == "Chegg"
    assert idx.match("Neopets.com", "", "2013-05").entry["Name"] == "Neopets"
    assert idx.match("Neopets.com", "", "2022-08").entry["Name"] == "Neopets2022"
    assert idx.match("Neopets.com", "", "2017") is None  # two candidates, neither close
    assert idx.match("Neopets.com", "", None) is None
    far = idx.match("Chegg.com", "", "2024-01")
    assert far.entry["Name"] == "Chegg" and not far.confident  # offered, never merged
    assert idx.match("AT&T", "", "2021-01").entry["Name"] == "AllegedATT"
    assert idx.match("ATT-Speculated", "", "2021").entry["Name"] == "AllegedATT"
    assert idx.match("Nobody Heard Of It", "", "2020") is None


def test_helpers():
    text, links = D.html_to_text('A <b>big</b> &amp; bad <a href="http://x.example/a">leak</a> <a href="/relative">no</a>')
    assert text == "A big & bad leak no" and links == [("leak", "http://x.example/a")]
    assert D.paste_url("Pastebin:8Q0BvKD8") == "https://pastebin.com/8Q0BvKD8"
    assert D.paste_url("AdHocUrl:http://siph0n.example/x.txt") == "http://siph0n.example/x.txt"
    assert D.paste_url("AdHocUrl:javascript:1") == "" and D.paste_url("OptOut:1") == ""
    # "Email addresses" and "IP addresses" are not a home address
    assert D.advice_for(["Email addresses", "IP addresses", "Usernames"], []) == []
    assert len(D.advice_for(["Physical addresses", "Phone numbers"], [])) == 2
    assert len(D.advice_for([], ["ssn", "address", "ip"])) == 2


def test_paste_and_stealer_groups(conn, data_dir):
    seed(conn)
    for kind, name, title in (("paste", "Pastebin:AbC123", "leak dump"), ("stealer", "bank.example", "Stealer log: bank.example")):
        conn.execute(
            "INSERT INTO breach_hits(subject_id, identifier_value, source, breach_name, title, first_seen, last_seen, kind) VALUES ('me',?,?,?,?,?,?,?)",
            (EMAIL, "hibp", name, title, "2026-11-01T00:00:00Z", "2026-11-01T00:00:00Z", kind),
        )
    conn.commit()
    groups = {g.kind: g for g in D.groups_for(conn, "me")}
    assert groups["paste"].links[0].url == "https://pastebin.com/AbC123"
    assert groups["stealer"].links[0].url == "https://bank.example"
    assert "clean device" in groups["stealer"].advice[0]


def test_dashboard_report_and_connector_show_links(scanned, monkeypatch):
    from unlist.app.main import create_app
    from unlist.mcp import tools

    monkeypatch.setenv("UNLIST_NO_NOTIFY", "1")
    li = by_title(D.groups_for(scanned, "me"))["LinkedIn"]
    with TestClient(create_app()) as client:
        page = client.get("/subjects/me").text
        assert f'href="/breaches/{li.id}"' in page and "https://haveibeenpwned.com/Breach/LinkedIn" in page
        page = client.get(f"/breaches/{li.id}").text
        for needle in ("Read it at the source", "https://haveibeenpwned.com/Breach/LinkedIn", "https://news.example/linkedin", "What happened", "164 million", "What to do", "/evidence/", "Delete the LinkedIn account", "does not say which breach"):
            assert needle in page, needle
        assert "<script>x()" not in page and "javascript:alert" not in page
        assert client.get("/breaches/99999").status_code == 404

    listing = tools.breaches_list("me")
    assert "https://haveibeenpwned.com/Breach/LinkedIn" in listing and "breach_show" in listing
    shown = tools.breach_show(li.id)
    assert "### LinkedIn" in shown and "Read it at the source" in shown and "https://news.example/linkedin" in shown
    assert "No breach hit" in tools.breach_show(99999)
    rep = tools.report_exposure("me")
    assert "Breach by breach" in rep and "https://xposedornot.com/breach/Adobe" in rep and "Act on these" in rep
