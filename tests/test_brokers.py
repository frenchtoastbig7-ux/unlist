from datetime import date

import httpx
import pytest

from unlist.catalog import Broker
from unlist.core.testing import html_response, make_fetcher
from unlist.scanners.brokers import findings as F
from unlist.scanners.brokers import scan_brokers, verify_finding
from unlist.scanners.brokers.matcher import extract_candidates
from unlist.scanners.brokers.urls import NameParts, Profile, build_search_urls
from unlist.subjects import Consent, ConsentError, Identifier, Subject, SubjectRepo


def subject(conn, with_place=True, dob=True):
    idents = [Identifier(subject_id="me", kind="name", value="Jane Q Doe", meta={"city": "Oakland", "state": "CA"} if with_place else {})]
    if with_place:
        idents.append(Identifier(subject_id="me", kind="address", value="1 Main St", current=False, meta={"city": "Berkeley", "state": "CA", "zip": "94704"}))
    if dob:
        idents.append(Identifier(subject_id="me", kind="dob", value="1982-06-15"))
    idents.append(Identifier(subject_id="me", kind="phone", value="510-555-0100"))
    idents.append(Identifier(subject_id="me", kind="relative", value="John Doe"))
    s = Subject(id="me", label="Jane", residency_state="CA",
                consent=Consent(holder="Jane", instrument="self-declaration: my own data", granted=date(2026, 1, 1), expires=date(2027, 1, 1)),
                identifiers=idents)
    SubjectRepo(conn).add(s)
    return SubjectRepo(conn).get("me")


def broker(template="https://www.ps.test/results?name={first}%20{last}&citystatezip={city}%2C%20{state}", fetch="http"):
    return Broker(id="ps", name="PS", hosts=["ps.test"], category="people-search",
                  search={"method": "url", "template": template, "fetch": fetch},
                  opt_out={"method": "form", "url": "https://www.ps.test/optout"})


def test_profile_and_urls(conn):
    p = Profile.from_subject(subject(conn), today=date(2026, 11, 4))
    assert [n.first for n in p.names] == ["Jane"] and p.names[0].middle == "Q"
    assert {pl.city for pl in p.places} == {"Oakland", "Berkeley"}
    assert p.age == 44 and p.phones == ["15105550100"]
    urls = build_search_urls(broker(), p)
    assert [u for u, _ in urls] == [
        "https://www.ps.test/results?name=Jane%20Doe&citystatezip=Oakland%2C%20CA",
        "https://www.ps.test/results?name=Jane%20Doe&citystatezip=Berkeley%2C%20CA",
    ]
    hy = build_search_urls(broker("https://www.ps.test/name/{first}-{last}/{city}-{state}"), p)
    assert hy[0][0] == "https://www.ps.test/name/Jane-Doe/Oakland-CA"
    plus = build_search_urls(broker("https://www.ps.test/people/{first}+{last}/{state_full}/"), p)
    assert plus[0][0] == "https://www.ps.test/people/Jane+Doe/California/"
    assert build_search_urls(broker("https://www.ps.test/{first}-{last}"), p)[0][0] == "https://www.ps.test/Jane-Doe"
    # a template that needs a place yields nothing for a subject without one
    p2 = Profile.from_subject(Subject(id="x", label="x", identifiers=[Identifier(subject_id="x", kind="name", value="Ann Lee")]))
    assert build_search_urls(broker(), p2) == []
    assert NameParts.parse("Cher") is None
    assert NameParts.parse("John Smith Jr.").last == "Smith"


def test_matcher_scores(conn, fixtures):
    p = Profile.from_subject(subject(conn), today=date(2026, 11, 4))
    cands = extract_candidates((fixtures / "results_page.html").read_bytes(), "https://www.ps.test/results", p, ["ps.test"])
    by_url = {c.listing_url: c for c in cands}
    assert "https://ads.example.net/offer" not in by_url  # off-host anchors ignored
    assert "https://www.ps.test/results" not in by_url  # the #top anchor
    best = by_url["https://www.ps.test/find/jane-doe/CA/oakland/123"]
    assert best.score == 1.0 and {"city", "age", "phone", "middle name", "relative"} <= set(best.reasons)
    assert best.age == 44 and "Oakland, CA" in best.places and best.phones == ["15105550100"]
    other = by_url["https://www.ps.test/find/jane-doe/TX/austin/456"]
    assert other.score < 0.5 and "age differs" in other.reasons
    weak = by_url["https://www.ps.test/find/jane-doe/CA/oakland/789"]
    assert 0.5 <= weak.score < best.score
    assert cands[0] is best


def test_scan_records_candidates_and_refusals(conn, fixtures, data_dir):
    subject(conn)
    page = (fixtures / "results_page.html").read_bytes()
    routes = {
        "https://www.ps.test/robots.txt": httpx.Response(404),
        "https://www.ps.test/results?name=Jane%20Doe&citystatezip=Oakland%2C%20CA": html_response(page),
        "https://www.ps.test/results?name=Jane%20Doe&citystatezip=Berkeley%2C%20CA": html_response((fixtures / "no_results.html").read_bytes()),
        "https://www.blocked.test/robots.txt": httpx.Response(404),
        "https://www.blocked.test/p/Jane-Doe": html_response(b"<h1>Access denied</h1>", status=403),
    }
    b2 = Broker(id="blocked", name="Blocked", hosts=["blocked.test"], category="people-search",
                search={"method": "url", "template": "https://www.blocked.test/p/{first}-{last}"},
                opt_out={"method": "email", "email": "privacy@blocked.test"})
    res = scan_brokers(conn, "me", brokers=[broker(), b2], fetcher=make_fetcher(routes), browser=None)
    assert res.brokers == 2 and res.urls == 3
    assert res.fetched == 2 and res.refused == 1 and res.no_results == 1
    assert res.new_candidates == 2 and res.below_threshold == 1
    rows = F.list_for(conn, "me")
    assert [r["status"] for r in rows] == ["candidate", "candidate"]
    assert rows[0]["score"] == 1.0
    checks = {r["broker_id"]: r["outcome"] for r in conn.execute("SELECT * FROM broker_checks")}
    assert checks["blocked"] == "refused"
    kinds = {r[0] for r in conn.execute("SELECT kind FROM captures WHERE tool='brokers'")}
    assert kinds == {"fetch", "refusal"}
    # second run: seen, not new
    res2 = scan_brokers(conn, "me", brokers=[broker()], fetcher=make_fetcher(routes), browser=None)
    assert res2.new_candidates == 0 and res2.seen == 2


def test_confirm_reject_and_verify(conn, fixtures, data_dir):
    subject(conn)
    page = (fixtures / "results_page.html").read_bytes()
    routes = {
        "https://www.ps.test/robots.txt": httpx.Response(404),
        "https://www.ps.test/results?name=Jane%20Doe&citystatezip=Oakland%2C%20CA": html_response(page),
        "https://www.ps.test/find/jane-doe/CA/oakland/123": html_response((fixtures / "listing_present.html").read_bytes()),
        "https://www.ps.test/find/jane-doe/CA/oakland/789": html_response((fixtures / "listing_gone.html").read_bytes()),
    }
    f = make_fetcher(routes)
    scan_brokers(conn, "me", brokers=[broker()], fetcher=f, browser=None)
    rows = F.list_for(conn, "me")
    good, weak = rows[0], rows[1]
    assert F.set_status(conn, good["id"], "confirmed")["status"] == "confirmed"
    assert F.set_status(conn, weak["id"], "rejected", note="not me")["note"] == "not me"
    with pytest.raises(ValueError):
        F.set_status(conn, good["id"], "bogus")
    assert verify_finding(conn, good["id"], fetcher=f)[0] == "present"
    assert F.get(conn, good["id"])["status"] == "confirmed"
    verdict, _ = verify_finding(conn, weak["id"], fetcher=f)
    assert verdict == "gone" and F.get(conn, weak["id"])["status"] == "removed"
    # it comes back: verify sees it, and the scan would too
    routes["https://www.ps.test/find/jane-doe/CA/oakland/789"] = html_response((fixtures / "listing_present.html").read_bytes())
    assert verify_finding(conn, weak["id"], fetcher=make_fetcher(routes))[0] == "present"
    assert F.get(conn, weak["id"])["status"] == "reappeared"
    # refused with no browser -> unknown, status untouched
    routes["https://www.ps.test/find/jane-doe/CA/oakland/123"] = html_response(b"denied", status=403)
    assert verify_finding(conn, good["id"], fetcher=make_fetcher(routes))[0] == "unknown"


def test_scan_needs_consent(conn, data_dir):
    subject(conn)
    SubjectRepo(conn).grant_consent("me", Consent(holder="Jane", instrument="expired declaration", granted=date(2025, 1, 1), expires=date(2025, 2, 1)))
    with pytest.raises(ConsentError):
        scan_brokers(conn, "me", brokers=[broker()], fetcher=make_fetcher({}), browser=None)


def test_mcp_tools(conn, fixtures, data_dir, monkeypatch):
    from unlist.mcp import tools

    subject(conn)
    page = (fixtures / "results_page.html").read_bytes()
    routes = {
        "https://www.ps.test/robots.txt": httpx.Response(404),
        "https://www.ps.test/results?name=Jane%20Doe&citystatezip=Oakland%2C%20CA": html_response(page),
        "https://www.ps.test/results?name=Jane%20Doe&citystatezip=Berkeley%2C%20CA": html_response(b"<p>No results found</p>"),
    }
    monkeypatch.setattr("unlist.scanners.brokers.run.make_fetcher", lambda: make_fetcher(routes))
    monkeypatch.setattr(tools, "_catalog_brokers", lambda ids: [broker()])
    out = tools.scan_brokers("me", brokers="ps", use_browser=False)
    assert "2 new candidate" in out
    listing = tools.findings_list("me")
    assert "candidate" in listing and "oakland/123" in listing
    fid = F.list_for(conn, "me")[0]["id"]
    assert "confirmed" in tools.findings_confirm(str(fid))
    assert "rejected" in tools.findings_reject(str(F.list_for(conn, "me")[1]["id"]), note="not me")
    shown = tools.findings_show(fid)
    assert "Oakland, CA" in shown and "reasons" in shown
