import json
from datetime import date

import httpx
import pytest

from unlist.core.testing import html_response, json_response, make_fetcher
from unlist.scanners import exposures as X
from unlist.scanners.brokers import findings as F
from unlist.scanners.brokers.urls import Profile
from unlist.scanners.domains import assess_dmarc, assess_spf, scan_domains
from unlist.scanners.mentions import build_queries, confirm_mention, scan_mentions
from unlist.scanners.usernames import scan_usernames
from unlist.scanners.usernames.wmn import DATA_URL, cache_path, check_site, load_sites, usable
from unlist.subjects import Consent, ConsentError, Identifier, Subject, SubjectRepo


def seed(conn, expires=date(2027, 1, 1)):
    SubjectRepo(conn).add(
        Subject(
            id="me", label="Jane Doe", residency_state="CA",
            consent=Consent(holder="Jane", instrument="self-declaration: my own data", granted=date(2026, 1, 1), expires=expires),
            identifiers=[
                Identifier(subject_id="me", kind="name", value="Jane Q Doe", meta={"city": "Oakland", "state": "CA"}),
                Identifier(subject_id="me", kind="email", value="jane@example.com"),
                Identifier(subject_id="me", kind="phone", value="510-555-0100"),
                Identifier(subject_id="me", kind="username", value="jane.doe82"),
                Identifier(subject_id="me", kind="domain", value="https://www.Janedoe.example/"),
            ],
        )
    )


def wmn_routes(fixtures):
    posts = []

    def post_site(request):
        posts.append(request.content.decode())
        return json_response('{"exists":true}')

    return {
        DATA_URL: json_response((fixtures / "wmn_sample.json").read_bytes()),
        "https://found.test/u/jane.doe82": html_response(b"<div class='profile-header'>jane</div>"),
        "https://missing.test/jane.doe82": httpx.Response(404, content=b"nope"),
        "https://soft.test/jane.doe82": html_response(b"<h1>Profile</h1><p>user does not exist</p>"),
        "https://post.test/api": post_site,
    }, posts


def test_wmn_rules_and_cache(conn, fixtures, data_dir):
    seed(conn)
    routes, posts = wmn_routes(fixtures)
    f = make_fetcher(routes)
    sites = load_sites(f)
    assert [s["name"] for s in sites] == ["FoundSite", "MissingSite", "SoftMissing", "Guarded", "Adult", "PostSite"]  # Retired dropped
    assert [s["name"] for s in sites if usable(s)] == ["FoundSite", "MissingSite", "SoftMissing", "PostSite"]
    assert cache_path().is_file()
    # a second load uses the cache: the download route can vanish
    del routes[DATA_URL]
    assert len(load_sites(make_fetcher(routes))) == 6
    by = {s["name"]: s for s in sites}
    assert check_site(f, by["FoundSite"], "jane.doe82")[0] == "found"
    assert check_site(f, by["FoundSite"], "jane.doe82")[2] == "https://found.test/@jane.doe82"
    assert check_site(f, by["MissingSite"], "jane.doe82")[0] == "missing"
    assert check_site(f, by["SoftMissing"], "jane.doe82")[0] == "missing"
    assert check_site(f, by["FoundSite"], "nobody")[0] == "unknown"  # 404 without the marker text
    assert check_site(f, by["PostSite"], "jane.doe82")[0] == "found"
    assert posts[-1] == '{"user":"janedoe82"}'  # strip_bad_char removed the dot


def test_scan_usernames_records_candidates(conn, fixtures, data_dir):
    seed(conn)
    routes, _ = wmn_routes(fixtures)
    res = scan_usernames(conn, "me", fetcher=make_fetcher(routes))
    assert res.sites == 4 and res.skipped_sites == 2
    assert res.found == 2 and res.new == 2 and res.missing == 2
    rows = X.list_for(conn, "me", "account")
    assert {r["key"] for r in rows} == {"FoundSite", "PostSite"} and all(r["status"] == "candidate" for r in rows)
    assert rows[0]["url"] == "https://found.test/@jane.doe82"
    # only "found" answers are kept as evidence
    assert conn.execute("SELECT COUNT(*) FROM captures WHERE tool='usernames'").fetchone()[0] == 2
    X.set_status(conn, rows[0]["id"], "confirmed")
    res2 = scan_usernames(conn, "me", fetcher=make_fetcher(routes), limit=1)
    assert res2.sites == 1 and res2.new == 0
    assert X.get(conn, rows[0]["id"])["status"] == "confirmed"  # a rescan does not undo a verdict
    with pytest.raises(ValueError):
        X.set_status(conn, rows[0]["id"], "bogus")


def brave(results):
    return json_response(json.dumps({"web": {"results": results}}))


def test_mentions_are_not_stored_until_confirmed(conn, data_dir):
    seed(conn)
    assert scan_mentions(conn, "me", api_key="").skipped
    p = Profile.from_subject(SubjectRepo(conn).get("me"))
    qs = build_queries(p)
    assert qs[0] == '"Jane Doe" "Oakland"' and '"jane@example.com"' in qs and any("510-555-0100" in q for q in qs)
    seen_headers = {}

    def handler(request):
        seen_headers["token"] = request.headers.get("x-subscription-token")
        return brave([
            {"title": "Jane Doe in Oakland - Spokeo", "url": "https://www.spokeo.com/Jane-Doe/California/Oakland", "description": "Jane Q Doe, 44, SECRET-SNIPPET"},
            {"title": "Jane Doe - Local paper", "url": "https://news.example/jane", "description": "A story"},
        ])

    from urllib.parse import quote

    routes = {f"https://api.search.brave.com/res/v1/web/search?q={quote(q, safe='')}&count=20": handler for q in qs}
    res = scan_mentions(conn, "me", fetcher=make_fetcher(routes), api_key="brave-key")
    assert seen_headers["token"] == "brave-key"
    assert len(res.mentions) == 2 and res.mentions[0].broker_id == "spokeo"  # broker hits first, de-duplicated
    # nothing about the results was written anywhere
    assert conn.execute("SELECT COUNT(*) FROM exposures").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM captures").fetchone()[0] == 0
    for path in data_dir.rglob("*"):
        if path.is_file() and path.suffix != ".db" and not path.name.endswith(("-wal", "-shm")):
            assert "SECRET-SNIPPET" not in path.read_text(errors="replace")
    dump = "\n".join(str(tuple(r)) for r in conn.execute("SELECT * FROM scan_runs"))
    assert "spokeo.com" not in dump and "SECRET-SNIPPET" not in dump
    # confirming records the operator's own note, and a broker URL becomes a confirmed listing
    eid, fid = confirm_mention(conn, "me", "https://www.spokeo.com/Jane-Doe/California/Oakland", title="Spokeo listing")
    assert X.get(conn, eid)["status"] == "confirmed" and F.get(conn, fid)["status"] == "confirmed"
    _, fid2 = confirm_mention(conn, "me", "https://news.example/jane")
    assert fid2 is None
    res = scan_mentions(conn, "me", fetcher=make_fetcher(routes), api_key="brave-key")
    assert res.mentions[0].already == "confirmed"
    with pytest.raises(ValueError):
        confirm_mention(conn, "me", "not a url")


def doh(records):
    return json_response(json.dumps({"Status": 0, "Answer": [{"data": f'"{r}"'} for r in records]}))


def test_domain_checks(conn, data_dir):
    seed(conn)
    assert SubjectRepo(conn).get("me").of_kind("domain")[0].value == "janedoe.example"
    assert assess_spf([])[0] == "issue" and assess_spf(["v=spf1 include:x -all"])[0] == "ok"
    assert assess_spf(["v=spf1 +all"])[0] == "issue" and assess_spf(["v=spf1 a", "v=spf1 b"])[0] == "issue"
    assert assess_dmarc(["v=DMARC1; p=none"])[0] == "issue" and assess_dmarc(["v=DMARC1; p=reject"])[0] == "ok"
    d = "janedoe.example"
    routes = {
        f"https://cloudflare-dns.com/dns-query?name={d}&type=TXT": doh(["google-site-verification=x"]),
        f"https://cloudflare-dns.com/dns-query?name=_dmarc.{d}&type=TXT": doh(["v=DMARC1; p=none"]),
        f"https://cloudflare-dns.com/dns-query?name={d}&type=MX": doh(["10 mx.example."]),
        f"https://crt.sh/?q=%25.{d}&output=json": json_response(json.dumps([{"name_value": f"vpn.{d}\n*.{d}"}, {"name_value": f"mail.{d}"}])),
    }
    res = scan_domains(conn, "me", fetcher=make_fetcher(routes))
    assert len(res.issues) == 2 and any("2 hostnames" in i for i in res.info)
    rows = X.list_for(conn, "me", "domain")
    assert {r["key"] for r in rows} == {"spf", "dmarc", "hostnames"}
    assert json.loads(next(r for r in rows if r["key"] == "hostnames")["detail_json"])["hostnames"] == [f"mail.{d}", f"vpn.{d}"]
    # the owner fixes both records: the findings resolve on the next scan
    routes[f"https://cloudflare-dns.com/dns-query?name={d}&type=TXT"] = doh(["v=spf1 include:_spf.example -all"])
    routes[f"https://cloudflare-dns.com/dns-query?name=_dmarc.{d}&type=TXT"] = doh(["v=DMARC1; p=quarantine"])
    res = scan_domains(conn, "me", fetcher=make_fetcher(routes))
    assert not res.issues and len(res.resolved) == 2
    assert {r["status"] for r in X.list_for(conn, "me", "domain") if r["key"] in ("spf", "dmarc")} == {"resolved"}


def test_consent_gates_every_scanner(conn, data_dir):
    seed(conn, expires=date(2026, 2, 1))
    for fn in (scan_usernames, scan_domains):
        with pytest.raises(ConsentError):
            fn(conn, "me", fetcher=make_fetcher({}))
    with pytest.raises(ConsentError):
        scan_mentions(conn, "me", fetcher=make_fetcher({}), api_key="k")


def test_footprint_mcp_tools(conn, fixtures, data_dir, monkeypatch):
    from unlist.mcp import tools

    seed(conn)
    routes, _ = wmn_routes(fixtures)
    monkeypatch.setattr("unlist.scanners.usernames.wmn.make_fetcher", lambda: make_fetcher(routes))
    monkeypatch.delenv("BRAVE_API_KEY", raising=False)
    out = tools.scan_usernames("me")
    assert "2 account(s) found" in out and "WhatsMyName" in out and "FoundSite" in out
    eid = X.list_for(conn, "me", "account")[0]["id"]
    assert "confirmed" in tools.exposures_confirm(str(eid))
    assert "rejected" in tools.exposures_reject(str(X.list_for(conn, "me", "account")[1]["id"]))
    assert "resolved" in tools.exposures_resolve(str(eid))
    assert "FoundSite" in tools.exposures_list("me", kind="account", status="resolved")
    assert "BRAVE_API_KEY" in tools.scan_mentions("me")
    assert "exposure" in tools.mentions_confirm("me", "https://news.example/jane")
    assert "No exposures match" in tools.exposures_list("me", kind="domain")
