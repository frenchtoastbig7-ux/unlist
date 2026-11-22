"""Regression tests for the review findings in core, catalog, subjects and reports."""

from __future__ import annotations

import json
import sqlite3
import stat
import threading
from datetime import UTC, date, datetime

import httpx
import pytest

from unlist.catalog.accounts import AccountDirectory, AccountService
from unlist.catalog.importers import (
    _md_tables,
    build_manual_registry,
    build_registry,
    read_jdm,
)
from unlist.catalog.loader import Catalog, absorb
from unlist.catalog.models import Broker, Search
from unlist.core import extract, report, store, timeutil
from unlist.core.audit import AuditLog
from unlist.core.testing import html_response, make_fetcher
from unlist.db import MIGRATION_DIRS
from unlist.reports.exposure import exposure_markdown
from unlist.subjects import Consent, ConsentError, Identifier, Subject, SubjectRepo

# clock ------------------------------------------------------------------------------


def test_consent_reads_the_pinned_application_clock(frozen_clock):
    assert timeutil.utcnow() == frozen_clock
    assert timeutil.today() == frozen_clock.date()
    c = Consent(
        holder="x",
        instrument="self-declaration",
        granted=date(2026, 1, 1),
        expires=frozen_clock.date(),
    )
    c.check()
    assert c.days_left() == 0


def test_consent_expiry_follows_the_clock(monkeypatch):
    c = Consent(
        holder="x", instrument="self-declaration", granted=date(2026, 1, 1), expires=date(2027, 1, 1)
    )
    c.check()
    monkeypatch.setattr(timeutil, "_clock", lambda: datetime(2027, 1, 2, 0, 0, 1, tzinfo=UTC))
    with pytest.raises(ConsentError):
        c.check()


def test_parse_dt_returns_none_for_impossible_values():
    for bad in ("99999999999999", float("inf"), float("nan"), 10**15, -(10**15)):
        assert timeutil.parse_dt(bad) is None, bad
    assert timeutil.parse_dt("20261104140509") == datetime(2026, 11, 4, 14, 5, 9, tzinfo=UTC)
    assert timeutil.parse_dt(0) == datetime(1970, 1, 1, tzinfo=UTC)


# fetch ------------------------------------------------------------------------------


def _redirect(to: str, status: int = 302) -> httpx.Response:
    return httpx.Response(status, headers={"location": to})


def test_redirect_hops_get_robots_and_rate_limit():
    hits: list[str] = []

    def secret(request):
        hits.append(str(request.url))
        return html_response(b"<p>secret</p>")

    routes = {
        "https://a.test/robots.txt": httpx.Response(404),
        "https://a.test/start": _redirect("https://b.test/private/page"),
        "https://b.test/robots.txt": httpx.Response(
            200, content=b"User-agent: *\nDisallow: /private/\n"
        ),
        "https://b.test/private/page": secret,
    }
    f = make_fetcher(routes)
    waited: list[str] = []
    real_wait = f.limiter.wait
    f.limiter.wait = lambda host: (waited.append(host), real_wait(host))[1]
    r = f.get("https://a.test/start")
    assert r.refused and r.status is None and hits == []
    assert "redirect target" in r.reason
    assert r.requested_url == "https://a.test/start"
    assert r.final_url == "https://b.test/private/page"
    assert r.history == [(302, "https://a.test/start")]
    # robots.txt and the page on a.test, then robots.txt on b.test: each waits on its host
    assert waited == ["a.test", "a.test", "b.test"]

    # check_robots=False still follows, and the destination host is rate limited
    waited.clear()
    r = f.get("https://a.test/start", check_robots=False)
    assert r.ok and r.final_url == "https://b.test/private/page" and len(hits) == 1
    assert waited == ["a.test", "b.test"]


def test_credential_headers_stay_on_the_first_origin():
    seen: dict[str, httpx.Headers] = {}

    def record(key, response):
        def handler(request):
            seen[key] = request.headers
            return response

        return handler

    routes = {
        "https://api.test/v1": record("first", _redirect("/v2")),
        "https://api.test/v2": record("same", _redirect("https://other.test/x")),
        "https://other.test/x": record("other", _redirect("https://api.test/back")),
        "https://api.test/back": record("back", html_response(b"ok")),
        "https://api.test/down": record("d0", _redirect("http://api.test/plain")),
        "http://api.test/plain": record("down", html_response(b"ok")),
    }
    f = make_fetcher(routes)
    headers = {"X-API-Key": "k", "Authorization": "Bearer t", "Accept": "application/json"}
    r = f.get("https://api.test/v1", check_robots=False, headers=headers)
    assert r.ok and [s for s, _ in r.history] == [302, 302, 302]
    assert seen["first"]["x-api-key"] == "k" and seen["same"]["x-api-key"] == "k"
    for hop in ("other", "back"):  # once dropped, the key does not come back
        assert "x-api-key" not in seen[hop] and "authorization" not in seen[hop]
        assert seen[hop]["accept"] == "application/json"
        assert "unlist" in seen[hop]["user-agent"]
    r = f.get("https://api.test/down", check_robots=False, headers=headers)
    assert r.ok and r.final_url == "http://api.test/plain"
    assert "x-api-key" not in seen["down"] and "authorization" not in seen["down"]


def test_malformed_url_and_redirect_loop_are_failures_not_exceptions():
    routes = {
        "https://loop.test/a": _redirect("https://loop.test/b"),
        "https://loop.test/b": _redirect("https://loop.test/a"),
        "https://site.test/bad": _redirect("http://x.test:abc/"),
        "https://site.test/port": _redirect("http://x.test:99999999/"),
    }
    f = make_fetcher(routes)
    for bad in ("http://[::1", "https://exa mple.test/\x00", "notaurl", ""):
        for r in (f.get(bad, check_robots=False), f.get(bad), f.post(bad, data={"a": "b"})):
            assert r.status is None and r.error and not r.refused and not r.ok, bad
            assert r.requested_url == bad and r.final_url == bad
    r = f.get("https://loop.test/a", check_robots=False)
    assert r.status is None and "redirects" in r.error and r.reason == "redirect limit reached"
    assert len(r.history) > 5
    for url in ("https://site.test/bad", "https://site.test/port"):
        r = f.get(url, check_robots=False)
        assert r.status is None and r.error and not r.ok, url


def test_post_redirects():
    seen: list[tuple[str, str, bytes]] = []

    def record(response):
        def handler(request):
            seen.append((request.method, str(request.url), request.content))
            return response

        return handler

    routes = {
        "https://api.test/form": record(_redirect("/done", 303)),
        "https://api.test/done": record(html_response(b"done")),
        "https://api.test/moved": record(_redirect("/new", 307)),
        "https://api.test/new": record(html_response(b"new")),
        "https://api.test/away": record(_redirect("https://other.test/collect", 307)),
        "https://other.test/collect": record(html_response(b"got it")),
    }
    f = make_fetcher(routes)
    r = f.post("https://api.test/form", data={"q": "jane"})
    assert r.ok and r.body == b"done" and seen[-1] == ("GET", "https://api.test/done", b"")
    r = f.post("https://api.test/moved", data={"q": "jane"})
    assert r.ok and seen[-1] == ("POST", "https://api.test/new", b"q=jane")
    # a body is not repeated to another origin: the 307 itself is the result
    r = f.post("https://api.test/away", data={"q": "jane"})
    assert r.status == 307 and r.final_url == "https://api.test/away"
    assert all(url != "https://other.test/collect" for _, url, _ in seen)


def test_retry_then_network_error_keeps_its_shape():
    calls = {"n": 0}

    def flaky(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503)
        return html_response(b"ok")

    f = make_fetcher(
        {"https://s.test/flaky": flaky, "https://s.test/down": httpx.ConnectError("nope")}
    )
    assert f.get("https://s.test/flaky", check_robots=False).ok and calls["n"] == 2
    r = f.get("https://s.test/down", check_robots=False)
    assert r.status is None and r.reason == "network error after retries"
    assert "ConnectError" in r.error and r.final_url == "https://s.test/down"


# store ------------------------------------------------------------------------------


def test_migrations_recorded_for_every_package_are_idempotent(conn):
    assert store.migrate(conn, MIGRATION_DIRS) == []
    names = {r[0] for r in conn.execute("SELECT name FROM schema_migrations")}
    assert {"scanners/0004_footprint.sql", "requests/0001_requests.sql"} <= names


def test_failed_migration_leaves_nothing_behind(tmp_path):
    good = tmp_path / "pkg" / "migrations"
    good.mkdir(parents=True)
    (good / "0001_a.sql").write_text(
        "-- two statements, the second one fails\n"
        "CREATE TABLE half (id INTEGER PRIMARY KEY);\n"
        "ALTER TABLE no_such_table ADD COLUMN x TEXT;\n"
    )
    conn = store.connect(tmp_path / "m.db")
    with pytest.raises(sqlite3.OperationalError):
        store.migrate(conn, [good])
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "half" not in tables
    assert conn.execute("SELECT 1 FROM schema_migrations WHERE name LIKE 'pkg/%'").fetchone() is None
    # once the script is fixed it applies whole, with a trigger body and a trailing comment
    (good / "0001_a.sql").write_text(
        "CREATE TABLE half (id INTEGER PRIMARY KEY, n INTEGER);\n"
        "CREATE TRIGGER bump AFTER INSERT ON half BEGIN\n"
        "  UPDATE half SET n = 1 WHERE id = NEW.id; SELECT 1;\n"
        "END;\n"
        "-- done\n"
    )
    assert store.migrate(conn, [good]) == ["pkg/0001_a.sql"]
    conn.execute("INSERT INTO half(id) VALUES (7)")
    assert conn.execute("SELECT n FROM half").fetchone()[0] == 1
    assert store.migrate(conn, [good]) == []
    conn.close()


def test_existing_wal_files_are_made_private(tmp_path):
    db = tmp_path / "u.db"
    for suffix in ("", "-wal", "-shm"):
        p = tmp_path / f"u.db{suffix}"
        p.touch()
        p.chmod(0o644)
    conn = store.connect(db)
    conn.execute("CREATE TABLE t (x)")
    conn.commit()
    for suffix in ("", "-wal", "-shm"):
        p = tmp_path / f"u.db{suffix}"
        if p.exists():
            assert stat.S_IMODE(p.stat().st_mode) == 0o600, suffix
    conn.close()
    fresh = store.connect(tmp_path / "new.db")
    fresh.execute("CREATE TABLE t (x)")
    fresh.commit()
    assert stat.S_IMODE((tmp_path / "new.db-wal").stat().st_mode) == 0o600
    fresh.close()


def test_headers_to_json_keeps_repeated_names():
    pairs = [("Set-Cookie", "a=1"), ("set-cookie", "b=2"), ("Vary", "Accept")]
    assert json.loads(store.headers_to_json(pairs)) == {
        "set-cookie": ["a=1", "b=2"],
        "vary": ["Accept"],
    }
    assert json.loads(store.headers_to_json({"X": "1"})) == {"x": ["1"]}
    multi = httpx.Headers([("Link", "<a>"), ("Link", "<b>")])
    assert json.loads(store.headers_to_json(multi)) == {"link": ["<a>", "<b>"]}


# audit, extract, report ----------------------------------------------------------------


def test_concurrent_appends_keep_one_chain(data_dir):
    path = data_dir / "audit.jsonl"

    def work(n: int) -> None:
        log = AuditLog(path)
        for i in range(25):
            log.append("e", worker=n, i=i)

    threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    log = AuditLog(path)
    assert len(log.entries()) == 200
    assert log.verify() == (True, "Chain intact across 200 entries.")


def test_audit_tail_read_handles_long_and_damaged_lines(data_dir):
    log = AuditLog(data_dir / "audit.jsonl")
    log.append("big", blob="x" * 200_000)  # longer than the tail window
    log.append("after")
    assert log.verify()[0]
    with log.path.open("a") as fh:
        fh.write("not json\n\n")
    last = log.entries()[-1]["hash"]
    assert log.append("again")["prev"] == last


def test_declared_html_is_extracted_not_passed_through():
    out = extract.extract(b"<ul><li>Jane Doe</li></ul>", content_type="text/html; charset=utf-8")
    assert out.text == "Jane Doe" and out.method != "plain"
    out = extract.extract("<section><h2>Jane</h2><span>Doe</span></section>", content_type="text/html")
    assert "<" not in out.text and "Jane" in out.text and "Doe" in out.text
    plain = extract.extract("a <p> is a tag", content_type="text/plain")
    assert plain.method == "plain" and plain.text == "a <p> is a tag"
    assert extract.extract("just words").method == "plain"


def test_reports_of_separate_runs_do_not_replace_each_other(tmp_path):
    at = datetime(2026, 11, 4, 9, 30, 15, tzinfo=UTC)
    first = report.write_report("monitor", "run", "Run", "one", run_at=at, data_dir=tmp_path)
    second = report.write_report("monitor", "run", "Run", "two", run_at=at, data_dir=tmp_path)
    third = report.write_report("monitor", "run", "Run", "three", run_at=at, data_dir=tmp_path)
    assert first.name == "2026-11-04_run.md"
    assert second.name == "2026-11-04_run_093015.md"
    assert third.name == "2026-11-04_run_093015-2.md"
    assert "one" in first.read_text() and "two" in second.read_text()


# subjects -----------------------------------------------------------------------------


def _subject(sid: str = "me") -> Subject:
    return Subject(
        id=sid,
        label=sid,
        consent=Consent(
            holder=sid,
            instrument="self-declaration: my own data",
            granted=date(2026, 1, 1),
            expires=date(2027, 1, 1),
        ),
    )


def test_upsert_returns_the_id_of_the_row_it_changed(conn):
    repo = SubjectRepo(conn)
    repo.add(_subject())
    a = repo.add_identifier("me", Identifier(subject_id="me", kind="email", value="a@x.test"))
    b = repo.add_identifier("me", Identifier(subject_id="me", kind="email", value="b@x.test"))
    again = repo.add_identifier(
        "me", Identifier(subject_id="me", kind="email", value="a@x.test", note="updated")
    )
    assert a.id != b.id and again.id == a.id


def test_ids_reject_a_trailing_newline():
    with pytest.raises(ValueError):
        Subject(id="me\n", label="x")
    with pytest.raises(ValueError):
        Broker(id="acme\n", name="Acme")
    with pytest.raises(ValueError):
        Identifier(subject_id="me", kind="email", value="a@x.test\n ok")


# catalog models -----------------------------------------------------------------------


def test_hosts_are_hostnames():
    b = Broker(
        id="x",
        name="X",
        hosts=["https://Example.test:443/path", "www.other.test:8443", "plain.test/", " "],
    )
    assert b.hosts == ["example.test", "other.test", "plain.test"]
    assert b.matches_host("example.test") and b.matches_host("EXAMPLE.test:443")
    assert b.matches_host("https://www.other.test/x") and not b.matches_host("")


def test_search_template_placeholders_any_case():
    for tpl in ("https://x.test/{FIRST}-{last}", "https://x.test/{first-name}", "https://x.test/{}"):
        with pytest.raises(ValueError):
            Search(method="url", template=tpl)
    assert Search(method="url", template="https://x.test/{first}-{last}").kinds == ["name"]


# catalog loader -----------------------------------------------------------------------


def _gen(id_: str, name: str, hosts: list[str], origin: str = "cppa-registry", **kw) -> Broker:
    return Broker(id=id_, name=name, hosts=hosts, origin=origin, **kw)


def test_counter_suffixed_ids_do_not_merge_unrelated_companies():
    # cppa: "Acme LLC" was the second acme; manual: a company actually listed second too
    cppa = _gen("acme-2", "Acme LLC", ["acme-llc.test"], registry={"ca": "9"})
    manual = _gen(
        "acme-2",
        "Acme",
        ["acme-other.test"],
        origin="optout-manual",
        opt_out={"method": "form", "url": "https://acme-other.test/optout"},
    )
    cat = Catalog([cppa, manual])
    assert len(cat) == 2
    assert cat.get("acme-2").hosts == ["acme-llc.test"] and cat.get("acme-2").opt_out.url is None
    other = cat.by_host("acme-other.test")
    assert other.id == "acme-2-2" and other.opt_out.url == "https://acme-other.test/optout"
    # with a shared host they are one company whatever the id says
    same = Catalog([cppa, manual.model_copy(update={"hosts": ["acme-llc.test"]})])
    assert len(same) == 1 and same.get("acme-2").opt_out.method == "form"
    # ids that are just the company's name keep merging across different hosts
    named = Catalog(
        [_gen("merkle", "Merkle Inc.", ["merkle.test"]),
         _gen("merkle", "Merkle", ["merkleinc.test"], origin="optout-manual")]
    )  # fmt: skip
    assert len(named) == 1 and set(named.get("merkle").hosts) == {"merkle.test", "merkleinc.test"}


def test_row_linking_two_generated_rows_folds_both():
    a = _gen("alpha", "Alpha", ["alpha.test"], registry={"ca": "1"})
    b = _gen("alpha-data", "Alpha Data", ["alphadata.test"], registry={"ca": "2"})
    link = _gen("alpha-group", "Alpha Group", ["alpha.test", "alphadata.test"], "optout-manual")
    cat = Catalog([a, b, link])
    assert len(cat) == 1
    only = next(iter(cat))
    assert set(only.hosts) == {"alpha.test", "alphadata.test"}
    assert cat.by_host("alpha.test") is only and cat.by_host("alphadata.test") is only
    # a later row for either host lands on the merged record, not a stale one
    cat2 = Catalog([a, b, link, _gen("late", "Late", ["alphadata.test"], "optout-manual")])
    assert len(cat2) == 1 and "Late" in next(iter(cat2)).aka


def test_curated_entry_does_not_swallow_a_counter_suffixed_stranger():
    stranger = _gen("acme-2", "Acme LLC", ["acme-llc.test"], registry={"ca": "9"})
    curated = Broker(id="acme-2", name="Acme Two", hosts=["acmetwo.test"])
    cat = Catalog([stranger, curated])
    assert cat.get("acme-2").name == "Acme Two" and cat.get("acme-2").registry.ca is None
    assert cat.by_host("acme-llc.test").id == "acme-2-2"
    # a generated row whose id is its own name is still absorbed by the curated entry
    cat = Catalog([_gen("acme", "Acme Inc", ["acme-inc.test"], registry={"ca": "5"}),
                   Broker(id="acme", name="Acme", hosts=["acme.test"])])  # fmt: skip
    assert len(cat) == 1 and cat.get("acme").registry.ca == "5"


def test_absorb_takes_the_form_url_with_the_form_method():
    curated = Broker(
        id="acme",
        name="Acme",
        hosts=["acme.test"],
        opt_out={"method": "unknown", "url": "https://acme.test/privacy"},
    )
    row = _gen(
        "acme",
        "Acme",
        ["acme.test"],
        origin="optout-manual",
        opt_out={"method": "form", "url": "https://acme.test/optout"},
    )
    merged = absorb(curated, row)
    assert merged.opt_out.method == "form" and merged.opt_out.url == "https://acme.test/optout"
    assert merged.contact.privacy_url == "https://acme.test/privacy"


def test_by_host_prefers_exact_then_longest_suffix():
    parent = Broker(id="parent", name="P", hosts=["example.test"])
    child = Broker(id="child", name="C", hosts=["profiles.example.test"])
    for order in ([parent, child], [child, parent]):
        cat = Catalog(order)
        assert cat.by_host("profiles.example.test").id == "child"
        assert cat.by_host("a.profiles.example.test").id == "child"
        assert cat.by_host("www.example.test:443").id == "parent"
        assert cat.by_host("other.example.test").id == "parent"
        assert cat.by_host("notexample.test") is None


# account directory ----------------------------------------------------------------------


def test_account_directory_matching():
    d = AccountDirectory(
        [
            AccountService(name="Bolt", url="https://bolt.eu/rider", domains=("bolt.eu",)),
            AccountService(name="Bolt Driver", url="https://bolt.eu/driver", domains=("bolt.eu",)),
            AccountService(name="GitHub", url="https://github.com/x", domains=("github.com",)),
            AccountService(name="Example", url="https://example.test/a"),
            AccountService(name="Example (Business)", url="https://example.test/b"),
        ]
    )
    assert d.find(host="github.com:443").name == "GitHub"
    assert d.find(host="https://gist.github.com/x").name == "GitHub"
    assert d.by_name("Example (Business)").url == "https://example.test/b"
    assert d.by_name("Example").url == "https://example.test/a"
    assert d.by_name("GitHub (User)").name == "GitHub"
    assert d.find(name="Bolt Driver", host="bolt.eu").name == "Bolt Driver"
    assert d.find(name="Bolt", host="bolt.eu").name == "Bolt"
    assert d.find(name="something else", host="bolt.eu").name == "Bolt"
    assert d.find(name="anything", host="gist.github.com").name == "GitHub"


# importers ------------------------------------------------------------------------------


def _cppa(name: str, website: str, email: str = "", privacy_url: str = "") -> dict:
    return {
        "broker_id": "1", "name": name, "dba": "", "website": website, "email": email,
        "phone": "", "postal": "", "privacy_url": privacy_url, "disclosures": [],
    }  # fmt: skip


def test_final_ids_are_unique():
    names = ["Acme", "Acme LLC", "Acme 2", "Acme Inc", "Acme 3"]
    ids = [b.id for b in build_registry(_cppa(n, f"site{i}.test") for i, n in enumerate(names))]
    assert ids == ["acme", "acme-2", "acme-2-2", "acme-3", "acme-3-2"]
    rows = [
        {"name": n, "aka": [], "domain": f"m{i}.test", "link": None, "email": None,
         "method": "unknown", "requires": [], "category": "other", "method_text": "", "notes": ""}
        for i, n in enumerate(names)
    ]  # fmt: skip
    manual = [b.id for b in build_manual_registry(rows)]
    assert len(set(manual)) == 5
    long = "x" * 80
    two = [b.id for b in build_registry([_cppa(long, "a.test"), _cppa(long, "b.test")])]
    assert len(set(two)) == 2 and all(len(i) <= 64 for i in two)


def test_unparseable_url_names_the_row(tmp_path):
    with pytest.raises(ValueError, match=r"CPPA row 2 \('Broken Co'\): website"):
        build_registry([_cppa("Fine", "fine.test"), _cppa("Broken Co", "http://[broken")])
    row = {"name": "Bad", "aka": [], "domain": "[bad", "link": None, "email": None,
           "method": "unknown", "requires": [], "category": "other", "method_text": "", "notes": ""}  # fmt: skip
    with pytest.raises(ValueError, match=r"opt-out manual row 1 \('Bad'\): domain"):
        build_manual_registry([row])
    sites = tmp_path / "sites.json"
    sites.write_text(json.dumps([{"name": "Svc", "url": "http://[nope/delete"}]))
    with pytest.raises(ValueError, match="JustDeleteMe entry 'Svc': url"):
        read_jdm(sites)


def test_privacy_notice_is_not_a_form():
    notice, emailed = build_registry(
        [
            _cppa("Notice Only", "n.test", privacy_url="https://n.test/privacy"),
            _cppa("Emailed", "e.test", email="p@e.test", privacy_url="https://e.test/privacy"),
        ]
    )
    assert notice.opt_out.method == "unknown" and notice.opt_out.url is None
    assert notice.contact.privacy_url == "https://n.test/privacy"
    assert "privacy page" in notice.opt_out_channel
    assert emailed.opt_out.method == "email" and emailed.opt_out.email == "p@e.test"


def test_escaped_pipe_stays_in_its_cell():
    text = (
        "| # | Site | Domain | Opt-Out Link | Method | Notes |\n"
        "|---|---|---|---|---|---|\n"
        "| 1 | **A \\| B Search** | ab.test | https://ab.test/optout | Online form | x \\| y |\n"
    )
    (headers, rows), = _md_tables(text)
    assert len(headers) == 6 and rows[0][1] == "**A | B Search**" and rows[0][5] == "x | y"
    assert rows[0][2] == "ab.test" and rows[0][3] == "https://ab.test/optout"


# reports --------------------------------------------------------------------------------


def test_failed_query_stops_the_export(conn):
    SubjectRepo(conn).add(_subject())
    body, meta = exposure_markdown(conn, "me")
    assert "None yet" in body and meta["counts"]["requests"] == 0
    conn.execute("ALTER TABLE requests RENAME TO requests_gone")
    with pytest.raises(sqlite3.OperationalError):
        exposure_markdown(conn, "me")


def test_password_checks_stay_out_of_reports_when_they_cannot_be_attributed(conn):
    repo = SubjectRepo(conn)
    repo.add(_subject())
    conn.execute(
        "INSERT INTO password_checks(label, pwned_count, checked_at) VALUES (?,?,?)",
        ("partner's bank login", 12, "2026-11-04T00:00:00Z"),
    )
    conn.commit()
    assert "partner's bank login" in exposure_markdown(conn, "me")[0]
    repo.add(_subject("kid"))
    for sid in ("me", "kid"):
        body = exposure_markdown(conn, sid)[0]
        assert "partner's bank login" not in body and "Password checks" not in body
