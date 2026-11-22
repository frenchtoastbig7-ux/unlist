"""Regression tests for review findings in the dashboard, CLI, MCP tools and broker scanner."""

import subprocess
import time
from datetime import date
from pathlib import Path

import httpx
import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient

from unlist.app.jobs import JobRunner
from unlist.app.main import create_app
from unlist.app.views import http_url, parse_ids
from unlist.catalog import Broker
from unlist.cli import main as cli
from unlist.core.testing import html_response, make_fetcher
from unlist.mcp import tools
from unlist.requests import approve, draft_request, set_state
from unlist.requests.engine import get as get_request
from unlist.scanners.brokers import findings as F
from unlist.scanners.brokers import scan_brokers, verify_finding
from unlist.scanners.brokers.browser import BrowserCapture, BrowserSession
from unlist.scanners.brokers.matcher import Candidate, extract_candidates
from unlist.scanners.brokers.urls import (
    Profile,
    build_phone_urls,
    build_search_urls,
)
from unlist.subjects import Consent, Identifier, Subject, SubjectRepo

ORIGIN = {"origin": "http://testserver", "host": "testserver"}
LISTING = "https://www.ps.test/find/jane-doe/CA/oakland/123"


@pytest.fixture
def client(data_dir, monkeypatch):
    monkeypatch.setenv("UNLIST_NO_NOTIFY", "1")
    for name in ("UNLIST_SMTP_HOST", "UNLIST_SMTP_USER", "UNLIST_SMTP_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    with TestClient(create_app(allowed_hosts=("testserver",))) as c:
        yield c


def make_subject(conn, identifiers=None, consent=None):
    idents = identifiers or [
        Identifier(subject_id="me", kind="name", value="Jane Q Doe", meta={"city": "Oakland", "state": "CA"}),
    ]
    consent = consent or Consent(
        holder="Jane", instrument="self-declaration: my own data",
        granted=date(2026, 1, 1), expires=date(2027, 1, 1),
    )
    SubjectRepo(conn).add(
        Subject(id="me", label="Jane Doe", residency_state="CA", consent=consent, identifiers=idents)
    )
    return SubjectRepo(conn).get("me")


def add_finding(conn, url=LISTING, status="confirmed", broker_id="ps", score=0.9):
    cand = Candidate(listing_url=url, name_text="Jane Doe", score=score)
    fid, _ = F.upsert_candidate(conn, "me", broker_id, cand, None)
    conn.commit()
    if status != "candidate":
        F.set_status(conn, fid, status)
    return fid


def ps_broker(**search):
    search = {"method": "url", "template": "https://www.ps.test/results?name={first}%20{last}", **search}
    return Broker(id="ps", name="PS", hosts=["ps.test"], category="people-search", search=search)


def job_ids(conn):
    return [r["id"] for r in conn.execute("SELECT id FROM app_jobs")]


# 89: Host header ----------------------------------------------------------------------


def test_only_loopback_hosts_are_served(data_dir):
    with TestClient(create_app(), base_url="http://127.0.0.1:8787") as c:
        assert c.get("/").status_code == 200
        assert c.get("/", headers={"host": "localhost:8787"}).status_code == 200
        assert c.get("/", headers={"host": "[::1]:8787"}).status_code == 200
        for host in ("attacker.example:8787", "testserver", "127.0.0.1.attacker.example", ""):
            r = c.get("/", headers={"host": host})
            assert r.status_code == 400, host
        # a rebinding page's "same-origin" POST is refused before the CSRF check sees it
        r = c.post(
            "/subjects", data={"id": "x", "label": "x"},
            headers={"host": "attacker.example:8787", "origin": "http://attacker.example:8787"},
        )
        assert r.status_code == 400


# 90: only http(s) URLs become links -----------------------------------------------------


def test_http_url_filter():
    assert http_url("https://a.test/x") == "https://a.test/x"
    assert http_url(" HTTP://a.test/x ") == "HTTP://a.test/x"
    for bad in ("JavaScript://a.test/%0aalert(1)", "javascript:alert(1)", "java\tscript:alert(1)",
                "data:text/html,x", "/relative", "", None):
        assert http_url(bad) == "", bad


def test_listing_with_script_scheme_is_never_a_link(client, conn):
    make_subject(conn)
    bad = "JavaScript://www.ps.test/%0aalert(document.domain)"
    fid = add_finding(conn, url=bad)
    for path in (f"/findings/{fid}", "/findings", "/subjects/me"):
        page = client.get(path).text
        assert 'href="JavaScript' not in page and 'href="javascript' not in page.lower(), path
    assert "JavaScript://www.ps.test" in client.get(f"/findings/{fid}").text  # shown as text
    good = add_finding(conn, url=LISTING)
    assert f'href="{LISTING}"' in client.get(f"/findings/{good}").text
    assert f'href="{LISTING}"' in client.get("/findings").text


def test_matcher_ignores_script_scheme_anchors(conn):
    profile = Profile.from_subject(make_subject(conn))
    page = (
        b'<ul><li><a href="JavaScript://www.ps.test/%0aalert(1)">Jane Doe</a> Oakland, CA</li>'
        b'<li><a href="/find/jane-doe/1">Jane Doe</a> Oakland, CA</li></ul>'
    )
    urls = [c.listing_url for c in extract_candidates(page, "https://www.ps.test/r", profile, ["ps.test"])]
    assert urls == ["https://www.ps.test/find/jane-doe/1"]


# 91, 92: accessible names ---------------------------------------------------------------


def test_scan_selectors_have_accessible_names(client, conn):
    make_subject(conn)
    page = client.get("/subjects/me").text
    assert '<select name="use_browser" aria-label=' in page
    assert '<select name="kinds" aria-label=' in page


def test_mention_checkboxes_are_named(client, conn, monkeypatch):
    from unlist.scanners import mentions

    make_subject(conn)

    class Result:
        errors, queries, skipped = [], ["q"], False
        mentions = [type("M", (), {
            "url": "https://news.example/jane", "title": "Jane wins", "host": "news.example",
            "broker_id": None, "description": "", "already": None,
        })()]

    monkeypatch.setattr(mentions, "scan_mentions", lambda conn, sid: Result())
    page = client.post("/subjects/me/mentions", headers=ORIGIN).text
    assert 'aria-label="About me: Jane wins (news.example)"' in page


# 94: id selections ----------------------------------------------------------------------


def test_parse_ids():
    assert parse_ids("") == [] and parse_ids(" 12, 14 15 ") == [12, 14, 15]
    for bad in ("#12", "12;14", "abc", "12 abc", "²", "-3"):
        with pytest.raises(ValueError):
            parse_ids(bad)


def test_bad_send_selection_sends_nothing(client, conn):
    for bad in ("#12", "12;14", "abc", "²"):
        r = client.post("/requests/send", data={"ids": bad}, headers=ORIGIN, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/requests?msg=Nothing%20sent")
    r = client.post("/findings/verify", data={"ids": "12 x"}, headers=ORIGIN, follow_redirects=False)
    assert r.headers["location"].startswith("/findings?msg=Nothing%20verified")
    assert job_ids(conn) == []
    # blank still means the whole approved queue
    r = client.post("/requests/send", data={"ids": " "}, headers=ORIGIN, follow_redirects=False)
    assert r.headers["location"].startswith("/jobs/")


def test_blind_draft_needs_a_positive_limit(client, conn):
    make_subject(conn)
    r = client.post("/requests/draft-blind", data={"subject": "me", "limit": "0"}, headers=ORIGIN, follow_redirects=True)
    assert "limit must be at least 1" in r.text
    assert "limit must be at least 1" in tools.requests_draft_blind("me", limit=0)
    assert "limit must be at least 1" in tools.requests_draft_blind("me", limit=-5)
    assert conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0] == 0


# 95, 129: report paths ------------------------------------------------------------------


def test_mcp_report_read_stays_inside_reports(data_dir):
    (data_dir / "reports" / "monitor").mkdir(parents=True)
    (data_dir / "reports" / "monitor" / "run.md").write_text("# real", encoding="utf-8")
    (data_dir / "reports-old").mkdir()
    (data_dir / "reports-old" / "x.md").write_text("OUTSIDE", encoding="utf-8")
    assert tools.report_read("monitor/run.md") == "# real"
    assert tools.report_read("../reports-old/x.md").startswith("No report")
    assert tools.report_read("../unlist.db").startswith("No report")


# 124: consent that has not started ------------------------------------------------------


def test_future_consent_is_not_called_expired(client, conn):
    make_subject(conn, consent=Consent(
        holder="Jane", instrument="self-declaration: my own data",
        granted=date(2099, 1, 1), expires=date(2099, 12, 31),
    ))
    out = tools.status()
    assert "CONSENT NOT YET IN FORCE (starts 2099-01-01)" in out and "EXPIRED" not in out
    for path in ("/", "/subjects/me"):
        page = client.get(path).text
        assert "NOT YET IN FORCE (starts 2099-01-01)" in page and "EXPIRED" not in page


# 126, 127, 128: approve and send selections ---------------------------------------------


def email_draft(conn, broker_id="spokeo"):
    return draft_request(conn, "me", broker_id, [], channel="email")["id"]


def test_approve_validates_every_id_first(conn, data_dir, monkeypatch):
    monkeypatch.setenv("UNLIST_SMTP_USER", "optout@example.net")
    make_subject(conn)
    rid = email_draft(conn)
    out = tools.requests_approve(f"{rid}, 9999")
    assert "Nothing approved" in out and "9999" in out
    assert get_request(conn, rid)["state"] == "drafted"
    assert "Nothing approved" in tools.requests_approve(f"{rid} request-17")
    assert get_request(conn, rid)["state"] == "drafted"
    assert "Approved 1" in tools.requests_approve(str(rid))


def test_send_rejects_a_malformed_selection(conn, data_dir, monkeypatch):
    from unlist.requests import mailer

    monkeypatch.setenv("UNLIST_SMTP_USER", "optout@example.net")
    make_subject(conn)
    rid = email_draft(conn)
    approve(conn, [rid])
    fake = mailer.FakeMailer()
    monkeypatch.setattr(mailer.SmtpSettings, "from_env", classmethod(lambda cls: fake))
    for bad in ("request-17", f"{rid}, x", "#1"):
        assert tools.requests_send(bad).startswith("Nothing sent"), bad
    assert "no request with id 9999" in tools.requests_send(f"{rid}, 9999")
    assert fake.sent == [] and get_request(conn, rid)["state"] == "approved"
    assert "yes" in tools.requests_send(str(rid))
    assert len(fake.sent) == 1


def test_dry_run_applies_the_send_rules(conn, data_dir, monkeypatch):
    monkeypatch.setenv("UNLIST_SMTP_USER", "optout@example.net")
    make_subject(conn)
    a, b, c = email_draft(conn, "spokeo"), email_draft(conn, "mylife"), email_draft(conn, "beenverified")
    approve(conn, [a, b, c])
    set_state(conn, c, "cancelled")
    out = tools.requests_send(f"{a}, {c}", dry_run=True)
    sending, holding = out.split("Would not send:")
    assert f"| {a} " in sending and f"| {c} " not in sending
    assert f"| {c} " in holding and "not approved (state cancelled)" in holding
    # the whole queue leaves the cancelled one out without comment, as a live send does
    out = tools.requests_send(dry_run=True)
    assert f"| {a} " in out and f"| {b} " in out and "Would not send" not in out
    monkeypatch.setenv("UNLIST_SEND_DAILY_CAP", "1")
    out = tools.requests_send(dry_run=True)
    sending, holding = out.split("Would not send:")
    assert sending.count("privacy@") == 1 and "daily cap of 1" in holding
    assert tools.requests_send("nope", dry_run=True).startswith("Nothing sent")
    assert [get_request(conn, i)["state"] for i in (a, b)] == ["approved", "approved"]


# 88: the job worker ---------------------------------------------------------------------


def wait_for(conn, job_id, statuses=("done", "failed")):
    for _ in range(100):
        row = JobRunner.get(conn, job_id)
        if row["status"] in statuses:
            return row
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} still {row['status']}")


def test_worker_survives_database_failures(conn, data_dir):
    import sqlite3

    runner = JobRunner()
    real_connect = runner.connect
    ran = []
    fail = {"next": False}

    def flaky_connect():
        if fail["next"]:
            fail["next"] = False
            raise sqlite3.OperationalError("database is locked")
        return real_connect()

    first = runner.submit("first", lambda ctx: ran.append("first") or "ok")
    runner.connect = flaky_connect
    fail["next"] = True  # the worker's connection for the first job fails
    runner.start()
    try:
        assert wait_for(conn, first)["status"] == "failed"
        assert ran == []  # never started, and not retried
        second = runner.submit("second", lambda ctx: ran.append("second") or "ok")
        assert wait_for(conn, second)["status"] == "done"

        def closes_its_connection(ctx):
            ran.append("third")
            ctx.conn.close()  # the final status write on this connection will fail
            return "finished"

        third = runner.submit("third", closes_its_connection)
        row = wait_for(conn, third)
        assert (row["status"], row["result"]) == ("done", "finished")
        fourth = runner.submit("fourth", lambda ctx: ran.append("fourth") or "ok")
        assert wait_for(conn, fourth)["status"] == "done"
        assert ran == ["second", "third", "fourth"]
    finally:
        runner.stop()


# 96, 121, 122: CLI ----------------------------------------------------------------------


class FakeLaunchctl:
    """Stands in for subprocess.run; says what launchd would for load, unload and list."""

    def __init__(self, load_rc=0, loaded_after_load=True, loaded_after_unload=False):
        self.load_rc = load_rc
        self.loaded = False
        self.loaded_after_load = loaded_after_load
        self.loaded_after_unload = loaded_after_unload
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append(argv[1])
        rc, err = 0, ""
        if argv[1] == "load":
            rc, err = self.load_rc, ("Load failed: 5: Input/output error" if self.load_rc else "")
            self.loaded = self.loaded_after_load and not self.load_rc
        elif argv[1] == "unload":
            if self.loaded_after_unload:
                rc, err = 1, "Unload failed: 5: Input/output error"
            self.loaded = self.loaded_after_unload
        elif argv[1] == "list":
            rc = 0 if self.loaded else 113
        return subprocess.CompletedProcess(argv, rc, stdout="", stderr=err)


@pytest.fixture
def home(tmp_path, data_dir, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    return tmp_path


def plist_path(home):
    from unlist.monitor.run import LAUNCHD_LABEL

    return home / "Library" / "LaunchAgents" / f"{LAUNCHD_LABEL}.plist"


def test_install_launchd_fails_when_the_job_does_not_load(home, monkeypatch):
    for fake in (FakeLaunchctl(load_rc=5), FakeLaunchctl(loaded_after_load=False)):
        monkeypatch.setattr(subprocess, "run", fake)
        r = CliRunner().invoke(cli, ["monitor", "install-launchd"])
        assert r.exit_code != 0 and "did not load" in r.output
        assert "daily at" not in r.output
    monkeypatch.setattr(subprocess, "run", FakeLaunchctl())
    r = CliRunner().invoke(cli, ["monitor", "install-launchd", "--hour", "7"])
    assert r.exit_code == 0 and "daily at 07:00" in r.output


def test_uninstall_launchd_keeps_the_plist_of_a_job_still_loaded(home, monkeypatch):
    plist = plist_path(home)
    plist.parent.mkdir(parents=True)
    plist.write_text("<plist/>", encoding="utf-8")
    monkeypatch.setattr(subprocess, "run", FakeLaunchctl(loaded_after_unload=True))
    r = CliRunner().invoke(cli, ["monitor", "uninstall-launchd"])
    assert r.exit_code != 0 and "did not unload" in r.output and plist.exists()
    monkeypatch.setattr(subprocess, "run", FakeLaunchctl())
    r = CliRunner().invoke(cli, ["monitor", "uninstall-launchd"])
    assert r.exit_code == 0 and "removed" in r.output and not plist.exists()


def test_status_reads_dotenv_first(data_dir, tmp_path, monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    (tmp_path / ".env").write_text("HIBP_API_KEY=from-dotenv\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    r = CliRunner().invoke(cli, ["status"])
    monkeypatch.delenv("HIBP_API_KEY", raising=False)  # _load_dotenv wrote to os.environ
    assert r.exit_code == 0 and "HIBP_API_KEY: set" in r.output


# 106: browser status follows the document shown -----------------------------------------


class FakeRequest:
    def __init__(self, frame, navigation=True):
        self.frame, self._nav = frame, navigation

    def is_navigation_request(self):
        return self._nav


class FakeResponse:
    def __init__(self, status, frame, navigation=True):
        self.status, self.request = status, FakeRequest(frame, navigation)


class FakePage:
    """A page that shows a challenge first; `after` runs when the operator clears it."""

    url = "https://www.ps.test/listing"

    def __init__(self, first_status, after):
        self.main_frame = object()
        self.first_status, self.after = first_status, after
        self.html = "<html>Just a moment...</html>"
        self.handlers = []
        self.waits = 0

    def on(self, event, handler):
        assert event == "response"
        self.handlers.append(handler)

    def emit(self, status, frame=None, navigation=True):
        for h in self.handlers:
            h(FakeResponse(status, frame or self.main_frame, navigation))

    def goto(self, url, wait_until=None):
        self.emit(self.first_status)
        return FakeResponse(self.first_status, self.main_frame)

    def wait_for_timeout(self, ms):
        self.waits += 1
        if self.waits == 2:  # first wait is the settle; the second is inside the challenge loop
            self.after(self)
            self.html = "<html>Jane Doe, Oakland, CA</html>"

    def wait_for_load_state(self, *a, **k): ...
    def content(self): return self.html
    def screenshot(self, full_page=False): return b"png"
    def title(self): return "t"
    def close(self): ...


def capture_with(page):
    session = BrowserSession(profile_dir=Path("/nonexistent"), challenge_wait_s=5)
    session._ctx = type("Ctx", (), {"new_page": lambda self: page})()
    return session.capture("https://www.ps.test/listing")


def test_capture_status_is_the_final_documents():
    def reloads(page):
        page.emit(200, frame=object())  # an iframe's document does not count
        page.emit(204, navigation=False)  # nor does a subresource
        page.emit(200)

    cap = capture_with(FakePage(403, reloads))
    assert (cap.status, cap.challenged) == (200, False) and b"Jane Doe" in cap.html
    # cleared in place with no new document: the 403 no longer describes the page
    cap = capture_with(FakePage(403, lambda page: None))
    assert (cap.status, cap.challenged) == (None, False)


# 107: details follow the observation that set the score ---------------------------------


def test_upsert_keeps_details_with_their_score(conn, data_dir):
    import json

    make_subject(conn)
    conn.execute("PRAGMA foreign_keys=OFF")  # capture ids here are labels, not rows

    def see(name, score, capture):
        cand = Candidate(listing_url=LISTING, name_text=name, score=score, places=[f"{name}, CA"])
        out = F.upsert_candidate(conn, "me", "ps", cand, capture)
        conn.commit()
        row = F.get(conn, out[0])
        return out[1], row["score"], json.loads(row["extract_json"])["name_text"], row["capture_id"]

    assert see("First", 0.6, None) == ("new", 0.6, "First", None)
    assert see("Better", 0.8, 11) == ("seen", 0.8, "Better", 11)
    assert see("Weaker", 0.5, 12) == ("seen", 0.8, "Better", 11)
    F.set_status(conn, 1, "removed")
    assert see("Back", 0.55, 13) == ("reappeared", 0.55, "Back", 13)


# 108: a no-results page is not a reverse-lookup listing ---------------------------------


def test_no_results_page_is_not_a_reverse_lookup_candidate(conn, fixtures):
    profile = Profile.from_subject(make_subject(conn))
    page = (fixtures / "no_results.html").read_bytes()
    for kind in ("phone", "address"):
        assert extract_candidates(page, "https://rev.test/5105550100", profile, ["rev.test"], kind) == []
    listing = b"<html><body><p>Owner: Jane Doe, Oakland, CA</p></body></html>"
    assert len(extract_candidates(listing, "https://rev.test/5105550100", profile, ["rev.test"], "phone")) == 1


# 109, 110: verify_finding ---------------------------------------------------------------


class FakeBrowser:
    def __init__(self, status, html=b"<html><body>Service unavailable</body></html>"):
        self.status, self.html = status, html

    def capture(self, url):
        return BrowserCapture(
            requested_url=url, final_url=url, status=self.status, html=self.html, png=b"",
            captured_at="2026-11-04T00:00:00Z",
        )


def blocked_routes(status=503):
    return {
        "https://www.ps.test/robots.txt": httpx.Response(404),
        LISTING: html_response(b"<html>try later</html>", status=status),
    }


@pytest.mark.parametrize("browser_status", [503, 403, 500, None])
def test_browser_error_page_is_not_removal_evidence(conn, data_dir, browser_status):
    make_subject(conn)
    fid = add_finding(conn)
    verdict, _ = verify_finding(
        conn, fid, fetcher=make_fetcher(blocked_routes()), browser=FakeBrowser(browser_status)
    )
    assert verdict == "unknown" and F.get(conn, fid)["status"] == "confirmed"


def test_browser_verdicts_that_still_count(conn, data_dir):
    make_subject(conn)
    fid = add_finding(conn)
    f = make_fetcher(blocked_routes(403))
    present = b"<html><body><h1>Jane Doe</h1> Oakland, CA</body></html>"
    # the name on a page of unknown status is still the name
    assert verify_finding(conn, fid, fetcher=f, browser=FakeBrowser(None, present))[0] == "present"
    assert verify_finding(conn, fid, fetcher=f, browser=FakeBrowser(200, present))[0] == "present"
    assert verify_finding(conn, fid, fetcher=f, browser=FakeBrowser(200, b"<p>nobody</p>"))[0] == "gone"
    assert F.get(conn, fid)["status"] == "removed"
    fid2 = add_finding(conn, url=LISTING + "4")
    routes = {**blocked_routes(403), LISTING + "4": html_response(b"x", status=403)}
    assert verify_finding(conn, fid2, fetcher=make_fetcher(routes), browser=FakeBrowser(410))[0] == "gone"


def test_scan_does_not_read_a_browser_error_page(conn, data_dir):
    make_subject(conn)
    url = "https://www.ps.test/results?name=Jane%20Doe"
    routes = {"https://www.ps.test/robots.txt": httpx.Response(404), url: html_response(b"x", status=503)}
    page = b'<html><body><ul><li><a href="/find/jane-doe/1">Jane Doe</a> Oakland, CA</li></ul></body></html>'
    res = scan_brokers(conn, "me", brokers=[ps_broker()], fetcher=make_fetcher(routes), browser=FakeBrowser(503, page))
    assert (res.errors, res.browser, res.new_candidates) == (1, 0, 0)
    row = conn.execute("SELECT outcome, note FROM broker_checks").fetchone()
    assert row["outcome"] == "error" and "HTTP 503" in row["note"]
    res = scan_brokers(conn, "me", brokers=[ps_broker()], fetcher=make_fetcher(routes), browser=FakeBrowser(200, page))
    assert (res.browser, res.new_candidates) == (1, 1)


def test_verify_does_not_undo_a_change_made_during_the_fetch(conn, data_dir):
    make_subject(conn)
    present = (b"<html><body><h1>Jane Doe</h1> Oakland, CA</body></html>", "present")
    gone = (b"<html><body>nobody here</body></html>", "gone")
    for n, (body, expected) in enumerate((present, gone)):
        url = f"{LISTING}{n}"
        fid = add_finding(conn, url=url)

        def reject_while_fetching(request, fid=fid, body=body):
            F.set_status(conn, fid, "rejected", note="operator, mid-fetch")
            return html_response(body)

        routes = {"https://www.ps.test/robots.txt": httpx.Response(404), url: reject_while_fetching}
        verdict, detail = verify_finding(conn, fid, fetcher=make_fetcher(routes))
        row = F.get(conn, fid)
        assert verdict == expected and row["status"] == "rejected", expected
        assert row["verified_at"] and row["note"] == "operator, mid-fetch"
        if expected == "gone":
            assert "left as it is" in detail


def test_verify_reappearance_still_recorded(conn, data_dir):
    make_subject(conn)
    fid = add_finding(conn, status="removed")
    routes = {
        "https://www.ps.test/robots.txt": httpx.Response(404),
        LISTING: html_response(b"<html><body><h1>Jane Doe</h1></body></html>"),
    }
    assert verify_finding(conn, fid, fetcher=make_fetcher(routes))[0] == "present"
    row = F.get(conn, fid)
    assert row["status"] == "reappeared" and row["status_changed_at"]


# 111, 112, 113: search URLs -------------------------------------------------------------


def profile_of(conn, *idents):
    return Profile.from_subject(make_subject(conn, identifiers=list(idents)))


def test_zip_is_kept_when_the_same_place_repeats(conn):
    def ident(kind, value, **meta):
        return Identifier(subject_id="me", kind=kind, value=value, meta=meta)

    p = profile_of(
        conn,
        ident("name", "Jane Doe", city="Oakland", state="CA"),
        ident("address", "1 Main St", city="Oakland", state="CA", zip="94612"),
        ident("address", "2 Oak St", city="oakland", state="CA", zip="94612"),
        ident("address", "3 Elm St", city="Oakland", state="CA", zip="94607"),
        ident("address", "4 Fir St", city="Oakland", state="CA"),
    )
    assert [(pl.city, pl.state, pl.zip) for pl in p.places] == [
        ("Oakland", "CA", "94612"), ("Oakland", "CA", "94607"),
    ]
    b = ps_broker(template="https://www.ps.test/{first}-{last}/{zip}")
    assert [u for u, _ in build_search_urls(b, p)] == [
        "https://www.ps.test/Jane-Doe/94612", "https://www.ps.test/Jane-Doe/94607",
    ]


def test_joined_name_parts_are_url_encoded(conn):
    p = Profile.from_subject(make_subject(conn))
    p.names = [type(p.names[0])(first="Mary Ann", last="Smith/Jones?x")]
    for joiner in "-_+":
        b = ps_broker(template=f"https://www.ps.test/name/{{first}}{joiner}{{last}}")
        assert [u for u, _ in build_search_urls(b, p)] == [
            f"https://www.ps.test/name/Mary{joiner}Ann{joiner}Smith%2FJones%3Fx"
        ]


def test_phone_lookup_is_us_numbers_only(conn):
    p = Profile.from_subject(make_subject(conn))
    b = ps_broker(phone_template="https://www.ps.test/phone/{phone}")
    p.phones = ["442079460958", "15105550100", "5105550101", "25105550102", "5550100"]
    assert [u for u, _ in build_phone_urls(b, p)] == [
        "https://www.ps.test/phone/5105550100", "https://www.ps.test/phone/5105550101",
    ]
