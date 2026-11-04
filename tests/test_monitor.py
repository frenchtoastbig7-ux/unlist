import pathlib
from datetime import date, timedelta

from unlist.core.testing import html_response, make_fetcher
from unlist.core.timeutil import iso_z, utcnow
from unlist.monitor import JOBS, run_due
from unlist.monitor.run import jobs_status, launchd_plist, set_interval
from unlist.requests import approve, draft_request, send_approved
from unlist.requests.engine import events_for, get, list_for
from unlist.requests.mailer import FakeMailer
from unlist.scanners.brokers import findings as F
from unlist.scanners.brokers.matcher import Candidate
from unlist.subjects import Consent, Identifier, Subject, SubjectRepo


def seed(conn):
    SubjectRepo(conn).add(
        Subject(
            id="me", label="Jane Doe", residency_state="CA",
            consent=Consent(holder="Jane", instrument="self-declaration: my own data", granted=date(2026, 1, 1), expires=date(2027, 1, 1)),
            identifiers=[
                Identifier(subject_id="me", kind="name", value="Jane Q Doe", meta={"city": "Oakland", "state": "CA"}),
                Identifier(subject_id="me", kind="email", value="jane@example.com"),
            ],
        )
    )


def test_due_logic_and_report(conn, data_dir, monkeypatch):
    monkeypatch.setenv("UNLIST_NO_NOTIFY", "1")
    seed(conn)
    quiet = {"breaches", "verify_listings", "brokers_full", "inbox"}
    s = run_due(conn, only=set(JOBS) - quiet, use_browser=False)
    assert set(s.ran) == {"deadlines", "drop_cycle", "followups"} and not s.changes
    assert s.report_path and "Monitor run" in pathlib.Path(s.report_path).read_text()
    s2 = run_due(conn, only=set(JOBS) - quiet, use_browser=False)
    assert s2.ran == [] and set(s2.skipped) == {"deadlines", "drop_cycle", "followups"}
    s3 = run_due(conn, only={"deadlines"}, force=True, use_browser=False)
    assert s3.ran == ["deadlines"]
    set_interval(conn, "deadlines", "6h")
    rows = {r[0]: r for r in jobs_status(conn)}
    assert rows["deadlines"][1] == "6h" and rows["breaches"][2] == "never"


def test_overdue_and_escalation(conn, data_dir, monkeypatch):
    monkeypatch.setenv("UNLIST_NO_NOTIFY", "1")
    seed(conn)
    fid, _ = F.upsert_candidate(conn, "me", "spokeo", Candidate(listing_url="https://www.spokeo.com/p/1", name_text="Jane Doe", score=0.9), None)
    F.set_status(conn, fid, "confirmed")
    r = draft_request(conn, "me", "spokeo", [fid], channel="email")
    approve(conn, [r["id"]])
    send_approved(conn, FakeMailer(), [r["id"]])
    past = iso_z(utcnow() - timedelta(days=1))
    conn.execute("UPDATE requests SET deadline=? WHERE id=?", (past, r["id"]))
    conn.commit()
    s = run_due(conn, only={"deadlines"}, force=True, use_browser=False)
    assert get(conn, r["id"])["state"] == "overdue" and any("overdue" in c for c in s.changes)
    kinds = [e["kind"] for e in events_for(conn, r["id"])]
    assert "escalation_note" in kinds
    note = next(e["detail"] for e in events_for(conn, r["id"]) if e["kind"] == "escalation_note")
    assert "cppa.ca.gov" in note


def test_verify_closes_request_and_followup_drafts(conn, data_dir, fixtures, monkeypatch):
    monkeypatch.setenv("UNLIST_NO_NOTIFY", "1")
    seed(conn)
    url = "https://www.spokeo.com/p/1"
    fid, _ = F.upsert_candidate(conn, "me", "spokeo", Candidate(listing_url=url, name_text="Jane Doe", score=0.9), None)
    F.set_status(conn, fid, "confirmed")
    r = draft_request(conn, "me", "spokeo", [fid], channel="email")
    approve(conn, [r["id"]])
    send_approved(conn, FakeMailer(), [r["id"]])
    routes = {"https://www.spokeo.com/robots.txt": html_response(b"", status=404), url: html_response((fixtures / "listing_gone.html").read_bytes())}
    monkeypatch.setattr("unlist.scanners.brokers.run.make_fetcher", lambda: make_fetcher(routes))
    s = run_due(conn, only={"verify_listings"}, force=True, use_browser=False)
    assert any("is gone" in c for c in s.changes)
    assert F.get(conn, fid)["status"] == "removed"
    assert get(conn, r["id"])["state"] == "verified_removed"
    # it comes back: verification flags it, the follow-up job drafts a new request
    routes[url] = html_response((fixtures / "listing_present.html").read_bytes())
    s = run_due(conn, only={"verify_listings", "followups"}, force=True, use_browser=False)
    assert any("REAPPEARED" in c for c in s.changes) and any("follow-up" in c for c in s.changes)
    assert F.get(conn, fid)["status"] == "reappeared"
    drafts = list_for(conn, "me", "drafted")
    assert len(drafts) == 1 and drafts[0]["broker_id"] == "spokeo"


def test_drop_cycle(conn, data_dir, monkeypatch):
    monkeypatch.setenv("UNLIST_NO_NOTIFY", "1")
    seed(conn)
    from unlist.requests.drop import record_drop

    d = record_drop(conn, "me", "12345678")
    past = iso_z(utcnow() - timedelta(days=1))
    conn.execute("UPDATE requests SET deadline=? WHERE id=?", (past, d["id"]))
    conn.commit()
    s = run_due(conn, only={"drop_cycle"}, force=True, use_browser=False)
    assert any("DROP cycle" in c for c in s.changes)
    assert get(conn, d["id"])["deadline"] > past and get(conn, d["id"])["state"] == "submitted"


def test_launchd_plist(data_dir):
    text = launchd_plist("/repo", "/usr/local/bin/uv", 7, 30)
    assert "<string>/repo</string>" in text and "run-due" in text and "<integer>7</integer>" in text
    assert str(data_dir) in text


def test_mcp_monitor_tools(conn, data_dir, monkeypatch):
    from unlist.mcp import tools

    monkeypatch.setenv("UNLIST_NO_NOTIFY", "1")
    seed(conn)
    assert "Unknown jobs" in tools.monitor_run_due(only="nope")
    out = tools.monitor_run_due(only="deadlines", force=True)
    assert "Ran: deadlines" in out and "Report:" in out
    assert "deadlines" in tools.monitor_status()
    assert "now runs every 2d" in tools.monitor_set_interval("deadlines", "2d")
    listing = tools.reports_list()
    assert "monitor/" in listing
    name = next(line.split("|")[1].strip() for line in listing.splitlines() if "monitor/" in line)
    assert "Monitor run" in tools.report_read(name)
    assert "No report" in tools.report_read("../../etc/passwd")
