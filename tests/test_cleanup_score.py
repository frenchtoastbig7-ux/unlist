import json
from datetime import date

import pytest

from unlist.catalog.accounts import load_accounts
from unlist.catalog.importers import read_jdm, write_jdm
from unlist.reports.score import exposure_score, label_for, record_score, trend
from unlist.requests import approve, send_approved
from unlist.requests.accounts import cleanup_plan, draft_account_request, google_results_prepare
from unlist.requests.engine import get
from unlist.requests.mailer import FakeMailer
from unlist.scanners import exposures as X
from unlist.scanners.breaches.hibp import Breach
from unlist.scanners.breaches.run import _upsert_hit
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
                Identifier(subject_id="me", kind="username", value="janedoe82"),
            ],
        )
    )


def hit(conn, name, classes, when, kind="breach", domain=None):
    _upsert_hit(conn, "me", None, "jane@example.com", "hibp", Breach(name=name, title=name, domain=domain, breach_date=when, data_classes=classes), None, "2026-11-05T00:00:00Z", kind)
    conn.commit()


def listing(conn, url, status="confirmed", phones=(), places=()):
    fid, _ = F.upsert_candidate(conn, "me", "spokeo", Candidate(listing_url=url, name_text="Jane Doe", score=0.9, phones=list(phones), places=list(places)), None)
    conn.commit()
    if status != "candidate":
        F.set_status(conn, fid, status)
    return fid


def test_jdm_import(tmp_path):
    src = tmp_path / "sites.json"
    src.write_text(json.dumps([
        {"name": "Bountysource", "url": "https://github.com/bountysource/core/issues/409", "difficulty": "hard", "email": "Support@Bountysource.com", "domains": ["bountysource.com"], "notes": "By email.", "notes_de": "x"},
        {"name": "GitHub", "url": "https://github.com/settings/admin", "difficulty": "easy", "domains": ["github.com"]},
        {"name": "NoDomains", "url": "https://www.nodomains.example/delete", "difficulty": "medium"},
        {"name": "", "url": "https://x"},
    ]))
    entries = read_jdm(src)
    assert [e["name"] for e in entries] == ["Bountysource", "GitHub", "NoDomains"]
    assert entries[0]["email"] == "support@bountysource.com" and entries[0]["domains"] == ["bountysource.com"]
    assert entries[2]["domains"] == ["nodomains.example"] and "notes_de" not in entries[0]
    out = write_jdm(entries, tmp_path / "jdm.json")
    assert json.loads(out.read_text())["sites"][1]["name"] == "GitHub"


def test_shipped_directory_lookups():
    d = load_accounts()
    assert len(d) > 2000
    assert d.find(host="www.github.com").name == "GitHub"
    assert d.find(host="gist.github.com").name == "GitHub"
    assert d.find(name="GitLab") is not None and d.find(name="GitHub (User)").name == "GitHub"
    assert d.find(host="no-such-service.invalid") is None and d.find(name="") is None


def test_cleanup_plan_and_account_request(conn, data_dir, monkeypatch):
    monkeypatch.setenv("UNLIST_SMTP_USER", "optout@example.net")
    seed(conn)
    eid, _ = X.upsert(conn, "me", "janedoe82", "account", "whatsmyname", "GitHub (User)", title="GitHub (User)", url="https://github.com/janedoe82")
    X.upsert(conn, "me", "janedoe82", "account", "whatsmyname", "SomeForum", title="SomeForum", url="https://forum.invalid/u/janedoe82")
    conn.commit()
    assert cleanup_plan(conn, "me") == []  # nothing confirmed, nothing breached
    X.set_status(conn, eid, "confirmed")
    hit(conn, "Adobe", ["Passwords"], "2013-10-04", domain="adobe.com")
    hit(conn, "Collection1", ["Passwords"], "2019-01-07")  # a compilation: no account to delete
    hit(conn, "Bountysource", ["Email addresses"], "2020-01-01", domain="bountysource.com")
    plan = cleanup_plan(conn, "me")
    by = {i.service: i for i in plan}
    assert set(by) == {"GitHub", "Adobe", "Bountysource"}
    assert by["GitHub"].why == "account you confirmed" and by["GitHub"].delete_url.startswith("https://github.com/")
    assert by["Adobe"].why == "breached service" and by["Bountysource"].email
    assert [i.difficulty for i in plan] == sorted((i.difficulty for i in plan), key=["easy", "medium", "hard", "limited", "impossible", "unknown"].index)
    with pytest.raises(ValueError):
        draft_account_request(conn, "me", "GitHub")  # no email route
    with pytest.raises(ValueError):
        draft_account_request(conn, "me", "No Such Service")
    r = draft_account_request(conn, "me", "Bountysource")
    assert r["broker_id"] == "account:bountysource" and r["channel"] == "email" and r["state"] == "drafted"
    assert "janedoe82" in r["body"] and "1798.105" in r["body"] and f"[{r['tag']}]" in r["body"]
    with pytest.raises(ValueError):
        draft_account_request(conn, "me", "bountysource.com")  # already open
    approve(conn, [r["id"]])
    assert send_approved(conn, FakeMailer(), [r["id"]])[0][1] is True
    assert get(conn, r["id"])["state"] == "sent" and get(conn, r["id"])["deadline"]


def test_google_results_prepare(conn, data_dir):
    seed(conn)
    listing(conn, "https://www.spokeo.com/p/1")
    listing(conn, "https://www.spokeo.com/p/2", status="candidate")
    X.upsert(conn, "me", "news.example", "mention", "operator", "https://news.example/jane", url="https://news.example/jane", status="confirmed")
    conn.commit()
    text, row = google_results_prepare(conn, "me")
    assert "results-about-you" in text and "https://www.spokeo.com/p/1" in text and "https://news.example/jane" in text
    assert "/p/2" not in text  # candidates are not submitted
    assert row["channel"] == "manual" and row["broker_id"] == "google-results"
    _, again = google_results_prepare(conn, "me")
    assert again["id"] == row["id"]


def test_score_moves_the_right_way(conn, data_dir):
    seed(conn)
    today = date(2026, 11, 5)
    assert exposure_score(conn, "me", today)[0] == 0
    hit(conn, "OldForum", ["Email addresses"], "2012-01-01")
    s1 = exposure_score(conn, "me", today)[0]
    hit(conn, "FreshShop", ["Email addresses", "Passwords"], "2026-03-01")
    s2 = exposure_score(conn, "me", today)[0]
    assert 0 < s1 < s2  # a recent breach with passwords weighs more than an old email-only one
    fid = listing(conn, "https://www.spokeo.com/p/1", phones=["15105550100"], places=["Oakland, CA"])
    s3 = exposure_score(conn, "me", today)[0]
    assert s3 == s2 + 10
    listing(conn, "https://www.spokeo.com/p/9", status="candidate")
    s4 = exposure_score(conn, "me", today)[0]
    assert s4 == s3 + 1
    hit(conn, "bank.example", ["Passwords"], None, kind="stealer")
    s5 = exposure_score(conn, "me", today)[0]
    assert s5 == s4 + 8
    F.set_status(conn, fid, "removed")
    s6, comps = exposure_score(conn, "me", today)
    assert s6 == s5 - 10 and next(c for c in comps if c.name == "live listings").points == 0
    # caps hold
    for i in range(30):
        listing(conn, f"https://www.spokeo.com/x/{i}")
    total, comps = exposure_score(conn, "me", today)
    assert next(c for c in comps if c.name == "live listings").points == 40 and total <= 100
    assert [label_for(x) for x in (0, 19, 20, 49, 50, 74, 75, 100)] == ["low", "low", "moderate", "moderate", "high", "high", "severe", "severe"]


def test_score_history_and_report(conn, data_dir):
    from unlist.mcp import tools

    seed(conn)
    assert record_score(conn, "me")[2] is True
    assert record_score(conn, "me")[2] is False  # unchanged: no duplicate row
    listing(conn, "https://www.spokeo.com/p/1")
    record_score(conn, "me")
    assert [s for _, s in trend(conn, "me")] == [0, 6]
    out = tools.exposure_score("me")
    assert "6 / 100" in out and "Trend: 0" in out and "live listings" in out
    hit(conn, "Pastebin:abc", ["Email addresses"], "2014-03-04", kind="paste")
    rep = tools.report_exposure("me")
    assert "## Score" in rep and "## Pastes and stealer logs" in rep and "Pastebin:abc" in rep
    assert "## Accounts, web mentions and domains" in rep
    assert "Nothing to clean up" in tools.accounts_cleanup("me")
    assert "Google" in tools.google_results_prepare("me")
    assert "Not drafted" in tools.account_deletion_draft("me", "GitHub")
