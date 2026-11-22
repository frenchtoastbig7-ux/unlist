"""Regression tests for the review findings in unlist/requests and unlist/monitor."""

import imaplib
import json
import plistlib
import smtplib
from datetime import date, timedelta

import pytest

from unlist.catalog import load_catalog
from unlist.core.testing import html_response, make_fetcher
from unlist.core.timeutil import iso_z, utcnow
from unlist.db import open_db
from unlist.monitor import run as monitor
from unlist.monitor import run_due
from unlist.requests import accounts, engine, form, inbox, mailer, pdf
from unlist.requests.drop import drop_profile, drop_status_summary, record_drop
from unlist.requests.mailer import FakeMailer
from unlist.scanners import exposures as X
from unlist.scanners.breaches.hibp import Breach
from unlist.scanners.breaches.run import _upsert_hit
from unlist.scanners.brokers import findings as F
from unlist.scanners.brokers.matcher import Candidate
from unlist.subjects import Consent, Identifier, Subject, SubjectRepo

SPOKEO_URL = "https://www.spokeo.com/Jane-Doe/California/Oakland/p1"
CONFIRM = "https://www.spokeo.com/optout/confirm?token=abc"


def make_subject(conn, sid="me", label="Jane Doe", state="CA", kind="self", name="Jane Q Doe"):
    SubjectRepo(conn).add(
        Subject(
            id=sid,
            label=label,
            kind=kind,
            residency_state=state,
            consent=Consent(
                holder=label,
                instrument="signed note 2026-01-01, kept in the household file",
                granted=date(2026, 1, 1),
                expires=date(2027, 1, 1),
            ),
            identifiers=[
                Identifier(
                    subject_id=sid, kind="name", value=name, meta={"city": "Oakland", "state": "CA"}
                ),
                Identifier(
                    subject_id=sid,
                    kind="address",
                    value="1 Main St",
                    meta={"city": "Berkeley", "state": "CA", "zip": "94704"},
                ),
                Identifier(subject_id=sid, kind="email", value=f"{sid}@example.com"),
                Identifier(subject_id=sid, kind="username", value="janedoe82"),
            ],
        )
    )
    return SubjectRepo(conn).get(sid)


def expire_consent(conn, sid="me"):
    SubjectRepo(conn).grant_consent(
        sid,
        Consent(
            holder="Jane",
            instrument="expired declaration",
            granted=date(2025, 1, 1),
            expires=date(2025, 2, 1),
        ),
    )


def add_finding(conn, broker_id="spokeo", url=SPOKEO_URL, status="confirmed", sid="me"):
    fid, _ = F.upsert_candidate(
        conn, sid, broker_id, Candidate(listing_url=url, name_text="Jane Doe", score=0.9), None
    )
    conn.commit()
    F.set_status(conn, fid, status)
    return fid


def sent_request(conn, sid="me", finding_ids=()):
    r = engine.draft_request(conn, sid, "spokeo", finding_ids, channel="email")
    engine.approve(conn, [r["id"]])
    assert engine.send_approved(conn, FakeMailer(), [r["id"]])[0][1] is True
    return engine.get(conn, r["id"])


def event_kinds(conn, rid):
    return [e["kind"] for e in engine.events_for(conn, rid)]


def message(uid, text, *, tag=None, links=(), sender="privacy@spokeo.com", subject="Re: request"):
    return inbox.Message(
        uid=uid,
        from_addr=sender,
        subject=f"{subject} [{tag}]" if tag else subject,
        date="2026-11-05T10:00:00Z",
        text=text,
        links=list(links),
    )


class RecordingFetcher:
    """Stands in for Fetcher where the test is about whether a link is opened at all."""

    def __init__(self, inner=None, fail=False):
        self.inner, self.fail, self.urls = inner, fail, []

    def get(self, url, **kw):
        self.urls.append(url)
        if self.fail:
            raise RuntimeError("the process died here")
        return self.inner.get(url, **kw)


# engine ------------------------------------------------------------------------------


def test_transition_only_from_allowed_states(conn, data_dir):
    make_subject(conn)
    fid = add_finding(conn)
    r = sent_request(conn, finding_ids=[fid])
    engine.set_state(conn, r["id"], "cancelled", "operator changed their mind")
    before = event_kinds(conn, r["id"])
    assert engine.transition(conn, r["id"], "completed", engine.SENT_STATES, "late") is False
    assert engine.mark_sent_if(conn, r["id"], "submitted", ("approved",), "late") is False
    assert engine.get(conn, r["id"])["state"] == "cancelled"
    assert event_kinds(conn, r["id"]) == before
    # a deadline that moved since it was read also stops the write
    live = sent_request(conn)
    assert not engine.transition(
        conn, live["id"], "overdue", ("sent",), if_deadline="2020-01-01T00:00:00Z"
    )
    assert engine.transition(conn, live["id"], "overdue", ("sent",), if_deadline=live["deadline"])
    # the operator's own call still works from any state
    assert engine.set_state(conn, r["id"], "completed")["state"] == "completed"
    with pytest.raises(ValueError):
        engine.transition(conn, r["id"], "nonsense", None)


def test_transition_leaves_a_rejected_finding_alone(conn, data_dir):
    make_subject(conn)
    fid = add_finding(conn)
    r = sent_request(conn, finding_ids=[fid])
    assert F.get(conn, fid)["status"] == "requested"
    F.set_status(conn, fid, "rejected")
    assert engine.transition(conn, r["id"], "verified_removed", engine.SENT_STATES)
    assert F.get(conn, fid)["status"] == "rejected"


def test_draft_rejects_another_brokers_finding(conn, data_dir):
    make_subject(conn)
    other = add_finding(conn, broker_id="mylife", url="https://www.mylife.com/jane-doe/e1")
    with pytest.raises(ValueError, match="mylife listing"):
        engine.draft_request(conn, "me", "spokeo", [other], channel="email")
    assert engine.list_for(conn, "me") == []


def test_blind_limit_zero_drafts_nothing(conn, data_dir):
    make_subject(conn)
    assert engine.draft_blind(conn, "me", category="marketing", limit=0) == []
    assert engine.draft_blind(conn, "me", category="marketing", limit=-1) == []
    assert len(engine.draft_blind(conn, "me", category="marketing", limit=2)) == 2


def test_plan_send_matches_the_live_send(conn, data_dir, monkeypatch):
    monkeypatch.setenv("UNLIST_SEND_DAILY_CAP", "1")
    make_subject(conn)
    rows = engine.draft_blind(conn, "me", category="marketing", limit=3)
    ids = [r["id"] for r in rows]
    engine.approve(conn, ids)
    engine.set_state(conn, ids[0], "cancelled")
    plan = engine.plan_send(conn, [*ids, ids[1], 9999])
    assert [r["id"] for r in plan.send] + [r["id"] for r in plan.held] == ids[1:]
    assert len(plan.send) == 1 and plan.room == 1 and plan.cap == 1
    assert dict(plan.rejected) == {
        ids[0]: "not approved (state cancelled)",
        9999: "no such request",
    }
    mail = FakeMailer()
    results = {rid: (ok, why) for rid, ok, why in engine.send_approved(conn, mail, [*ids, 9999])}
    assert len(mail.sent) == 1 and results[plan.send[0]["id"]][0] is True
    assert results[plan.held[0]["id"]] == (False, plan.held_reason)
    assert results[ids[0]][0] is False and results[9999] == (False, "no such request")


def test_send_stops_when_consent_has_lapsed(conn, data_dir):
    make_subject(conn)
    r = engine.draft_request(conn, "me", "spokeo", (), channel="email")
    engine.approve(conn, [r["id"]])
    expire_consent(conn)
    mail = FakeMailer()
    rid, ok, why = engine.send_approved(conn, mail)[0]
    assert (rid, ok) == (r["id"], False) and "consent is not in force" in why
    assert mail.sent == [] and engine.get(conn, r["id"])["state"] == "approved"


def test_sent_copy_failure_does_not_resend(conn, data_dir, monkeypatch):
    make_subject(conn)
    r = engine.draft_request(conn, "me", "spokeo", (), channel="email")
    engine.approve(conn, [r["id"]])

    def full_disk(conn, row):
        raise OSError("No space left on device")

    monkeypatch.setattr(engine, "_store_sent_copy", full_disk)
    mail = FakeMailer()
    rid, ok, why = engine.send_approved(conn, mail)[0]
    assert ok is True and "could not be stored" in why
    assert engine.get(conn, rid)["state"] == "sent" and "sent_copy_failed" in event_kinds(conn, rid)
    assert engine.send_approved(conn, mail) == [] and len(mail.sent) == 1


# mailer ------------------------------------------------------------------------------


class FakeSmtp:
    instances: list = []
    quit_error: Exception | None = None
    send_error: Exception | None = None

    def __init__(self, host, port, **kw):
        self.sent, self.closed = [], False
        FakeSmtp.instances.append(self)

    def ehlo(self):
        pass

    def starttls(self, context=None):
        pass

    def login(self, user, password):
        pass

    def send_message(self, msg):
        if FakeSmtp.send_error:
            raise FakeSmtp.send_error
        self.sent.append(msg)

    def quit(self):
        if FakeSmtp.quit_error:
            raise FakeSmtp.quit_error

    def close(self):
        self.closed = True


def test_quit_failure_after_acceptance_is_not_a_send_failure(monkeypatch):
    monkeypatch.setattr(smtplib, "SMTP", FakeSmtp)
    monkeypatch.setattr(FakeSmtp, "instances", [])
    m = mailer.Mailer(
        mailer.SmtpSettings("smtp.example", 587, "u@example.net", "pw", "u@example.net")
    )
    monkeypatch.setattr(FakeSmtp, "quit_error", smtplib.SMTPResponseException(421, b"bye"))
    assert m.send("privacy@spokeo.com", "s", "b", "UNLIST-AAAAAA").endswith("@example.net>")
    assert len(FakeSmtp.instances[0].sent) == 1 and FakeSmtp.instances[0].closed
    # a refusal of the message itself is still an error, and the connection is closed
    monkeypatch.setattr(FakeSmtp, "send_error", smtplib.SMTPRecipientsRefused({}))
    with pytest.raises(smtplib.SMTPRecipientsRefused):
        m.send("privacy@spokeo.com", "s", "b", "UNLIST-AAAAAA")
    assert FakeSmtp.instances[1].sent == [] and FakeSmtp.instances[1].closed


def test_bad_port_is_a_configuration_error(monkeypatch):
    for k, v in {"HOST": "smtp.example", "USER": "u@example.net", "PASSWORD": "pw"}.items():
        monkeypatch.setenv(f"UNLIST_SMTP_{k}", v)
    monkeypatch.setenv("UNLIST_IMAP_HOST", "imap.example")
    for bad in ("abc", "0", "70000"):
        monkeypatch.setenv("UNLIST_SMTP_PORT", bad)
        with pytest.raises(mailer.ConfigError, match=r"UNLIST_SMTP_PORT.*1 to 65535"):
            mailer.SmtpSettings.from_env()
    monkeypatch.setenv("UNLIST_SMTP_PORT", "")
    assert mailer.SmtpSettings.from_env().port == 587
    monkeypatch.setenv("UNLIST_IMAP_PORT", "abc")
    with pytest.raises(ValueError, match="UNLIST_IMAP_PORT"):
        inbox.ImapSettings.from_env()
    monkeypatch.delenv("UNLIST_IMAP_PORT")
    assert inbox.ImapSettings.from_env().port == 993


# accounts ----------------------------------------------------------------------------


def test_cleanup_keeps_two_profiles_and_ties_the_breach_to_both(conn, data_dir):
    make_subject(conn)
    for user in ("janedoe82", "jdoe-work"):
        eid, _ = X.upsert(
            conn, "me", user, "account", "whatsmyname", f"GitHub (User) {user}",
            title="GitHub (User)", url=f"https://github.com/{user}",
        )  # fmt: skip
        X.set_status(conn, eid, "confirmed")
    for ident in ("me@example.com", "old@example.com"):
        _upsert_hit(
            conn, "me", None, ident, "hibp",
            Breach(name="GitHub", title="GitHub", domain="github.com", breach_date="2020-01-01",
                   data_classes=["Email addresses"]),
            None, "2026-11-05T00:00:00Z", "breach",
        )  # fmt: skip
    conn.commit()
    plan = accounts.cleanup_plan(conn, "me")
    assert [i.service for i in plan] == ["GitHub", "GitHub"]
    assert {i.identifier for i in plan} == {"janedoe82", "jdoe-work"}
    assert all(i.why == "account you confirmed; also breached" for i in plan)


def test_google_request_once_submitted_keeps_its_urls(conn, data_dir):
    make_subject(conn)
    add_finding(conn, url="https://www.spokeo.com/p/1")
    _, first = accounts.google_results_prepare(conn, "me")
    engine.mark_sent(conn, first["id"], "submitted", "done by hand")
    # nothing new: the submitted record is returned untouched
    text, same = accounts.google_results_prepare(conn, "me")
    assert same["id"] == first["id"] and "nothing new" in text
    add_finding(conn, url="https://www.spokeo.com/p/2")
    text, second = accounts.google_results_prepare(conn, "me")
    assert second["id"] != first["id"] and second["state"] == "drafted"
    assert json.loads(second["listings_json"]) == ["https://www.spokeo.com/p/2"]
    assert "/p/2" in text and "- https://www.spokeo.com/p/1" not in text
    kept = engine.get(conn, first["id"])
    assert json.loads(kept["listings_json"]) == ["https://www.spokeo.com/p/1"]
    assert kept["body"] == first["body"] and kept["state"] == "submitted"
    # the draft is still refreshed in place
    add_finding(conn, url="https://www.spokeo.com/p/3")
    _, again = accounts.google_results_prepare(conn, "me")
    assert again["id"] == second["id"] and len(json.loads(again["listings_json"])) == 2


# DROP --------------------------------------------------------------------------------


def test_drop_profile_lists_zip_not_street_address(conn, data_dir):
    make_subject(conn)
    text = drop_profile(conn, "me")
    assert "94704" in text and "1 Main St" not in text and "Addresses" not in text


def test_drop_uses_the_submission_date_and_repairs_a_bare_row(conn, data_dir):
    make_subject(conn)
    with pytest.raises(ValueError, match="not a date"):
        record_drop(conn, "me", "12345678", "soon")
    with pytest.raises(ValueError, match="future"):
        record_drop(conn, "me", "12345678", iso_z(utcnow() + timedelta(days=30)))
    assert engine.list_for(conn, "me") == []
    then = utcnow() - timedelta(days=19)
    d = record_drop(conn, "me", "12345678", iso_z(then))
    assert d["state"] == "submitted" and d["sent_at"] == iso_z(then)
    assert d["deadline"] == iso_z(then + timedelta(days=45))
    # correcting the ID keeps the dates
    fixed = record_drop(conn, "me", "87654321")
    assert (fixed["id"], fixed["drop_id"]) == (d["id"], "87654321")
    assert (fixed["sent_at"], fixed["deadline"]) == (d["sent_at"], d["deadline"])
    # a row left without dates by an interrupted earlier version is repaired on retry
    conn.execute("UPDATE requests SET sent_at=NULL, deadline=NULL WHERE id=?", (d["id"],))
    conn.commit()
    mended = record_drop(conn, "me", "87654321")
    assert mended["sent_at"] and mended["deadline"] > mended["sent_at"]
    summary = json.loads(drop_status_summary(conn, "me"))
    assert summary["check_drop_status_on"] == mended["deadline"] and "next_cycle_due" not in summary


def test_drop_reminder_catches_up_after_a_late_record(conn, data_dir, monkeypatch):
    monkeypatch.setenv("UNLIST_NO_NOTIFY", "1")
    make_subject(conn)
    d = record_drop(conn, "me", "12345678", iso_z(utcnow() - timedelta(days=200)))
    run_due(conn, only={"drop_cycle"}, force=True, use_browser=False)
    assert engine.get(conn, d["id"])["deadline"] > iso_z(utcnow())


# form --------------------------------------------------------------------------------


def test_fill_refusal():
    spokeo = load_catalog(include_overrides=False).get("spokeo")
    ok = "https://www.spokeo.com/optout"
    assert form.fill_refusal(ok, ok, spokeo) is None
    assert form.fill_refusal(ok, "https://spokeo.com/optout/start?x=1", spokeo) is None
    assert "not https" in form.fill_refusal("http://www.spokeo.com/optout", ok, spokeo)
    assert "not https" in form.fill_refusal(ok, "http://www.spokeo.com/optout", spokeo)
    assert "another site" in form.fill_refusal(ok, "https://evil.example/optout", spokeo)
    assert "another site" in form.fill_refusal(ok, "https://spokeo.com.evil.example/", spokeo)
    assert form.fill_refusal(ok, "https://www.spokeo.com@evil.example/optout", spokeo)
    assert form.fill_refusal("", ok, spokeo) and form.fill_refusal(ok, "http://[bad", spokeo)
    # a form hosted for the broker elsewhere is fine as long as the page stays there
    hosted = "https://forms.vendor.example/spokeo"
    assert form.fill_refusal(hosted, hosted + "?step=1", spokeo) is None


class FakeLocator:
    def __init__(self, page, selector):
        self.page, self.selector, self.first = page, selector, self

    def count(self):
        return 1

    def fill(self, value, timeout=None):
        self.page.filled[self.selector] = value

    def scroll_into_view_if_needed(self, timeout=None):
        pass


class FakePage:
    """A page that lands on `lands_on`, then moves to `moves_to` and closes."""

    def __init__(self, lands_on, moves_to=None, on_wait=None):
        self.url, self._lands_on, self._moves_to, self._on_wait = (
            "about:blank",
            lands_on,
            moves_to,
            on_wait,
        )
        self.filled, self.waits, self.origin = {}, 0, 1.0

    def goto(self, url, wait_until=None):
        self.url = self._lands_on or url

    def wait_for_timeout(self, ms):
        self.waits += 1
        if self.waits == 2 and self._moves_to:
            if self._on_wait:
                self._on_wait()
            self.url, self.origin = self._moves_to, 2.0

    def is_closed(self):
        return self.waits >= 4

    def locator(self, selector):
        return FakeLocator(self, selector)

    def evaluate(self, expr):
        return self.origin

    def content(self):
        return f"<html>{self.url}</html>"

    def screenshot(self, full_page=False):
        return b"\x89PNG " + self.url.encode()

    def title(self):
        return "page"


def fake_browser(monkeypatch, page):
    class Session:
        def __init__(self, **kw):
            self._ctx = self

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            pass

        def start(self):
            pass

        def new_page(self):
            return page

    monkeypatch.setattr("unlist.scanners.brokers.browser.BrowserSession", Session)


def form_request(conn):
    make_subject(conn)
    fid = add_finding(conn)
    r = engine.draft_request(conn, "me", "spokeo", [fid])
    engine.approve(conn, [r["id"]])
    return r["id"]


def test_form_assist_fills_only_on_the_intended_https_page(conn, data_dir, monkeypatch):
    rid = form_request(conn)
    page = FakePage("https://evil.example/optout")
    fake_browser(monkeypatch, page)
    assert form.run_form_assist(rid, timeout_s=30) == "closed without submission"
    assert page.filled == {}
    note = next(e["detail"] for e in engine.events_for(conn, rid) if e["kind"] == "form_prefilled")
    assert "nothing filled" in note and "another site" in note
    page = FakePage("https://www.spokeo.com/optout")
    fake_browser(monkeypatch, page)
    form.run_form_assist(rid, timeout_s=30)
    assert page.filled["input[name='url']"] == SPOKEO_URL


def test_form_assist_does_not_undo_a_cancellation(conn, data_dir, monkeypatch):
    rid = form_request(conn)

    def cancel_in_dashboard():
        other = open_db()
        engine.set_state(other, rid, "cancelled", "changed my mind")
        other.close()

    page = FakePage(None, "https://www.spokeo.com/optout/thanks", on_wait=cancel_in_dashboard)
    fake_browser(monkeypatch, page)
    outcome = form.run_form_assist(rid, timeout_s=30)
    row = engine.get(conn, rid)
    assert row["state"] == "cancelled" and row["sent_at"] is None and "cancelled" in outcome
    assert "form_submitted_late" in event_kinds(conn, rid)
    # and the ordinary case still records the submission
    engine.set_state(conn, rid, "approved")
    fake_browser(monkeypatch, FakePage(None, "https://www.spokeo.com/optout/thanks"))
    assert form.run_form_assist(rid, timeout_s=30) == "submitted"
    assert engine.get(conn, rid)["state"] == "submitted"


def test_snapshot_is_of_one_document():
    class Navigating(FakePage):
        """Navigates while the first screenshot is being taken."""

        shots = 0

        def screenshot(self, full_page=False):
            self.shots += 1
            if self.shots == 1:
                self.url, self.origin = "https://www.spokeo.com/b", 2.0
            return b"shot of " + self.url.encode()

    page = Navigating(None)
    page.url = "https://www.spokeo.com/a"
    cap = form._snapshot(page, "https://www.spokeo.com/a")
    assert cap.final_url == "https://www.spokeo.com/b" and b"/b" in cap.html and b"/b" in cap.png

    class Restless(FakePage):
        def screenshot(self, full_page=False):
            self.origin += 1
            return b"shot"

    page = Restless(None)
    page.url = "https://www.spokeo.com/a"
    cap = form._snapshot(page, "https://www.spokeo.com/a")
    assert cap.png == b"" and cap.html == b"<html>https://www.spokeo.com/a</html>"


# inbox -------------------------------------------------------------------------------


def test_html_links_are_decoded_and_bad_ones_dropped():
    raw = (
        b"From: Privacy <privacy@spokeo.com>\r\nSubject: confirm\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b'<p>Confirm <a href="https://www.spokeo.com/optout/confirm?id=7&amp;token=abc">here</a>'
        b' or <a href="http://[broken">here</a> <a href="mailto:x@y">mail</a></p>'
    )
    m = inbox.parse_message("42", raw, "imap.example/u/INBOX/9")
    assert m.links == ["https://www.spokeo.com/optout/confirm?id=7&token=abc"]
    assert m.key == "imap.example/u/INBOX/9/42" and m.uid == "42"
    plain = b"From: a@b\r\nSubject: s\r\n\r\nSee https://www.spokeo.com/x?a=1&b=2 now"
    assert inbox.parse_message("1", plain).links == ["https://www.spokeo.com/x?a=1&b=2"]


def test_completed_that_still_asks_for_confirmation_is_verification():
    m = message("1", "Your request has been processed. Click the link to confirm your request.")
    assert inbox.classify(m)[0] == "verification"
    assert inbox.classify(message("2", "Your record has been removed."))[0] == "completed"


def test_malformed_and_http_links_are_never_followed(conn, data_dir):
    make_subject(conn)
    r = sent_request(conn)
    bad = "http://[not-a-host/confirm?token=1"
    plain = "http://www.spokeo.com/optout/confirm?token=abc"
    spoof = "https://www.spokeo.com@evil.example/confirm?token=1"
    m = message("1", "nothing to see", tag=r["tag"], links=[bad, plain, spoof])
    assert inbox.classify(m)[0] == "verification"
    assert inbox.verification_links(m, ["spokeo.com"]) == ([], [bad, plain, spoof])
    later = message("2", "Your record has been removed.", tag=r["tag"])
    fetcher = RecordingFetcher()
    results = inbox.process_messages(conn, [m, later], fetcher=fetcher)
    assert fetcher.urls == [] and "check it yourself" in results[0]["action"]
    assert results[1]["kind"] == "completed" and engine.get(conn, r["id"])["state"] == "completed"


def test_late_reply_does_not_reopen_a_closed_request(conn, data_dir):
    make_subject(conn)
    r = sent_request(conn)
    engine.set_state(conn, r["id"], "cancelled")
    refusal = message("1", "We are unable to locate a record.", tag=r["tag"])
    confirm = message("2", "Click the link to confirm your request.", tag=r["tag"], links=[CONFIRM])
    fetcher = RecordingFetcher()
    results = inbox.process_messages(conn, [refusal, confirm], fetcher=fetcher)
    assert [x["request_id"] for x in results] == [r["id"], r["id"]]
    assert all("nothing changed" in x["action"] for x in results) and fetcher.urls == []
    assert engine.get(conn, r["id"])["state"] == "cancelled"


def test_untagged_reply_to_two_requests_is_left_for_the_operator(conn, data_dir):
    make_subject(conn)
    make_subject(conn, sid="kid", label="Sam Doe", kind="household", name="Sam Doe")
    a, b = sent_request(conn), sent_request(conn, sid="kid")
    done = message("1", "Your information has been removed.", sender="support@spokeo.com")
    res = inbox.process_messages(conn, [done], fetcher=RecordingFetcher())[0]
    assert res["request_id"] is None and f"{a['id']}, {b['id']}" in res["action"]
    assert inbox.match_request(conn, done, load_catalog()) is None
    assert {engine.get(conn, x["id"])["state"] for x in (a, b)} == {"sent"}
    # a tag settles it
    tagged = message("2", "Your information has been removed.", tag=b["tag"])
    assert (
        inbox.process_messages(conn, [tagged], fetcher=RecordingFetcher())[0]["request_id"]
        == b["id"]
    )
    assert engine.get(conn, b["id"])["state"] == "completed"
    assert engine.get(conn, a["id"])["state"] == "sent"


def test_confirmation_link_needs_consent_in_force(conn, data_dir):
    make_subject(conn)
    r = sent_request(conn)
    expire_consent(conn)
    m = message("1", "Click the link to confirm your request.", tag=r["tag"], links=[CONFIRM])
    fetcher = RecordingFetcher()
    res = inbox.process_messages(conn, [m], fetcher=fetcher)[0]
    assert fetcher.urls == [] and "not followed" in res["action"]
    assert engine.get(conn, r["id"])["state"] == "sent"
    assert "verification_not_followed" in event_kinds(conn, r["id"])


def test_interrupted_link_follow_is_not_repeated(conn, data_dir):
    make_subject(conn)
    r = sent_request(conn)
    m = message("1", "Click the link to confirm your request.", tag=r["tag"], links=[CONFIRM])
    dying = RecordingFetcher(fail=True)
    with pytest.raises(RuntimeError):
        inbox.process_messages(conn, [m], fetcher=dying)
    conn.rollback()
    row = conn.execute("SELECT * FROM inbox_messages").fetchone()
    assert row["action"] == inbox.CLAIM_ACTION and row["request_id"] == r["id"]
    again = RecordingFetcher(make_fetcher({CONFIRM: html_response(b"ok")}))
    assert inbox.process_messages(conn, [m], fetcher=again) == [] and again.urls == []
    assert engine.get(conn, r["id"])["state"] == "sent"


def test_followed_link_updates_the_claim_row(conn, data_dir):
    make_subject(conn)
    r = sent_request(conn)
    m = message("1", "Click the link to confirm your request.", tag=r["tag"], links=[CONFIRM])
    fetcher = RecordingFetcher(make_fetcher({CONFIRM: html_response(b"<p>Confirmed</p>")}))
    res = inbox.process_messages(conn, [m], fetcher=fetcher)[0]
    rows = conn.execute("SELECT * FROM inbox_messages").fetchall()
    assert len(rows) == 1 and rows[0]["action"] == res["action"] == f"followed {CONFIRM}"
    assert rows[0]["capture_id"] and engine.get(conn, r["id"])["state"] == "acknowledged"


def test_same_uid_in_another_mailbox_is_a_new_message(conn, data_dir):
    make_subject(conn)
    r = sent_request(conn)
    first = message("7", "We have received your request.", tag=r["tag"])
    first.scope = "imap.example/u/INBOX/100"
    second = message("7", "Your information has been removed.", tag=r["tag"])
    second.scope = "imap.example/u/INBOX/101"  # the server renumbered the folder
    assert len(inbox.process_messages(conn, [first], fetcher=RecordingFetcher())) == 1
    assert inbox.process_messages(conn, [first], fetcher=RecordingFetcher()) == []
    assert len(inbox.process_messages(conn, [second], fetcher=RecordingFetcher())) == 1
    assert engine.get(conn, r["id"])["state"] == "completed"


class FakeImap:
    made: dict = {}
    store_status = "OK"

    def __init__(self, host, port, **kw):
        FakeImap.made = {"host": host, "port": port, **kw}

    def login(self, user, password):
        pass

    def select(self, folder):
        return "OK", [b"3"]

    def response(self, code):
        return code, [b"777"]

    def uid(self, command, *args):
        if command == "search":
            return "OK", [b"5"]
        if command == "fetch":
            return "OK", [(b"5 (BODY[] {9}", b"From: a@b\r\nSubject: hi\r\n\r\nbody"), b")"]
        return FakeImap.store_status, [b"[CANNOT] read-only mailbox"]

    def logout(self):
        pass


def test_imap_session_is_verified_bounded_and_scoped(monkeypatch):
    monkeypatch.setattr(imaplib, "IMAP4_SSL", FakeImap)
    settings = inbox.ImapSettings("imap.example", 993, "u@example.net", "pw")
    with inbox.ImapInbox(settings) as box:
        ctx = FakeImap.made["ssl_context"]
        assert ctx.check_hostname and ctx.verify_mode.name == "CERT_REQUIRED"
        assert FakeImap.made["timeout"] == inbox.IMAP_TIMEOUT_S
        (m,) = box.fetch_unseen()
        assert m.uid == "5" and m.key == "imap.example/u@example.net/INBOX/777/5"
        box.mark_seen("5")
        assert box.mark_seen_all(["5"]) == []
        monkeypatch.setattr(FakeImap, "store_status", "NO")
        with pytest.raises(RuntimeError, match="refused to mark message 5 seen"):
            box.mark_seen("5")
        assert len(box.mark_seen_all(["5", "6"])) == 2


# letters -----------------------------------------------------------------------------


def test_width_tables_cover_the_font():
    assert len(pdf._ASCII_W) == 95 and len(pdf._LATIN1_W) == 96
    assert pdf.text_width("W" * 10, 10) == pytest.approx(94.4)
    assert pdf.text_width("il", 1000) == 444 and pdf.text_width("é€", 1000) == 1112


def test_wrap_respects_the_printable_width():
    wide = pdf.wrap_line("W" * 80)
    assert len(wide) > 1 and "".join(wide) == "W" * 80
    assert all(pdf.text_width(ln) <= pdf.TEXT_W for ln in wide)
    para = "  Name: " + "Wilhelmina MMMMMMMM " * 12
    lines = pdf.wrap_line(para)
    assert lines[0].startswith("  Name:") and " ".join(lines).split() == para.split()
    assert all(pdf.text_width(ln) <= pdf.TEXT_W for ln in lines)
    assert pdf.wrap_line("short line") == ["short line"]
    assert b"(" + b"W" * 80 + b")" not in pdf.text_to_pdf("W" * 80)


def test_letter_refuses_text_it_cannot_print(conn, data_dir):
    make_subject(conn, name="李雷")
    r = engine.draft_request(conn, "me", "acxiom", (), channel="mail")
    with pytest.raises(pdf.LetterError, match="李"):
        pdf.write_letter(conn, r["id"])
    assert not list((data_dir / "letters").glob("*.pdf"))
    assert "letter_written" not in event_kinds(conn, r["id"])
    assert pdf.text_to_pdf("Zoë Müller — “ok”").startswith(b"%PDF-1.4")


def test_letter_wording(conn, data_dir, monkeypatch):
    monkeypatch.delenv("UNLIST_SMTP_USER", raising=False)
    s = make_subject(conn, kind="household")
    spokeo = load_catalog(include_overrides=False).get("spokeo")
    for key in ("ccpa_delete", "ccpa_optout", "state_tx", "plain"):
        body = engine.render(key, s, spokeo, [], "T", "optout@example.net").body
        assert "authorised agent" in body and "signed note" not in body
        assert "to optout@example.net, when the request" in body
        assert "more burdensome" not in body and "is sufficient" not in body
        assert "this email address" not in body and "government-issued" in body
    # a postal letter with no reply address does not point at one
    bare = engine.render("plain", s, spokeo, ["https://x"], "T", None, include_contact=False).body
    assert "Please confirm in writing when the request has been carried out." in bare
    assert "email address" not in bare
    assert (
        "proportionate to this request (11 CCR § 7060)"
        in engine.render("ccpa_delete", s, spokeo, [], "T", None).body
    )


# monitor -----------------------------------------------------------------------------


def test_interval_that_cannot_be_scheduled(conn, data_dir, monkeypatch):
    monkeypatch.setenv("UNLIST_NO_NOTIFY", "1")
    make_subject(conn)
    with pytest.raises(ValueError, match="too long"):
        monitor.set_interval(conn, "deadlines", "1000000000000000s")
    monitor.set_interval(conn, "deadlines", "52w")
    # one already stored by an earlier version must not break the page or the run
    run_due(conn, only={"deadlines", "score"}, force=True, use_browser=False)
    conn.execute("UPDATE jobs SET interval_seconds=1000000000000000 WHERE name='deadlines'")
    conn.commit()
    rows = {r[0]: r for r in monitor.jobs_status(conn)}
    assert "interval too long" in rows["deadlines"][3]
    s = run_due(conn, only={"deadlines", "score"}, use_browser=False)
    assert "deadlines" in s.skipped and s.report_path


def test_job_is_claimed_before_it_runs(conn, data_dir, monkeypatch):
    monkeypatch.setenv("UNLIST_NO_NOTIFY", "1")
    make_subject(conn)
    run_due(conn, only={"deadlines"}, force=True, use_browser=False)
    assert conn.execute("SELECT claimed_at FROM jobs WHERE name='deadlines'").fetchone()[0] is None
    conn.execute("UPDATE jobs SET claimed_at=? WHERE name='deadlines'", (iso_z(utcnow()),))
    conn.commit()
    s = run_due(conn, only={"deadlines"}, force=True, use_browser=False)
    assert s.ran == [] and s.skipped == ["deadlines"] and "another run" in s.problems[0]
    # a claim left by a run that died is taken over
    old = iso_z(utcnow() - monitor.CLAIM_STALE_AFTER - timedelta(minutes=1))
    conn.execute("UPDATE jobs SET claimed_at=? WHERE name='deadlines'", (old,))
    conn.commit()
    assert run_due(conn, only={"deadlines"}, force=True, use_browser=False).ran == ["deadlines"]
    assert monitor._claim(conn, "score") and not monitor._claim(conn, "score")


def test_a_failing_job_does_not_stop_the_run(conn, data_dir, monkeypatch):
    monkeypatch.setenv("UNLIST_NO_NOTIFY", "1")
    make_subject(conn)

    def boom(conn, subjects, s, browser):
        raise RuntimeError("kaboom")

    monkeypatch.setitem(monitor._JOB_FUNCS, "deadlines", boom)
    s = run_due(conn, only={"deadlines", "score"}, force=True, use_browser=False)
    assert s.ran == ["deadlines", "score"] and "deadlines: kaboom" in s.problems and s.report_path
    row = conn.execute("SELECT * FROM jobs WHERE name='deadlines'").fetchone()
    assert row["last_result"] == "error: kaboom" and row["claimed_at"] is None


def test_bad_mailbox_settings_stay_inside_their_jobs(conn, data_dir, monkeypatch):
    monkeypatch.setenv("UNLIST_NO_NOTIFY", "1")
    make_subject(conn)
    r = engine.draft_request(conn, "me", "spokeo", (), channel="email")
    engine.approve(conn, [r["id"]])
    for k, v in {"HOST": "mail.example", "USER": "u@example.net", "PASSWORD": "pw"}.items():
        monkeypatch.setenv(f"UNLIST_SMTP_{k}", v)
    monkeypatch.setenv("UNLIST_IMAP_HOST", "mail.example")
    monkeypatch.setenv("UNLIST_IMAP_PORT", "abc")
    monkeypatch.setenv("UNLIST_SMTP_PORT", "abc")
    s = run_due(conn, only={"inbox", "send_queue", "score"}, force=True, use_browser=False)
    assert s.ran == ["inbox", "send_queue", "score"] and s.report_path
    assert any("UNLIST_IMAP_PORT" in p for p in s.problems)
    assert any("UNLIST_SMTP_PORT" in p for p in s.problems)
    assert engine.get(conn, r["id"])["state"] == "approved"


def test_inbox_job_reports_messages_it_could_not_flag(conn, data_dir, monkeypatch):
    monkeypatch.setenv("UNLIST_NO_NOTIFY", "1")
    make_subject(conn)
    for k, v in {"HOST": "imap.example", "USER": "u@example.net", "PASSWORD": "pw"}.items():
        monkeypatch.setenv(f"UNLIST_IMAP_{k}", v)
    monkeypatch.setattr(imaplib, "IMAP4_SSL", FakeImap)
    monkeypatch.setattr(FakeImap, "store_status", "NO")
    s = run_due(conn, only={"inbox"}, force=True, use_browser=False)
    assert any("refused to mark message 5 seen" in p for p in s.problems)
    assert any("mail from a@b" in c for c in s.changes)
    # the message is not processed twice while it stays unread
    assert not run_due(conn, only={"inbox"}, force=True, use_browser=False).changes


def test_gone_listing_closes_a_request_left_open(conn, data_dir, fixtures, monkeypatch):
    monkeypatch.setenv("UNLIST_NO_NOTIFY", "1")
    make_subject(conn)
    url = "https://www.spokeo.com/p/1"
    fid = add_finding(conn, url=url)
    r = sent_request(conn, finding_ids=[fid])
    F.set_status(conn, fid, "removed")  # an earlier run stopped right after this
    routes = {
        "https://www.spokeo.com/robots.txt": html_response(b"", status=404),
        url: html_response((fixtures / "listing_gone.html").read_bytes()),
    }
    monkeypatch.setattr("unlist.scanners.brokers.run.make_fetcher", lambda: make_fetcher(routes))
    s = run_due(conn, only={"verify_listings"}, force=True, use_browser=False)
    assert engine.get(conn, r["id"])["state"] == "verified_removed"
    assert not any("is gone" in c for c in s.changes)  # not news: it was already removed


def test_launchd_plist_survives_awkward_paths(data_dir):
    text = monitor.launchd_plist("/Users/me/R&D <unlist>", "/opt/uv & co/uv", 7, 30)
    job = plistlib.loads(text.encode())
    assert job["ProgramArguments"][:3] == [
        "/opt/uv & co/uv",
        "--directory",
        "/Users/me/R&D <unlist>",
    ]
    assert job["StartCalendarInterval"] == {"Hour": 7, "Minute": 30}
    assert job["EnvironmentVariables"]["UNLIST_DATA_DIR"] == str(data_dir)
    assert job["Label"] == monitor.LAUNCHD_LABEL
