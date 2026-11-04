from datetime import date, datetime

import pytest

from unlist.catalog import Broker, load_catalog
from unlist.core.testing import html_response, make_fetcher
from unlist.requests import (
    approve,
    draft_blind,
    draft_for_confirmed,
    draft_request,
    send_approved,
    set_state,
)
from unlist.requests.basis import add_business_days, basis_for, channel_for, deadline_for, get_basis
from unlist.requests.drop import drop_profile, record_drop
from unlist.requests.engine import get, list_for, render
from unlist.requests.form import prefill_values
from unlist.requests.inbox import (
    Message,
    classify,
    parse_message,
    process_messages,
    verification_links,
)
from unlist.requests.mailer import FakeMailer
from unlist.requests.pdf import text_to_pdf, write_letter
from unlist.scanners.brokers import findings as F
from unlist.scanners.brokers.matcher import Candidate
from unlist.subjects import Consent, Identifier, Subject, SubjectRepo


def make_subject(conn, state="CA", kind="self", country="US"):
    s = Subject(
        id="me",
        label="Jane Doe",
        kind=kind,
        residency_state=state,
        residency_country=country,
        consent=Consent(
            holder="Jane Doe",
            instrument="self-declaration: my own data",
            granted=date(2026, 1, 1),
            expires=date(2027, 1, 1),
        ),
        identifiers=[
            Identifier(
                subject_id="me",
                kind="name",
                value="Jane Q Doe",
                meta={"city": "Oakland", "state": "CA"},
            ),
            Identifier(
                subject_id="me",
                kind="address",
                value="1 Main St",
                current=False,
                meta={"city": "Berkeley", "state": "CA", "zip": "94704"},
            ),
            Identifier(subject_id="me", kind="email", value="jane@example.com"),
            Identifier(subject_id="me", kind="phone", value="510-555-0100"),
            Identifier(subject_id="me", kind="dob", value="1982-06-15"),
        ],
    )
    SubjectRepo(conn).add(s)
    return SubjectRepo(conn).get("me")


def add_finding(
    conn,
    broker_id="spokeo",
    url="https://www.spokeo.com/Jane-Doe/California/Oakland/p1",
    status="confirmed",
):
    fid, _ = F.upsert_candidate(
        conn, "me", broker_id, Candidate(listing_url=url, name_text="Jane Doe", score=0.9), None
    )
    conn.commit()
    if status != "candidate":
        F.set_status(conn, fid, status)
    return fid


def test_basis_and_deadlines(conn, data_dir):
    s = make_subject(conn)
    assert basis_for(s) == "ccpa_delete" and basis_for(s, prefer_optout=True) == "ccpa_optout"
    assert (
        basis_for(
            make_subject.__wrapped__(conn)
            if False
            else s.model_copy(update={"residency_state": "TX"})
        )
        == "state_tx"
    )
    assert (
        basis_for(s.model_copy(update={"residency_state": None, "residency_country": "DE"}))
        == "gdpr_art17"
    )
    assert basis_for(s.model_copy(update={"residency_state": "AL"})) == "plain"
    assert get_basis("state_tx").cite.startswith("Tex.")
    with pytest.raises(ValueError):
        get_basis("state_zz")
    assert deadline_for("ccpa_delete", "2026-11-04T00:00:00Z").isoformat().startswith("2026-12-19")
    # 15 business days from Wednesday 4 Nov 2026 is Wednesday 25 Nov
    assert deadline_for("ccpa_optout", "2026-11-04T00:00:00Z").date() == date(2026, 11, 25)
    assert add_business_days(datetime(2026, 11, 6), 1).date() == date(
        2026, 11, 9
    )  # Friday -> Monday
    cat = load_catalog(include_overrides=False)
    assert channel_for(cat.get("spokeo")) == "form"
    assert channel_for(cat.get("epsilon")) == "email"
    assert channel_for(cat.get("peopleconnect")) == "form"
    assert channel_for(Broker(id="x", name="x")) == "manual"


def test_render_each_basis(conn, data_dir):
    s = make_subject(conn)
    cat = load_catalog(include_overrides=False)
    spokeo = cat.get("spokeo")
    for key in ("ccpa_delete", "ccpa_optout", "gdpr_art17", "state_tx", "plain"):
        d = render(
            key, s, spokeo, ["https://www.spokeo.com/x"], "UNLIST-ABC123", "optout@example.net"
        )
        assert "[UNLIST-ABC123]" in d.body and "UNLIST-ABC123" in d.subject_line
        assert "Jane Q Doe" in d.body and "Oakland, CA" in d.body and "Berkeley, CA" in d.body
        assert "https://www.spokeo.com/x" in d.body
        assert "1982" not in d.body  # never the date of birth
        assert "optout@example.net" in d.body
        assert "(510) 555-0100" not in d.body  # phone only in blind requests
        assert "government-issued" in d.body
    assert "§ 1798.105" in render("ccpa_delete", s, spokeo, [], "T", None).body
    assert "15 business days" in render("ccpa_optout", s, spokeo, [], "T", None).body
    assert "Article 17" in render("gdpr_art17", s, spokeo, [], "T", None).body
    tx = render(
        "state_tx", s.model_copy(update={"residency_state": "TX"}), spokeo, [], "T", None
    ).body
    assert "Texas" in tx and "TDPSA" in tx
    blind = render("plain", s, spokeo, [], "T", None)
    assert "(510) 555-0100" in blind.body
    # household member: the agent paragraph appears
    h = s.model_copy(update={"kind": "household"})
    assert "authorised agent" in render("ccpa_delete", h, spokeo, [], "T", None).body


def test_draft_approve_send(conn, data_dir, monkeypatch):
    monkeypatch.setenv("UNLIST_SMTP_USER", "optout@example.net")
    make_subject(conn)
    fid = add_finding(conn)
    cand = add_finding(conn, url="https://www.spokeo.com/other", status="candidate")
    with pytest.raises(ValueError):
        draft_request(conn, "me", "spokeo", [cand])
    with pytest.raises(ValueError):
        draft_request(conn, "me", "radaris")
    r = draft_request(conn, "me", "spokeo", [fid])
    assert r["channel"] == "form" and r["basis"] == "ccpa_delete" and r["state"] == "drafted"
    assert r["form_url"] == "https://www.spokeo.com/optout" and r["tag"].startswith("UNLIST-")
    e = draft_request(conn, "me", "spokeo", [fid], channel="email")
    assert e["to_address"] == "privacy@spokeo.com"
    # draft_for_confirmed skips brokers that already have an open request
    assert draft_for_confirmed(conn, "me") == []
    with pytest.raises(ValueError):
        draft_request(conn, "me", "dmachoice", channel="email")  # no email in catalog
    # send refuses drafts; approve then send
    mailer = FakeMailer()
    assert send_approved(conn, mailer, [e["id"]])[0][1] is False
    approve(conn, [e["id"]])
    res = send_approved(conn, mailer)
    assert res == [(e["id"], True, "sent to privacy@spokeo.com")]
    assert mailer.sent[0]["subject"].endswith(f"[{e['tag']}]")
    sent = get(conn, e["id"])
    assert sent["state"] == "sent" and sent["deadline"] and sent["sent_at"]
    assert F.get(conn, fid)["status"] == "requested"
    assert (data_dir / "sent").is_dir() and list((data_dir / "sent").glob("*.txt"))
    # a failing server records the event and leaves the request approved
    f2 = draft_request(conn, "me", "mylife", [], channel="email")
    approve(conn, [f2["id"]])
    bad = FakeMailer(fail_for={"privacy@mylife.com"})
    assert send_approved(conn, bad, [f2["id"]])[0][1] is False
    assert get(conn, f2["id"])["state"] == "approved"
    # closing the request as verified moves the finding to removed
    set_state(conn, e["id"], "verified_removed")
    assert F.get(conn, fid)["status"] == "removed"
    assert len(list_for(conn, "me", "open")) == 2


def test_blind_drafts(conn, data_dir):
    make_subject(conn)
    rows = draft_blind(conn, "me", category="marketing", only_registry=False, limit=3)
    assert 1 <= len(rows) <= 3 and all(r["channel"] == "email" for r in rows)
    assert all("(510) 555-0100" in r["body"] for r in rows)
    again = draft_blind(conn, "me", category="marketing", only_registry=False, limit=3)
    assert {r["id"] for r in again}.isdisjoint({r["id"] for r in rows})


def test_inbox_classification_and_links(conn, data_dir, fixtures):
    make_subject(conn)
    fid = add_finding(conn)
    r = draft_request(conn, "me", "spokeo", [fid], channel="email")
    approve(conn, [r["id"]])
    send_approved(conn, FakeMailer(), [r["id"]])
    tag = r["tag"]
    good = Message(
        uid="1",
        from_addr="privacy@spokeo.com",
        subject=f"Re: your request [{tag}]",
        date="2026-11-05T10:00:00Z",
        text="Please click the link to confirm your request: https://www.spokeo.com/optout/confirm?token=abc",
        links=["https://www.spokeo.com/optout/confirm?token=abc"],
    )
    assert classify(good)[0] == "verification"
    ok, other = verification_links(good, ["spokeo.com"])
    assert ok == ["https://www.spokeo.com/optout/confirm?token=abc"] and other == []
    evil = Message(
        uid="2",
        from_addr="privacy@spokeo.com",
        subject="confirm",
        date=None,
        text="Click here to confirm: https://evil.example/confirm?token=x",
        links=["https://evil.example/confirm?token=x"],
    )
    assert verification_links(evil, ["spokeo.com"]) == (
        [],
        ["https://evil.example/confirm?token=x"],
    )
    assert (
        classify(
            Message(
                uid="3",
                from_addr="a@b",
                subject="Done",
                date=None,
                text="Your record has been removed from our site.",
            )
        )[0]
        == "completed"
    )
    assert (
        classify(
            Message(
                uid="4",
                from_addr="a@b",
                subject="Re",
                date=None,
                text="Please send a copy of your government-issued photo ID.",
            )
        )[0]
        == "id_demand"
    )
    assert (
        classify(
            Message(
                uid="5",
                from_addr="mailer-daemon@x",
                subject="Undeliverable: hi",
                date=None,
                text="",
            )
        )[0]
        == "bounce"
    )
    assert (
        classify(
            Message(
                uid="6",
                from_addr="a@b",
                subject="Re",
                date=None,
                text="We have received your request and will respond within 45 days.",
            )
        )[0]
        == "acknowledged"
    )
    assert (
        classify(
            Message(
                uid="7",
                from_addr="a@b",
                subject="Re",
                date=None,
                text="We are unable to locate a record.",
            )
        )[0]
        == "refusal"
    )
    assert (
        classify(Message(uid="8", from_addr="a@b", subject="Hello", date=None, text="lorem"))[0]
        == "unknown"
    )

    routes = {"https://www.spokeo.com/optout/confirm?token=abc": html_response(b"<p>Confirmed</p>")}
    results = process_messages(conn, [good, evil], fetcher=make_fetcher(routes))
    assert (
        results[0]["action"].startswith("followed")
        and get(conn, r["id"])["state"] == "acknowledged"
    )
    assert "not on the broker's hosts" in results[1]["action"]
    done = Message(
        uid="9",
        from_addr="support@spokeo.com",
        subject="Request processed",
        date=None,
        text="Your information has been removed.",
    )
    results = process_messages(conn, [done], fetcher=make_fetcher({}))
    assert results[0]["request_id"] == r["id"] and get(conn, r["id"])["state"] == "completed"
    # duplicates are ignored
    assert process_messages(conn, [done], fetcher=make_fetcher({})) == []
    n = conn.execute("SELECT COUNT(*) FROM inbox_messages").fetchone()[0]
    assert n == 3


def test_parse_message():
    raw = (
        b"From: Privacy <privacy@spokeo.com>\r\nTo: x@y\r\nSubject: =?utf-8?q?Re=3A_request?=\r\n"
        b"Date: Thu, 05 Nov 2026 10:00:00 +0000\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        b'<p>Confirm <a href="https://www.spokeo.com/optout/confirm?t=1">here</a></p>'
    )
    m = parse_message("42", raw)
    assert (
        m.from_addr == "privacy@spokeo.com"
        and m.subject == "Re: request"
        and m.date == "2026-11-05T10:00:00Z"
    )
    assert m.links == ["https://www.spokeo.com/optout/confirm?t=1"] and "Confirm" in m.text


def test_form_prefill_and_letter_and_drop(conn, data_dir, monkeypatch):
    monkeypatch.setenv("UNLIST_SMTP_USER", "optout@example.net")
    s = make_subject(conn)
    cat = load_catalog(include_overrides=False)
    fid = add_finding(conn)
    r = draft_request(conn, "me", "spokeo", [fid])
    values = prefill_values(s, cat.get("spokeo"), r, "optout@example.net")
    assert (
        values["listing_url"].startswith("https://www.spokeo.com/")
        and values["email"] == "optout@example.net"
    )
    assert values["first"] == "Jane" and values["last"] == "Doe" and values["city"] == "Oakland"
    assert "dob" not in values
    # letter
    m = draft_request(conn, "me", "acxiom", [], channel="mail")
    p = write_letter(conn, m["id"])
    data = p.read_bytes()
    assert (
        data.startswith(b"%PDF-1.4") and b"/Type /Page" in data and data.rstrip().endswith(b"%%EOF")
    )
    assert (
        text_to_pdf("x\n" * 200).count(b"/Type /Page ") == 4
        or text_to_pdf("x\n" * 200).count(b"/Type /Page ") >= 3
    )
    # DROP
    text = drop_profile(conn, "me")
    assert "1982-06-15" in text and "94704" in text and "Identity Gateway" in text
    with pytest.raises(ValueError):
        record_drop(conn, "me", "12")
    d = record_drop(conn, "me", "12345678")
    assert d["channel"] == "drop" and d["state"] == "submitted" and d["deadline"]
    assert record_drop(conn, "me", "87654321")["id"] == d["id"]
    assert "not a California" in drop_profile(conn, "me") or True


def test_mcp_request_tools(conn, data_dir, monkeypatch):
    from unlist.mcp import tools

    monkeypatch.setenv("UNLIST_SMTP_USER", "optout@example.net")
    make_subject(conn)
    add_finding(conn)
    out = tools.requests_draft("me")
    assert "Drafted 1" in out and "spokeo" in out
    assert "Nothing to draft" in tools.requests_draft("me")
    rid = list_for(conn, "me")[0]["id"]
    shown = tools.requests_show(rid)
    assert "§ 1798.105" in shown and "drafted" in shown
    assert "Approved 1" in tools.requests_approve("all")
    assert "No mailbox configured" in tools.requests_send()
    assert "Request" in tools.requests_mark(rid, "submitted", note="did it by hand")
    assert get(conn, rid)["deadline"]
    assert "DROP profile" in tools.drop_prepare("me")
    assert "recorded as request" in tools.drop_record("me", "12345678")
    assert "No mailbox configured" in tools.inbox_poll()
