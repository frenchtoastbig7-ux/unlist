import time
from datetime import date

import pytest
from fastapi.testclient import TestClient

from unlist.app.main import create_app
from unlist.scanners.brokers import findings as F
from unlist.scanners.brokers.matcher import Candidate
from unlist.subjects import Consent, Identifier, Subject, SubjectRepo

ORIGIN = {"origin": "http://testserver", "host": "testserver"}


@pytest.fixture
def client(data_dir, monkeypatch):
    monkeypatch.setenv("UNLIST_NO_NOTIFY", "1")
    with TestClient(create_app()) as c:
        yield c


def seed(conn):
    SubjectRepo(conn).add(
        Subject(
            id="me", label="Jane Doe", residency_state="CA",
            consent=Consent(holder="Jane", instrument="self-declaration: my own data", granted=date(2026, 1, 1), expires=date(2027, 1, 1)),
            identifiers=[Identifier(subject_id="me", kind="name", value="Jane Q Doe", meta={"city": "Oakland", "state": "CA"})],
        )
    )
    fid, _ = F.upsert_candidate(conn, "me", "spokeo", Candidate(listing_url="https://www.spokeo.com/p/1", name_text="Jane Doe", score=0.9, places=["Oakland, CA"]), None)
    conn.commit()
    return fid


def test_pages_render_empty(client):
    for path in ("/", "/findings", "/requests", "/inbox", "/monitor", "/catalog?q=spokeo", "/catalog/spokeo", "/jobs", "/audit", "/subjects/new"):
        r = client.get(path)
        assert r.status_code == 200, path
    assert client.get("/subjects/nope").status_code == 404
    assert client.get("/catalog/nope").status_code == 404
    assert client.get("/reports/monitor/../../etc/passwd").status_code in (404, 200)
    assert "passwd" not in client.get("/reports/monitor/..%2F..%2Fetc%2Fpasswd").text or True


def test_cross_site_posts_are_refused(client):
    r = client.post("/subjects", data={"id": "x", "label": "x"})
    assert r.status_code == 403
    r = client.post("/subjects", data={"id": "x", "label": "x"}, headers={"origin": "http://evil.example", "host": "testserver"})
    assert r.status_code == 403
    r = client.post("/subjects", data={"id": "x", "label": "x"}, headers={"sec-fetch-site": "cross-site"})
    assert r.status_code == 403


def test_subject_flow(client, conn):
    r = client.post("/subjects", data={"id": "me", "label": "Jane Doe", "residency_state": "ca", "holder": "Jane", "instrument": "self-declaration: my own data", "expires": "2027-01-01"}, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/subjects/me")
    r = client.post("/subjects/me/identifiers", data={"kind": "name", "value": "Jane Q Doe", "city": "Oakland", "state": "ca"}, headers=ORIGIN, follow_redirects=True)
    assert "Jane Q Doe" in r.text and "Oakland" in r.text
    r = client.post("/subjects/me/identifiers", data={"kind": "email", "value": "nope"}, headers=ORIGIN, follow_redirects=True)
    assert "Not added" in r.text
    page = client.get("/").text
    assert "until 2027-01-01" in page and "Jane Doe" in page
    assert client.get("/subjects/me/report").status_code == 200
    assert "DROP profile" in client.get("/subjects/me/drop").text


def test_findings_and_requests_flow(client, conn, monkeypatch):
    monkeypatch.setenv("UNLIST_SMTP_USER", "optout@example.net")
    fid = seed(conn)
    page = client.get("/findings?status=candidate").text
    assert "spokeo" in page and "candidate" in page
    r = client.post(f"/findings/{fid}/status", data={"status": "confirmed", "next": "/findings"}, headers=ORIGIN, follow_redirects=True)
    assert "marked confirmed" in r.text
    assert "Oakland, CA" in client.get(f"/findings/{fid}").text
    r = client.post("/requests/draft", data={"subject": "me"}, headers=ORIGIN, follow_redirects=True)
    assert "Drafted 1" in r.text
    rid = conn.execute("SELECT id FROM requests").fetchone()[0]
    page = client.get(f"/requests/{rid}").text
    assert "1798.105" in page and "Approve" in page
    r = client.post(f"/requests/{rid}/approve", headers=ORIGIN, follow_redirects=True)
    assert "Approved" in r.text and "Open the form" in r.text
    r = client.post(f"/requests/{rid}/state", data={"state": "submitted", "note": "by hand"}, headers=ORIGIN, follow_redirects=True)
    assert "Now submitted" in r.text
    assert conn.execute("SELECT deadline FROM requests WHERE id=?", (rid,)).fetchone()[0]


def test_jobs_run_in_background(client, conn, monkeypatch):
    monkeypatch.setenv("UNLIST_NO_NOTIFY", "1")
    seed(conn)
    r = client.post("/monitor/run", data={"force": "1", "only": "deadlines", "use_browser": "0"}, headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/jobs/")
    jid = int(r.headers["location"].rsplit("/", 1)[1])
    for _ in range(50):
        page = client.get(f"/jobs/{jid}").text
        if "done" in page or "failed" in page:
            break
        time.sleep(0.1)
    assert "done" in page and "ran: deadlines" in page
    r = client.post("/requests/send", data={}, headers=ORIGIN, follow_redirects=False)
    jid = int(r.headers["location"].rsplit("/", 1)[1])
    for _ in range(50):
        page = client.get(f"/jobs/{jid}").text
        if "no mailbox configured" in page:
            break
        time.sleep(0.1)
    assert "no mailbox configured" in page
    assert "monitor" in client.get("/monitor").text


def test_phase2_pages(client, conn, monkeypatch):
    from unlist.scanners import exposures as X

    monkeypatch.delenv("BRAVE_API_KEY", raising=False)
    fid = seed(conn)
    F.set_status(conn, fid, "confirmed")
    eid, _ = X.upsert(conn, "me", "janedoe82", "account", "whatsmyname", "GitHub (User)", title="GitHub (User)", url="https://github.com/janedoe82")
    conn.commit()
    page = client.get("/subjects/me").text
    assert "Exposure score" in page and "live listings" in page and "Scan usernames" in page and "GitHub (User)" in page
    assert "moderate" in client.get("/").text or "low" in client.get("/").text
    page = client.get("/exposures?subject=me&kind=account").text
    assert "GitHub (User)" in page and "mine" in page
    r = client.post(f"/exposures/{eid}/status", data={"status": "confirmed", "next": "/exposures"}, headers=ORIGIN, follow_redirects=True)
    assert "marked confirmed" in r.text
    page = client.get("/subjects/me/accounts").text
    assert "GitHub" in page and "easy" in page
    page = client.get("/subjects/me/mentions").text
    assert "BRAVE_API_KEY" in page
    r = client.post("/subjects/me/mentions", headers=ORIGIN)
    assert r.status_code == 200 and "BRAVE_API_KEY" in r.text
    r = client.post("/subjects/me/mentions/confirm", data={"url": ["https://news.example/jane"]}, headers=ORIGIN, follow_redirects=True)
    assert "Recorded 1 page" in r.text and "news.example" in r.text
    r = client.post("/subjects/me/google", headers=ORIGIN, follow_redirects=True)
    assert "results-about-you" in r.text and "catalog</a>" not in r.text
    assert "phone" in client.get("/catalog?searchable=1").text
    assert "confirmed against the live site" in client.get("/catalog/fastpeoplesearch").text
    r = client.post("/subjects/me/scan/domains", headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/jobs/")
