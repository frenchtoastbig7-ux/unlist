import hashlib
import json
from datetime import date

import httpx
import pytest

from unlist.core.testing import json_response, make_fetcher
from unlist.scanners.breaches import scan_breaches
from unlist.scanners.breaches.hibp import HibpClient
from unlist.scanners.breaches.run import hits_for, record_password_check
from unlist.subjects import Consent, ConsentError, Identifier, Subject, SubjectRepo

EMAIL = "jane@example.com"
Q = "jane%40example.com"


def seed(conn, consent=True):
    repo = SubjectRepo(conn)
    s = Subject(
        id="me",
        label="Jane",
        residency_state="CA",
        consent=Consent(
            holder="Jane",
            instrument="self-declaration: my own data",
            granted=date(2026, 1, 1),
            expires=date(2027, 1, 1) if consent else date(2026, 2, 1),
        ),
        identifiers=[
            Identifier(subject_id="me", kind="email", value=EMAIL),
            Identifier(subject_id="me", kind="email", value="old@example.com", current=False),
        ],
    )
    repo.add(s)


def routes(fixtures, with_key=True):
    r = {
        "https://haveibeenpwned.com/api/v3/breaches": json_response((fixtures / "hibp_breaches.json").read_bytes()),
        f"https://leakcheck.io/api/public?check={Q}": json_response((fixtures / "leakcheck_public.json").read_bytes()),
        f"https://api.xposedornot.com/v1/check-email/{Q}": json_response((fixtures / "xon_check.json").read_bytes()),
    }
    if with_key:
        r[f"https://haveibeenpwned.com/api/v3/breachedaccount/{Q}?truncateResponse=false"] = json_response(
            (fixtures / "hibp_account.json").read_bytes()
        )
    return r


def test_scan_without_key_skips_hibp_lookups(conn, fixtures, data_dir):
    seed(conn)
    f = make_fetcher(routes(fixtures, with_key=False))
    res = scan_breaches(conn, "me", fetcher=f, hibp_api_key="")
    assert res.emails == [EMAIL]  # the past address is not queried
    assert "hibp" in res.skipped
    assert res.new_hits == 4  # LinkedIn + Some Forum (leakcheck), Adobe + Collection1 (xon)
    hits = hits_for(conn, "me")
    names = {(h["source"], h["breach_name"]) for h in hits}
    assert ("xposedornot", "Adobe") in names and ("leakcheck", "LinkedIn") in names
    adobe = next(h for h in hits if h["breach_name"] == "Adobe")
    assert adobe["breach_date"] == "2013-10-04"  # filled from the HIBP catalog
    assert "Passwords" in json.loads(adobe["data_classes_json"])
    # evidence was kept for every API answer
    n = conn.execute("SELECT COUNT(*) FROM captures WHERE tool='breaches'").fetchone()[0]
    assert n == 3  # catalog + two lookups
    linkedin = next(h for h in hits if h["breach_name"] == "LinkedIn")
    assert linkedin["breach_date"] == "2012-05-05"  # HIBP's full date beats LeakCheck's month
    # second run: nothing new
    res2 = scan_breaches(conn, "me", fetcher=make_fetcher(routes(fixtures, with_key=False)), hibp_api_key="")
    assert res2.new_hits == 0 and res2.seen_hits == 4


def test_scan_with_key_uses_breachedaccount(conn, fixtures, data_dir):
    seed(conn)
    res = scan_breaches(conn, "me", fetcher=make_fetcher(routes(fixtures)), hibp_api_key="k", sources=("hibp",))
    assert res.new_hits == 1 and not res.skipped
    assert hits_for(conn, "me")[0]["source"] == "hibp"


def test_hibp_404_means_clean_and_401_is_reported(conn, fixtures, data_dir):
    seed(conn)
    r = routes(fixtures)
    r[f"https://haveibeenpwned.com/api/v3/breachedaccount/{Q}?truncateResponse=false"] = httpx.Response(404)
    res = scan_breaches(conn, "me", fetcher=make_fetcher(r), hibp_api_key="k", sources=("hibp",))
    assert res.new_hits == 0 and not res.errors
    r[f"https://haveibeenpwned.com/api/v3/breachedaccount/{Q}?truncateResponse=false"] = httpx.Response(401, content=b"bad key")
    res = scan_breaches(conn, "me", fetcher=make_fetcher(r), hibp_api_key="k", sources=("hibp",))
    assert res.skipped.get("hibp", "").startswith("rejected")
    kinds = {row[0] for row in conn.execute("SELECT kind FROM captures WHERE status=401")}
    assert kinds == {"refusal"}


def test_consent_gate(conn, fixtures, data_dir):
    seed(conn, consent=False)
    with pytest.raises(ConsentError):
        scan_breaches(conn, "me", fetcher=make_fetcher(routes(fixtures)))
    assert conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0] == 0


def test_pwned_password_k_anonymity(conn, data_dir):
    pw = "correct horse battery staple"
    digest = hashlib.sha1(pw.encode()).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    seen = {}

    def page(request):
        seen["url"] = str(request.url)
        seen["padding"] = request.headers.get("add-padding")
        body = f"0000000000000000000000000000000000A:0\n{suffix}:12345\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:3\n"
        return httpx.Response(200, content=body.encode())

    f = make_fetcher({f"https://api.pwnedpasswords.com/range/{prefix}": page})
    count = record_password_check(conn, "test label", pw, fetcher=f)
    assert count == 12345
    assert seen["url"].endswith(prefix) and suffix not in seen["url"]
    assert seen["padding"] == "true"
    row = conn.execute("SELECT * FROM password_checks").fetchone()
    assert row["label"] == "test label" and row["pwned_count"] == 12345
    assert pw not in (data_dir / "audit.jsonl").read_text()
    # a hash not in the range -> 0
    _, c2 = HibpClient(f).pwned_password_count("something-else-entirely")
    assert c2 is None or c2 == 0


def test_report_and_mcp_tools(conn, fixtures, data_dir, monkeypatch):
    from unlist.mcp import tools

    seed(conn)
    monkeypatch.setattr("unlist.scanners.breaches.run.make_fetcher", lambda: make_fetcher(routes(fixtures, with_key=False)))
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    out = tools.scan_breaches("me", sources="leakcheck,xposedornot")
    assert "4 new" in out and "LinkedIn" in out
    assert "Unknown sources" in tools.scan_breaches("me", sources="nope")
    listing = tools.breaches_list("me", since="2030-01-01")
    assert "No breach hits" in listing
    rep = tools.report_exposure("me")
    assert "## Breaches" in rep and "Adobe" in rep and "Act on these" in rep and "Written to" in rep
    assert "No password checks" in tools.password_checks_list()
