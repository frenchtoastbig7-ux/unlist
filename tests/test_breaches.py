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
        f"https://api.xposedornot.com/v1/breach-analytics?email={Q}": json_response((fixtures / "xon_analytics.json").read_bytes()),
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
    assert res.new_hits == 1 and set(res.skipped) == {"hibp-stealer"}
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


def test_pastes_stealer_and_plan(conn, fixtures, data_dir):
    seed(conn)
    base = routes(fixtures)
    base["https://haveibeenpwned.com/api/v3/subscription/status"] = json_response('{"SubscriptionName":"Pro 1","Rpm":1000,"SubscribedUntil":"2027-01-01T00:00:00Z"}')
    base[f"https://haveibeenpwned.com/api/v3/pasteaccount/{Q}"] = json_response((fixtures / "hibp_pastes.json").read_bytes())
    base[f"https://haveibeenpwned.com/api/v3/stealerlogsbyemail/{Q}"] = json_response('["netflix.com","bank.example"]')
    f = make_fetcher(base)
    res = scan_breaches(conn, "me", fetcher=f, hibp_api_key="k", sources=("hibp",))
    assert res.plan["name"] == "Pro 1" and not res.skipped
    assert res.new_by_kind == {"breach": 1, "paste": 2, "stealer": 2}
    pastes = hits_for(conn, "me", kind="paste")
    assert {p["breach_name"] for p in pastes} == {"Pastebin:8Q0BvKD8", "Pastie:7152479"}
    assert pastes[0]["breach_date"] and pastes[0]["pwn_count"]
    assert {s["domain"] for s in hits_for(conn, "me", kind="stealer")} == {"netflix.com", "bank.example"}
    assert f.limiter.host_intervals["haveibeenpwned.com"] < 1  # paced to the plan's rate
    # a Core plan: pastes yes, stealer logs skipped without calling the endpoint
    conn.execute("DELETE FROM breach_hits")
    base["https://haveibeenpwned.com/api/v3/subscription/status"] = json_response('{"SubscriptionName":"Core 1","Rpm":10}')
    calls = []
    base[f"https://haveibeenpwned.com/api/v3/stealerlogsbyemail/{Q}"] = lambda req: calls.append(1) or httpx.Response(403)
    res = scan_breaches(conn, "me", fetcher=make_fetcher(base), hibp_api_key="k", sources=("hibp",))
    assert "hibp-stealer" in res.skipped and calls == [] and res.new_by_kind == {"breach": 1, "paste": 2}


def test_xon_analytics_metrics_and_fallback(conn, fixtures, data_dir):
    from unlist.scanners.breaches.run import metrics_for

    seed(conn)
    res = scan_breaches(conn, "me", fetcher=make_fetcher(routes(fixtures, with_key=False)), hibp_api_key="", sources=("xposedornot",))
    assert res.new_hits == 2
    m = metrics_for(conn, "me")[("xposedornot", f"risk:{EMAIL}")]
    assert m["risk_label"] == "Medium" and m["risk_score"] == 45 and m["pastes"] == 2
    adobe = next(h for h in hits_for(conn, "me") if h["breach_name"] == "Adobe")
    assert adobe["breach_date"] == "2013-10-04" and adobe["pwn_count"] == 152445165
    # analytics rate-limited: the plain check still answers
    conn.execute("DELETE FROM breach_hits")
    r = routes(fixtures, with_key=False)
    r[f"https://api.xposedornot.com/v1/breach-analytics?email={Q}"] = httpx.Response(429)
    res = scan_breaches(conn, "me", fetcher=make_fetcher(r), hibp_api_key="", sources=("xposedornot",))
    assert res.new_hits == 2 and not res.errors


def test_username_and_phone_lookups_redact_values(conn, fixtures, data_dir):
    seed(conn)
    repo = SubjectRepo(conn)
    repo.add_identifier("me", Identifier(subject_id="me", kind="username", value="janedoe82"))
    repo.add_identifier("me", Identifier(subject_id="me", kind="phone", value="(510) 555-0100"))
    base = routes(fixtures, with_key=False)
    base["https://leakcheck.io/api/public?check=janedoe82"] = json_response('{"success":true,"found":1,"fields":["username","password"],"sources":[{"name":"GameForum","date":"2018-03"}]}')
    base["https://leakcheck.io/api/v2/query/5105550100?type=phone"] = json_response((fixtures / "leakcheck_pro_phone.json").read_bytes())
    # without a Pro key the phone is not queried and the reason is stated
    res = scan_breaches(conn, "me", fetcher=make_fetcher(base), hibp_api_key="", leakcheck_api_key="", sources=("leakcheck",))
    assert "leakcheck-phone" in res.skipped and res.usernames == ["janedoe82"]
    assert any(h["identifier_value"] == "janedoe82" and h["breach_name"] == "GameForum" for h in hits_for(conn, "me"))
    # with a key: field names kept, values gone from the database, the raw file and the audit log
    res = scan_breaches(conn, "me", fetcher=make_fetcher(base), hibp_api_key="", leakcheck_api_key="pro", sources=("leakcheck",))
    phone_hits = [h for h in hits_for(conn, "me") if h["source"] == "leakcheck-pro"]
    assert {h["breach_name"] for h in phone_hits} == {"SomeShop", "TelcoDump"}
    shop = next(h for h in phone_hits if h["breach_name"] == "SomeShop")
    assert {"password", "phone", "email"} <= set(json.loads(shop["data_classes_json"]))
    secret = "hunter2-SECRET"
    dump = "\n".join(str(tuple(r)) for t in ("breach_hits", "captures", "scan_runs") for r in conn.execute(f"SELECT * FROM {t}"))
    assert secret not in dump and "1 Main St" not in dump
    for p in data_dir.rglob("*"):
        if p.is_file() and p.suffix in (".json", ".jsonl", ".txt", ".bin"):
            assert secret not in p.read_text(errors="replace"), p
    stored = [p for p in (data_dir / "raw").rglob("*.json") if "redacted by unlist" in p.read_text()]
    assert stored and "SomeShop" in stored[0].read_text()
