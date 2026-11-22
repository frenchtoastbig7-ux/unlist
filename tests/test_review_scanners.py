"""Regression tests for the scanner fixes made after the automated review."""

import hashlib
import json
import sqlite3
from datetime import date
from types import SimpleNamespace
from urllib.parse import quote

import httpx
import pytest

from unlist.core.testing import html_response, json_response, make_fetcher
from unlist.scanners import exposures as X
from unlist.scanners.breaches import detail as D
from unlist.scanners.breaches import scan_breaches, xposedornot
from unlist.scanners.breaches.hibp import Breach, HibpClient
from unlist.scanners.breaches.leakcheck import LeakCheckClient, LeakCheckProClient, redact
from unlist.scanners.breaches.run import _upsert_hit, hits_for, metrics_for, record_password_check
from unlist.scanners.breaches.xposedornot import XposedOrNotClient, parse_analytics
from unlist.scanners.domains import assess_dmarc, assess_spf, scan_domains
from unlist.scanners.evidence import record_browser
from unlist.scanners.mentions import build_queries, confirm_mention, scan_mentions, web_host
from unlist.scanners.usernames import scan_usernames
from unlist.scanners.usernames.wmn import DATA_URL, cache_path, check_site, load_sites
from unlist.subjects import Consent, Identifier, Subject, SubjectRepo

EMAIL = "jane@example.com"
Q = "jane%40example.com"
CATALOG = "https://haveibeenpwned.com/api/v3/breaches"
LEAK = f"https://leakcheck.io/api/public?check={Q}"
ANALYTICS = f"https://api.xposedornot.com/v1/breach-analytics?email={Q}"
CHECK = f"https://api.xposedornot.com/v1/check-email/{Q}"
PRO = "https://leakcheck.io/api/v2/query/"


def seed(conn, *extra):
    SubjectRepo(conn).add(
        Subject(
            id="me",
            label="Jane Doe",
            residency_state="CA",
            consent=Consent(
                holder="Jane",
                instrument="self-declaration: my own data",
                granted=date(2026, 1, 1),
                expires=date(2027, 1, 1),
            ),
            identifiers=[
                Identifier(subject_id="me", kind="name", value="Jane Doe"),
                Identifier(subject_id="me", kind="email", value=EMAIL),
                *extra,
            ],
        )
    )


def ident(kind, value):
    return Identifier(subject_id="me", kind=kind, value=value)


def catalog(*entries):
    return json_response(json.dumps(list(entries)))


def hit_row(conn, name, source="leakcheck", breach_date=None, domain=None, classes=(), capture=None):
    conn.execute(
        "INSERT INTO breach_hits(subject_id, identifier_value, source, breach_name, title, domain, "
        "breach_date, data_classes_json, capture_id, first_seen, last_seen, kind) "
        "VALUES ('me',?,?,?,?,?,?,?,?,'2026-01-01','2026-01-01','breach')",
        (EMAIL, source, name, name, domain, breach_date, json.dumps(list(classes)), capture),
    )
    conn.commit()


# breach detail ---------------------------------------------------------------------------


def test_failed_evidence_read_is_not_cached(conn, fixtures, data_dir):  # 30
    seed(conn)
    scan_breaches(
        conn,
        "me",
        fetcher=make_fetcher({CATALOG: json_response((fixtures / "hibp_breaches.json").read_bytes())}),
        hibp_api_key="",
        sources=(),
    )
    raw = data_dir / conn.execute("SELECT raw_path FROM captures").fetchone()["raw_path"]
    hidden = raw.with_suffix(".hidden")
    raw.rename(hidden)  # the file cannot be read for now
    assert len(D.hibp_index(conn)) == 0
    hidden.rename(raw)
    assert len(D.hibp_index(conn)) == 3  # the same process reads it once it is back
    raw.rename(hidden)
    assert len(D.hibp_index(conn)) == 3  # a successful read stays cached


def test_exact_name_with_conflicting_date_is_only_possible():  # 31
    idx = D.HibpIndex([{"Name": "Dropbox", "Title": "Dropbox", "BreachDate": "2012-07-01"}])
    assert idx.match("Dropbox", "", "2012-07").confident
    assert idx.match("Dropbox", "", "2013").confident  # a year either side still agrees
    assert idx.match("Dropbox", "", None).confident
    far = idx.match("Dropbox", "", "2024-05")
    assert far.entry["Name"] == "Dropbox" and far.basis == "name" and not far.confident


def test_conflicting_dates_keep_two_incidents_apart(conn, data_dir):  # 31, 39
    seed(conn)
    routes = {
        CATALOG: catalog(
            {"Name": "Dropbox", "Title": "Dropbox", "Domain": "dropbox.com",
             "BreachDate": "2012-07-01", "DataClasses": ["Email addresses", "Passwords"]},
            {"Name": "LinkedIn", "Title": "LinkedIn", "Domain": "linkedin.com",
             "BreachDate": "2012-05-05", "DataClasses": ["Email addresses", "Passwords"]},
        ),
        LEAK: json_response(json.dumps({
            "success": True, "found": 2, "fields": ["email"],
            "sources": [{"name": "Dropbox", "date": "2024-05"}, {"name": "LinkedIn", "date": "2012-05"}],
        })),
    }  # fmt: skip
    scan_breaches(conn, "me", fetcher=make_fetcher(routes), hibp_api_key="", sources=("leakcheck",))
    rows = {h["breach_name"]: h for h in hits_for(conn, "me")}
    # years apart: the provider's date is kept and nothing is taken from the catalog
    assert rows["Dropbox"]["breach_date"] == "2024-05" and rows["Dropbox"]["domain"] is None
    assert json.loads(rows["Dropbox"]["data_classes_json"]) == ["email"]
    # compatible dates are still enriched
    assert rows["LinkedIn"]["breach_date"] == "2012-05-05"
    assert "Passwords" in json.loads(rows["LinkedIn"]["data_classes_json"])
    groups = {g.title: g for g in D.groups_for(conn, "me")}
    dropbox = groups["Dropbox"]
    assert dropbox.hibp is None and dropbox.possible_hibp["Name"] == "Dropbox"
    assert dropbox.date == "2024-05" and dropbox.classes == []
    assert groups["LinkedIn"].hibp["Name"] == "LinkedIn"


def test_distinct_domains_are_not_merged_without_a_match(conn, data_dir):  # 32
    seed(conn)
    hit_row(conn, "service.com", breach_date="2020-03")
    hit_row(conn, "service.net", source="leakcheck-pro", breach_date="2020-09")
    groups = D.groups_for(conn, "me")
    assert sorted(g.domain for g in groups) == ["service.com", "service.net"]
    assert all(len(g.hit_ids) == 1 for g in groups)
    # a bare name cannot say which of the two it is, so it stays on its own
    hit_row(conn, "Service", source="xposedornot", breach_date="2020")
    assert len(D.groups_for(conn, "me")) == 3


def test_bare_name_joins_the_only_domain_with_that_name(conn, data_dir):  # 32
    seed(conn)
    hit_row(conn, "Chegg.com", breach_date="2018-04")
    hit_row(conn, "Chegg", source="xposedornot", breach_date="2018", classes=["Passwords"])
    hit_row(conn, "Chegg", source="leakcheck-pro", breach_date="2021")  # another year
    groups = D.groups_for(conn, "me")
    assert sorted(len(g.hit_ids) for g in groups) == [1, 2]
    merged = next(g for g in groups if len(g.hit_ids) == 2)
    assert merged.domain == "chegg.com" and set(merged.sources) == {"leakcheck", "xposedornot"}


def test_stored_hibp_classes_stand_in_for_a_missing_catalog(conn, data_dir):  # 33
    seed(conn)
    hit_row(conn, "Adobe", source="hibp", breach_date="2013-10-04", classes=["Passwords", "Usernames"])
    (g,) = D.groups_for(conn, "me")  # no breach list is stored at all
    assert g.hibp is None
    assert g.classes_by_source == [("Have I Been Pwned", ["Passwords", "Usernames"])]
    assert any("Change the password" in a for a in g.advice)


def test_catalog_entry_is_preferred_over_stored_classes(conn, data_dir):  # 33
    seed(conn)
    entry = {"Name": "Adobe", "Title": "Adobe", "BreachDate": "2013-10-04", "DataClasses": ["Passwords"]}
    scan_breaches(
        conn, "me", fetcher=make_fetcher({CATALOG: catalog(entry)}), hibp_api_key="", sources=()
    )
    hit_row(conn, "Adobe", source="hibp", breach_date="2013-10-04", classes=["Passwords", "Stale"])
    (g,) = D.groups_for(conn, "me")
    assert g.hibp and g.classes_by_source == [("Have I Been Pwned", ["Passwords"])]


# HIBP ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [b"", b"<html><body>Just a moment...</body></html>", b"not-a-range:1\n", b"0" * 35 + b":x\n"],
)
def test_unreadable_password_range_is_not_a_zero(conn, data_dir, body):  # 34
    pw = "correct horse battery staple"
    prefix = hashlib.sha1(pw.encode()).hexdigest().upper()[:5]
    f = make_fetcher({f"https://api.pwnedpasswords.com/range/{prefix}": httpx.Response(200, content=body)})
    assert HibpClient(f).pwned_password_count(pw)[1] is None
    assert record_password_check(conn, "label", pw, fetcher=f) is None
    assert conn.execute("SELECT COUNT(*) FROM password_checks").fetchone()[0] == 0


def test_valid_password_range_without_the_suffix_is_zero(conn, data_dir):  # 34
    pw = "correct horse battery staple"
    prefix = hashlib.sha1(pw.encode()).hexdigest().upper()[:5]
    body = ("0" * 34 + "A:3\r\n" + "F" * 35 + ":0\r\n").encode()
    f = make_fetcher({f"https://api.pwnedpasswords.com/range/{prefix}": httpx.Response(200, content=body)})
    assert record_password_check(conn, "label", pw, fetcher=f) == 0


def test_catalog_request_carries_no_api_key(conn, fixtures, data_dir):  # 77
    seed(conn)
    seen = {}

    def breaches(request):
        seen["catalog"] = request.headers.get("hibp-api-key")
        return json_response((fixtures / "hibp_breaches.json").read_bytes())

    def account(request):
        seen["account"] = request.headers.get("hibp-api-key")
        return httpx.Response(404)

    routes = {
        CATALOG: breaches,
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{Q}?truncateResponse=false": account,
    }
    scan_breaches(conn, "me", fetcher=make_fetcher(routes), hibp_api_key="k", sources=("hibp",))
    assert seen == {"catalog": None, "account": "k"}


# LeakCheck -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        "null",
        "[]",
        '"text"',
        '{"success":true,"sources":"LinkedIn"}',
        '{"success":true,"sources":["LinkedIn"]}',
        '{"success":true,"sources":[{"name":"A"},null]}',
        '{"success":true,"fields":"email","sources":[]}',
    ],
)
def test_leakcheck_rejects_unusable_shapes(body):  # 35
    f = make_fetcher({LEAK: json_response(body), f"{PRO}x?type=email": json_response(body)})
    assert LeakCheckClient(f).check(EMAIL)[1] is None


@pytest.mark.parametrize(
    "body",
    ["null", "[]", '{"success":true,"result":"x"}', '{"success":true,"result":[null]}',
     '{"success":true,"result":[{"source":{"name":"A"}},"x"]}'],
)  # fmt: skip
def test_leakcheck_pro_rejects_unusable_shapes(body):  # 35
    f = make_fetcher({f"{PRO}x?type=email": json_response(body)})
    assert LeakCheckProClient(f, "k").query("x", "email")[1] is None


def test_leakcheck_no_match_answers_stay_empty_lists():  # 35
    body = '{"success":false,"error":"Not found"}'
    f = make_fetcher({LEAK: json_response(body), f"{PRO}x?type=email": json_response(body)})
    assert LeakCheckClient(f).check(EMAIL)[1] == []
    assert LeakCheckProClient(f, "k").query("x", "email")[1] == []
    f = make_fetcher({LEAK: json_response('{"success":true,"found":0,"sources":[]}')})
    assert LeakCheckClient(f).check(EMAIL)[1] == []
    # one source with a non-string source inside its own object is still tolerated
    f = make_fetcher({f"{PRO}x?type=email": json_response('{"success":true,"result":[{"source":7,"zip":1}]}')})
    (b,) = LeakCheckProClient(f, "k").query("x", "email")[1]
    assert b.name == "Unknown source" and b.data_classes == ["zip"]


SECRETS = {
    "success": True,
    "found": 1,
    "quota": 398,
    "debug": {"echo": "hunter2-TOP", "pin": 424242},
    "result": [
        {
            "email": "jane@example.com",
            "pin": 918273,
            "balance": 1234.56,
            "password": "hunter2-SECRET",
            "profile": {"ssn": "078-05-1120", "answers": ["mothers-maiden-NAME", 55512]},
            "tokens": [777001, {"otp": 880022}],
            "source": {
                "name": "SomeShop",
                "breach_date": "2021-06",
                "unverified": 0,
                "passwordless": 1,
                "note": "contact-LEAKED",
                "records": 31337,
            },
            "fields": ["email", "password", {"nested": "field-VALUE"}, 606060],
        }
    ],
}
LEAKED = ("hunter2", "424242", "918273", "1234.56", "078-05-1120", "mothers-maiden", "55512",
          "777001", "880022", "contact-LEAKED", "31337", "field-VALUE", "606060", "jane@example", "398")  # fmt: skip


def test_redact_builds_evidence_from_an_allow_list():  # 36
    out = redact(json.dumps(SECRETS).encode())
    text = out.decode()
    for value in LEAKED:
        assert value not in text, value
    assert json.loads(out) == {
        "redacted": "[redacted by unlist]",
        "success": True,
        "result": [
            {
                "source": {"name": "SomeShop", "breach_date": "2021-06", "unverified": 0, "passwordless": 1},
                "fields": ["balance", "email", "password", "pin", "profile", "tokens"],
            }
        ],
    }


@pytest.mark.parametrize(
    "body",
    [
        b"not json at all hunter2-SECRET",
        b'"hunter2-SECRET"',
        b"[918273]",
        b'{"success":false,"error":"no plan for hunter2-SECRET","pin":918273}',
        b'{"success":true,"result":{"pin":918273,"password":"hunter2-SECRET"}}',
        b'{"result":[{"pin":918273}],"password":"hunter2-SECRET"}',
    ],
)
def test_redact_keeps_no_value_from_an_unknown_or_error_answer(body):  # 36
    out = redact(body).decode()
    assert "hunter2" not in out and "918273" not in out
    assert "redacted" in json.loads(out)


def test_non_string_leaked_values_never_reach_disk(conn, data_dir):  # 36
    seed(conn, ident("phone", "(510) 555-0100"))
    answer = json.loads(json.dumps(SECRETS))
    answer["result"][0]["phone"] = 5105550100  # a number, as some dumps hold it
    routes = {
        CATALOG: catalog(),
        LEAK: json_response('{"success":false,"error":"Not found"}'),
        f"{PRO}5105550100?type=phone": json_response(json.dumps(answer)),
    }
    res = scan_breaches(
        conn, "me", fetcher=make_fetcher(routes), hibp_api_key="", leakcheck_api_key="pro",
        sources=("leakcheck",),
    )  # fmt: skip
    (hit,) = hits_for(conn, "me")
    assert hit["breach_name"] == "SomeShop" and hit["identifier_value"] == "15105550100"
    assert "pin" in json.loads(hit["data_classes_json"]) and not res.errors
    dump = "\n".join(
        str(tuple(r))
        for t in ("breach_hits", "captures", "scan_runs", "subject_metrics")
        for r in conn.execute(f"SELECT * FROM {t}")
    )
    files = [p for p in data_dir.rglob("*") if p.is_file() and p.suffix in (".json", ".jsonl", ".txt", ".bin")]
    assert any("SomeShop" in p.read_text() for p in files)
    for value in [v for v in LEAKED if v not in ("jane@example", "398")]:  # her own address, a year
        assert value not in dump, value
        for p in files:
            assert value not in p.read_text(errors="replace"), (value, p)


def test_phone_hits_must_report_the_full_number(conn, data_dir):  # 78
    seed(conn, ident("phone", "+44 7911 123456"), ident("phone", "510-555-0100"))

    def item(source, **fields):
        return {**fields, "source": {"name": source, "breach_date": "2022-01"}}

    uk = {"success": True, "result": [
        item("Mine", phone="+44 7911 123456"),
        item("OtherCountry", phone="33 7911 123456"),  # the same tail, another number
        item("NoPhone", email="x@example.com"),
    ]}  # fmt: skip
    us = {"success": True, "result": [
        item("MineUS", phone="(510) 555-0100"),
        item("MineUS11", phone=15105550100),
        item("Elsewhere", phone="445105550100"),
    ]}  # fmt: skip
    asked = []

    def answer(body):
        def handler(request):
            asked.append(str(request.url))
            return json_response(json.dumps(body))

        return handler

    routes = {
        CATALOG: catalog(),
        LEAK: json_response('{"success":false,"error":"Not found"}'),
        f"{PRO}447911123456?type=phone": answer(uk),
        f"{PRO}5105550100?type=phone": answer(us),
    }
    res = scan_breaches(
        conn, "me", fetcher=make_fetcher(routes), hibp_api_key="", leakcheck_api_key="pro",
        sources=("leakcheck",),
    )  # fmt: skip
    # an international number is asked about in full, never by its last ten digits
    assert sorted(asked) == sorted([f"{PRO}447911123456?type=phone", f"{PRO}5105550100?type=phone"])
    stored = {(h["identifier_value"], h["breach_name"]) for h in hits_for(conn, "me")}
    assert stored == {
        ("447911123456", "Mine"),
        ("15105550100", "MineUS"),
        ("15105550100", "MineUS11"),
    }
    assert res.skipped["leakcheck-phone-unattributed"].startswith("3 result(s) not stored")


# storing hits ----------------------------------------------------------------------------


def test_hit_insert_tolerates_a_concurrent_insert(conn, data_dir):  # 37
    seed(conn)
    other = sqlite3.connect(data_dir / "unlist.db", timeout=5)
    b = Breach(name="Adobe", title="Adobe", data_classes=["Passwords"])
    # another scan stored the same hit after this one would have looked for it
    assert _upsert_hit(other, "me", None, EMAIL, "xposedornot", Breach(name="Adobe"), None, "2026-01-01T00:00:00Z")
    other.commit()
    other.close()
    assert _upsert_hit(conn, "me", None, EMAIL, "xposedornot", b, None, "2026-02-02T00:00:00Z") is False
    (row,) = hits_for(conn, "me")
    assert row["first_seen"] == "2026-01-01T00:00:00Z" and row["last_seen"] == "2026-02-02T00:00:00Z"
    assert json.loads(row["data_classes_json"]) == ["Passwords"]
    # an answer without classes does not blank the stored ones
    assert not _upsert_hit(conn, "me", None, EMAIL, "xposedornot", Breach(name="Adobe"), None, "2026-03-03T00:00:00Z")
    assert json.loads(hits_for(conn, "me")[0]["data_classes_json"]) == ["Passwords"]


def xon_routes(fixtures, analytics):
    return {
        CATALOG: catalog(),
        ANALYTICS: analytics,
        CHECK: json_response((fixtures / "xon_check.json").read_bytes()),
    }


def test_richer_answer_replaces_the_evidence_and_is_not_downgraded(conn, fixtures, data_dir):  # 38
    seed(conn)
    limited = xon_routes(fixtures, httpx.Response(429))
    full = xon_routes(fixtures, json_response((fixtures / "xon_analytics.json").read_bytes()))

    def scan(routes):
        return scan_breaches(conn, "me", fetcher=make_fetcher(routes), hibp_api_key="", sources=("xposedornot",))

    def adobe():
        row = next(h for h in hits_for(conn, "me") if h["breach_name"] == "Adobe")
        note = conn.execute("SELECT note FROM captures WHERE id=?", (row["capture_id"],)).fetchone()[0]
        return row, note

    assert scan(limited).new_hits == 2
    row, note = adobe()
    assert note.startswith("xposedornot lookup") and row["breach_date"] is None
    assert scan(full).new_hits == 0
    row, note = adobe()
    assert note == "xposedornot analytics"
    assert row["breach_date"] == "2013" and row["domain"] == "adobe.com" and row["pwn_count"] == 152445165
    g = next(g for g in D.groups_for(conn, "me") if g.title == "Adobe")
    assert ("Passwords", D.PASSWORD_RISK["hardtocrack"]) in g.facts  # read from the new capture
    # the plain lookup answering later does not take the detailed capture away
    scan(limited)
    assert adobe()[1] == "xposedornot analytics"


def test_risk_metric_is_cleared_only_by_a_confirmed_no_match(conn, fixtures, data_dir):  # 40
    seed(conn)
    key = ("xposedornot", f"risk:{EMAIL}")

    def scan(analytics):
        routes = xon_routes(fixtures, analytics)
        return scan_breaches(conn, "me", fetcher=make_fetcher(routes), hibp_api_key="", sources=("xposedornot",))

    scan(json_response((fixtures / "xon_analytics.json").read_bytes()))
    assert metrics_for(conn, "me")[key]["risk_label"] == "Medium"
    scan(httpx.Response(429))  # no assessment available: the earlier one is not discarded
    assert metrics_for(conn, "me")[key]["risk_label"] == "Medium"
    scan(httpx.Response(404))  # the source now says it has nothing
    assert key not in metrics_for(conn, "me")
    scan(json_response((fixtures / "xon_analytics.json").read_bytes()))
    scan(json_response('{"Error":"Not found"}'))
    assert key not in metrics_for(conn, "me")


# XposedOrNot -----------------------------------------------------------------------------


@pytest.mark.parametrize("body", ["null", "[]", '"x"', "7", '{"breaches":"Adobe"}', "{}"])
def test_xon_check_rejects_unusable_replies(body):  # 41
    r, hits = XposedOrNotClient(make_fetcher({CHECK: json_response(body)})).check(EMAIL)
    assert r.ok and hits is None


def test_xon_check_keeps_no_match_and_hits(fixtures):  # 41
    f = make_fetcher({CHECK: json_response('{"Error":"Not found"}')})
    assert XposedOrNotClient(f).check(EMAIL)[1] == []
    f = make_fetcher({CHECK: json_response((fixtures / "xon_check.json").read_bytes())})
    assert [b.name for b in XposedOrNotClient(f).check(EMAIL)[1]] == ["Adobe", "Collection1"]


@pytest.mark.parametrize("body", [b"null", b"[]", b'"x"', b"{}", b'{"status":"ok"}', b'{"Error":"Rate limit"}'])
def test_analytics_without_recognised_fields_is_unusable(body):  # 42, 79
    assert parse_analytics(body) is None


def test_analytics_tolerates_odd_inner_shapes():  # 42
    assert parse_analytics(b'{"Error":"Not found"}') == ([], {})
    hits, metrics = parse_analytics(
        b'{"ExposedBreaches":{"breaches_details":[null,"x",{"breach":"Adobe"}]},'
        b'"BreachMetrics":{"risk":["High"],"passwords_strength":7},"PastesSummary":[1]}'
    )
    assert [b.name for b in hits] == ["Adobe"]
    assert metrics == {"risk_label": None, "risk_score": None, "pastes": 0, "password_strength": {}}
    assert parse_analytics(b'{"ExposedBreaches":null,"BreachesSummary":{"site":""}}')[0] == []


@pytest.mark.parametrize("body", ["[]", "{}", "null"])
def test_unusable_analytics_falls_back_to_the_plain_lookup(conn, fixtures, data_dir, body):  # 42, 79
    seed(conn)
    routes = xon_routes(fixtures, json_response(body))
    res = scan_breaches(conn, "me", fetcher=make_fetcher(routes), hibp_api_key="", sources=("xposedornot",))
    assert res.new_hits == 2 and not res.errors
    assert xposedornot.analytics(make_fetcher(routes), EMAIL)[1] is None


def test_null_answers_are_recorded_as_failures_and_the_scan_finishes(conn, data_dir):  # 35, 41
    seed(conn)
    routes = {
        CATALOG: json_response("null"),
        LEAK: json_response("null"),
        ANALYTICS: json_response("null"),
        CHECK: json_response("null"),
    }
    res = scan_breaches(conn, "me", fetcher=make_fetcher(routes), hibp_api_key="")
    assert res.new_hits == 0
    assert any(e.startswith("leakcheck ") for e in res.errors)
    assert any(e.startswith("xposedornot ") for e in res.errors)
    assert conn.execute("SELECT finished_at FROM scan_runs").fetchone()[0]


# domains ---------------------------------------------------------------------------------


def doh(records, status=0):
    body = {"Status": status}
    if records is not None:
        body["Answer"] = [{"data": f'"{r}"'} for r in records]
    return json_response(json.dumps(body))


def domain_routes(d, **over):
    routes = {
        f"https://cloudflare-dns.com/dns-query?name={d}&type=TXT": doh(["v=spf1 -all"]),
        f"https://cloudflare-dns.com/dns-query?name=_dmarc.{d}&type=TXT": doh(["v=DMARC1; p=reject"]),
        f"https://cloudflare-dns.com/dns-query?name={d}&type=MX": doh(["10 mx.example."]),
        f"https://crt.sh/?q=%25.{d}&output=json": json_response("[]"),
    }
    for key, value in over.items():
        url = next(u for u in routes if key in u)
        routes[url] = value
    return routes


def test_resolver_errors_are_failed_lookups_not_missing_records(conn, data_dir):  # 43
    d = "janedoe.example"
    seed(conn, ident("domain", d))
    bad = {"type=TXT": doh(None, status=2)}  # SERVFAIL for the SPF lookup
    res = scan_domains(conn, "me", fetcher=make_fetcher(domain_routes(d, **bad)))
    assert f"spf {d}: lookup failed" in res.errors
    assert not any("spf" in i.lower() for i in res.issues)
    assert not [r for r in X.list_for(conn, "me", "domain") if r["key"] == "spf"]
    # NXDOMAIN is an answer: there is no record
    gone = {"_dmarc": doh(None, status=3)}
    res = scan_domains(conn, "me", fetcher=make_fetcher(domain_routes(d, **gone)))
    assert any("DMARC" in i for i in res.issues) and not any("dmarc" in e for e in res.errors)
    for body in ("null", "[]", '{"Answer":[]}', '{"Status":0,"Answer":[7]}'):
        res = scan_domains(conn, "me", fetcher=make_fetcher(domain_routes(d, **{"type=TXT": json_response(body)})))
        assert f"spf {d}: lookup failed" in res.errors, body


def test_spf_is_evaluated_in_order():  # 44
    assert assess_spf(["v=spf1 all -all"])[0] == "issue"  # the first all passes everyone
    assert assess_spf(["v=spf1 +all -all"])[0] == "issue"
    assert assess_spf(["v=spf1 ?all"])[0] == "issue"
    assert assess_spf(["v=spf1 include:x.example"])[0] == "issue"
    assert assess_spf(["v=spf1 include:x.example -all +all"])[0] == "ok"
    assert assess_spf(["v=spf1 mx ~ALL"])[0] == "ok"
    assert assess_spf(["v=spf1 redirect=_spf.example.com"])[0] == "ok"
    assert assess_spf(["v=spf1 include:mall-all.example"])[0] == "issue"  # not a substring test
    assert assess_spf(["v=spf10 -all"])[0] == "issue"  # not an SPF record


def test_dmarc_needs_one_record_with_an_enforcing_policy():  # 45
    assert assess_dmarc(["v=DMARC1"])[0] == "issue"
    assert assess_dmarc(["v=DMARC1; rua=mailto:x@example.com"])[0] == "issue"
    assert assess_dmarc(["v=DMARC1; p=bogus"])[0] == "issue"
    assert assess_dmarc(["v=DMARC1; sp=reject"])[0] == "issue"  # sp is not the domain's policy
    assert assess_dmarc(["v=DMARC1; p=reject", "v=DMARC1; p=none"])[0] == "issue"
    assert assess_dmarc(["v=DMARC1; p=reject", "v=DMARC1; p=reject"])[0] == "issue"
    assert assess_dmarc(["v=DMARC1; p=none; sp=reject"])[0] == "issue"
    assert assess_dmarc(["v=DMARC1;p=Quarantine;pct=100"])[0] == "ok"
    assert assess_dmarc(["v=DMARC1 ; P = reject"])[0] == "ok"


def test_weak_records_do_not_resolve_an_open_finding(conn, data_dir):  # 44, 45
    d = "janedoe.example"
    seed(conn, ident("domain", d))
    open_ = {"type=TXT": doh([]), "_dmarc": doh([])}
    scan_domains(conn, "me", fetcher=make_fetcher(domain_routes(d, **open_)))
    weak = {"type=TXT": doh(["v=spf1 all -all"]), "_dmarc": doh(["v=DMARC1; rua=mailto:a@b.example"])}
    res = scan_domains(conn, "me", fetcher=make_fetcher(domain_routes(d, **weak)))
    assert not res.resolved and len(res.issues) == 2
    assert {r["status"] for r in X.list_for(conn, "me", "domain")} == {"confirmed"}


def test_missing_mx_is_reported_without_claiming_no_mail(conn, data_dir):  # 46
    d = "janedoe.example"
    seed(conn, ident("domain", d))
    res = scan_domains(conn, "me", fetcher=make_fetcher(domain_routes(d, **{"type=MX": doh([])})))
    assert res.info == [f"{d}: no explicit MX record"]


def test_only_certificate_names_under_the_domain_are_kept(conn, data_dir):  # 47
    d = "janedoe.example"
    seed(conn, ident("domain", d))
    rows = [
        {"name_value": f"VPN.{d}.\nunrelated.example\n*.{d}\nnot{d}"},
        {"name_value": f"{d}\nevil-{d}\n{d}.attacker.example"},
        "junk",
        {"name_value": None},
    ]
    routes = domain_routes(d, **{"crt.sh": json_response(json.dumps(rows))})
    scan_domains(conn, "me", fetcher=make_fetcher(routes))
    row = next(r for r in X.list_for(conn, "me", "domain") if r["key"] == "hostnames")
    assert json.loads(row["detail_json"])["hostnames"] == [d, f"vpn.{d}"]
    # an answer that is not a list of rows is simply no hostnames
    res = scan_domains(conn, "me", fetcher=make_fetcher(domain_routes(d, **{"crt.sh": json_response("null")})))
    assert not res.errors


# evidence and exposures ------------------------------------------------------------------


def test_same_html_with_a_different_screenshot_is_stored(conn, data_dir):  # 48
    def cap(png):
        return SimpleNamespace(
            requested_url="https://b.example/p", final_url="https://b.example/p", status=200,
            html=b"<html>same</html>", png=png, captured_at="2026-03-01T10:00:00Z",
            challenged=False, note=None,
        )  # fmt: skip

    ids = [record_browser(conn, "brokers", cap(png)) for png in (b"png-one", b"png-two", b"png-one")]
    rows = [conn.execute("SELECT * FROM captures WHERE id=?", (i,)).fetchone() for i in ids]
    assert len({r["raw_path"] for r in rows}) == 1 and len({r["sha256"] for r in rows}) == 1
    assert rows[0]["shot_path"] != rows[1]["shot_path"] and rows[0]["shot_path"] == rows[2]["shot_path"]
    assert (data_dir / rows[1]["shot_path"]).read_bytes() == b"png-two"
    assert hashlib.sha256(b"png-one").hexdigest() in rows[0]["shot_path"]


def test_refresh_keeps_a_status_changed_on_another_connection(conn, data_dir):  # 49
    seed(conn)
    eid, how = X.upsert(conn, "me", "jane", "account", "whatsmyname", "Site")
    conn.commit()
    assert how == "new"

    class Racing:
        """The dashboard rejects the exposure between upsert's SELECT and its UPDATE."""

        def execute(self, sql, *args):
            cur = conn.execute(sql, *args)
            if sql.lstrip().upper().startswith("SELECT"):
                row = cur.fetchone()
                other = sqlite3.connect(data_dir / "unlist.db", timeout=5)
                other.execute("UPDATE exposures SET status='rejected' WHERE id=?", (eid,))
                other.commit()
                other.close()
                return SimpleNamespace(fetchone=lambda: row)
            return cur

    assert X.upsert(Racing(), "me", "jane", "account", "whatsmyname", "Site", detail={"a": 1}) == (eid, "seen")
    conn.commit()
    row = X.get(conn, eid)
    assert row["status"] == "rejected" and json.loads(row["detail_json"]) == {"a": 1}
    # a resolved exposure seen again is still reopened with the scanner's status
    X.set_status(conn, eid, "resolved")
    assert X.upsert(conn, "me", "jane", "account", "whatsmyname", "Site", status="confirmed") == (eid, "reopened")
    assert X.get(conn, eid)["status"] == "confirmed"


# mentions --------------------------------------------------------------------------------


def brave_routes(conn, answers):
    from unlist.scanners.brokers.urls import Profile

    qs = build_queries(Profile.from_subject(SubjectRepo(conn).get("me")))
    assert len(qs) == len(answers)
    return {
        f"https://api.search.brave.com/res/v1/web/search?q={quote(q, safe='')}&count=20": a
        for q, a in zip(qs, answers, strict=True)
    }


def test_invalid_results_are_skipped_and_valid_ones_kept(conn, data_dir):  # 50, 81
    seed(conn)
    good = {"title": "Jane", "url": "https://news.example/jane", "description": "A story"}
    mixed = json_response(json.dumps({"web": {"results": [
        good,
        None,
        "text",
        {"title": "no url"},
        {"title": "bad host", "url": "http://[bad/x"},
        {"title": "script", "url": "javascript:alert(document.cookie)"},
        {"title": "data", "url": "data:text/html,<script>1</script>"},
        {"title": "relative", "url": "//news.example/other"},
        {"title": "ftp", "url": "ftp://files.example/jane"},
        {"title": "number", "url": 7},
        {"title": "second", "url": "HTTPS://WWW.Other.example:8443/p"},
    ]}}))  # fmt: skip
    res = scan_mentions(
        conn, "me", fetcher=make_fetcher(brave_routes(conn, [mixed, json_response("null")])),
        api_key="k",
    )  # fmt: skip
    assert [(m.url, m.host) for m in res.mentions] == [
        ("https://news.example/jane", "news.example"),
        ("HTTPS://WWW.Other.example:8443/p", "other.example"),
    ]
    assert len(res.errors) == 1 and res.errors[0].endswith("unreadable answer")
    for body in ('{"web":[]}', '{"web":{"results":"x"}}', "[]"):
        res = scan_mentions(
            conn, "me", fetcher=make_fetcher(brave_routes(conn, [json_response(body), mixed])),
            api_key="k",
        )  # fmt: skip
        assert len(res.mentions) == 2 and len(res.errors) == 1, body


@pytest.mark.parametrize(
    "url",
    ["//news.example/jane", "javascript:alert(1)", "news.example/jane", "ftp://news.example/x",
     "http://", "http:///path", "http://[bad/x", "https://exa mple.com/", " https://news.example/",
     "https://news.example:port/", "mailto:jane@example.com", "http://bad_host!/x"],
)  # fmt: skip
def test_confirm_mention_needs_an_absolute_web_url(conn, data_dir, url):  # 51
    seed(conn)
    assert web_host(url) == ""
    with pytest.raises(ValueError):
        confirm_mention(conn, "me", url)
    assert conn.execute("SELECT COUNT(*) FROM exposures").fetchone()[0] == 0


def test_web_host_accepts_ordinary_addresses():  # 51
    assert web_host("https://www.News.example/jane?x=1") == "news.example"
    assert web_host("http://127.0.0.1:8080/x") == "127.0.0.1"
    assert web_host("https://[2001:db8::1]/x") == "2001:db8::1"
    assert web_host("https://user@sub.news.example./x") == "sub.news.example."


# usernames -------------------------------------------------------------------------------


def wmn(*sites):
    return json_response(json.dumps({"sites": list(sites)}))


SITE = {"name": "Site", "uri_check": "https://site.test/u/{account}", "e_code": 200,
        "e_string": "profile", "m_code": 404, "m_string": "", "cat": "social"}  # fmt: skip


def test_bad_refresh_keeps_the_last_good_cache(conn, data_dir):  # 52
    f = make_fetcher({DATA_URL: wmn(SITE)})
    assert [s["name"] for s in load_sites(f)] == ["Site"]
    good = cache_path().read_bytes()
    stale = cache_path().stat().st_mtime + 8 * 86400  # the cache is now too old
    for body in (b"<html>captive portal</html>", b"null", b'{"sites":"x"}', b'{"sites":[]}'):
        bad = make_fetcher({DATA_URL: httpx.Response(200, content=body)})
        assert [s["name"] for s in load_sites(bad, now=stale)] == ["Site"]
        assert cache_path().read_bytes() == good
    assert not list(cache_path().parent.glob("*.part"))
    # a later good download replaces it
    newer = make_fetcher({DATA_URL: wmn(SITE, {**SITE, "name": "Other"}, "junk")})
    assert [s["name"] for s in load_sites(newer, now=stale)] == ["Site", "Other"]
    assert cache_path().read_bytes() != good


def test_first_download_must_be_valid(conn, data_dir):  # 52
    with pytest.raises(RuntimeError, match="not valid"):
        load_sites(make_fetcher({DATA_URL: httpx.Response(200, content=b"{oops")}))
    assert not cache_path().exists()
    with pytest.raises(RuntimeError):
        load_sites(make_fetcher({DATA_URL: httpx.Response(503)}))


def test_zero_limit_sends_the_username_nowhere(conn, data_dir):  # 53
    seed(conn, ident("username", "janedoe82"))
    asked = []

    def profile(request):
        asked.append(str(request.url))
        return html_response(b"profile")

    routes = {DATA_URL: wmn(SITE), "https://site.test/u/janedoe82": profile}
    res = scan_usernames(conn, "me", fetcher=make_fetcher(routes), limit=0)
    assert res.sites == 0 and res.found == 0 and asked == []
    assert conn.execute("SELECT finished_at FROM scan_runs WHERE id=?", (res.run_id,)).fetchone()[0]
    with pytest.raises(ValueError):
        scan_usernames(conn, "me", fetcher=make_fetcher(routes), limit=-1)
    assert asked == [] and conn.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0] == 1
    assert scan_usernames(conn, "me", fetcher=make_fetcher(routes), limit=None).found == 1
    assert len(asked) == 1


def test_username_is_encoded_for_the_url_and_the_body():  # 82
    seen = {}

    def page(request):
        seen["url"] = str(request.url)
        seen["body"] = request.content.decode()
        return html_response(b"profile")

    name = 'a/b?c=d"e&f é'
    encoded = "a%2Fb%3Fc%3Dd%22e%26f%20%C3%A9"
    f = make_fetcher({f"https://site.test/u/{encoded}": page, "https://post.test/api": page})
    verdict, _, pretty = check_site(f, {**SITE, "uri_pretty": "https://site.test/@{account}"}, name)
    assert verdict == "found" and seen["url"] == f"https://site.test/u/{encoded}"
    assert pretty == f"https://site.test/@{encoded}"
    post = {**SITE, "uri_check": "https://post.test/api", "post_body": '{"user":"{account}","n":1}'}
    check_site(f, post, name)
    assert json.loads(seen["body"]) == {"user": name, "n": 1}  # still valid JSON, same name
    check_site(f, {**post, "post_body": "user={account}&go=1"}, name)
    assert seen["body"] == f"user={encoded}&go=1"
    # strip_bad_char still applies first, and ordinary names are untouched
    check_site(f, {**post, "strip_bad_char": "."}, "jane.doe_8-2")
    assert json.loads(seen["body"])["user"] == "janedoe_8-2"


def test_one_unusable_rule_does_not_abort_the_scan(conn, data_dir):  # 83
    seed(conn, ident("username", "janedoe82"))
    sites = [
        {**SITE, "name": "BadUrl", "uri_check": "http://[broken/{account}"},
        {**SITE, "name": "BadType", "uri_check": "https://x.test/{account}", "headers": "oops"},
        {**SITE, "name": "Good"},
    ]
    routes = {DATA_URL: wmn(*sites), "https://site.test/u/janedoe82": html_response(b"profile")}
    res = scan_usernames(conn, "me", fetcher=make_fetcher(routes))
    assert res.sites == 3 and res.found == 1 and res.unknown == 2
    assert [r["key"] for r in X.list_for(conn, "me", "account")] == ["Good"]
    run = conn.execute("SELECT * FROM scan_runs WHERE id=?", (res.run_id,)).fetchone()
    assert run["finished_at"] and json.loads(run["counts_json"])["unknown"] == 2
    events = (data_dir / "audit.jsonl").read_text()
    assert "scan.usernames.finish" in events
