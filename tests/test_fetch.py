from pathlib import Path

import httpx

from unlist.core.fetch import RateLimiter
from unlist.core.testing import FakeSleep, html_response, make_fetcher

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def test_rate_limiter_waits_per_host():
    t = {"now": 100.0}
    sleep = FakeSleep()
    rl = RateLimiter(default_interval=2.0, sleep=sleep, clock=lambda: t["now"])
    assert rl.wait("a.example") == 0.0
    assert rl.wait("b.example") == 0.0
    t["now"] += 0.5
    assert rl.wait("a.example") == 1.5
    assert sleep.calls == [1.5]


def test_robots_disallow_refuses_without_fetching():
    hits = []

    def page(request):
        hits.append(str(request.url))
        return html_response(b"<html>secret</html>")

    routes = {
        "https://blocked.test/robots.txt": httpx.Response(
            200, content=fixture_bytes("robots_disallow_all.txt")
        ),
        "https://blocked.test/story": page,
    }
    r = make_fetcher(routes).get("https://blocked.test/story")
    assert r.refused and r.blocked and r.status is None
    assert "robots.txt" in r.reason
    assert hits == []


def test_403_is_returned_not_raised():
    routes = {
        "https://site.test/robots.txt": httpx.Response(404),
        "https://site.test/page": html_response(b"<h1>Access denied</h1>", status=403),
    }
    r = make_fetcher(routes).get("https://site.test/page")
    assert r.status == 403 and r.blocked and not r.refused
    assert r.body == b"<h1>Access denied</h1>"


def test_user_agent_names_the_project():
    seen = {}

    def page(request):
        seen["ua"] = request.headers.get("user-agent")
        return html_response(b"<p>ok</p>")

    f = make_fetcher({"https://site.test/page": page})
    f.get("https://site.test/page")
    assert seen["ua"] is None or "unlist" in seen["ua"] or "python-httpx" in seen["ua"]
