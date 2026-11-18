"""Helpers for offline tests: a Fetcher backed by an in-memory route table, no network."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

import httpx

from unlist.core.fetch import Fetcher, RateLimiter
from unlist.core.timeutil import utcnow

Route = httpx.Response | Exception | Callable[[httpx.Request], httpx.Response]


class FakeSleep:
    def __init__(self) -> None:
        self.calls: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def html_response(body: bytes, status: int = 200, **headers: str) -> httpx.Response:
    h = {"content-type": "text/html; charset=utf-8", **headers}
    return httpx.Response(status, content=body, headers=h)


def json_response(body: bytes | str, status: int = 200) -> httpx.Response:
    if isinstance(body, str):
        body = body.encode("utf-8")
    return httpx.Response(status, content=body, headers={"content-type": "application/json"})


def make_fetcher(
    routes: dict[str, Route],
    sleep: FakeSleep | None = None,
    now: Callable[[], datetime] = utcnow,
) -> Fetcher:
    """Build a Fetcher whose transport answers from a URL -> Response map.

    Unknown URLs get a 404. A route value may be a Response, an Exception to raise,
    or a callable taking the request. The route table is live: tests may replace
    entries between calls to simulate a page changing.
    """
    sleep = sleep or FakeSleep()

    def handler(request: httpx.Request) -> httpx.Response:
        key = str(request.url)
        if key in routes:
            r = routes[key]
            if isinstance(r, Exception):
                raise r
            if callable(r):
                return r(request)
            return r
        return httpx.Response(404, content=b"not found")

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)
    limiter = RateLimiter(sleep=sleep, clock=lambda: 0.0)
    return Fetcher(client=client, limiter=limiter, sleep=sleep, retries=1, backoff=0.1, now=now)
