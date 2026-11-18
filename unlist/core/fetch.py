"""Rate-limited HTTP GET with retries, redirect tracking, raw capture, hashing, robots.txt.

Design notes
- One Fetcher per process. It keeps a per-host clock and a robots.txt cache.
- The default host interval is 2 seconds. Hosts with documented higher limits
  can be relaxed via host_intervals.
- A fetch never raises for an HTTP error status. The caller decides what a 403
  means. Network failures after retries produce a FetchResult with status None
  and an error string, so a refusal can still be recorded as evidence.
- robots.txt is honoured for plain HTTP fetches. A disallow produces a
  FetchResult with refused=True and no request is made.
"""

from __future__ import annotations

import time
import urllib.robotparser
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlsplit

import httpx

from unlist import USER_AGENT
from unlist.core.store import sha256_hex
from unlist.core.timeutil import iso_z, utcnow

DEFAULT_INTERVAL = 2.0
DEFAULT_TIMEOUT = 30.0
RETRY_STATUSES = {500, 502, 503, 504, 429}


@dataclass
class FetchResult:
    requested_url: str
    final_url: str
    status: int | None
    headers: list[tuple[str, str]]
    body: bytes
    sha256: str
    captured_at: str
    refused: bool = False
    reason: str | None = None
    error: str | None = None
    history: list[tuple[int, str]] = field(default_factory=list)

    @property
    def content_type(self) -> str | None:
        for k, v in self.headers:
            if k.lower() == "content-type":
                return v
        return None

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300 and not self.refused

    @property
    def blocked(self) -> bool:
        """True when the site declined automated access: robots disallow, 401, 403, 429, 451."""
        return self.refused or self.status in (401, 403, 429, 451)


class RateLimiter:
    """Per-host minimum interval between requests."""

    def __init__(
        self,
        default_interval: float = DEFAULT_INTERVAL,
        host_intervals: dict[str, float] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.default_interval = default_interval
        self.host_intervals = dict(host_intervals or {})
        self._last: dict[str, float] = {}
        self._sleep = sleep
        self._clock = clock

    def interval_for(self, host: str) -> float:
        return self.host_intervals.get(host, self.default_interval)

    def wait(self, host: str) -> float:
        """Block until the host may be contacted again. Returns seconds slept."""
        now = self._clock()
        last = self._last.get(host)
        slept = 0.0
        if last is not None:
            remaining = self.interval_for(host) + last - now
            if remaining > 0:
                self._sleep(remaining)
                slept = remaining
        self._last[host] = self._clock()
        return slept


class Fetcher:
    def __init__(
        self,
        *,
        client: httpx.Client | None = None,
        limiter: RateLimiter | None = None,
        user_agent: str = USER_AGENT,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = 2,
        backoff: float = 3.0,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], datetime] = utcnow,
    ) -> None:
        self.user_agent = user_agent
        self._now = now
        self.client = client or httpx.Client(
            follow_redirects=True,
            timeout=timeout,
            headers={"User-Agent": user_agent, "Accept": "*/*"},
        )
        self.limiter = limiter or RateLimiter(sleep=sleep)
        self.retries = retries
        self.backoff = backoff
        self._sleep = sleep
        self._robots: dict[str, urllib.robotparser.RobotFileParser | None] = {}

    # robots.txt -----------------------------------------------------------------

    def _robots_for(self, url: str) -> urllib.robotparser.RobotFileParser | None:
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin in self._robots:
            return self._robots[origin]
        rp = urllib.robotparser.RobotFileParser()
        try:
            self.limiter.wait(parts.netloc)
            resp = self.client.get(f"{origin}/robots.txt", headers={"User-Agent": self.user_agent})
        except httpx.HTTPError:
            self._robots[origin] = None
            return None
        if resp.status_code >= 400:
            # Missing robots.txt means everything is allowed; 401/403 on robots.txt is
            # treated by urllib as disallow-all, which is the conservative reading.
            if resp.status_code in (401, 403):
                rp.disallow_all = True
            else:
                rp.allow_all = True
        else:
            rp.parse(resp.text.splitlines())
        self._robots[origin] = rp
        return rp

    def robots_allows(self, url: str) -> bool:
        rp = self._robots_for(url)
        if rp is None:
            return True
        return rp.can_fetch(self.user_agent, url) and rp.can_fetch("unlist", url)

    # fetch ----------------------------------------------------------------------

    def get(
        self,
        url: str,
        *,
        check_robots: bool = True,
        headers: dict | None = None,
        retries: int | None = None,
    ) -> FetchResult:
        """GET url. retries overrides the instance default for this call (0 disables)."""
        max_retries = self.retries if retries is None else retries
        captured_at = iso_z(self._now())
        if check_robots and not self.robots_allows(url):
            return FetchResult(
                requested_url=url,
                final_url=url,
                status=None,
                headers=[],
                body=b"",
                sha256=sha256_hex(b""),
                captured_at=captured_at,
                refused=True,
                reason="robots.txt disallows automated fetch of this URL",
            )
        host = urlsplit(url).netloc
        attempt = 0
        last_error: str | None = None
        while True:
            self.limiter.wait(host)
            captured_at = iso_z(self._now())
            try:
                resp = self.client.get(url, headers=headers or {})
            except httpx.HTTPError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                resp = None
            if resp is not None and resp.status_code not in RETRY_STATUSES:
                body = resp.content
                return FetchResult(
                    requested_url=url,
                    final_url=str(resp.url),
                    status=resp.status_code,
                    headers=list(resp.headers.multi_items()),
                    body=body,
                    sha256=sha256_hex(body),
                    captured_at=captured_at,
                    history=[(r.status_code, str(r.url)) for r in resp.history],
                    reason=_reason_for(resp.status_code),
                )
            if resp is not None:
                last_error = f"HTTP {resp.status_code}"
                last_resp = resp
            else:
                last_resp = None
            if attempt >= max_retries:
                break
            attempt += 1
            self._sleep(self.backoff * attempt)
        if last_resp is not None:
            body = last_resp.content
            return FetchResult(
                requested_url=url,
                final_url=str(last_resp.url),
                status=last_resp.status_code,
                headers=list(last_resp.headers.multi_items()),
                body=body,
                sha256=sha256_hex(body),
                captured_at=captured_at,
                history=[(r.status_code, str(r.url)) for r in last_resp.history],
                reason=_reason_for(last_resp.status_code),
                error=last_error,
            )
        return FetchResult(
            requested_url=url,
            final_url=url,
            status=None,
            headers=[],
            body=b"",
            sha256=sha256_hex(b""),
            captured_at=captured_at,
            error=last_error,
            reason="network error after retries",
        )

    def post(
        self,
        url: str,
        *,
        data: dict[str, str] | None = None,
        content: bytes | None = None,
        headers: dict | None = None,
        retries: int = 0,
    ) -> FetchResult:
        """POST url with a form body (data) or raw bytes (content).

        Mirrors get: rate limited per host, captured headers, a FetchResult with
        status None and an error on network failure. robots.txt is not consulted
        (POST targets are APIs) and retries are off unless asked for.
        """
        host = urlsplit(url).netloc
        attempt = 0
        last_error: str | None = None
        last_resp: httpx.Response | None = None
        captured_at = iso_z(self._now())
        while True:
            self.limiter.wait(host)
            captured_at = iso_z(self._now())
            try:
                resp = self.client.post(url, data=data, content=content, headers=headers or {})
            except httpx.HTTPError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                resp = None
            if resp is not None and resp.status_code not in RETRY_STATUSES:
                return self._result(url, resp, captured_at)
            if resp is not None:
                last_error = f"HTTP {resp.status_code}"
                last_resp = resp
            else:
                last_resp = None
            if attempt >= retries:
                break
            attempt += 1
            self._sleep(self.backoff * attempt)
        if last_resp is not None:
            return self._result(url, last_resp, captured_at, error=last_error)
        return FetchResult(
            requested_url=url,
            final_url=url,
            status=None,
            headers=[],
            body=b"",
            sha256=sha256_hex(b""),
            captured_at=captured_at,
            error=last_error,
            reason="network error after retries",
        )

    @staticmethod
    def _result(
        url: str, resp: httpx.Response, captured_at: str, error: str | None = None
    ) -> FetchResult:
        body = resp.content
        return FetchResult(
            requested_url=url,
            final_url=str(resp.url),
            status=resp.status_code,
            headers=list(resp.headers.multi_items()),
            body=body,
            sha256=sha256_hex(body),
            captured_at=captured_at,
            history=[(r.status_code, str(r.url)) for r in resp.history],
            reason=_reason_for(resp.status_code),
            error=error,
        )


def _reason_for(status: int) -> str | None:
    if status == 403:
        return "site returned 403 Forbidden to automated fetch"
    if status == 401:
        return "site requires authentication (401)"
    if status == 429:
        return "site rate-limited the request (429)"
    if status == 451:
        return "unavailable for legal reasons (451)"
    return None


_default: Fetcher | None = None


def default_fetcher() -> Fetcher:
    global _default
    if _default is None:
        _default = Fetcher()
    return _default
