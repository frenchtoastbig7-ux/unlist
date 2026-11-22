"""Rate-limited HTTP GET/POST with retries, hop-by-hop redirects, raw capture, robots.txt.

Design notes
- One Fetcher per process. It keeps a per-host clock and a robots.txt cache.
- The default host interval is 2 seconds. Hosts with documented higher limits
  can be relaxed via host_intervals.
- A fetch never raises for an HTTP error status. The caller decides what a 403
  means. Network failures after retries produce a FetchResult with status None
  and an error string, so a refusal can still be recorded as evidence.
- robots.txt is honoured for plain HTTP fetches. A disallow produces a
  FetchResult with refused=True and no request is made.
- Redirects are followed one hop at a time so each hop gets the robots check and
  its host's rate limit, and caller-supplied credentials never leave the origin
  they were meant for. A malformed URL or a redirect loop is a failed fetch
  (status None), not an exception.
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
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
MAX_REDIRECTS = 10
# Request headers that may follow a redirect to another origin. Anything else a caller
# adds (X-API-Key, hibp-api-key, X-Subscription-Token, Authorization) stays behind.
_FORWARDABLE_HEADERS = {"accept", "accept-language", "user-agent", "content-type"}
_DEFAULT_PORTS = {"http": 80, "https": 443}


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


@dataclass
class _Attempt:
    """One pass over a redirect chain: a final response, a robots refusal, or a failure."""

    final_url: str
    captured_at: str
    resp: httpx.Response | None = None
    history: list[tuple[int, str]] = field(default_factory=list)
    refused: bool = False
    error: str | None = None
    reason: str | None = None
    retryable: bool = False


def _origin(url: str) -> tuple[str, str | None, int | None]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    return scheme, parts.hostname, parts.port or _DEFAULT_PORTS.get(scheme)


def _has_header(headers: dict[str, str], name: str) -> bool:
    return any(k.lower() == name for k in headers)


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
        # Redirects are followed here, hop by hop (see _attempt), never by httpx.
        self.client = client or httpx.Client(
            follow_redirects=False,
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
        resp = self._attempt("GET", f"{origin}/robots.txt", check_robots=False).resp
        if resp is None:
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
        return self._fetch("GET", url, max_retries, check_robots=check_robots, headers=headers)

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
        return self._fetch(
            "POST", url, retries, check_robots=False, headers=headers, data=data, content=content
        )

    def _fetch(self, method: str, url: str, max_retries: int, **kwargs) -> FetchResult:
        attempt = 0
        while True:
            a = self._attempt(method, url, **kwargs)
            if a.resp is not None and a.resp.status_code not in RETRY_STATUSES:
                return self._result(url, a)
            if not a.retryable and a.resp is None:
                return self._result(url, a)
            if attempt >= max_retries:
                break
            attempt += 1
            self._sleep(self.backoff * attempt)
        if a.resp is not None:
            a.error = f"HTTP {a.resp.status_code}"
        else:
            a.reason = "network error after retries"
        return self._result(url, a)

    def _attempt(
        self,
        method: str,
        url: str,
        *,
        check_robots: bool,
        headers: dict | None = None,
        data: dict[str, str] | None = None,
        content: bytes | None = None,
    ) -> _Attempt:
        """Send one request and follow its redirects by hand.

        Every hop waits for its own host's rate limit and, for a GET with check_robots,
        is checked against that host's robots.txt. Headers the caller added (API keys)
        go only to the origin the caller named: the first hop to another origin, or
        from https to http, drops everything outside _FORWARDABLE_HEADERS for the rest
        of the chain. A body is never re-sent to another origin.
        """
        hop_headers = {str(k): str(v) for k, v in (headers or {}).items()}
        if not _has_header(hop_headers, "user-agent"):
            hop_headers["User-Agent"] = self.user_agent
        history: list[tuple[int, str]] = []
        captured_at = iso_z(self._now())
        current = url
        try:
            first_origin = _origin(url)
            for _ in range(MAX_REDIRECTS + 1):
                parts = urlsplit(current)
                if method == "GET" and check_robots and not self.robots_allows(current):
                    reason = "robots.txt disallows automated fetch of this URL"
                    if history:
                        reason = "robots.txt disallows automated fetch of the redirect target"
                    return _Attempt(
                        current, captured_at, history=history, refused=True, reason=reason
                    )
                self.limiter.wait(parts.netloc)
                captured_at = iso_z(self._now())
                request = self.client.build_request(
                    method, current, headers=hop_headers, data=data, content=content
                )
                resp = self.client.send(request, follow_redirects=False)
                location = resp.headers.get("location")
                if resp.status_code not in REDIRECT_STATUSES or not location:
                    return _Attempt(str(resp.url), captured_at, resp=resp, history=history)
                target = str(resp.url.join(location))
                has_body = data is not None or content is not None
                cross_origin = _origin(target) != first_origin
                keeps_method = resp.status_code in (307, 308) or method != "POST"
                if has_body and keeps_method and cross_origin:
                    # Hand the 3xx back rather than repeat the body somewhere else.
                    return _Attempt(str(resp.url), captured_at, resp=resp, history=history)
                history.append((resp.status_code, str(resp.url)))
                if not keeps_method:
                    method, data, content = "GET", None, None
                    hop_headers = {
                        k: v for k, v in hop_headers.items() if k.lower() != "content-type"
                    }
                # A scheme change is already a different origin; https to http is the
                # case that must never carry a key, so it is spelled out.
                downgrade = first_origin[0] == "https" and _origin(target)[0] != "https"
                if cross_origin or downgrade:
                    hop_headers = {
                        k: v for k, v in hop_headers.items() if k.lower() in _FORWARDABLE_HEADERS
                    }
                current = target
        except (ValueError, httpx.InvalidURL) as exc:
            # urlsplit and httpx both refuse some strings outright; that is a failed
            # fetch like any other, not a reason to take down the caller's whole run.
            return _Attempt(
                current,
                captured_at,
                history=history,
                error=f"{type(exc).__name__}: {exc}",
                reason="malformed URL",
            )
        except httpx.HTTPError as exc:
            return _Attempt(
                current,
                captured_at,
                history=history,
                error=f"{type(exc).__name__}: {exc}",
                retryable=True,
            )
        return _Attempt(
            current,
            captured_at,
            history=history,
            error=f"more than {MAX_REDIRECTS} redirects",
            reason="redirect limit reached",
        )

    @staticmethod
    def _result(url: str, a: _Attempt) -> FetchResult:
        if a.resp is None:
            return FetchResult(
                requested_url=url,
                final_url=a.final_url if a.refused else url,
                status=None,
                headers=[],
                body=b"",
                sha256=sha256_hex(b""),
                captured_at=a.captured_at,
                refused=a.refused,
                reason=a.reason,
                error=a.error,
                history=a.history,
            )
        body = a.resp.content
        return FetchResult(
            requested_url=url,
            final_url=a.final_url,
            status=a.resp.status_code,
            headers=list(a.resp.headers.multi_items()),
            body=body,
            sha256=sha256_hex(body),
            captured_at=a.captured_at,
            history=a.history,
            reason=_reason_for(a.resp.status_code),
            error=a.error,
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
