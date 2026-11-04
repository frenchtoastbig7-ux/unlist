"""A visible Chromium you can watch, for sites that refuse plain fetches.

The browser does what you would do by hand: open the page, wait, save it. If the site
shows a challenge (Cloudflare, a CAPTCHA), the page stays open and the tool waits for
you to deal with it; it never attempts to solve one. The profile persists under
~/.unlist/browser so a site that remembers you does not challenge you every time.
"""

from __future__ import annotations

import contextlib
import time
from dataclasses import dataclass
from pathlib import Path

from unlist import paths
from unlist.core.timeutil import now_iso
from unlist.scanners.brokers.matcher import looks_like_challenge


class BrowserUnavailable(RuntimeError):
    pass


@dataclass
class BrowserCapture:
    requested_url: str
    final_url: str
    status: int | None
    html: bytes
    png: bytes
    captured_at: str
    title: str = ""
    challenged: bool = False
    note: str | None = None


class BrowserSession:
    def __init__(
        self,
        profile_dir: Path | None = None,
        *,
        headless: bool = False,
        timeout_ms: int = 30_000,
        settle_ms: int = 2_000,
        challenge_wait_s: int = 120,
    ) -> None:
        self.profile_dir = profile_dir or paths.browser_profile_dir()
        self.headless = headless
        self.timeout_ms = timeout_ms
        self.settle_ms = settle_ms
        self.challenge_wait_s = challenge_wait_s
        self._pw = None
        self._ctx = None

    def __enter__(self) -> BrowserSession:
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def start(self) -> None:
        if self._ctx is not None:
            return
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise BrowserUnavailable(
                "Playwright is not installed: uv sync --extra browser && "
                "uv run playwright install chromium"
            ) from exc
        self.profile_dir.mkdir(parents=True, exist_ok=True)
        paths.make_private(self.profile_dir)
        self._pw = sync_playwright().start()
        try:
            self._ctx = self._pw.chromium.launch_persistent_context(
                str(self.profile_dir),
                headless=self.headless,
                viewport={"width": 1280, "height": 1600},
            )
        except Exception as exc:
            self._pw.stop()
            self._pw = None
            raise BrowserUnavailable(f"could not start Chromium: {exc}") from exc
        self._ctx.set_default_timeout(self.timeout_ms)

    def close(self) -> None:
        if self._ctx is not None:
            with contextlib.suppress(Exception):
                self._ctx.close()
            self._ctx = None
        if self._pw is not None:
            with contextlib.suppress(Exception):
                self._pw.stop()
            self._pw = None

    def capture(self, url: str) -> BrowserCapture:
        """Open url, wait for it to settle, save HTML and a full-page screenshot."""
        self.start()
        assert self._ctx is not None
        page = self._ctx.new_page()
        note = None
        try:
            resp = page.goto(url, wait_until="domcontentloaded")
            status = resp.status if resp else None
            page.wait_for_timeout(self.settle_ms)
            with contextlib.suppress(Exception):
                page.wait_for_load_state("networkidle", timeout=8_000)
            html = page.content()
            challenged = looks_like_challenge(html)
            if challenged:
                deadline = time.monotonic() + self.challenge_wait_s
                while time.monotonic() < deadline:
                    page.wait_for_timeout(2_000)
                    html = page.content()
                    if not looks_like_challenge(html):
                        challenged = False
                        note = "site challenged; cleared by the operator in the browser"
                        break
                if challenged:
                    note = f"site challenged; not cleared within {self.challenge_wait_s}s"
            png = page.screenshot(full_page=True)
            return BrowserCapture(
                requested_url=url,
                final_url=page.url,
                status=status,
                html=html.encode("utf-8"),
                png=png,
                captured_at=now_iso(),
                title=page.title(),
                challenged=challenged,
                note=note,
            )
        finally:
            with contextlib.suppress(Exception):
                page.close()
