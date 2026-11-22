"""Browser-assisted web forms: the tool opens the opt-out page in a visible Chromium,
fills what it can from the broker's playbook, takes a screenshot, and stops. You submit,
solve whatever is interactive, and close the window; the helper records what it saw."""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import subprocess
import sys
import time
from urllib.parse import urlsplit

from unlist import paths
from unlist.catalog import Broker, load_catalog
from unlist.core.audit import AuditLog
from unlist.core.timeutil import now_iso
from unlist.requests import engine
from unlist.scanners.brokers.urls import NameParts
from unlist.scanners.evidence import record_browser
from unlist.subjects import SubjectRepo
from unlist.subjects.models import Subject

FIELD_KEYS = (
    "listing_url",
    "email",
    "first",
    "last",
    "name",
    "city",
    "state",
    "zip",
    "phone",
    "age",
)


def prefill_values(
    subject: Subject, broker: Broker, row: sqlite3.Row, from_address: str | None
) -> dict[str, str]:
    """Values the playbook may ask for. Nothing beyond what the opt-out needs; no DOB."""
    listings = json.loads(row["listings_json"] or "[]")
    names = [i for i in subject.identifiers if i.kind == "name" and i.current] or [
        i for i in subject.identifiers if i.kind in ("name", "alias")
    ]
    parts = NameParts.parse(names[0].value) if names else None
    place = names[0].meta if names else {}
    emails = [i.value for i in subject.identifiers if i.kind == "email" and i.current]
    phones = [i.value for i in subject.identifiers if i.kind == "phone" and i.current]
    values = {
        "listing_url": listings[0] if listings else "",
        "email": from_address or (emails[0] if emails else ""),
        "first": parts.first if parts else "",
        "last": parts.last if parts else "",
        "name": names[0].value if names else subject.label,
        "city": str(place.get("city") or ""),
        "state": str(place.get("state") or ""),
        "zip": str(place.get("zip") or ""),
        "phone": phones[0] if phones else "",
    }
    return {k: v for k, v in values.items() if v}


OPENABLE_STATES = ("drafted", "approved", "awaiting_verification")


def _https_host(url: str) -> str | None:
    """The host of an https URL without userinfo, else None."""
    try:
        parts = urlsplit(url or "")
        host = parts.hostname
    except ValueError:
        return None
    if parts.scheme.lower() != "https" or not host or "@" in parts.netloc:
        return None
    return host.lower().removeprefix("www.")


def fill_refusal(url: str, final_url: str, broker: Broker) -> str | None:
    """Why the subject's details must not be typed into this page, or None when they may.

    Both the opt-out URL and the page the browser actually landed on must be https, and
    the landing page must be the host the opt-out URL names or one of the broker's own
    hosts: a redirect elsewhere, or plain http, gets nothing filled in."""
    intended = _https_host(url)
    if intended is None:
        return f"the opt-out URL is not https: {url}"
    landed = _https_host(final_url)
    if landed is None:
        return f"the page that opened is not https: {final_url}"
    if landed != intended and not broker.matches_host(landed):
        return f"the page redirected to another site: {final_url}"
    return None


def launch_form_assist(request_id: int) -> int:
    """Start the helper as its own process so the browser outlives the MCP tool call."""
    log_dir = paths.data_dir() / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log = (log_dir / f"form-assist-{request_id}.log").open("ab")
    env = dict(os.environ)
    env.setdefault("UNLIST_DATA_DIR", str(paths.data_dir()))
    proc = subprocess.Popen(
        [sys.executable, "-m", "unlist.cli", "form-assist", str(request_id)],
        stdout=log,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        env=env,
        start_new_session=True,
    )
    return proc.pid


def run_form_assist(request_id: int, *, timeout_s: int = 1800, headless: bool = False) -> str:
    """The helper itself. Blocks until you close the window or the timeout passes."""
    from unlist.db import open_db
    from unlist.scanners.brokers.browser import BrowserSession

    conn = open_db()
    row = engine.get(conn, request_id)
    if row["channel"] != "form":
        return f"request {request_id} is {row['channel']}, not a form"
    if row["state"] not in OPENABLE_STATES:
        return f"request {request_id} is {row['state']}; nothing to open"
    subject = SubjectRepo(conn).require(row["subject_id"])
    broker = load_catalog().get(row["broker_id"])
    url = row["form_url"] or broker.opt_out.url or broker.contact.privacy_url
    if not url:
        return "no form URL known for this broker"
    values = prefill_values(subject, broker, row, engine._from_address())
    playbook = broker.opt_out.form
    audit = AuditLog()
    audit.append("form.open", request_id=request_id, broker=broker.id, url=url)
    with BrowserSession(headless=headless, timeout_ms=60_000, challenge_wait_s=timeout_s) as br:
        br.start()
        ctx = br._ctx
        assert ctx is not None
        page = ctx.new_page()
        page.goto(url, wait_until="domcontentloaded")
        page.wait_for_timeout(2500)
        filled: list[str] = []
        refusal = fill_refusal(url, page.url, broker)
        if refusal:
            playbook = None
        if playbook:
            for key, selector in playbook.fields.items():
                val = values.get(key)
                if not val:
                    continue
                try:
                    loc = page.locator(selector).first
                    if loc.count():
                        loc.fill(val, timeout=5_000)
                        filled.append(key)
                except Exception:
                    continue
            if playbook.stop_before:
                with contextlib.suppress(Exception):
                    page.locator(playbook.stop_before).first.scroll_into_view_if_needed(
                        timeout=5_000
                    )
        cap_before = _snapshot(page, url)
        before_id = record_browser(
            conn,
            "forms",
            cap_before,
            note=f"form before submit, request {request_id}; filled {filled}",
        )
        conn.execute("UPDATE requests SET capture_before=? WHERE id=?", (before_id, request_id))
        engine.add_event(
            conn,
            request_id,
            "form_prefilled",
            (
                f"nothing filled: {refusal}; check the address before typing anything"
                if refusal
                else f"filled {', '.join(filled) or 'nothing (no playbook match)'}"
            )
            + "; waiting for you",
            before_id,
        )
        conn.commit()
        # Now it is yours. Record every navigation; stop when the page closes or time runs out.
        last_cap = cap_before
        last_url = page.url
        deadline = time.monotonic() + timeout_s
        closed = False
        while time.monotonic() < deadline:
            try:
                if page.is_closed():
                    closed = True
                    break
                page.wait_for_timeout(1500)
                if page.url != last_url:
                    last_url = page.url
                    page.wait_for_timeout(1500)
                    last_cap = _snapshot(page, url)
            except Exception:
                closed = True
                break
        after_id = record_browser(conn, "forms", last_cap, note=f"form after, request {request_id}")
        if closed and last_cap is not cap_before:
            # The window was open for a while: only move a request that is still where it
            # was when it opened, so a cancellation made meanwhile is not undone.
            if engine.mark_sent_if(
                conn,
                request_id,
                "submitted",
                OPENABLE_STATES,
                f"form submitted in the browser; final page {last_cap.final_url}",
                after_id,
            ):
                outcome = "submitted"
            else:
                state = engine.get(conn, request_id)["state"]
                engine.add_event(
                    conn,
                    request_id,
                    "form_submitted_late",
                    f"the form moved on to {last_cap.final_url}, but the request was already "
                    f"{state}; state left unchanged, evidence kept",
                    after_id,
                )
                outcome = f"form moved on, but the request is {state}; left unchanged"
        elif closed:
            engine.add_event(
                conn,
                request_id,
                "form_closed",
                "window closed without navigating away; use requests_mark if you did submit",
                after_id,
            )
            outcome = "closed without submission"
        else:
            engine.add_event(
                conn, request_id, "form_timeout", f"no action within {timeout_s}s", after_id
            )
            outcome = "timed out"
        conn.commit()
        audit.append("form.done", request_id=request_id, outcome=outcome)
        return outcome


def _document_id(page) -> tuple[str, object]:
    """Identifies the loaded document: its URL and the time its navigation started."""
    return page.url, page.evaluate("performance.timeOrigin")


def _snapshot(page, requested_url: str, attempts: int = 3):
    """HTML, screenshot, URL and title of one document. If the page navigates while they
    are being read the parts would describe different documents, so the capture is taken
    again; if it never holds still, only the HTML and the URL read beside it are kept."""
    from unlist.scanners.brokers.browser import BrowserCapture

    html, final_url = "", page.url
    for _ in range(attempts):
        try:
            before = _document_id(page)
        except Exception:
            before = None
        html = page.content()
        final_url = page.url
        try:
            png = page.screenshot(full_page=True)
        except Exception:
            png = b""
        try:
            title = page.title()
            stable = before is not None and _document_id(page) == before
        except Exception:
            title, stable = "", False
        if stable:
            break
    else:
        png, title = b"", ""
    return BrowserCapture(
        requested_url=requested_url,
        final_url=final_url,
        status=None,
        html=html.encode("utf-8"),
        png=png,
        captured_at=now_iso(),
        title=title,
    )
