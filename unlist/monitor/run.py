"""run_due: everything that should happen on a schedule, in one call."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
from dataclasses import dataclass, field
from datetime import timedelta

from unlist import paths
from unlist.core.audit import AuditLog
from unlist.core.report import table, write_report
from unlist.core.timeutil import (
    format_interval,
    is_due,
    iso_z,
    now_iso,
    parse_dt,
    parse_interval,
    utcnow,
)
from unlist.requests import engine
from unlist.scanners.brokers import findings as F
from unlist.subjects import ConsentError, SubjectRepo

# name -> (default interval, description)
JOBS: dict[str, tuple[str, str]] = {
    "breaches": ("7d", "re-run breach lookups for every subject"),
    "verify_listings": ("14d", "re-open requested and removed listings"),
    "brokers_full": ("30d", "full people-search sweep for every subject"),
    "deadlines": ("1d", "mark requests past their legal deadline overdue"),
    "drop_cycle": ("1d", "remind about the 45-day DROP cycle"),
    "followups": ("1d", "draft follow-ups for listings that reappeared"),
    "inbox": ("1d", "read the opt-out mailbox if configured"),
    "send_queue": ("1d", "send the day's share of approved email requests"),
    "usernames": ("30d", "re-check where the subjects' usernames exist"),
    "domains": ("7d", "re-check SPF, DMARC and certificate logs for owned domains"),
    "score": ("1d", "recompute exposure scores and note changes"),
}

ESCALATION = {
    "CA": "File a complaint with the California Privacy Protection Agency "
    "(cppa.ca.gov/complaints) or the Attorney General (oag.ca.gov/contact/"
    "consumer-complaint-against-business-or-company). Under Cal. Civ. Code § 1798.155 "
    "the CPPA may fine $2,500 per violation ($7,500 if intentional).",
    "TX": "File with the Texas Attorney General (texasattorneygeneral.gov/consumer-protection/"
    "file-consumer-complaint); the TDPSA gives a 30-day cure period after notice.",
    "VT": "File with the Vermont Attorney General Consumer Assistance Program "
    "(ago.vermont.gov/cap).",
    "OR": "File with the Oregon Department of Justice (justice.oregon.gov/consumercomplaints).",
    "GB": "Complain to the ICO (ico.org.uk/make-a-complaint) after the one-month deadline.",
    "EU": "Complain to your national supervisory authority "
    "(edpb.europa.eu/about-edpb/about-edpb/members_en).",
}
GENERIC_ESCALATION = (
    "Send a second request citing the first (tag in the subject line) and the missed deadline."
)


@dataclass
class RunSummary:
    ran: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    changes: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    report_path: str | None = None

    @property
    def changed(self) -> bool:
        return bool(self.changes)


def _job_interval(conn: sqlite3.Connection, name: str) -> int:
    row = conn.execute("SELECT interval_seconds FROM jobs WHERE name=?", (name,)).fetchone()
    if row:
        return int(row["interval_seconds"])
    seconds = parse_interval(JOBS[name][0])
    conn.execute("INSERT OR IGNORE INTO jobs(name, interval_seconds) VALUES (?,?)", (name, seconds))
    conn.commit()
    return seconds


def _due(conn: sqlite3.Connection, name: str, force: bool) -> bool:
    interval = _job_interval(conn, name)
    if force:
        return True
    row = conn.execute("SELECT last_run FROM jobs WHERE name=?", (name,)).fetchone()
    return is_due(row["last_run"] if row else None, interval)


def _done(conn: sqlite3.Connection, name: str, result: str) -> None:
    conn.execute(
        "UPDATE jobs SET last_run=?, last_result=? WHERE name=?", (now_iso(), result[:500], name)
    )
    conn.commit()


def set_interval(conn: sqlite3.Connection, name: str, interval: str) -> None:
    if name not in JOBS:
        raise ValueError(f"unknown job {name!r}; one of {', '.join(JOBS)}")
    seconds = parse_interval(interval)
    conn.execute(
        "INSERT INTO jobs(name, interval_seconds) VALUES (?,?) "
        "ON CONFLICT(name) DO UPDATE SET interval_seconds=excluded.interval_seconds",
        (name, seconds),
    )
    conn.commit()


def jobs_status(conn: sqlite3.Connection) -> list[list[object]]:
    rows = []
    for name, (_default, desc) in JOBS.items():
        interval = _job_interval(conn, name)
        row = conn.execute(
            "SELECT last_run, last_result FROM jobs WHERE name=?", (name,)
        ).fetchone()
        last = row["last_run"] if row else None
        nxt = ""
        if last:
            dt = parse_dt(last)
            if dt:
                nxt = iso_z(dt + timedelta(seconds=interval))
        rows.append(
            [
                name,
                format_interval(interval),
                last or "never",
                nxt or "now",
                (row["last_result"] if row else "") or "",
                desc,
            ]
        )
    return rows


def run_due(
    conn: sqlite3.Connection,
    *,
    force: bool = False,
    use_browser: bool = True,
    only: set[str] | None = None,
    notify: bool = True,
) -> RunSummary:
    s = RunSummary()
    audit = AuditLog()
    audit.append("monitor.run.start", force=force)
    repo = SubjectRepo(conn)
    subjects = []
    for subj in repo.list():
        try:
            subj.require_consent()
            subjects.append(subj)
        except ConsentError as exc:
            s.problems.append(str(exc))

    def selected(name: str) -> bool:
        return (only is None or name in only) and _due(conn, name, force)

    browser = None
    try:
        if use_browser and any(selected(n) for n in ("verify_listings", "brokers_full")):
            try:
                from unlist.scanners.brokers.browser import BrowserSession

                browser = BrowserSession()
                browser.start()
            except Exception as exc:
                s.problems.append(f"browser unavailable, HTTP only: {exc}")
                browser = None
        for name in JOBS:
            if only is not None and name not in only:
                continue
            if not _due(conn, name, force):
                s.skipped.append(name)
                continue
            s.ran.append(name)
            _JOB_FUNCS[name](conn, subjects, s, browser)
    finally:
        if browser is not None:
            browser.close()

    s.report_path = str(_write_report(conn, s))
    audit.append("monitor.run.finish", ran=s.ran, changes=len(s.changes), problems=len(s.problems))
    if notify and s.changes:
        notify_mac("unlist", f"{len(s.changes)} change(s); see the monitor report")
    return s


def _job_breaches(conn, subjects, s: RunSummary, _browser) -> None:
    from unlist.scanners.breaches import scan_breaches

    total_new = 0
    for subj in subjects:
        try:
            res = scan_breaches(conn, subj.id)
        except Exception as exc:
            s.problems.append(f"breaches {subj.id}: {exc}")
            continue
        total_new += res.new_hits
        if res.new_hits:
            s.changes.append(f"{subj.id}: {res.new_hits} new breach hit(s)")
        s.problems.extend(f"breaches {subj.id}: {e}" for e in res.errors)
    _done(conn, "breaches", f"{total_new} new")


def _job_verify(conn, subjects, s: RunSummary, browser) -> None:
    from unlist.scanners.brokers import verify_finding

    gone = back = unknown = 0
    for subj in subjects:
        for row in F.list_for(conn, subj.id):
            if row["status"] not in ("requested", "removed", "confirmed", "reappeared"):
                continue
            try:
                verdict, _detail = verify_finding(conn, row["id"], browser=browser)
            except Exception as exc:
                s.problems.append(f"verify {row['id']}: {exc}")
                continue
            if verdict == "gone" and row["status"] != "removed":
                gone += 1
                s.changes.append(f"{subj.id}: listing {row['id']} at {row['broker_id']} is gone")
                _close_requests_for_finding(conn, row["id"])
            elif verdict == "present" and row["status"] == "removed":
                back += 1
                s.changes.append(f"{subj.id}: listing {row['id']} at {row['broker_id']} REAPPEARED")
            elif verdict == "unknown":
                unknown += 1
    _done(conn, "verify_listings", f"{gone} gone, {back} back, {unknown} unknown")


def _close_requests_for_finding(conn, finding_id: int) -> None:
    for r in engine.list_for(conn, None, "open"):
        fids = json.loads(r["finding_ids_json"] or "[]")
        if finding_id not in fids or r["state"] not in engine.SENT_STATES:
            continue
        remaining = [f for f in fids if F.get(conn, f)["status"] != "removed"]
        if not remaining:
            engine.set_state(conn, r["id"], "verified_removed", "every listing verified gone")


def _job_brokers(conn, subjects, s: RunSummary, browser) -> None:
    from unlist.scanners.brokers import scan_brokers

    total = 0
    for subj in subjects:
        try:
            res = scan_brokers(conn, subj.id, browser=browser)
        except Exception as exc:
            s.problems.append(f"brokers {subj.id}: {exc}")
            continue
        total += res.new_candidates + res.reappeared
        if res.new_candidates:
            s.changes.append(f"{subj.id}: {res.new_candidates} new candidate listing(s) to review")
        if res.reappeared:
            s.changes.append(f"{subj.id}: {res.reappeared} listing(s) reappeared")
        if res.challenged:
            s.problems.append(f"brokers {subj.id}: {res.challenged} site(s) challenged the browser")
    _done(conn, "brokers_full", f"{total} new or back")


def _escalation_for(subj) -> str:
    if subj.residency_country == "US":
        key = subj.residency_state or ""
    elif subj.residency_country == "GB":
        key = "GB"
    elif subj.is_eu:
        key = "EU"
    else:
        key = ""
    return ESCALATION.get(key, GENERIC_ESCALATION)


def _job_deadlines(conn, _subjects, s: RunSummary, _browser) -> None:
    now = now_iso()
    n = 0
    repo = SubjectRepo(conn)
    for r in engine.list_for(conn, None, "open"):
        if r["state"] not in ("sent", "submitted", "awaiting_verification", "acknowledged"):
            continue
        if r["channel"] == "drop" or not r["deadline"] or r["deadline"] > now:
            continue
        advice = _escalation_for(repo.get(r["subject_id"]))
        engine.set_state(conn, r["id"], "overdue", f"deadline {r['deadline'][:10]} passed")
        engine.add_event(conn, r["id"], "escalation_note", advice)
        conn.commit()
        s.changes.append(f"request {r['id']} ({r['broker_id']}) is overdue; escalation note added")
        n += 1
    _done(conn, "deadlines", f"{n} overdue")


def _job_drop(conn, _subjects, s: RunSummary, _browser) -> None:
    now = utcnow()
    n = 0
    for r in engine.list_for(conn, None, "open"):
        if r["channel"] != "drop" or not r["deadline"]:
            continue
        due = parse_dt(r["deadline"])
        if due and due <= now:
            nxt = iso_z(due + timedelta(days=45))
            conn.execute("UPDATE requests SET deadline=? WHERE id=?", (nxt, r["id"]))
            engine.add_event(
                conn,
                r["id"],
                "drop_cycle",
                "45-day cycle passed; check consumer.drop.privacy.ca.gov/dropstatus; "
                f"next {nxt[:10]}",
            )
            conn.commit()
            s.changes.append(f"DROP cycle passed for request {r['id']}; check the status page")
            n += 1
    _done(conn, "drop_cycle", f"{n} cycle(s) passed")


def _job_followups(conn, subjects, s: RunSummary, _browser) -> None:
    n = 0
    for subj in subjects:
        for row in F.list_for(conn, subj.id, "reappeared"):
            if engine.open_for_broker(conn, subj.id, row["broker_id"]):
                continue
            try:
                r = engine.draft_request(conn, subj.id, row["broker_id"], [row["id"]])
            except Exception as exc:
                s.problems.append(f"followup {row['id']}: {exc}")
                continue
            s.changes.append(
                f"drafted follow-up request {r['id']} for reappeared listing {row['id']} "
                f"({row['broker_id']}); approve to send"
            )
            n += 1
    _done(conn, "followups", f"{n} drafted")


def _job_inbox(conn, _subjects, s: RunSummary, _browser) -> None:
    from unlist.requests.inbox import ImapInbox, ImapSettings, process_messages

    settings = ImapSettings.from_env()
    if settings is None:
        _done(conn, "inbox", "not configured")
        return
    try:
        with ImapInbox(settings) as inbox:
            messages = inbox.fetch_unseen()
            results = process_messages(conn, messages)
            for m in messages:
                inbox.mark_seen(m.uid)
    except Exception as exc:
        s.problems.append(f"inbox: {exc}")
        _done(conn, "inbox", f"error: {exc}")
        return
    for r in results:
        s.changes.append(f"mail from {r['from']}: {r['kind']}; {r['action']}")
    _done(conn, "inbox", f"{len(results)} message(s)")


def _job_send_queue(conn, _subjects, s: RunSummary, _browser) -> None:
    from unlist.requests.mailer import Mailer, SmtpSettings

    waiting = [r for r in engine.list_for(conn, None, "approved") if r["channel"] == "email"]
    if not waiting:
        _done(conn, "send_queue", "nothing approved")
        return
    settings = SmtpSettings.from_env()
    if settings is None:
        _done(conn, "send_queue", f"{len(waiting)} approved, no mailbox configured")
        s.problems.append(f"{len(waiting)} approved email request(s) wait for a mailbox in .env")
        return
    results = engine.send_approved(conn, Mailer(settings))
    sent = sum(1 for _, ok, _ in results if ok)
    held = sum(1 for _, ok, d in results if not ok and d.startswith("held"))
    failed = [d for _, ok, d in results if not ok and not d.startswith("held")]
    if sent:
        s.changes.append(f"sent {sent} approved request(s); {held} held for the daily cap")
    s.problems.extend(f"send: {d}" for d in failed)
    _done(conn, "send_queue", f"{sent} sent, {held} held, {len(failed)} failed")


def _job_usernames(conn, subjects, s: RunSummary, _browser) -> None:
    from unlist.scanners.usernames import scan_usernames

    new = 0
    for subj in subjects:
        if not subj.of_kind("username"):
            continue
        try:
            res = scan_usernames(conn, subj.id)
        except Exception as exc:
            s.problems.append(f"usernames {subj.id}: {exc}")
            continue
        new += res.new
        if res.new:
            s.changes.append(f"{subj.id}: {res.new} new account(s) under your usernames to review")
    _done(conn, "usernames", f"{new} new")


def _job_domains(conn, subjects, s: RunSummary, _browser) -> None:
    from unlist.scanners.domains import scan_domains

    issues = 0
    for subj in subjects:
        if not subj.of_kind("domain"):
            continue
        try:
            res = scan_domains(conn, subj.id)
        except Exception as exc:
            s.problems.append(f"domains {subj.id}: {exc}")
            continue
        issues += len(res.issues)
        s.changes.extend(f"{subj.id}: {r}" for r in res.resolved)
        s.problems.extend(f"domains {subj.id}: {e}" for e in res.errors)
    _done(conn, "domains", f"{issues} open issue(s)")


def _job_score(conn, subjects, s: RunSummary, _browser) -> None:
    from unlist.reports.score import label_for, record_score, trend

    notes = []
    for subj in subjects:
        before = trend(conn, subj.id, 1)
        score, _comps, changed = record_score(conn, subj.id)
        notes.append(f"{subj.id} {score}")
        if changed and before and before[-1][1] != score:
            s.changes.append(
                f"{subj.id}: exposure score {before[-1][1]} → {score} ({label_for(score)})"
            )
    _done(conn, "score", ", ".join(notes) or "no subjects")


_JOB_FUNCS = {
    "breaches": _job_breaches,
    "verify_listings": _job_verify,
    "brokers_full": _job_brokers,
    "deadlines": _job_deadlines,
    "drop_cycle": _job_drop,
    "followups": _job_followups,
    "inbox": _job_inbox,
    "send_queue": _job_send_queue,
    "usernames": _job_usernames,
    "domains": _job_domains,
    "score": _job_score,
}


def _write_report(conn, s: RunSummary):
    body = ["## What changed", ""]
    body += [f"- {c}" for c in s.changes] or ["Nothing changed."]
    body += ["", "## Problems", ""]
    body += [f"- {p}" for p in s.problems] or ["None."]
    body += ["", "## Jobs", ""]
    body.append(
        table(["job", "every", "last run", "next", "last result", "what"], jobs_status(conn))
    )
    open_reqs = engine.list_for(conn, None, "open")
    if open_reqs:
        body += ["", "## Open requests", ""]
        body.append(
            table(
                ["id", "subject", "broker", "channel", "state", "deadline"],
                [
                    [
                        r["id"],
                        r["subject_id"],
                        r["broker_id"],
                        r["channel"],
                        r["state"],
                        (r["deadline"] or "")[:10],
                    ]
                    for r in open_reqs
                ],
            )
        )
    return write_report(
        "monitor",
        "run",
        "Monitor run",
        "\n".join(body),
        params={"ran": s.ran, "skipped": s.skipped},
        counts={"changes": len(s.changes), "problems": len(s.problems)},
    )


def notify_mac(title: str, message: str) -> bool:
    """A macOS notification via osascript; silently does nothing elsewhere."""
    if os.uname().sysname != "Darwin" or os.environ.get("UNLIST_NO_NOTIFY"):
        return False
    safe = message.replace('"', "'")
    script = f'display notification "{safe}" with title "{title}"'
    try:
        subprocess.run(["osascript", "-e", script], check=False, capture_output=True, timeout=10)
        return True
    except Exception:
        return False


LAUNCHD_LABEL = "inc.sovereignedge.unlist"


def launchd_plist(repo_dir: str, uv_path: str, hour: int = 9, minute: int = 0) -> str:
    data_dir = str(paths.data_dir())
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{uv_path}</string>
    <string>--directory</string>
    <string>{repo_dir}</string>
    <string>run</string>
    <string>unlist</string>
    <string>run-due</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict><key>UNLIST_DATA_DIR</key><string>{data_dir}</string></dict>
  <key>StartCalendarInterval</key>
  <dict><key>Hour</key><integer>{hour}</integer><key>Minute</key><integer>{minute}</integer></dict>
  <key>StandardOutPath</key><string>{data_dir}/logs/launchd.out</string>
  <key>StandardErrorPath</key><string>{data_dir}/logs/launchd.err</string>
</dict>
</plist>
"""
