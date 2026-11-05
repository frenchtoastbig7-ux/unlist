"""The exposure score: one number, 0 to 100, for how findable and how breached a subject
is right now. Higher is worse. Every point is explained in the breakdown, and removing a
listing or closing an account lowers it."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import date

from unlist.core.timeutil import now_iso

SENSITIVE = ("password", "security question", "social security", "ssn", "credit card",
             "bank account", "government issued", "passport", "driver", "biometric")  # fmt: skip
LIVE = ("confirmed", "requested", "reappeared")


@dataclass
class Component:
    name: str
    points: float
    cap: float
    detail: str


def label_for(score: int) -> str:
    if score >= 75:
        return "severe"
    if score >= 50:
        return "high"
    if score >= 20:
        return "moderate"
    return "low"


def _rows(conn: sqlite3.Connection, sql: str, *args) -> list[sqlite3.Row]:
    try:
        return conn.execute(sql, args).fetchall()
    except sqlite3.OperationalError:
        return []


def exposure_score(
    conn: sqlite3.Connection, subject_id: str, today: date | None = None
) -> tuple[int, list[Component]]:
    today = today or date.today()
    comps: list[Component] = []

    # People-search listings that are live right now: the thing a stranger uses to find you.
    listings = _rows(conn, "SELECT * FROM findings WHERE subject_id=?", subject_id)
    live = [f for f in listings if f["status"] in LIVE]
    pts = 0.0
    with_phone = with_place = 0
    for f in live:
        ex = json.loads(f["extract_json"] or "{}")
        pts += 6
        if ex.get("phones"):
            pts += 2
            with_phone += 1
        if ex.get("places"):
            pts += 2
            with_place += 1
    comps.append(Component(
        "live listings", min(pts, 40), 40,
        f"{len(live)} live ({with_place} show places, {with_phone} show a phone)",
    ))  # fmt: skip
    cands = [f for f in listings if f["status"] == "candidate"]
    comps.append(
        Component("unreviewed candidates", min(len(cands), 5), 5, f"{len(cands)} to review")
    )

    # Breaches, weighted by what leaked and how recently.
    hits = _rows(conn, "SELECT * FROM breach_hits WHERE subject_id=?", subject_id)
    by_name: dict[str, dict] = {}
    for h in hits:
        if (h["kind"] if "kind" in h.keys() else "breach") != "breach":  # noqa: SIM118
            continue
        d = by_name.setdefault(h["breach_name"], {"classes": set(), "date": h["breach_date"] or ""})
        d["classes"].update(c.lower() for c in json.loads(h["data_classes_json"] or "[]"))
    pts = 0.0
    sensitive_n = recent_n = 0
    for d in by_name.values():
        p = 2.0
        if any(tok in c for c in d["classes"] for tok in SENSITIVE):
            p += 3
            sensitive_n += 1
        year = d["date"][:4]
        if year.isdigit() and int(year) >= today.year - 2:
            p *= 1.5
            recent_n += 1
        pts += p
    comps.append(Component(
        "breaches", min(pts, 30), 30,
        f"{len(by_name)} breach(es); {sensitive_n} with passwords or identity data, {recent_n} recent",
    ))  # fmt: skip

    pastes = [h for h in hits if "kind" in h.keys() and h["kind"] == "paste"]  # noqa: SIM118
    stealer = [h for h in hits if "kind" in h.keys() and h["kind"] == "stealer"]  # noqa: SIM118
    comps.append(Component(
        "pastes and stealer logs", min(3 * len(pastes) + 8 * len(stealer), 20), 20,
        f"{len(pastes)} paste(s), {len(stealer)} site(s) in infostealer logs",
    ))  # fmt: skip

    exposures = _rows(conn, "SELECT * FROM exposures WHERE subject_id=?", subject_id)
    accounts = [e for e in exposures if e["kind"] == "account" and e["status"] == "confirmed"]
    comps.append(Component("public accounts", min(0.5 * len(accounts), 5), 5,
                           f"{len(accounts)} confirmed account(s) under your usernames"))  # fmt: skip
    mentions = [
        e for e in exposures
        if e["kind"] == "mention" and e["status"] == "confirmed"
        and not json.loads(e["detail_json"] or "{}").get("broker")
    ]  # fmt: skip
    comps.append(Component("web mentions", min(2 * len(mentions), 6), 6,
                           f"{len(mentions)} confirmed page(s) outside broker sites"))  # fmt: skip
    domain_issues = [
        e for e in exposures
        if e["kind"] == "domain" and e["status"] == "confirmed" and e["source"] == "dns"
    ]  # fmt: skip
    comps.append(Component("owned domains", min(3 * len(domain_issues), 6), 6,
                           f"{len(domain_issues)} email-spoofing issue(s)"))  # fmt: skip
    overdue = _rows(
        conn, "SELECT id FROM requests WHERE subject_id=? AND state='overdue'", subject_id
    )
    comps.append(
        Component("overdue requests", min(2 * len(overdue), 6), 6, f"{len(overdue)} overdue")
    )

    total = int(min(100.0, sum(c.points for c in comps)) + 0.5)  # half rounds up, always
    return total, comps


def record_score(conn: sqlite3.Connection, subject_id: str) -> tuple[int, list[Component], bool]:
    """Compute and append to the history when the score or its parts changed."""
    score, comps = exposure_score(conn, subject_id)
    breakdown = json.dumps([[c.name, c.points, c.detail] for c in comps])
    last = conn.execute(
        "SELECT score, breakdown_json FROM score_history WHERE subject_id=? ORDER BY id DESC LIMIT 1",
        (subject_id,),
    ).fetchone()
    changed = last is None or last["score"] != score or last["breakdown_json"] != breakdown
    if changed:
        conn.execute(
            "INSERT INTO score_history(subject_id, at, score, breakdown_json) VALUES (?,?,?,?)",
            (subject_id, now_iso(), score, breakdown),
        )
        conn.commit()
    return score, comps, changed


def trend(conn: sqlite3.Connection, subject_id: str, n: int = 12) -> list[tuple[str, int]]:
    rows = _rows(
        conn,
        "SELECT at, score FROM score_history WHERE subject_id=? ORDER BY id DESC LIMIT ?",
        subject_id, n,
    )  # fmt: skip
    return [(r["at"], r["score"]) for r in reversed(rows)]


def score_markdown(conn: sqlite3.Connection, subject_id: str) -> str:
    from unlist.core.report import table

    score, comps, _ = record_score(conn, subject_id)
    lines = [f"**Exposure score: {score} / 100 ({label_for(score)})**. Higher is worse.", ""]
    lines.append(table(
        ["component", "points", "of", "why"],
        [[c.name, f"{c.points:g}", f"{c.cap:g}", c.detail] for c in comps],
    ))  # fmt: skip
    t = trend(conn, subject_id)
    if len(t) > 1:
        lines += ["", "Trend: " + " → ".join(f"{s} ({at[:10]})" for at, s in t)]
    return "\n".join(lines)
