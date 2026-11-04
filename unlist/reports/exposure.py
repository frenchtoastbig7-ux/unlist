"""The exposure report: what is known to be out there for one subject, as of now."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from unlist.core.report import table, write_report
from unlist.subjects import SubjectRepo


_SENSITIVE_TOKENS = (
    "password",
    "security question",
    "social security",
    "ssn",
    "credit card",
    "bank account",
    "government issued",
    "passport",
    "driver",
    "biometric",
    "auth token",
    "private messages",
)


def _is_sensitive(data_class: str) -> bool:
    c = data_class.lower()
    return any(tok in c for tok in _SENSITIVE_TOKENS)


def _rows(conn: sqlite3.Connection, sql: str, *args: object) -> list[sqlite3.Row]:
    try:
        return conn.execute(sql, args).fetchall()
    except sqlite3.OperationalError:
        return []


def exposure_markdown(conn: sqlite3.Connection, subject_id: str) -> tuple[str, dict]:
    subject = SubjectRepo(conn).get(subject_id)
    parts: list[str] = []
    counts: dict[str, object] = {}

    hits = _rows(
        conn,
        "SELECT * FROM breach_hits WHERE subject_id=? "
        "ORDER BY COALESCE(breach_date,'') DESC, breach_name",
        subject_id,
    )
    counts["breach_hits"] = len(hits)
    by_name: dict[str, dict] = {}
    for h in hits:
        d = by_name.setdefault(
            h["breach_name"],
            {
                "date": h["breach_date"] or "",
                "domain": h["domain"] or "",
                "emails": set(),
                "sources": set(),
                "classes": set(),
                "first_seen": h["first_seen"],
            },
        )
        d["emails"].add(h["identifier_value"])
        d["sources"].add(h["source"])
        d["classes"].update(json.loads(h["data_classes_json"] or "[]"))
        d["first_seen"] = min(d["first_seen"], h["first_seen"])
    counts["breaches"] = len(by_name)
    parts.append("## Breaches\n")
    if by_name:
        parts.append(
            table(
                ["breach", "date", "domain", "addresses", "data exposed", "sources", "first seen"],
                [
                    [
                        name,
                        d["date"],
                        d["domain"],
                        ", ".join(sorted(d["emails"])),
                        ", ".join(sorted(d["classes"]))[:120],
                        ", ".join(sorted(d["sources"])),
                        d["first_seen"][:10],
                    ]
                    for name, d in by_name.items()
                ],
            )
        )
        sensitive = {c for d in by_name.values() for c in d["classes"] if _is_sensitive(c)}
        if sensitive:
            parts.append(
                "\n**Act on these:** " + ", ".join(sorted(sensitive)) + " appear in at least one breach. "
                "Change the password anywhere it was reused; consider a credit freeze if identity "
                "data is listed."
            )
    else:
        parts.append("No breach hits recorded. Run scan_breaches.")

    findings = _rows(
        conn, "SELECT * FROM findings WHERE subject_id=? ORDER BY status, first_seen", subject_id
    )
    counts["findings"] = len(findings)
    parts.append("\n## People-search listings\n")
    if findings:
        by_status: dict[str, int] = {}
        for f in findings:
            by_status[f["status"]] = by_status.get(f["status"], 0) + 1
        counts["findings_by_status"] = by_status
        parts.append(
            table(
                ["broker", "status", "listing", "score", "first seen", "last seen"],
                [
                    [f["broker_id"], f["status"], f["listing_url"], f["score"], f["first_seen"][:10], f["last_seen"][:10]]
                    for f in findings
                ],
            )
        )
    else:
        parts.append("No listings recorded. Run scan_brokers.")

    requests = _rows(conn, "SELECT * FROM requests WHERE subject_id=? ORDER BY id", subject_id)
    counts["requests"] = len(requests)
    parts.append("\n## Removal requests\n")
    if requests:
        parts.append(
            table(
                ["id", "broker", "channel", "basis", "state", "deadline"],
                [[r["id"], r["broker_id"], r["channel"], r["basis"], r["state"], (r["deadline"] or "")[:10]] for r in requests],
            )
        )
    else:
        parts.append("None yet. Confirm findings, then requests_draft.")

    pw = _rows(conn, "SELECT * FROM password_checks ORDER BY checked_at DESC LIMIT 20")
    if pw:
        parts.append("\n## Password checks (counts only)\n")
        parts.append(table(["label", "seen in breaches", "checked"], [[p["label"], p["pwned_count"], p["checked_at"][:10]] for p in pw]))

    body = "\n".join(parts)
    title = f"Exposure report: {subject.label}"
    return body, {"title": title, "counts": counts}


def write_exposure_report(conn: sqlite3.Connection, subject_id: str) -> tuple[Path, str]:
    body, meta = exposure_markdown(conn, subject_id)
    path = write_report("exposure", subject_id, meta["title"], body, params={"subject": subject_id}, counts=meta["counts"])
    return path, body
