"""Account clean-up: for accounts you confirmed and services that were breached, where to
delete the account and how hard it is; and, where a service takes deletion by email, a
drafted request that goes through the same approval gate as everything else."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from urllib.parse import urlsplit

from unlist.catalog.accounts import DIFFICULTY_ORDER, AccountService, load_accounts
from unlist.core.audit import AuditLog
from unlist.core.timeutil import now_iso
from unlist.requests import engine
from unlist.requests.basis import basis_for, get_basis
from unlist.scanners import exposures as X
from unlist.subjects import SubjectRepo

GOOGLE_RESULTS_URL = "https://myactivity.google.com/results-about-you"
GOOGLE_HELP_URL = "https://support.google.com/websearch/answer/12719076"


@dataclass
class CleanupItem:
    service: str
    why: str
    identifier: str
    profile_url: str
    delete_url: str
    difficulty: str
    notes: str
    email: str
    exposure_id: int | None = None


def cleanup_plan(conn: sqlite3.Connection, subject_id: str) -> list[CleanupItem]:
    """Confirmed accounts and breached services, each with how to delete the account."""
    SubjectRepo(conn).require(subject_id)
    directory = load_accounts()
    items: dict[str, CleanupItem] = {}
    for e in X.list_for(conn, subject_id, "account", "confirmed"):
        host = urlsplit(e["url"] or "").netloc
        svc = directory.find(name=e["title"] or e["key"], host=host)
        items[(e["title"] or e["key"]).lower()] = _item(
            e["title"] or e["key"], "account you confirmed", e["identifier_value"], e["url"] or "",
            svc, e["id"],
        )  # fmt: skip
    rows = conn.execute(
        "SELECT DISTINCT breach_name, title, domain, identifier_value FROM breach_hits "
        "WHERE subject_id=? AND kind='breach'",
        (subject_id,),
    ).fetchall()
    for h in rows:
        name = h["title"] or h["breach_name"]
        svc = directory.find(name=name, host=h["domain"] or "")
        if svc is None:
            continue  # a compilation or a defunct service: no account to delete
        key = svc.name.lower()
        if key in items:
            items[key].why += "; also breached"
            continue
        items[key] = _item(svc.name, "breached service", h["identifier_value"], "", svc, None)
    return sorted(
        items.values(),
        key=lambda i: (DIFFICULTY_ORDER.get(i.difficulty, 5), i.service.lower()),
    )


def _item(name, why, identifier, profile_url, svc: AccountService | None, eid) -> CleanupItem:
    return CleanupItem(
        service=svc.name if svc else name,
        why=why,
        identifier=identifier,
        profile_url=profile_url,
        delete_url=svc.url if svc else "",
        difficulty=svc.difficulty if svc else "unknown",
        notes=svc.notes if svc else "Not in the JustDeleteMe directory; look in account settings.",
        email=svc.email if svc else "",
        exposure_id=eid,
    )


_BASIS_SENTENCE = {
    "ccpa_delete": "I make this request under the California Consumer Privacy Act, "
    "Cal. Civ. Code § 1798.105; you have 45 days to comply.",
    "gdpr_art17": "I make this request under Article 17 of the GDPR; you must respond "
    "within one month.",
}


def draft_account_request(conn: sqlite3.Connection, subject_id: str, service: str) -> sqlite3.Row:
    """An email asking a service to delete the subject's account, as a drafted request."""
    subject = SubjectRepo(conn).require(subject_id)
    svc = load_accounts().find(name=service, host=service if "." in service else "")
    if svc is None:
        raise ValueError(f"{service!r} is not in the account directory")
    if not svc.email:
        raise ValueError(f"{svc.name} does not take deletion by email; use its page: {svc.url}")
    broker_id = "account:" + engine_slug(svc.name)
    if engine.open_for_broker(conn, subject_id, broker_id):
        raise ValueError(f"a request to {svc.name} is already open")
    basis_key = basis_for(subject)
    if basis_key == "ccpa_optout":
        basis_key = "ccpa_delete"
    basis = get_basis(basis_key)
    tag = engine._new_tag(conn)
    usernames = [i.value for i in subject.of_kind("username")]
    sentence = _BASIS_SENTENCE.get(basis_key, "")
    if basis_key.startswith("state_"):
        sentence = (
            f"I make this request under {basis.cite}; you have {basis.window} days to respond."
        )
    body = (
        engine._env.get_template("account_deletion.txt.j2")
        .render(
            broker_name=svc.name,
            basis_sentence=sentence,
            usernames=usernames,
            emails=[i.value for i in subject.of_kind("email") if i.current],
            names=[i.value for i in subject.of_kind("name")] or [subject.label],
            tag=tag,
            agent=subject.kind == "household",
            agent_instrument=subject.consent.instrument if subject.consent else "",
            signature=subject.label,
        )
        .strip()
        + "\n"
    )
    cur = conn.execute(
        """INSERT INTO requests(subject_id, broker_id, channel, basis, state, tag, to_address,
             subject_line, body, listings_json, finding_ids_json, created_at, note)
           VALUES (?,?, 'email', ?, 'drafted', ?, ?, ?, ?, '[]', '[]', ?, ?)""",
        (subject_id, broker_id, basis_key, tag, svc.email,
         f"Account deletion request [{tag}]", body, now_iso(), f"account deletion at {svc.name}"),
    )  # fmt: skip
    rid = int(cur.lastrowid)
    engine.add_event(conn, rid, "drafted", f"account deletion / {basis_key}")
    conn.commit()
    AuditLog().append("request.draft", request_id=rid, subject=subject_id, broker=broker_id,
                      channel="email", basis=basis_key)  # fmt: skip
    return engine.get(conn, rid)


def engine_slug(name: str) -> str:
    from unlist.catalog.importers import slugify

    return slugify(name)


def google_results_prepare(conn: sqlite3.Connection, subject_id: str) -> tuple[str, sqlite3.Row]:
    """What to submit to Google's "Results about you", and a manual request that tracks it."""
    SubjectRepo(conn).require(subject_id)
    urls: list[str] = []
    for f in conn.execute(
        "SELECT listing_url FROM findings WHERE subject_id=? "
        "AND status IN ('confirmed','requested','reappeared')",
        (subject_id,),
    ):
        urls.append(f["listing_url"])
    for e in X.list_for(conn, subject_id, "mention", "confirmed"):
        if e["url"] and e["url"] not in urls:
            urls.append(e["url"])
    lines = [
        "# Google: Results about you",
        "",
        f"1. Open {GOOGLE_RESULTS_URL} signed in to your Google account and add the contact "
        "details you want watched (name, address, phone, email). Google then alerts you itself "
        "when new results show them.",
        "2. For each page below, search for it in Google, open the three-dot menu on the result, "
        "choose Remove result, then 'It shows my personal contact info'.",
        "3. Removal from Search does not remove the page; the requests to the sites themselves "
        "do that. Do both.",
        "",
    ]
    lines += [f"- {u}" for u in urls] or ["- (no confirmed listings or mentions yet)"]
    lines += ["", f"There is no API for this; details: {GOOGLE_HELP_URL}"]
    text = "\n".join(lines)
    row = engine.open_for_broker(conn, subject_id, "google-results")
    if row is None:
        tag = engine._new_tag(conn)
        cur = conn.execute(
            """INSERT INTO requests(subject_id, broker_id, channel, basis, state, tag, form_url,
                 subject_line, body, listings_json, finding_ids_json, created_at, note)
               VALUES (?, 'google-results', 'manual', 'plain', 'drafted', ?, ?, ?, ?, ?, '[]', ?, ?)""",
            (subject_id, tag, GOOGLE_RESULTS_URL, "Google Results about you", text,
             json.dumps(urls), now_iso(), "submit by hand, then mark it submitted"),
        )  # fmt: skip
        engine.add_event(conn, int(cur.lastrowid), "drafted", "manual / google results")
        conn.commit()
        row = engine.get(conn, int(cur.lastrowid))
    else:
        conn.execute(
            "UPDATE requests SET body=?, listings_json=? WHERE id=?",
            (text, json.dumps(urls), row["id"]),
        )
        conn.commit()
        row = engine.get(conn, row["id"])
    return text, row
