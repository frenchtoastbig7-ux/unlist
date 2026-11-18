"""SQLite persistence for subjects, identifiers and consents."""

from __future__ import annotations

import json
import sqlite3
from datetime import date

from unlist.core.timeutil import iso_z, now_iso, parse_dt
from unlist.subjects.models import Consent, ConsentError, Identifier, IdentifierKind, Subject


class SubjectRepo:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    # subjects -------------------------------------------------------------------

    def add(self, subject: Subject) -> Subject:
        self.conn.execute(
            """INSERT INTO subjects(id, label, kind, residency_state, residency_country, note,
                                    created_at) VALUES (?,?,?,?,?,?,?)""",
            (
                subject.id,
                subject.label,
                subject.kind,
                subject.residency_state,
                subject.residency_country,
                subject.note,
                iso_z(subject.created_at),
            ),
        )
        self.conn.commit()
        if subject.consent:
            self.grant_consent(subject.id, subject.consent)
        for ident in subject.identifiers:
            self.add_identifier(subject.id, ident)
        return self.get(subject.id)

    def update(self, subject_id: str, **fields: object) -> Subject:
        allowed = {"label", "residency_state", "residency_country", "note"}
        bad = set(fields) - allowed
        if bad:
            raise ValueError(f"cannot update {sorted(bad)}")
        if not fields:
            return self.get(subject_id)
        current = self.get(subject_id)
        merged = current.model_copy(update=fields)
        Subject.model_validate(merged.model_dump())
        sets = ", ".join(f"{k} = ?" for k in fields)
        self.conn.execute(
            f"UPDATE subjects SET {sets} WHERE id = ?", (*fields.values(), subject_id)
        )
        self.conn.commit()
        return self.get(subject_id)

    def delete(self, subject_id: str) -> None:
        self.conn.execute("DELETE FROM subjects WHERE id = ?", (subject_id,))
        self.conn.commit()

    def get(self, subject_id: str) -> Subject:
        row = self.conn.execute("SELECT * FROM subjects WHERE id = ?", (subject_id,)).fetchone()
        if row is None:
            raise KeyError(f"no subject {subject_id!r}")
        return self._hydrate(row)

    def exists(self, subject_id: str) -> bool:
        return (
            self.conn.execute("SELECT 1 FROM subjects WHERE id = ?", (subject_id,)).fetchone()
            is not None
        )

    def list(self) -> list[Subject]:
        rows = self.conn.execute("SELECT * FROM subjects ORDER BY created_at, id").fetchall()
        return [self._hydrate(r) for r in rows]

    def _hydrate(self, row: sqlite3.Row) -> Subject:
        created = parse_dt(row["created_at"])
        return Subject(
            id=row["id"],
            label=row["label"],
            kind=row["kind"],
            residency_state=row["residency_state"],
            residency_country=row["residency_country"],
            note=row["note"] or "",
            consent=self.consent_for(row["id"]),
            identifiers=self.identifiers_for(row["id"]),
            created_at=created,
        )

    # consent --------------------------------------------------------------------

    def grant_consent(self, subject_id: str, consent: Consent) -> Consent:
        if not self.exists(subject_id):
            raise KeyError(f"no subject {subject_id!r}")
        self.conn.execute(
            """INSERT INTO consents(subject_id, holder, instrument, granted, expires, scope_note,
                                    recorded_at) VALUES (?,?,?,?,?,?,?)""",
            (
                subject_id,
                consent.holder,
                consent.instrument,
                consent.granted.isoformat(),
                consent.expires.isoformat(),
                consent.scope_note,
                now_iso(),
            ),
        )
        self.conn.commit()
        return consent

    def consent_for(self, subject_id: str) -> Consent | None:
        row = self.conn.execute(
            "SELECT * FROM consents WHERE subject_id = ? ORDER BY id DESC LIMIT 1", (subject_id,)
        ).fetchone()
        if row is None:
            return None
        return Consent(
            holder=row["holder"],
            instrument=row["instrument"],
            granted=date.fromisoformat(row["granted"]),
            expires=date.fromisoformat(row["expires"]),
            scope_note=row["scope_note"],
        )

    def require(self, subject_id: str, when: date | None = None) -> Subject:
        """The subject, or ConsentError. Every network or outbound action starts here."""
        try:
            subject = self.get(subject_id)
        except KeyError as exc:
            raise ConsentError(str(exc)) from exc
        subject.require_consent(when)
        return subject

    # identifiers ----------------------------------------------------------------

    def add_identifier(self, subject_id: str, ident: Identifier) -> Identifier:
        if not self.exists(subject_id):
            raise KeyError(f"no subject {subject_id!r}")
        ident = ident.model_copy(update={"subject_id": subject_id})
        cur = self.conn.execute(
            """INSERT INTO identifiers(subject_id, kind, value, current, meta_json, note, added_at)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(subject_id, kind, value) DO UPDATE SET
                 current = excluded.current, meta_json = excluded.meta_json,
                 note = excluded.note""",
            (
                subject_id,
                ident.kind,
                ident.value,
                1 if ident.current else 0,
                ident.meta_json,
                ident.note,
                iso_z(ident.added_at),
            ),
        )
        self.conn.commit()
        if cur.lastrowid:
            ident.id = int(cur.lastrowid)
        return ident

    def remove_identifier(self, identifier_id: int) -> None:
        self.conn.execute("DELETE FROM identifiers WHERE id = ?", (identifier_id,))
        self.conn.commit()

    def identifiers_for(
        self, subject_id: str, kind: IdentifierKind | None = None
    ) -> list[Identifier]:
        sql = "SELECT * FROM identifiers WHERE subject_id = ?"
        args: list[object] = [subject_id]
        if kind:
            sql += " AND kind = ?"
            args.append(kind)
        sql += " ORDER BY kind, id"
        out = []
        for r in self.conn.execute(sql, args):
            out.append(
                Identifier(
                    id=r["id"],
                    subject_id=r["subject_id"],
                    kind=r["kind"],
                    value=r["value"],
                    current=bool(r["current"]),
                    meta=json.loads(r["meta_json"] or "{}"),
                    note=r["note"] or "",
                    added_at=parse_dt(r["added_at"]),
                )
            )
        return out
