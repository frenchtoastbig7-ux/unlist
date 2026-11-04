from datetime import date

import pytest

from unlist.subjects import Consent, ConsentError, Identifier, Subject, SubjectRepo


def make_subject(**kw):
    base = {
        "id": "me",
        "label": "Operator",
        "kind": "self",
        "residency_state": "ca",
        "consent": Consent(
            holder="Operator",
            instrument="self-declaration: my own data",
            granted=date(2026, 11, 1),
            expires=date(2027, 11, 1),
        ),
    }
    base.update(kw)
    return Subject(**base)


def test_consent_expired_refuses():
    s = make_subject()
    s.require_consent(date(2026, 12, 1))
    with pytest.raises(ConsentError):
        s.require_consent(date(2027, 11, 2))
    with pytest.raises(ConsentError):
        s.require_consent(date(2026, 10, 1))


def test_no_consent_refuses():
    with pytest.raises(ConsentError):
        make_subject(consent=None).require_consent()


def test_instrument_must_be_substantive():
    with pytest.raises(ValueError):
        Consent(holder="x", instrument="ok", granted=date(2026, 1, 1), expires=date(2027, 1, 1))


def test_residency_drives_regime():
    assert make_subject().legal_regime == "ccpa"
    assert make_subject(residency_state="TX").legal_regime == "tx"
    assert make_subject(residency_state="AL").legal_regime == "none"
    assert make_subject(residency_state=None, residency_country="de").legal_regime == "gdpr"
    with pytest.raises(ValueError):
        make_subject(residency_state="ZZ")


def test_identifier_normalisation():
    e = Identifier(subject_id="me", kind="email", value="  Me@Example.COM ")
    assert e.value == "me@example.com"
    p = Identifier(subject_id="me", kind="phone", value="(415) 555-0100")
    assert p.value == "14155550100"
    n = Identifier(subject_id="me", kind="name", value="Jane   Q  Doe", meta={"state": "ca"})
    assert n.value == "Jane Q Doe" and n.meta["state"] == "CA"
    with pytest.raises(ValueError):
        Identifier(subject_id="me", kind="email", value="not-an-email")
    with pytest.raises(ValueError):
        Identifier(subject_id="me", kind="dob", value="1/2/1980")


def test_repo_roundtrip(conn):
    repo = SubjectRepo(conn)
    s = make_subject()
    s.identifiers = [
        Identifier(subject_id="me", kind="name", value="Jane Doe", meta={"city": "Oakland", "state": "CA"}),
        Identifier(subject_id="me", kind="email", value="jane@example.com"),
    ]
    repo.add(s)
    got = repo.get("me")
    assert got.consent.expires == date(2027, 11, 1)
    assert {i.kind for i in got.identifiers} == {"name", "email"}
    assert got.of_kind("name")[0].meta == {"city": "Oakland", "state": "CA"}
    # upsert on the same (kind, value) updates rather than duplicating
    repo.add_identifier("me", Identifier(subject_id="me", kind="email", value="JANE@example.com", note="work"))
    emails = repo.identifiers_for("me", "email")
    assert len(emails) == 1 and emails[0].note == "work"
    # latest consent wins
    repo.grant_consent("me", Consent(holder="Operator", instrument="renewed declaration", granted=date(2027, 1, 1), expires=date(2028, 1, 1)))
    assert repo.get("me").consent.expires == date(2028, 1, 1)
    assert repo.require("me", date(2027, 6, 1)).id == "me"
    with pytest.raises(ConsentError):
        repo.require("me", date(2028, 2, 1))
    with pytest.raises(ConsentError):
        repo.require("nobody")
    repo.delete("me")
    assert repo.list() == []
    assert conn.execute("SELECT COUNT(*) FROM identifiers").fetchone()[0] == 0
