"""Subjects, identifiers and consent.

The shape encodes the tool's central constraint: nothing is searched for, drafted or
sent unless it is tied to a subject whose consent is on record and has not lapsed.
For yourself the instrument is a self-declaration; for a household member it is the
text of what they agreed to, with an expiry you will have to renew.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, date, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

IdentifierKind = Literal[
    "name", "alias", "email", "phone", "address", "dob", "username", "relative"
]
SubjectKind = Literal["self", "household"]

US_STATES = {
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "DC", "FL", "GA", "HI", "ID", "IL", "IN", "IA",
    "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS", "MO", "MT", "NE", "NV", "NH", "NJ", "NM",
    "NY", "NC", "ND", "OH", "OK", "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA",
    "WV", "WI", "WY", "PR",
}  # fmt: skip

_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class ConsentError(RuntimeError):
    """Raised when an action is attempted for a subject without consent in force."""


def utcnow() -> datetime:
    return datetime.now(UTC)


class Consent(BaseModel):
    holder: str = Field(description="Who gave the consent (the subject themself, or a guardian)")
    instrument: str = Field(description="What was agreed: self-declaration, or the words used")
    granted: date
    expires: date
    scope_note: str = ""

    @field_validator("instrument")
    @classmethod
    def _instrument_is_substantive(cls, v: str) -> str:
        if len(v.strip()) < 8:
            raise ValueError("instrument must say what was agreed (at least 8 characters)")
        return v.strip()

    def check(self, when: date | None = None) -> None:
        today = when or utcnow().date()
        if today < self.granted:
            raise ConsentError(
                f"Consent ({self.instrument}) does not take effect until {self.granted}."
            )
        if today > self.expires:
            raise ConsentError(
                f"Consent ({self.instrument}) expired on {self.expires}. Nothing runs for this "
                "subject until it is renewed with consent_grant."
            )

    def days_left(self, when: date | None = None) -> int:
        return (self.expires - (when or utcnow().date())).days


def normalise_phone(value: str) -> str:
    """Digits only; a leading US country code is kept so 10 and 11 digit forms compare equal."""
    digits = re.sub(r"\D", "", value)
    if len(digits) == 10:
        digits = "1" + digits
    return digits


class Identifier(BaseModel):
    """One thing a broker might index you by.

    meta carries structure the matcher uses: for name/alias and address, city, state and
    zip; for address also from_year/to_year; for relative, the relation. value is the
    normalised text (emails lowercased, phones digits only, names whitespace-collapsed).
    """

    id: int | None = None
    subject_id: str
    kind: IdentifierKind
    value: str
    current: bool = True
    meta: dict[str, Any] = Field(default_factory=dict)
    note: str = ""
    added_at: datetime = Field(default_factory=utcnow)

    @field_validator("value")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = " ".join(v.split())
        if not v:
            raise ValueError("value must not be empty")
        return v

    def model_post_init(self, __context: Any) -> None:
        if self.kind == "email":
            self.value = self.value.lower()
            if not _EMAIL.match(self.value):
                raise ValueError(f"not an email address: {self.value}")
        elif self.kind == "phone":
            self.value = normalise_phone(self.value)
            if len(self.value) < 10:
                raise ValueError("phone needs at least 10 digits")
        elif self.kind == "dob":
            try:
                date.fromisoformat(self.value)
            except ValueError as exc:
                raise ValueError("dob must be YYYY-MM-DD") from exc
        state = self.meta.get("state")
        if state:
            self.meta["state"] = str(state).upper()

    @property
    def meta_json(self) -> str:
        return json.dumps(self.meta, sort_keys=True, ensure_ascii=False)


class Subject(BaseModel):
    id: str
    label: str
    kind: SubjectKind = "self"
    residency_state: str | None = None
    residency_country: str = "US"
    note: str = ""
    consent: Consent | None = None
    identifiers: list[Identifier] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)

    @field_validator("id")
    @classmethod
    def _slug(cls, v: str) -> str:
        if not _SLUG.match(v):
            raise ValueError("id must be a short slug: lowercase letters, digits, hyphens")
        return v

    @field_validator("residency_state")
    @classmethod
    def _state(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        v = v.upper()
        if v not in US_STATES:
            raise ValueError(f"unknown US state code {v!r}")
        return v

    @field_validator("residency_country")
    @classmethod
    def _country(cls, v: str) -> str:
        v = v.upper()
        if len(v) != 2:
            raise ValueError("residency_country is a two-letter ISO code")
        return v

    def require_consent(self, when: date | None = None) -> None:
        if self.consent is None:
            raise ConsentError(
                f"No consent recorded for subject {self.id!r}. Use consent_grant first."
            )
        self.consent.check(when)

    def of_kind(self, kind: IdentifierKind, current_only: bool = False) -> list[Identifier]:
        return [
            i for i in self.identifiers if i.kind == kind and (i.current or not current_only)
        ]

    @property
    def is_california(self) -> bool:
        return self.residency_country == "US" and self.residency_state == "CA"

    @property
    def is_eu(self) -> bool:
        return self.residency_country in EU_EEA_UK

    @property
    def legal_regime(self) -> str:
        """The strongest regime a request can cite: ccpa, gdpr, a state code, or none."""
        if self.is_california:
            return "ccpa"
        if self.is_eu:
            return "gdpr"
        if self.residency_country == "US" and self.residency_state in STATE_PRIVACY_LAWS:
            return self.residency_state.lower()
        return "none"


EU_EEA_UK = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT",
    "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "IS", "LI", "NO",
    "GB",
}  # fmt: skip

# Comprehensive state privacy laws in force as of 2026-11 that grant a deletion right.
# Value: (short name, statute cite, deletion response window in days).
STATE_PRIVACY_LAWS: dict[str, tuple[str, str, int]] = {
    "CA": ("CCPA/CPRA", "Cal. Civ. Code § 1798.105", 45),
    "VA": ("VCDPA", "Va. Code § 59.1-577", 45),
    "CO": ("CPA", "Colo. Rev. Stat. § 6-1-1306", 45),
    "CT": ("CTDPA", "Conn. Gen. Stat. § 42-518", 45),
    "UT": ("UCPA", "Utah Code § 13-61-201", 45),
    "TX": ("TDPSA", "Tex. Bus. & Com. Code § 541.051", 45),
    "OR": ("OCPA", "ORS 646A.574", 45),
    "MT": ("MCDPA", "Mont. Code § 30-14-2808", 45),
    "IA": ("ICDPA", "Iowa Code § 715D.3", 90),
    "DE": ("DPDPA", "6 Del. C. § 12D-104", 45),
    "NH": ("NHPA", "RSA 507-H:4", 45),
    "NJ": ("NJDPA", "N.J.S.A. 56:8-166.8", 45),
    "TN": ("TIPA", "Tenn. Code § 47-18-3203", 45),
    "MN": ("MCDPA", "Minn. Stat. § 325O.05", 45),
    "MD": ("MODPA", "Md. Code Com. Law § 14-4605", 45),
    "IN": ("INCDPA", "Ind. Code § 24-15-3-1", 45),
    "KY": ("KCDPA", "KRS 367.3613", 45),
    "RI": ("RIDTPPA", "R.I. Gen. Laws § 6-48.1-5", 45),
    "NE": ("NDPA", "Neb. Rev. Stat. § 87-1104", 45),
}
