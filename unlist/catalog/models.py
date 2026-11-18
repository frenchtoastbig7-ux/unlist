"""Pydantic schema for a catalog entry."""

from __future__ import annotations

import re
from datetime import date
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator, model_validator

Category = Literal["people-search", "background-check", "marketing", "credit", "other"]
OptOutMethod = Literal["form", "email", "account", "drop_only", "mail", "phone", "unknown"]
Requirement = Literal["listing_url", "email_link", "phone_code", "id_upload", "account", "mail_in"]
Captcha = Literal["unknown", "none", "recaptcha", "hcaptcha", "turnstile", "other"]
FetchMode = Literal["http", "browser"]
Origin = Literal["curated", "cppa-registry", "optout-manual", "markup", "operator"]
SearchKind = Literal["name", "phone", "address"]
GENERATED_ORIGINS = ("cppa-registry", "optout-manual")
Status = Literal["active", "defunct", "seized", "merged"]

SEARCH_PLACEHOLDERS = {"first", "last", "middle", "city", "state", "state_full", "zip", "age"}
# phone: 10 digits; phone_dashed NNN-NNN-NNNN; phone_1dashed 1-NNN-NNN-NNNN; phone_e164 1NNNNNNNNNN
PHONE_PLACEHOLDERS = {
    "phone", "phone_dashed", "phone_1dashed", "phone_e164", "area", "prefix", "line",
}  # fmt: skip
# street as typed (percent-encoded); *_slug lowercase with hyphens
ADDRESS_PLACEHOLDERS = {"street", "street_slug", "city", "city_slug", "state", "state_lower", "zip"}
_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_PLACEHOLDER = re.compile(r"\{([a-z0-9_]+)\}")


class Contact(BaseModel):
    privacy_email: str | None = None
    privacy_url: str | None = None
    phone: str | None = None
    postal: str | None = None


class Search(BaseModel):
    """How to look someone up on the site: by name (template), by phone, by street address.

    verified lists the kinds whose URL pattern was confirmed against the live site; the
    rest are documented patterns the scanner still tries and labels as unverified.
    """

    method: Literal["url", "none"] = "none"
    template: str | None = None
    phone_template: str | None = None
    address_template: str | None = None
    fetch: FetchMode = "http"
    verified: list[SearchKind] = Field(default_factory=list)
    notes: str = ""

    @model_validator(mode="after")
    def _template_when_url(self) -> Search:
        if self.method == "url" and not (
            self.template or self.phone_template or self.address_template
        ):
            raise ValueError("search.method url needs a template")
        for kind, tpl, allowed in (
            ("name", self.template, SEARCH_PLACEHOLDERS),
            ("phone", self.phone_template, PHONE_PLACEHOLDERS),
            ("address", self.address_template, ADDRESS_PLACEHOLDERS),
        ):
            if not tpl:
                continue
            bad = set(_PLACEHOLDER.findall(tpl)) - allowed
            if bad:
                raise ValueError(f"unknown {kind} search placeholders {sorted(bad)}")
        return self

    @property
    def placeholders(self) -> set[str]:
        return set(_PLACEHOLDER.findall(self.template or ""))

    @property
    def kinds(self) -> list[str]:
        if self.method != "url":
            return []
        return [
            k
            for k, t in (
                ("name", self.template),
                ("phone", self.phone_template),
                ("address", self.address_template),
            )
            if t
        ]

    def template_for(self, kind: str) -> str | None:
        return {
            "name": self.template,
            "phone": self.phone_template,
            "address": self.address_template,
        }.get(kind)


class FormPlaybook(BaseModel):
    """CSS selectors for the browser channel. The tool fills, screenshots, and stops."""

    fields: dict[str, str] = Field(default_factory=dict)
    stop_before: str | None = None
    notes: str = ""


class OptOut(BaseModel):
    method: OptOutMethod = "unknown"
    url: str | None = None
    email: str | None = None
    requires: list[Requirement] = Field(default_factory=list)
    captcha: Captcha = "unknown"
    form: FormPlaybook | None = None
    notes: str = ""

    @model_validator(mode="after")
    def _channel_present(self) -> OptOut:
        if self.method == "form" and not self.url:
            raise ValueError("opt_out.method form needs a url")
        if self.method == "email" and not self.email:
            raise ValueError("opt_out.method email needs an email")
        return self


class Registry(BaseModel):
    ca: str | None = Field(default=None, description="CPPA Broker ID")
    vt: bool = False
    tx: bool = False
    or_: bool = Field(default=False, alias="or")

    model_config = {"populate_by_name": True}


class Legal(BaseModel):
    ccpa: bool = True
    gdpr: bool = False


class Broker(BaseModel):
    id: str
    name: str
    aka: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    category: Category = "other"
    status: Status = "active"
    registry: Registry = Field(default_factory=Registry)
    contact: Contact = Field(default_factory=Contact)
    search: Search = Field(default_factory=Search)
    opt_out: OptOut = Field(default_factory=OptOut)
    legal: Legal = Field(default_factory=Legal)
    disclosures: list[str] = Field(default_factory=list)
    notes: str = ""
    sources: list[str] = Field(default_factory=list)
    last_verified: date | None = None
    origin: Origin = "curated"

    @field_validator("id")
    @classmethod
    def _slug(cls, v: str) -> str:
        if not _SLUG.match(v):
            raise ValueError("id must be a slug: lowercase letters, digits, hyphens")
        return v

    @field_validator("hosts")
    @classmethod
    def _hosts(cls, v: list[str]) -> list[str]:
        out = []
        for h in v:
            h = h.strip().lower()
            if "://" in h:
                h = urlsplit(h).netloc
            h = h.removeprefix("www.").rstrip("/")
            if h and h not in out:
                out.append(h)
        return out

    @property
    def searchable(self) -> bool:
        return self.status == "active" and bool(self.search.kinds)

    @property
    def opt_out_channel(self) -> str:
        """Short human label of how to get out, for tables."""
        m = self.opt_out.method
        if m == "form":
            return f"form {self.opt_out.url}"
        if m == "email":
            return f"email {self.opt_out.email}"
        if m == "account":
            return f"account {self.opt_out.url or ''}".strip()
        if m == "unknown" and self.contact.privacy_url:
            return f"privacy page {self.contact.privacy_url}"
        return m

    def matches_host(self, host: str) -> bool:
        host = host.lower().removeprefix("www.")
        return any(host == h or host.endswith("." + h) for h in self.hosts)
