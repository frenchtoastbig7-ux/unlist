"""Build registry/*.yaml from public data.

- California CPPA Data Broker Registry CSV (public record, cppa.ca.gov/data_broker_registry):
  name, DBA, website, contact email, phone, postal address, and the "website that contains
  details on how consumers can exercise their CA Consumer Privacy rights", plus yes/no
  disclosure columns.
- The Markup / CalMatters opt-out pages dataset (Apache-2.0): a checked opt-out URL per
  CPPA registrant and whether the page was hidden from search engines.

The importers are deterministic so the generated file can be regenerated and diffed.
"""

from __future__ import annotations

import csv
import re
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from unlist.catalog.models import Broker

csv.field_size_limit(10_000_000)

MARKUP_URL = "https://github.com/the-markup/investigation-data-broker-opt-out-pages"

_NON_SLUG = re.compile(r"[^a-z0-9]+")
_CORP = re.compile(
    r"\b(inc|llc|l\.l\.c|ltd|limited|corp|corporation|co|company|plc|gmbh|lp|llp|holdings)\b\.?",
    re.IGNORECASE,
)

# CPPA column prefixes (the headers are long sentences; match on their start).
_COL = {
    "broker_id": "Broker ID",
    "name": "Data broker name",
    "dba": "Doing Business As",
    "website": "Data broker primary website:",
    "email": "Data broker primary contact email",
    "phone": "Data broker primary phone",
    "street": "Data broker primary street address",
    "city": "Data broker city",
    "state": "Data broker state",
    "zip": "Data broker zip",
    "country": "Data broker country",
    "privacy_url": "Data broker's primary website that contains details",
}

# Disclosure columns worth keeping as short tags. Prefix of the header -> tag.
_DISCLOSURES = {
    "Data broker collects personal information of minors": "minors",
    "Data broker collects consumers' precise geolocation": "precise-geolocation",
    "Data broker collects consumers' reproductive health": "reproductive-health",
    "Data broker collects consumers' biometric data": "biometrics",
    "Data broker collects consumers' government": "government-id",
    "Data broker collects consumers' citizenship": "citizenship",
    "Data broker collects consumers' sexual orientation": "sexual-orientation",
    "Data broker collects consumers' union": "union-membership",
    "Data broker collects consumers' health": "health",
    "Data broker collects consumers' racial": "race-ethnicity",
    "Data broker collects consumers' religious": "religion",
    "Data broker sells or shares personal information to foreign": "foreign-actors",
    "Data broker sells or shares personal information to government": "government-buyers",
    "Data broker sells or shares personal information to generative": "genai-training",
    "Data broker is regulated by the Fair Credit": "fcra",
    "Data broker is regulated by the Gramm": "glba",
}


def slugify(name: str) -> str:
    base = _CORP.sub(" ", name.lower())
    slug = _NON_SLUG.sub("-", base).strip("-")
    return slug[:60].rstrip("-") or "broker"


def host_of(url: str | None) -> str | None:
    if not url:
        return None
    u = url.strip()
    if not u:
        return None
    if "://" not in u:
        u = "https://" + u
    host = urlsplit(u).netloc.lower().removeprefix("www.").rstrip(";,./")
    return host or None


def _clean_url(url: str | None) -> str | None:
    if not url:
        return None
    u = url.strip().split()[0].rstrip(";,") if url.strip() else ""
    if not u or u.lower() in {"n/a", "na", "none"}:
        return None
    if "://" not in u:
        u = "https://" + u
    return u


def _col(headers: list[str], prefix: str) -> int | None:
    for i, h in enumerate(headers):
        if h.strip().lstrip("﻿").startswith(prefix):
            return i
    return None


def _yes(value: str | None) -> bool:
    return (value or "").strip().lower() in {"yes", "y", "true", "1"}


def read_cppa(path: Path) -> list[dict[str, object]]:
    """Rows of the CPPA CSV as plain dicts keyed by our short names."""
    with Path(path).open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.reader(fh)
        headers = next(reader)
        idx = {k: _col(headers, v) for k, v in _COL.items()}
        missing = [k for k, v in idx.items() if v is None and k in {"name", "website"}]
        if missing:
            raise ValueError(f"CPPA CSV is missing expected columns: {missing}")
        disc_idx = {tag: _col(headers, prefix) for prefix, tag in _DISCLOSURES.items()}
        rows = []
        for raw in reader:
            if not any(cell.strip() for cell in raw):
                continue
            rows.append(_row(raw, idx, disc_idx))
    return rows


def _row(raw: list[str], idx: dict[str, int | None], disc_idx: dict[str, int | None]) -> dict:
    def cell(key: str) -> str:
        i = idx.get(key)
        return raw[i].strip() if i is not None and i < len(raw) else ""

    postal_parts = (cell("street"), cell("city"), cell("state"), cell("zip"), cell("country"))
    return {
        "broker_id": cell("broker_id"),
        "name": cell("name"),
        "dba": cell("dba"),
        "website": cell("website"),
        "email": cell("email").lower(),
        "phone": cell("phone"),
        "postal": ", ".join(p for p in postal_parts if p),
        "privacy_url": cell("privacy_url"),
        "disclosures": sorted(
            tag
            for tag, i in disc_idx.items()
            if i is not None and i < len(raw) and _yes(raw[i])
        ),
    }


def read_markup(path: Path) -> dict[str, dict[str, str]]:
    """The Markup dataset keyed by hostname_original (and by lowercased company name)."""
    out: dict[str, dict[str, str]] = {}
    with Path(path).open(newline="", encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            host = (row.get("hostname_original") or "").lower().removeprefix("www.")
            if host:
                out.setdefault(host, row)
            name = (row.get("company_name") or "").strip().lower()
            if name:
                out.setdefault("name:" + name, row)
    return out


def build_registry(
    cppa_rows: Iterable[dict[str, object]], markup: dict[str, dict[str, str]] | None = None
) -> list[Broker]:
    markup = markup or {}
    seen: dict[str, int] = {}
    brokers: list[Broker] = []
    for row in cppa_rows:
        name = str(row["name"]).strip()
        if not name:
            continue
        slug = slugify(name)
        n = seen.get(slug, 0)
        seen[slug] = n + 1
        if n:
            slug = f"{slug}-{n + 1}"
        website = _clean_url(str(row["website"]))
        host = host_of(website)
        privacy_url = _clean_url(str(row["privacy_url"]))
        notes: list[str] = []
        m = None
        if host:
            m = markup.get(host)
        if m is None:
            m = markup.get("name:" + name.lower())
        if m is not None:
            checked = _clean_url(m.get("url_final") or m.get("url_original"))
            if checked and (m.get("status") or "").lower() == "success":
                privacy_url = checked
            if (m.get("hiding_found") or "").upper() == "TRUE":
                notes.append(
                    "The Markup (2025) found this opt-out page hidden from search engines."
                )
        aka = [a.strip() for a in str(row["dba"]).replace(",", ";").split(";") if a.strip()]
        email = str(row["email"]) or None
        method = "email" if email else ("form" if privacy_url else "unknown")
        brokers.append(
            Broker(
                id=slug,
                name=name,
                aka=aka,
                hosts=[host] if host else [],
                category="other",
                registry={"ca": str(row["broker_id"]) or None},
                contact={
                    "privacy_email": email,
                    "privacy_url": privacy_url,
                    "phone": str(row["phone"]) or None,
                    "postal": str(row["postal"]) or None,
                },
                opt_out={"method": method, "url": privacy_url, "email": email},
                disclosures=list(row["disclosures"]),
                notes=" ".join(notes),
                sources=["https://cppa.ca.gov/data_broker_registry/"] + ([MARKUP_URL] if m else []),
                origin="cppa-registry",
            )
        )
    return brokers


def write_registry_yaml(brokers: list[Broker], path: Path, header: str = "") -> Path:
    items = []
    for b in sorted(brokers, key=lambda b: b.id):
        d = b.model_dump(mode="json", by_alias=True, exclude_defaults=True)
        d["id"] = b.id
        d["name"] = b.name
        d["origin"] = b.origin
        items.append(d)
    text = yaml.safe_dump(
        {"brokers": items}, sort_keys=False, allow_unicode=True, width=100, default_flow_style=False
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text((header.rstrip() + "\n" if header else "") + text, encoding="utf-8")
    return path
