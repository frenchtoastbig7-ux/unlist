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


# The opt-out manual (thumpersecure/opt-out-manual-2026, Unlicense) ------------------------

MANUAL_URL = "https://github.com/thumpersecure/opt-out-manual-2026"
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_URL_RE = re.compile(r"https?://[^\s|)]+")
_BOLD = re.compile(r"\*\*(.+?)\*\*")
_PAREN = re.compile(r"\(([^)]+)\)")
_MANUAL_CATEGORY = {
    "PUB": "people-search",
    "B2B": "marketing",
    "AD": "marketing",
    "MKT": "marketing",
    "FIN": "credit",
    "HR": "background-check",
    "ID": "background-check",
}


def _md_tables(text: str) -> list[tuple[list[str], list[list[str]]]]:
    """Every pipe table in a Markdown document as (headers, rows of cells)."""
    tables: list[tuple[list[str], list[list[str]]]] = []
    headers: list[str] | None = None
    rows: list[list[str]] = []
    prev: list[str] | None = None
    for line in text.splitlines():
        if not line.lstrip().startswith("|"):
            if headers is not None:
                tables.append((headers, rows))
            headers, rows, prev = None, [], None
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if all(re.fullmatch(r":?-+:?", c) for c in cells if c) and prev is not None:
            headers, rows = prev, []
            continue
        if headers is not None:
            rows.append(cells)
        prev = cells
    if headers is not None:
        tables.append((headers, rows))
    return tables


def _site_name(cell: str) -> tuple[str, list[str], str | None]:
    """'**Name** (alias or domain)' -> (name, aka, domain or None)."""
    m = _BOLD.search(cell)
    name = (m.group(1) if m else cell).strip()
    aka: list[str] = []
    domain = None
    rest = cell[m.end() :] if m else ""
    for inner in _PAREN.findall(rest):
        inner = inner.strip()
        if re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", inner.lower()):
            domain = inner.lower()
        elif inner:
            aka.append(inner)
    return name, aka, domain


def _manual_method(method: str, link: str | None, email: str | None) -> tuple[str, list[str]]:
    m = method.lower()
    requires: list[str] = []
    if "🪪" in method or " id" in m:
        requires.append("id_upload")
    if "phone code" in m or "📞" in method:
        requires.append("phone_code")
    if "no opt-out" in m:
        return "unknown", requires
    if "fax" in m or "📠" in method or "✉" in method or "mail-in" in m:
        return "mail", ["mail_in", *requires]
    starts_email = method.strip().startswith("📧") or m.startswith("email")
    if starts_email and email:
        return "email", requires
    has_form = any(w in m for w in ("form", "online", "on-site", "one-click"))
    if has_form and link:
        if "📧" in method or "confirm" in m or "verify" in m:
            requires.append("email_link")
        return "form", requires
    if email:
        return "email", requires
    return "unknown", requires


def read_optout_manual(path: Path) -> list[dict[str, object]]:
    """Rows from the three broker tables of The.Manual.md as plain dicts.

    Table shapes (by header):
      Site | Difficulty | Time | Needs Email? | Needs ID? | Opt-Out Link     (master index)
      # | Site | Domain | Opt-Out Link | Method | Notes                      (additional sites)
      # | Site | Website | Category | Opt-Out Method | Processing Time | Notes   (data brokers)
    """
    text = Path(path).read_text(encoding="utf-8")
    out: list[dict[str, object]] = []
    for headers, rows in _md_tables(text):
        h = [x.lower() for x in headers]
        if "site" not in h:
            continue
        idx = {name: i for i, name in enumerate(h)}

        def cell(row: list[str], key: str, _idx: dict[str, int] = idx) -> str:
            i = _idx.get(key)
            return row[i].strip() if i is not None and i < len(row) else ""

        if "opt-out link" in idx and "difficulty" in idx:
            shape = "main"
        elif "opt-out link" in idx and "method" in idx:
            shape = "additional"
        elif "opt-out method" in idx and "category" in idx:
            shape = "broker"
        else:
            continue
        for row in rows:
            name, aka, domain = _site_name(cell(row, "site"))
            if not name or name.lower() == "site":
                continue
            domain = (cell(row, "domain") or cell(row, "website") or domain or "").lower()
            link_cell = cell(row, "opt-out link")
            link_m = _URL_RE.search(link_cell)
            link = link_m.group(0).rstrip(".,") if link_m else None
            notes = cell(row, "notes")
            if shape == "main":
                method_text = "Online form" + (" + 📧" if "📧" in cell(row, "needs email?") else "")
                if cell(row, "needs id?") not in ("", "—", "-"):
                    method_text += " + 🪪 ID"
                extra = f"{cell(row, 'difficulty')} · {cell(row, 'time')}".strip(" ·")
                category = "people-search"
            elif shape == "additional":
                method_text = cell(row, "method")
                extra = "" if link else link_cell
                category = "people-search"
            else:
                method_text = cell(row, "opt-out method")
                proc = cell(row, "processing time")
                extra = f"Processing time: {proc}" if proc and proc.lower() != "varies" else ""
                category = _MANUAL_CATEGORY.get(cell(row, "category").upper(), "other")
            email_m = (
                _EMAIL_RE.search(method_text)
                or _EMAIL_RE.search(link_cell)
                or _EMAIL_RE.search(notes)
            )
            email = email_m.group(0).lower().rstrip(".") if email_m else None
            if not link and "📧" not in method_text.split("+")[0]:
                note_url = _URL_RE.search(notes)
                if note_url:
                    link = note_url.group(0).rstrip(".,")
            on_site = "on-site" in method_text.lower() or "embedded" in link_cell.lower()
            if on_site and not link and domain:
                # Removal is a control on the listing page itself.
                link = f"https://{domain}"
            method, requires = _manual_method(method_text, link, email)
            if on_site and "listing_url" not in requires:
                requires.append("listing_url")
            out.append(
                {
                    "name": name,
                    "aka": aka,
                    "domain": domain,
                    "link": link,
                    "email": email,
                    "method": method,
                    "requires": requires,
                    "category": category,
                    "shape": shape,
                    "method_text": method_text,
                    "notes": " ".join(p for p in (notes, extra) if p).strip(),
                }
            )
    return out


def build_manual_registry(rows: Iterable[dict[str, object]]) -> list[Broker]:
    seen: dict[str, int] = {}
    hosts_seen: set[str] = set()
    brokers: list[Broker] = []
    for row in rows:
        name = str(row["name"])
        host = host_of(str(row["domain"])) if row["domain"] else None
        if host and host in hosts_seen:
            continue  # the same site listed in two tables: keep the first, more detailed row
        if host:
            hosts_seen.add(host)
        slug = slugify(name)
        n = seen.get(slug, 0)
        seen[slug] = n + 1
        if n:
            slug = f"{slug}-{n + 1}"
        link = _clean_url(str(row["link"])) if row["link"] else None
        email = str(row["email"]) if row["email"] else None
        method = str(row["method"])
        site_url = f"https://{host}" if host else None
        note = str(row["notes"])
        if method == "unknown" and "form" in str(row["method_text"]).lower():
            note = (note + " Opt-out is a web form reached from the site's privacy page.").strip()
        brokers.append(
            Broker(
                id=slug,
                name=name,
                aka=list(row["aka"]),  # type: ignore[arg-type]
                hosts=[host] if host else [],
                category=str(row["category"]),  # type: ignore[arg-type]
                contact={"privacy_email": email, "privacy_url": link or site_url},
                opt_out={
                    "method": method,
                    "url": link if method in ("form", "account") else None,
                    "email": email,
                    "requires": list(row["requires"]),  # type: ignore[arg-type]
                    "notes": note,
                },
                sources=[MANUAL_URL],
                origin="optout-manual",
            )
        )
    return brokers
