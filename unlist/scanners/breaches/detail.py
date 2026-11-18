"""What a breach hit is, what it held, and where to read about it at the source.

Everything here is derived from answers already kept as evidence: the HIBP breach list
(description, data classes, disclosure link), XposedOrNot analytics (description,
reference link, how passwords were stored) and LeakCheck (field names). Nothing is
fetched, and no leaked value is involved: these sources say which kinds of data a breach
held, never the data itself.

Hits from different sources are grouped when they are the same incident. A hit is tied
to an HIBP entry by exact name, by domain or by title, and only when the dates agree;
otherwise the entry is offered as a possible match and nothing is taken from it.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from functools import lru_cache
from html.parser import HTMLParser
from urllib.parse import quote, urlsplit

from unlist import paths

HIBP_PAGE = "https://haveibeenpwned.com/Breach/"
XON_PAGE = "https://xposedornot.com/breach/"

SOURCE_LABELS = {
    "hibp": "Have I Been Pwned",
    "xposedornot": "XposedOrNot",
    "leakcheck": "LeakCheck",
    "leakcheck-pro": "LeakCheck Pro",
}

PASSWORD_RISK = {
    "plaintext": "stored as plain text, so treat it as known",
    "easytocrack": "stored with a weak hash that is easy to crack, so treat it as known",
    "hardtocrack": "stored with a strong hash, which slows cracking but does not prevent it",
}

# HIBP paste sources whose Id is enough to rebuild the address.
PASTE_URLS = {
    "pastebin": "https://pastebin.com/{id}",
    "pastie": "http://pastie.org/pastes/{id}",
    "slexy": "https://slexy.org/view/{id}",
    "ghostbin": "https://ghostbin.com/paste/{id}",
    "justpaste": "https://justpaste.it/{id}",
}

_DOMAIN = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")


@dataclass(frozen=True)
class Link:
    label: str
    url: str
    note: str = ""


@dataclass
class HibpMatch:
    entry: dict
    basis: str  # name | domain | title
    confident: bool


@dataclass
class BreachGroup:
    key: str
    kind: str  # breach | paste | stealer
    title: str
    hit_ids: list[int] = field(default_factory=list)
    date: str = ""
    domain: str = ""
    identifiers: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    # what each source says this breach held: [(source label, [data classes])]
    classes_by_source: list[tuple[str, list[str]]] = field(default_factory=list)
    # LeakCheck's public answer lists fields per identifier, across all of its sources
    identifier_fields: list[tuple[str, list[str]]] = field(default_factory=list)
    descriptions: list[tuple[str, str]] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    facts: list[tuple[str, str]] = field(default_factory=list)
    advice: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    hibp: dict | None = None
    possible_hibp: dict | None = None
    first_seen: str = ""
    last_seen: str = ""
    account: object | None = None

    @property
    def id(self) -> int:
        return self.hit_ids[0]

    @property
    def classes(self) -> list[str]:
        """Data classes attributed to this breach itself, in first-seen order."""
        out: list[str] = []
        seen: set[str] = set()
        for _, classes in self.classes_by_source:
            for c in classes:
                if c.lower() not in seen:
                    seen.add(c.lower())
                    out.append(c)
        return out

    @property
    def fields_any(self) -> list[str]:
        out: list[str] = []
        for _, fields in self.identifier_fields:
            for f in fields:
                if f not in out:
                    out.append(f)
        return out

    @property
    def source_labels(self) -> list[str]:
        return [SOURCE_LABELS.get(s, s) for s in self.sources]


# text helpers ---------------------------------------------------------------------------


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._anchor: list[str] = []
        self._skip = 0  # inside <script> or <style>

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in ("script", "style"):
            self._skip += 1
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._anchor = []

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            if safe_url(self._href):
                self.links.append((" ".join("".join(self._anchor).split()), self._href))
            self._href = None

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        self.parts.append(data)
        if self._href is not None:
            self._anchor.append(data)


def html_to_text(html: str) -> tuple[str, list[tuple[str, str]]]:
    """Plain text and the http(s) links of a source's HTML description. Never rendered."""
    p = _Text()
    p.feed(html or "")
    p.close()
    return " ".join("".join(p.parts).split()), p.links


def safe_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def _year(date: str | None) -> int | None:
    m = re.match(r"(\d{4})", date or "")
    return int(m.group(1)) if m else None


def _as_domain(name: str) -> str:
    n = (name or "").strip().lower()
    return n if _DOMAIN.match(n) else ""


def _stem(name: str) -> str:
    """'Chegg.com' -> 'chegg'; a plain name is only normalised."""
    d = _as_domain(name)
    return _norm(d.rsplit(".", 1)[0].split(".")[-1]) if d else _norm(name)


# stored answers -------------------------------------------------------------------------


@lru_cache(maxsize=128)
def _read_json(path: str) -> object:
    # raw files are write-once and named by their hash, so a path never changes content
    try:
        with open(path, "rb") as fh:
            return json.loads(fh.read())
    except (OSError, ValueError):
        return None


def _capture_json(conn: sqlite3.Connection, capture_id: int | None) -> object:
    if not capture_id:
        return None
    row = conn.execute("SELECT raw_path FROM captures WHERE id=?", (capture_id,)).fetchone()
    if not row:
        return None
    return _read_json(str(paths.data_dir() / row["raw_path"]))


class HibpIndex:
    def __init__(self, entries: list[dict]) -> None:
        self.by_name: dict[str, dict] = {}
        self._by_domain: dict[str, list[dict]] = {}
        self._by_title: dict[str, list[dict]] = {}
        for e in entries:
            name = str(e.get("Name") or "")
            if not name:
                continue
            self.by_name[name] = e
            dom = str(e.get("Domain") or "").lower()
            if dom:
                self._by_domain.setdefault(dom, []).append(e)
            for key in {_norm(name), _norm(str(e.get("Title") or ""))}:
                if key:
                    self._by_title.setdefault(key, []).append(e)

    def __len__(self) -> int:
        return len(self.by_name)

    def _domain_candidates(self, host: str) -> list[dict]:
        host = host.lower().removeprefix("www.")
        while host.count(".") >= 1:
            if host in self._by_domain:
                return self._by_domain[host]
            host = host.split(".", 1)[1]
        return []

    def match(self, name: str, domain: str = "", date: str | None = None) -> HibpMatch | None:
        year = _year(date)
        exact = self.by_name.get(name)
        if exact:
            return HibpMatch(exact, "name", True)
        tries: list[tuple[str, list[dict]]] = []
        for host in (domain, _as_domain(name)):
            if host:
                tries.append(("domain", self._domain_candidates(host)))
        tries.append(("title", self._by_title.get(_norm(name), [])))
        if _as_domain(name):
            tries.append(("title", self._by_title.get(_stem(name), [])))
        elif "-" in name:
            # sources qualify some names ("ATT-Speculated"); the dates still have to agree
            tries.append(("title", self._by_title.get(_norm(name.split("-", 1)[0]), [])))
        for basis, cands in tries:
            if not cands:
                continue
            if year is None:
                return HibpMatch(cands[0], basis, False) if len(cands) == 1 else None
            scored = sorted(
                (abs((_year(c.get("BreachDate")) or 0) - year), i, c) for i, c in enumerate(cands)
            )
            gap, _, best = scored[0]
            if gap <= 1:
                return HibpMatch(best, basis, True)
            # one candidate with other dates is offered as possible; several are a guess
            return HibpMatch(best, basis, False) if len(cands) == 1 else None
        return None


@lru_cache(maxsize=2)
def _index_for(path: str) -> HibpIndex:
    data = _read_json(path)
    return HibpIndex([e for e in data if isinstance(e, dict)] if isinstance(data, list) else [])


def hibp_index(conn: sqlite3.Connection) -> HibpIndex:
    """The most recent HIBP breach list this tool has stored. Empty before the first scan."""
    try:
        row = conn.execute(
            "SELECT raw_path FROM captures WHERE tool='breaches' AND status=200 "
            "AND note LIKE 'hibp breach list%' ORDER BY id DESC LIMIT 1"
        ).fetchone()
    except sqlite3.OperationalError:
        row = None
    if not row:
        return HibpIndex([])
    return _index_for(str(paths.data_dir() / row["raw_path"]))


def _xon_detail(conn: sqlite3.Connection, hit: sqlite3.Row) -> dict:
    body = _capture_json(conn, hit["capture_id"])
    if not isinstance(body, dict):
        return {}
    for b in ((body.get("ExposedBreaches") or {}).get("breaches_details")) or []:
        if isinstance(b, dict) and str(b.get("breach") or "") == hit["breach_name"]:
            return b
    return {}


def _leakcheck_fields(conn: sqlite3.Connection, hit: sqlite3.Row) -> list[str] | None:
    body = _capture_json(conn, hit["capture_id"])
    if isinstance(body, dict) and isinstance(body.get("fields"), list):
        return [str(f) for f in body["fields"]]
    return None


def paste_url(name: str) -> str:
    """Address of a paste from an HIBP 'Source:Id' name, when it can be rebuilt."""
    source, _, pid = name.partition(":")
    if not pid:
        return ""
    if source.lower() == "adhocurl":
        return pid if safe_url(pid) else ""
    pattern = PASTE_URLS.get(source.lower())
    return pattern.format(id=quote(pid, safe="")) if pattern else ""


# advice ---------------------------------------------------------------------------------

# (substrings to look for, whole field names to look for, advice)
_ADVICE: tuple[tuple[tuple[str, ...], tuple[str, ...], str], ...] = (
    (
        ("password",),
        (),
        "Change the password for this account and anywhere you used the same one. "
        "`unlist password-check` tells you whether a password of yours is in known breaches.",
    ),
    (
        ("social security", "government", "passport", "driver", "national id"),
        ("ssn",),
        "Identity numbers are involved: place a credit freeze with Equifax, Experian and "
        "TransUnion, and watch for accounts you did not open.",
    ),
    (
        ("credit card", "bank account", "payment", "financial"),
        (),
        "Watch the statements for that card or account and ask the issuer for a new number.",
    ),
    (
        ("phone",),
        (),
        "Expect scam calls and texts to that number, and set a port-out PIN with your carrier.",
    ),
    (
        ("physical address", "home address", "date of birth", "dates of birth"),
        ("address", "dob"),
        "Name, address and birth date are what people-search sites combine. Run the "
        "people-search scan and remove the listings it finds.",
    ),
    (
        ("security question",),
        (),
        "Change the security questions anywhere you gave the same answers.",
    ),
)

_UNSCOPED = (
    " LeakCheck lists this field for your identifier without saying which of its sources held it."
)


def _involves(values: list[str], substrings: tuple[str, ...], whole: tuple[str, ...]) -> bool:
    return any(v in whole or any(t in v for t in substrings) for v in values)


def advice_for(classes: list[str], fields: list[str]) -> list[str]:
    """Plain next steps for the kinds of data involved."""
    own = [c.lower() for c in classes]
    loose = [f.lower() for f in fields]
    out = []
    for substrings, whole, text in _ADVICE:
        if _involves(own, substrings, whole):
            out.append(text)
        elif _involves(loose, substrings, whole):
            out.append(text + _UNSCOPED)
    return out


# grouping -------------------------------------------------------------------------------


def _row_classes(hit: sqlite3.Row) -> list[str]:
    try:
        return [str(c) for c in json.loads(hit["data_classes_json"] or "[]")]
    except ValueError:
        return []


def _kind(hit: sqlite3.Row) -> str:
    return hit["kind"] if "kind" in hit.keys() else "breach"  # noqa: SIM118


def _add_link(g: BreachGroup, label: str, url: str, note: str = "") -> None:
    if url and safe_url(url) and all(link.url != url for link in g.links):
        g.links.append(Link(label, url, note))


def _add_once(items: list, item: object) -> None:
    if item not in items:
        items.append(item)


def _fmt_count(n: object) -> str:
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return ""


def _group_key(hit: sqlite3.Row, match: HibpMatch | None) -> str:
    kind = _kind(hit)
    if kind != "breach":
        return f"{kind}:{hit['breach_name']}"
    if match and match.confident:
        return f"hibp:{match.entry['Name']}"
    year = _year(hit["breach_date"])
    return f"name:{_stem(hit['breach_name'])}:{year or ''}"


def build_groups(conn: sqlite3.Connection, hits: list[sqlite3.Row]) -> list[BreachGroup]:
    """Group hits into incidents and attach description, data classes, links and advice."""
    index = hibp_index(conn)
    groups: dict[str, BreachGroup] = {}
    for hit in hits:
        kind = _kind(hit)
        match = (
            index.match(hit["breach_name"], hit["domain"] or "", hit["breach_date"])
            if kind == "breach"
            else None
        )
        key = _group_key(hit, match)
        g = groups.get(key)
        if g is None:
            g = groups[key] = BreachGroup(
                key=key, kind=kind, title=hit["title"] or hit["breach_name"]
            )
        g.hit_ids.append(int(hit["id"]))
        _add_once(g.identifiers, hit["identifier_value"])
        _add_once(g.sources, hit["source"])
        g.first_seen = min(filter(None, (g.first_seen, hit["first_seen"])))
        g.last_seen = max(g.last_seen, hit["last_seen"] or "")
        if len(hit["breach_date"] or "") > len(g.date):
            g.date = hit["breach_date"]
        g.domain = g.domain or (hit["domain"] or "") or _as_domain(hit["breach_name"])
        if hit["capture_id"]:
            g.evidence.append(
                {
                    "capture_id": int(hit["capture_id"]),
                    "source": SOURCE_LABELS.get(hit["source"], hit["source"]),
                    "identifier": hit["identifier_value"],
                }
            )
        if match and match.confident:
            g.hibp = match.entry
        elif match and not g.hibp:
            g.possible_hibp = match.entry
        _absorb_hit(conn, g, hit, kind)
    out = list(groups.values())
    for g in out:
        _finish(g)
    out.sort(key=lambda g: (g.date or "", g.title.lower()), reverse=True)
    return out


def _absorb_hit(conn: sqlite3.Connection, g: BreachGroup, hit: sqlite3.Row, kind: str) -> None:
    source = hit["source"]
    label = SOURCE_LABELS.get(source, source)
    name = hit["breach_name"]
    if kind == "paste":
        _add_once(g.classes_by_source, (label, ["Email addresses"]))
        url = paste_url(name)
        _add_link(g, "The paste itself", url, "pastes are often removed soon after they appear")
        if hit["pwn_count"]:
            _add_once(g.facts, ("Addresses in the paste", _fmt_count(hit["pwn_count"])))
        return
    if kind == "stealer":
        _add_once(g.classes_by_source, (label, ["Passwords"]))
        _add_link(g, "The site whose saved login was captured", f"https://{name}")
        return
    if source == "xposedornot":
        d = _xon_detail(conn, hit)
        classes = [c.strip() for c in str(d.get("xposed_data") or "").split(";") if c.strip()]
        _add_once(g.classes_by_source, (label, classes or _row_classes(hit)))
        if d.get("details"):
            _add_once(g.descriptions, (label, " ".join(str(d["details"]).split())))
        _add_link(g, f"XposedOrNot: {name}", XON_PAGE + quote(name, safe=""))
        for ref in re.split(r"[\s;,]+", str(d.get("references") or "")):
            _add_link(g, "Report cited by XposedOrNot", ref)
        if d.get("industry"):
            _add_once(g.facts, ("Industry", str(d["industry"])))
        risk = PASSWORD_RISK.get(str(d.get("password_risk") or "").lower())
        if risk:
            _add_once(g.facts, ("Passwords", risk))
        if not g.hibp and _fmt_count(d.get("xposed_records") or hit["pwn_count"]):
            _add_once(
                g.facts,
                ("Records exposed", _fmt_count(d.get("xposed_records") or hit["pwn_count"])),
            )
    elif source == "leakcheck":
        fields = _leakcheck_fields(conn, hit)
        if fields is None:
            fields = _row_classes(hit)
        _add_once(g.identifier_fields, (hit["identifier_value"], fields))
    elif source == "hibp":
        pass  # the HIBP entry itself is added once in _finish
    else:  # leakcheck-pro and any later source that reports per breach
        _add_once(g.classes_by_source, (label, _row_classes(hit)))


def _finish(g: BreachGroup) -> None:
    e = g.hibp
    if e:
        g.title = str(e.get("Title") or e.get("Name") or g.title)
        g.date = str(e.get("BreachDate") or g.date)
        g.domain = str(e.get("Domain") or g.domain)
        g.classes_by_source.insert(
            0, (SOURCE_LABELS["hibp"], [str(c) for c in e.get("DataClasses") or []])
        )
        text, links = html_to_text(str(e.get("Description") or ""))
        if text:
            g.descriptions.insert(0, (SOURCE_LABELS["hibp"], text))
        head = [Link(f"Have I Been Pwned: {g.title}", HIBP_PAGE + quote(str(e["Name"]), safe=""))]
        if e.get("DisclosureUrl") and safe_url(str(e["DisclosureUrl"])):
            head.append(Link("The organisation's own disclosure", str(e["DisclosureUrl"])))
        for anchor, url in links:
            head.append(Link(anchor or "Report cited by Have I Been Pwned", url))
        rest = [x for x in g.links if all(x.url != h.url for h in head)]
        seen: set[str] = set()
        g.links = [x for x in (*head, *rest) if not (x.url in seen or seen.add(x.url))]
        facts = [
            ("Accounts affected", _fmt_count(e.get("PwnCount"))),
            ("Added to Have I Been Pwned", str(e.get("AddedDate") or "")[:10]),
            ("Verified", "yes" if e.get("IsVerified") else "no, unverified"),
        ]
        if e.get("IsSensitive"):
            facts.append(("Sensitive", "yes: HIBP only shows this breach to the address owner"))
        if e.get("IsFabricated"):
            facts.append(("Fabricated", "HIBP considers this data likely fabricated"))
        if e.get("IsSpamList"):
            facts.append(("Spam list", "a list used for spam, not a breach of one site"))
        g.facts = [f for f in facts if f[1]] + g.facts
    elif g.possible_hibp:
        p = g.possible_hibp
        _add_link(
            g,
            f"Possibly this breach at Have I Been Pwned: {p.get('Title') or p.get('Name')}",
            HIBP_PAGE + quote(str(p["Name"]), safe=""),
            f"same site, but HIBP dates it {p.get('BreachDate') or 'unknown'}",
        )
    if g.kind == "breach" and g.domain:
        _add_link(g, f"The affected site: {g.domain}", f"https://{g.domain}")
        from unlist.catalog.accounts import load_accounts

        g.account = load_accounts().find(g.title, g.domain)
    g.classes_by_source = [(s, c) for s, c in g.classes_by_source if c]
    # LeakCheck's per-identifier fields only stand in when no source describes the breach
    g.advice = advice_for(g.classes, [] if g.classes else g.fields_any)
    if g.kind == "stealer":
        g.advice.insert(
            0,
            "Malware on a device of yours captured the saved password for this site. Change "
            "it from a clean device and sign out other sessions.",
        )


def groups_for(
    conn: sqlite3.Connection, subject_id: str, since: str | None = None
) -> list[BreachGroup]:
    sql = "SELECT * FROM breach_hits WHERE subject_id=?"
    args: list[object] = [subject_id]
    hits = conn.execute(sql + " ORDER BY id", args).fetchall()
    groups = build_groups(conn, hits)
    if since:
        groups = [g for g in groups if g.first_seen >= since]
    return groups


def group_for_hit(conn: sqlite3.Connection, hit_id: int) -> tuple[sqlite3.Row, BreachGroup] | None:
    hit = conn.execute("SELECT * FROM breach_hits WHERE id=?", (hit_id,)).fetchone()
    if not hit:
        return None
    for g in groups_for(conn, hit["subject_id"]):
        if hit_id in g.hit_ids:
            return hit, g
    return None


def exposed_summary(g: BreachGroup, limit: int = 0) -> str:
    """One line for tables: what the breach held, or LeakCheck's unscoped fields."""
    if g.classes:
        text = ", ".join(g.classes)
    elif g.fields_any:
        text = "any of: " + ", ".join(g.fields_any) + " (LeakCheck, not per breach)"
    else:
        text = ""
    return text if not limit or len(text) <= limit else text[: limit - 1] + "…"


def group_markdown(g: BreachGroup) -> str:
    """The detail view as Markdown, for the connector and the report."""
    lines = [f"### {g.title}", ""]
    head = [f"kind: {g.kind}"]
    if g.date:
        head.append(f"date: {g.date}")
    if g.domain:
        head.append(f"site: {g.domain}")
    head.append("reported by: " + ", ".join(g.source_labels))
    lines.append(" · ".join(head))
    lines.append("")
    lines.append("**Your identifiers in it:** " + ", ".join(g.identifiers))
    for source, classes in g.classes_by_source:
        lines.append(f"**Data in this breach ({source}):** " + ", ".join(classes))
    for ident, fields in g.identifier_fields:
        lines.append(
            f"**LeakCheck fields for {ident}:** " + ", ".join(fields) + " (across all of its "
            "sources for this identifier, not this breach alone)"
        )
    for label, value in g.facts:
        lines.append(f"**{label}:** {value}")
    for source, text in g.descriptions:
        lines += ["", f"> {text}", f"> ({source})"]
    if g.links:
        lines += ["", "**Read it at the source:**"]
        lines += [
            f"- [{link.label}]({link.url})" + (f" ({link.note})" if link.note else "")
            for link in g.links
        ]
    if g.account is not None:
        lines.append(
            f"- [Delete the {g.account.name} account]({g.account.url}) "
            f"(difficulty: {g.account.difficulty})"
        )
    if g.advice:
        lines += ["", "**What to do:**"] + [f"- {a}" for a in g.advice]
    lines += [
        "",
        "These sources report the kinds of data a breach held, not the values. unlist never "
        "stores leaked values.",
    ]
    return "\n".join(lines)
