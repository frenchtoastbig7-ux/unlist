"""Find listing blocks on a results page and score them against the subject."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin, urlsplit

from lxml import html as lxml_html

from unlist.scanners.brokers.urls import Profile

_AGE = re.compile(r"\b(?:age|aged)\s*:?\s*(\d{2,3})\b|\b(\d{2})\s*(?:years? old|yrs)\b", re.I)
_PLACE = re.compile(r"\b([A-Z][A-Za-z.'\-]+(?: [A-Z][A-Za-z.'\-]+){0,3}),\s*([A-Z]{2})\b")
_PHONE = re.compile(r"\(?\b(\d{3})\)?[-.\s]?(\d{3})[-.\s]?(\d{4})\b")
_NO_RESULTS = re.compile(
    r"no (?:results|records|matches|people) (?:found|were found|match)|0 results"
    r"|we (?:couldn.t|could not) find|did not match any|no exact matches",
    re.I,
)
_CHALLENGE = re.compile(
    r"just a moment|verify you are human|are you a robot|attention required|cf-chl|captcha|"
    r"access denied|unusual traffic",
    re.I,
)

BLOCK_TAGS = {"li", "article", "tr", "div", "section", "dl", "p"}
MAX_BLOCK_CHARS = 1500
CANDIDATE_THRESHOLD = 0.5


@dataclass
class Candidate:
    listing_url: str
    name_text: str
    score: float = 0.0
    age: int | None = None
    places: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    snippet: str = ""
    reasons: list[str] = field(default_factory=list)

    def extract_json(self) -> str:
        d = asdict(self)
        d.pop("listing_url")
        d.pop("score")
        return json.dumps(d, ensure_ascii=False)


def looks_like_no_results(text: str) -> bool:
    return bool(_NO_RESULTS.search(text))


def looks_like_challenge(text: str) -> bool:
    return bool(_CHALLENGE.search(text[:20000]))


def _text(el) -> str:
    return re.sub(r"\s+", " ", el.text_content() or "").strip()


def _block_for(anchor, name_anchors):
    """The nearest ancestor that reads like one listing card, not the whole page.

    Climb while the ancestor stays short and holds no other listing's name link.
    """
    best = anchor
    node = anchor.getparent()
    while node is not None and node.tag not in ("body", "html"):
        if node.tag in BLOCK_TAGS:
            if len(_text(node)) > MAX_BLOCK_CHARS:
                break
            if sum(1 for a in node.iter("a") if a in name_anchors) > 1:
                break
            best = node
        node = node.getparent()
    return best


def _name_in(text: str, first: str, last: str) -> bool:
    t = text.lower()
    return bool(re.search(rf"\b{re.escape(first.lower())}\b", t)) and bool(
        re.search(rf"\b{re.escape(last.lower())}\b", t)
    )


def extract_candidates(
    body: bytes | str, page_url: str, profile: Profile, hosts: list[str]
) -> list[Candidate]:
    """Anchors on the broker's own hosts whose text carries one of the subject's names."""
    raw = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    try:
        tree = lxml_html.fromstring(raw)
    except Exception:
        return []
    page_host = urlsplit(page_url).netloc.lower().removeprefix("www.")
    allowed = set(hosts) | {page_host}
    found: dict[str, Candidate] = {}
    name_anchors: dict = {}
    for a in tree.iter("a"):
        href = a.get("href")
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        anchor_text = _text(a)
        if not anchor_text or len(anchor_text) > 80:
            continue
        matched = [n for n in profile.names if _name_in(anchor_text, n.first, n.last)]
        if matched:
            name_anchors[a] = matched
    for a, matched in name_anchors.items():
        href = a.get("href")
        anchor_text = _text(a)
        url = urljoin(page_url, href)
        host = urlsplit(url).netloc.lower().removeprefix("www.")
        if not any(host == h or host.endswith("." + h) for h in allowed):
            continue
        url = url.split("#", 1)[0]
        if url in found:
            continue
        block_text = _text(_block_for(a, name_anchors))
        cand = Candidate(listing_url=url, name_text=anchor_text, snippet=block_text[:400])
        m = _AGE.search(block_text)
        if m:
            cand.age = int(m.group(1) or m.group(2))
        cand.places = sorted({f"{c}, {s}" for c, s in _PLACE.findall(block_text)})[:12]
        cand.phones = sorted({"1" + "".join(p) for p in _PHONE.findall(block_text)})[:6]
        cand.score, cand.reasons = score(cand, profile, matched[0].middle)
        found[url] = cand
    return sorted(found.values(), key=lambda c: -c.score)


def score(cand: Candidate, profile: Profile, middle: str = "") -> tuple[float, list[str]]:
    """0 to 1. Name alone is never enough: 0.4 for full name, the rest from place, age, phone."""
    s = 0.4
    reasons = ["name"]
    text = (cand.name_text + " " + cand.snippet).lower()
    if middle and re.search(rf"\b{re.escape(middle.lower())}", text):
        s += 0.1
        reasons.append("middle name")
    known_cities = {p.city.lower() for p in profile.places if p.city}
    known_states = {p.state.upper() for p in profile.places if p.state}
    cand_cities = {c.split(",")[0].strip().lower() for c in cand.places}
    cand_states = {c.split(",")[1].strip().upper() for c in cand.places if "," in c}
    if known_cities & cand_cities:
        s += 0.3
        reasons.append("city")
    elif known_states & cand_states:
        s += 0.1
        reasons.append("state only")
    if profile.age and cand.age is not None:
        if abs(profile.age - cand.age) <= 1:
            s += 0.2
            reasons.append("age")
        elif abs(profile.age - cand.age) > 5:
            s -= 0.2
            reasons.append("age differs")
    if set(profile.phones) & set(cand.phones):
        s += 0.3
        reasons.append("phone")
    for rel in profile.relatives:
        parts = rel.split()
        if len(parts) >= 2 and _name_in(text, parts[0], parts[-1]):
            s += 0.1
            reasons.append("relative")
            break
    return max(0.0, min(1.0, round(s, 2))), reasons


def name_present(body: bytes | str, profile: Profile) -> bool:
    """Does a listing page still show any of the subject's names? Used to verify removals."""
    raw = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    try:
        text = _text(lxml_html.fromstring(raw))
    except Exception:
        text = raw
    return any(_name_in(text, n.first, n.last) for n in profile.names)
