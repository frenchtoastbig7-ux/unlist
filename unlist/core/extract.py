"""HTML to text. trafilatura first, readability-lxml as fallback. Returns text and language."""

from __future__ import annotations

import re
from dataclasses import dataclass

from lxml import html as lxml_html

try:  # optional at import time so tests can run without the model files
    import py3langid
except Exception:  # pragma: no cover
    py3langid = None

_WS = re.compile(r"[ \t\r\f\v]+")
_BLANKS = re.compile(r"\n{3,}")


@dataclass
class Extracted:
    text: str
    lang: str | None
    title: str | None
    method: str


def normalise_whitespace(text: str) -> str:
    text = text.replace("\xa0", " ")
    text = _WS.sub(" ", text)
    text = "\n".join(line.strip() for line in text.splitlines())
    text = _BLANKS.sub("\n\n", text)
    return text.strip()


def _html_lang(raw: str) -> str | None:
    m = re.search(r"<html[^>]*\blang\s*=\s*[\"']?([A-Za-z]{2,3})(?:[-_][A-Za-z]+)?", raw[:4000])
    return m.group(1).lower() if m else None


def _title(raw: str) -> str | None:
    m = re.search(r"<title[^>]*>(.*?)</title>", raw, re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    return normalise_whitespace(re.sub(r"\s+", " ", m.group(1))) or None


def detect_lang(text: str, html_hint: str | None = None) -> str | None:
    """Prefer the document's own lang attribute; fall back to py3langid on the text."""
    if html_hint:
        return html_hint
    if py3langid is None or len(text) < 20:
        return None
    try:
        lang, _ = py3langid.classify(text[:20000])
    except Exception:  # pragma: no cover
        return None
    return lang


def _via_trafilatura(raw: str, url: str | None) -> str | None:
    try:
        import trafilatura
    except ImportError:  # pragma: no cover
        return None
    text = trafilatura.extract(
        raw,
        url=url,
        include_comments=False,
        include_tables=True,
        favor_recall=True,
        output_format="txt",
    )
    return text or None


def _via_readability(raw: str) -> str | None:
    try:
        from readability import Document
    except ImportError:  # pragma: no cover
        return None
    try:
        doc = Document(raw)
        summary = doc.summary(html_partial=True)
    except Exception:
        return None
    tree = lxml_html.fromstring(summary)
    for bad in tree.xpath("//script|//style|//noscript"):
        bad.drop_tree()
    text = tree.text_content()
    return text or None


def _via_body(raw: str) -> str:
    try:
        tree = lxml_html.fromstring(raw)
    except Exception:
        return ""
    for bad in tree.xpath("//script|//style|//noscript|//nav|//header|//footer"):
        bad.drop_tree()
    return tree.text_content()


def extract(
    data: bytes | str, url: str | None = None, content_type: str | None = None
) -> Extracted:
    """Extract main text and detect language from an HTML (or plain text) document."""
    raw = _decode(data, content_type) if isinstance(data, bytes) else data
    ct = (content_type or "").lower()
    if ct.startswith("text/plain") or not re.search(r"<\s*(html|body|div|p|article)\b", raw, re.I):
        text = normalise_whitespace(raw)
        return Extracted(text=text, lang=detect_lang(text), title=None, method="plain")

    hint = _html_lang(raw)
    title = _title(raw)
    text = _via_trafilatura(raw, url)
    method = "trafilatura"
    if not text or len(text.strip()) < 80:
        alt = _via_readability(raw)
        if alt and len(alt.strip()) > len(text or ""):
            text, method = alt, "readability"
    if not text or len(text.strip()) < 80:
        alt = _via_body(raw)
        if alt and len(alt.strip()) > len(text or ""):
            text, method = alt, "body"
    text = normalise_whitespace(text or "")
    return Extracted(text=text, lang=detect_lang(text, hint), title=title, method=method)


def _decode(data: bytes, content_type: str | None) -> str:
    charset = None
    if content_type:
        m = re.search(r"charset=([\w\-]+)", content_type, re.I)
        if m:
            charset = m.group(1)
    if not charset:
        head = data[:4096].decode("ascii", "ignore")
        m = re.search(r"charset=[\"']?([\w\-]+)", head, re.I)
        if m:
            charset = m.group(1)
    for enc in filter(None, (charset, "utf-8", "gb18030", "latin-1")):
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", "replace")
