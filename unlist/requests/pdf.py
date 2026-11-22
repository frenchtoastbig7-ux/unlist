"""A tiny text-only PDF writer for postal letters, so no PDF library is needed."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from unlist import paths
from unlist.requests import engine

PAGE_W, PAGE_H = 612, 792  # US Letter, points
MARGIN = 72
LINE_H = 14
FONT_SIZE = 11
TEXT_W = PAGE_W - 2 * MARGIN

# Helvetica advance widths (Adobe core-font AFM, 1/1000 em) for WinAnsi codes 32-126.
_ASCII_W = (
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
    1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
    333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
    556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
)  # fmt: skip
# Codes 128-159 that WinAnsi defines, then 160-255.
_HIGH_W = {
    0x80: 556, 0x82: 222, 0x83: 556, 0x84: 333, 0x85: 1000, 0x86: 556, 0x87: 556, 0x88: 333,
    0x89: 1000, 0x8A: 667, 0x8B: 333, 0x8C: 1000, 0x8E: 611, 0x91: 222, 0x92: 222, 0x93: 333,
    0x94: 333, 0x95: 350, 0x96: 556, 0x97: 1000, 0x98: 333, 0x99: 1000, 0x9A: 500, 0x9B: 333,
    0x9C: 944, 0x9E: 500, 0x9F: 667,
}  # fmt: skip
_LATIN1_W = (
    278, 333, 556, 556, 556, 556, 260, 556, 333, 737, 370, 556, 584, 333, 737, 333,
    400, 584, 333, 333, 333, 556, 537, 278, 333, 333, 365, 556, 834, 834, 834, 611,
    667, 667, 667, 667, 667, 667, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278,
    722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611,
    556, 556, 556, 556, 556, 556, 889, 500, 556, 556, 556, 556, 278, 278, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 584, 611, 556, 556, 556, 556, 500, 556, 500,
)  # fmt: skip
_WIDEST = 1015


class LetterError(ValueError):
    """The letter cannot be rendered faithfully."""


def _encode(text: str) -> bytes:
    """WinAnsi bytes for the built-in Helvetica. The writer has no Unicode font, so text it
    cannot print is refused: a letter must not go out with `?` where a name should be."""
    try:
        return text.encode("cp1252")
    except UnicodeEncodeError:
        bad = sorted({c for c in text if not _encodable(c)})
        shown = " ".join(bad[:12])
        raise LetterError(
            "this letter contains characters the built-in PDF font cannot print "
            f"({shown}); it was not written. Send it by email or print the text yourself."
        ) from None


def _encodable(ch: str) -> bool:
    try:
        ch.encode("cp1252")
    except UnicodeEncodeError:
        return False
    return True


def text_width(text: str, size: float = FONT_SIZE) -> float:
    """Width in points of text set in Helvetica at `size`."""
    units = 0
    for code in _encode(text):
        if 32 <= code <= 126:
            units += _ASCII_W[code - 32]
        elif code >= 160:
            units += _LATIN1_W[code - 160]
        else:
            units += _HIGH_W.get(code, _WIDEST)
    return units * size / 1000


def wrap_line(para: str, max_width: float = TEXT_W, size: float = FONT_SIZE) -> list[str]:
    """Break one paragraph into lines no wider than max_width, at spaces where possible.
    Leading indentation stays on the first line; a single word wider than the line is cut."""
    para = para.expandtabs(4).rstrip()
    body = para.lstrip(" ")
    current = para[: len(para) - len(body)]
    lines: list[str] = []
    started = False
    for word in body.split():
        candidate = current + (" " if started else "") + word
        if text_width(candidate, size) <= max_width:
            current, started = candidate, True
            continue
        if started:
            lines.append(current)
            current, started = "", False
        while text_width(current + word, size) > max_width:
            cut = len(word)
            while cut > 1 and text_width(current + word[:cut], size) > max_width:
                cut -= 1
            lines.append(current + word[:cut])
            current, word = "", word[cut:]
        current, started = current + word, True
    lines.append(current)
    return lines


def _escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def text_to_pdf(text: str) -> bytes:
    lines: list[str] = []
    for para in text.splitlines():
        if not para.strip():
            lines.append("")
            continue
        lines.extend(wrap_line(para))
    per_page = (PAGE_H - 2 * MARGIN) // LINE_H
    pages = [lines[i : i + per_page] for i in range(0, len(lines), per_page)] or [[]]

    objects: list[bytes] = []

    def add(obj: bytes) -> int:
        objects.append(obj)
        return len(objects)

    font = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    page_ids: list[int] = []
    pages_id_placeholder = len(objects) + 1 + 2 * len(pages)  # computed after pages/contents
    for page_lines in pages:
        content_lines = [f"BT /F1 {FONT_SIZE} Tf {MARGIN} {PAGE_H - MARGIN} Td {LINE_H} TL"]
        for ln in page_lines:
            content_lines.append(f"({_escape(ln)}) Tj T*")
        content_lines.append("ET")
        stream = _encode("\n".join(content_lines))
        content = add(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        page = add(
            f"<< /Type /Page /Parent {pages_id_placeholder} 0 R /MediaBox [0 0 {PAGE_W} {PAGE_H}] "
            f"/Resources << /Font << /F1 {font} 0 R >> >> /Contents {content} 0 R >>".encode()
        )
        page_ids.append(page)
    kids = " ".join(f"{p} 0 R" for p in page_ids)
    pages_id = add(f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode())
    assert pages_id == pages_id_placeholder
    catalog = add(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode())

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    trailer = f"trailer\n<< /Size {len(objects) + 1} /Root {catalog} 0 R >>\n"
    out += f"{trailer}startxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def write_letter(conn: sqlite3.Connection, request_id: int) -> Path:
    """Render a request as a PDF letter under <data>/letters, with the postal address on top."""
    from unlist.catalog import load_catalog

    row = engine.get(conn, request_id)
    catalog = load_catalog()
    broker = catalog.get(row["broker_id"]) if row["broker_id"] in catalog else None
    head = []
    if broker and broker.contact.postal:
        head += [broker.name, broker.contact.postal, ""]
    head.append(row["created_at"][:10])
    head.append("")
    text = "\n".join(head) + row["body"]
    out_dir = paths.data_dir() / "letters"
    out_dir.mkdir(parents=True, exist_ok=True)
    paths.make_private(out_dir)
    p = out_dir / f"{row['id']:05d}_{row['tag']}.pdf"
    pdf = text_to_pdf(text)  # raises LetterError before anything is written
    p.write_bytes(pdf)
    paths.make_private(p)
    engine.add_event(conn, request_id, "letter_written", str(p))
    conn.commit()
    return p
