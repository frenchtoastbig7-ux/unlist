"""A tiny text-only PDF writer for postal letters, so no PDF library is needed."""

from __future__ import annotations

import sqlite3
import textwrap
from pathlib import Path

from unlist import paths
from unlist.requests import engine

PAGE_W, PAGE_H = 612, 792  # US Letter, points
MARGIN = 72
LINE_H = 14
FONT_SIZE = 11
CHARS_PER_LINE = 88


def _escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def text_to_pdf(text: str) -> bytes:
    lines: list[str] = []
    for para in text.splitlines():
        if not para.strip():
            lines.append("")
            continue
        lines.extend(textwrap.wrap(para, CHARS_PER_LINE, replace_whitespace=False) or [""])
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
            safe = _escape(ln.encode("cp1252", "replace").decode("cp1252"))
            content_lines.append(f"({safe}) Tj T*")
        content_lines.append("ET")
        stream = "\n".join(content_lines).encode("cp1252", "replace")
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
    p.write_bytes(text_to_pdf(text))
    paths.make_private(p)
    engine.add_event(conn, request_id, "letter_written", str(p))
    conn.commit()
    return p
