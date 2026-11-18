"""Markdown report helpers with a standard header (tool, run time UTC, parameters, counts)."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path

from unlist import __version__, paths
from unlist.core.timeutil import iso_z, local_label, utcnow

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(text: str, max_len: int = 60) -> str:
    slug = _SLUG_RE.sub("-", text.lower()).strip("-")
    return slug[:max_len].rstrip("-") or "report"


def header(
    tool: str,
    title: str,
    params: Mapping[str, object] | None = None,
    counts: Mapping[str, object] | None = None,
    run_at: datetime | None = None,
) -> str:
    run_at = run_at or utcnow()
    lines = [
        f"# {title}",
        "",
        f"- Tool: `{tool}` (unlist {__version__})",
        f"- Run at: {iso_z(run_at)}, which is {local_label(run_at)}",
    ]
    if params:
        lines.append("- Parameters:")
        for k, v in params.items():
            lines.append(f"  - {k}: {_fmt(v)}")
    if counts:
        lines.append("- Counts:")
        for k, v in counts.items():
            lines.append(f"  - {k}: {_fmt(v)}")
    lines.append("")
    lines.append("All times are UTC unless labelled local.")
    lines.append("")
    return "\n".join(lines)


def _fmt(v: object) -> str:
    if isinstance(v, list | tuple):
        return ", ".join(str(x) for x in v) if v else "(none)"
    if v is None or v == "":
        return "(none)"
    return str(v)


def table(headers: Iterable[str], rows: Iterable[Iterable[object]]) -> str:
    headers = list(headers)
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(" --- " for _ in headers) + "|"]
    for row in rows:
        cells = [_cell(c) for c in row]
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out)


def _cell(v: object) -> str:
    s = "" if v is None else str(v)
    return s.replace("|", "\\|").replace("\n", " ")


def code_block(text: str, lang: str = "") -> str:
    fence = "```"
    while fence in text:
        fence += "`"
    return f"{fence}{lang}\n{text.rstrip()}\n{fence}"


def report_path(
    tool: str, slug: str, run_at: datetime | None = None, data_dir: Path | None = None
) -> Path:
    run_at = run_at or utcnow()
    base = (data_dir or paths.data_dir()) / "reports" / tool
    return base / f"{run_at:%Y-%m-%d}_{slugify(slug)}.md"


def write_report(
    tool: str,
    slug: str,
    title: str,
    body: str,
    params: Mapping[str, object] | None = None,
    counts: Mapping[str, object] | None = None,
    run_at: datetime | None = None,
    data_dir: Path | None = None,
) -> Path:
    run_at = run_at or utcnow()
    path = report_path(tool, slug, run_at, data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = header(tool, title, params, counts, run_at) + "\n" + body.rstrip() + "\n"
    path.write_text(content, encoding="utf-8")
    return path
