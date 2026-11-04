"""unlist-mcp: a local stdio MCP server exposing unlist to the Claude desktop app.

Everything runs on this machine; the server never listens on a network port.
"""

from __future__ import annotations

from collections.abc import Callable

from mcp.server.mcpserver import MCPServer

from unlist import __version__
from unlist.mcp import tools

INSTRUCTIONS = """unlist: a local tool that finds the operator's own personal data on data brokers,
people-search sites and in breach databases, drives opt-out requests, keeps evidence, and watches
for reappearance. Local only; the data directory holds personal data of consenting subjects.

Rules the tools enforce: nothing runs for a subject without consent on record and in force;
findings are candidates until the operator confirms them; nothing is sent or submitted until
the operator approves it; CAPTCHAs and phone verifications are the operator's to do; the tool
never solves them. Every action is written to a hash-chained audit log. All times are UTC.

Tools are grouped by prefix: status/audit_, subject_/identifier_/consent_ (who the tool works
for), catalog_ (the brokers and how to opt out), scan_ (find listings and breach hits),
findings_ (confirm or reject candidates), requests_ (draft, approve, send), inbox_ (replies and
verification links), form_ (browser-assisted web forms), drop_ (California DROP), monitor_ and
report_. Network tools can take minutes because of the per-host rate limiter."""

# (function, description). Order is the order shown to the model.
TOOLS: list[tuple[Callable, str]] = [
    (tools.status, "What is on this machine: subjects, identifiers, catalog size, counts, credentials present, audit chain."),
    (tools.subject_add, "Create a subject: yourself (kind self) or a consenting household member. Two-letter residency_state decides which law requests cite."),
    (tools.subject_list, "List subjects with identifier counts and consent state."),
    (tools.subject_show, "Show one subject: consent, every identifier with location metadata."),
    (tools.consent_grant, "Record consent for a subject (holder, instrument, expiry YYYY-MM-DD). Required before any scan, draft or send."),
    (tools.identifier_add, "Add a name, alias, email, phone, address, dob, username or relative to a subject, with city/state (and years for addresses)."),
    (tools.identifier_remove, "Remove an identifier by id."),
    (tools.catalog_list, "List brokers in the catalog, optionally by category or only the searchable people-search sites."),
    (tools.catalog_show, "Everything known about one broker: hosts, registry, contact, search template, opt-out method and requirements."),
    (tools.catalog_search, "Find brokers by name, alias, id or host."),
    (tools.audit_tail, "Last entries of the audit log and whether the hash chain verifies."),
    (tools.scan_breaches, "Look up the subject's email addresses in breach databases (HIBP with key, LeakCheck, XposedOrNot). Breach names and data classes only. Needs consent."),
    (tools.breaches_list, "Breach hits recorded for a subject, optionally only those first seen since an ISO date."),
    (tools.password_checks_list, "Results of Pwned Passwords checks made at the terminal (label and count only; passwords are never typed in chat)."),
    (tools.report_exposure, "Markdown exposure report for a subject: breaches, listings, requests, password checks; also written to the reports directory."),
    (tools.scan_brokers, "Search people-search sites for the subject's names and places; HTTP first, a visible browser when refused. Listings become candidates to confirm. Slow. Needs consent."),
    (tools.findings_list, "Listings found for a subject, optionally by status (candidate, confirmed, rejected, requested, removed, reappeared) or broker."),
    (tools.findings_show, "One finding in full: what the page showed, score reasons, evidence paths."),
    (tools.findings_confirm, "Mark findings as the subject's own (comma-separated ids). Only confirmed findings get removal requests."),
    (tools.findings_reject, "Mark findings as someone else's (comma-separated ids)."),
    (tools.findings_verify, "Re-open listings to see whether they are still there; gone moves a finding to removed, back again to reappeared."),
]


def build_server() -> MCPServer:
    server = MCPServer(
        name="unlist",
        title="unlist: personal data exposure and removal",
        instructions=INSTRUCTIONS,
        version=__version__,
    )
    for fn, description in TOOLS:
        server.tool(name=fn.__name__, description=description)(fn)
    return server


def main() -> None:
    _load_dotenv()
    build_server().run(transport="stdio")


def _load_dotenv() -> None:
    """GUI apps do not read the shell profile; read <repo>/.env if present."""
    import os
    from pathlib import Path

    for candidate in (Path.cwd() / ".env", Path(__file__).resolve().parents[2] / ".env"):
        if candidate.is_file():
            for line in candidate.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip("'\""))
            break


if __name__ == "__main__":
    main()
