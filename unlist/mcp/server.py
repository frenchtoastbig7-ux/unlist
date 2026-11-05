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
    (tools.scan_usernames, "Check where the subject's usernames exist (WhatsMyName dataset, about 700 sites, one request each). Hits are candidate accounts to confirm. Minutes per username. Needs consent."),
    (tools.scan_mentions, "Search the web for the subject's name with city, phones and emails (Brave Search API key). Results are shown, not stored; broker sites are flagged. Needs consent."),
    (tools.mentions_confirm, "Record URLs as pages about the subject; a URL on a known broker's site becomes a confirmed listing."),
    (tools.scan_domains, "For domains the subject owns: SPF, DMARC, MX and hostnames in certificate logs. Needs consent."),
    (tools.exposures_list, "Accounts found by username, confirmed web mentions and owned-domain findings, by kind and status."),
    (tools.exposures_confirm, "Mark exposures as the subject's own (comma-separated ids)."),
    (tools.exposures_reject, "Mark exposures as someone else's (comma-separated ids)."),
    (tools.exposures_resolve, "Mark exposures as dealt with (account deleted, page gone, record fixed)."),
    (tools.requests_draft, "Draft removal requests: one per broker with confirmed findings, or one for a named broker. Law and channel chosen from residency and the catalog. Nothing is sent until approved."),
    (tools.requests_draft_blind, "Draft email deletion requests to brokers with no known listing (catalog brokers with an email address), by category, capped."),
    (tools.requests_list, "Removal requests by subject, state (or 'open') and broker."),
    (tools.requests_show, "One request in full: letter text, listings, events, replies."),
    (tools.requests_approve, "Approve drafted requests by id, or 'all'. The gate before anything is sent or opened."),
    (tools.requests_send, "Send approved email requests from the opt-out mailbox; dry_run lists them instead."),
    (tools.requests_mark, "Set a request's state by hand (completed, cancelled, failed, submitted...)."),
    (tools.inbox_poll, "Read the opt-out mailbox: classify replies, follow confirmation links on broker hosts, update request states, surface the rest."),
    (tools.form_open, "Open an approved form request in a visible browser, prefilled; you submit and close the window; before/after screenshots are kept."),
    (tools.letter_write, "Render a mail-channel request as a PDF letter."),
    (tools.drop_prepare, "California DROP: the exact profile to enter at the state platform."),
    (tools.drop_record, "Record the DROP ID after submitting, to track the 45-day cycle."),
    (tools.exposure_score, "Exposure score 0-100 (higher is worse) with the breakdown and trend."),
    (tools.accounts_cleanup, "Where and how to delete confirmed accounts and accounts at breached services (JustDeleteMe directory)."),
    (tools.account_deletion_draft, "Draft an account-deletion email to a service that accepts one; goes through approve and send."),
    (tools.google_results_prepare, "Prepare Google's Results about you: steps and the URLs to submit; tracked as a manual request."),
    (tools.monitor_run_due, "Run every scheduled job that is due (breach rescans, listing verification, full sweep, deadlines, DROP cycle, follow-ups, inbox); force runs all. Writes a monitor report."),
    (tools.monitor_status, "Scheduled jobs: interval, last run, next due, last result."),
    (tools.monitor_set_interval, "Change a job's interval (e.g. verify_listings 7d)."),
    (tools.reports_list, "Reports written so far, newest first."),
    (tools.report_read, "Read one report by path."),
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
