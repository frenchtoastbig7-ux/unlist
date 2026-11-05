# unlist

Find your own personal data on people-search sites, data brokers and in breach databases,
get it removed, keep the evidence, and notice when it comes back. A local tool for one
operator and the household members who agree to it, driven from the Claude desktop app
through an MCP connector.

Not a service. Nothing is hosted, no account exists anywhere, and the only personal data
the project holds is in a directory on your machine (`~/.unlist`) that is never part of
this repository.

## What it does

| Area | What you get |
| --- | --- |
| **Subjects and consent** | You and, if they agree, people in your household. Every scan, draft and send checks that consent is recorded and has not expired. |
| **Catalog** | 848 brokers: curated people-search entries with search patterns and opt-out playbooks, the California state registry, and a public-domain opt-out manual, merged so each company appears once. 27 sites are searchable by name, phone number or street address. See [CATALOG-SOURCES.md](CATALOG-SOURCES.md). |
| **People-search scanning** | Rate-limited fetches that honour robots.txt and record refusals, falling back to a visible browser you can watch. Every page is evidence with a SHA-256 and a screenshot. Matches are candidates until you confirm them, because independent tests found roughly four in ten "found" records belong to someone else. |
| **Breaches and dark web** | Have I Been Pwned (breaches, pastes, and infostealer logs if your plan includes them), LeakCheck (emails and usernames; phones with a Pro key, values dropped), XposedOrNot analytics with a risk score, and Pwned Passwords by k-anonymity at a hidden terminal prompt. |
| **Footprint** | Where your usernames exist (WhatsMyName rules, about 590 usable sites), web mentions of your name, phone and email (Brave Search API, shown and not stored), and SPF, DMARC and certificate-log checks for domains you own. |
| **Exposure score** | One number from 0 to 100 with every point explained, and its trend. Removing a listing or closing an account lowers it. |
| **Removal** | Requests under the law that applies to you (CCPA, GDPR, your state's privacy act, or a plain request), sent from a dedicated mailbox after you approve a batch and paced by a daily cap; web forms prefilled in a visible browser where you click submit; California DROP and Google's "Results about you" prepared for you to submit; postal letters as PDFs. |
| **Account clean-up** | For accounts you confirm and services that were breached: where to delete the account and how hard it is (JustDeleteMe directory), with a drafted email where the service takes one. |
| **Monitoring** | Eleven scheduled jobs: breach rescans, listing verification, full sweeps, deadlines with escalation notes, the DROP cycle, follow-ups, the inbox, the send queue, usernames, domains and the score. A launchd job runs them daily. |
| **Audit** | Everything the tool did on your behalf goes to a hash-chained log. |

### How this compares with a commercial service

It covers the same ground as pentester.com's consumer product: an exposure scan, a score,
breach and paste monitoring, a broker catalog of similar size, removals and rescans, and
extra people. Two things it does not have: a proprietary multi-billion-record breach corpus
(it asks every public source that will answer for your own identifiers, and what a paid key
unlocks is listed in `.env.example`), and a web vulnerability scanner. What it adds is that
nothing leaves your machine except the lookups and requests themselves, every claim has a
stored page behind it, and nothing is sent without your approval.

## Install

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --extra extract
```

Browser-assisted scanning and forms need Playwright as well:

```bash
uv sync --extra extract --extra browser
uv run playwright install chromium
```

## The dashboard

```bash
uv sync --extra extract --extra app
uv run unlist app
```

opens http://127.0.0.1:8787/ (localhost only, never a network port): subjects and
identifiers, scans as background jobs with a live log, candidate listings with their
screenshots to confirm or reject, request drafts to read and approve, sending, the inbox,
the monitor schedule, reports, the catalog and the audit log. Form posts are accepted only
from the dashboard's own origin, so a web page you happen to visit cannot drive it.

## Connect it to the Claude desktop app

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (adjust the two
paths), then quit and reopen Claude:

```json
{
  "mcpServers": {
    "unlist": {
      "command": "/Users/you/.local/bin/uv",
      "args": ["--directory", "/path/to/unlist", "run", "unlist-mcp"]
    }
  }
}
```

## A first session, in chat

1. "Create a subject for me, resident of California" → `subject_add`
2. "Record my consent for a year" → `consent_grant`
3. "Add my name Jane Q Doe in Oakland CA, my previous address in Berkeley 94704, my email
   and phone" → `identifier_add` (names and addresses carry city and state; brokers index
   by place; a date of birth is only needed for DROP and never goes in a letter)
4. "Scan breaches" → `scan_breaches`; "scan the people-search sites" → `scan_brokers`
   (a Chromium window opens for sites that refuse plain fetches; if one shows a CAPTCHA,
   solve it there and the scan continues)
5. "Show me the candidates" → `findings_list`; confirm the ones that are you, reject the
   rest (`findings_confirm`, `findings_reject`)
6. "Draft the requests" → `requests_draft`; read them with `requests_show`; "approve all"
7. "Send them" → `requests_send` (email, from the opt-out mailbox); "open the Spokeo
   form" → `form_open` (prefilled; you click submit and close the window)
8. Californians: "prepare DROP" → `drop_prepare`, submit at the state site, `drop_record`
9. Later: "poll the inbox" → `inbox_poll`; "what's due?" → `monitor_run_due`;
   "exposure report" → `report_exposure`

10. "Add my usernames and scan them" → `scan_usernames`, then confirm the accounts that are
    yours (`exposures_confirm`); "what should I delete?" → `accounts_cleanup`
11. "What's my score?" → `exposure_score`

For blind requests to brokers you have no listing on (the Incogni approach), use
`requests_draft_blind` with a category and a cap, then approve. Approved email requests go
out at most 40 a day (`UNLIST_SEND_DAILY_CAP`), people-search sites first; the monitor sends
the next share each day.

Credentials (optional HIBP key, the opt-out mailbox) go in `.env` at the repo root; see
`.env.example`. GUI apps do not read your shell profile, so the server reads that file.

## Network posture

- Per-host rate limit, a plain user agent naming this project, robots.txt honoured for
  plain HTTP. A 403 or a robots disallow is recorded as a refusal, not worked around; the
  browser path is a visible browser doing what you would do by hand.
- Breach lookups use sources that return breach names and data classes. The one optional
  source that returns leaked values (LeakCheck Pro, for phone numbers) has them dropped at
  parse time; the stored copy of its answer is redacted.
- The username scanner makes one request per site for your own handle. That is a lookup, not
  a crawl, so robots.txt is not consulted there; sites the dataset marks as challenge-protected
  are skipped.
- Web-mention results are not written to disk.
- Outbound email goes from a mailbox you create for this purpose, never your main account.

## Legal basis the requests cite

| Residency | Basis | Response window |
| --- | --- | --- |
| California | CCPA/CPRA deletion (Civ. Code § 1798.105) or opt-out of sale (§ 1798.120); authorised-agent wording per 11 CCR § 7063 / § 7026(j) | 45 days (deletion), 15 business days (opt-out) |
| EU/EEA/UK | GDPR Art. 17 erasure | one month |
| Other US states with a comprehensive privacy law | that state's deletion right | 45 days (90 in Iowa) |
| Elsewhere | plain removal request citing the broker's own opt-out policy | 30 days by convention |

California residents also get a prepared profile for the state's DROP platform, which brokers
must honour on a 45-day cycle; the tool cannot submit it for you (there is no consumer API).

## What it will not do

Solve CAPTCHAs, answer verification calls, upload identity documents, submit forms unattended,
keep leaked passwords or other leaked values, scan websites for vulnerabilities, run for anyone
whose consent is not on record, or send anything you have not approved.

## Scheduling

```bash
uv run unlist monitor install-launchd --hour 9
```

writes `~/Library/LaunchAgents/inc.sovereignedge.unlist.plist` so `unlist run-due` runs
every morning: breach rescans weekly, listing verification every 14 days, a full sweep and
a username recheck monthly, owned-domain checks weekly, and deadline, DROP-cycle, follow-up,
inbox, send-queue and score jobs daily. Web mentions run on demand only, since their
results are not stored and so cannot be compared between runs.
Intervals are changed with `monitor_set_interval`. Each run writes a report under
`~/.unlist/reports/monitor/` and posts a macOS notification when something changed.

## Development

```bash
uv sync --extra extract --extra dev
uv run ruff check .
uv run pytest -q
uv run unlist catalog validate
```

Regenerate the registry part of the catalog from the current CPPA CSV:

```bash
uv run unlist catalog import-registry --cppa registry.csv --markup data-broker-opt-out-pages.csv
```

## Layout

```
unlist/
  core/        fetch, store, extract, report, timeutil, audit, testing helpers
  subjects/    Subject, Identifier, Consent and their SQLite repo
  catalog/     Broker schema, loader, importers, brokers/*.yaml, registry/cppa.yaml
  scanners/    breaches/ (HIBP, LeakCheck, XposedOrNot), brokers/ (urls, browser, matcher,
               findings, run), usernames/, mentions/, domains/, exposures
  requests/    legal bases, letter templates, engine, mailer, inbox, form, drop, pdf
  monitor/     scheduled jobs, escalation notes, launchd plist
  reports/     exposure report and score
  mcp/         the MCP server and its tools
  app/         the local web dashboard (FastAPI, Jinja, one background job worker)
  cli.py       serve-mcp, status, catalog maintenance
tests/         offline; browser tests are marked and skipped in CI
```

## Licence

MIT © 2026 Sovereign Edge Inc. See [LICENSE](LICENSE).
