"""Shared plumbing: fetch, store, extract, report, timeutil, audit, testing helpers.

Copied from ttw-toolkit's ttw_core (same author, MIT) and trimmed: no WARC, no
language tooling. The evidence rules are unchanged: raw bytes are written once and
never modified, every capture carries a SHA-256 and a UTC timestamp, refusals are
recorded rather than worked around.
"""
