"""Breach-database lookups for a subject's email addresses.

Sources return breach names and data classes, never leaked values:
- Have I Been Pwned: the public breach list without a key; per-address lookups with
  HIBP_API_KEY (a Core plan; checking your own addresses is within the terms).
- LeakCheck public API: source names and field types, no key, one request a second.
- XposedOrNot: breach names, no key.
- Pwned Passwords: k-anonymity range lookup for a password typed at the CLI prompt;
  only the count is kept.
"""

from unlist.scanners.breaches.run import ScanResult, scan_breaches

__all__ = ["ScanResult", "scan_breaches"]
