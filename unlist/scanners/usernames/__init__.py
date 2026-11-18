"""Where does a handle of yours exist? One request per site, using the WhatsMyName
project's detection rules (CC BY-SA 4.0, fetched at run time and cached, never shipped).

This is a lookup of the subject's own username, one profile URL per site, not a crawl,
so robots.txt is not consulted here; sites the dataset marks as protected by a challenge
are skipped rather than worked around.
"""

from unlist.scanners.usernames.wmn import UsernameScanResult, scan_usernames

__all__ = ["UsernameScanResult", "scan_usernames"]
