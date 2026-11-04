"""People-search scanning: build each broker's search URL from the subject's names and
places, fetch it (plain HTTP first, a visible browser when the site refuses robots),
keep the page and a screenshot as evidence, and score every listing against the subject.

A listing is a *candidate* until the operator confirms it. Independent tests of
commercial services found around four in ten returned records belong to someone else.
"""

from unlist.scanners.brokers.run import BrokerScanResult, scan_brokers, verify_finding

__all__ = ["BrokerScanResult", "scan_brokers", "verify_finding"]
