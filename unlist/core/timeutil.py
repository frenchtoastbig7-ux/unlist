"""UTC time helpers. Everything stored or displayed is UTC."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from dateutil import parser as _dparser

ISO_Z = "%Y-%m-%dT%H:%M:%SZ"

_INTERVAL_RE = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.IGNORECASE)
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def utcnow() -> datetime:
    """Current time as an aware UTC datetime, truncated to whole seconds."""
    return datetime.now(UTC).replace(microsecond=0)


def to_utc(dt: datetime) -> datetime:
    """Convert any datetime to aware UTC. Naive datetimes are assumed to be UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def iso_z(dt: datetime) -> str:
    """Format as ISO 8601 UTC with the Z suffix, second precision."""
    return to_utc(dt).replace(microsecond=0).strftime(ISO_Z)


def now_iso() -> str:
    return iso_z(utcnow())


def parse_dt(value: str | datetime | int | float | None) -> datetime | None:
    """Parse common date representations into an aware UTC datetime.

    Accepts ISO 8601 (with or without Z), RFC 2822 (HTTP dates), Wayback
    14-digit timestamps, unix epoch numbers, and most human formats dateutil
    understands. Returns None when the value is empty or unparseable.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return to_utc(value)
    if isinstance(value, int | float):
        return datetime.fromtimestamp(float(value), tz=UTC)
    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"\d{14}", text):
        return datetime.strptime(text, "%Y%m%d%H%M%S").replace(tzinfo=UTC)
    if re.fullmatch(r"\d{9,11}(\.\d+)?", text):
        return datetime.fromtimestamp(float(text), tz=UTC)
    try:
        parsed = _dparser.parse(text)
    except (ValueError, OverflowError):
        return None
    return to_utc(parsed)


def normalise(value: str | datetime | int | float | None) -> str | None:
    """Parse and re-emit as ISO 8601 Z, or None."""
    dt = parse_dt(value)
    return iso_z(dt) if dt else None


def parse_interval(text: str) -> int:
    """Parse '6h', '30m', '2d', '1w', '90s' into seconds."""
    m = _INTERVAL_RE.match(text)
    if not m:
        raise ValueError(f"bad interval {text!r}; use forms like 30m, 6h, 2d, 1w")
    return int(m.group(1)) * _UNIT_SECONDS[m.group(2).lower()]


def format_interval(seconds: int) -> str:
    for unit, size in (("w", 604800), ("d", 86400), ("h", 3600), ("m", 60)):
        if seconds % size == 0 and seconds >= size:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


def is_due(last_run: str | None, interval_seconds: int | None, now: datetime | None = None) -> bool:
    """True when a scheduled job should run: never run, or interval elapsed."""
    if interval_seconds is None or interval_seconds <= 0:
        return False
    if not last_run:
        return True
    last = parse_dt(last_run)
    if last is None:
        return True
    now = now or utcnow()
    return now >= last + timedelta(seconds=interval_seconds)


def local_label(dt: datetime) -> str:
    """For report output only: the local rendering of a UTC time, labelled as such."""
    local = to_utc(dt).astimezone()
    return local.strftime("%Y-%m-%d %H:%M %Z (local)")
