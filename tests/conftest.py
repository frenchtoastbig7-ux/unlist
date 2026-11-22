from __future__ import annotations

import datetime as _dt
import importlib
import sys
from pathlib import Path

import pytest

from unlist.core import timeutil
from unlist.db import open_db

FIXTURES = Path(__file__).parent / "fixtures"

# The suite's fixtures grant consent for fixed windows (most end 2027-01-01), so the
# application's idea of "now" is pinned inside them. Tests of expiry pass their own dates.
FROZEN_NOW = _dt.datetime(2026, 11, 22, 12, 0, 0, tzinfo=_dt.UTC)

_RealDate = _dt.date
_RealDateTime = _dt.datetime

# Application modules that read date.today() or datetime.now() themselves instead of
# going through unlist.core.timeutil. Imported up front so the sweep below finds them
# even when a test would only import them later.
_DIRECT_CLOCK_READERS = (
    "unlist.app.views",
    "unlist.mcp.tools",
    "unlist.reports.score",
    "unlist.scanners.brokers.urls",
    "unlist.core.audit",
)


class _FrozenMeta(type(_RealDate)):
    def __instancecheck__(cls, obj: object) -> bool:
        return isinstance(obj, cls.__mro__[1])


class _FrozenDate(_RealDate, metaclass=_FrozenMeta):
    """date, except today() is pinned. Constructing one yields a plain date."""

    def __new__(cls, *args, **kwargs):
        return _RealDate(*args, **kwargs)

    @classmethod
    def today(cls):
        return FROZEN_NOW.date()


class _FrozenDateTime(_RealDateTime, metaclass=_FrozenMeta):
    """datetime, except now()/utcnow()/today() are pinned."""

    def __new__(cls, *args, **kwargs):
        return _RealDateTime(*args, **kwargs)

    @classmethod
    def now(cls, tz=None):
        return FROZEN_NOW.astimezone(tz) if tz else FROZEN_NOW.replace(tzinfo=None)

    @classmethod
    def utcnow(cls):
        return FROZEN_NOW.replace(tzinfo=None)

    @classmethod
    def today(cls):
        return FROZEN_NOW.replace(tzinfo=None)


def _is_class(obj: object, base: type, but_not: type | None = None) -> bool:
    if not isinstance(obj, type) or not issubclass(obj, base):
        return False
    return but_not is None or not issubclass(obj, but_not)


@pytest.fixture(autouse=True)
def frozen_clock(request, monkeypatch):
    """Pin the clock the application reads. Opt out with @pytest.mark.real_clock."""
    if request.node.get_closest_marker("real_clock"):
        return None
    monkeypatch.setattr(timeutil, "_clock", lambda: FROZEN_NOW)
    for name in _DIRECT_CLOCK_READERS:
        try:
            importlib.import_module(name)
        except Exception:  # an optional dependency missing: nothing there to pin
            continue
    for name, module in list(sys.modules.items()):
        if module is None or not (name == "unlist" or name.startswith("unlist.")):
            continue
        if _is_class(getattr(module, "date", None), _RealDate, but_not=_RealDateTime):
            monkeypatch.setattr(module, "date", _FrozenDate)
        if _is_class(getattr(module, "datetime", None), _RealDateTime):
            monkeypatch.setattr(module, "datetime", _FrozenDateTime)
    return FROZEN_NOW


def pytest_configure(config):
    config.addinivalue_line("markers", "real_clock: do not pin the application clock")


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def data_dir(tmp_path, monkeypatch) -> Path:
    d = tmp_path / "data"
    d.mkdir()
    monkeypatch.setenv("UNLIST_DATA_DIR", str(d))
    monkeypatch.setenv("UNLIST_ACTOR", "tests")
    return d


@pytest.fixture
def conn(data_dir):
    c = open_db(data_dir / "unlist.db")
    yield c
    c.close()
