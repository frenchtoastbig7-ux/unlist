from __future__ import annotations

from pathlib import Path

import pytest

from unlist.db import open_db

FIXTURES = Path(__file__).parent / "fixtures"


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
