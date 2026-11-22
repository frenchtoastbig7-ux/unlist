import stat
from pathlib import Path

from unlist.core import store
from unlist.db import MIGRATION_DIRS, open_db


def test_migrate_is_idempotent(conn):
    assert store.migrate(conn, MIGRATION_DIRS) == []
    names = {r[0] for r in conn.execute("SELECT name FROM schema_migrations")}
    assert "core/0001_captures.sql" in names
    assert "subjects/0001_subjects.sql" in names
    on_disk = sum(len(list(d.glob("*.sql"))) for d in (store.CORE_MIGRATIONS, *MIGRATION_DIRS))
    assert len(names) == on_disk


def test_db_file_is_private(data_dir):
    conn = open_db(data_dir / "unlist.db")
    conn.close()
    mode = stat.S_IMODE((data_dir / "unlist.db").stat().st_mode)
    assert mode == 0o600


def test_raw_path_layout(data_dir):
    p = store.raw_path_for("brokers", "ab" * 32, "html", "2026-11-04T14:05:09Z", data_dir)
    assert p == data_dir / "raw" / "brokers" / "2026" / "11" / "04" / ("ab" * 32 + ".html")
    assert store.text_path_for(p) == data_dir / "text" / "brokers" / "2026" / "11" / "04" / (
        "ab" * 32 + ".txt"
    )


def test_write_raw_never_modifies(tmp_path: Path):
    p = tmp_path / "x.html"
    store.write_raw(p, b"hello")
    store.write_raw(p, b"hello")
    try:
        store.write_raw(p, b"changed")
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected refusal to overwrite raw file")
    assert p.read_bytes() == b"hello"


def test_insert_and_get_capture(conn):
    row = store.CaptureRow(
        tool="brokers",
        requested_url="https://x.test/a",
        final_url="https://x.test/a",
        status=403,
        captured_at="2026-11-04T00:00:00Z",
        sha256="0" * 64,
        raw_path="raw/brokers/2026/11/04/0.html",
        kind="refusal",
        note="403",
    )
    cid = store.insert_capture(conn, row)
    got = store.get_capture(conn, cid)
    assert got["kind"] == "refusal" and got["status"] == 403
