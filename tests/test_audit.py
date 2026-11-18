import json

from unlist.core.audit import AuditLog


def test_chain_verifies_and_detects_edits(data_dir):
    log = AuditLog(data_dir / "audit.jsonl")
    log.append("a", x=1)
    log.append("b", y=2)
    assert log.verify()[0]
    lines = (data_dir / "audit.jsonl").read_text().splitlines()
    first = json.loads(lines[0])
    first["data"]["x"] = 999
    (data_dir / "audit.jsonl").write_text(json.dumps(first) + "\n" + lines[1] + "\n")
    ok, detail = log.verify()
    assert not ok and "Entry 1" in detail


def test_dropped_line_detected(data_dir):
    log = AuditLog(data_dir / "audit.jsonl")
    for i in range(3):
        log.append("e", i=i)
    lines = (data_dir / "audit.jsonl").read_text().splitlines()
    (data_dir / "audit.jsonl").write_text(lines[0] + "\n" + lines[2] + "\n")
    assert not log.verify()[0]
