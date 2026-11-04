CREATE TABLE IF NOT EXISTS captures (
  id INTEGER PRIMARY KEY,
  tool TEXT NOT NULL,
  requested_url TEXT NOT NULL,
  final_url TEXT NOT NULL,
  status INTEGER,
  captured_at TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  raw_path TEXT NOT NULL,
  text_path TEXT,
  shot_path TEXT,
  kind TEXT NOT NULL DEFAULT 'fetch',
  headers_json TEXT,
  note TEXT
);
CREATE INDEX IF NOT EXISTS captures_tool_url ON captures(tool, requested_url);
CREATE INDEX IF NOT EXISTS captures_sha ON captures(sha256);
