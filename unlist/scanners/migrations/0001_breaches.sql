CREATE TABLE IF NOT EXISTS scan_runs (
  id INTEGER PRIMARY KEY,
  subject_id TEXT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,                 -- breaches | brokers
  started_at TEXT NOT NULL,
  finished_at TEXT,
  params_json TEXT NOT NULL DEFAULT '{}',
  counts_json TEXT NOT NULL DEFAULT '{}',
  note TEXT
);
CREATE INDEX IF NOT EXISTS scan_runs_subject ON scan_runs(subject_id, kind, id);

CREATE TABLE IF NOT EXISTS breach_hits (
  id INTEGER PRIMARY KEY,
  subject_id TEXT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
  identifier_id INTEGER REFERENCES identifiers(id) ON DELETE SET NULL,
  identifier_value TEXT NOT NULL,
  source TEXT NOT NULL,               -- hibp | leakcheck | xposedornot
  breach_name TEXT NOT NULL,
  title TEXT,
  domain TEXT,
  breach_date TEXT,
  added_date TEXT,
  data_classes_json TEXT NOT NULL DEFAULT '[]',
  pwn_count INTEGER,
  is_verified INTEGER,
  is_sensitive INTEGER,
  capture_id INTEGER REFERENCES captures(id) ON DELETE SET NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  UNIQUE (subject_id, identifier_value, source, breach_name)
);
CREATE INDEX IF NOT EXISTS breach_hits_subject ON breach_hits(subject_id, first_seen);

-- Only a label and a count. The password never touches the disk or the network in full.
CREATE TABLE IF NOT EXISTS password_checks (
  id INTEGER PRIMARY KEY,
  label TEXT NOT NULL,
  pwned_count INTEGER NOT NULL,
  checked_at TEXT NOT NULL
);
