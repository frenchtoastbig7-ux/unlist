CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY,
  subject_id TEXT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
  broker_id TEXT NOT NULL,
  listing_url TEXT NOT NULL,
  score REAL NOT NULL,
  extract_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'candidate'
    CHECK (status IN ('candidate','confirmed','rejected','requested','removed','reappeared')),
  capture_id INTEGER REFERENCES captures(id) ON DELETE SET NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  status_changed_at TEXT,
  verified_at TEXT,
  note TEXT,
  UNIQUE (subject_id, broker_id, listing_url)
);
CREATE INDEX IF NOT EXISTS findings_subject_status ON findings(subject_id, status);

-- What happened for each broker in each run: fetched, refused, browser, none, error.
CREATE TABLE IF NOT EXISTS broker_checks (
  id INTEGER PRIMARY KEY,
  run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  subject_id TEXT NOT NULL,
  broker_id TEXT NOT NULL,
  search_url TEXT NOT NULL,
  outcome TEXT NOT NULL,
  capture_id INTEGER REFERENCES captures(id) ON DELETE SET NULL,
  candidates INTEGER NOT NULL DEFAULT 0,
  checked_at TEXT NOT NULL,
  note TEXT
);
CREATE INDEX IF NOT EXISTS broker_checks_run ON broker_checks(run_id);
