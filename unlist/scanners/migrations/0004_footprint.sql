-- breach_hits gains a kind (breach | paste | stealer) and a place for source-specific detail.
ALTER TABLE breach_hits ADD COLUMN kind TEXT NOT NULL DEFAULT 'breach';
ALTER TABLE breach_hits ADD COLUMN detail_json TEXT NOT NULL DEFAULT '{}';

-- Everything that is neither an email breach nor a people-search listing: accounts found
-- by username, web mentions the operator confirmed, owned-domain findings.
CREATE TABLE IF NOT EXISTS exposures (
  id INTEGER PRIMARY KEY,
  subject_id TEXT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
  identifier_value TEXT NOT NULL,
  kind TEXT NOT NULL,                 -- account | mention | domain
  source TEXT NOT NULL,
  key TEXT NOT NULL,
  title TEXT,
  url TEXT,
  detail_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'candidate'
    CHECK (status IN ('candidate','confirmed','rejected','resolved')),
  capture_id INTEGER REFERENCES captures(id) ON DELETE SET NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  status_changed_at TEXT,
  note TEXT,
  UNIQUE (subject_id, kind, source, key, identifier_value)
);
CREATE INDEX IF NOT EXISTS exposures_subject ON exposures(subject_id, kind, status);

-- Per-subject numbers a source reports (risk scores, paste counts, plan in force).
CREATE TABLE IF NOT EXISTS subject_metrics (
  subject_id TEXT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
  source TEXT NOT NULL,
  metric TEXT NOT NULL,
  value_json TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (subject_id, source, metric)
);
