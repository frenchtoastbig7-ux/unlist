CREATE TABLE IF NOT EXISTS subjects (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('self', 'household')),
  residency_state TEXT,
  residency_country TEXT NOT NULL DEFAULT 'US',
  note TEXT,
  created_at TEXT NOT NULL
);

-- The latest row per subject is the consent in force. Rows are never updated.
CREATE TABLE IF NOT EXISTS consents (
  id INTEGER PRIMARY KEY,
  subject_id TEXT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
  holder TEXT NOT NULL,
  instrument TEXT NOT NULL,
  granted TEXT NOT NULL,
  expires TEXT NOT NULL,
  scope_note TEXT NOT NULL DEFAULT '',
  recorded_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS consents_subject ON consents(subject_id, id);

CREATE TABLE IF NOT EXISTS identifiers (
  id INTEGER PRIMARY KEY,
  subject_id TEXT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  current INTEGER NOT NULL DEFAULT 1,
  meta_json TEXT NOT NULL DEFAULT '{}',
  note TEXT NOT NULL DEFAULT '',
  added_at TEXT NOT NULL,
  UNIQUE (subject_id, kind, value)
);
