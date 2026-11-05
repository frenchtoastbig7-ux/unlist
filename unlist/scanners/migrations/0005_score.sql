CREATE TABLE IF NOT EXISTS score_history (
  id INTEGER PRIMARY KEY,
  subject_id TEXT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
  at TEXT NOT NULL,
  score INTEGER NOT NULL,
  breakdown_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS score_history_subject ON score_history(subject_id, id);
