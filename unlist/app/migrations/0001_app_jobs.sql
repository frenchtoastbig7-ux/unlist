CREATE TABLE IF NOT EXISTS app_jobs (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  params_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL,            -- queued | running | done | failed | abandoned
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  log TEXT NOT NULL DEFAULT '',
  result TEXT
);
