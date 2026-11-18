CREATE TABLE IF NOT EXISTS jobs (
  name TEXT PRIMARY KEY,
  interval_seconds INTEGER NOT NULL,
  last_run TEXT,
  last_result TEXT
);
