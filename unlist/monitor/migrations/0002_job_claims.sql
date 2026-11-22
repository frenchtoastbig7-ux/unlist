-- When a run started a job and has not finished it yet; NULL when no run holds the job.
ALTER TABLE jobs ADD COLUMN claimed_at TEXT;
