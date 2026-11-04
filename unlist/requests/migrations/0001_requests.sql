CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY,
  subject_id TEXT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
  broker_id TEXT NOT NULL,
  channel TEXT NOT NULL CHECK (channel IN ('email','form','drop','mail','manual')),
  basis TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'drafted',
  tag TEXT NOT NULL UNIQUE,
  to_address TEXT,
  subject_line TEXT,
  body TEXT,
  form_url TEXT,
  drop_id TEXT,
  listings_json TEXT NOT NULL DEFAULT '[]',
  finding_ids_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  approved_at TEXT,
  sent_at TEXT,
  deadline TEXT,
  last_reply_at TEXT,
  closed_at TEXT,
  capture_before INTEGER REFERENCES captures(id) ON DELETE SET NULL,
  capture_after INTEGER REFERENCES captures(id) ON DELETE SET NULL,
  note TEXT
);
CREATE INDEX IF NOT EXISTS requests_subject_state ON requests(subject_id, state);
CREATE INDEX IF NOT EXISTS requests_broker ON requests(subject_id, broker_id);

CREATE TABLE IF NOT EXISTS request_events (
  id INTEGER PRIMARY KEY,
  request_id INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
  at TEXT NOT NULL,
  kind TEXT NOT NULL,
  detail TEXT,
  capture_id INTEGER REFERENCES captures(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS request_events_request ON request_events(request_id, id);

CREATE TABLE IF NOT EXISTS inbox_messages (
  id INTEGER PRIMARY KEY,
  message_uid TEXT NOT NULL UNIQUE,
  request_id INTEGER REFERENCES requests(id) ON DELETE SET NULL,
  from_addr TEXT,
  subject TEXT,
  received_at TEXT,
  classification TEXT NOT NULL,
  detail TEXT,
  links_json TEXT NOT NULL DEFAULT '[]',
  capture_id INTEGER REFERENCES captures(id) ON DELETE SET NULL,
  action TEXT,
  seen_at TEXT NOT NULL
);
