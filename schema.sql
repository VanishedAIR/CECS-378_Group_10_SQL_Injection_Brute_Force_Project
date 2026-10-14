-- Group 10 security lab schema (six tables). Timestamps are UTC epoch milliseconds.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username_key TEXT NOT NULL UNIQUE,
  display_username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('user', 'admin'))
);

CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT NOT NULL UNIQUE,
  timestamp_utc INTEGER NOT NULL,
  username_key TEXT NOT NULL,
  source_ip TEXT NOT NULL,
  user_id INTEGER REFERENCES users (id),
  outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'blocked')),
  blocked_scopes_json TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_username_time
  ON login_attempts (username_key, timestamp_utc);

CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time
  ON login_attempts (source_ip, timestamp_utc);

CREATE INDEX IF NOT EXISTS idx_login_attempts_outcome
  ON login_attempts (outcome);

CREATE TABLE IF NOT EXISTS query_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT NOT NULL UNIQUE,
  timestamp_utc INTEGER NOT NULL,
  user_id INTEGER NOT NULL REFERENCES users (id),
  source_ip TEXT NOT NULL,
  route_mode TEXT NOT NULL CHECK (route_mode IN ('vulnerable', 'protected')),
  input_excerpt TEXT NOT NULL,
  query_template TEXT NOT NULL,
  parameters_json TEXT NOT NULL DEFAULT '[]',
  lab_sql TEXT,
  result_count INTEGER,
  duration_ms INTEGER NOT NULL,
  error_code TEXT
);

CREATE INDEX IF NOT EXISTS idx_query_audit_timestamp
  ON query_audit (timestamp_utc);

CREATE TABLE IF NOT EXISTS security_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp_utc INTEGER NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN ('BRUTE_FORCE_DETECTED', 'SQLI_ATTEMPT')),
  rule_id TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
  scope_type TEXT NOT NULL CHECK (scope_type IN ('account', 'ip', 'request')),
  scope_key TEXT NOT NULL,
  trigger_login_attempt_id INTEGER REFERENCES login_attempts (id),
  query_audit_id INTEGER REFERENCES query_audit (id),
  details_json TEXT NOT NULL DEFAULT '{}',
  CHECK (
    (trigger_login_attempt_id IS NOT NULL AND query_audit_id IS NULL)
    OR (trigger_login_attempt_id IS NULL AND query_audit_id IS NOT NULL)
  ),
  CHECK (
    (event_type = 'BRUTE_FORCE_DETECTED' AND scope_type IN ('account', 'ip'))
    OR (event_type = 'SQLI_ATTEMPT' AND scope_type = 'request')
  )
);

CREATE INDEX IF NOT EXISTS idx_security_events_timestamp
  ON security_events (timestamp_utc);

CREATE TABLE IF NOT EXISTS cooldowns (
  scope_type TEXT NOT NULL CHECK (scope_type IN ('account', 'ip')),
  scope_key TEXT NOT NULL,
  blocked_until INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  trigger_event_id INTEGER NOT NULL REFERENCES security_events (id),
  PRIMARY KEY (scope_type, scope_key)
);
