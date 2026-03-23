-- +migrate Up
CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    callback_url TEXT NOT NULL DEFAULT '',
    cert_pem     BLOB NOT NULL,
    key_pem      BLOB NOT NULL,
    cert_cn      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS call_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    created_at   TEXT NOT NULL,
    callback_url TEXT NOT NULL,
    status_code  INTEGER,
    duration_ms  INTEGER NOT NULL,
    error        TEXT,
    probe_result TEXT
);

CREATE INDEX IF NOT EXISTS idx_call_history_session ON call_history(session_id, created_at DESC);

-- +migrate Down
DROP TABLE call_history;
DROP TABLE sessions;
