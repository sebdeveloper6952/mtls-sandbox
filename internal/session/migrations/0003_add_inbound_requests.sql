-- +migrate Up
CREATE TABLE inbound_requests (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id     TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    created_at     TEXT NOT NULL,
    method         TEXT NOT NULL,
    path           TEXT NOT NULL,
    status_code    INTEGER NOT NULL,
    latency_ms     INTEGER NOT NULL,
    handshake_ok   INTEGER NOT NULL DEFAULT 0,
    failure_code   TEXT,
    failure_reason TEXT,
    report         TEXT
);

CREATE INDEX IF NOT EXISTS idx_inbound_session ON inbound_requests(session_id, created_at DESC);

-- +migrate Down
DROP TABLE inbound_requests;
