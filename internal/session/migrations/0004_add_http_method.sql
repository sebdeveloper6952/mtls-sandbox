-- +migrate Up
ALTER TABLE call_history ADD COLUMN http_method TEXT NOT NULL DEFAULT 'GET';

-- +migrate Down
SELECT 1; -- SQLite does not support DROP COLUMN before 3.35
