-- +migrate Up
ALTER TABLE call_history ADD COLUMN test_mode TEXT NOT NULL DEFAULT 'normal';

-- +migrate Down
SELECT 1; -- SQLite does not support DROP COLUMN before 3.35
