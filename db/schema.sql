CREATE TABLE IF NOT EXISTS alerts (
    alert_id        UUID PRIMARY KEY,
    detected_at     TIMESTAMPTZ NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    user_id         TEXT        NOT NULL,
    rule            TEXT        NOT NULL,
    severity        TEXT        NOT NULL,
    details         TEXT        NOT NULL,
    event_id        UUID        NOT NULL,
    -- idempotency: the same event can't create the same alert twice
    CONSTRAINT one_alert_per_event_rule UNIQUE (event_id, rule)
);

-- Supports the API query "alerts for one user, newest first"
CREATE INDEX IF NOT EXISTS idx_alerts_user_time ON alerts (user_id, detected_at DESC);
-- Supports "latest alerts across all users"
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts (detected_at DESC);