-- 002_sessions.sql — session management & refresh-token lifecycle.
-- Only the SHA-256 hash of the refresh token is stored; the raw token lives on
-- the client. Rotation replaces refresh_token_hash; reuse of a rotated token is
-- detected via is_revoked and triggers session-family revocation.

CREATE TABLE IF NOT EXISTS sessions (
    id                  BIGSERIAL PRIMARY KEY,
    user_id             BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash  VARCHAR(64) NOT NULL,
    device_id           VARCHAR(255),
    ip_address          VARCHAR(64),
    user_agent          VARCHAR(512),
    is_revoked          BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    last_used_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_hash ON sessions (refresh_token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);
