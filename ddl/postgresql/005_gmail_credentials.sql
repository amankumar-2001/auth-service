-- 005_gmail_credentials.sql
-- Per-user Gmail OAuth tokens, obtained via the Gmail-connect flow and consumed
-- by mcp-gateway. Access/refresh tokens are stored ENCRYPTED (AES-256-GCM via the
-- KMS) as bytea — never plaintext. One row per user (the mailbox they connected).

CREATE TABLE IF NOT EXISTS gmail_credentials (
    user_id           BIGINT       PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    access_token_enc  BYTEA        NOT NULL,
    refresh_token_enc BYTEA        NOT NULL,
    token_expiry      TIMESTAMPTZ  NOT NULL,
    scope             TEXT         NOT NULL DEFAULT '',
    email             TEXT         NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT now()
);
