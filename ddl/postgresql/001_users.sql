-- 001_users.sql — account-service identity records.
-- Stores only a salted password hash (bcrypt embeds the salt) and AES-256-GCM
-- encrypted phone bytes. Never store plaintext passwords or PII.

CREATE TABLE IF NOT EXISTS users (
    id               BIGSERIAL PRIMARY KEY,
    email            VARCHAR(320) NOT NULL UNIQUE,
    name             VARCHAR(120) NOT NULL DEFAULT '',
    phone_encrypted  BYTEA,
    -- Keyed HMAC of the normalized phone (blind index). phone_encrypted uses a
    -- random nonce and is not queryable; lookups match on phone_hash instead.
    phone_hash       VARCHAR(64),
    password_hash    VARCHAR(255) NOT NULL DEFAULT '',
    verified         BOOLEAN      NOT NULL DEFAULT FALSE,
    is_active        BOOLEAN      NOT NULL DEFAULT TRUE,
    failed_attempts  INT          NOT NULL DEFAULT 0,
    locked_until     TIMESTAMPTZ,
    provider         VARCHAR(32)  NOT NULL DEFAULT 'local',
    provider_uid     VARCHAR(255),
    last_login       TIMESTAMPTZ,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_users_provider_uid ON users (provider_uid);
CREATE INDEX IF NOT EXISTS idx_users_phone_hash ON users (phone_hash);
