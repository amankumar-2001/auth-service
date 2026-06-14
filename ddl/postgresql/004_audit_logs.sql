-- 004_audit_logs.sql — immutable, append-only security audit trail.
-- Application code only ever INSERTs; a trigger blocks UPDATE/DELETE to keep the
-- trail tamper-evident for compliance (GDPR).

CREATE TABLE IF NOT EXISTS audit_logs (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT,
    event_type  VARCHAR(64) NOT NULL,
    ip_address  VARCHAR(64),
    device_id   VARCHAR(255),
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_logs (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_logs (event_type);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs (created_at);

CREATE OR REPLACE FUNCTION audit_logs_block_mutation() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only; % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_logs_immutable ON audit_logs;
CREATE TRIGGER trg_audit_logs_immutable
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_block_mutation();
