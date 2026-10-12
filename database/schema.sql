-- SentinelAI database schema
-- Phase 1: Foundation (users, resources) + tables used by later phases
-- (policies, access_events, security_alerts) so the schema does not need
-- to be redesigned as later phases are implemented.

CREATE TABLE IF NOT EXISTS users (
    user_id             SERIAL PRIMARY KEY,
    username            VARCHAR(64) UNIQUE NOT NULL,
    email               VARCHAR(255) UNIQUE NOT NULL,
    password_hash       VARCHAR(255) NOT NULL,
    role                VARCHAR(64) NOT NULL,
    department          VARCHAR(64) NOT NULL,
    clearance_level     VARCHAR(32) NOT NULL DEFAULT 'PUBLIC'
                            CHECK (clearance_level IN ('PUBLIC', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET')),
    device_trust        VARCHAR(32) NOT NULL DEFAULT 'UNTRUSTED'
                            CHECK (device_trust IN ('TRUSTED', 'UNTRUSTED')),
    account_status      VARCHAR(32) NOT NULL DEFAULT 'ACTIVE'
                            CHECK (account_status IN ('ACTIVE', 'LOCKED', 'DISABLED')),
    failed_login_count  INTEGER NOT NULL DEFAULT 0,
    otp_secret          VARCHAR(64),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS resources (
    resource_id         SERIAL PRIMARY KEY,
    resource_name       VARCHAR(255) NOT NULL,
    owner_id            INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    classification      VARCHAR(32) NOT NULL DEFAULT 'PUBLIC'
                            CHECK (classification IN ('PUBLIC', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET')),
    department          VARCHAR(64) NOT NULL,
    required_role       VARCHAR(64),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policies (
    policy_id           SERIAL PRIMARY KEY,
    policy_type         VARCHAR(16) NOT NULL CHECK (policy_type IN ('RBAC', 'MAC', 'ABAC', 'TBAC', 'OBAC')),
    policy_name         VARCHAR(255) NOT NULL,
    rule_definition     JSONB NOT NULL,
    priority            INTEGER NOT NULL DEFAULT 0,
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS access_events (
    event_id            SERIAL PRIMARY KEY,
    user_id             INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    resource_id         INTEGER REFERENCES resources(resource_id) ON DELETE SET NULL,
    action               VARCHAR(32) NOT NULL,
    timestamp            TIMESTAMPTZ NOT NULL DEFAULT now(),
    location             VARCHAR(255),
    device_id            VARCHAR(255),
    policy_decision      VARCHAR(16) NOT NULL CHECK (policy_decision IN ('ALLOW', 'DENY')),
    risk_score           INTEGER CHECK (risk_score BETWEEN 0 AND 100),
    final_decision       VARCHAR(32) NOT NULL CHECK (final_decision IN ('ALLOW', 'MFA_REQUIRED', 'BLOCK', 'DENY')),
    reason                TEXT
);

CREATE TABLE IF NOT EXISTS resource_grants (
    grant_id             SERIAL PRIMARY KEY,
    user_id              INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    resource_id          INTEGER NOT NULL REFERENCES resources(resource_id) ON DELETE CASCADE,
    action               VARCHAR(32),
    granted_by           INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    reason               TEXT,
    expires_at           TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS security_alerts (
    alert_id             SERIAL PRIMARY KEY,
    user_id              INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    event_id             INTEGER REFERENCES access_events(event_id) ON DELETE SET NULL,
    alert_type           VARCHAR(64) NOT NULL,
    risk_score            INTEGER CHECK (risk_score BETWEEN 0 AND 100),
    severity              VARCHAR(16) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    description           TEXT,
    status                 VARCHAR(16) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_access_events_user_id ON access_events(user_id);
CREATE INDEX IF NOT EXISTS idx_access_events_timestamp ON access_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_alerts_user_id ON security_alerts(user_id);
CREATE INDEX IF NOT EXISTS idx_resource_grants_user_resource ON resource_grants(user_id, resource_id);
