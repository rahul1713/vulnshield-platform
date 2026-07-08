-- Machine-scoped tokens for endpoint agents (not user JWTs).

CREATE TABLE IF NOT EXISTS agent_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id VARCHAR(100) NOT NULL,
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    label VARCHAR(255),
    scopes JSONB NOT NULL DEFAULT '["agent:register", "agent:heartbeat", "agent:ingest"]',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_agent_tokens_agent_id ON agent_tokens(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_tokens_active ON agent_tokens(agent_id) WHERE is_active = TRUE AND revoked_at IS NULL;
