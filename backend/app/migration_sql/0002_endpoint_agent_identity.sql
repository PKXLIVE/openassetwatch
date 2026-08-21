-- Endpoint-agent identity is deliberately separate from passive-sensor identity.
-- Raw enrollment tokens and credentials are never stored in PostgreSQL.

CREATE TABLE IF NOT EXISTS endpoint_agent_enrollments (
    enrollment_id TEXT PRIMARY KEY,
    token_lookup_id CHAR(32) NOT NULL UNIQUE,
    token_digest CHAR(64) NOT NULL,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    requested_deployment_id VARCHAR(160),
    requested_agent_type VARCHAR(32) NOT NULL DEFAULT 'endpoint-agent',
    requested_display_name VARCHAR(160),
    status VARCHAR(16) NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 10,
    created_by VARCHAR(128) NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    issued_agent_id TEXT REFERENCES agent_enrollments(agent_id),
    CHECK (requested_agent_type IN ('endpoint-agent')),
    CHECK (status = ANY (ARRAY['pending', 'consumed', 'expired', 'revoked']::CHARACTER VARYING[])),
    CHECK (failed_attempts >= 0 AND max_attempts BETWEEN 1 AND 100),
    CHECK (token_lookup_id ~ '^[0-9a-f]{32}$'),
    CHECK (token_digest ~ '^[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_endpoint_agent_enrollments_site_status
    ON endpoint_agent_enrollments (site_id, status, expires_at);

CREATE INDEX IF NOT EXISTS idx_endpoint_agent_enrollments_issued_agent
    ON endpoint_agent_enrollments (issued_agent_id)
    WHERE issued_agent_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS endpoint_agent_credentials (
    credential_id TEXT PRIMARY KEY,
    token_lookup_id CHAR(32) NOT NULL UNIQUE,
    credential_digest CHAR(64) NOT NULL,
    agent_id TEXT NOT NULL REFERENCES agent_enrollments(agent_id) ON DELETE CASCADE,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    deployment_id VARCHAR(160),
    agent_type VARCHAR(32) NOT NULL DEFAULT 'endpoint-agent',
    status VARCHAR(16) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    rotated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    predecessor_credential_id TEXT REFERENCES endpoint_agent_credentials(credential_id),
    replacement_credential_id TEXT REFERENCES endpoint_agent_credentials(credential_id),
    CHECK (agent_type IN ('endpoint-agent')),
    CHECK (status = ANY (ARRAY['active', 'rotated', 'revoked', 'expired']::CHARACTER VARYING[])),
    CHECK (token_lookup_id ~ '^[0-9a-f]{32}$'),
    CHECK (credential_digest ~ '^[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_endpoint_agent_credentials_agent_status
    ON endpoint_agent_credentials (agent_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_endpoint_agent_credentials_site
    ON endpoint_agent_credentials (site_id, status);

CREATE INDEX IF NOT EXISTS idx_endpoint_agent_credentials_last_used
    ON endpoint_agent_credentials (last_used_at DESC);

CREATE TABLE IF NOT EXISTS endpoint_agent_identity_audit_events (
    event_id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    outcome VARCHAR(16) NOT NULL,
    actor VARCHAR(128) NOT NULL,
    enrollment_id TEXT REFERENCES endpoint_agent_enrollments(enrollment_id),
    credential_id TEXT REFERENCES endpoint_agent_credentials(credential_id),
    agent_id TEXT REFERENCES agent_enrollments(agent_id),
    site_id TEXT REFERENCES sites(site_id),
    reason_code VARCHAR(64),
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (outcome = ANY (ARRAY['success', 'rejected']::CHARACTER VARYING[]))
);

CREATE INDEX IF NOT EXISTS idx_endpoint_agent_identity_audit_created
    ON endpoint_agent_identity_audit_events (created_at DESC, event_id DESC);

CREATE INDEX IF NOT EXISTS idx_endpoint_agent_identity_audit_agent
    ON endpoint_agent_identity_audit_events (agent_id, created_at DESC);

CREATE TABLE IF NOT EXISTS endpoint_agent_inventory_batches (
    storage_id BIGSERIAL PRIMARY KEY,
    inventory_batch_id VARCHAR(160) NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    agent_id TEXT NOT NULL REFERENCES agent_enrollments(agent_id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL REFERENCES endpoint_agent_credentials(credential_id),
    inventory_mode VARCHAR(16) NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    collection_id BIGINT REFERENCES local_inventory_collections(id),
    observed_asset_count INTEGER NOT NULL DEFAULT 0,
    normalized_asset_count INTEGER NOT NULL DEFAULT 0,
    component_count INTEGER NOT NULL DEFAULT 0,
    ingestion_status VARCHAR(16) NOT NULL DEFAULT 'accepted',
    reevaluation_state VARCHAR(24) NOT NULL DEFAULT 'queued',
    reevaluation_error_code VARCHAR(80),
    reevaluation_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (site_id, agent_id, inventory_batch_id),
    CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (inventory_mode = ANY (ARRAY['complete', 'partial']::CHARACTER VARYING[])),
    CHECK (ingestion_status IN ('accepted')),
    CHECK (reevaluation_state = ANY (ARRAY['queued', 'running', 'completed', 'retryable-failure']::CHARACTER VARYING[])),
    CHECK (observed_asset_count >= 0 AND observed_asset_count <= 16),
    CHECK (normalized_asset_count >= 0 AND normalized_asset_count <= 16),
    CHECK (component_count >= 0 AND component_count <= 32000)
);

CREATE INDEX IF NOT EXISTS idx_endpoint_agent_inventory_agent_received
    ON endpoint_agent_inventory_batches (agent_id, received_at DESC);

CREATE INDEX IF NOT EXISTS idx_endpoint_agent_inventory_reevaluation
    ON endpoint_agent_inventory_batches (reevaluation_state, reevaluation_updated_at);
