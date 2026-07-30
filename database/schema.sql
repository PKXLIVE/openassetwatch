CREATE TABLE IF NOT EXISTS collector_inventory_submissions (
    id BIGSERIAL PRIMARY KEY,
    collector_guid TEXT,
    collector_id TEXT,
    collector_name TEXT,
    mode TEXT,
    schema_version TEXT,
    collector_version TEXT,
    collected_at TIMESTAMPTZ,
    received_at TIMESTAMPTZ NOT NULL,
    device_count INTEGER NOT NULL DEFAULT 0,
    network_observation_count INTEGER NOT NULL DEFAULT 0,
    software_count INTEGER NOT NULL DEFAULT 0,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_collector_inventory_submissions_received_at
    ON collector_inventory_submissions (received_at DESC);

CREATE INDEX IF NOT EXISTS idx_collector_inventory_submissions_collector_id
    ON collector_inventory_submissions (collector_id);

CREATE INDEX IF NOT EXISTS idx_collector_inventory_submissions_collector_guid
    ON collector_inventory_submissions (collector_guid);

CREATE TABLE IF NOT EXISTS collectors (
    id BIGSERIAL PRIMARY KEY,
    collector_id TEXT NOT NULL UNIQUE,
    collector_guid TEXT,
    collector_name TEXT,
    collector_version TEXT,
    deployment_id TEXT,
    deployment_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    labels_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    supported_capabilities_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled_capabilities_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    last_mode TEXT,
    last_seen_at TIMESTAMPTZ,
    last_submission_id BIGINT REFERENCES collector_inventory_submissions(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_collectors_collector_guid
    ON collectors (collector_guid)
    WHERE collector_guid IS NOT NULL;

CREATE TABLE IF NOT EXISTS assets (
    id BIGSERIAL PRIMARY KEY,
    asset_key TEXT NOT NULL UNIQUE,
    asset_kind TEXT NOT NULL,
    hostname TEXT,
    primary_ip TEXT,
    mac_address TEXT,
    source TEXT,
    collector_id TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    last_submission_id BIGINT REFERENCES collector_inventory_submissions(id),
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_assets_collector_id
    ON assets (collector_id);

CREATE INDEX IF NOT EXISTS idx_assets_mac_address
    ON assets (mac_address);

CREATE INDEX IF NOT EXISTS idx_assets_primary_ip
    ON assets (primary_ip);

CREATE TABLE IF NOT EXISTS asset_ip_history (
    id BIGSERIAL PRIMARY KEY,
    asset_id BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    ip_address TEXT,
    mac_address TEXT,
    interface TEXT,
    state TEXT,
    source TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    observations_count INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_asset_ip_history_asset_id
    ON asset_ip_history (asset_id);

CREATE INDEX IF NOT EXISTS idx_asset_ip_history_ip_address
    ON asset_ip_history (ip_address);

CREATE TABLE IF NOT EXISTS asset_software_detections (
    id BIGSERIAL PRIMARY KEY,
    asset_id BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    category TEXT,
    detected BOOLEAN,
    version TEXT,
    evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    confidence TEXT,
    scope TEXT,
    source TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (asset_id, name, category)
);

CREATE INDEX IF NOT EXISTS idx_asset_software_detections_asset_id
    ON asset_software_detections (asset_id);

CREATE TABLE IF NOT EXISTS collector_policies (
    id BIGSERIAL PRIMARY KEY,
    policy_id TEXT NOT NULL UNIQUE,
    policy_name TEXT,
    policy_version INTEGER NOT NULL DEFAULT 1,
    policy_json JSONB NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_collector_policies_enabled
    ON collector_policies (enabled);

CREATE TABLE IF NOT EXISTS policy_assignments (
    id BIGSERIAL PRIMARY KEY,
    assignment_name TEXT,
    policy_id TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    priority INTEGER NOT NULL DEFAULT 0,
    collector_guid TEXT,
    collector_id TEXT,
    deployment_id TEXT,
    platform TEXT,
    label_selector JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policy_assignments_enabled_priority
    ON policy_assignments (enabled, priority DESC);

CREATE INDEX IF NOT EXISTS idx_policy_assignments_policy_id
    ON policy_assignments (policy_id);

CREATE TABLE IF NOT EXISTS sites (
    site_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS agent_enrollments (
    agent_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    display_name TEXT,
    agent_type TEXT NOT NULL,
    platform TEXT,
    architecture TEXT,
    version TEXT,
    hostname TEXT,
    mode TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ,
    identity_status TEXT NOT NULL DEFAULT 'legacy',
    CHECK (agent_type IN ('endpoint-agent', 'network-sensor'))
);

CREATE INDEX IF NOT EXISTS idx_agent_enrollments_site_id
    ON agent_enrollments (site_id);

CREATE INDEX IF NOT EXISTS idx_agent_enrollments_last_seen_at
    ON agent_enrollments (last_seen_at DESC);

CREATE TABLE IF NOT EXISTS sensor_enrollments (
    enrollment_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    requested_sensor_id TEXT,
    requested_sensor_name TEXT,
    sensor_type TEXT NOT NULL,
    token_lookup_id TEXT NOT NULL UNIQUE,
    token_digest TEXT NOT NULL,
    status TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 10,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    issued_sensor_id TEXT,
    CHECK (sensor_type IN ('passive-network-sensor')),
    CHECK (status IN ('pending', 'used', 'expired', 'revoked')),
    CHECK (failed_attempts >= 0 AND max_attempts BETWEEN 1 AND 100)
);

CREATE INDEX IF NOT EXISTS idx_sensor_enrollments_site_status
    ON sensor_enrollments (site_id, status, expires_at);

CREATE INDEX IF NOT EXISTS idx_sensor_enrollments_requested_sensor
    ON sensor_enrollments (requested_sensor_id)
    WHERE requested_sensor_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS sensor_credentials (
    credential_id TEXT PRIMARY KEY,
    sensor_id TEXT NOT NULL,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    sensor_type TEXT NOT NULL,
    token_lookup_id TEXT NOT NULL UNIQUE,
    credential_digest TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    rotated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    predecessor_credential_id TEXT REFERENCES sensor_credentials(credential_id),
    replacement_credential_id TEXT REFERENCES sensor_credentials(credential_id),
    CHECK (sensor_type IN ('passive-network-sensor')),
    CHECK (status IN ('active', 'revoked', 'rotated', 'expired'))
);

CREATE INDEX IF NOT EXISTS idx_sensor_credentials_sensor_status
    ON sensor_credentials (sensor_id, status);

CREATE INDEX IF NOT EXISTS idx_sensor_credentials_site_id
    ON sensor_credentials (site_id);

CREATE INDEX IF NOT EXISTS idx_sensor_credentials_last_used_at
    ON sensor_credentials (last_used_at DESC);

CREATE TABLE IF NOT EXISTS sensor_identity_audit_events (
    event_id BIGSERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    outcome TEXT NOT NULL,
    enrollment_id TEXT,
    credential_id TEXT,
    sensor_id TEXT,
    site_id TEXT,
    reason_code TEXT,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (outcome IN ('success', 'rejected'))
);

CREATE INDEX IF NOT EXISTS idx_sensor_identity_audit_created_at
    ON sensor_identity_audit_events (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_sensor_identity_audit_sensor_id
    ON sensor_identity_audit_events (sensor_id, created_at DESC);

CREATE TABLE IF NOT EXISTS agent_checkins (
    id BIGSERIAL PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    agent_id TEXT,
    version TEXT,
    platform TEXT,
    architecture TEXT,
    hostname TEXT,
    mode TEXT,
    checked_in_at TIMESTAMPTZ,
    received_at TIMESTAMPTZ NOT NULL,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_agent_checkins_site_id_received_at
    ON agent_checkins (site_id, received_at DESC);

CREATE INDEX IF NOT EXISTS idx_agent_checkins_agent_id_received_at
    ON agent_checkins (agent_id, received_at DESC);

CREATE TABLE IF NOT EXISTS local_inventory_collections (
    id BIGSERIAL PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    source_agent_id TEXT,
    schema_version TEXT,
    collected_at TIMESTAMPTZ,
    received_at TIMESTAMPTZ NOT NULL,
    observed_asset_count INTEGER NOT NULL DEFAULT 0,
    normalized_asset_count INTEGER NOT NULL DEFAULT 0,
    observation_batch_id TEXT,
    observation_source TEXT,
    observed_at TIMESTAMPTZ,
    delivery_state TEXT NOT NULL DEFAULT 'live',
    confidence DOUBLE PRECISION,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_local_inventory_collections_site_id_received_at
    ON local_inventory_collections (site_id, received_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_local_inventory_observation_batch
    ON local_inventory_collections (site_id, source_agent_id, observation_batch_id)
    WHERE observation_batch_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS control_tower_assets (
    asset_key TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    hostname TEXT,
    primary_ip TEXT,
    mac TEXT,
    os TEXT,
    platform TEXT,
    source_agent_id TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    evidence_count INTEGER NOT NULL DEFAULT 0,
    observation_batch_id TEXT,
    observation_source TEXT,
    observed_at TIMESTAMPTZ,
    delivery_state TEXT NOT NULL DEFAULT 'live',
    confidence DOUBLE PRECISION,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (site_id, asset_id)
);

CREATE INDEX IF NOT EXISTS idx_control_tower_assets_site_id
    ON control_tower_assets (site_id);

CREATE INDEX IF NOT EXISTS idx_control_tower_assets_last_seen_at
    ON control_tower_assets (last_seen_at DESC);

CREATE TABLE IF NOT EXISTS ai_advisor_runs (
    run_id TEXT PRIMARY KEY,
    question_sha256 TEXT NOT NULL,
    site_id TEXT,
    provider TEXT NOT NULL,
    mode TEXT NOT NULL,
    tool_names_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    evidence_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ai_advisor_runs_created_at
    ON ai_advisor_runs (created_at DESC);

CREATE TABLE IF NOT EXISTS finding_evaluation_runs (
    run_id TEXT PRIMARY KEY,
    trigger_type TEXT NOT NULL,
    requested_by TEXT,
    scope_site_id TEXT,
    scope_asset_id TEXT,
    scope_sensor_id TEXT,
    ruleset_version TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    data_as_of TIMESTAMPTZ,
    site_count INTEGER NOT NULL DEFAULT 0,
    sensor_count INTEGER NOT NULL DEFAULT 0,
    asset_count INTEGER NOT NULL DEFAULT 0,
    candidate_count INTEGER NOT NULL DEFAULT 0,
    opened_count INTEGER NOT NULL DEFAULT 0,
    updated_count INTEGER NOT NULL DEFAULT 0,
    reopened_count INTEGER NOT NULL DEFAULT 0,
    resolved_count INTEGER NOT NULL DEFAULT 0,
    error_code TEXT,
    CHECK (status IN ('running', 'completed', 'failed'))
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    dedupe_key TEXT NOT NULL UNIQUE,
    rule_id TEXT NOT NULL,
    rule_version INTEGER NOT NULL,
    previous_rule_version INTEGER,
    rule_version_changed_at TIMESTAMPTZ,
    engine_version TEXT NOT NULL,
    category TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    site_id TEXT NOT NULL REFERENCES sites(site_id) ON DELETE CASCADE,
    asset_id TEXT,
    sensor_id TEXT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    status TEXT NOT NULL,
    evidence_observed_at TIMESTAMPTZ,
    evidence_freshness TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ,
    resolution_basis TEXT,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT,
    suppressed_at TIMESTAMPTZ,
    suppressed_by TEXT,
    suppressed_until TIMESTAMPTZ,
    suppression_reason TEXT,
    reopen_count INTEGER NOT NULL DEFAULT 0,
    last_evaluation_run_id TEXT NOT NULL REFERENCES finding_evaluation_runs(run_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (subject_type IN ('asset', 'sensor', 'site')),
    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
    CHECK (confidence >= 0.0 AND confidence <= 1.0),
    CHECK (status IN ('active', 'acknowledged', 'resolved', 'suppressed')),
    CHECK (evidence_freshness IN ('fresh', 'aging', 'stale', 'unknown')),
    CHECK (
        (subject_type = 'asset' AND asset_id IS NOT NULL AND sensor_id IS NULL)
        OR (subject_type = 'sensor' AND sensor_id IS NOT NULL AND asset_id IS NULL)
        OR (subject_type = 'site' AND asset_id IS NULL AND sensor_id IS NULL)
    )
);

ALTER TABLE finding_evaluation_runs
    ADD COLUMN IF NOT EXISTS scope_sensor_id TEXT;
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS previous_rule_version INTEGER;
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS rule_version_changed_at TIMESTAMPTZ;
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS engine_version TEXT NOT NULL DEFAULT 'oaw.findings.v1';
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS evaluated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

CREATE TABLE IF NOT EXISTS finding_evidence (
    evidence_id BIGSERIAL PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    evidence_ref TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    source TEXT NOT NULL,
    observed_at TIMESTAMPTZ,
    freshness TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    summary TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (finding_id, evidence_ref),
    CHECK (freshness IN ('fresh', 'aging', 'stale', 'unknown')),
    CHECK (confidence >= 0.0 AND confidence <= 1.0)
);

CREATE TABLE IF NOT EXISTS asset_risk_scores (
    site_id TEXT NOT NULL REFERENCES sites(site_id) ON DELETE CASCADE,
    asset_id TEXT NOT NULL,
    score INTEGER NOT NULL,
    band TEXT NOT NULL,
    formula_version TEXT NOT NULL,
    finding_count INTEGER NOT NULL,
    data_as_of TIMESTAMPTZ,
    calculated_at TIMESTAMPTZ NOT NULL,
    evaluation_run_id TEXT NOT NULL REFERENCES finding_evaluation_runs(run_id),
    PRIMARY KEY (site_id, asset_id),
    CHECK (score >= 0 AND score <= 100)
);

CREATE TABLE IF NOT EXISTS site_risk_scores (
    site_id TEXT PRIMARY KEY REFERENCES sites(site_id) ON DELETE CASCADE,
    score INTEGER NOT NULL,
    band TEXT NOT NULL,
    formula_version TEXT NOT NULL,
    asset_count INTEGER NOT NULL,
    finding_count INTEGER NOT NULL,
    data_as_of TIMESTAMPTZ,
    calculated_at TIMESTAMPTZ NOT NULL,
    evaluation_run_id TEXT NOT NULL REFERENCES finding_evaluation_runs(run_id),
    CHECK (score >= 0 AND score <= 100)
);

CREATE TABLE IF NOT EXISTS risk_factors (
    risk_factor_id BIGSERIAL PRIMARY KEY,
    subject_type TEXT NOT NULL,
    site_id TEXT NOT NULL REFERENCES sites(site_id) ON DELETE CASCADE,
    asset_id TEXT,
    finding_id TEXT REFERENCES findings(finding_id) ON DELETE SET NULL,
    factor_type TEXT NOT NULL,
    category TEXT NOT NULL,
    label TEXT NOT NULL,
    severity TEXT,
    confidence DOUBLE PRECISION NOT NULL,
    freshness TEXT NOT NULL,
    base_weight DOUBLE PRECISION NOT NULL,
    adjusted_weight DOUBLE PRECISION NOT NULL,
    ordinal INTEGER NOT NULL,
    evaluation_run_id TEXT NOT NULL REFERENCES finding_evaluation_runs(run_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (subject_type IN ('asset', 'site')),
    CHECK (confidence >= 0.0 AND confidence <= 1.0)
);

CREATE INDEX IF NOT EXISTS idx_findings_status_severity
    ON findings (status, severity, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_site_status
    ON findings (site_id, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_asset_status
    ON findings (site_id, asset_id, status) WHERE asset_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_findings_sensor_status
    ON findings (sensor_id, status) WHERE sensor_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_findings_rule_status
    ON findings (rule_id, status);
CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding_id
    ON finding_evidence (finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_runs_started_at
    ON finding_evaluation_runs (started_at DESC);
CREATE INDEX IF NOT EXISTS idx_finding_runs_scope
    ON finding_evaluation_runs (
        scope_site_id,
        scope_asset_id,
        scope_sensor_id,
        started_at DESC
    );
CREATE INDEX IF NOT EXISTS idx_asset_risk_score_desc
    ON asset_risk_scores (score DESC, site_id, asset_id);
CREATE INDEX IF NOT EXISTS idx_site_risk_score_desc
    ON site_risk_scores (score DESC, site_id);
CREATE INDEX IF NOT EXISTS idx_risk_factors_subject
    ON risk_factors (subject_type, site_id, asset_id, ordinal);
