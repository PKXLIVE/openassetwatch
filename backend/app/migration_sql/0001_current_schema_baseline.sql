-- OpenAssetWatch schema migration 0001: current schema baseline.
-- This reviewed file is immutable after application. The migration runner
-- computes its SHA-256 over these exact UTF-8 bytes before execution.

CREATE TABLE IF NOT EXISTS oaw_schema_migrations (
    version INTEGER PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    checksum CHAR(64) NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    execution_duration_ms INTEGER NOT NULL,
    application_version VARCHAR(64) NOT NULL,
    minimum_application_version VARCHAR(64) NOT NULL,
    CHECK (version > 0),
    CHECK (execution_duration_ms >= 0 AND execution_duration_ms <= 86400000),
    CHECK (checksum ~ '^[0-9a-f]{64}$')
);

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

-- Adoption bridges are no-ops on fresh databases and fill only columns that
-- the historical lazy startup DDL added safely.
ALTER TABLE collector_inventory_submissions
    ADD COLUMN IF NOT EXISTS collector_guid TEXT;

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

ALTER TABLE collectors
    ADD COLUMN IF NOT EXISTS collector_guid TEXT;
ALTER TABLE collectors
    ADD COLUMN IF NOT EXISTS deployment_id TEXT;
ALTER TABLE collectors
    ADD COLUMN IF NOT EXISTS deployment_json JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE collectors
    ADD COLUMN IF NOT EXISTS labels_json JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE collectors
    ADD COLUMN IF NOT EXISTS supported_capabilities_json JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE collectors
    ADD COLUMN IF NOT EXISTS enabled_capabilities_json JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE collectors
    ADD COLUMN IF NOT EXISTS last_submission_id BIGINT REFERENCES collector_inventory_submissions(id);

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

ALTER TABLE agent_enrollments
    ADD COLUMN IF NOT EXISTS identity_status TEXT NOT NULL DEFAULT 'legacy';

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

ALTER TABLE local_inventory_collections
    ADD COLUMN IF NOT EXISTS observation_batch_id TEXT;
ALTER TABLE local_inventory_collections
    ADD COLUMN IF NOT EXISTS observation_source TEXT;
ALTER TABLE local_inventory_collections
    ADD COLUMN IF NOT EXISTS observed_at TIMESTAMPTZ;
ALTER TABLE local_inventory_collections
    ADD COLUMN IF NOT EXISTS delivery_state TEXT NOT NULL DEFAULT 'live';
ALTER TABLE local_inventory_collections
    ADD COLUMN IF NOT EXISTS confidence DOUBLE PRECISION;

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

ALTER TABLE control_tower_assets
    ADD COLUMN IF NOT EXISTS observation_batch_id TEXT;
ALTER TABLE control_tower_assets
    ADD COLUMN IF NOT EXISTS observation_source TEXT;
ALTER TABLE control_tower_assets
    ADD COLUMN IF NOT EXISTS observed_at TIMESTAMPTZ;
ALTER TABLE control_tower_assets
    ADD COLUMN IF NOT EXISTS delivery_state TEXT NOT NULL DEFAULT 'live';
ALTER TABLE control_tower_assets
    ADD COLUMN IF NOT EXISTS confidence DOUBLE PRECISION;

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
ALTER TABLE findings
    ALTER COLUMN engine_version DROP DEFAULT;
ALTER TABLE findings
    ALTER COLUMN evaluated_at DROP DEFAULT;

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
    evidence_ref TEXT,
    match_id TEXT,
    evaluation_run_id TEXT NOT NULL REFERENCES finding_evaluation_runs(run_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (subject_type IN ('asset', 'site')),
    CHECK (confidence >= 0.0 AND confidence <= 1.0)
);

ALTER TABLE risk_factors
    ADD COLUMN IF NOT EXISTS evidence_ref TEXT;
ALTER TABLE risk_factors
    ADD COLUMN IF NOT EXISTS match_id TEXT;

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

CREATE TABLE IF NOT EXISTS asset_components (
    component_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    component_type TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    namespace TEXT,
    vendor TEXT,
    name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    version TEXT,
    normalized_version TEXT,
    architecture TEXT,
    package_manager TEXT,
    canonical_identifier TEXT,
    cpe_hint TEXT,
    install_scope TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    firmware_evidence_type TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    freshness TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    normalization_status TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    not_observed_at TIMESTAMPTZ,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    model_version TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (
        site_id,
        asset_id,
        canonical_identifier,
        architecture,
        install_scope
    ),
    FOREIGN KEY (site_id, asset_id)
        REFERENCES control_tower_assets(site_id, asset_id) ON DELETE CASCADE,
    CHECK (confidence >= 0.0 AND confidence <= 1.0),
    CHECK (freshness IN ('fresh', 'aging', 'stale', 'unknown')),
    CHECK (firmware_evidence_type IN (
        'direct',
        'vendor-reported',
        'collector-reported',
        'inferred',
        'unknown'
    )),
    CHECK (normalization_status IN (
        'normalized',
        'identity-uncertain',
        'version-unknown',
        'unsupported-ecosystem',
        'insufficient-firmware-evidence'
    ))
);

CREATE TABLE IF NOT EXISTS asset_component_history (
    history_id BIGSERIAL PRIMARY KEY,
    component_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    previous_version TEXT,
    current_version TEXT,
    snapshot_json JSONB NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (event_type IN (
        'first-observed',
        'version-changed',
        'source-changed',
        'confidence-changed',
        'normalization-changed',
        'not-observed',
        'observed-again'
    ))
);

CREATE TABLE IF NOT EXISTS component_evidence (
    component_id TEXT NOT NULL
        REFERENCES asset_components(component_id) ON DELETE CASCADE,
    evidence_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (component_id, evidence_id),
    CHECK (observation_count >= 1)
);

CREATE INDEX IF NOT EXISTS idx_asset_components_asset
    ON asset_components (site_id, asset_id, active, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_asset_components_identity
    ON asset_components (ecosystem, canonical_identifier, active)
    WHERE canonical_identifier IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_asset_components_name
    ON asset_components (ecosystem, normalized_name, vendor);
CREATE INDEX IF NOT EXISTS idx_asset_components_type
    ON asset_components (component_type, active, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_asset_components_source
    ON asset_components (source_type, source_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_asset_component_history_component
    ON asset_component_history (component_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_component_evidence_component
    ON component_evidence (component_id, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS advisory_catalog_imports (
    import_id TEXT PRIMARY KEY,
    catalog_version TEXT NOT NULL,
    source TEXT NOT NULL,
    source_version TEXT NOT NULL,
    source_license TEXT NOT NULL,
    provenance TEXT NOT NULL,
    checksum TEXT NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL,
    imported_at TIMESTAMPTZ NOT NULL,
    advisory_count INTEGER NOT NULL,
    status TEXT NOT NULL,
    CHECK (status IN ('completed', 'failed')),
    UNIQUE (source, catalog_version, checksum)
);

CREATE TABLE IF NOT EXISTS advisories (
    advisory_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    source_record_id TEXT NOT NULL,
    source_version TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss DOUBLE PRECISION,
    known_exploited BOOLEAN NOT NULL DEFAULT FALSE,
    published_at TIMESTAMPTZ NOT NULL,
    modified_at TIMESTAMPTZ NOT NULL,
    withdrawn_at TIMESTAMPTZ,
    current BOOLEAN NOT NULL DEFAULT TRUE,
    catalog_import_id TEXT NOT NULL
        REFERENCES advisory_catalog_imports(import_id),
    checksum TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (source, source_record_id),
    CHECK (severity IN (
        'critical',
        'high',
        'medium',
        'low',
        'informational'
    )),
    CHECK (cvss IS NULL OR (cvss >= 0.0 AND cvss <= 10.0))
);

CREATE TABLE IF NOT EXISTS advisory_aliases (
    advisory_id TEXT NOT NULL
        REFERENCES advisories(advisory_id) ON DELETE CASCADE,
    alias TEXT NOT NULL,
    PRIMARY KEY (advisory_id, alias)
);

CREATE TABLE IF NOT EXISTS advisory_affected_components (
    affected_id TEXT PRIMARY KEY,
    advisory_id TEXT NOT NULL
        REFERENCES advisories(advisory_id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL,
    namespace TEXT,
    vendor TEXT,
    name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    canonical_identifier TEXT,
    exact_versions_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    fixed_versions_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    architectures_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    platforms_json JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE TABLE IF NOT EXISTS advisory_version_ranges (
    range_id TEXT PRIMARY KEY,
    affected_id TEXT NOT NULL
        REFERENCES advisory_affected_components(affected_id)
        ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    introduced TEXT,
    introduced_unbounded BOOLEAN NOT NULL DEFAULT FALSE,
    introduced_inclusive BOOLEAN NOT NULL DEFAULT TRUE,
    fixed TEXT,
    fixed_inclusive BOOLEAN NOT NULL DEFAULT FALSE,
    last_affected TEXT,
    last_affected_inclusive BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (affected_id, ordinal)
);

ALTER TABLE advisory_version_ranges
    ADD COLUMN IF NOT EXISTS introduced_unbounded BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS advisory_references (
    advisory_id TEXT NOT NULL
        REFERENCES advisories(advisory_id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    reference_type TEXT NOT NULL,
    reference_url TEXT NOT NULL,
    PRIMARY KEY (advisory_id, ordinal)
);

CREATE INDEX IF NOT EXISTS idx_advisories_current_severity
    ON advisories (current, withdrawn_at, severity, modified_at DESC);
CREATE INDEX IF NOT EXISTS idx_advisories_known_exploited
    ON advisories (known_exploited, current)
    WHERE known_exploited = TRUE;
CREATE INDEX IF NOT EXISTS idx_advisory_aliases_alias
    ON advisory_aliases (alias);
CREATE INDEX IF NOT EXISTS idx_advisory_affected_identity
    ON advisory_affected_components (ecosystem, canonical_identifier)
    WHERE canonical_identifier IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_advisory_affected_name
    ON advisory_affected_components (ecosystem, normalized_name, vendor);
CREATE INDEX IF NOT EXISTS idx_advisory_ranges_affected
    ON advisory_version_ranges (affected_id, ordinal);
CREATE INDEX IF NOT EXISTS idx_catalog_imports_imported
    ON advisory_catalog_imports (imported_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_catalog_imports_source_version_checksum_ci
    ON advisory_catalog_imports (
        LOWER(source),
        catalog_version,
        checksum
    );

CREATE TABLE IF NOT EXISTS vulnerability_evaluation_runs (
    run_id TEXT PRIMARY KEY,
    trigger_type TEXT NOT NULL,
    requested_by TEXT,
    scope_site_id TEXT,
    scope_asset_id TEXT,
    scope_component_id TEXT,
    scope_advisory_id TEXT,
    engine_version TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    component_count INTEGER NOT NULL DEFAULT 0,
    advisory_count INTEGER NOT NULL DEFAULT 0,
    candidate_count INTEGER NOT NULL DEFAULT 0,
    affected_count INTEGER NOT NULL DEFAULT 0,
    changed_count INTEGER NOT NULL DEFAULT 0,
    error_code TEXT,
    CHECK (status IN ('running', 'completed', 'failed'))
);

CREATE TABLE IF NOT EXISTS vulnerability_matches (
    match_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    component_id TEXT NOT NULL
        REFERENCES asset_components(component_id) ON DELETE CASCADE,
    advisory_id TEXT NOT NULL
        REFERENCES advisories(advisory_id) ON DELETE CASCADE,
    affected_id TEXT NOT NULL,
    match_status TEXT NOT NULL,
    match_confidence DOUBLE PRECISION NOT NULL,
    matched_identifier TEXT,
    installed_version TEXT,
    affected_range TEXT,
    fixed_version TEXT,
    first_matched_at TIMESTAMPTZ,
    last_matched_at TIMESTAMPTZ,
    evaluated_at TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ,
    evidence_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    reason_codes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    engine_version TEXT NOT NULL,
    last_run_id TEXT NOT NULL
        REFERENCES vulnerability_evaluation_runs(run_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (component_id, advisory_id),
    CHECK (match_confidence >= 0.0 AND match_confidence <= 1.0),
    CHECK (match_status IN (
        'affected',
        'not-affected',
        'fixed',
        'version-unknown',
        'identity-uncertain',
        'unsupported-comparison',
        'insufficient-evidence',
        'advisory-withdrawn'
    ))
);

CREATE TABLE IF NOT EXISTS vulnerability_match_history (
    history_id BIGSERIAL PRIMARY KEY,
    match_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    component_id TEXT NOT NULL,
    advisory_id TEXT NOT NULL,
    previous_status TEXT,
    current_status TEXT NOT NULL,
    previous_version TEXT,
    current_version TEXT,
    previous_advisory_checksum TEXT,
    current_advisory_checksum TEXT,
    snapshot_json JSONB NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL,
    evaluation_run_id TEXT NOT NULL
        REFERENCES vulnerability_evaluation_runs(run_id)
);

CREATE INDEX IF NOT EXISTS idx_vulnerability_matches_asset
    ON vulnerability_matches (
        site_id,
        asset_id,
        match_status,
        evaluated_at DESC
    );
CREATE INDEX IF NOT EXISTS idx_vulnerability_matches_component
    ON vulnerability_matches (component_id, match_status);
CREATE INDEX IF NOT EXISTS idx_vulnerability_matches_advisory
    ON vulnerability_matches (advisory_id, match_status);
CREATE INDEX IF NOT EXISTS idx_vulnerability_matches_status
    ON vulnerability_matches (match_status, evaluated_at DESC);
CREATE INDEX IF NOT EXISTS idx_vulnerability_history_match
    ON vulnerability_match_history (match_id, evaluated_at DESC);
CREATE INDEX IF NOT EXISTS idx_vulnerability_runs_started
    ON vulnerability_evaluation_runs (started_at DESC);

CREATE TABLE IF NOT EXISTS kev_catalog_imports (
    import_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    catalog_version TEXT NOT NULL,
    catalog_date_released TIMESTAMPTZ NOT NULL,
    payload_sha256 TEXT NOT NULL,
    source_digest TEXT NOT NULL,
    catalog_sequence BIGINT,
    license_identifier TEXT NOT NULL,
    provenance_json JSONB NOT NULL,
    record_count INTEGER NOT NULL,
    active BOOLEAN NOT NULL DEFAULT FALSE,
    imported_at TIMESTAMPTZ NOT NULL,
    activated_at TIMESTAMPTZ,
    deactivated_at TIMESTAMPTZ,
    UNIQUE (source_id, catalog_version, payload_sha256)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_kev_imports_active
    ON kev_catalog_imports (source_id) WHERE active = TRUE;
CREATE INDEX IF NOT EXISTS idx_kev_imports_released
    ON kev_catalog_imports (catalog_date_released DESC, import_id);

CREATE TABLE IF NOT EXISTS kev_records (
    import_id TEXT NOT NULL REFERENCES kev_catalog_imports(import_id),
    kev_record_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    vendor_project TEXT NOT NULL,
    product TEXT NOT NULL,
    vulnerability_name TEXT NOT NULL,
    date_added DATE NOT NULL,
    short_description TEXT NOT NULL,
    required_action TEXT NOT NULL,
    cisa_due_date DATE NOT NULL,
    ransomware_campaign_status TEXT NOT NULL,
    notes TEXT,
    cwes_json JSONB NOT NULL,
    record_digest TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    active BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (import_id, kev_record_id),
    UNIQUE (import_id, cve_id),
    CHECK (ransomware_campaign_status IN ('Known', 'Unknown', 'Not supplied'))
);

CREATE INDEX IF NOT EXISTS idx_kev_records_cve
    ON kev_records (cve_id, active);
CREATE INDEX IF NOT EXISTS idx_kev_records_date_added
    ON kev_records (date_added DESC, cve_id);
CREATE INDEX IF NOT EXISTS idx_kev_records_due_date
    ON kev_records (cisa_due_date, cve_id);
CREATE INDEX IF NOT EXISTS idx_kev_records_ransomware
    ON kev_records (ransomware_campaign_status, active);
CREATE INDEX IF NOT EXISTS idx_kev_records_import
    ON kev_records (import_id, active);

CREATE TABLE IF NOT EXISTS kev_record_history (
    history_id BIGSERIAL PRIMARY KEY,
    kev_record_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    import_id TEXT NOT NULL REFERENCES kev_catalog_imports(import_id),
    event_type TEXT NOT NULL,
    snapshot_json JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    CHECK (event_type IN ('added', 'updated', 'removed', 'reactivated'))
);

CREATE INDEX IF NOT EXISTS idx_kev_history_cve
    ON kev_record_history (cve_id, recorded_at DESC);

CREATE TABLE IF NOT EXISTS advisory_kev_correlations (
    correlation_id TEXT PRIMARY KEY,
    import_id TEXT NOT NULL REFERENCES kev_catalog_imports(import_id),
    advisory_id TEXT NOT NULL REFERENCES advisories(advisory_id),
    kev_record_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    exact_alias TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    current BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (import_id, advisory_id, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_kev_correlations_advisory
    ON advisory_kev_correlations (advisory_id, current);
CREATE INDEX IF NOT EXISTS idx_kev_correlations_cve
    ON advisory_kev_correlations (cve_id, current);

CREATE TABLE IF NOT EXISTS vulnerability_priority_factors (
    factor_id TEXT PRIMARY KEY,
    import_id TEXT NOT NULL REFERENCES kev_catalog_imports(import_id),
    match_id TEXT NOT NULL REFERENCES vulnerability_matches(match_id),
    advisory_id TEXT NOT NULL REFERENCES advisories(advisory_id),
    kev_record_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    priority_status TEXT NOT NULL,
    source_freshness TEXT NOT NULL,
    base_weight DOUBLE PRECISION NOT NULL,
    adjusted_weight DOUBLE PRECISION NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    current BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (import_id, match_id, cve_id),
    CHECK (priority_status IN ('known_exploited', 'known_exploited_ransomware')),
    CHECK (source_freshness IN ('fresh', 'aging', 'stale')),
    CHECK (base_weight >= 0 AND base_weight <= 25),
    CHECK (adjusted_weight >= 0 AND adjusted_weight <= 25)
);

CREATE INDEX IF NOT EXISTS idx_kev_factors_match
    ON vulnerability_priority_factors (match_id, current);
CREATE INDEX IF NOT EXISTS idx_kev_factors_cve
    ON vulnerability_priority_factors (cve_id, current);
CREATE INDEX IF NOT EXISTS idx_kev_factors_import
    ON vulnerability_priority_factors (import_id, current);
CREATE INDEX IF NOT EXISTS idx_kev_factors_record_current
    ON vulnerability_priority_factors (kev_record_id, match_id)
    WHERE current = TRUE;

CREATE TABLE IF NOT EXISTS vulnerability_priority_factor_history (
    history_id BIGSERIAL PRIMARY KEY,
    factor_id TEXT NOT NULL,
    match_id TEXT NOT NULL,
    kev_record_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    previous_current BOOLEAN,
    current_current BOOLEAN NOT NULL,
    snapshot_json JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_kev_factor_history_match
    ON vulnerability_priority_factor_history (match_id, recorded_at DESC);

CREATE TABLE IF NOT EXISTS advisory_feed_runs (
    run_id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL,
    request_mode TEXT NOT NULL,
    state TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    manifest_digest TEXT,
    payload_digest TEXT,
    publisher_key_id TEXT,
    catalog_version TEXT,
    catalog_sequence BIGINT,
    license_identifier TEXT,
    signature_status TEXT,
    license_status TEXT,
    attribution_status TEXT,
    advisory_count INTEGER,
    alias_count INTEGER,
    reference_count INTEGER,
    preview_json JSONB,
    active_catalog_before TEXT,
    activated_catalog_after TEXT,
    approved_by TEXT,
    approved_at TIMESTAMPTZ,
    rejected_by TEXT,
    rejected_at TIMESTAMPTZ,
    rejection_reason TEXT,
    reevaluation_status TEXT NOT NULL DEFAULT 'not-started',
    reevaluation_run_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    error_code TEXT,
    error_summary TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (request_mode IN ('remote-sync', 'local-reviewed-bundle')),
    CHECK (state IN (
        'created', 'downloading', 'downloaded', 'verifying', 'verified',
        'preview_ready', 'pending_approval', 'approved', 'importing',
        'activated', 'activated_degraded', 'rejected', 'failed', 'expired'
    )),
    CHECK (reevaluation_status IN ('not-started', 'pending', 'running', 'completed', 'failed')),
    CHECK (manifest_digest IS NULL OR manifest_digest ~ '^[0-9a-f]{64}$'),
    CHECK (payload_digest IS NULL OR payload_digest ~ '^[0-9a-f]{64}$'),
    CHECK (catalog_sequence IS NULL OR catalog_sequence > 0),
    CHECK (error_summary IS NULL OR LENGTH(error_summary) <= 240),
    CHECK (rejection_reason IS NULL OR LENGTH(rejection_reason) <= 240)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_advisory_feed_runs_active_source
    ON advisory_feed_runs (source_id)
    WHERE state IN (
        'created', 'downloading', 'downloaded', 'verifying', 'verified',
        'preview_ready', 'pending_approval', 'approved', 'importing'
    );
CREATE INDEX IF NOT EXISTS idx_advisory_feed_runs_created
    ON advisory_feed_runs (created_at DESC, run_id);
CREATE INDEX IF NOT EXISTS idx_advisory_feed_runs_source_created
    ON advisory_feed_runs (source_id, created_at DESC);

CREATE TABLE IF NOT EXISTS advisory_feed_catalogs (
    catalog_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE REFERENCES advisory_feed_runs(run_id),
    source_id TEXT NOT NULL,
    catalog_version TEXT NOT NULL,
    catalog_sequence BIGINT NOT NULL,
    manifest_digest TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    catalog_checksum TEXT NOT NULL,
    publisher_key_id TEXT NOT NULL,
    license_identifier TEXT NOT NULL,
    attribution TEXT NOT NULL,
    provenance_json JSONB NOT NULL,
    manifest_created_at TIMESTAMPTZ NOT NULL,
    manifest_expires_at TIMESTAMPTZ NOT NULL,
    manifest_bytes BYTEA NOT NULL,
    signature_bytes BYTEA NOT NULL,
    payload_bytes BYTEA NOT NULL,
    catalog_bytes BYTEA NOT NULL,
    preview_json JSONB NOT NULL,
    active BOOLEAN NOT NULL DEFAULT FALSE,
    activation_count INTEGER NOT NULL DEFAULT 0,
    first_activated_at TIMESTAMPTZ,
    last_activated_at TIMESTAMPTZ,
    retained_at TIMESTAMPTZ NOT NULL,
    UNIQUE (source_id, catalog_sequence),
    UNIQUE (source_id, catalog_version),
    UNIQUE (source_id, manifest_digest),
    UNIQUE (source_id, payload_digest),
    CHECK (catalog_sequence > 0),
    CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    CHECK (catalog_checksum ~ '^[0-9a-f]{64}$'),
    CHECK (activation_count >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_advisory_feed_catalogs_active_source
    ON advisory_feed_catalogs (source_id) WHERE active = TRUE;
CREATE INDEX IF NOT EXISTS idx_advisory_feed_catalogs_retained
    ON advisory_feed_catalogs (source_id, retained_at DESC);

CREATE TABLE IF NOT EXISTS advisory_catalog_activations (
    activation_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    source_id TEXT NOT NULL,
    catalog_id TEXT NOT NULL REFERENCES advisory_feed_catalogs(catalog_id),
    previous_catalog_id TEXT REFERENCES advisory_feed_catalogs(catalog_id),
    requested_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    reevaluation_status TEXT NOT NULL DEFAULT 'pending',
    reevaluation_run_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    impact_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    affected_before INTEGER,
    affected_after INTEGER,
    findings_before INTEGER,
    findings_after INTEGER,
    risk_before INTEGER,
    risk_after INTEGER,
    error_code TEXT,
    CHECK (action IN ('activate', 'rollback')),
    CHECK (reevaluation_status IN ('pending', 'running', 'completed', 'failed')),
    CHECK (error_code IS NULL OR LENGTH(error_code) <= 80)
);

CREATE INDEX IF NOT EXISTS idx_advisory_catalog_activations_created
    ON advisory_catalog_activations (created_at DESC, activation_id);
CREATE INDEX IF NOT EXISTS idx_advisory_catalog_activations_source
    ON advisory_catalog_activations (source_id, created_at DESC);

CREATE TABLE IF NOT EXISTS classification_evidence (
    evidence_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    asset_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    collection_method TEXT NOT NULL,
    evidence_kind TEXT NOT NULL,
    observed_value TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    direct BOOLEAN NOT NULL,
    strength TEXT NOT NULL,
    source_confidence DOUBLE PRECISION NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 1,
    agreement_state TEXT NOT NULL DEFAULT 'unassessed',
    classifier_used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (site_id, asset_id)
        REFERENCES control_tower_assets(site_id, asset_id) ON DELETE CASCADE,
    CHECK (strength IN ('direct', 'medium', 'weak')),
    CHECK (source_confidence >= 0.0 AND source_confidence <= 1.0),
    CHECK (observation_count >= 1),
    CHECK (agreement_state IN ('unassessed', 'supporting', 'conflicting', 'unused'))
);

CREATE TABLE IF NOT EXISTS classification_runs (
    run_id TEXT PRIMARY KEY,
    classifier_version TEXT NOT NULL,
    trigger_type TEXT NOT NULL,
    requested_by TEXT,
    scope_site_id TEXT,
    scope_asset_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    assets_evaluated INTEGER NOT NULL DEFAULT 0,
    assets_changed INTEGER NOT NULL DEFAULT 0,
    conflicts_found INTEGER NOT NULL DEFAULT 0,
    finding_evaluations INTEGER NOT NULL DEFAULT 0,
    bounded_errors_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    CHECK (status IN ('running', 'completed', 'failed'))
);

CREATE TABLE IF NOT EXISTS asset_classifications (
    classification_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    asset_id TEXT NOT NULL,
    classifier_version TEXT NOT NULL,
    category TEXT NOT NULL,
    subtype TEXT,
    manufacturer TEXT,
    product_hint TEXT,
    os_family TEXT,
    os_version_hint TEXT,
    managed_capability_json JSONB NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    status TEXT NOT NULL,
    supporting_evidence_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    conflicting_evidence_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    independent_source_count INTEGER NOT NULL DEFAULT 0,
    evidence_count INTEGER NOT NULL DEFAULT 0,
    first_classified_at TIMESTAMPTZ NOT NULL,
    last_classified_at TIMESTAMPTZ NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL,
    superseded_at TIMESTAMPTZ,
    freshness TEXT NOT NULL,
    reason_codes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    conflicts_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    last_run_id TEXT NOT NULL REFERENCES classification_runs(run_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (site_id, asset_id),
    FOREIGN KEY (site_id, asset_id)
        REFERENCES control_tower_assets(site_id, asset_id) ON DELETE CASCADE,
    CHECK (confidence >= 0.0 AND confidence <= 1.0),
    CHECK (status IN (
        'classified', 'partially-classified', 'unknown',
        'conflicting', 'insufficient-evidence'
    )),
    CHECK (freshness IN ('fresh', 'aging', 'stale', 'unknown'))
);

CREATE TABLE IF NOT EXISTS asset_classification_history (
    history_id BIGSERIAL PRIMARY KEY,
    classification_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    classifier_version TEXT NOT NULL,
    snapshot_json JSONB NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    superseded_at TIMESTAMPTZ NOT NULL,
    superseded_by_run_id TEXT NOT NULL REFERENCES classification_runs(run_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS asset_classification_evidence (
    classification_id TEXT NOT NULL
        REFERENCES asset_classifications(classification_id) ON DELETE CASCADE,
    evidence_id TEXT NOT NULL
        REFERENCES classification_evidence(evidence_id) ON DELETE CASCADE,
    relation TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    PRIMARY KEY (classification_id, evidence_id, relation),
    CHECK (relation IN ('supporting', 'conflicting'))
);

CREATE TABLE IF NOT EXISTS classification_conflicts (
    conflict_id TEXT PRIMARY KEY,
    classification_id TEXT NOT NULL
        REFERENCES asset_classifications(classification_id) ON DELETE CASCADE,
    site_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    conflict_type TEXT NOT NULL,
    selected_value TEXT NOT NULL,
    conflicting_value TEXT NOT NULL,
    supporting_evidence_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    conflicting_evidence_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    reason_code TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ,
    last_run_id TEXT NOT NULL REFERENCES classification_runs(run_id),
    CHECK (status IN ('open', 'resolved'))
);

CREATE INDEX IF NOT EXISTS idx_classification_evidence_asset
    ON classification_evidence (site_id, asset_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_classification_evidence_source
    ON classification_evidence (source_type, source_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_asset_classifications_filters
    ON asset_classifications (site_id, category, status, confidence DESC);
CREATE INDEX IF NOT EXISTS idx_asset_classifications_manufacturer
    ON asset_classifications (manufacturer) WHERE manufacturer IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_asset_classifications_os
    ON asset_classifications (os_family) WHERE os_family IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_classification_history_asset
    ON asset_classification_history (site_id, asset_id, superseded_at DESC);
CREATE INDEX IF NOT EXISTS idx_classification_conflicts_open
    ON classification_conflicts (site_id, asset_id, last_seen_at DESC)
    WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_classification_runs_started
    ON classification_runs (started_at DESC);
