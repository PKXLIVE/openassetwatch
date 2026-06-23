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
    CHECK (agent_type IN ('endpoint-agent', 'network-sensor'))
);

CREATE INDEX IF NOT EXISTS idx_agent_enrollments_site_id
    ON agent_enrollments (site_id);

CREATE INDEX IF NOT EXISTS idx_agent_enrollments_last_seen_at
    ON agent_enrollments (last_seen_at DESC);

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
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_local_inventory_collections_site_id_received_at
    ON local_inventory_collections (site_id, received_at DESC);

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
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (site_id, asset_id)
);

CREATE INDEX IF NOT EXISTS idx_control_tower_assets_site_id
    ON control_tower_assets (site_id);

CREATE INDEX IF NOT EXISTS idx_control_tower_assets_last_seen_at
    ON control_tower_assets (last_seen_at DESC);
