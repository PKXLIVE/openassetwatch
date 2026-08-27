-- Canonical inventory ingestion authority and additive compatibility mappings.
-- Existing collector and local-inventory records remain historical; new
-- authoritative asset state is written through canonical collections.

CREATE TABLE IF NOT EXISTS canonical_ingestion_sources (
    source_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    source_identity VARCHAR(160) NOT NULL,
    source_type VARCHAR(40) NOT NULL,
    adapter_type VARCHAR(40) NOT NULL,
    authentication_class VARCHAR(40) NOT NULL,
    source_authority VARCHAR(40) NOT NULL,
    trust_rank INTEGER NOT NULL,
    compatibility_status VARCHAR(24) NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (site_id, adapter_type, authentication_class, source_identity),
    CHECK (source_id ~ '^src_[0-9a-f]{32}$'),
    CHECK (source_type IN ('endpoint-agent', 'passive-sensor', 'legacy-collector', 'transitional')),
    CHECK (adapter_type IN ('endpoint-agent', 'passive-sensor', 'python-collector', 'transitional-local')),
    CHECK (authentication_class IN ('bound-credential', 'development-shared', 'legacy-shared', 'unauthenticated')),
    CHECK (source_authority IN ('authenticated-endpoint', 'authenticated-passive-sensor', 'legacy-collector', 'untrusted-transitional')),
    CHECK (trust_rank BETWEEN 0 AND 100),
    CHECK (compatibility_status IN ('canonical', 'compatibility', 'deprecated'))
);

CREATE INDEX IF NOT EXISTS idx_canonical_ingestion_sources_site_adapter
    ON canonical_ingestion_sources (site_id, adapter_type, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_canonical_ingestion_sources_authority
    ON canonical_ingestion_sources (source_authority, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS canonical_inventory_collections (
    canonical_collection_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    source_id TEXT NOT NULL REFERENCES canonical_ingestion_sources(source_id),
    adapter_type VARCHAR(40) NOT NULL,
    route_name VARCHAR(96) NOT NULL,
    idempotency_key VARCHAR(200) NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    schema_version VARCHAR(80) NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL,
    inventory_mode VARCHAR(24) NOT NULL,
    original_identifier VARCHAR(160),
    observed_asset_count INTEGER NOT NULL,
    canonical_asset_count INTEGER NOT NULL,
    evidence_count INTEGER NOT NULL,
    component_count INTEGER NOT NULL,
    ingestion_status VARCHAR(16) NOT NULL DEFAULT 'accepted',
    replay_count INTEGER NOT NULL DEFAULT 0,
    evaluation_state VARCHAR(24) NOT NULL DEFAULT 'queued',
    evaluation_error_code VARCHAR(80),
    evaluation_asset_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    compatibility_collection_id BIGINT UNIQUE REFERENCES local_inventory_collections(id),
    legacy_submission_id BIGINT UNIQUE REFERENCES collector_inventory_submissions(id),
    warning_codes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (source_id, idempotency_key),
    CHECK (canonical_collection_id ~ '^col_[0-9a-f]{32}$'),
    CHECK (adapter_type IN ('endpoint-agent', 'passive-sensor', 'python-collector', 'transitional-local')),
    CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (inventory_mode IN ('complete', 'partial', 'passive', 'legacy', 'transitional')),
    CHECK (observed_asset_count BETWEEN 0 AND 1000),
    CHECK (canonical_asset_count BETWEEN 0 AND 1000),
    CHECK (evidence_count BETWEEN 0 AND 64000),
    CHECK (component_count BETWEEN 0 AND 32000),
    CHECK (ingestion_status IN ('accepted')),
    CHECK (replay_count BETWEEN 0 AND 1000000000),
    CHECK (evaluation_state IN ('queued', 'running', 'completed', 'retryable-failure', 'not-required')),
    CHECK (jsonb_typeof(evaluation_asset_ids_json) = 'array'),
    CHECK (jsonb_typeof(warning_codes_json) = 'array')
);

CREATE INDEX IF NOT EXISTS idx_canonical_inventory_collections_site_time
    ON canonical_inventory_collections (site_id, ingested_at DESC);

CREATE INDEX IF NOT EXISTS idx_canonical_inventory_collections_adapter_time
    ON canonical_inventory_collections (adapter_type, ingested_at DESC);

CREATE INDEX IF NOT EXISTS idx_canonical_inventory_collections_source_time
    ON canonical_inventory_collections (source_id, ingested_at DESC);

CREATE INDEX IF NOT EXISTS idx_canonical_inventory_collections_evaluation
    ON canonical_inventory_collections (evaluation_state, updated_at);

CREATE TABLE IF NOT EXISTS canonical_asset_authority (
    asset_key TEXT PRIMARY KEY REFERENCES control_tower_assets(asset_key),
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    asset_id TEXT NOT NULL,
    canonical_collection_id TEXT NOT NULL REFERENCES canonical_inventory_collections(canonical_collection_id),
    source_id TEXT NOT NULL REFERENCES canonical_ingestion_sources(source_id),
    adapter_type VARCHAR(40) NOT NULL,
    source_authority VARCHAR(40) NOT NULL,
    trust_rank INTEGER NOT NULL,
    compatibility_status VARCHAR(24) NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (site_id, asset_id),
    CHECK (adapter_type IN ('endpoint-agent', 'passive-sensor', 'python-collector', 'transitional-local')),
    CHECK (source_authority IN ('authenticated-endpoint', 'authenticated-passive-sensor', 'legacy-collector', 'untrusted-transitional')),
    CHECK (trust_rank BETWEEN 0 AND 100),
    CHECK (compatibility_status IN ('canonical', 'compatibility', 'deprecated'))
);

CREATE INDEX IF NOT EXISTS idx_canonical_asset_authority_collection
    ON canonical_asset_authority (canonical_collection_id);

CREATE INDEX IF NOT EXISTS idx_canonical_asset_authority_source
    ON canonical_asset_authority (source_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS legacy_submission_mappings (
    mapping_id BIGSERIAL PRIMARY KEY,
    legacy_submission_id BIGINT NOT NULL UNIQUE REFERENCES collector_inventory_submissions(id),
    canonical_collection_id TEXT NOT NULL UNIQUE REFERENCES canonical_inventory_collections(canonical_collection_id),
    mapping_status VARCHAR(24) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (mapping_status IN ('mapped-on-ingest', 'historical-preview', 'conflict', 'historical-only'))
);

CREATE INDEX IF NOT EXISTS idx_legacy_submission_mappings_collection
    ON legacy_submission_mappings (canonical_collection_id);

CREATE TABLE IF NOT EXISTS ingestion_compatibility_events (
    event_id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(40) NOT NULL,
    outcome VARCHAR(16) NOT NULL,
    route_name VARCHAR(96) NOT NULL,
    adapter_type VARCHAR(40) NOT NULL,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    source_id TEXT REFERENCES canonical_ingestion_sources(source_id),
    canonical_collection_id TEXT REFERENCES canonical_inventory_collections(canonical_collection_id),
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (event_type IN ('accepted', 'replay', 'evaluation-state')),
    CHECK (outcome IN ('success', 'retryable')),
    CHECK (adapter_type IN ('endpoint-agent', 'passive-sensor', 'python-collector', 'transitional-local')),
    CHECK (jsonb_typeof(metadata_json) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_ingestion_compatibility_events_route_time
    ON ingestion_compatibility_events (route_name, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ingestion_compatibility_events_collection
    ON ingestion_compatibility_events (canonical_collection_id, created_at DESC);
