-- Source-scoped native software collection status and component presence.
-- Canonical components remain authoritative; these tables prevent one native
-- package source from withdrawing observations owned by another source.

CREATE UNIQUE INDEX IF NOT EXISTS uq_canonical_sources_id_site
    ON canonical_ingestion_sources (source_id, site_id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_canonical_collections_id_site_source
    ON canonical_inventory_collections (
        canonical_collection_id,
        site_id,
        source_id
    );

CREATE UNIQUE INDEX IF NOT EXISTS uq_asset_components_id_site_asset
    ON asset_components (component_id, site_id, asset_id);

CREATE TABLE IF NOT EXISTS component_source_snapshots (
    source_snapshot_id TEXT PRIMARY KEY,
    canonical_collection_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    agent_source_id TEXT NOT NULL,
    collection_source_id VARCHAR(64) NOT NULL,
    platform VARCHAR(32) NOT NULL,
    collection_status VARCHAR(16) NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    record_count INTEGER NOT NULL,
    truncated BOOLEAN NOT NULL DEFAULT FALSE,
    error_code VARCHAR(80),
    limitations_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (
        canonical_collection_id,
        asset_id,
        agent_source_id,
        collection_source_id
    ),
    UNIQUE (
        source_snapshot_id,
        canonical_collection_id,
        site_id,
        asset_id,
        agent_source_id,
        collection_source_id
    ),
    UNIQUE (
        source_snapshot_id,
        site_id,
        asset_id,
        agent_source_id,
        collection_source_id
    ),
    FOREIGN KEY (canonical_collection_id, site_id, agent_source_id)
        REFERENCES canonical_inventory_collections(
            canonical_collection_id,
            site_id,
            source_id
        ),
    FOREIGN KEY (site_id, asset_id)
        REFERENCES control_tower_assets(site_id, asset_id),
    CHECK (source_snapshot_id ~ '^css_[0-9a-f]{32}$'),
    CHECK (collection_source_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    CHECK (platform IN ('windows', 'linux', 'darwin')),
    CHECK (collection_status IN ('complete', 'partial', 'unsupported', 'failed')),
    CHECK (record_count BETWEEN 0 AND 2000),
    CHECK (jsonb_typeof(limitations_json) = 'array'),
    CHECK (jsonb_array_length(limitations_json) <= 8),
    CHECK (
        collection_status <> 'complete'
        OR (truncated = FALSE AND error_code IS NULL)
    ),
    CHECK (
        collection_status <> 'failed'
        OR record_count = 0 AND error_code IS NOT NULL
    ),
    CHECK (
        collection_status <> 'unsupported'
        OR record_count = 0 AND error_code IS NOT NULL
    ),
    CHECK (
        collection_status <> 'partial'
        OR truncated = TRUE
        OR error_code IS NOT NULL
        OR jsonb_array_length(limitations_json) > 0
    )
);

CREATE TABLE IF NOT EXISTS component_collection_sources (
    site_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    agent_source_id TEXT NOT NULL,
    collection_source_id VARCHAR(64) NOT NULL,
    platform VARCHAR(32) NOT NULL,
    collection_status VARCHAR(16) NOT NULL,
    last_attempt_at TIMESTAMPTZ NOT NULL,
    last_successful_complete_at TIMESTAMPTZ,
    last_source_snapshot_id TEXT NOT NULL,
    last_successful_snapshot_id TEXT,
    canonical_collection_id TEXT NOT NULL,
    record_count INTEGER NOT NULL,
    truncated BOOLEAN NOT NULL DEFAULT FALSE,
    error_code VARCHAR(80),
    limitations_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (
        site_id,
        asset_id,
        agent_source_id,
        collection_source_id
    ),
    FOREIGN KEY (site_id, asset_id)
        REFERENCES control_tower_assets(site_id, asset_id),
    FOREIGN KEY (
        last_source_snapshot_id,
        canonical_collection_id,
        site_id,
        asset_id,
        agent_source_id,
        collection_source_id
    ) REFERENCES component_source_snapshots (
        source_snapshot_id,
        canonical_collection_id,
        site_id,
        asset_id,
        agent_source_id,
        collection_source_id
    ),
    FOREIGN KEY (
        last_successful_snapshot_id,
        site_id,
        asset_id,
        agent_source_id,
        collection_source_id
    ) REFERENCES component_source_snapshots (
        source_snapshot_id,
        site_id,
        asset_id,
        agent_source_id,
        collection_source_id
    ),
    CHECK (collection_status IN ('complete', 'partial', 'unsupported', 'failed')),
    CHECK (record_count BETWEEN 0 AND 2000),
    CHECK (jsonb_typeof(limitations_json) = 'array'),
    CHECK (jsonb_array_length(limitations_json) <= 8),
    CHECK (
        collection_status <> 'complete'
        OR (truncated = FALSE AND error_code IS NULL)
    ),
    CHECK (
        collection_status <> 'failed'
        OR record_count = 0 AND error_code IS NOT NULL
    ),
    CHECK (
        collection_status <> 'unsupported'
        OR record_count = 0 AND error_code IS NOT NULL
    ),
    CHECK (
        collection_status <> 'partial'
        OR truncated = TRUE
        OR error_code IS NOT NULL
        OR jsonb_array_length(limitations_json) > 0
    )
);

CREATE TABLE IF NOT EXISTS component_source_presence (
    component_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    agent_source_id TEXT NOT NULL,
    collection_source_id VARCHAR(64) NOT NULL,
    source_record_id VARCHAR(240) NOT NULL,
    evidence_method VARCHAR(64) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    first_observed_at TIMESTAMPTZ NOT NULL,
    last_observed_at TIMESTAMPTZ NOT NULL,
    not_observed_at TIMESTAMPTZ,
    last_source_snapshot_id TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (component_id, agent_source_id, collection_source_id),
    FOREIGN KEY (site_id, asset_id)
        REFERENCES control_tower_assets(site_id, asset_id),
    FOREIGN KEY (component_id, site_id, asset_id)
        REFERENCES asset_components(component_id, site_id, asset_id),
    FOREIGN KEY (
        last_source_snapshot_id,
        site_id,
        asset_id,
        agent_source_id,
        collection_source_id
    ) REFERENCES component_source_snapshots (
        source_snapshot_id,
        site_id,
        asset_id,
        agent_source_id,
        collection_source_id
    ),
    CHECK (collection_source_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    CHECK (evidence_method ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    CHECK (
        (active = TRUE AND not_observed_at IS NULL)
        OR (active = FALSE AND not_observed_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_component_source_snapshots_scope
    ON component_source_snapshots (
        site_id,
        asset_id,
        agent_source_id,
        collection_source_id,
        observed_at DESC
    );

CREATE INDEX IF NOT EXISTS idx_component_collection_sources_agent
    ON component_collection_sources (
        agent_source_id,
        last_attempt_at DESC
    );

CREATE INDEX IF NOT EXISTS idx_component_source_presence_scope
    ON component_source_presence (
        site_id,
        asset_id,
        agent_source_id,
        collection_source_id,
        active
    );
