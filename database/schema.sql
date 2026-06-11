CREATE TABLE IF NOT EXISTS collector_inventory_submissions (
    id BIGSERIAL PRIMARY KEY,
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
