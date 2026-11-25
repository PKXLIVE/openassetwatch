-- Audited asset importance (CTEM-GAP-02).
-- Additive only. An importance assignment is an operator assertion about the
-- consequence of losing or degrading one asset in this environment. It is not
-- discovered evidence, not a vulnerability severity, and not a score. It never
-- changes findings, evidence, risk scores, decisions, or finding work tracking;
-- decisions read it only through deterministic finding evaluation.
--
-- Absence of a row means importance is unknown. Unknown is never read as low.

-- Current assignment for an asset. Bound to the site that owns the asset
-- through the existing (site_id, asset_id) unique key of control_tower_assets.
CREATE TABLE IF NOT EXISTS asset_importance_assignments (
    site_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    importance VARCHAR(16) NOT NULL,
    assignment_state VARCHAR(16) NOT NULL,
    source VARCHAR(16) NOT NULL,
    reason VARCHAR(500) NOT NULL,
    revision INTEGER NOT NULL,
    principal VARCHAR(64) NOT NULL,
    actor_label VARCHAR(120) NOT NULL,
    actor_verification VARCHAR(16) NOT NULL DEFAULT 'unverified',
    created_at TIMESTAMPTZ NOT NULL,
    reviewed_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (site_id, asset_id),
    FOREIGN KEY (site_id, asset_id)
        REFERENCES control_tower_assets(site_id, asset_id) ON DELETE CASCADE,
    CHECK (importance IN ('critical', 'high', 'standard', 'low', 'unknown')),
    CHECK (assignment_state IN ('assigned', 'withdrawn')),
    CHECK ((importance = 'unknown') = (assignment_state = 'withdrawn')),
    CHECK (source = 'operator'),
    CHECK (principal = 'api-admin-token'),
    CHECK (actor_verification = 'unverified'),
    CHECK (revision >= 1),
    CHECK (reviewed_at >= created_at),
    CHECK (updated_at >= reviewed_at)
);

-- Append-only history of every importance change, including withdrawal and
-- re-affirmation, with the previous value and the stated reason.
CREATE TABLE IF NOT EXISTS asset_importance_events (
    event_id BIGSERIAL PRIMARY KEY,
    site_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    event_type VARCHAR(16) NOT NULL,
    previous_importance VARCHAR(16),
    importance VARCHAR(16) NOT NULL,
    reason VARCHAR(500) NOT NULL,
    principal VARCHAR(64) NOT NULL,
    actor_label VARCHAR(120) NOT NULL,
    actor_verification VARCHAR(16) NOT NULL DEFAULT 'unverified',
    occurred_at TIMESTAMPTZ NOT NULL,
    UNIQUE (site_id, asset_id, revision),
    FOREIGN KEY (site_id, asset_id)
        REFERENCES asset_importance_assignments(site_id, asset_id) ON DELETE CASCADE,
    CHECK (revision >= 1),
    CHECK (event_type IN ('assigned', 'changed', 'reviewed', 'withdrawn')),
    CHECK (previous_importance IN ('critical', 'high', 'standard', 'low', 'unknown')),
    CHECK (importance IN ('critical', 'high', 'standard', 'low', 'unknown')),
    CHECK (revision <> 1 OR event_type = 'assigned' AND previous_importance IS NULL),
    CHECK (revision = 1 OR previous_importance IS NOT NULL),
    CHECK (
        event_type <> 'assigned'
        OR importance <> 'unknown'
        AND (previous_importance IS NULL OR previous_importance = 'unknown')
    ),
    CHECK (
        event_type <> 'changed'
        OR importance <> 'unknown'
        AND previous_importance <> 'unknown'
        AND importance <> previous_importance
    ),
    CHECK (event_type <> 'reviewed' OR importance <> 'unknown' AND importance = previous_importance),
    CHECK (event_type <> 'withdrawn' OR importance = 'unknown' AND previous_importance <> 'unknown'),
    CHECK (principal = 'api-admin-token'),
    CHECK (actor_verification = 'unverified')
);

CREATE INDEX IF NOT EXISTS idx_asset_importance_assignments_site_importance
    ON asset_importance_assignments (site_id, importance, asset_id);

CREATE INDEX IF NOT EXISTS idx_asset_importance_events_occurred
    ON asset_importance_events (site_id, occurred_at DESC);

-- Importance events are append-only. Direct UPDATE, DELETE, and TRUNCATE are
-- rejected; only the referential cascade that removes a whole asset (for
-- example when its site is deleted) may remove event rows.
CREATE OR REPLACE FUNCTION public.oaw_asset_importance_events_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND pg_trigger_depth() > 1 THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'asset importance events are append-only'
        USING ERRCODE = 'check_violation';
END;
$$;

DROP TRIGGER IF EXISTS trg_asset_importance_events_append_only
    ON asset_importance_events;
CREATE TRIGGER trg_asset_importance_events_append_only
    BEFORE UPDATE OR DELETE ON asset_importance_events
    FOR EACH ROW EXECUTE FUNCTION public.oaw_asset_importance_events_append_only();

DROP TRIGGER IF EXISTS trg_asset_importance_events_no_truncate
    ON asset_importance_events;
CREATE TRIGGER trg_asset_importance_events_no_truncate
    BEFORE TRUNCATE ON asset_importance_events
    FOR EACH STATEMENT EXECUTE FUNCTION public.oaw_asset_importance_events_append_only();

-- Deleting an assignment cascades to its events, so a direct DELETE would
-- erase the append-only history. Withdrawal is recorded as an event instead;
-- an assignment row is removed only by the cascade that removes its asset.
CREATE OR REPLACE FUNCTION public.oaw_asset_importance_assignments_cascade_only_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF pg_trigger_depth() > 1 THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'asset importance assignments are removed only with their asset'
        USING ERRCODE = 'check_violation';
END;
$$;

DROP TRIGGER IF EXISTS trg_asset_importance_assignments_cascade_only_delete
    ON asset_importance_assignments;
CREATE TRIGGER trg_asset_importance_assignments_cascade_only_delete
    BEFORE DELETE ON asset_importance_assignments
    FOR EACH ROW EXECUTE FUNCTION public.oaw_asset_importance_assignments_cascade_only_delete();
