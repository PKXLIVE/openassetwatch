-- Manual finding work tracking.
-- Additive only. Work items record operator-supplied coordination state
-- (work status, unverified owner labels, opaque reference labels) beside a
-- deterministic finding. They never change finding status, evidence, or risk;
-- those remain owned by the evidence-based reconciliation path.

-- Composite key target so work tracking can only bind a finding to the site
-- that owns it. finding_id is already the primary key, so this is a
-- uniqueness restatement and cannot reject existing rows.
CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_id_site
    ON findings (finding_id, site_id);

CREATE TABLE IF NOT EXISTS finding_work_items (
    work_item_id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL UNIQUE,
    site_id TEXT NOT NULL,
    work_status VARCHAR(16) NOT NULL,
    owner_kind VARCHAR(8),
    owner_label VARCHAR(120),
    owner_verification VARCHAR(16) NOT NULL DEFAULT 'unverified',
    revision INTEGER NOT NULL,
    created_principal VARCHAR(64) NOT NULL,
    created_actor_label VARCHAR(120) NOT NULL,
    actor_verification VARCHAR(16) NOT NULL DEFAULT 'unverified',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (work_item_id, site_id),
    UNIQUE (work_item_id, finding_id, site_id),
    FOREIGN KEY (finding_id, site_id)
        REFERENCES findings(finding_id, site_id) ON DELETE CASCADE,
    CHECK (work_item_id ~ '^fwi_[0-9a-f]{32}$'),
    CHECK (work_status IN ('open', 'in_progress', 'blocked', 'done', 'cancelled')),
    CHECK (owner_kind IN ('person', 'team')),
    CHECK ((owner_kind IS NULL) = (owner_label IS NULL)),
    CHECK (owner_verification = 'unverified'),
    CHECK (created_principal = 'api-admin-token'),
    CHECK (actor_verification = 'unverified'),
    CHECK (revision >= 1),
    CHECK (updated_at >= created_at)
);

CREATE TABLE IF NOT EXISTS finding_work_references (
    reference_id TEXT PRIMARY KEY,
    work_item_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    reference_type VARCHAR(16) NOT NULL,
    reference_system VARCHAR(40) NOT NULL,
    reference_label VARCHAR(120) NOT NULL,
    reference_verification VARCHAR(16) NOT NULL DEFAULT 'unverified',
    added_actor_label VARCHAR(120) NOT NULL,
    added_at TIMESTAMPTZ NOT NULL,
    removed_actor_label VARCHAR(120),
    removed_at TIMESTAMPTZ,
    UNIQUE (reference_id, work_item_id),
    FOREIGN KEY (work_item_id, site_id)
        REFERENCES finding_work_items(work_item_id, site_id) ON DELETE CASCADE,
    CHECK (reference_id ~ '^fwr_[0-9a-f]{32}$'),
    CHECK (reference_type IN ('ticket', 'change', 'other')),
    CHECK (reference_system ~ '^[a-z0-9][a-z0-9._-]{0,39}$'),
    CHECK (reference_label ~ '^[A-Za-z0-9][A-Za-z0-9 ._#-]{0,119}$'),
    CHECK (reference_verification = 'unverified'),
    CHECK ((removed_at IS NULL) = (removed_actor_label IS NULL)),
    CHECK (removed_at IS NULL OR removed_at >= added_at)
);

CREATE TABLE IF NOT EXISTS finding_work_events (
    event_id BIGSERIAL PRIMARY KEY,
    work_item_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    event_type VARCHAR(32) NOT NULL,
    from_status VARCHAR(16),
    to_status VARCHAR(16),
    owner_kind VARCHAR(8),
    owner_label VARCHAR(120),
    reference_id TEXT,
    note VARCHAR(1000),
    finding_status VARCHAR(16) NOT NULL,
    principal VARCHAR(64) NOT NULL,
    actor_label VARCHAR(120) NOT NULL,
    actor_verification VARCHAR(16) NOT NULL DEFAULT 'unverified',
    occurred_at TIMESTAMPTZ NOT NULL,
    UNIQUE (work_item_id, revision),
    FOREIGN KEY (work_item_id, finding_id, site_id)
        REFERENCES finding_work_items(work_item_id, finding_id, site_id)
        ON DELETE CASCADE,
    FOREIGN KEY (reference_id, work_item_id)
        REFERENCES finding_work_references(reference_id, work_item_id),
    CHECK (revision >= 1),
    CHECK (
        event_type IN (
            'created',
            'status_changed',
            'owner_changed',
            'reference_added',
            'reference_removed',
            'note_added'
        )
    ),
    CHECK (from_status IN ('open', 'in_progress', 'blocked', 'done', 'cancelled')),
    CHECK (to_status IN ('open', 'in_progress', 'blocked', 'done', 'cancelled')),
    CHECK (owner_kind IN ('person', 'team')),
    CHECK ((owner_kind IS NULL) = (owner_label IS NULL)),
    CHECK (finding_status IN ('active', 'acknowledged', 'resolved', 'suppressed')),
    CHECK (principal = 'api-admin-token'),
    CHECK (actor_verification = 'unverified'),
    CHECK (event_type <> 'created' OR revision = 1 AND to_status IS NOT NULL),
    CHECK (
        event_type <> 'status_changed'
        OR from_status IS NOT NULL AND to_status IS NOT NULL
    ),
    CHECK (event_type <> 'reference_added' OR reference_id IS NOT NULL),
    CHECK (event_type <> 'reference_removed' OR reference_id IS NOT NULL),
    CHECK (event_type <> 'note_added' OR note IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_finding_work_items_site_status
    ON finding_work_items (site_id, work_status, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_finding_work_references_item
    ON finding_work_references (work_item_id, added_at);

CREATE UNIQUE INDEX IF NOT EXISTS uq_finding_work_references_active
    ON finding_work_references (
        work_item_id,
        reference_type,
        reference_system,
        reference_label
    )
    WHERE removed_at IS NULL;

-- Work events are an append-only audit trail. Direct UPDATE, DELETE, and
-- TRUNCATE are rejected; only the referential cascade that removes a whole
-- finding (for example when its site is deleted) may remove event rows.
CREATE OR REPLACE FUNCTION public.oaw_finding_work_events_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND pg_trigger_depth() > 1 THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'finding work events are append-only'
        USING ERRCODE = 'check_violation';
END;
$$;

DROP TRIGGER IF EXISTS trg_finding_work_events_append_only
    ON finding_work_events;
CREATE TRIGGER trg_finding_work_events_append_only
    BEFORE UPDATE OR DELETE ON finding_work_events
    FOR EACH ROW EXECUTE FUNCTION public.oaw_finding_work_events_append_only();

DROP TRIGGER IF EXISTS trg_finding_work_events_no_truncate
    ON finding_work_events;
CREATE TRIGGER trg_finding_work_events_no_truncate
    BEFORE TRUNCATE ON finding_work_events
    FOR EACH STATEMENT EXECUTE FUNCTION public.oaw_finding_work_events_append_only();

-- Deleting a work item cascades to its events, so a direct work-item DELETE
-- would erase the append-only history. Work items may be removed only by the
-- referential cascade that removes their finding.
CREATE OR REPLACE FUNCTION public.oaw_finding_work_items_cascade_only_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF pg_trigger_depth() > 1 THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'finding work items are removed only with their finding'
        USING ERRCODE = 'check_violation';
END;
$$;

DROP TRIGGER IF EXISTS trg_finding_work_items_cascade_only_delete
    ON finding_work_items;
CREATE TRIGGER trg_finding_work_items_cascade_only_delete
    BEFORE DELETE ON finding_work_items
    FOR EACH ROW EXECUTE FUNCTION public.oaw_finding_work_items_cascade_only_delete();
