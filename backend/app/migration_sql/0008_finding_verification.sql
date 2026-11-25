-- Evidence-based remediation verification (CTEM-GAP-06).
-- Additive only. Verification is a deterministic read model over existing
-- authorities: a work item marked done is the remediation report, and the
-- deterministic finding lifecycle remains the only path that resolves a
-- finding. These tables never change findings, evidence, risk, decisions,
-- asset importance, or work status. The finding lifecycle additionally
-- records the affirmative evidence behind each resolution it makes.

-- Affirmative evidence that established each deterministic resolution.
-- Written by the finding lifecycle in the same transaction that resolves the
-- finding, from the same inputs that made it eligible. The resolution basis
-- keeps a confirmed technical change (for example a component version at or
-- above the fix) distinct from a reviewed advisory or applicability change.
-- `observed_at` is collection time; `resolved_at` is evaluation time.
CREATE TABLE IF NOT EXISTS finding_resolution_evidence (
    resolution_evidence_id BIGSERIAL PRIMARY KEY,
    finding_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    resolved_at TIMESTAMPTZ NOT NULL,
    evaluation_run_id TEXT NOT NULL REFERENCES finding_evaluation_runs(run_id),
    resolution_basis VARCHAR(40) NOT NULL,
    evidence_ref TEXT NOT NULL,
    evidence_type VARCHAR(64) NOT NULL,
    source VARCHAR(120) NOT NULL,
    observed_at TIMESTAMPTZ,
    freshness VARCHAR(16) NOT NULL,
    installed_version VARCHAR(160),
    fixed_version VARCHAR(160),
    supporting_snapshot_id TEXT,
    UNIQUE (finding_id, resolved_at, evidence_ref),
    FOREIGN KEY (finding_id, site_id)
        REFERENCES findings(finding_id, site_id) ON DELETE CASCADE,
    CHECK (
        resolution_basis IN (
            'component-removed',
            'component-version-fixed',
            'component-version-available',
            'sensor-check-in',
            'fresh-observation',
            'classification-recognized',
            'classification-consistent',
            'managed-evidence',
            'healthy-coverage',
            'applicability-not-affected',
            'advisory-withdrawn',
            'advisory-identity-reviewed',
            'match-fixed-unattributed'
        )
    ),
    CHECK (freshness IN ('fresh', 'aging', 'stale', 'unknown')),
    CHECK (supporting_snapshot_id ~ '^css_[0-9a-f]{32}$')
);

-- Evidence captured when a work item is marked done. Finding evidence rows are
-- replaced on every evaluation, so the "before" references must be copied at
-- report time to stay comparable later.
CREATE TABLE IF NOT EXISTS finding_verification_baselines (
    baseline_id BIGSERIAL PRIMARY KEY,
    work_item_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    report_revision INTEGER NOT NULL,
    reported_at TIMESTAMPTZ NOT NULL,
    finding_rule_id TEXT NOT NULL,
    finding_status VARCHAR(16) NOT NULL,
    finding_evidence_observed_at TIMESTAMPTZ,
    finding_evidence_freshness VARCHAR(16) NOT NULL,
    finding_reopen_count INTEGER NOT NULL,
    evidence_references JSONB NOT NULL,
    match_versions JSONB NOT NULL,
    collection_snapshot_id TEXT,
    collection_status VARCHAR(16),
    collection_observed_at TIMESTAMPTZ,
    UNIQUE (work_item_id, report_revision),
    FOREIGN KEY (work_item_id, finding_id, site_id)
        REFERENCES finding_work_items(work_item_id, finding_id, site_id)
        ON DELETE CASCADE,
    CHECK (report_revision >= 1),
    CHECK (finding_status IN ('active', 'acknowledged', 'resolved', 'suppressed')),
    CHECK (finding_evidence_freshness IN ('fresh', 'aging', 'stale', 'unknown')),
    CHECK (finding_reopen_count >= 0),
    CHECK (jsonb_typeof(evidence_references) = 'array'),
    CHECK (jsonb_array_length(evidence_references) <= 8),
    CHECK (jsonb_typeof(match_versions) = 'array'),
    CHECK (jsonb_array_length(match_versions) <= 8),
    CHECK (collection_status IN ('complete', 'partial', 'unsupported', 'failed')),
    CHECK ((collection_snapshot_id IS NULL) = (collection_status IS NULL)),
    CHECK ((collection_status IS NULL) = (collection_observed_at IS NULL))
);

-- Append-only record of material verification transitions for one
-- remediation report, recorded during deterministic finding evaluation.
CREATE TABLE IF NOT EXISTS finding_verification_history (
    history_id BIGSERIAL PRIMARY KEY,
    work_item_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    report_revision INTEGER NOT NULL,
    sequence INTEGER NOT NULL,
    ruleset_version VARCHAR(64) NOT NULL,
    previous_state VARCHAR(32),
    verification_state VARCHAR(32) NOT NULL,
    reason_codes JSONB NOT NULL,
    after_evidence_references JSONB NOT NULL,
    finding_status VARCHAR(16) NOT NULL,
    finding_evidence_observed_at TIMESTAMPTZ,
    collection_status VARCHAR(16),
    input_digest CHAR(64) NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL,
    evaluation_run_id TEXT NOT NULL REFERENCES finding_evaluation_runs(run_id),
    UNIQUE (work_item_id, report_revision, sequence),
    FOREIGN KEY (work_item_id, finding_id, site_id)
        REFERENCES finding_work_items(work_item_id, finding_id, site_id)
        ON DELETE CASCADE,
    CHECK (report_revision >= 1),
    CHECK (sequence >= 1),
    CHECK (sequence = 1 OR previous_state IS NOT NULL),
    CHECK (ruleset_version ~ '^oaw[.]verification[.]rules[.]v[0-9]+$'),
    CHECK (
        verification_state IN (
            'awaiting-evidence',
            'insufficient-evidence',
            'evidence-stale',
            'still-present',
            'conflicting-evidence',
            'manual-review-required',
            'verified',
            'resolved-before-report',
            'resolved-by-advisory-change',
            'report-withdrawn'
        )
    ),
    CHECK (
        previous_state IN (
            'awaiting-evidence',
            'insufficient-evidence',
            'evidence-stale',
            'still-present',
            'conflicting-evidence',
            'manual-review-required',
            'verified',
            'resolved-before-report',
            'resolved-by-advisory-change',
            'report-withdrawn'
        )
    ),
    CHECK (jsonb_typeof(reason_codes) = 'array'),
    CHECK (jsonb_array_length(reason_codes) >= 1),
    CHECK (jsonb_array_length(reason_codes) <= 32),
    CHECK (jsonb_typeof(after_evidence_references) = 'array'),
    CHECK (jsonb_array_length(after_evidence_references) <= 8),
    CHECK (finding_status IN ('active', 'acknowledged', 'resolved', 'suppressed')),
    CHECK (collection_status IN ('complete', 'partial', 'unsupported', 'failed')),
    CHECK (input_digest ~ '^[0-9a-f]{64}$')
);

-- Outcome of the verification step of each finding evaluation run.
-- Verification runs after findings, risk, and decisions are settled and in its
-- own transaction, so a failure or a capacity limit never fails the core
-- evaluation. It stays visible here instead: `failed` wrote no history for the
-- run, and `incomplete` evaluated only the first `evaluated_count` reports.
CREATE TABLE IF NOT EXISTS finding_verification_runs (
    evaluation_run_id TEXT PRIMARY KEY REFERENCES finding_evaluation_runs(run_id),
    scope_site_id TEXT,
    scope_asset_id TEXT,
    scope_sensor_id TEXT,
    status VARCHAR(16) NOT NULL,
    evaluated_count INTEGER NOT NULL,
    transition_count INTEGER NOT NULL,
    error_code VARCHAR(80),
    recorded_at TIMESTAMPTZ NOT NULL,
    CHECK (status IN ('completed', 'incomplete', 'failed')),
    CHECK (evaluated_count >= 0),
    CHECK (transition_count >= 0 AND transition_count <= evaluated_count),
    CHECK ((status = 'completed') = (error_code IS NULL))
);

CREATE INDEX IF NOT EXISTS idx_finding_resolution_evidence_finding
    ON finding_resolution_evidence (finding_id, resolved_at DESC);

CREATE INDEX IF NOT EXISTS idx_finding_verification_baselines_finding
    ON finding_verification_baselines (finding_id, report_revision DESC);

CREATE INDEX IF NOT EXISTS idx_finding_verification_history_finding
    ON finding_verification_history (finding_id, evaluated_at DESC);

-- Baselines and history are append-only. Direct UPDATE, DELETE, and TRUNCATE
-- are rejected; only the referential cascade that removes a whole finding (for
-- example when its site is deleted) may remove rows.
CREATE OR REPLACE FUNCTION public.oaw_finding_verification_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND pg_trigger_depth() > 1 THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'finding verification records are append-only'
        USING ERRCODE = 'check_violation';
END;
$$;

DROP TRIGGER IF EXISTS trg_finding_resolution_evidence_append_only
    ON finding_resolution_evidence;
CREATE TRIGGER trg_finding_resolution_evidence_append_only
    BEFORE UPDATE OR DELETE ON finding_resolution_evidence
    FOR EACH ROW EXECUTE FUNCTION public.oaw_finding_verification_append_only();

DROP TRIGGER IF EXISTS trg_finding_resolution_evidence_no_truncate
    ON finding_resolution_evidence;
CREATE TRIGGER trg_finding_resolution_evidence_no_truncate
    BEFORE TRUNCATE ON finding_resolution_evidence
    FOR EACH STATEMENT EXECUTE FUNCTION public.oaw_finding_verification_append_only();

DROP TRIGGER IF EXISTS trg_finding_verification_baselines_append_only
    ON finding_verification_baselines;
CREATE TRIGGER trg_finding_verification_baselines_append_only
    BEFORE UPDATE OR DELETE ON finding_verification_baselines
    FOR EACH ROW EXECUTE FUNCTION public.oaw_finding_verification_append_only();

DROP TRIGGER IF EXISTS trg_finding_verification_baselines_no_truncate
    ON finding_verification_baselines;
CREATE TRIGGER trg_finding_verification_baselines_no_truncate
    BEFORE TRUNCATE ON finding_verification_baselines
    FOR EACH STATEMENT EXECUTE FUNCTION public.oaw_finding_verification_append_only();

DROP TRIGGER IF EXISTS trg_finding_verification_history_append_only
    ON finding_verification_history;
CREATE TRIGGER trg_finding_verification_history_append_only
    BEFORE UPDATE OR DELETE ON finding_verification_history
    FOR EACH ROW EXECUTE FUNCTION public.oaw_finding_verification_append_only();

DROP TRIGGER IF EXISTS trg_finding_verification_history_no_truncate
    ON finding_verification_history;
CREATE TRIGGER trg_finding_verification_history_no_truncate
    BEFORE TRUNCATE ON finding_verification_history
    FOR EACH STATEMENT EXECUTE FUNCTION public.oaw_finding_verification_append_only();

DROP TRIGGER IF EXISTS trg_finding_verification_runs_append_only
    ON finding_verification_runs;
CREATE TRIGGER trg_finding_verification_runs_append_only
    BEFORE UPDATE OR DELETE ON finding_verification_runs
    FOR EACH ROW EXECUTE FUNCTION public.oaw_finding_verification_append_only();

DROP TRIGGER IF EXISTS trg_finding_verification_runs_no_truncate
    ON finding_verification_runs;
CREATE TRIGGER trg_finding_verification_runs_no_truncate
    BEFORE TRUNCATE ON finding_verification_runs
    FOR EACH STATEMENT EXECUTE FUNCTION public.oaw_finding_verification_append_only();
