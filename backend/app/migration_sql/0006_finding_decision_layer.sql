-- Deterministic finding decision layer (oaw.decision.v1).
-- Additive only. A decision is a reproducible projection of one finding's
-- authoritative fields and evidence. It never changes findings, evidence,
-- risk scores, or finding work tracking.

-- Current decision for each finding. One row per finding, bound to the site
-- that owns the finding through the composite key target from migration 0005.
CREATE TABLE IF NOT EXISTS finding_decisions (
    finding_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL,
    schema_version VARCHAR(32) NOT NULL,
    ruleset_version VARCHAR(64) NOT NULL,
    decision_state VARCHAR(16) NOT NULL,
    decision_rule_id VARCHAR(64) NOT NULL,
    action_band VARCHAR(16),
    urgency VARCHAR(32),
    severity VARCHAR(16) NOT NULL,
    evidence_confidence VARCHAR(16) NOT NULL,
    evidence_confidence_value DOUBLE PRECISION NOT NULL,
    evidence_freshness VARCHAR(16) NOT NULL,
    exploitation_status VARCHAR(32) NOT NULL,
    exposure_state VARCHAR(32) NOT NULL,
    asset_importance VARCHAR(16) NOT NULL,
    uncertainty_present BOOLEAN NOT NULL,
    verification_required BOOLEAN NOT NULL,
    prioritization_excluded BOOLEAN NOT NULL,
    reason_codes JSONB NOT NULL,
    evidence_references JSONB NOT NULL,
    input_digest CHAR(64) NOT NULL,
    finding_evaluated_at TIMESTAMPTZ NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL,
    evaluation_run_id TEXT NOT NULL REFERENCES finding_evaluation_runs(run_id),
    revision INTEGER NOT NULL,
    FOREIGN KEY (finding_id, site_id)
        REFERENCES findings(finding_id, site_id) ON DELETE CASCADE,
    CHECK (schema_version = 'oaw.decision.v1'),
    CHECK (ruleset_version ~ '^oaw[.]decision[.]rules[.]v[0-9]+$'),
    CHECK (decision_state IN ('current', 'not-current')),
    CHECK (decision_rule_id ~ '^[a-z][a-z0-9-]{0,63}$'),
    CHECK (action_band IN ('monitor', 'plan', 'prioritize', 'act-now')),
    CHECK (urgency IN ('immediate', 'expedited', 'scheduled', 'monitor', 'verification-required')),
    CHECK (decision_state <> 'current' OR action_band IS NOT NULL),
    CHECK (decision_state = 'current' OR action_band IS NULL),
    CHECK (action_band IS NOT NULL OR urgency IS NULL),
    CHECK (action_band IS NULL OR urgency IS NOT NULL),
    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
    CHECK (evidence_confidence IN ('high', 'medium', 'low', 'insufficient', 'conflicted')),
    CHECK (evidence_confidence_value >= 0.0 AND evidence_confidence_value <= 1.0),
    CHECK (evidence_freshness IN ('fresh', 'aging', 'stale', 'unknown')),
    CHECK (
        exploitation_status IN (
            'known-exploited',
            'public-exploit-evidence',
            'no-known-exploitation',
            'unknown',
            'not-applicable'
        )
    ),
    CHECK (
        exposure_state IN (
            'internet-reachable',
            'externally-reachable',
            'internally-reachable',
            'segmented',
            'not-reachable',
            'unknown',
            'not-applicable'
        )
    ),
    CHECK (asset_importance IN ('critical', 'high', 'standard', 'low', 'unknown', 'not-applicable')),
    CHECK (jsonb_typeof(reason_codes) = 'array'),
    CHECK (jsonb_array_length(reason_codes) >= 1),
    CHECK (jsonb_array_length(reason_codes) <= 32),
    CHECK (jsonb_typeof(evidence_references) = 'array'),
    CHECK (jsonb_array_length(evidence_references) <= 8),
    CHECK (input_digest ~ '^[0-9a-f]{64}$'),
    CHECK (revision >= 1)
);

-- Append-only record of material decision transitions: a change of ruleset,
-- decision state, action band, urgency, or reason codes. Re-evaluation with
-- unchanged outcome writes nothing here.
CREATE TABLE IF NOT EXISTS finding_decision_history (
    history_id BIGSERIAL PRIMARY KEY,
    finding_id TEXT NOT NULL,
    site_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    transition_cause VARCHAR(32) NOT NULL,
    ruleset_version VARCHAR(64) NOT NULL,
    previous_decision_state VARCHAR(16),
    decision_state VARCHAR(16) NOT NULL,
    previous_action_band VARCHAR(16),
    action_band VARCHAR(16),
    previous_urgency VARCHAR(32),
    urgency VARCHAR(32),
    previous_reason_codes JSONB,
    reason_codes JSONB NOT NULL,
    input_digest CHAR(64) NOT NULL,
    finding_evaluated_at TIMESTAMPTZ NOT NULL,
    evaluated_at TIMESTAMPTZ NOT NULL,
    evaluation_run_id TEXT NOT NULL REFERENCES finding_evaluation_runs(run_id),
    UNIQUE (finding_id, revision),
    FOREIGN KEY (finding_id, site_id)
        REFERENCES findings(finding_id, site_id) ON DELETE CASCADE,
    CHECK (revision >= 1),
    CHECK (
        transition_cause IN (
            'initial',
            'inputs-changed',
            'ruleset-changed',
            'finding-resolved',
            'finding-reopened'
        )
    ),
    CHECK (transition_cause <> 'initial' OR revision = 1),
    CHECK (revision = 1 OR previous_decision_state IS NOT NULL),
    CHECK (ruleset_version ~ '^oaw[.]decision[.]rules[.]v[0-9]+$'),
    CHECK (previous_decision_state IN ('current', 'not-current')),
    CHECK (decision_state IN ('current', 'not-current')),
    CHECK (previous_action_band IN ('monitor', 'plan', 'prioritize', 'act-now')),
    CHECK (action_band IN ('monitor', 'plan', 'prioritize', 'act-now')),
    CHECK (decision_state <> 'current' OR action_band IS NOT NULL),
    CHECK (decision_state = 'current' OR action_band IS NULL),
    CHECK (previous_urgency IN ('immediate', 'expedited', 'scheduled', 'monitor', 'verification-required')),
    CHECK (urgency IN ('immediate', 'expedited', 'scheduled', 'monitor', 'verification-required')),
    CHECK (previous_reason_codes IS NULL OR jsonb_typeof(previous_reason_codes) = 'array'),
    CHECK (jsonb_typeof(reason_codes) = 'array'),
    CHECK (jsonb_array_length(reason_codes) >= 1),
    CHECK (jsonb_array_length(reason_codes) <= 32),
    CHECK (input_digest ~ '^[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS idx_finding_decisions_site_band
    ON finding_decisions (site_id, action_band, finding_id);

CREATE INDEX IF NOT EXISTS idx_finding_decisions_run
    ON finding_decisions (evaluation_run_id);

CREATE INDEX IF NOT EXISTS idx_finding_decision_history_finding
    ON finding_decision_history (finding_id, evaluated_at DESC);

-- Decision history is append-only. Direct UPDATE, DELETE, and TRUNCATE are
-- rejected; only the referential cascade that removes a whole finding (for
-- example when its site is deleted) may remove history rows.
CREATE OR REPLACE FUNCTION public.oaw_finding_decision_history_append_only()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'DELETE' AND pg_trigger_depth() > 1 THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'finding decision history is append-only'
        USING ERRCODE = 'check_violation';
END;
$$;

DROP TRIGGER IF EXISTS trg_finding_decision_history_append_only
    ON finding_decision_history;
CREATE TRIGGER trg_finding_decision_history_append_only
    BEFORE UPDATE OR DELETE ON finding_decision_history
    FOR EACH ROW EXECUTE FUNCTION public.oaw_finding_decision_history_append_only();

DROP TRIGGER IF EXISTS trg_finding_decision_history_no_truncate
    ON finding_decision_history;
CREATE TRIGGER trg_finding_decision_history_no_truncate
    BEFORE TRUNCATE ON finding_decision_history
    FOR EACH STATEMENT EXECUTE FUNCTION public.oaw_finding_decision_history_append_only();
