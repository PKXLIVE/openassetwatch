"""Persistence and lifecycle reconciliation for deterministic findings and risk."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence
from uuid import uuid4

from sqlalchemy import bindparam, text

from .findings import RULESET_VERSION, EvaluationSnapshot, FindingCandidate
from .risk import AssetRiskScore, SiteRiskScore


MAX_RECONCILE_RECORDS = 20_000
MAX_FINDING_PAGE = 200
FINDING_STATUSES = frozenset({"active", "acknowledged", "resolved", "suppressed"})
FINDING_SEVERITIES = frozenset({"critical", "high", "medium", "low", "informational"})

FINDINGS_SCHEMA_SQL = (
    """
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
    )
    """,
    """
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
    )
    """,
    "ALTER TABLE finding_evaluation_runs ADD COLUMN IF NOT EXISTS scope_sensor_id TEXT",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS previous_rule_version INTEGER",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS rule_version_changed_at TIMESTAMPTZ",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS engine_version TEXT NOT NULL DEFAULT 'oaw.findings.v1'",
    "ALTER TABLE findings ADD COLUMN IF NOT EXISTS evaluated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
    """
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
    )
    """,
    """
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
    )
    """,
    """
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
    )
    """,
    """
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
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_findings_status_severity ON findings (status, severity, updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_findings_site_status ON findings (site_id, status, updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_findings_asset_status ON findings (site_id, asset_id, status) WHERE asset_id IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS idx_findings_sensor_status ON findings (sensor_id, status) WHERE sensor_id IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS idx_findings_rule_status ON findings (rule_id, status)",
    "CREATE INDEX IF NOT EXISTS idx_finding_evidence_finding_id ON finding_evidence (finding_id)",
    "CREATE INDEX IF NOT EXISTS idx_finding_runs_started_at ON finding_evaluation_runs (started_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_finding_runs_scope ON finding_evaluation_runs (scope_site_id, scope_asset_id, scope_sensor_id, started_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_asset_risk_score_desc ON asset_risk_scores (score DESC, site_id, asset_id)",
    "CREATE INDEX IF NOT EXISTS idx_site_risk_score_desc ON site_risk_scores (score DESC, site_id)",
    "CREATE INDEX IF NOT EXISTS idx_risk_factors_subject ON risk_factors (subject_type, site_id, asset_id, ordinal)",
)


def ensure_findings_schema(connection: Any) -> None:
    for statement in FINDINGS_SCHEMA_SQL:
        connection.execute(text(statement))


def finding_id_for_dedupe(dedupe_key: str) -> str:
    return "fnd_" + dedupe_key.removeprefix("fdk_")[:32]


@dataclass(frozen=True)
class ReconcileResult:
    opened: int
    updated: int
    reopened: int
    resolved: int


class SqlFindingStore:
    def _engine(self):
        from .database import get_engine

        return get_engine()

    def ensure_schema(self) -> None:
        from .database import ensure_database_schema

        ensure_database_schema()

    def begin_run(
        self,
        *,
        trigger_type: str,
        requested_by: str | None,
        site_id: str | None,
        asset_id: str | None,
        sensor_id: str | None,
        ruleset_version: str,
        started_at: datetime,
    ) -> str:
        self.ensure_schema()
        run_id = "frun_" + uuid4().hex
        with self._engine().begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO finding_evaluation_runs (
                        run_id, trigger_type, requested_by, scope_site_id, scope_asset_id,
                        scope_sensor_id,
                        ruleset_version, status, started_at
                    )
                    VALUES (
                        :run_id, :trigger_type, :requested_by, :scope_site_id, :scope_asset_id,
                        :scope_sensor_id,
                        :ruleset_version, 'running', :started_at
                    )
                    """
                ),
                {
                    "run_id": run_id,
                    "trigger_type": trigger_type[:40],
                    "requested_by": requested_by[:120] if requested_by else None,
                    "scope_site_id": site_id,
                    "scope_asset_id": asset_id,
                    "scope_sensor_id": sensor_id,
                    "ruleset_version": ruleset_version,
                    "started_at": started_at,
                },
            )
        return run_id

    def fail_run(self, run_id: str, *, completed_at: datetime, error_code: str) -> None:
        with self._engine().begin() as connection:
            connection.execute(
                text(
                    """
                    UPDATE finding_evaluation_runs
                    SET status = 'failed', completed_at = :completed_at, error_code = :error_code
                    WHERE run_id = :run_id AND status = 'running'
                    """
                ),
                {"run_id": run_id, "completed_at": completed_at, "error_code": error_code[:80]},
            )

    def complete_run(
        self,
        run_id: str,
        *,
        snapshot: EvaluationSnapshot,
        result: ReconcileResult,
        completed_at: datetime,
    ) -> None:
        with self._engine().begin() as connection:
            connection.execute(
                text(
                    """
                    UPDATE finding_evaluation_runs
                    SET status = 'completed',
                        completed_at = :completed_at,
                        data_as_of = :data_as_of,
                        site_count = :site_count,
                        sensor_count = :sensor_count,
                        asset_count = :asset_count,
                        candidate_count = :candidate_count,
                        opened_count = :opened_count,
                        updated_count = :updated_count,
                        reopened_count = :reopened_count,
                        resolved_count = :resolved_count
                    WHERE run_id = :run_id AND status = 'running'
                    """
                ),
                {
                    "run_id": run_id,
                    "completed_at": completed_at,
                    "data_as_of": snapshot.data_as_of,
                    "site_count": snapshot.site_count,
                    "sensor_count": snapshot.sensor_count,
                    "asset_count": snapshot.asset_count,
                    "candidate_count": len(snapshot.candidates),
                    "opened_count": result.opened,
                    "updated_count": result.updated,
                    "reopened_count": result.reopened,
                    "resolved_count": result.resolved,
                },
            )

    @staticmethod
    def _scope_rows(
        connection: Any,
        *,
        site_id: str | None,
        asset_id: str | None,
        sensor_id: str | None,
    ) -> list[dict[str, Any]]:
        rows = connection.execute(
            text(
                """
                SELECT *
                FROM findings
                WHERE (:site_id IS NULL OR site_id = :site_id)
                  AND (:asset_id IS NULL OR asset_id = :asset_id)
                  AND (:sensor_id IS NULL OR sensor_id = :sensor_id)
                ORDER BY updated_at DESC, finding_id
                LIMIT :limit
                """
            ),
            {
                "site_id": site_id,
                "asset_id": asset_id,
                "sensor_id": sensor_id,
                "limit": MAX_RECONCILE_RECORDS + 1,
            },
        ).mappings().all()
        if len(rows) > MAX_RECONCILE_RECORDS:
            raise ValueError("finding reconciliation record limit exceeded")
        return [dict(row) for row in rows]

    def reconcile(
        self,
        *,
        run_id: str,
        snapshot: EvaluationSnapshot,
        evaluated_at: datetime,
        site_id: str | None,
        asset_id: str | None,
        sensor_id: str | None,
    ) -> ReconcileResult:
        opened = updated = reopened = resolved = 0
        candidate_by_key = {candidate.dedupe_key: candidate for candidate in snapshot.candidates}
        selected_rules = set(snapshot.evaluated_rule_ids)
        with self._engine().begin() as connection:
            # Serialize reconciliation transactions. The evaluated_at guards
            # below also prevent an older pre-lock snapshot from overwriting a
            # newer finding state after it acquires the lock.
            connection.execute(
                text(
                    "SELECT pg_advisory_xact_lock("
                    "hashtext('openassetwatch-findings')::bigint)"
                )
            )
            scoped = self._scope_rows(
                connection,
                site_id=site_id,
                asset_id=asset_id,
                sensor_id=sensor_id,
            )
            existing_by_key = {str(row["dedupe_key"]): row for row in scoped}
            for candidate in snapshot.candidates:
                previous = existing_by_key.get(candidate.dedupe_key)
                write_result = connection.execute(
                    text(
                        """
                        INSERT INTO findings (
                            finding_id, dedupe_key, rule_id, rule_version, engine_version,
                            category,
                            subject_type, site_id, asset_id, sensor_id,
                            title, description, recommendation, severity, confidence,
                            status, evidence_observed_at, evidence_freshness,
                            first_seen_at, last_seen_at, evaluated_at,
                            last_evaluation_run_id
                        )
                        VALUES (
                            :finding_id, :dedupe_key, :rule_id, :rule_version,
                            :engine_version, :category,
                            :subject_type, :site_id, :asset_id, :sensor_id,
                            :title, :description, :recommendation, :severity, :confidence,
                            'active', :evidence_observed_at, :evidence_freshness,
                            :evaluated_at, :evaluated_at, :evaluated_at, :run_id
                        )
                        ON CONFLICT (dedupe_key) DO UPDATE SET
                            previous_rule_version = CASE
                                WHEN findings.rule_version <> EXCLUDED.rule_version
                                    THEN findings.rule_version
                                ELSE findings.previous_rule_version
                            END,
                            rule_version_changed_at = CASE
                                WHEN findings.rule_version <> EXCLUDED.rule_version
                                    THEN :evaluated_at
                                ELSE findings.rule_version_changed_at
                            END,
                            rule_version = EXCLUDED.rule_version,
                            engine_version = EXCLUDED.engine_version,
                            category = EXCLUDED.category,
                            title = EXCLUDED.title,
                            description = EXCLUDED.description,
                            recommendation = EXCLUDED.recommendation,
                            severity = EXCLUDED.severity,
                            confidence = EXCLUDED.confidence,
                            status = CASE
                                WHEN findings.status = 'resolved' THEN 'active'
                                WHEN findings.status = 'suppressed'
                                     AND findings.suppressed_until IS NOT NULL
                                     AND findings.suppressed_until <= :evaluated_at
                                    THEN 'active'
                                ELSE findings.status
                            END,
                            evidence_observed_at = EXCLUDED.evidence_observed_at,
                            evidence_freshness = EXCLUDED.evidence_freshness,
                            last_seen_at = :evaluated_at,
                            evaluated_at = :evaluated_at,
                            resolved_at = CASE WHEN findings.status = 'resolved' THEN NULL ELSE findings.resolved_at END,
                            resolution_basis = CASE WHEN findings.status = 'resolved' THEN NULL ELSE findings.resolution_basis END,
                            reopen_count = findings.reopen_count + CASE WHEN findings.status = 'resolved' THEN 1 ELSE 0 END,
                            last_evaluation_run_id = :run_id,
                            updated_at = :evaluated_at
                        WHERE findings.evaluated_at <= EXCLUDED.evaluated_at
                        """
                    ),
                    {
                        "finding_id": finding_id_for_dedupe(candidate.dedupe_key),
                        "dedupe_key": candidate.dedupe_key,
                        "rule_id": candidate.rule_id,
                        "rule_version": candidate.rule_version,
                        "engine_version": RULESET_VERSION,
                        "category": candidate.category,
                        "subject_type": candidate.subject_type,
                        "site_id": candidate.site_id,
                        "asset_id": candidate.asset_id,
                        "sensor_id": candidate.sensor_id,
                        "title": candidate.title,
                        "description": candidate.description,
                        "recommendation": candidate.recommendation,
                        "severity": candidate.severity,
                        "confidence": candidate.confidence,
                        "evidence_observed_at": candidate.evidence_observed_at,
                        "evidence_freshness": candidate.evidence_freshness,
                        "evaluated_at": evaluated_at,
                        "run_id": run_id,
                    },
                )
                if write_result.rowcount == 0:
                    continue
                if previous is None:
                    opened += 1
                elif previous["status"] == "resolved":
                    reopened += 1
                else:
                    updated += 1
                finding_id = finding_id_for_dedupe(candidate.dedupe_key)
                connection.execute(
                    text("DELETE FROM finding_evidence WHERE finding_id = :finding_id"),
                    {"finding_id": finding_id},
                )
                for evidence in candidate.evidence:
                    connection.execute(
                        text(
                            """
                            INSERT INTO finding_evidence (
                                finding_id, evidence_ref, evidence_type, source,
                                observed_at, freshness, confidence, summary
                            )
                            VALUES (
                                :finding_id, :evidence_ref, :evidence_type, :source,
                                :observed_at, :freshness, :confidence, :summary
                            )
                            """
                        ),
                        {
                            "finding_id": finding_id,
                            "evidence_ref": evidence.evidence_ref,
                            "evidence_type": evidence.evidence_type,
                            "source": evidence.source,
                            "observed_at": evidence.observed_at,
                            "freshness": evidence.freshness,
                            "confidence": evidence.confidence,
                            "summary": evidence.summary,
                        },
                    )
            for row in scoped:
                if row["dedupe_key"] in candidate_by_key or row["rule_id"] not in selected_rules:
                    continue
                if row["status"] == "resolved":
                    continue
                subject_id = (
                    row["asset_id"]
                    if row["subject_type"] == "asset"
                    else row["sensor_id"]
                    if row["subject_type"] == "sensor"
                    else row["site_id"]
                )
                resolution_key = (row["rule_id"], row["subject_type"], row["site_id"], subject_id)
                if (
                    resolution_key not in snapshot.resolution_eligible
                    and row["dedupe_key"]
                    not in snapshot.resolution_eligible_dedupe_keys
                ):
                    continue
                resolution_result = connection.execute(
                    text(
                        """
                        UPDATE findings
                        SET status = 'resolved',
                            resolved_at = :evaluated_at,
                            resolution_basis = 'fresh deterministic evidence no longer matches the rule',
                            evaluated_at = :evaluated_at,
                            last_evaluation_run_id = :run_id,
                            updated_at = :evaluated_at
                        WHERE finding_id = :finding_id
                          AND evaluated_at <= :evaluated_at
                        """
                    ),
                    {
                        "finding_id": row["finding_id"],
                        "evaluated_at": evaluated_at,
                        "run_id": run_id,
                    },
                )
                resolved += max(0, resolution_result.rowcount)
        return ReconcileResult(opened=opened, updated=updated, reopened=reopened, resolved=resolved)

    def active_findings(self, *, site_id: str | None = None) -> list[dict[str, Any]]:
        self.ensure_schema()
        with self._engine().begin() as connection:
            rows = connection.execute(
                text(
                    """
                    SELECT *
                    FROM findings
                    WHERE status IN ('active', 'acknowledged')
                      AND (:site_id IS NULL OR site_id = :site_id)
                    ORDER BY site_id, asset_id, finding_id
                    LIMIT :limit
                    """
                ),
                {"site_id": site_id, "limit": MAX_RECONCILE_RECORDS + 1},
            ).mappings().all()
        if len(rows) > MAX_RECONCILE_RECORDS:
            raise ValueError("active finding limit exceeded")
        return [dict(row) for row in rows]

    def replace_risk(
        self,
        *,
        run_id: str,
        asset_scores: Sequence[AssetRiskScore],
        site_scores: Sequence[SiteRiskScore],
        calculated_at: datetime,
        snapshot_at: datetime,
        site_id: str | None,
    ) -> None:
        with self._engine().begin() as connection:
            connection.execute(
                text(
                    "SELECT pg_advisory_xact_lock("
                    "hashtext('openassetwatch-risk')::bigint)"
                )
            )
            newest = connection.execute(
                text(
                    """
                    SELECT MAX(runs.started_at)
                    FROM site_risk_scores AS scores
                    JOIN finding_evaluation_runs AS runs
                      ON runs.run_id = scores.evaluation_run_id
                    WHERE :site_id IS NULL OR scores.site_id = :site_id
                    """
                ),
                {"site_id": site_id},
            ).scalar_one_or_none()
            if newest is not None and newest > snapshot_at:
                return
            connection.execute(
                text("DELETE FROM risk_factors WHERE :site_id IS NULL OR site_id = :site_id"),
                {"site_id": site_id},
            )
            connection.execute(
                text("DELETE FROM asset_risk_scores WHERE :site_id IS NULL OR site_id = :site_id"),
                {"site_id": site_id},
            )
            connection.execute(
                text("DELETE FROM site_risk_scores WHERE :site_id IS NULL OR site_id = :site_id"),
                {"site_id": site_id},
            )
            for score in asset_scores:
                connection.execute(
                    text(
                        """
                        INSERT INTO asset_risk_scores (
                            site_id, asset_id, score, band, formula_version,
                            finding_count, data_as_of, calculated_at, evaluation_run_id
                        )
                        VALUES (
                            :site_id, :asset_id, :score, :band, :formula_version,
                            :finding_count, :data_as_of, :calculated_at, :run_id
                        )
                        """
                    ),
                    {
                        "site_id": score.site_id,
                        "asset_id": score.asset_id,
                        "score": score.score,
                        "band": score.band,
                        "formula_version": score.formula_version,
                        "finding_count": score.finding_count,
                        "data_as_of": score.data_as_of,
                        "calculated_at": calculated_at,
                        "run_id": run_id,
                    },
                )
                self._insert_factors(
                    connection,
                    subject_type="asset",
                    site_id=score.site_id,
                    asset_id=score.asset_id,
                    factors=score.factors,
                    run_id=run_id,
                )
            for score in site_scores:
                connection.execute(
                    text(
                        """
                        INSERT INTO site_risk_scores (
                            site_id, score, band, formula_version, asset_count,
                            finding_count, data_as_of, calculated_at, evaluation_run_id
                        )
                        VALUES (
                            :site_id, :score, :band, :formula_version, :asset_count,
                            :finding_count, :data_as_of, :calculated_at, :run_id
                        )
                        """
                    ),
                    {
                        "site_id": score.site_id,
                        "score": score.score,
                        "band": score.band,
                        "formula_version": score.formula_version,
                        "asset_count": score.asset_count,
                        "finding_count": score.finding_count,
                        "data_as_of": score.data_as_of,
                        "calculated_at": calculated_at,
                        "run_id": run_id,
                    },
                )
                self._insert_factors(
                    connection,
                    subject_type="site",
                    site_id=score.site_id,
                    asset_id=None,
                    factors=score.factors,
                    run_id=run_id,
                )

    @staticmethod
    def _insert_factors(
        connection: Any,
        *,
        subject_type: str,
        site_id: str,
        asset_id: str | None,
        factors: Iterable[Any],
        run_id: str,
    ) -> None:
        for factor in factors:
            connection.execute(
                text(
                    """
                    INSERT INTO risk_factors (
                        subject_type, site_id, asset_id, finding_id, factor_type,
                        category, label, severity, confidence, freshness,
                        base_weight, adjusted_weight, ordinal, evaluation_run_id
                    )
                    VALUES (
                        :subject_type, :site_id, :asset_id, :finding_id, :factor_type,
                        :category, :label, :severity, :confidence, :freshness,
                        :base_weight, :adjusted_weight, :ordinal, :run_id
                    )
                    """
                ),
                {
                    "subject_type": subject_type,
                    "site_id": site_id,
                    "asset_id": asset_id,
                    "finding_id": factor.finding_id,
                    "factor_type": factor.factor_type,
                    "category": factor.category,
                    "label": factor.label,
                    "severity": factor.severity,
                    "confidence": factor.confidence,
                    "freshness": factor.freshness,
                    "base_weight": factor.base_weight,
                    "adjusted_weight": factor.adjusted_weight,
                    "ordinal": factor.ordinal,
                    "run_id": run_id,
                },
            )

    @staticmethod
    def _finding_filters(
        *,
        site_id: str | None,
        asset_id: str | None,
        sensor_id: str | None,
        status: str | None,
        severity: str | None,
        rule_id: str | None,
        category: str | None,
        updated_after: datetime | None,
        updated_before: datetime | None,
    ) -> tuple[str, dict[str, Any]]:
        clauses: list[str] = []
        params: dict[str, Any] = {}
        for column, value in (
            ("site_id", site_id),
            ("asset_id", asset_id),
            ("sensor_id", sensor_id),
            ("status", status),
            ("severity", severity),
            ("rule_id", rule_id),
            ("category", category),
        ):
            if value is not None:
                clauses.append(f"{column} = :{column}")
                params[column] = value
        if updated_after is not None:
            clauses.append("updated_at >= :updated_after")
            params["updated_after"] = updated_after
        if updated_before is not None:
            clauses.append("updated_at <= :updated_before")
            params["updated_before"] = updated_before
        return (" WHERE " + " AND ".join(clauses)) if clauses else "", params

    def list_findings(
        self,
        *,
        site_id: str | None = None,
        asset_id: str | None = None,
        sensor_id: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        category: str | None = None,
        updated_after: datetime | None = None,
        updated_before: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        self.ensure_schema()
        if status is not None and status not in FINDING_STATUSES:
            raise ValueError("invalid finding status")
        if severity is not None and severity not in FINDING_SEVERITIES:
            raise ValueError("invalid finding severity")
        bounded_limit = max(1, min(limit, MAX_FINDING_PAGE))
        bounded_offset = max(0, min(offset, 10_000))
        where, params = self._finding_filters(
            site_id=site_id,
            asset_id=asset_id,
            sensor_id=sensor_id,
            status=status,
            severity=severity,
            rule_id=rule_id,
            category=category,
            updated_after=updated_after,
            updated_before=updated_before,
        )
        with self._engine().begin() as connection:
            total = int(
                connection.execute(text("SELECT COUNT(*) FROM findings" + where), params).scalar_one()
            )
            rows = connection.execute(
                text(
                    "SELECT * FROM findings"
                    + where
                    + " ORDER BY "
                    "CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 "
                    "WHEN 'low' THEN 4 ELSE 5 END, updated_at DESC, finding_id "
                    "LIMIT :limit OFFSET :offset"
                ),
                {**params, "limit": bounded_limit, "offset": bounded_offset},
            ).mappings().all()
            items = [dict(row) for row in rows]
            self._attach_evidence(connection, items)
        return {
            "items": items,
            "total": total,
            "limit": bounded_limit,
            "offset": bounded_offset,
            "truncated": bounded_offset + len(items) < total,
        }

    @staticmethod
    def _attach_evidence(connection: Any, items: list[dict[str, Any]]) -> None:
        finding_ids = [item["finding_id"] for item in items]
        if not finding_ids:
            return
        statement = text(
            """
            SELECT finding_id, evidence_ref, evidence_type, source,
                   observed_at, freshness, confidence, summary
            FROM finding_evidence
            WHERE finding_id IN :finding_ids
            ORDER BY finding_id, evidence_id
            """
        ).bindparams(bindparam("finding_ids", expanding=True))
        evidence_rows = connection.execute(statement, {"finding_ids": finding_ids}).mappings().all()
        by_finding: dict[str, list[dict[str, Any]]] = {}
        for row in evidence_rows:
            by_finding.setdefault(str(row["finding_id"]), []).append(dict(row))
        for item in items:
            item["evidence"] = by_finding.get(str(item["finding_id"]), [])

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        self.ensure_schema()
        with self._engine().begin() as connection:
            row = connection.execute(
                text("SELECT * FROM findings WHERE finding_id = :finding_id"),
                {"finding_id": finding_id},
            ).mappings().first()
            if row is None:
                return None
            item = dict(row)
            self._attach_evidence(connection, [item])
            return item

    def acknowledge(self, finding_id: str, *, actor: str, at: datetime) -> dict[str, Any] | None:
        self.ensure_schema()
        with self._engine().begin() as connection:
            row = connection.execute(
                text(
                    """
                    UPDATE findings
                    SET status = 'acknowledged',
                        acknowledged_at = :at,
                        acknowledged_by = :actor,
                        updated_at = :at
                    WHERE finding_id = :finding_id AND status IN ('active', 'acknowledged')
                    RETURNING *
                    """
                ),
                {"finding_id": finding_id, "actor": actor[:120], "at": at},
            ).mappings().first()
            if row is None:
                return None
            item = dict(row)
            self._attach_evidence(connection, [item])
            return item

    def suppress(
        self,
        finding_id: str,
        *,
        actor: str,
        reason: str,
        until: datetime | None,
        at: datetime,
    ) -> dict[str, Any] | None:
        self.ensure_schema()
        with self._engine().begin() as connection:
            row = connection.execute(
                text(
                    """
                    UPDATE findings
                    SET status = 'suppressed',
                        suppressed_at = :at,
                        suppressed_by = :actor,
                        suppressed_until = :until,
                        suppression_reason = :reason,
                        updated_at = :at
                    WHERE finding_id = :finding_id AND status IN ('active', 'acknowledged', 'suppressed')
                    RETURNING *
                    """
                ),
                {
                    "finding_id": finding_id,
                    "actor": actor[:120],
                    "reason": reason[:500],
                    "until": until,
                    "at": at,
                },
            ).mappings().first()
            if row is None:
                return None
            item = dict(row)
            self._attach_evidence(connection, [item])
            return item

    def _risk_factors(
        self,
        connection: Any,
        *,
        subject_type: str,
        site_id: str,
        asset_id: str | None,
    ) -> list[dict[str, Any]]:
        rows = connection.execute(
            text(
                """
                SELECT factor_type, finding_id, category, label, severity,
                       confidence, freshness, base_weight, adjusted_weight, ordinal
                FROM risk_factors
                WHERE subject_type = :subject_type
                  AND site_id = :site_id
                  AND (:asset_id IS NULL OR asset_id = :asset_id)
                ORDER BY ordinal, risk_factor_id
                LIMIT 100
                """
            ),
            {"subject_type": subject_type, "site_id": site_id, "asset_id": asset_id},
        ).mappings().all()
        return [dict(row) for row in rows]

    def get_asset_risk(self, *, site_id: str, asset_id: str) -> dict[str, Any] | None:
        self.ensure_schema()
        with self._engine().begin() as connection:
            row = connection.execute(
                text(
                    """
                    SELECT * FROM asset_risk_scores
                    WHERE site_id = :site_id AND asset_id = :asset_id
                    """
                ),
                {"site_id": site_id, "asset_id": asset_id},
            ).mappings().first()
            if row is None:
                return None
            item = dict(row)
            item["factors"] = self._risk_factors(
                connection,
                subject_type="asset",
                site_id=site_id,
                asset_id=asset_id,
            )
            return item

    def get_site_risk(self, *, site_id: str) -> dict[str, Any] | None:
        self.ensure_schema()
        with self._engine().begin() as connection:
            row = connection.execute(
                text("SELECT * FROM site_risk_scores WHERE site_id = :site_id"),
                {"site_id": site_id},
            ).mappings().first()
            if row is None:
                return None
            item = dict(row)
            item["factors"] = self._risk_factors(
                connection,
                subject_type="site",
                site_id=site_id,
                asset_id=None,
            )
            return item

    def risk_summary(self, *, site_id: str | None = None, limit: int = 100) -> dict[str, Any]:
        self.ensure_schema()
        bounded_limit = max(1, min(limit, 200))
        with self._engine().begin() as connection:
            site_rows = connection.execute(
                text(
                    """
                    SELECT * FROM site_risk_scores
                    WHERE (:site_id IS NULL OR site_id = :site_id)
                    ORDER BY score DESC, site_id
                    LIMIT :limit
                    """
                ),
                {"site_id": site_id, "limit": bounded_limit},
            ).mappings().all()
            asset_rows = connection.execute(
                text(
                    """
                    SELECT * FROM asset_risk_scores
                    WHERE (:site_id IS NULL OR site_id = :site_id)
                    ORDER BY score DESC, site_id, asset_id
                    LIMIT :limit
                    """
                ),
                {"site_id": site_id, "limit": bounded_limit},
            ).mappings().all()
            severity_rows = connection.execute(
                text(
                    """
                    SELECT severity, COUNT(*) AS count
                    FROM findings
                    WHERE status IN ('active', 'acknowledged')
                      AND (:site_id IS NULL OR site_id = :site_id)
                    GROUP BY severity
                    ORDER BY severity
                    """
                ),
                {"site_id": site_id},
            ).mappings().all()
            site_items = [dict(row) for row in site_rows]
            asset_items = [dict(row) for row in asset_rows]
            self._attach_summary_risk_factors(
                connection,
                subject_type="site",
                items=site_items,
            )
            self._attach_summary_risk_factors(
                connection,
                subject_type="asset",
                items=asset_items,
            )
        return {
            "sites": site_items,
            "assets": asset_items,
            "active_findings_by_severity": {
                str(row["severity"]): int(row["count"]) for row in severity_rows
            },
            "formula_version": (
                str(site_rows[0]["formula_version"])
                if site_rows
                else str(asset_rows[0]["formula_version"])
                if asset_rows
                else "oaw.risk.v1"
            ),
        }

    @staticmethod
    def _attach_summary_risk_factors(
        connection: Any,
        *,
        subject_type: str,
        items: list[dict[str, Any]],
    ) -> None:
        if not items:
            return
        site_ids = sorted({str(item["site_id"]) for item in items})
        params: dict[str, Any] = {"subject_type": subject_type, "site_ids": site_ids}
        asset_clause = ""
        expanding = [bindparam("site_ids", expanding=True)]
        if subject_type == "asset":
            params["subject_keys"] = sorted(
                {
                    f"{item['site_id']}\x1f{item['asset_id']}"
                    for item in items
                    if item.get("asset_id")
                }
            )
            asset_clause = (
                "\n                  AND "
                "(site_id || CHR(31) || asset_id) IN :subject_keys"
            )
            expanding.append(bindparam("subject_keys", expanding=True))
        statement = text(
            """
            WITH ranked AS (
                SELECT
                    subject_type, site_id, asset_id, factor_type, finding_id,
                    category, label, severity, confidence, freshness,
                    base_weight, adjusted_weight, ordinal, risk_factor_id,
                    ROW_NUMBER() OVER (
                        PARTITION BY subject_type, site_id, asset_id
                        ORDER BY ordinal, risk_factor_id
                    ) AS factor_rank
                FROM risk_factors
                WHERE subject_type = :subject_type
                  AND site_id IN :site_ids
            """
            + asset_clause
            + """
            )
            SELECT
                site_id, asset_id, factor_type, finding_id, category, label,
                severity, confidence, freshness, base_weight, adjusted_weight,
                ordinal
            FROM ranked
            WHERE factor_rank <= 8
            ORDER BY site_id, asset_id, ordinal, risk_factor_id
            """
        ).bindparams(*expanding)
        rows = connection.execute(statement, params).mappings().all()
        allowed = {
            (str(item["site_id"]), str(item.get("asset_id") or ""))
            for item in items
        }
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for row in rows:
            key = (str(row["site_id"]), str(row.get("asset_id") or ""))
            if key in allowed:
                factor = dict(row)
                factor.pop("site_id", None)
                factor.pop("asset_id", None)
                grouped.setdefault(key, []).append(factor)
        for item in items:
            key = (str(item["site_id"]), str(item.get("asset_id") or ""))
            item["factors"] = grouped.get(key, [])


class InMemoryFindingStore:
    """Small deterministic store used by lifecycle and integration tests."""

    def __init__(self) -> None:
        self.findings: dict[str, dict[str, Any]] = {}
        self.runs: dict[str, dict[str, Any]] = {}
        self.asset_risk: dict[tuple[str, str], AssetRiskScore] = {}
        self.site_risk: dict[str, SiteRiskScore] = {}

    def begin_run(self, **values: Any) -> str:
        run_id = f"frun_test_{len(self.runs) + 1}"
        self.runs[run_id] = {"status": "running", **values}
        return run_id

    def fail_run(self, run_id: str, *, completed_at: datetime, error_code: str) -> None:
        self.runs[run_id].update(status="failed", completed_at=completed_at, error_code=error_code)

    def complete_run(
        self,
        run_id: str,
        *,
        snapshot: EvaluationSnapshot,
        result: ReconcileResult,
        completed_at: datetime,
    ) -> None:
        self.runs[run_id].update(
            status="completed",
            completed_at=completed_at,
            candidate_count=len(snapshot.candidates),
            result=result,
        )

    def reconcile(
        self,
        *,
        run_id: str,
        snapshot: EvaluationSnapshot,
        evaluated_at: datetime,
        site_id: str | None,
        asset_id: str | None,
        sensor_id: str | None,
    ) -> ReconcileResult:
        opened = updated = reopened = resolved = 0
        matched: set[str] = set()
        for candidate in snapshot.candidates:
            finding_id = finding_id_for_dedupe(candidate.dedupe_key)
            matched.add(finding_id)
            previous = self.findings.get(finding_id)
            if (
                previous is not None
                and previous.get("evaluated_at") is not None
                and previous["evaluated_at"] > evaluated_at
            ):
                continue
            status = "active"
            reopen_count = 0
            first_seen_at = evaluated_at
            if previous:
                first_seen_at = previous["first_seen_at"]
                reopen_count = int(previous.get("reopen_count", 0))
                if previous["status"] == "resolved":
                    reopened += 1
                    reopen_count += 1
                else:
                    updated += 1
                    status = previous["status"]
                    if (
                        status == "suppressed"
                        and previous.get("suppressed_until") is not None
                        and previous["suppressed_until"] <= evaluated_at
                    ):
                        status = "active"
            else:
                opened += 1
            administrative = {
                key: previous[key]
                for key in (
                    "acknowledged_at",
                    "acknowledged_by",
                    "suppressed_at",
                    "suppressed_by",
                    "suppressed_until",
                    "suppression_reason",
                )
                if previous is not None and key in previous
            }
            previous_rule_version = (
                previous.get("previous_rule_version")
                if previous is not None
                else None
            )
            rule_version_changed_at = (
                previous.get("rule_version_changed_at")
                if previous is not None
                else None
            )
            if previous is not None and previous["rule_version"] != candidate.rule_version:
                previous_rule_version = previous["rule_version"]
                rule_version_changed_at = evaluated_at
            self.findings[finding_id] = {
                **candidate.__dict__,
                **administrative,
                "engine_version": RULESET_VERSION,
                "previous_rule_version": previous_rule_version,
                "rule_version_changed_at": rule_version_changed_at,
                "finding_id": finding_id,
                "status": status,
                "first_seen_at": first_seen_at,
                "last_seen_at": evaluated_at,
                "evaluated_at": evaluated_at,
                "resolved_at": None,
                "resolution_basis": None,
                "reopen_count": reopen_count,
                "last_evaluation_run_id": run_id,
                "evidence": [item.__dict__ for item in candidate.evidence],
            }
        selected = set(snapshot.evaluated_rule_ids)
        for finding_id, finding in self.findings.items():
            if finding_id in matched or finding["rule_id"] not in selected or finding["status"] == "resolved":
                continue
            if (
                finding.get("evaluated_at") is not None
                and finding["evaluated_at"] > evaluated_at
            ):
                continue
            if site_id and finding["site_id"] != site_id:
                continue
            if asset_id and finding.get("asset_id") != asset_id:
                continue
            if sensor_id and finding.get("sensor_id") != sensor_id:
                continue
            subject_id = (
                finding.get("asset_id")
                if finding["subject_type"] == "asset"
                else finding.get("sensor_id")
                if finding["subject_type"] == "sensor"
                else finding["site_id"]
            )
            key = (finding["rule_id"], finding["subject_type"], finding["site_id"], subject_id)
            if (
                key not in snapshot.resolution_eligible
                and finding["dedupe_key"]
                not in snapshot.resolution_eligible_dedupe_keys
            ):
                continue
            finding.update(
                status="resolved",
                resolved_at=evaluated_at,
                evaluated_at=evaluated_at,
                resolution_basis="fresh deterministic evidence no longer matches the rule",
                last_evaluation_run_id=run_id,
            )
            resolved += 1
        return ReconcileResult(opened=opened, updated=updated, reopened=reopened, resolved=resolved)

    def active_findings(self, *, site_id: str | None = None) -> list[dict[str, Any]]:
        return [
            dict(item)
            for item in self.findings.values()
            if item["status"] in {"active", "acknowledged"}
            and (not site_id or item["site_id"] == site_id)
        ]

    def acknowledge(self, finding_id: str, *, actor: str, at: datetime) -> dict[str, Any] | None:
        finding = self.findings.get(finding_id)
        if finding is None or finding["status"] not in {"active", "acknowledged"}:
            return None
        finding.update(
            status="acknowledged",
            acknowledged_at=at,
            acknowledged_by=actor[:120],
        )
        return dict(finding)

    def suppress(
        self,
        finding_id: str,
        *,
        actor: str,
        reason: str,
        until: datetime | None,
        at: datetime,
    ) -> dict[str, Any] | None:
        finding = self.findings.get(finding_id)
        if finding is None or finding["status"] not in {"active", "acknowledged", "suppressed"}:
            return None
        finding.update(
            status="suppressed",
            suppressed_at=at,
            suppressed_by=actor[:120],
            suppressed_until=until,
            suppression_reason=reason[:500],
        )
        return dict(finding)

    def replace_risk(
        self,
        *,
        run_id: str,
        asset_scores: Sequence[AssetRiskScore],
        site_scores: Sequence[SiteRiskScore],
        calculated_at: datetime,
        snapshot_at: datetime,
        site_id: str | None,
    ) -> None:
        if site_id:
            self.asset_risk = {key: value for key, value in self.asset_risk.items() if key[0] != site_id}
            self.site_risk.pop(site_id, None)
        else:
            self.asset_risk.clear()
            self.site_risk.clear()
        self.asset_risk.update({(item.site_id, item.asset_id): item for item in asset_scores})
        self.site_risk.update({item.site_id: item for item in site_scores})


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
