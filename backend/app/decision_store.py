"""Persistence for deterministic finding decisions.

Decisions are a projection. This store reads findings and finding evidence,
and writes only `finding_decisions` and `finding_decision_history`. It never
writes findings, evidence, risk tables, or finding work tracking, and it reads
no work-tracking table: work status cannot influence a decision.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Sequence

from sqlalchemy import text

from .decisions import (
    ACTION_BANDS,
    DECISION_RULESET_VERSION,
    REASON_CODE_EXPLANATIONS,
    FindingDecision,
    decision_input_from_records,
    evaluate_decision,
)


MAX_DECISION_RECORDS = 20_000
MAX_DECISION_PAGE = 200
MAX_DECISION_OFFSET = 10_000
DECISION_STATES = frozenset({"current", "not-current"})

# Effective operator-assigned importance for a finding row aliased `f`.
# Importance counts only when the current assignment is `assigned` and agrees
# with the append-only history: an event exists at the assignment's revision
# with the same value, reason, principal, actor label, verification, and time,
# and no later event exists (the same rule as `history_agrees`). Anything else, including no
# assignment, a withdrawal, a non-asset finding, or a projection that was
# altered without history, is `unknown`. Unknown is never read as low, and a
# corrupted projection can never drive the critical-asset rule.
EFFECTIVE_IMPORTANCE_JOIN = """
        LEFT JOIN asset_importance_assignments AS ai
          ON f.subject_type = 'asset'
         AND ai.site_id = f.site_id
         AND ai.asset_id = f.asset_id
        LEFT JOIN asset_importance_events AS aie
          ON aie.site_id = ai.site_id
         AND aie.asset_id = ai.asset_id
         AND aie.revision = ai.revision
         AND aie.importance = ai.importance
         AND aie.reason = ai.reason
         AND aie.principal = ai.principal
         AND aie.actor_label = ai.actor_label
         AND aie.actor_verification = ai.actor_verification
         AND aie.occurred_at = ai.updated_at
         AND aie.occurred_at = ai.reviewed_at
"""
EFFECTIVE_IMPORTANCE_COLUMN = """
        CASE
            WHEN ai.assignment_state = 'assigned'
             AND aie.event_id IS NOT NULL
             AND NOT EXISTS (
                 SELECT 1 FROM asset_importance_events AS later
                 WHERE later.site_id = ai.site_id
                   AND later.asset_id = ai.asset_id
                   AND later.revision > ai.revision
             )
            THEN ai.importance
            ELSE 'unknown'
        END
"""


@dataclass(frozen=True)
class DecisionReconcileResult:
    evaluated: int
    changed: int
    transitions: int


def transition_cause(previous: Mapping[str, Any] | None, decision: FindingDecision) -> str:
    if previous is None:
        return "initial"
    if previous["ruleset_version"] != decision.ruleset_version:
        return "ruleset-changed"
    if previous["decision_state"] == "current" and decision.decision_state == "not-current":
        return "finding-resolved"
    if previous["decision_state"] == "not-current" and decision.decision_state == "current":
        return "finding-reopened"
    return "inputs-changed"


def _stored_outcome(row: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        row["ruleset_version"],
        row["decision_state"],
        row["action_band"],
        row["urgency"],
        tuple(row["reason_codes"] or ()),
    )


def _bounded_page(limit: int, offset: int) -> tuple[int, int]:
    return max(1, min(limit, MAX_DECISION_PAGE)), max(0, min(offset, MAX_DECISION_OFFSET))


class SqlDecisionStore:
    def _engine(self):
        from .database import get_engine

        return get_engine()

    def ensure_schema(self) -> None:
        from .database import ensure_database_schema

        ensure_database_schema()

    # -------------------------------------------------------------- loading

    @staticmethod
    def _evidence_by_finding(connection: Any, finding_ids: Sequence[str]) -> dict[str, list[dict[str, Any]]]:
        if not finding_ids:
            return {}
        rows = connection.execute(
            text(
                """
                SELECT finding_id, evidence_ref, evidence_type, freshness
                FROM finding_evidence
                WHERE finding_id = ANY(:finding_ids)
                ORDER BY finding_id, evidence_id
                """
            ),
            {"finding_ids": list(finding_ids)},
        ).mappings().all()
        grouped: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            grouped.setdefault(str(row["finding_id"]), []).append(dict(row))
        return grouped

    # ------------------------------------------------------------ reconcile

    def reconcile_decisions(
        self,
        *,
        run_id: str,
        evaluated_at: datetime,
        site_id: str | None,
    ) -> DecisionReconcileResult:
        """Recompute decisions for every finding in scope after a finding evaluation.

        Idempotent: unchanged inputs write nothing. An older evaluation never
        overwrites a decision produced by a newer one.
        """

        evaluated = changed = transitions = 0
        with self._engine().begin() as connection:
            connection.execute(
                text("SELECT pg_advisory_xact_lock(hashtext('openassetwatch-decisions')::bigint)")
            )
            findings = connection.execute(
                text(
                    """
                    SELECT f.finding_id, f.site_id, f.rule_id, f.subject_type, f.category,
                           f.severity, f.confidence, f.evidence_freshness, f.status,
                           f.evaluated_at,
                    """
                    + EFFECTIVE_IMPORTANCE_COLUMN
                    + """ AS asset_importance
                    FROM findings AS f
                    """
                    + EFFECTIVE_IMPORTANCE_JOIN
                    + """
                    WHERE (:site_id IS NULL OR f.site_id = :site_id)
                    ORDER BY f.finding_id
                    LIMIT :limit
                    """
                ),
                {"site_id": site_id, "limit": MAX_DECISION_RECORDS + 1},
            ).mappings().all()
            if len(findings) > MAX_DECISION_RECORDS:
                raise ValueError("decision evaluation record limit exceeded")
            finding_ids = [str(row["finding_id"]) for row in findings]
            evidence = self._evidence_by_finding(connection, finding_ids)
            existing = {
                str(row["finding_id"]): dict(row)
                for row in connection.execute(
                    text(
                        """
                        SELECT finding_id, ruleset_version, decision_state, action_band,
                               urgency, reason_codes, input_digest, evaluated_at, revision
                        FROM finding_decisions
                        WHERE finding_id = ANY(:finding_ids)
                        FOR UPDATE
                        """
                    ),
                    {"finding_ids": finding_ids},
                ).mappings()
            }
            for finding in findings:
                finding_id = str(finding["finding_id"])
                decision = evaluate_decision(
                    decision_input_from_records(finding, evidence.get(finding_id, []))
                )
                evaluated += 1
                previous = existing.get(finding_id)
                if previous is not None:
                    if previous["evaluated_at"] > evaluated_at:
                        continue
                    if (
                        previous["input_digest"] == decision.input_digest
                        and _stored_outcome(previous) == decision.outcome()
                    ):
                        continue
                material = previous is None or _stored_outcome(previous) != decision.outcome()
                revision = 1 if previous is None else int(previous["revision"]) + (1 if material else 0)
                self._upsert(connection, decision, revision=revision, run_id=run_id, at=evaluated_at)
                changed += 1
                if material:
                    self._append_history(
                        connection,
                        decision,
                        previous=previous,
                        revision=revision,
                        run_id=run_id,
                        at=evaluated_at,
                    )
                    transitions += 1
        return DecisionReconcileResult(evaluated=evaluated, changed=changed, transitions=transitions)

    @staticmethod
    def _upsert(
        connection: Any,
        decision: FindingDecision,
        *,
        revision: int,
        run_id: str,
        at: datetime,
    ) -> None:
        connection.execute(
            text(
                """
                INSERT INTO finding_decisions (
                    finding_id, site_id, schema_version, ruleset_version,
                    decision_state, decision_rule_id, action_band, urgency,
                    severity, evidence_confidence, evidence_confidence_value,
                    evidence_freshness, exploitation_status, exposure_state,
                    asset_importance, uncertainty_present, verification_required,
                    prioritization_excluded, reason_codes, evidence_references,
                    input_digest, finding_evaluated_at, evaluated_at,
                    evaluation_run_id, revision
                ) VALUES (
                    :finding_id, :site_id, :schema_version, :ruleset_version,
                    :decision_state, :decision_rule_id, :action_band, :urgency,
                    :severity, :evidence_confidence, :evidence_confidence_value,
                    :evidence_freshness, :exploitation_status, :exposure_state,
                    :asset_importance, :uncertainty_present, :verification_required,
                    :prioritization_excluded, CAST(:reason_codes AS JSONB),
                    CAST(:evidence_references AS JSONB), :input_digest,
                    :finding_evaluated_at, :evaluated_at, :run_id, :revision
                )
                ON CONFLICT (finding_id) DO UPDATE SET
                    schema_version = EXCLUDED.schema_version,
                    ruleset_version = EXCLUDED.ruleset_version,
                    decision_state = EXCLUDED.decision_state,
                    decision_rule_id = EXCLUDED.decision_rule_id,
                    action_band = EXCLUDED.action_band,
                    urgency = EXCLUDED.urgency,
                    severity = EXCLUDED.severity,
                    evidence_confidence = EXCLUDED.evidence_confidence,
                    evidence_confidence_value = EXCLUDED.evidence_confidence_value,
                    evidence_freshness = EXCLUDED.evidence_freshness,
                    exploitation_status = EXCLUDED.exploitation_status,
                    exposure_state = EXCLUDED.exposure_state,
                    asset_importance = EXCLUDED.asset_importance,
                    uncertainty_present = EXCLUDED.uncertainty_present,
                    verification_required = EXCLUDED.verification_required,
                    prioritization_excluded = EXCLUDED.prioritization_excluded,
                    reason_codes = EXCLUDED.reason_codes,
                    evidence_references = EXCLUDED.evidence_references,
                    input_digest = EXCLUDED.input_digest,
                    finding_evaluated_at = EXCLUDED.finding_evaluated_at,
                    evaluated_at = EXCLUDED.evaluated_at,
                    evaluation_run_id = EXCLUDED.evaluation_run_id,
                    revision = EXCLUDED.revision
                WHERE finding_decisions.evaluated_at <= EXCLUDED.evaluated_at
                """
            ),
            {
                "finding_id": decision.finding_id,
                "site_id": decision.site_id,
                "schema_version": decision.schema_version,
                "ruleset_version": decision.ruleset_version,
                "decision_state": decision.decision_state,
                "decision_rule_id": decision.decision_rule_id,
                "action_band": decision.action_band,
                "urgency": decision.urgency,
                "severity": decision.severity,
                "evidence_confidence": decision.evidence_confidence,
                "evidence_confidence_value": decision.evidence_confidence_value,
                "evidence_freshness": decision.evidence_freshness,
                "exploitation_status": decision.exploitation_status,
                "exposure_state": decision.exposure_state,
                "asset_importance": decision.asset_importance,
                "uncertainty_present": decision.uncertainty_present,
                "verification_required": decision.verification_required,
                "prioritization_excluded": decision.prioritization_excluded,
                "reason_codes": json.dumps(list(decision.reason_codes)),
                "evidence_references": json.dumps(list(decision.evidence_references)),
                "input_digest": decision.input_digest,
                "finding_evaluated_at": decision.finding_evaluated_at,
                "evaluated_at": at,
                "run_id": run_id,
                "revision": revision,
            },
        )

    @staticmethod
    def _append_history(
        connection: Any,
        decision: FindingDecision,
        *,
        previous: Mapping[str, Any] | None,
        revision: int,
        run_id: str,
        at: datetime,
    ) -> None:
        connection.execute(
            text(
                """
                INSERT INTO finding_decision_history (
                    finding_id, site_id, revision, transition_cause, ruleset_version,
                    previous_decision_state, decision_state, previous_action_band,
                    action_band, previous_urgency, urgency, previous_reason_codes,
                    reason_codes, input_digest, finding_evaluated_at, evaluated_at,
                    evaluation_run_id
                ) VALUES (
                    :finding_id, :site_id, :revision, :cause, :ruleset_version,
                    :previous_decision_state, :decision_state, :previous_action_band,
                    :action_band, :previous_urgency, :urgency,
                    CAST(:previous_reason_codes AS JSONB), CAST(:reason_codes AS JSONB),
                    :input_digest, :finding_evaluated_at, :evaluated_at, :run_id
                )
                """
            ),
            {
                "finding_id": decision.finding_id,
                "site_id": decision.site_id,
                "revision": revision,
                "cause": transition_cause(previous, decision),
                "ruleset_version": decision.ruleset_version,
                "previous_decision_state": previous["decision_state"] if previous else None,
                "decision_state": decision.decision_state,
                "previous_action_band": previous["action_band"] if previous else None,
                "action_band": decision.action_band,
                "previous_urgency": previous["urgency"] if previous else None,
                "urgency": decision.urgency,
                "previous_reason_codes": (
                    json.dumps(list(previous["reason_codes"] or ())) if previous else None
                ),
                "reason_codes": json.dumps(list(decision.reason_codes)),
                "input_digest": decision.input_digest,
                "finding_evaluated_at": decision.finding_evaluated_at,
                "evaluated_at": at,
                "run_id": run_id,
            },
        )

    # ---------------------------------------------------------------- reads

    _DECISION_SELECT = (
        """
        SELECT d.*, f.status AS finding_status, f.asset_id, f.sensor_id,
               f.rule_id AS current_rule_id, f.subject_type, f.category,
               f.severity AS current_severity, f.confidence AS current_confidence,
               f.evidence_freshness AS current_evidence_freshness,
               f.evaluated_at AS current_finding_evaluated_at,
        """
        + EFFECTIVE_IMPORTANCE_COLUMN
        + """ AS current_asset_importance
        FROM finding_decisions AS d
        JOIN findings AS f
          ON f.finding_id = d.finding_id
         AND f.site_id = d.site_id
        """
        + EFFECTIVE_IMPORTANCE_JOIN
    )

    @staticmethod
    def _projection_state(row: Mapping[str, Any], evidence: Sequence[Mapping[str, Any]]) -> str:
        """Recompute the decision from current authoritative inputs.

        `current`: the stored decision is exactly what the ruleset produces now.
        `stale`: inputs changed and no evaluation has run since.
        `inconsistent`: inputs match but the stored outcome differs, which means
        the projection was altered or a ruleset defect exists.
        """

        recomputed = evaluate_decision(
            decision_input_from_records(
                {
                    "finding_id": row["finding_id"],
                    "site_id": row["site_id"],
                    "rule_id": row["current_rule_id"],
                    "subject_type": row["subject_type"],
                    "category": row["category"],
                    "severity": row["current_severity"],
                    "confidence": row["current_confidence"],
                    "evidence_freshness": row["current_evidence_freshness"],
                    "status": row["finding_status"],
                    "evaluated_at": row["current_finding_evaluated_at"],
                    "asset_importance": row["current_asset_importance"],
                },
                evidence,
            )
        )
        if recomputed.input_digest != row["input_digest"] or recomputed.ruleset_version != row["ruleset_version"]:
            return "stale"
        if recomputed.outcome() != _stored_outcome(row) or recomputed.decision_rule_id != row["decision_rule_id"]:
            return "inconsistent"
        return "current"

    @staticmethod
    def _attention(connection: Any, items: list[dict[str, Any]]) -> None:
        finding_ids = [item["finding_id"] for item in items]
        if not finding_ids:
            return
        contributions = {
            str(row["finding_id"]): float(row["contribution"])
            for row in connection.execute(
                text(
                    """
                    SELECT finding_id, SUM(adjusted_weight) AS contribution
                    FROM risk_factors
                    WHERE finding_id = ANY(:finding_ids) AND subject_type = 'asset'
                    GROUP BY finding_id
                    """
                ),
                {"finding_ids": finding_ids},
            ).mappings()
        }
        asset_keys = sorted(
            {(item["site_id"], item["asset_id"]) for item in items if item.get("asset_id")}
        )
        scores: dict[tuple[str, str], dict[str, Any]] = {}
        if asset_keys:
            # One keyed lookup for the whole page; the pairs match the
            # (site_id, asset_id) primary key, so the read stays indexed.
            rows = connection.execute(
                text(
                    """
                    SELECT scores.site_id, scores.asset_id, scores.score, scores.formula_version
                    FROM asset_risk_scores AS scores
                    JOIN unnest(CAST(:site_ids AS TEXT[]), CAST(:asset_ids AS TEXT[]))
                         AS wanted(site_id, asset_id)
                      ON wanted.site_id = scores.site_id
                     AND wanted.asset_id = scores.asset_id
                    """
                ),
                {
                    "site_ids": [site_id for site_id, _asset_id in asset_keys],
                    "asset_ids": [asset_id for _site_id, asset_id in asset_keys],
                },
            ).mappings()
            for row in rows:
                scores[(str(row["site_id"]), str(row["asset_id"]))] = dict(row)
        for item in items:
            score = scores.get((item["site_id"], item.get("asset_id"))) if item.get("asset_id") else None
            contribution = contributions.get(item["finding_id"])
            item["attention"] = {
                "asset_score": int(score["score"]) if score else None,
                "formula_version": str(score["formula_version"]) if score else None,
                "finding_contribution": round(contribution, 4) if contribution is not None else None,
            }

    def _project(self, connection: Any, rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        evidence = self._evidence_by_finding(connection, [str(row["finding_id"]) for row in rows])
        items: list[dict[str, Any]] = []
        for row in rows:
            reason_codes = list(row["reason_codes"] or ())
            items.append(
                {
                    "schema_version": row["schema_version"],
                    "ruleset_version": row["ruleset_version"],
                    "finding_id": row["finding_id"],
                    "site_id": row["site_id"],
                    "asset_id": row["asset_id"],
                    "sensor_id": row["sensor_id"],
                    "finding_rule_id": row["current_rule_id"],
                    "finding_status": row["finding_status"],
                    "decision_state": row["decision_state"],
                    "decision_rule_id": row["decision_rule_id"],
                    "action_band": row["action_band"],
                    "urgency": row["urgency"],
                    "severity": row["severity"],
                    "evidence_confidence": row["evidence_confidence"],
                    "evidence_confidence_value": float(row["evidence_confidence_value"]),
                    "evidence_freshness": row["evidence_freshness"],
                    "exploitation_status": row["exploitation_status"],
                    "exposure_state": row["exposure_state"],
                    "asset_importance": row["asset_importance"],
                    "uncertainty_present": bool(row["uncertainty_present"]),
                    "verification_required": bool(row["verification_required"]),
                    "prioritization_excluded": bool(row["prioritization_excluded"]),
                    "reason_codes": reason_codes,
                    "reasons": [
                        {"code": code, "explanation": REASON_CODE_EXPLANATIONS[code]}
                        for code in reason_codes
                        if code in REASON_CODE_EXPLANATIONS
                    ],
                    "evidence_references": list(row["evidence_references"] or ()),
                    "input_digest": row["input_digest"],
                    "finding_evaluated_at": row["finding_evaluated_at"],
                    "evaluated_at": row["evaluated_at"],
                    "evaluation_run_id": row["evaluation_run_id"],
                    "revision": int(row["revision"]),
                    "projection_state": self._projection_state(
                        row, evidence.get(str(row["finding_id"]), [])
                    ),
                }
            )
        self._attention(connection, items)
        return items

    def get_decision(self, finding_id: str) -> dict[str, Any] | None:
        self.ensure_schema()
        with self._engine().begin() as connection:
            row = connection.execute(
                text(self._DECISION_SELECT + " WHERE d.finding_id = :finding_id"),
                {"finding_id": finding_id},
            ).mappings().first()
            if row is None:
                return None
            return self._project(connection, [dict(row)])[0]

    def list_decisions(
        self,
        *,
        site_id: str | None = None,
        action_band: str | None = None,
        decision_state: str | None = "current",
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        self.ensure_schema()
        if action_band is not None and action_band not in ACTION_BANDS:
            raise ValueError("invalid action band")
        if decision_state is not None and decision_state not in DECISION_STATES:
            raise ValueError("invalid decision state")
        bounded_limit, bounded_offset = _bounded_page(limit, offset)
        clauses: list[str] = []
        params: dict[str, Any] = {}
        for column, value in (
            ("site_id", site_id),
            ("action_band", action_band),
            ("decision_state", decision_state),
        ):
            if value is not None:
                clauses.append(f"d.{column} = :{column}")
                params[column] = value
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._engine().begin() as connection:
            total = int(
                connection.execute(
                    text("SELECT COUNT(*) FROM finding_decisions AS d" + where), params
                ).scalar_one()
            )
            rows = connection.execute(
                text(
                    self._DECISION_SELECT
                    + where
                    + " ORDER BY CASE d.action_band WHEN 'act-now' THEN 1 WHEN 'prioritize' THEN 2"
                    " WHEN 'plan' THEN 3 WHEN 'monitor' THEN 4 ELSE 5 END,"
                    " CASE d.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3"
                    " WHEN 'low' THEN 4 ELSE 5 END, d.finding_id"
                    " LIMIT :limit OFFSET :offset"
                ),
                {**params, "limit": bounded_limit, "offset": bounded_offset},
            ).mappings().all()
            items = self._project(connection, [dict(row) for row in rows])
        return {
            "items": items,
            "total": total,
            "limit": bounded_limit,
            "offset": bounded_offset,
            "truncated": bounded_offset + len(items) < total,
        }

    def list_history(self, finding_id: str, *, limit: int = 50, offset: int = 0) -> dict[str, Any] | None:
        self.ensure_schema()
        bounded_limit, bounded_offset = _bounded_page(limit, offset)
        with self._engine().begin() as connection:
            exists = connection.execute(
                text("SELECT 1 FROM finding_decisions WHERE finding_id = :finding_id"),
                {"finding_id": finding_id},
            ).first()
            if exists is None:
                return None
            total = int(
                connection.execute(
                    text("SELECT COUNT(*) FROM finding_decision_history WHERE finding_id = :finding_id"),
                    {"finding_id": finding_id},
                ).scalar_one()
            )
            rows = connection.execute(
                text(
                    """
                    SELECT finding_id, site_id, revision, transition_cause, ruleset_version,
                           previous_decision_state, decision_state, previous_action_band,
                           action_band, previous_urgency, urgency, previous_reason_codes,
                           reason_codes, input_digest, finding_evaluated_at, evaluated_at,
                           evaluation_run_id
                    FROM finding_decision_history
                    WHERE finding_id = :finding_id
                    ORDER BY revision
                    LIMIT :limit OFFSET :offset
                    """
                ),
                {"finding_id": finding_id, "limit": bounded_limit, "offset": bounded_offset},
            ).mappings().all()
        items = []
        for row in rows:
            item = dict(row)
            item["previous_reason_codes"] = (
                list(item["previous_reason_codes"]) if item["previous_reason_codes"] is not None else None
            )
            item["reason_codes"] = list(item["reason_codes"] or ())
            items.append(item)
        return {
            "items": items,
            "total": total,
            "limit": bounded_limit,
            "offset": bounded_offset,
            "truncated": bounded_offset + len(items) < total,
        }


__all__ = [
    "DECISION_RULESET_VERSION",
    "DecisionReconcileResult",
    "SqlDecisionStore",
    "transition_cause",
]
