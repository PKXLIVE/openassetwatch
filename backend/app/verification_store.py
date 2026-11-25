"""Persistence and read model for remediation verification (CTEM-GAP-06).

This store reads findings, finding evidence, finding work items and events,
component source snapshots, and vulnerability matches. It writes only the
append-only ``finding_verification_baselines`` and
``finding_verification_history``. It never writes findings, evidence, risk,
decisions, asset importance, or work status, so verification cannot resolve a
finding or change what the decision layer sees.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Sequence

from sqlalchemy import text

from .findings import RULES_BY_ID
from .verification import (
    CONFLICT_RULES,
    MAX_VERIFICATION_EVIDENCE_REFERENCES,
    REASON_CODE_EXPLANATIONS,
    UNVERIFIED_STATES,
    VERIFICATION_RULESET_VERSION,
    VERIFICATION_STATES,
    CollectionSnapshot,
    FindingState,
    RemediationReport,
    VerificationInput,
    VerificationOutcome,
    evaluate_verification,
    evidence_from_json,
    evidence_from_records,
    evidence_to_json,
    method_for,
    proofs_from_records,
)
from .findings import TECHNICAL_RESOLUTION_BASES


MAX_VERIFICATION_RECORDS = 20_000
MAX_VERIFICATION_PAGE = 200
MAX_VERIFICATION_OFFSET = 10_000
COMPONENT_COLLECTION_CHECK = "component-source-snapshot"


@dataclass(frozen=True)
class VerificationReconcileResult:
    evaluated: int
    transitions: int


def _bounded_page(limit: int, offset: int) -> tuple[int, int]:
    return max(1, min(limit, MAX_VERIFICATION_PAGE)), max(0, min(offset, MAX_VERIFICATION_OFFSET))


def capture_baseline(
    connection: Any,
    *,
    work_item_id: str,
    finding_id: str,
    site_id: str,
    report_revision: int,
    reported_at: datetime,
) -> None:
    """Record the evidence present when a work item is marked done.

    Runs inside the caller's work-status transaction, so the baseline and the
    `done` event commit or roll back together. It reads the finding and its
    evidence; it writes only the baseline.
    """

    finding = connection.execute(
        text(
            """
            SELECT finding_id, site_id, rule_id, subject_type, asset_id, status,
                   evidence_observed_at, evidence_freshness, reopen_count
            FROM findings
            WHERE finding_id = :finding_id AND site_id = :site_id
            """
        ),
        {"finding_id": finding_id, "site_id": site_id},
    ).mappings().one()
    evidence = connection.execute(
        text(
            """
            SELECT evidence_ref, evidence_type, freshness, observed_at
            FROM finding_evidence
            WHERE finding_id = :finding_id
            ORDER BY evidence_type, evidence_ref
            LIMIT :limit
            """
        ),
        {"finding_id": finding_id, "limit": MAX_VERIFICATION_EVIDENCE_REFERENCES},
    ).mappings().all()
    snapshot = None
    if finding["subject_type"] == "asset" and finding["asset_id"] is not None:
        snapshot = connection.execute(
            text(
                """
                SELECT source_snapshot_id, collection_status, observed_at
                FROM component_source_snapshots
                WHERE site_id = :site_id AND asset_id = :asset_id
                  AND observed_at <= :reported_at
                ORDER BY observed_at DESC, source_snapshot_id
                LIMIT 1
                """
            ),
            {"site_id": site_id, "asset_id": finding["asset_id"], "reported_at": reported_at},
        ).mappings().first()
    connection.execute(
        text(
            """
            INSERT INTO finding_verification_baselines (
                work_item_id, finding_id, site_id, report_revision, reported_at,
                finding_rule_id, finding_status, finding_evidence_observed_at,
                finding_evidence_freshness, finding_reopen_count, evidence_references,
                collection_snapshot_id, collection_status, collection_observed_at
            ) VALUES (
                :work_item_id, :finding_id, :site_id, :report_revision, :reported_at,
                :rule_id, :status, :evidence_observed_at, :evidence_freshness,
                :reopen_count, CAST(:evidence AS JSONB), :snapshot_id,
                :collection_status, :collection_observed_at
            )
            """
        ),
        {
            "work_item_id": work_item_id,
            "finding_id": finding_id,
            "site_id": site_id,
            "report_revision": report_revision,
            "reported_at": reported_at,
            "rule_id": finding["rule_id"],
            "status": finding["status"],
            "evidence_observed_at": finding["evidence_observed_at"],
            "evidence_freshness": finding["evidence_freshness"],
            "reopen_count": int(finding["reopen_count"]),
            "evidence": json.dumps(evidence_to_json(evidence_from_records(evidence))),
            "snapshot_id": snapshot["source_snapshot_id"] if snapshot else None,
            "collection_status": snapshot["collection_status"] if snapshot else None,
            "collection_observed_at": snapshot["observed_at"] if snapshot else None,
        },
    )


class SqlVerificationStore:
    def _engine(self):
        from .database import get_engine

        return get_engine()

    def ensure_schema(self) -> None:
        from .database import ensure_database_schema

        ensure_database_schema()

    # -------------------------------------------------------------- loading

    @staticmethod
    def _load_inputs(connection: Any, findings: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
        """Load every verification input for the given findings in bounded queries."""

        finding_ids = [str(row["finding_id"]) for row in findings]
        context: dict[str, dict[str, Any]] = {
            str(row["finding_id"]): {"finding": dict(row), "evidence": [], "work": None, "report": None,
                                     "baseline": None, "snapshot": None, "recorded": False, "conflict": False,
                                     "proofs": [], "at_resolution": None, "after_resolution": None}
            for row in findings
        }
        if not finding_ids:
            return context
        for row in connection.execute(
            text(
                """
                SELECT finding_id, evidence_ref, evidence_type, freshness, observed_at
                FROM finding_evidence
                WHERE finding_id = ANY(:ids)
                ORDER BY finding_id, evidence_type, evidence_ref
                """
            ),
            {"ids": finding_ids},
        ).mappings():
            context[str(row["finding_id"])]["evidence"].append(dict(row))
        work_rows = connection.execute(
            text(
                """
                SELECT work_item_id, finding_id, site_id, work_status
                FROM finding_work_items
                WHERE finding_id = ANY(:ids)
                """
            ),
            {"ids": finding_ids},
        ).mappings().all()
        by_work: dict[str, str] = {}
        for row in work_rows:
            context[str(row["finding_id"])]["work"] = dict(row)
            by_work[str(row["work_item_id"])] = str(row["finding_id"])
        if by_work:
            # The latest transition to `done` is the remediation report.
            for row in connection.execute(
                text(
                    """
                    SELECT DISTINCT ON (work_item_id) work_item_id, revision, occurred_at
                    FROM finding_work_events
                    WHERE work_item_id = ANY(:ids)
                      AND event_type = 'status_changed'
                      AND to_status = 'done'
                    ORDER BY work_item_id, revision DESC
                    """
                ),
                {"ids": list(by_work)},
            ).mappings():
                context[by_work[str(row["work_item_id"])]]["report"] = dict(row)
            pairs = [
                (work_id, int(context[finding_id]["report"]["revision"]))
                for work_id, finding_id in by_work.items()
                if context[finding_id]["report"] is not None
            ]
            if pairs:
                for row in connection.execute(
                    text(
                        """
                        SELECT b.*
                        FROM finding_verification_baselines AS b
                        JOIN unnest(CAST(:work_ids AS TEXT[]), CAST(:revisions AS INTEGER[]))
                             AS wanted(work_item_id, report_revision)
                          ON wanted.work_item_id = b.work_item_id
                         AND wanted.report_revision = b.report_revision
                        """
                    ),
                    {"work_ids": [p[0] for p in pairs], "revisions": [p[1] for p in pairs]},
                ).mappings():
                    context[str(row["finding_id"])]["baseline"] = dict(row)
        # Affirmative evidence recorded for each finding's current resolution.
        resolved = [
            (fid, item["finding"]["resolved_at"])
            for fid, item in context.items()
            if item["finding"]["status"] == "resolved" and item["finding"].get("resolved_at") is not None
        ]
        if resolved:
            for row in connection.execute(
                text(
                    """
                    SELECT e.finding_id, e.resolution_basis, e.evidence_ref, e.evidence_type,
                           e.source, e.observed_at, e.freshness, e.installed_version, e.fixed_version
                    FROM finding_resolution_evidence AS e
                    JOIN unnest(CAST(:finding_ids AS TEXT[]), CAST(:resolved AS TIMESTAMPTZ[]))
                         AS wanted(finding_id, resolved_at)
                      ON wanted.finding_id = e.finding_id
                     AND wanted.resolved_at = e.resolved_at
                    ORDER BY e.finding_id, e.evidence_type, e.evidence_ref
                    """
                ),
                {"finding_ids": [r[0] for r in resolved], "resolved": [r[1] for r in resolved]},
            ).mappings():
                context[str(row["finding_id"])]["proofs"].append(dict(row))
        # Collection completeness for component methods: the newest snapshot
        # since the report, the newest between the report and the resolution,
        # and the newest after the resolution.
        wanted = [
            (
                fid,
                item["finding"]["site_id"],
                item["finding"]["asset_id"],
                item["report"]["occurred_at"],
                item["finding"]["resolved_at"] if item["finding"]["status"] == "resolved" else None,
            )
            for fid, item in context.items()
            if item["report"] is not None
            and item["finding"].get("asset_id") is not None
            and method_for(str(item["finding"]["rule_id"])).collection_check == COMPONENT_COLLECTION_CHECK
        ]
        if wanted:
            for row in connection.execute(
                text(
                    """
                    SELECT wanted.finding_id,
                           EXISTS (
                               SELECT 1 FROM component_source_snapshots AS any_s
                               WHERE any_s.site_id = wanted.site_id AND any_s.asset_id = wanted.asset_id
                           ) AS recorded,
                           later.source_snapshot_id, later.collection_status, later.observed_at,
                           at_res.source_snapshot_id AS at_id, at_res.collection_status AS at_status,
                           at_res.observed_at AS at_observed,
                           after_res.source_snapshot_id AS after_id,
                           after_res.collection_status AS after_status,
                           after_res.observed_at AS after_observed
                    FROM unnest(
                        CAST(:finding_ids AS TEXT[]), CAST(:site_ids AS TEXT[]),
                        CAST(:asset_ids AS TEXT[]), CAST(:reported AS TIMESTAMPTZ[]),
                        CAST(:resolved AS TIMESTAMPTZ[])
                    ) AS wanted(finding_id, site_id, asset_id, reported_at, resolved_at)
                    LEFT JOIN LATERAL (
                        SELECT s.source_snapshot_id, s.collection_status, s.observed_at
                        FROM component_source_snapshots AS s
                        WHERE s.site_id = wanted.site_id AND s.asset_id = wanted.asset_id
                          AND s.observed_at > wanted.reported_at
                        ORDER BY s.observed_at DESC, s.source_snapshot_id
                        LIMIT 1
                    ) AS later ON TRUE
                    LEFT JOIN LATERAL (
                        SELECT s.source_snapshot_id, s.collection_status, s.observed_at
                        FROM component_source_snapshots AS s
                        WHERE s.site_id = wanted.site_id AND s.asset_id = wanted.asset_id
                          AND wanted.resolved_at IS NOT NULL
                          AND s.observed_at > wanted.reported_at
                          AND s.observed_at <= wanted.resolved_at
                        ORDER BY s.observed_at DESC, s.source_snapshot_id
                        LIMIT 1
                    ) AS at_res ON TRUE
                    LEFT JOIN LATERAL (
                        SELECT s.source_snapshot_id, s.collection_status, s.observed_at
                        FROM component_source_snapshots AS s
                        WHERE s.site_id = wanted.site_id AND s.asset_id = wanted.asset_id
                          AND wanted.resolved_at IS NOT NULL
                          AND s.observed_at > wanted.resolved_at
                        ORDER BY s.observed_at DESC, s.source_snapshot_id
                        LIMIT 1
                    ) AS after_res ON TRUE
                    """
                ),
                {
                    "finding_ids": [w[0] for w in wanted],
                    "site_ids": [w[1] for w in wanted],
                    "asset_ids": [w[2] for w in wanted],
                    "reported": [w[3] for w in wanted],
                    "resolved": [w[4] for w in wanted],
                },
            ).mappings():
                item = context[str(row["finding_id"])]
                item["recorded"] = bool(row["recorded"])
                for target, prefix in (("snapshot", ""), ("at_resolution", "at_"), ("after_resolution", "after_")):
                    snapshot_id = row["source_snapshot_id"] if not prefix else row[f"{prefix}id"]
                    if snapshot_id is None:
                        continue
                    item[target] = CollectionSnapshot(
                        snapshot_id=str(snapshot_id),
                        collection_status=str(row["collection_status"] if not prefix else row[f"{prefix}status"]),
                        observed_at=row["observed_at"] if not prefix else row[f"{prefix}observed"],
                    )
        # Identity and classification conflicts current on the same asset.
        assets = sorted(
            {
                (item["finding"]["site_id"], item["finding"]["asset_id"])
                for item in context.values()
                if item["report"] is not None and item["finding"].get("asset_id") is not None
            }
        )
        if assets:
            conflicted = {
                (str(row["site_id"]), str(row["asset_id"]))
                for row in connection.execute(
                    text(
                        """
                        SELECT DISTINCT f.site_id, f.asset_id
                        FROM findings AS f
                        JOIN unnest(CAST(:site_ids AS TEXT[]), CAST(:asset_ids AS TEXT[]))
                             AS wanted(site_id, asset_id)
                          ON wanted.site_id = f.site_id AND wanted.asset_id = f.asset_id
                        WHERE f.rule_id = ANY(:rules) AND f.status <> 'resolved'
                        """
                    ),
                    {
                        "site_ids": [a[0] for a in assets],
                        "asset_ids": [a[1] for a in assets],
                        "rules": sorted(CONFLICT_RULES),
                    },
                ).mappings()
            }
            for item in context.values():
                key = (item["finding"]["site_id"], item["finding"].get("asset_id"))
                item["conflict"] = key in conflicted
        return context

    @staticmethod
    def _input(item: Mapping[str, Any]) -> VerificationInput:
        finding = item["finding"]
        state = FindingState(
            finding_id=str(finding["finding_id"]),
            site_id=str(finding["site_id"]),
            rule_id=str(finding["rule_id"]),
            subject_type=str(finding["subject_type"]),
            status=str(finding["status"]),
            evidence_observed_at=finding["evidence_observed_at"],
            evidence_freshness=str(finding["evidence_freshness"]),
            evaluated_at=finding["evaluated_at"],
            resolved_at=finding["resolved_at"],
            reopen_count=int(finding["reopen_count"]),
            evidence=evidence_from_records(item["evidence"]),
        )
        report = None
        if item["report"] is not None and item["work"] is not None:
            baseline = item["baseline"]
            report = RemediationReport(
                report_revision=int(item["report"]["revision"]),
                reported_at=item["report"]["occurred_at"],
                work_status=str(item["work"]["work_status"]),
                baseline_captured=baseline is not None,
                baseline_reopen_count=int(baseline["finding_reopen_count"]) if baseline else None,
                baseline_evidence=evidence_from_json(baseline["evidence_references"]) if baseline else (),
            )
        return VerificationInput(
            finding=state,
            report=report,
            collection_since_report=item["snapshot"],
            collection_recorded=bool(item["recorded"]),
            identity_conflict_active=bool(item["conflict"]),
            resolution_evidence=proofs_from_records(item["proofs"]),
            collection_at_resolution=item["at_resolution"],
            collection_after_resolution=item["after_resolution"],
        )

    _FINDING_SELECT = """
        SELECT finding_id, site_id, rule_id, subject_type, asset_id, sensor_id,
               title, recommendation, status, evidence_observed_at, evidence_freshness,
               evaluated_at, resolved_at, resolution_basis, reopen_count
        FROM findings
    """

    # ------------------------------------------------------------ reconcile

    def reconcile_verifications(
        self,
        *,
        run_id: str,
        evaluated_at: datetime,
        site_id: str | None,
    ) -> VerificationReconcileResult:
        """Record material verification transitions after a finding evaluation.

        Only findings with a remediation report are recorded. Unchanged
        outcomes write nothing.
        """

        evaluated = transitions = 0
        with self._engine().begin() as connection:
            connection.execute(
                text("SELECT pg_advisory_xact_lock(hashtext('openassetwatch-verification')::bigint)")
            )
            findings = connection.execute(
                text(
                    self._FINDING_SELECT
                    + """
                    WHERE (:site_id IS NULL OR site_id = :site_id)
                      AND finding_id IN (
                          SELECT finding_id FROM finding_work_events
                          WHERE event_type = 'status_changed' AND to_status = 'done'
                      )
                    ORDER BY finding_id
                    LIMIT :limit
                    """
                ),
                {"site_id": site_id, "limit": MAX_VERIFICATION_RECORDS + 1},
            ).mappings().all()
            if len(findings) > MAX_VERIFICATION_RECORDS:
                raise ValueError("verification record limit exceeded")
            context = self._load_inputs(connection, findings)
            reported = {fid: item for fid, item in context.items() if item["report"] is not None and item["work"]}
            latest: dict[tuple[str, int], dict[str, Any]] = {}
            if reported:
                for row in connection.execute(
                    text(
                        """
                        SELECT DISTINCT ON (work_item_id, report_revision)
                               work_item_id, report_revision, sequence, ruleset_version,
                               verification_state, reason_codes
                        FROM finding_verification_history
                        WHERE work_item_id = ANY(:ids)
                        ORDER BY work_item_id, report_revision, sequence DESC
                        """
                    ),
                    {"ids": [item["work"]["work_item_id"] for item in reported.values()]},
                ).mappings():
                    latest[(str(row["work_item_id"]), int(row["report_revision"]))] = dict(row)
            for finding_id, item in reported.items():
                outcome = evaluate_verification(self._input(item))
                evaluated += 1
                key = (str(item["work"]["work_item_id"]), int(item["report"]["revision"]))
                previous = latest.get(key)
                if previous is not None and (
                    previous["ruleset_version"],
                    previous["verification_state"],
                    tuple(previous["reason_codes"] or ()),
                ) == outcome.outcome():
                    continue
                self._append_history(
                    connection,
                    item=item,
                    outcome=outcome,
                    previous=previous,
                    run_id=run_id,
                    at=evaluated_at,
                )
                transitions += 1
        return VerificationReconcileResult(evaluated=evaluated, transitions=transitions)

    @staticmethod
    def _append_history(
        connection: Any,
        *,
        item: Mapping[str, Any],
        outcome: VerificationOutcome,
        previous: Mapping[str, Any] | None,
        run_id: str,
        at: datetime,
    ) -> None:
        # The collection that decided the outcome: at resolution for a resolved
        # finding, otherwise the newest since the report.
        snapshot = item["at_resolution"] if item["finding"]["status"] == "resolved" else item["snapshot"]
        connection.execute(
            text(
                """
                INSERT INTO finding_verification_history (
                    work_item_id, finding_id, site_id, report_revision, sequence,
                    ruleset_version, previous_state, verification_state, reason_codes,
                    after_evidence_references, finding_status, finding_evidence_observed_at,
                    collection_status, input_digest, evaluated_at, evaluation_run_id
                ) VALUES (
                    :work_item_id, :finding_id, :site_id, :report_revision, :sequence,
                    :ruleset_version, :previous_state, :state, CAST(:reasons AS JSONB),
                    CAST(:after AS JSONB), :finding_status, :observed_at,
                    :collection_status, :digest, :at, :run_id
                )
                """
            ),
            {
                "work_item_id": item["work"]["work_item_id"],
                "finding_id": outcome.finding_id,
                "site_id": outcome.site_id,
                "report_revision": int(item["report"]["revision"]),
                "sequence": 1 if previous is None else int(previous["sequence"]) + 1,
                "ruleset_version": outcome.ruleset_version,
                "previous_state": previous["verification_state"] if previous else None,
                "state": outcome.verification_state,
                "reasons": json.dumps(list(outcome.reason_codes)),
                "after": json.dumps(evidence_to_json(outcome.after_evidence_references)),
                "finding_status": item["finding"]["status"],
                "observed_at": item["finding"]["evidence_observed_at"],
                "collection_status": snapshot.collection_status if snapshot else None,
                "digest": outcome.input_digest,
                "at": at,
                "run_id": run_id,
            },
        )

    # ---------------------------------------------------------------- reads

    @staticmethod
    def _guidance(connection: Any, item: Mapping[str, Any]) -> dict[str, Any]:
        finding = item["finding"]
        rule = RULES_BY_ID.get(str(finding["rule_id"]))
        method = method_for(str(finding["rule_id"]))
        components = []
        match_ids = [row["evidence_ref"] for row in item["evidence"] if row["evidence_type"] == "vulnerability-match"]
        if match_ids:
            components = [
                {
                    "match_id": row["match_id"],
                    "match_status": row["match_status"],
                    "installed_version": row["installed_version"],
                    "fixed_version": row["fixed_version"],
                }
                for row in connection.execute(
                    text(
                        """
                        SELECT match_id, match_status, installed_version, fixed_version
                        FROM vulnerability_matches
                        WHERE match_id = ANY(:ids) AND site_id = :site_id
                        ORDER BY match_id
                        """
                    ),
                    {"ids": match_ids, "site_id": finding["site_id"]},
                ).mappings()
            ]
        return {
            "condition": str(finding["title"]),
            "recommendation": str(finding["recommendation"]),
            "method_id": method.method_id,
            "automated": method.automated,
            "evidence_source": method.evidence_source,
            "comparable_evidence": method.comparable_evidence,
            "collection_check": method.collection_check,
            "required_evidence": list(rule.required_evidence) if rule else [],
            "resolution_behavior": rule.resolution_behavior if rule else None,
            "components": components,
        }

    @staticmethod
    def _collection(snapshot: CollectionSnapshot | None) -> dict[str, Any] | None:
        if snapshot is None:
            return None
        return {
            "snapshot_id": snapshot.snapshot_id,
            "collection_status": snapshot.collection_status,
            "observed_at": snapshot.observed_at,
        }

    def _project(self, connection: Any, item: Mapping[str, Any], *, with_guidance: bool) -> dict[str, Any]:
        outcome = evaluate_verification(self._input(item))
        finding = item["finding"]
        baseline = item["baseline"]
        report = item["report"]
        work = item["work"]
        snapshot = item["snapshot"]
        result: dict[str, Any] = {
            "schema_version": outcome.schema_version,
            "ruleset_version": outcome.ruleset_version,
            "finding_id": outcome.finding_id,
            "site_id": outcome.site_id,
            "asset_id": finding.get("asset_id"),
            "sensor_id": finding.get("sensor_id"),
            "finding_rule_id": outcome.finding_rule_id,
            "finding_status": finding["status"],
            "finding_resolved_at": finding["resolved_at"],
            "finding_evidence_observed_at": finding["evidence_observed_at"],
            "finding_evidence_freshness": finding["evidence_freshness"],
            "verification_state": outcome.verification_state,
            "verified": outcome.verification_state == "verified",
            "method_id": outcome.method_id,
            "automated": outcome.automated,
            "collection_completeness": outcome.collection_completeness,
            "collection_since_report": None
            if snapshot is None
            else {
                "snapshot_id": snapshot.snapshot_id,
                "collection_status": snapshot.collection_status,
                "observed_at": snapshot.observed_at,
            },
            "reason_codes": list(outcome.reason_codes),
            "reasons": [
                {"code": code, "explanation": REASON_CODE_EXPLANATIONS[code]} for code in outcome.reason_codes
            ],
            "work_item_id": work["work_item_id"] if work else None,
            "work_status": work["work_status"] if work else None,
            "report_revision": int(report["revision"]) if report else None,
            "reported_at": report["occurred_at"] if report else None,
            "before_evidence_references": evidence_to_json(evidence_from_json(baseline["evidence_references"]))
            if baseline
            else [],
            "before_collection": None
            if not baseline or baseline["collection_snapshot_id"] is None
            else {
                "snapshot_id": baseline["collection_snapshot_id"],
                "collection_status": baseline["collection_status"],
                "observed_at": baseline["collection_observed_at"],
            },
            "after_evidence_references": evidence_to_json(outcome.after_evidence_references),
            "resolution_evidence": [
                {
                    "resolution_basis": proof["resolution_basis"],
                    "technical": proof["resolution_basis"] in TECHNICAL_RESOLUTION_BASES,
                    "evidence_ref": proof["evidence_ref"],
                    "evidence_type": proof["evidence_type"],
                    "source": proof["source"],
                    "observed_at": proof["observed_at"],
                    "freshness": proof["freshness"],
                    "installed_version": proof["installed_version"],
                    "fixed_version": proof["fixed_version"],
                }
                for proof in item["proofs"][:MAX_VERIFICATION_EVIDENCE_REFERENCES]
            ],
            "collection_at_resolution": self._collection(item["at_resolution"]),
            "collection_after_resolution": self._collection(item["after_resolution"]),
            "input_digest": outcome.input_digest,
        }
        if with_guidance:
            result["guidance"] = self._guidance(connection, item)
        return result

    def get_verification(self, finding_id: str) -> dict[str, Any] | None:
        self.ensure_schema()
        with self._engine().begin() as connection:
            row = connection.execute(
                text(self._FINDING_SELECT + " WHERE finding_id = :finding_id"),
                {"finding_id": finding_id},
            ).mappings().first()
            if row is None:
                return None
            item = self._load_inputs(connection, [row])[finding_id]
            result = self._project(connection, item, with_guidance=True)
            recorded = None
            if item["work"] is not None and item["report"] is not None:
                recorded = connection.execute(
                    text(
                        """
                        SELECT verification_state, reason_codes, evaluated_at, sequence
                        FROM finding_verification_history
                        WHERE work_item_id = :work_item_id AND report_revision = :revision
                        ORDER BY sequence DESC
                        LIMIT 1
                        """
                    ),
                    {"work_item_id": item["work"]["work_item_id"], "revision": int(item["report"]["revision"])},
                ).mappings().first()
            result["last_recorded"] = (
                None
                if recorded is None
                else {
                    "verification_state": recorded["verification_state"],
                    "reason_codes": list(recorded["reason_codes"] or ()),
                    "evaluated_at": recorded["evaluated_at"],
                    "sequence": int(recorded["sequence"]),
                }
            )
            # `current`: the last recorded outcome is what the rules give now.
            # `stale`: inputs changed and no evaluation has recorded it yet.
            result["record_state"] = (
                "not-recorded"
                if recorded is None
                else "current"
                if recorded["verification_state"] == result["verification_state"]
                and list(recorded["reason_codes"] or ()) == result["reason_codes"]
                else "stale"
            )
            return result

    def list_unverified(
        self,
        *,
        site_id: str | None = None,
        verification_state: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Work marked done whose finding is not verified."""

        self.ensure_schema()
        if verification_state is not None and verification_state not in UNVERIFIED_STATES:
            raise ValueError("invalid unverified verification state")
        bounded_limit, bounded_offset = _bounded_page(limit, offset)
        with self._engine().begin() as connection:
            rows = connection.execute(
                text(
                    self._FINDING_SELECT
                    + """
                    WHERE finding_id IN (
                        SELECT finding_id FROM finding_work_items
                        WHERE work_status = 'done'
                          AND (:site_id IS NULL OR site_id = :site_id)
                    )
                    ORDER BY finding_id
                    LIMIT :limit
                    """
                ),
                {"site_id": site_id, "limit": MAX_VERIFICATION_RECORDS + 1},
            ).mappings().all()
            if len(rows) > MAX_VERIFICATION_RECORDS:
                raise ValueError("verification record limit exceeded")
            context = self._load_inputs(connection, rows)
            matching = []
            for item in context.values():
                projected = self._project(connection, item, with_guidance=False)
                if projected["verification_state"] not in UNVERIFIED_STATES:
                    continue
                if verification_state is not None and projected["verification_state"] != verification_state:
                    continue
                matching.append(projected)
        matching.sort(key=lambda entry: (str(entry["reported_at"]), entry["finding_id"]))
        page = matching[bounded_offset : bounded_offset + bounded_limit]
        return {
            "items": page,
            "total": len(matching),
            "limit": bounded_limit,
            "offset": bounded_offset,
            "truncated": bounded_offset + len(page) < len(matching),
        }

    def list_history(self, finding_id: str, *, limit: int = 50, offset: int = 0) -> dict[str, Any] | None:
        self.ensure_schema()
        bounded_limit, bounded_offset = _bounded_page(limit, offset)
        with self._engine().begin() as connection:
            exists = connection.execute(
                text("SELECT 1 FROM findings WHERE finding_id = :finding_id"),
                {"finding_id": finding_id},
            ).first()
            if exists is None:
                return None
            total = int(
                connection.execute(
                    text("SELECT COUNT(*) FROM finding_verification_history WHERE finding_id = :finding_id"),
                    {"finding_id": finding_id},
                ).scalar_one()
            )
            rows = connection.execute(
                text(
                    """
                    SELECT h.work_item_id, h.finding_id, h.site_id, h.report_revision, h.sequence,
                           h.ruleset_version, h.previous_state, h.verification_state, h.reason_codes,
                           h.after_evidence_references, h.finding_status,
                           h.finding_evidence_observed_at, h.collection_status, h.input_digest,
                           h.evaluated_at, h.evaluation_run_id
                    FROM finding_verification_history AS h
                    WHERE h.finding_id = :finding_id
                    ORDER BY h.report_revision, h.sequence
                    LIMIT :limit OFFSET :offset
                    """
                ),
                {"finding_id": finding_id, "limit": bounded_limit, "offset": bounded_offset},
            ).mappings().all()
        items = []
        for row in rows:
            item = dict(row)
            item["reason_codes"] = list(item["reason_codes"] or ())
            item["after_evidence_references"] = evidence_to_json(
                evidence_from_json(item["after_evidence_references"])
            )
            items.append(item)
        return {
            "items": items,
            "total": total,
            "limit": bounded_limit,
            "offset": bounded_offset,
            "truncated": bounded_offset + len(items) < total,
        }


__all__ = [
    "SqlVerificationStore",
    "VerificationReconcileResult",
    "capture_baseline",
    "VERIFICATION_RULESET_VERSION",
    "VERIFICATION_STATES",
]
