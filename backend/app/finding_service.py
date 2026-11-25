"""Application service for deterministic finding and risk evaluations."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Sequence

from .decision_store import DecisionReconcileResult, SqlDecisionStore
from .finding_store import InMemoryFindingStore, ReconcileResult, SqlFindingStore
from .findings import RULESET_VERSION, EvaluationSnapshot, FindingsConfig, evaluate_rules
from .risk import RiskConfig, calculate_risk
from .verification_store import SqlVerificationStore, VerificationReconcileResult


LOGGER = logging.getLogger(__name__)
MAX_EVALUATION_ASSETS = 50_000
MAX_EVALUATION_SITES = 10_000
MAX_EVALUATION_SENSORS = 20_000


@dataclass(frozen=True)
class EvaluationResult:
    run_id: str
    trigger_type: str
    scope_site_id: str | None
    scope_asset_id: str | None
    scope_sensor_id: str | None
    ruleset_version: str
    evaluated_rule_ids: tuple[str, ...]
    candidate_count: int
    opened_count: int
    updated_count: int
    reopened_count: int
    resolved_count: int
    asset_risk_count: int
    site_risk_count: int
    data_as_of: datetime | None
    started_at: datetime
    completed_at: datetime
    decision_evaluated_count: int = 0
    decision_transition_count: int = 0
    verification_evaluated_count: int = 0
    verification_transition_count: int = 0
    # completed | incomplete | failed | not-run. Verification never fails the
    # evaluation; its outcome is reported here and in finding_verification_runs.
    verification_status: str = "not-run"
    verification_error_code: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _load_inputs(
    *,
    site_id: str | None,
    include_vulnerability_matches: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    from .database import list_agent_enrollments, list_control_tower_assets, list_sites

    sites = list_sites(limit=MAX_EVALUATION_SITES + 1, site_id=site_id)
    sensors = list_agent_enrollments(
        limit=MAX_EVALUATION_SENSORS + 1,
        site_id=site_id,
    )
    assets = list_control_tower_assets(
        limit=MAX_EVALUATION_ASSETS + 1,
        site_id=site_id,
    )
    if len(sites) > MAX_EVALUATION_SITES:
        raise ValueError("deterministic evaluation site limit exceeded")
    if len(sensors) > MAX_EVALUATION_SENSORS:
        raise ValueError("deterministic evaluation sensor limit exceeded")
    if len(assets) > MAX_EVALUATION_ASSETS:
        raise ValueError("deterministic evaluation asset limit exceeded")
    vulnerability_matches: list[dict[str, Any]] = []
    if include_vulnerability_matches:
        from .vulnerability_store import SqlVulnerabilityStore

        vulnerability_matches = SqlVulnerabilityStore().active_match_snapshot(
            site_id=site_id,
        )
    matches_by_asset: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for match in vulnerability_matches:
        matches_by_asset.setdefault(
            (str(match.get("site_id") or ""), str(match.get("asset_id") or "")),
            [],
        ).append(match)
    for asset in assets:
        asset["vulnerability_matches"] = matches_by_asset.get(
            (str(asset.get("site_id") or ""), str(asset.get("asset_id") or "")),
            [],
        )
    return sites, sensors, assets


def evaluate_findings(
    *,
    trigger_type: str,
    requested_by: str | None = None,
    site_id: str | None = None,
    asset_id: str | None = None,
    sensor_id: str | None = None,
    rule_ids: Sequence[str] | None = None,
    now: datetime | None = None,
    findings_config: FindingsConfig | None = None,
    risk_config: RiskConfig | None = None,
    store: SqlFindingStore | InMemoryFindingStore | None = None,
    decision_store: SqlDecisionStore | None = None,
    verification_store: SqlVerificationStore | None = None,
    sites: Sequence[dict[str, Any]] | None = None,
    sensors: Sequence[dict[str, Any]] | None = None,
    assets: Sequence[dict[str, Any]] | None = None,
) -> EvaluationResult:
    if asset_id and not site_id:
        raise ValueError("asset-scoped evaluation requires site_id")
    if sensor_id and not site_id:
        raise ValueError("sensor-scoped evaluation requires site_id")
    if asset_id and sensor_id:
        raise ValueError("asset_id and sensor_id scopes are mutually exclusive")
    if sensor_id:
        if rule_ids is None:
            rule_ids = ("sensor-stale",)
        elif set(rule_ids) - {"sensor-stale"}:
            raise ValueError("sensor-scoped evaluation supports only sensor-stale")
    started_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    # Decisions are recomputed in production evaluations. A caller that injects
    # its own finding store (tests, in-memory demos) opts in explicitly.
    resolved_decision_store = decision_store or (SqlDecisionStore() if store is None else None)
    resolved_verification_store = verification_store or (SqlVerificationStore() if store is None else None)
    resolved_store = store or SqlFindingStore()
    run_id = resolved_store.begin_run(
        trigger_type=trigger_type,
        requested_by=requested_by,
        site_id=site_id,
        asset_id=asset_id,
        sensor_id=sensor_id,
        ruleset_version=RULESET_VERSION,
        started_at=started_at,
    )
    try:
        if sites is None or sensors is None or assets is None:
            vulnerability_rule_ids = {
                "vulnerable-component",
                "component-version-unavailable",
                "advisory-identity-uncertain",
            }
            loaded_sites, loaded_sensors, loaded_assets = _load_inputs(
                site_id=site_id,
                include_vulnerability_matches=(
                    rule_ids is None
                    or bool(set(rule_ids) & vulnerability_rule_ids)
                ),
            )
            sites = loaded_sites if sites is None else sites
            sensors = loaded_sensors if sensors is None else sensors
            assets = loaded_assets if assets is None else assets
        snapshot: EvaluationSnapshot = evaluate_rules(
            sites=sites,
            sensors=sensors,
            assets=assets,
            now=started_at,
            config=findings_config,
            rule_ids=rule_ids,
            site_id=site_id,
            asset_id=asset_id,
            sensor_id=sensor_id,
        )
        lifecycle: ReconcileResult = resolved_store.reconcile(
            run_id=run_id,
            snapshot=snapshot,
            evaluated_at=started_at,
            site_id=site_id,
            asset_id=asset_id,
            sensor_id=sensor_id,
        )
        risk_sites = [dict(item) for item in sites if not site_id or item.get("site_id") == site_id]
        risk_assets = [dict(item) for item in assets if not site_id or item.get("site_id") == site_id]
        active_findings = resolved_store.active_findings(site_id=site_id)
        asset_scores, site_scores = calculate_risk(
            sites=risk_sites,
            assets=risk_assets,
            findings=active_findings,
            config=risk_config,
        )
        completed_at = datetime.now(timezone.utc)
        resolved_store.replace_risk(
            run_id=run_id,
            asset_scores=asset_scores,
            site_scores=site_scores,
            calculated_at=completed_at,
            snapshot_at=started_at,
            site_id=site_id,
        )
        # The decision layer runs after findings and the Operational Attention
        # Score are settled, inside the same evaluation run. It reads only
        # findings and finding evidence; work tracking never reaches it.
        decisions = (
            resolved_decision_store.reconcile_decisions(
                run_id=run_id,
                evaluated_at=started_at,
                site_id=site_id,
            )
            if resolved_decision_store is not None
            else DecisionReconcileResult(evaluated=0, changed=0, transitions=0)
        )
        # Verification history is recorded last, as a downstream read model of
        # the settled findings. Nothing it computes flows back into findings,
        # risk, or decisions, and it cannot resolve a finding. It runs in its
        # own transaction: a failure is recorded as a failed verification run
        # and never turns the settled evaluation into a failed one.
        verifications = _reconcile_verifications(
            resolved_verification_store,
            run_id=run_id,
            evaluated_at=started_at,
            site_id=site_id,
            asset_id=asset_id,
            sensor_id=sensor_id,
        )
        resolved_store.complete_run(
            run_id,
            snapshot=snapshot,
            result=lifecycle,
            completed_at=completed_at,
        )
        return EvaluationResult(
            run_id=run_id,
            trigger_type=trigger_type,
            scope_site_id=site_id,
            scope_asset_id=asset_id,
            scope_sensor_id=sensor_id,
            ruleset_version=RULESET_VERSION,
            evaluated_rule_ids=snapshot.evaluated_rule_ids,
            candidate_count=len(snapshot.candidates),
            opened_count=lifecycle.opened,
            updated_count=lifecycle.updated,
            reopened_count=lifecycle.reopened,
            resolved_count=lifecycle.resolved,
            asset_risk_count=len(asset_scores),
            site_risk_count=len(site_scores),
            data_as_of=snapshot.data_as_of,
            started_at=started_at,
            completed_at=completed_at,
            decision_evaluated_count=decisions.evaluated,
            decision_transition_count=decisions.transitions,
            verification_evaluated_count=verifications.evaluated,
            verification_transition_count=verifications.transitions,
            verification_status=verifications.status,
            verification_error_code=verifications.error_code,
        )
    except Exception as exc:
        try:
            resolved_store.fail_run(
                run_id,
                completed_at=datetime.now(timezone.utc),
                error_code=type(exc).__name__,
            )
        except Exception as record_exc:  # noqa: BLE001 - preserve the original error.
            LOGGER.warning(
                "failed to record deterministic evaluation failure safely: %s",
                type(record_exc).__name__,
            )
        raise


def _reconcile_verifications(
    store: SqlVerificationStore | None,
    *,
    run_id: str,
    evaluated_at: datetime,
    site_id: str | None,
    asset_id: str | None,
    sensor_id: str | None,
) -> VerificationReconcileResult:
    if store is None:
        return VerificationReconcileResult(evaluated=0, transitions=0, status="not-run")
    scope = {"site_id": site_id, "asset_id": asset_id, "sensor_id": sensor_id}
    try:
        return store.reconcile_verifications(run_id=run_id, evaluated_at=evaluated_at, **scope)
    except Exception as exc:  # noqa: BLE001 - core evaluation results are already settled.
        error_code = type(exc).__name__
        LOGGER.warning("verification reconcile failed safely: %s", error_code)
        try:
            return store.record_failed_run(run_id=run_id, error_code=error_code, at=evaluated_at, **scope)
        except Exception as record_exc:  # noqa: BLE001 - keep the failure visible in the result.
            LOGGER.warning("failed to record verification failure safely: %s", type(record_exc).__name__)
            return VerificationReconcileResult(evaluated=0, transitions=0, status="failed", error_code=error_code)


def evaluate_site_best_effort(
    *,
    site_id: str,
    trigger_type: str = "evidence-ingestion",
    requested_by: str = "control-tower",
    sensor_id: str | None = None,
) -> None:
    """Best-effort site evaluation that never fails its calling operation."""

    try:
        evaluate_findings(
            trigger_type=trigger_type,
            requested_by=requested_by,
            site_id=site_id,
            sensor_id=sensor_id,
        )
    except Exception as exc:  # noqa: BLE001 - ingestion must remain independent.
        LOGGER.warning(
            "post-ingestion deterministic finding evaluation failed safely: %s",
            type(exc).__name__,
        )
