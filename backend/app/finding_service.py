"""Application service for deterministic finding and risk evaluations."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Sequence

from .finding_store import InMemoryFindingStore, ReconcileResult, SqlFindingStore
from .findings import RULESET_VERSION, EvaluationSnapshot, FindingsConfig, evaluate_rules
from .risk import RiskConfig, calculate_risk


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

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _load_inputs(
    *,
    site_id: str | None,
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
            loaded_sites, loaded_sensors, loaded_assets = _load_inputs(site_id=site_id)
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
