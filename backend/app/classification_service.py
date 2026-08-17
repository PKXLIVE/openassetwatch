"""Application service for targeted deterministic classification evaluation."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from .classification import CLASSIFIER_VERSION, ClassificationEvidence, classify_asset
from .classification_store import InMemoryClassificationStore, SqlClassificationStore


LOGGER = logging.getLogger(__name__)
MAX_CLASSIFICATION_ASSETS = 50_000
MAX_TARGETED_ASSETS = 500
EVIDENCE_LOAD_BATCH_SIZE = 500
MAX_SITE_REEVALUATIONS = 100


@dataclass(frozen=True)
class ClassificationEvaluationResult:
    run_id: str
    trigger_type: str
    scope_site_id: str | None
    scope_asset_ids: tuple[str, ...]
    classifier_version: str
    status: str
    assets_evaluated: int
    assets_changed: int
    conflicts_found: int
    finding_evaluations: int
    started_at: datetime
    completed_at: datetime
    bounded_errors: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["scope_asset_ids"] = list(self.scope_asset_ids)
        result["bounded_errors"] = list(self.bounded_errors)
        return result


def _load_assets(
    *,
    site_id: str | None,
    asset_ids: Sequence[str],
) -> list[dict[str, Any]]:
    from .database import list_control_tower_assets

    unique_asset_ids = list(dict.fromkeys(asset_ids))
    assets = list_control_tower_assets(
        limit=(
            min(len(unique_asset_ids), MAX_TARGETED_ASSETS) + 1
            if unique_asset_ids
            else MAX_CLASSIFICATION_ASSETS + 1
        ),
        site_id=site_id,
        asset_ids=unique_asset_ids if unique_asset_ids else None,
    )
    if len(assets) > MAX_CLASSIFICATION_ASSETS:
        raise ValueError("deterministic classification asset limit exceeded")
    selected = set(unique_asset_ids)
    if selected:
        assets = [asset for asset in assets if str(asset.get("asset_id")) in selected]
    return assets


def _load_evidence(
    *,
    store: SqlClassificationStore | InMemoryClassificationStore,
    assets: Sequence[Mapping[str, Any]],
) -> dict[tuple[str, str], list[ClassificationEvidence]]:
    grouped: dict[tuple[str, str], list[ClassificationEvidence]] = {}
    by_site: dict[str, list[str]] = {}
    for asset in assets:
        site_id = str(asset.get("site_id") or "")
        asset_id = str(asset.get("asset_id") or "")
        if site_id and asset_id:
            by_site.setdefault(site_id, []).append(asset_id)
    for site_id, asset_ids in by_site.items():
        unique_asset_ids = list(dict.fromkeys(asset_ids))
        for start in range(0, len(unique_asset_ids), EVIDENCE_LOAD_BATCH_SIZE):
            batch = unique_asset_ids[start : start + EVIDENCE_LOAD_BATCH_SIZE]
            for asset_id, evidence in store.load_evidence(
                site_id=site_id,
                asset_ids=batch,
            ).items():
                grouped[(site_id, asset_id)] = evidence
    return grouped


def _reevaluate_findings(
    *,
    changed_assets: Sequence[tuple[str, str]],
    trigger_type: str,
    requested_by: str | None,
) -> tuple[int, list[str]]:
    from .finding_service import evaluate_findings

    count = 0
    errors: list[str] = []
    unique_assets = list(dict.fromkeys(changed_assets))
    if len(unique_assets) == 1:
        scopes: list[tuple[str | None, str | None]] = [unique_assets[0]]
    else:
        site_ids = sorted({site_id for site_id, _asset_id in unique_assets})
        scopes = (
            [(None, None)]
            if len(site_ids) > MAX_SITE_REEVALUATIONS
            else [(site_id, None) for site_id in site_ids]
        )
    for site_id, asset_id in scopes:
        try:
            evaluate_findings(
                trigger_type=f"classification:{trigger_type}"[:64],
                requested_by=requested_by or "classification-engine",
                site_id=site_id,
                asset_id=asset_id,
            )
            count += 1
        except Exception as exc:  # noqa: BLE001 - classification remains authoritative.
            code = f"finding-reevaluation:{type(exc).__name__}"[:80]
            if code not in errors:
                errors.append(code)
            LOGGER.warning(
                "post-classification finding evaluation failed safely: %s",
                type(exc).__name__,
            )
    return count, errors[:20]


def evaluate_classifications(
    *,
    trigger_type: str,
    requested_by: str | None = None,
    site_id: str | None = None,
    asset_id: str | None = None,
    asset_ids: Sequence[str] | None = None,
    now: datetime | None = None,
    store: SqlClassificationStore | InMemoryClassificationStore | None = None,
    assets: Sequence[Mapping[str, Any]] | None = None,
    evidence_by_asset: Mapping[tuple[str, str], Sequence[ClassificationEvidence]]
    | None = None,
    reevaluate_findings: bool = True,
) -> ClassificationEvaluationResult:
    if asset_id and asset_ids:
        raise ValueError("asset_id and asset_ids are mutually exclusive")
    requested_asset_ids = tuple(
        dict.fromkeys(([asset_id] if asset_id else list(asset_ids or [])))
    )
    if requested_asset_ids and not site_id:
        raise ValueError("asset-scoped classification requires site_id")
    if len(requested_asset_ids) > MAX_TARGETED_ASSETS:
        raise ValueError("targeted classification asset limit exceeded")
    started_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    resolved_store = store or SqlClassificationStore()
    run_id = resolved_store.begin_run(
        trigger_type=trigger_type,
        requested_by=requested_by,
        site_id=site_id,
        asset_ids=requested_asset_ids,
        started_at=started_at,
    )
    try:
        loaded_assets = (
            [dict(asset) for asset in assets]
            if assets is not None
            else _load_assets(site_id=site_id, asset_ids=requested_asset_ids)
        )
        if len(loaded_assets) > MAX_CLASSIFICATION_ASSETS:
            raise ValueError("deterministic classification asset limit exceeded")
        if requested_asset_ids:
            requested = set(requested_asset_ids)
            loaded_assets = [
                asset
                for asset in loaded_assets
                if str(asset.get("asset_id") or "") in requested
            ]
        loaded_evidence = (
            {
                key: list(values)
                for key, values in evidence_by_asset.items()
            }
            if evidence_by_asset is not None
            else _load_evidence(store=resolved_store, assets=loaded_assets)
        )
        changed_assets: list[tuple[str, str]] = []
        conflict_count = 0
        for asset in loaded_assets:
            resolved_site_id = str(asset.get("site_id") or "")
            resolved_asset_id = str(asset.get("asset_id") or "")
            if not resolved_site_id or not resolved_asset_id:
                continue
            previous = resolved_store.current(
                site_id=resolved_site_id,
                asset_id=resolved_asset_id,
            )
            classification = classify_asset(
                site_id=resolved_site_id,
                asset_id=resolved_asset_id,
                evidence=loaded_evidence.get(
                    (resolved_site_id, resolved_asset_id),
                    [],
                ),
                now=started_at,
                previous=previous,
            )
            reconciliation = resolved_store.reconcile(
                run_id=run_id,
                result=classification,
            )
            if reconciliation.changed:
                changed_assets.append((resolved_site_id, resolved_asset_id))
            conflict_count += reconciliation.conflict_count
        finding_evaluations = 0
        bounded_errors: list[str] = []
        if reevaluate_findings and changed_assets:
            finding_evaluations, bounded_errors = _reevaluate_findings(
                changed_assets=changed_assets,
                trigger_type=trigger_type,
                requested_by=requested_by,
            )
        completed_at = datetime.now(timezone.utc)
        resolved_store.complete_run(
            run_id,
            completed_at=completed_at,
            assets_evaluated=len(loaded_assets),
            assets_changed=len(changed_assets),
            conflicts_found=conflict_count,
            finding_evaluations=finding_evaluations,
            bounded_errors=bounded_errors,
        )
        return ClassificationEvaluationResult(
            run_id=run_id,
            trigger_type=trigger_type,
            scope_site_id=site_id,
            scope_asset_ids=requested_asset_ids,
            classifier_version=CLASSIFIER_VERSION,
            status="completed",
            assets_evaluated=len(loaded_assets),
            assets_changed=len(changed_assets),
            conflicts_found=conflict_count,
            finding_evaluations=finding_evaluations,
            started_at=started_at,
            completed_at=completed_at,
            bounded_errors=tuple(bounded_errors),
        )
    except Exception as exc:
        try:
            resolved_store.fail_run(
                run_id,
                completed_at=datetime.now(timezone.utc),
                error_code=type(exc).__name__,
            )
        except Exception as record_exc:  # noqa: BLE001 - preserve original failure.
            LOGGER.warning(
                "failed to record classification evaluation failure safely: %s",
                type(record_exc).__name__,
            )
        raise


def evaluate_assets_best_effort(
    *,
    site_id: str,
    asset_ids: Sequence[str],
    trigger_type: str = "evidence-ingestion",
    requested_by: str = "control-tower",
) -> None:
    """Best-effort targeted evaluation that never invalidates accepted ingestion."""

    try:
        evaluate_classifications(
            trigger_type=trigger_type,
            requested_by=requested_by,
            site_id=site_id,
            asset_ids=list(dict.fromkeys(asset_ids))[:MAX_TARGETED_ASSETS],
        )
    except Exception as exc:  # noqa: BLE001 - accepted evidence remains accepted.
        LOGGER.warning(
            "post-ingestion deterministic classification failed safely: %s",
            type(exc).__name__,
        )
