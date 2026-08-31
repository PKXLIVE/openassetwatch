"""Durable normalized component inventory and history."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Sequence

from sqlalchemy import bindparam, text

from .component_intelligence import (
    MAX_COMPONENTS_PER_ASSET,
    ComponentSourceSnapshot,
    NormalizedComponent,
)


MAX_COMPONENT_PAGE = 200
MAX_COMPONENT_OFFSET = 10_000
MAX_COMPONENT_EVIDENCE_ROWS = 256
_COMPONENT_FRESHNESS_SQL = """
CASE
    WHEN ac.last_seen_at >= NOW() - INTERVAL '72 hours' THEN 'fresh'
    WHEN ac.last_seen_at >= NOW() - INTERVAL '720 hours' THEN 'aging'
    ELSE 'stale'
END
"""
_SOURCE_TRUST = {
    "untrusted-ingestion": 0,
    "passive-network-sensor": 1,
    "connector": 1,
    "reviewed-connector": 2,
    "endpoint-collector": 3,
}

COMPONENT_SCHEMA_SQL = (
    """
    CREATE TABLE IF NOT EXISTS asset_components (
        component_id TEXT PRIMARY KEY,
        asset_id TEXT NOT NULL,
        site_id TEXT NOT NULL REFERENCES sites(site_id),
        component_type TEXT NOT NULL,
        ecosystem TEXT NOT NULL,
        namespace TEXT,
        vendor TEXT,
        name TEXT NOT NULL,
        normalized_name TEXT NOT NULL,
        version TEXT,
        normalized_version TEXT,
        architecture TEXT,
        package_manager TEXT,
        canonical_identifier TEXT,
        cpe_hint TEXT,
        install_scope TEXT NOT NULL,
        source_type TEXT NOT NULL,
        source_id TEXT NOT NULL,
        firmware_evidence_type TEXT NOT NULL,
        first_seen_at TIMESTAMPTZ NOT NULL,
        last_seen_at TIMESTAMPTZ NOT NULL,
        observed_at TIMESTAMPTZ NOT NULL,
        freshness TEXT NOT NULL,
        confidence DOUBLE PRECISION NOT NULL,
        normalization_status TEXT NOT NULL,
        active BOOLEAN NOT NULL DEFAULT TRUE,
        not_observed_at TIMESTAMPTZ,
        metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        model_version TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (site_id, asset_id, canonical_identifier, architecture, install_scope),
        FOREIGN KEY (site_id, asset_id)
            REFERENCES control_tower_assets(site_id, asset_id) ON DELETE CASCADE,
        CHECK (confidence >= 0.0 AND confidence <= 1.0),
        CHECK (freshness IN ('fresh', 'aging', 'stale', 'unknown')),
        CHECK (firmware_evidence_type IN (
            'direct', 'vendor-reported', 'collector-reported', 'inferred', 'unknown'
        )),
        CHECK (normalization_status IN (
            'normalized', 'identity-uncertain', 'version-unknown',
            'unsupported-ecosystem', 'insufficient-firmware-evidence'
        ))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS asset_component_history (
        history_id BIGSERIAL PRIMARY KEY,
        component_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        asset_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        previous_version TEXT,
        current_version TEXT,
        snapshot_json JSONB NOT NULL,
        observed_at TIMESTAMPTZ NOT NULL,
        recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CHECK (event_type IN (
            'first-observed', 'version-changed', 'source-changed',
            'confidence-changed', 'normalization-changed',
            'not-observed', 'observed-again'
        ))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS component_evidence (
        component_id TEXT NOT NULL
            REFERENCES asset_components(component_id) ON DELETE CASCADE,
        evidence_id TEXT NOT NULL,
        source_id TEXT NOT NULL,
        source_type TEXT NOT NULL,
        observed_at TIMESTAMPTZ NOT NULL,
        first_seen_at TIMESTAMPTZ NOT NULL,
        last_seen_at TIMESTAMPTZ NOT NULL,
        observation_count INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (component_id, evidence_id),
        CHECK (observation_count >= 1)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_asset_components_asset ON asset_components (site_id, asset_id, active, last_seen_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_asset_components_identity ON asset_components (ecosystem, canonical_identifier, active) WHERE canonical_identifier IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS idx_asset_components_name ON asset_components (ecosystem, normalized_name, vendor)",
    "CREATE INDEX IF NOT EXISTS idx_asset_components_type ON asset_components (component_type, active, last_seen_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_asset_components_source ON asset_components (source_type, source_id, last_seen_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_asset_component_history_component ON asset_component_history (component_id, observed_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_component_evidence_component ON component_evidence (component_id, last_seen_at DESC)",
)


def ensure_component_schema(connection: Any) -> None:
    """Temporary compatibility seam; versioned migrations own durable DDL."""

    from .schema_migrations import ensure_schema_ready

    ensure_schema_ready(connection.engine)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, default=str)


def _json_value(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return default


def _history_event(
    previous: dict[str, Any] | None,
    component: NormalizedComponent,
) -> str | None:
    if previous is None:
        return "first-observed"
    if not previous.get("active", True):
        return "observed-again"
    if previous.get("normalized_version") != component.normalized_version:
        return "version-changed"
    if (
        previous.get("source_type"),
        previous.get("source_id"),
    ) != (component.source_type, component.source_id):
        return "source-changed"
    if float(previous.get("confidence") or 0.0) != component.confidence:
        return "confidence-changed"
    if previous.get("normalization_status") != component.normalization_status:
        return "normalization-changed"
    return None


def _should_replace_component(
    previous: dict[str, Any] | None,
    component: NormalizedComponent,
) -> bool:
    if previous is None:
        return True
    boundary = previous.get("observed_at")
    not_observed_at = previous.get("not_observed_at")
    if isinstance(not_observed_at, datetime) and (
        not isinstance(boundary, datetime) or not_observed_at > boundary
    ):
        boundary = not_observed_at
    if isinstance(boundary, datetime):
        if component.observed_at < boundary:
            return False
        if component.observed_at > boundary:
            return _SOURCE_TRUST.get(component.source_type, 0) >= _SOURCE_TRUST.get(
                str(previous.get("source_type") or ""),
                0,
            )
    previous_key = (
        _SOURCE_TRUST.get(str(previous.get("source_type") or ""), 0),
        float(previous.get("confidence") or 0.0),
        str(previous.get("source_type") or ""),
        str(previous.get("source_id") or ""),
        str(previous.get("normalized_version") or ""),
    )
    component_key = (
        _SOURCE_TRUST.get(component.source_type, 0),
        component.confidence,
        component.source_type,
        component.source_id,
        component.normalized_version or "",
    )
    return component_key >= previous_key


def _prune_component_rows(connection: Any, *, component_id: str) -> None:
    connection.execute(
        text(
            """
            DELETE FROM component_evidence
            WHERE component_id = :component_id
              AND evidence_id IN (
                SELECT evidence_id
                FROM component_evidence
                WHERE component_id = :component_id
                ORDER BY last_seen_at DESC, evidence_id
                OFFSET :keep
              )
            """
        ),
        {"component_id": component_id, "keep": MAX_COMPONENT_EVIDENCE_ROWS},
    )


def _persist_source_snapshot(
    connection: Any,
    snapshot: ComponentSourceSnapshot,
) -> None:
    connection.execute(
        text(
            """
            INSERT INTO component_source_snapshots (
                source_snapshot_id, canonical_collection_id, site_id, asset_id,
                agent_source_id, collection_source_id, platform,
                collection_status, observed_at, record_count, truncated,
                error_code, limitations_json
            ) VALUES (
                :source_snapshot_id, :canonical_collection_id, :site_id,
                :asset_id, :agent_source_id, :collection_source_id, :platform,
                :collection_status, :observed_at, :record_count, :truncated,
                :error_code, CAST(:limitations_json AS JSONB)
            )
            ON CONFLICT (source_snapshot_id) DO NOTHING
            """
        ),
        {
            **snapshot.__dict__,
            "limitations_json": _json(list(snapshot.limitations)),
        },
    )


def _upsert_source_presence(
    connection: Any,
    *,
    component: NormalizedComponent,
    snapshot: ComponentSourceSnapshot,
) -> None:
    connection.execute(
        text(
            """
            INSERT INTO component_source_presence (
                component_id, site_id, asset_id, agent_source_id,
                collection_source_id, source_record_id, evidence_method,
                active, first_observed_at, last_observed_at,
                last_source_snapshot_id
            ) VALUES (
                :component_id, :site_id, :asset_id, :agent_source_id,
                :collection_source_id, :source_record_id, :evidence_method,
                TRUE, :observed_at, :observed_at, :source_snapshot_id
            )
            ON CONFLICT (component_id, agent_source_id, collection_source_id)
            DO UPDATE SET
                source_record_id = EXCLUDED.source_record_id,
                evidence_method = EXCLUDED.evidence_method,
                active = TRUE,
                last_observed_at = GREATEST(
                    component_source_presence.last_observed_at,
                    EXCLUDED.last_observed_at
                ),
                not_observed_at = NULL,
                last_source_snapshot_id = EXCLUDED.last_source_snapshot_id,
                updated_at = NOW()
            WHERE EXCLUDED.last_observed_at >= GREATEST(
                component_source_presence.last_observed_at,
                COALESCE(
                    component_source_presence.not_observed_at,
                    component_source_presence.last_observed_at
                )
            )
            """
        ),
        {
            "component_id": component.component_id,
            "site_id": component.site_id,
            "asset_id": component.asset_id,
            "agent_source_id": component.source_id,
            "collection_source_id": component.collection_source_id,
            "source_record_id": component.source_record_id,
            "evidence_method": component.evidence_method,
            "observed_at": component.observed_at,
            "source_snapshot_id": snapshot.source_snapshot_id,
        },
    )


def _record_source_state(
    connection: Any,
    snapshot: ComponentSourceSnapshot,
) -> None:
    complete = snapshot.collection_status == "complete"
    connection.execute(
        text(
            """
            INSERT INTO component_collection_sources (
                site_id, asset_id, agent_source_id, collection_source_id,
                platform, collection_status, last_attempt_at,
                last_successful_complete_at, last_source_snapshot_id,
                last_successful_snapshot_id, canonical_collection_id,
                record_count, truncated, error_code, limitations_json
            ) VALUES (
                :site_id, :asset_id, :agent_source_id, :collection_source_id,
                :platform, :collection_status, :observed_at,
                :successful_at, :source_snapshot_id, :successful_snapshot_id,
                :canonical_collection_id, :record_count, :truncated,
                :error_code, CAST(:limitations_json AS JSONB)
            )
            ON CONFLICT (
                site_id, asset_id, agent_source_id, collection_source_id
            ) DO UPDATE SET
                platform = EXCLUDED.platform,
                collection_status = EXCLUDED.collection_status,
                last_attempt_at = EXCLUDED.last_attempt_at,
                last_successful_complete_at = CASE
                    WHEN EXCLUDED.collection_status = 'complete'
                    THEN EXCLUDED.last_attempt_at
                    ELSE component_collection_sources.last_successful_complete_at
                END,
                last_source_snapshot_id = EXCLUDED.last_source_snapshot_id,
                last_successful_snapshot_id = CASE
                    WHEN EXCLUDED.collection_status = 'complete'
                    THEN EXCLUDED.last_source_snapshot_id
                    ELSE component_collection_sources.last_successful_snapshot_id
                END,
                canonical_collection_id = EXCLUDED.canonical_collection_id,
                record_count = EXCLUDED.record_count,
                truncated = EXCLUDED.truncated,
                error_code = EXCLUDED.error_code,
                limitations_json = EXCLUDED.limitations_json,
                updated_at = NOW()
            WHERE EXCLUDED.last_attempt_at >= component_collection_sources.last_attempt_at
            """
        ),
        {
            **snapshot.__dict__,
            "successful_at": snapshot.observed_at if complete else None,
            "successful_snapshot_id": (
                snapshot.source_snapshot_id if complete else None
            ),
            "limitations_json": _json(list(snapshot.limitations)),
        },
    )


def _apply_complete_source_snapshot(
    connection: Any,
    *,
    snapshot: ComponentSourceSnapshot,
    observed_ids: set[str],
) -> int:
    """Retire only presence omitted by this exact complete source scope.

    Partial, failed, unsupported, stale, or differently scoped snapshots never
    reach the mutation below. History and snapshots are append-only here.
    """

    if snapshot.collection_status != "complete":
        return 0
    statement = text(
        """
        SELECT component_id, source_record_id
        FROM component_source_presence
        WHERE site_id = :site_id
          AND asset_id = :asset_id
          AND agent_source_id = :agent_source_id
          AND collection_source_id = :collection_source_id
          AND active = TRUE
          AND last_observed_at <= :observed_at
        """
        + (
            "\n          AND component_id NOT IN :observed_ids"
            if observed_ids
            else ""
        )
        + "\n        FOR UPDATE"
    )
    if observed_ids:
        statement = statement.bindparams(bindparam("observed_ids", expanding=True))
    params: dict[str, Any] = {
        "site_id": snapshot.site_id,
        "asset_id": snapshot.asset_id,
        "agent_source_id": snapshot.agent_source_id,
        "collection_source_id": snapshot.collection_source_id,
        "observed_at": snapshot.observed_at,
    }
    if observed_ids:
        params["observed_ids"] = sorted(observed_ids)
    rows = connection.execute(statement, params).mappings().all()
    removed = 0
    for row in rows[:MAX_COMPONENTS_PER_ASSET]:
        component_id = str(row["component_id"])
        changed = connection.execute(
            text(
                """
                UPDATE component_source_presence
                SET active = FALSE,
                    not_observed_at = :observed_at,
                    last_source_snapshot_id = :source_snapshot_id,
                    updated_at = NOW()
                WHERE component_id = :component_id
                  AND site_id = :site_id
                  AND asset_id = :asset_id
                  AND agent_source_id = :agent_source_id
                  AND collection_source_id = :collection_source_id
                  AND active = TRUE
                  AND last_observed_at <= :observed_at
                RETURNING component_id
                """
            ),
            {
                "component_id": component_id,
                "site_id": snapshot.site_id,
                "asset_id": snapshot.asset_id,
                "agent_source_id": snapshot.agent_source_id,
                "collection_source_id": snapshot.collection_source_id,
                "observed_at": snapshot.observed_at,
                "source_snapshot_id": snapshot.source_snapshot_id,
            },
        ).scalar_one_or_none()
        if changed is None:
            continue
        any_active = bool(
            connection.execute(
                text(
                    """
                    SELECT 1
                    FROM component_source_presence
                    WHERE component_id = :component_id AND active = TRUE
                    LIMIT 1
                    """
                ),
                {"component_id": component_id},
            ).scalar_one_or_none()
        )
        if not any_active:
            connection.execute(
                text(
                    """
                    UPDATE asset_components
                    SET active = FALSE,
                        not_observed_at = :observed_at,
                        updated_at = NOW()
                    WHERE component_id = :component_id
                      AND observed_at <= :observed_at
                    """
                ),
                {
                    "component_id": component_id,
                    "observed_at": snapshot.observed_at,
                },
            )
        connection.execute(
            text(
                """
                INSERT INTO asset_component_history (
                    component_id, site_id, asset_id, event_type,
                    previous_version, current_version, snapshot_json,
                    observed_at
                )
                SELECT component_id, site_id, asset_id, 'not-observed',
                       version, CASE WHEN :any_active THEN version ELSE NULL END,
                       CAST(:snapshot_json AS JSONB), :observed_at
                FROM asset_components
                WHERE component_id = :component_id
                """
            ),
            {
                "component_id": component_id,
                "any_active": any_active,
                "snapshot_json": _json(
                    {
                        "component_id": component_id,
                        "active": any_active,
                        "reason": "complete-source-omission",
                        "collection_source_id": snapshot.collection_source_id,
                        "source_snapshot_id": snapshot.source_snapshot_id,
                        "source_record_id": row["source_record_id"],
                    }
                ),
                "observed_at": snapshot.observed_at,
            },
        )
        removed += 1
    return removed


def persist_components(
    connection: Any,
    *,
    components: Sequence[NormalizedComponent],
    complete_assets: Sequence[tuple[str, str, str, datetime]] = (),
) -> dict[str, int]:
    """Upsert a bounded component snapshot and preserve material history."""

    inserted = updated = removed = 0
    observed_by_asset: dict[tuple[str, str, str], set[str]] = {}
    for component in components[: MAX_COMPONENTS_PER_ASSET * 500]:
        previous_row = connection.execute(
            text(
                """
                SELECT *
                FROM asset_components
                WHERE component_id = :component_id
                FOR UPDATE
                """
            ),
            {"component_id": component.component_id},
        ).mappings().one_or_none()
        previous = dict(previous_row) if previous_row is not None else None
        replace_current = _should_replace_component(previous, component)
        event_type = (
            _history_event(previous, component) if replace_current else None
        )
        applied_component_id = None
        if replace_current:
            applied_component_id = connection.execute(
                text(
                    """
                INSERT INTO asset_components (
                    component_id, asset_id, site_id, component_type, ecosystem,
                    namespace, vendor, name, normalized_name, version,
                    normalized_version, architecture, package_manager,
                    canonical_identifier, cpe_hint, install_scope, source_type,
                    source_id, firmware_evidence_type, first_seen_at, last_seen_at,
                    observed_at, freshness, confidence, normalization_status,
                    active, metadata_json, model_version
                )
                VALUES (
                    :component_id, :asset_id, :site_id, :component_type, :ecosystem,
                    :namespace, :vendor, :name, :normalized_name, :version,
                    :normalized_version, :architecture, :package_manager,
                    :canonical_identifier, :cpe_hint, :install_scope, :source_type,
                    :source_id, :firmware_evidence_type, :first_seen_at, :last_seen_at,
                    :observed_at, :freshness, :confidence, :normalization_status,
                    TRUE, CAST(:metadata_json AS JSONB), :model_version
                )
                ON CONFLICT (component_id) DO UPDATE SET
                    component_type = EXCLUDED.component_type,
                    ecosystem = EXCLUDED.ecosystem,
                    namespace = EXCLUDED.namespace,
                    vendor = EXCLUDED.vendor,
                    name = EXCLUDED.name,
                    normalized_name = EXCLUDED.normalized_name,
                    version = EXCLUDED.version,
                    normalized_version = EXCLUDED.normalized_version,
                    architecture = EXCLUDED.architecture,
                    package_manager = EXCLUDED.package_manager,
                    canonical_identifier = EXCLUDED.canonical_identifier,
                    cpe_hint = EXCLUDED.cpe_hint,
                    install_scope = EXCLUDED.install_scope,
                    source_type = EXCLUDED.source_type,
                    source_id = EXCLUDED.source_id,
                    firmware_evidence_type = EXCLUDED.firmware_evidence_type,
                    first_seen_at = LEAST(asset_components.first_seen_at, EXCLUDED.first_seen_at),
                    last_seen_at = GREATEST(asset_components.last_seen_at, EXCLUDED.last_seen_at),
                    observed_at = GREATEST(asset_components.observed_at, EXCLUDED.observed_at),
                    freshness = EXCLUDED.freshness,
                    confidence = EXCLUDED.confidence,
                    normalization_status = EXCLUDED.normalization_status,
                    active = TRUE,
                    not_observed_at = NULL,
                    metadata_json = EXCLUDED.metadata_json,
                    model_version = EXCLUDED.model_version,
                    updated_at = NOW()
                WHERE (
                    EXCLUDED.observed_at > GREATEST(
                        asset_components.observed_at,
                        COALESCE(
                            asset_components.not_observed_at,
                            asset_components.observed_at
                        )
                    )
                    AND CASE EXCLUDED.source_type
                        WHEN 'endpoint-collector' THEN 3
                        WHEN 'reviewed-connector' THEN 2
                        WHEN 'passive-network-sensor' THEN 1
                        WHEN 'connector' THEN 1
                        ELSE 0
                    END >= CASE asset_components.source_type
                        WHEN 'endpoint-collector' THEN 3
                        WHEN 'reviewed-connector' THEN 2
                        WHEN 'passive-network-sensor' THEN 1
                        WHEN 'connector' THEN 1
                        ELSE 0
                    END
                ) OR (
                    EXCLUDED.observed_at = GREATEST(
                        asset_components.observed_at,
                        COALESCE(
                            asset_components.not_observed_at,
                            asset_components.observed_at
                        )
                    )
                    AND ROW(
                        CASE EXCLUDED.source_type
                            WHEN 'endpoint-collector' THEN 3
                            WHEN 'reviewed-connector' THEN 2
                            WHEN 'passive-network-sensor' THEN 1
                            WHEN 'connector' THEN 1
                            ELSE 0
                        END,
                        EXCLUDED.confidence,
                        EXCLUDED.source_type,
                        EXCLUDED.source_id,
                        COALESCE(EXCLUDED.normalized_version, '')
                    ) >= ROW(
                        CASE asset_components.source_type
                            WHEN 'endpoint-collector' THEN 3
                            WHEN 'reviewed-connector' THEN 2
                            WHEN 'passive-network-sensor' THEN 1
                            WHEN 'connector' THEN 1
                            ELSE 0
                        END,
                        asset_components.confidence,
                        asset_components.source_type,
                        asset_components.source_id,
                        COALESCE(asset_components.normalized_version, '')
                    )
                )
                RETURNING component_id
                """
                ),
                {
                    **component.as_dict(),
                    "metadata_json": _json(component.metadata),
                },
            ).scalar_one_or_none()
        if applied_component_id is None:
            event_type = None
        if event_type:
            snapshot = component.as_dict()
            snapshot["evidence_ids"] = list(component.evidence_ids)
            connection.execute(
                text(
                    """
                    INSERT INTO asset_component_history (
                        component_id, site_id, asset_id, event_type,
                        previous_version, current_version, snapshot_json,
                        observed_at
                    )
                    VALUES (
                        :component_id, :site_id, :asset_id, :event_type,
                        :previous_version, :current_version,
                        CAST(:snapshot_json AS JSONB), :observed_at
                    )
                    """
                ),
                {
                    "component_id": component.component_id,
                    "site_id": component.site_id,
                    "asset_id": component.asset_id,
                    "event_type": event_type,
                    "previous_version": (
                        previous.get("version") if previous else None
                    ),
                    "current_version": component.version,
                    "snapshot_json": _json(snapshot),
                    "observed_at": component.observed_at,
                },
            )
        for evidence_id in component.evidence_ids:
            connection.execute(
                text(
                    """
                    INSERT INTO component_evidence (
                        component_id, evidence_id, source_id, source_type,
                        observed_at, first_seen_at, last_seen_at
                    )
                    VALUES (
                        :component_id, :evidence_id, :source_id, :source_type,
                        :observed_at, :observed_at, :observed_at
                    )
                    ON CONFLICT (component_id, evidence_id) DO UPDATE SET
                        observed_at = GREATEST(
                            component_evidence.observed_at,
                            EXCLUDED.observed_at
                        ),
                        last_seen_at = GREATEST(
                            component_evidence.last_seen_at,
                            EXCLUDED.last_seen_at
                        ),
                        observation_count = LEAST(
                            component_evidence.observation_count + 1,
                            2147483647
                        )
                    """
                ),
                {
                    "component_id": component.component_id,
                    "evidence_id": evidence_id,
                    "source_id": component.source_id,
                    "source_type": component.source_type,
                    "observed_at": component.observed_at,
                },
            )
        _prune_component_rows(
            connection,
            component_id=component.component_id,
        )
        observed_by_asset.setdefault(
            (component.site_id, component.asset_id, component.source_id),
            set(),
        ).add(component.component_id)
        if previous is None and applied_component_id is not None:
            inserted += 1
        elif applied_component_id is not None:
            updated += 1

    for site_id, asset_id, source_id, observed_at in complete_assets:
        observed_ids = observed_by_asset.get((site_id, asset_id, source_id), set())
        statement = text(
            """
            SELECT component_id, version, metadata_json
            FROM asset_components
            WHERE site_id = :site_id
              AND asset_id = :asset_id
              AND source_id = :source_id
              AND active = TRUE
              AND observed_at <= :observed_at
            """
            + (
                "\n              AND component_id NOT IN :observed_ids"
                if observed_ids
                else ""
            )
            + "\n            FOR UPDATE"
        )
        if observed_ids:
            statement = statement.bindparams(
                bindparam("observed_ids", expanding=True)
            )
        params: dict[str, Any] = {
            "site_id": site_id,
            "asset_id": asset_id,
            "source_id": source_id,
            "observed_at": observed_at,
        }
        if observed_ids:
            params["observed_ids"] = sorted(observed_ids)
        rows = connection.execute(statement, params).mappings().all()
        for row in rows[:MAX_COMPONENTS_PER_ASSET]:
            connection.execute(
                text(
                    """
                    UPDATE asset_components
                    SET active = FALSE,
                        not_observed_at = :observed_at,
                        updated_at = NOW()
                    WHERE component_id = :component_id
                      AND active = TRUE
                    """
                ),
                {
                    "component_id": row["component_id"],
                    "observed_at": observed_at,
                },
            )
            connection.execute(
                text(
                    """
                    INSERT INTO asset_component_history (
                        component_id, site_id, asset_id, event_type,
                        previous_version, current_version, snapshot_json,
                        observed_at
                    )
                    VALUES (
                        :component_id, :site_id, :asset_id, 'not-observed',
                        :previous_version, NULL, CAST(:snapshot_json AS JSONB),
                        :observed_at
                    )
                    """
                ),
                {
                    "component_id": row["component_id"],
                    "site_id": site_id,
                    "asset_id": asset_id,
                    "previous_version": row["version"],
                    "snapshot_json": _json(
                        {
                            "component_id": row["component_id"],
                            "active": False,
                            "reason": "complete-inventory-omission",
                        }
                    ),
                    "observed_at": observed_at,
                },
            )
            removed += 1
    return {"inserted": inserted, "updated": updated, "not_observed": removed}


def persist_authenticated_endpoint_source_presence(
    connection: Any,
    *,
    components: Sequence[NormalizedComponent],
    source_snapshots: Sequence[ComponentSourceSnapshot],
) -> dict[str, int]:
    """Persist native source state after revalidating server-owned authority."""

    if not source_snapshots:
        return {"snapshots": 0, "not_observed": 0}
    reviewed_sources = {
        "windows": {"windows-uninstall-32", "windows-uninstall-64"},
        "linux": {"linux-dpkg", "linux-rpm"},
        "darwin": {"macos-pkgutil"},
    }
    lock_authenticated_endpoint_source_site(
        connection,
        source_snapshots=source_snapshots,
    )

    snapshots_by_scope: dict[tuple[str, str, str, str], ComponentSourceSnapshot] = {}
    for snapshot in source_snapshots:
        authority = connection.execute(
            text(
                """
                SELECT c.site_id, c.source_id, c.adapter_type,
                       c.ingestion_status, c.evaluation_state,
                       s.source_authority, s.authentication_class
                FROM canonical_inventory_collections c
                JOIN canonical_ingestion_sources s
                  ON s.source_id = c.source_id
                WHERE c.canonical_collection_id = :canonical_collection_id
                FOR UPDATE OF c, s
                """
            ),
            {"canonical_collection_id": snapshot.canonical_collection_id},
        ).mappings().one_or_none()
        if authority is None or (
            str(authority["site_id"]),
            str(authority["source_id"]),
            str(authority["adapter_type"]),
            str(authority["ingestion_status"]),
            str(authority["evaluation_state"]),
            str(authority["source_authority"]),
            str(authority["authentication_class"]),
        ) != (
            snapshot.site_id,
            snapshot.agent_source_id,
            "endpoint-agent",
            "accepted",
            "running",
            "authenticated-endpoint",
            "bound-credential",
        ):
            raise ValueError("native source snapshot lacks bound endpoint authority")
        if snapshot.collection_source_id not in reviewed_sources.get(
            snapshot.platform, set()
        ):
            raise ValueError("native source snapshot scope is not reviewed")
        expected_digest = hashlib.sha256(
            "\x00".join(
                (
                    snapshot.canonical_collection_id,
                    snapshot.site_id,
                    snapshot.asset_id,
                    snapshot.agent_source_id,
                    snapshot.collection_source_id,
                )
            ).encode("utf-8")
        ).hexdigest()[:32]
        if snapshot.source_snapshot_id != f"css_{expected_digest}":
            raise ValueError("native source snapshot identity is not server-derived")
        if snapshot.collection_status == "complete" and (
            snapshot.truncated or snapshot.error_code
        ):
            raise ValueError("incomplete native source cannot withdraw presence")
        scope = (
            snapshot.site_id,
            snapshot.asset_id,
            snapshot.agent_source_id,
            snapshot.collection_source_id,
        )
        if scope in snapshots_by_scope:
            raise ValueError("duplicate native source snapshot scope")
        previous = connection.execute(
            text(
                """
                SELECT last_attempt_at, canonical_collection_id
                FROM component_collection_sources
                WHERE site_id = :site_id
                  AND asset_id = :asset_id
                  AND agent_source_id = :agent_source_id
                  AND collection_source_id = :collection_source_id
                FOR UPDATE
                """
            ),
            {
                "site_id": snapshot.site_id,
                "asset_id": snapshot.asset_id,
                "agent_source_id": snapshot.agent_source_id,
                "collection_source_id": snapshot.collection_source_id,
            },
        ).mappings().one_or_none()
        if previous is not None and (
            snapshot.observed_at < previous["last_attempt_at"]
            or (
                snapshot.observed_at == previous["last_attempt_at"]
                and snapshot.canonical_collection_id
                != str(previous["canonical_collection_id"])
            )
        ):
            raise ValueError("native source snapshot is stale or out of order")
        snapshots_by_scope[scope] = snapshot

    observed_by_source: dict[tuple[str, str, str, str], set[str]] = {}
    for component in components:
        if not component.collection_source_id:
            continue
        scope = (
            component.site_id,
            component.asset_id,
            component.source_id,
            component.collection_source_id,
        )
        snapshot = snapshots_by_scope.get(scope)
        if snapshot is None:
            raise ValueError("native component lacks a validated source snapshot")
        observed_by_source.setdefault(scope, set()).add(component.component_id)
    for scope, snapshot in snapshots_by_scope.items():
        observed_count = len(observed_by_source.get(scope, set()))
        if observed_count != snapshot.record_count:
            raise ValueError("native source snapshot record count mismatch")
        if snapshot.collection_status in {"failed", "unsupported"} and observed_count:
            raise ValueError("failed native source cannot report component presence")

    for snapshot in source_snapshots:
        _persist_source_snapshot(connection, snapshot)
    for component in components:
        if not component.collection_source_id:
            continue
        scope = (
            component.site_id,
            component.asset_id,
            component.source_id,
            component.collection_source_id,
        )
        _upsert_source_presence(
            connection,
            component=component,
            snapshot=snapshots_by_scope[scope],
        )
    removed = 0
    for scope, snapshot in snapshots_by_scope.items():
        _record_source_state(connection, snapshot)
        removed += _apply_complete_source_snapshot(
            connection,
            snapshot=snapshot,
            observed_ids=observed_by_source.get(scope, set()),
        )
    return {"snapshots": len(source_snapshots), "not_observed": removed}


def lock_authenticated_endpoint_source_site(
    connection: Any,
    *,
    source_snapshots: Sequence[ComponentSourceSnapshot],
) -> str:
    """Lock the native projection site before any component-row mutation.

    Every native projection transaction must acquire this lock before it
    touches component rows. Keeping one lock order prevents a concurrent older
    complete snapshot from deadlocking with, and then overtaking, a newer
    snapshot that observes the same component.
    """

    site_ids = {snapshot.site_id for snapshot in source_snapshots}
    if len(site_ids) != 1:
        raise ValueError("native source snapshots must share one site")
    site_id = next(iter(site_ids))
    if connection.execute(
        text("SELECT site_id FROM sites WHERE site_id = :site_id FOR UPDATE"),
        {"site_id": site_id},
    ).scalar_one_or_none() is None:
        raise ValueError("native source snapshot site is not configured")
    return site_id


class SqlComponentStore:
    def __init__(self) -> None:
        self._schema_ready = False

    def _engine(self):
        from .database import get_engine

        return get_engine()

    def ensure_schema(self) -> None:
        if self._schema_ready:
            return
        from .schema_migrations import ensure_schema_ready

        ensure_schema_ready(self._engine())
        self._schema_ready = True

    def persist(
        self,
        *,
        components: Sequence[NormalizedComponent],
        complete_assets: Sequence[tuple[str, str, str, datetime]] = (),
    ) -> dict[str, int]:
        self.ensure_schema()
        with self._engine().begin() as connection:
            return persist_components(
                connection,
                components=components,
                complete_assets=complete_assets,
            )

    def list_components(
        self,
        *,
        site_id: str | None = None,
        asset_id: str | None = None,
        component_type: str | None = None,
        ecosystem: str | None = None,
        vendor: str | None = None,
        package: str | None = None,
        freshness: str | None = None,
        active: bool | None = True,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        self.ensure_schema()
        if not 1 <= limit <= MAX_COMPONENT_PAGE:
            raise ValueError("component limit must be between 1 and 200")
        if not 0 <= offset <= MAX_COMPONENT_OFFSET:
            raise ValueError("component offset must be between 0 and 10000")
        where = [
            "(:site_id IS NULL OR ac.site_id = :site_id)",
            "(:asset_id IS NULL OR ac.asset_id = :asset_id)",
            "(:component_type IS NULL OR ac.component_type = :component_type)",
            "(:ecosystem IS NULL OR ac.ecosystem = :ecosystem)",
            "(:vendor IS NULL OR LOWER(ac.vendor) = LOWER(:vendor))",
            "(:package IS NULL OR ac.normalized_name = LOWER(:package))",
            "(:freshness IS NULL OR (" + _COMPONENT_FRESHNESS_SQL + ") = :freshness)",
            "(:active IS NULL OR ac.active = :active)",
        ]
        params = {
            "site_id": site_id,
            "asset_id": asset_id,
            "component_type": component_type,
            "ecosystem": ecosystem,
            "vendor": vendor,
            "package": package,
            "freshness": freshness,
            "active": active,
            "limit": limit,
            "offset": offset,
        }
        base = " FROM asset_components ac WHERE " + " AND ".join(where)
        with self._engine().begin() as connection:
            rows = connection.execute(
                text(
                    """
                    SELECT ac.*,
                        """
                    + _COMPONENT_FRESHNESS_SQL
                    + """ AS effective_freshness,
                        COALESCE(
                            (
                                SELECT jsonb_agg(
                                    bounded.evidence_id
                                    ORDER BY bounded.last_seen_at DESC
                                )
                                FROM (
                                    SELECT ce.evidence_id, ce.last_seen_at
                                    FROM component_evidence ce
                                    WHERE ce.component_id = ac.component_id
                                    ORDER BY ce.last_seen_at DESC, ce.evidence_id
                                    LIMIT 16
                                ) bounded
                            ),
                            '[]'::jsonb
                        ) AS evidence_ids_json
                        ,COALESCE(
                            (
                                SELECT jsonb_agg(
                                    bounded.source_state
                                    ORDER BY bounded.collection_source_id,
                                             bounded.agent_source_id
                                )
                                FROM (
                                    SELECT
                                        csp.collection_source_id,
                                        csp.agent_source_id,
                                        jsonb_build_object(
                                            'source_snapshot_id', csp.last_source_snapshot_id,
                                            'canonical_collection_id', css.canonical_collection_id,
                                            'agent_source_id', csp.agent_source_id,
                                            'collection_source_id', csp.collection_source_id,
                                            'platform', css.platform,
                                            'collection_status', css.collection_status,
                                            'source_record_id', csp.source_record_id,
                                            'evidence_method', csp.evidence_method,
                                            'presence_active', csp.active,
                                            'last_attempt_at', css.observed_at,
                                            'last_successful_complete_at', ccs.last_successful_complete_at,
                                            'last_observed_at', csp.last_observed_at,
                                            'not_observed_at', csp.not_observed_at
                                        ) AS source_state
                                    FROM component_source_presence csp
                                    JOIN component_collection_sources ccs
                                      ON ccs.site_id = csp.site_id
                                     AND ccs.asset_id = csp.asset_id
                                     AND ccs.agent_source_id = csp.agent_source_id
                                     AND ccs.collection_source_id = csp.collection_source_id
                                    JOIN component_source_snapshots css
                                      ON css.source_snapshot_id = csp.last_source_snapshot_id
                                     AND css.site_id = csp.site_id
                                     AND css.asset_id = csp.asset_id
                                     AND css.agent_source_id = csp.agent_source_id
                                     AND css.collection_source_id = csp.collection_source_id
                                    WHERE csp.component_id = ac.component_id
                                    ORDER BY csp.collection_source_id,
                                             csp.agent_source_id
                                    LIMIT 8
                                ) bounded
                            ),
                            '[]'::jsonb
                        ) AS collection_sources_json
                    """
                    + base
                    + """
                    ORDER BY ac.last_seen_at DESC, ac.component_id
                    LIMIT :limit OFFSET :offset
                    """
                ),
                params,
            ).mappings().all()
            total = int(
                connection.execute(
                    text("SELECT COUNT(*)" + base),
                    params,
                ).scalar_one()
            )
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["freshness"] = item.pop(
                "effective_freshness",
                item.get("freshness", "unknown"),
            )
            item["metadata"] = _json_value(item.pop("metadata_json"), {})
            item["evidence_ids"] = _json_value(
                item.pop("evidence_ids_json"),
                [],
            )[:16]
            item["collection_sources"] = _json_value(
                item.pop("collection_sources_json"),
                [],
            )[:8]
            items.append(item)
        return {
            "items": items,
            "total": total,
            "limit": limit,
            "offset": offset,
            "truncated": offset + len(items) < total,
        }

    def list_history(
        self,
        *,
        component_id: str,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        self.ensure_schema()
        safe_limit = max(1, min(limit, 200))
        with self._engine().begin() as connection:
            rows = connection.execute(
                text(
                    """
                    SELECT *
                    FROM asset_component_history
                    WHERE component_id = :component_id
                    ORDER BY observed_at DESC, history_id DESC
                    LIMIT :limit
                    """
                ),
                {"component_id": component_id, "limit": safe_limit},
            ).mappings().all()
        result = []
        for row in rows:
            item = dict(row)
            item["snapshot"] = _json_value(item.pop("snapshot_json"), {})
            result.append(item)
        return result

    def component_snapshot(
        self,
        *,
        site_id: str | None = None,
        limit: int = 2_000,
    ) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 10_000))
        items: list[dict[str, Any]] = []
        offset = 0
        while len(items) < safe_limit:
            page = self.list_components(
                site_id=site_id,
                active=None,
                limit=min(200, safe_limit - len(items)),
                offset=offset,
            )
            items.extend(page["items"])
            if not page["truncated"]:
                break
            offset += len(page["items"])
        return items
