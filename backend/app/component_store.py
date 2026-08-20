"""Durable normalized component inventory and history."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Sequence

from sqlalchemy import bindparam, text

from .component_intelligence import (
    MAX_COMPONENTS_PER_ASSET,
    NormalizedComponent,
)


MAX_COMPONENT_PAGE = 200
MAX_COMPONENT_OFFSET = 10_000
MAX_COMPONENT_HISTORY_ROWS = 256
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
    connection.execute(
        text(
            """
            DELETE FROM asset_component_history
            WHERE history_id IN (
                SELECT history_id
                FROM asset_component_history
                WHERE component_id = :component_id
                ORDER BY observed_at DESC, history_id DESC
                OFFSET :keep
              )
            """
        ),
        {"component_id": component_id, "keep": MAX_COMPONENT_HISTORY_ROWS},
    )


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
