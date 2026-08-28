"""Bounded, parameterized source queries for temporal signal projection."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import text

from .temporal_contracts import TEMPORAL_METRICS, TemporalMetricDefinition
from .temporal_projection import ProjectionAggregate, TemporalSiteNotFound


SITE_EXISTS_SQL = "SELECT EXISTS (SELECT 1 FROM sites WHERE site_id = :site_id)"

ASSETS_NEW_SQL = """
WITH event_buckets AS (
    SELECT
        date_trunc('day', first_seen_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
            AS bucket_start,
        COUNT(DISTINCT asset_id)::BIGINT AS value,
        COUNT(DISTINCT asset_id)::BIGINT AS evidence_count,
        MAX(first_seen_at) AS source_observed_at,
        MAX(created_at) AS source_received_at
    FROM control_tower_assets
    WHERE site_id = :site_id
      AND first_seen_at >= :start
      AND first_seen_at < :end
    GROUP BY 1
),
coverage_buckets AS (
    SELECT
        date_trunc('day', observed_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
            AS bucket_start,
        MAX(observed_at) AS source_observed_at,
        MAX(ingested_at) AS source_received_at
    FROM canonical_inventory_collections
    WHERE site_id = :site_id
      AND observed_at >= :start
      AND observed_at < :end
    GROUP BY 1
)
SELECT
    COALESCE(events.bucket_start, coverage.bucket_start) AS bucket_start,
    COALESCE(events.value, 0)::BIGINT AS value,
    COALESCE(events.evidence_count, 0)::BIGINT AS evidence_count,
    GREATEST(events.source_observed_at, coverage.source_observed_at)
        AS source_observed_at,
    GREATEST(events.source_received_at, coverage.source_received_at)
        AS source_received_at,
    events.bucket_start IS NOT NULL AS complete,
    events.bucket_start IS NOT NULL OR coverage.bucket_start IS NOT NULL
        AS coverage_observed
FROM event_buckets AS events
FULL OUTER JOIN coverage_buckets AS coverage USING (bucket_start)
ORDER BY bucket_start ASC
"""

COLLECTORS_ACTIVE_SQL = """
SELECT
    date_trunc(
        'day', COALESCE(checkins.checked_in_at, checkins.received_at)
        AT TIME ZONE 'UTC'
    ) AT TIME ZONE 'UTC' AS bucket_start,
    COUNT(DISTINCT checkins.agent_id)::BIGINT AS value,
    COUNT(DISTINCT checkins.agent_id)::BIGINT AS evidence_count,
    MAX(COALESCE(checkins.checked_in_at, checkins.received_at))
        AS source_observed_at,
    MAX(checkins.received_at) AS source_received_at,
    TRUE AS complete,
    TRUE AS coverage_observed
FROM agent_checkins AS checkins
JOIN agent_enrollments AS enrollments
  ON enrollments.agent_id = checkins.agent_id
 AND enrollments.site_id = checkins.site_id
WHERE checkins.site_id = :site_id
  AND checkins.agent_id IS NOT NULL
  AND COALESCE(checkins.checked_in_at, checkins.received_at) >= :start
  AND COALESCE(checkins.checked_in_at, checkins.received_at) < :end
GROUP BY 1
ORDER BY bucket_start ASC
"""

FINDINGS_NEW_SQL = """
WITH event_buckets AS (
    SELECT
        date_trunc('day', first_seen_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
            AS bucket_start,
        COUNT(DISTINCT finding_id)::BIGINT AS value,
        COUNT(DISTINCT finding_id)::BIGINT AS evidence_count,
        MAX(first_seen_at) AS source_observed_at,
        MAX(created_at) AS source_received_at
    FROM findings
    WHERE site_id = :site_id
      AND first_seen_at >= :start
      AND first_seen_at < :end
    GROUP BY 1
),
coverage_buckets AS (
    SELECT
        date_trunc(
            'day', COALESCE(completed_at, started_at) AT TIME ZONE 'UTC'
        ) AT TIME ZONE 'UTC' AS bucket_start,
        MAX(COALESCE(data_as_of, completed_at, started_at))
            AS source_observed_at,
        MAX(COALESCE(completed_at, started_at)) AS source_received_at,
        BOOL_OR(
            status = 'completed'
            AND scope_asset_id IS NULL
            AND scope_sensor_id IS NULL
        ) AS complete
    FROM finding_evaluation_runs
    WHERE (scope_site_id = :site_id OR scope_site_id IS NULL)
      AND COALESCE(completed_at, started_at) >= :start
      AND COALESCE(completed_at, started_at) < :end
    GROUP BY 1
)
SELECT
    COALESCE(events.bucket_start, coverage.bucket_start) AS bucket_start,
    COALESCE(events.value, 0)::BIGINT AS value,
    COALESCE(events.evidence_count, 0)::BIGINT AS evidence_count,
    GREATEST(events.source_observed_at, coverage.source_observed_at)
        AS source_observed_at,
    GREATEST(events.source_received_at, coverage.source_received_at)
        AS source_received_at,
    COALESCE(coverage.complete, FALSE) AS complete,
    coverage.bucket_start IS NOT NULL AS coverage_observed
FROM event_buckets AS events
FULL OUTER JOIN coverage_buckets AS coverage USING (bucket_start)
ORDER BY bucket_start ASC
"""

VULNERABILITIES_NEW_SQL = """
WITH event_buckets AS (
    SELECT
        date_trunc('day', first_matched_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
            AS bucket_start,
        COUNT(DISTINCT match_id)::BIGINT AS value,
        COUNT(DISTINCT match_id)::BIGINT AS evidence_count,
        MAX(first_matched_at) AS source_observed_at,
        MAX(created_at) AS source_received_at
    FROM vulnerability_matches
    WHERE site_id = :site_id
      AND first_matched_at >= :start
      AND first_matched_at < :end
    GROUP BY 1
),
coverage_buckets AS (
    SELECT
        date_trunc(
            'day', COALESCE(completed_at, started_at) AT TIME ZONE 'UTC'
        ) AT TIME ZONE 'UTC' AS bucket_start,
        MAX(COALESCE(completed_at, started_at)) AS source_observed_at,
        MAX(COALESCE(completed_at, started_at)) AS source_received_at,
        BOOL_OR(
            status = 'completed'
            AND scope_asset_id IS NULL
            AND scope_component_id IS NULL
            AND scope_advisory_id IS NULL
        ) AS complete
    FROM vulnerability_evaluation_runs
    WHERE (scope_site_id = :site_id OR scope_site_id IS NULL)
      AND COALESCE(completed_at, started_at) >= :start
      AND COALESCE(completed_at, started_at) < :end
    GROUP BY 1
)
SELECT
    COALESCE(events.bucket_start, coverage.bucket_start) AS bucket_start,
    COALESCE(events.value, 0)::BIGINT AS value,
    COALESCE(events.evidence_count, 0)::BIGINT AS evidence_count,
    GREATEST(events.source_observed_at, coverage.source_observed_at)
        AS source_observed_at,
    GREATEST(events.source_received_at, coverage.source_received_at)
        AS source_received_at,
    COALESCE(coverage.complete, FALSE) AS complete,
    coverage.bucket_start IS NOT NULL AS coverage_observed
FROM event_buckets AS events
FULL OUTER JOIN coverage_buckets AS coverage USING (bucket_start)
ORDER BY bucket_start ASC
"""

INVENTORY_COLLECTIONS_SQL = """
SELECT
    date_trunc('day', observed_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
        AS bucket_start,
    COUNT(canonical_collection_id)::BIGINT AS value,
    COUNT(canonical_collection_id)::BIGINT AS evidence_count,
    MAX(observed_at) AS source_observed_at,
    MAX(ingested_at) AS source_received_at,
    TRUE AS complete,
    TRUE AS coverage_observed
FROM canonical_inventory_collections
WHERE site_id = :site_id
  AND observed_at >= :start
  AND observed_at < :end
GROUP BY 1
ORDER BY bucket_start ASC
"""

INVENTORY_ASSET_OBSERVATIONS_SQL = """
SELECT
    date_trunc('day', observed_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
        AS bucket_start,
    SUM(canonical_asset_count)::BIGINT AS value,
    COUNT(canonical_collection_id)::BIGINT AS evidence_count,
    MAX(observed_at) AS source_observed_at,
    MAX(ingested_at) AS source_received_at,
    TRUE AS complete,
    TRUE AS coverage_observed
FROM canonical_inventory_collections
WHERE site_id = :site_id
  AND observed_at >= :start
  AND observed_at < :end
GROUP BY 1
ORDER BY bucket_start ASC
"""

METRIC_QUERIES = {
    "site.assets.new.count": ASSETS_NEW_SQL,
    "site.collectors.active.count": COLLECTORS_ACTIVE_SQL,
    "site.findings.new.count": FINDINGS_NEW_SQL,
    "site.vulnerabilities.new.count": VULNERABILITIES_NEW_SQL,
    "site.inventory.collections.count": INVENTORY_COLLECTIONS_SQL,
    "site.inventory.asset_observations.count": INVENTORY_ASSET_OBSERVATIONS_SQL,
}
if set(METRIC_QUERIES) != {metric.metric_key for metric in TEMPORAL_METRICS}:
    raise RuntimeError("temporal metric registry and query map differ")


def _with_knowledge_cutoff(
    query: str,
    replacements: tuple[tuple[str, str], ...],
) -> str:
    """Build a fixed as-of query variant without accepting caller-owned SQL."""

    result = query
    for anchor, predicate in replacements:
        if result.count(anchor) != 1:
            raise RuntimeError("temporal cutoff query anchor is not unique")
        result = result.replace(anchor, f"{anchor}\n      AND {predicate}")
    return result


METRIC_QUERIES_AS_OF = {
    "site.assets.new.count": _with_knowledge_cutoff(
        ASSETS_NEW_SQL,
        (
            ("AND first_seen_at < :end", "created_at < :knowledge_cutoff"),
            ("AND observed_at < :end", "ingested_at < :knowledge_cutoff"),
        ),
    ),
    "site.collectors.active.count": _with_knowledge_cutoff(
        COLLECTORS_ACTIVE_SQL,
        (
            (
                "AND COALESCE(checkins.checked_in_at, checkins.received_at) < :end",
                "checkins.received_at < :knowledge_cutoff",
            ),
        ),
    ),
    "site.findings.new.count": _with_knowledge_cutoff(
        FINDINGS_NEW_SQL,
        (
            ("AND first_seen_at < :end", "created_at < :knowledge_cutoff"),
            (
                "AND COALESCE(completed_at, started_at) < :end",
                "COALESCE(completed_at, started_at) < :knowledge_cutoff",
            ),
        ),
    ),
    "site.vulnerabilities.new.count": _with_knowledge_cutoff(
        VULNERABILITIES_NEW_SQL,
        (
            ("AND first_matched_at < :end", "created_at < :knowledge_cutoff"),
            (
                "AND COALESCE(completed_at, started_at) < :end",
                "COALESCE(completed_at, started_at) < :knowledge_cutoff",
            ),
        ),
    ),
    "site.inventory.collections.count": _with_knowledge_cutoff(
        INVENTORY_COLLECTIONS_SQL,
        (("AND observed_at < :end", "ingested_at < :knowledge_cutoff"),),
    ),
    "site.inventory.asset_observations.count": _with_knowledge_cutoff(
        INVENTORY_ASSET_OBSERVATIONS_SQL,
        (("AND observed_at < :end", "ingested_at < :knowledge_cutoff"),),
    ),
}
if set(METRIC_QUERIES_AS_OF) != set(METRIC_QUERIES):
    raise RuntimeError("temporal as-of query map and metric registry differ")


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        raise RuntimeError("temporal source timestamps must include a timezone")
    return value.astimezone(timezone.utc)


class SqlTemporalStore:
    """Read-only projector source. Query selection is registry-owned, never caller-owned."""

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

    def metric_buckets(
        self,
        *,
        metric: TemporalMetricDefinition,
        site_id: str,
        start: datetime,
        end: datetime,
        knowledge_cutoff: datetime | None = None,
    ) -> dict[datetime, ProjectionAggregate]:
        query_map = (
            METRIC_QUERIES_AS_OF
            if knowledge_cutoff is not None
            else METRIC_QUERIES
        )
        query = query_map.get(metric.metric_key)
        if query is None:
            raise ValueError("unsupported temporal metric query")
        self.ensure_schema()
        params = {"site_id": site_id, "start": start, "end": end}
        if knowledge_cutoff is not None:
            normalized_cutoff = _utc(knowledge_cutoff)
            if normalized_cutoff is None:
                raise ValueError("knowledge cutoff is required")
            params["knowledge_cutoff"] = normalized_cutoff
        with self._engine().begin() as connection:
            if not connection.execute(
                text(SITE_EXISTS_SQL),
                {"site_id": site_id},
            ).scalar_one():
                raise TemporalSiteNotFound()
            rows = connection.execute(text(query), params).mappings().all()
        return self._project_rows(rows)

    @staticmethod
    def _project_rows(rows: list[Any]) -> dict[datetime, ProjectionAggregate]:
        projected: dict[datetime, ProjectionAggregate] = {}
        for row in rows:
            item = dict(row)
            bucket = _utc(item.get("bucket_start"))
            if bucket is None:
                raise RuntimeError("temporal source query returned a null bucket")
            if bucket in projected:
                raise RuntimeError("temporal source query returned a duplicate bucket")
            projected[bucket] = ProjectionAggregate(
                value=int(item.get("value") or 0),
                evidence_count=int(item.get("evidence_count") or 0),
                source_observed_at=_utc(item.get("source_observed_at")),
                source_received_at=_utc(item.get("source_received_at")),
                complete=bool(item.get("complete")),
                coverage_observed=bool(item.get("coverage_observed")),
            )
        return projected
