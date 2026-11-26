"""Bounded, read-only loaders for security outcome metrics (CTEM-GAP-09).

Each request runs in one read-only transaction, reads only the rows its metric
needs (scoped to the site in SQL), and stops at `MAX_METRIC_ROWS`: a result
that would need more rows is reported as unavailable instead of being
computed from a truncated set. Nothing here writes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import text

from .outcome_metrics import (
    CATALOG_VERSION,
    METRICS_BY_ID,
    MetricDefinition,
    MetricFilters,
    MetricInputs,
    MetricWindow,
    compute_metric,
    resolve_window,
    validate_filters,
)

MAX_METRIC_ROWS = 100_000
# The migration that started each history source.
SOURCE_MIGRATIONS = {"work-events": 5, "decision-history": 6, "verification-history": 8, "verification-runs": 8}

_SITE = "(CAST(:site_id AS TEXT) IS NULL OR {column} = :site_id)"


class MetricNotFound(LookupError):
    pass


class SqlOutcomeMetricsStore:
    def _engine(self):
        from .database import get_engine

        return get_engine()

    def compute(
        self,
        metric_id: str,
        *,
        site_id: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        action_band: str | None = None,
        verification_state: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        definition = METRICS_BY_ID.get(metric_id)
        if definition is None:
            raise MetricNotFound(metric_id)
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        filters = MetricFilters(site_id=site_id, action_band=action_band, verification_state=verification_state)
        validate_filters(definition, filters)
        window = resolve_window(definition, start=start, end=end, now=now)
        with self._engine().begin() as connection:
            connection.execute(text("SET TRANSACTION READ ONLY"))
            inputs = _load(connection, definition, window, site_id, now)
            freshness = _freshness(connection, definition, site_id)
        result = compute_metric(definition, window=window, filters=filters, inputs=inputs, now=now)
        return {
            "catalog_version": CATALOG_VERSION,
            "metric_id": definition.metric_id,
            "metric_version": definition.version,
            "display_name": definition.display_name,
            "unit": definition.unit,
            "value_kind": definition.value_kind,
            "counting_grain": definition.counting_grain,
            "population": definition.population,
            "numerator_definition": definition.numerator,
            "denominator_definition": definition.denominator,
            "time_semantics": definition.time_semantics,
            "time_range": {"start": window.start, "end": window.end},
            "filters": {"site_id": site_id, "action_band": action_band, "verification_state": verification_state},
            **result,
            "source_freshness": freshness,
            "limitations": list(definition.limitations),
            "computed_at": now,
        }


# ------------------------------------------------------------------ loaders


def _rows(connection: Any, sql: str, params: Mapping[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    rows = [dict(row) for row in connection.execute(text(sql + " LIMIT :row_limit"),
                                                    {**params, "row_limit": MAX_METRIC_ROWS + 1}).mappings()]
    return rows[:MAX_METRIC_ROWS], len(rows) > MAX_METRIC_ROWS


def _recording_since(connection: Any) -> dict[str, datetime | None]:
    applied = {
        int(row["version"]): row["applied_at"]
        for row in connection.execute(
            text("SELECT version, applied_at FROM public.oaw_schema_migrations WHERE version IN (5, 6, 8)")
        ).mappings()
    }
    return {source: applied.get(version) for source, version in SOURCE_MIGRATIONS.items()}


def _load(connection: Any, definition: MetricDefinition, window: MetricWindow, site_id: str | None,
          now: datetime) -> MetricInputs:
    metric_id = definition.metric_id
    params = {"site_id": site_id, "start": window.start, "end": window.end}
    since = _recording_since(connection)
    values: dict[str, Any] = {"recording_since": since}
    truncated = False

    def take(sql: str, extra: Mapping[str, Any] | None = None) -> list[dict[str, Any]]:
        nonlocal truncated
        rows, over = _rows(connection, sql, {**params, **(extra or {})})
        truncated = truncated or over
        return rows

    if metric_id in {"findings.open-by-band", "findings.backlog-age-by-band", "quality.evidence-freshness"}:
        values["open_findings"] = take(
            f"""
            SELECT f.finding_id, f.first_seen_at, f.evidence_freshness, d.action_band
            FROM findings f
            LEFT JOIN finding_decisions d ON d.finding_id = f.finding_id AND d.decision_state = 'current'
            WHERE f.status IN ('active', 'acknowledged') AND {_SITE.format(column="f.site_id")}
            ORDER BY f.finding_id
            """
        )
    elif metric_id == "findings.band-episode-duration":
        # The full recorded history before the window end of every finding
        # with a row in the window or a band in effect at the window start, so
        # an episode's true start is known.
        values["decision_history"] = take(
            f"""
            WITH scoped AS (
                SELECT h.* FROM finding_decision_history h
                WHERE {_SITE.format(column="h.site_id")} AND h.evaluated_at < :end
            ),
            relevant AS (
                SELECT finding_id FROM scoped WHERE evaluated_at >= :start
                UNION
                SELECT finding_id FROM (
                    SELECT DISTINCT ON (finding_id) finding_id, decision_state
                    FROM scoped WHERE evaluated_at < :start
                    ORDER BY finding_id, revision DESC
                ) prior
                WHERE decision_state = 'current'
            )
            SELECT s.finding_id, s.revision, s.evaluated_at, s.decision_state, s.action_band,
                   s.previous_action_band, s.transition_cause, f.created_at AS finding_created_at
            FROM scoped s
            JOIN relevant r ON r.finding_id = s.finding_id
            JOIN findings f ON f.finding_id = s.finding_id
            ORDER BY s.finding_id, s.revision
            """
        )
    elif metric_id in {"findings.band-transitions", "findings.reopened"}:
        rows = take(
            f"""
            SELECT h.finding_id, h.revision, h.evaluated_at, h.decision_state, h.action_band,
                   h.previous_action_band, h.transition_cause
            FROM finding_decision_history h
            WHERE {_SITE.format(column="h.site_id")} AND h.evaluated_at >= :start AND h.evaluated_at < :end
            ORDER BY h.finding_id, h.revision
            """
        )
        values["decision_history"] = rows
        if metric_id == "findings.reopened":
            reopened = sorted({row["finding_id"] for row in rows if row["transition_cause"] == "finding-reopened"})
            verified: dict[str, list[datetime]] = {}
            if reopened:
                for row in take(
                    """
                    SELECT finding_id, evaluated_at FROM finding_verification_history
                    WHERE finding_id = ANY(:ids) AND verification_state = 'verified' AND evaluated_at < :end
                    ORDER BY finding_id, evaluated_at
                    """,
                    {"ids": reopened},
                ):
                    verified.setdefault(row["finding_id"], []).append(row["evaluated_at"])
            values["verified_times"] = verified
    elif metric_id.startswith("remediation.") and metric_id != "remediation.done-unverified" or (
        metric_id == "quality.unmeasurable-outcomes"
    ):
        # Reports made in the window, plus reports first verified in it.
        reports = take(
            f"""
            SELECT e.work_item_id, e.finding_id, e.revision, e.occurred_at, f.first_seen_at AS finding_first_seen_at
            FROM finding_work_events e
            JOIN findings f ON f.finding_id = e.finding_id
            WHERE {_SITE.format(column="e.site_id")}
              AND e.event_type = 'status_changed' AND e.to_status = 'done' AND e.occurred_at < :end
              AND (
                  e.occurred_at >= :start
                  OR EXISTS (
                      SELECT 1 FROM finding_verification_history v
                      WHERE v.work_item_id = e.work_item_id AND v.report_revision = e.revision
                        AND v.verification_state = 'verified'
                        AND v.evaluated_at >= :start AND v.evaluated_at < :end
                  )
              )
            ORDER BY e.work_item_id, e.revision
            """
        )
        values["reports"] = reports
        work_items = sorted({row["work_item_id"] for row in reports})
        values["verification_history"] = take(
            """
            SELECT work_item_id, report_revision, sequence, verification_state, evaluated_at
            FROM finding_verification_history
            WHERE work_item_id = ANY(:ids) AND evaluated_at < :end
            ORDER BY work_item_id, report_revision, sequence
            """,
            {"ids": work_items},
        ) if work_items else []
    elif metric_id == "remediation.done-unverified":
        values["done_items"] = take(
            f"""
            SELECT w.work_item_id, w.finding_id, report.revision AS report_revision, latest.verification_state
            FROM finding_work_items w
            LEFT JOIN LATERAL (
                SELECT e.revision FROM finding_work_events e
                WHERE e.work_item_id = w.work_item_id AND e.event_type = 'status_changed' AND e.to_status = 'done'
                ORDER BY e.revision DESC LIMIT 1
            ) report ON TRUE
            LEFT JOIN LATERAL (
                SELECT v.verification_state FROM finding_verification_history v
                WHERE v.work_item_id = w.work_item_id AND v.report_revision = report.revision
                ORDER BY v.sequence DESC LIMIT 1
            ) latest ON TRUE
            WHERE w.work_status = 'done' AND {_SITE.format(column="w.site_id")}
            ORDER BY w.work_item_id
            """
        )
    elif metric_id == "quality.verification-run-coverage":
        values["evaluation_runs"] = take(
            f"""
            SELECT r.run_id, r.started_at, v.status AS verification_status
            FROM finding_evaluation_runs r
            LEFT JOIN finding_verification_runs v ON v.evaluation_run_id = r.run_id
            WHERE r.status = 'completed' AND r.started_at >= :start AND r.started_at < :end
              AND (CAST(:site_id AS TEXT) IS NULL OR r.scope_site_id IS NULL OR r.scope_site_id = :site_id)
            ORDER BY r.started_at, r.run_id
            """
        )
    elif metric_id == "quality.history-coverage":
        coverage = []
        row = connection.execute(
            text(
                f"""
                SELECT COUNT(*) AS total,
                       COUNT(*) FILTER (WHERE created_at < :work) AS work,
                       COUNT(*) FILTER (WHERE created_at < :decision) AS decision,
                       COUNT(*) FILTER (WHERE created_at < :verification) AS verification
                FROM findings WHERE {_SITE.format(column="site_id")}
                """
            ),
            {"site_id": site_id, "work": since["work-events"], "decision": since["decision-history"],
             "verification": since["verification-history"]},
        ).mappings().one()
        for source, key in (("work-events", "work"), ("decision-history", "decision"),
                            ("verification-history", "verification")):
            if since[source] is not None:
                coverage.append({"source": source, "findings_total": row["total"], "findings_before": row[key]})
        values["history_coverage"] = coverage

    if definition.reads_verification:
        values["degraded_verification_runs"] = _degraded_runs(connection, window, site_id)
    values["truncated"] = truncated
    return MetricInputs(**values)


def _degraded_runs(connection: Any, window: MetricWindow, site_id: str | None) -> int:
    """Failed or incomplete verification in the window, or in the latest run for current metrics."""

    scope = "(CAST(:site_id AS TEXT) IS NULL OR r.scope_site_id IS NULL OR r.scope_site_id = :site_id)"
    if window.start is not None:
        sql = f"""
            SELECT COUNT(*) FROM finding_evaluation_runs r
            JOIN finding_verification_runs v ON v.evaluation_run_id = r.run_id
            WHERE r.started_at >= :start AND r.started_at < :end AND v.status IN ('failed', 'incomplete')
              AND {scope}
        """
    else:
        sql = f"""
            SELECT COUNT(*) FROM (
                SELECT v.status FROM finding_evaluation_runs r
                LEFT JOIN finding_verification_runs v ON v.evaluation_run_id = r.run_id
                WHERE r.status = 'completed' AND {scope}
                ORDER BY r.started_at DESC, r.run_id DESC LIMIT 1
            ) latest WHERE latest.status IN ('failed', 'incomplete')
        """
    return int(connection.execute(text(sql), {"site_id": site_id, "start": window.start,
                                              "end": window.end}).scalar_one())


def _freshness(connection: Any, definition: MetricDefinition, site_id: str | None) -> list[dict[str, Any]]:
    """When the sources this metric reads were last written, in scope."""

    items = [
        {
            "source": "finding-evaluation",
            "latest_record_at": connection.execute(
                text(
                    """
                    SELECT MAX(completed_at) FROM finding_evaluation_runs r
                    WHERE r.status = 'completed'
                      AND (CAST(:site_id AS TEXT) IS NULL OR r.scope_site_id IS NULL OR r.scope_site_id = :site_id)
                    """
                ),
                {"site_id": site_id},
            ).scalar_one(),
        }
    ]
    if "finding_work_events" in definition.source_records or "finding_work_items" in definition.source_records:
        items.append(
            {
                "source": "work-events",
                "latest_record_at": connection.execute(
                    text(f"SELECT MAX(occurred_at) FROM finding_work_events WHERE {_SITE.format(column='site_id')}"),
                    {"site_id": site_id},
                ).scalar_one(),
            }
        )
    return items
