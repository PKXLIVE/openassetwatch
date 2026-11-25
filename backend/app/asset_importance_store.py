"""Persistence for audited asset importance (CTEM-GAP-02).

This store writes only ``asset_importance_assignments`` and the append-only
``asset_importance_events``. It never writes findings, evidence, risk scores,
decisions, or finding work tracking. The asset's site always comes from the
request path and is enforced against ``control_tower_assets`` by a composite
foreign key, so an asset cannot be assigned under another site.

Withdrawal keeps the current record (state ``withdrawn``, importance
``unknown``) and appends a ``withdrawn`` event that records the value being
withdrawn. Earlier events keep the prior value, actor label, reason, and time.
Nothing is physically deleted except by the cascade that removes the asset.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from sqlalchemy import text

from .asset_importance import (
    ASSIGNABLE_IMPORTANCE,
    IMPORTANCE_PRINCIPAL,
    assignment_event_type,
    direction,
    effective_source,
    review_state,
    validate_assignable,
)


MAX_IMPORTANCE_PAGE = 200
MAX_IMPORTANCE_OFFSET = 10_000
EFFECTIVE_FILTER_VALUES = frozenset({*ASSIGNABLE_IMPORTANCE, "unknown"})

AssetImportanceErrorKind = Literal["asset_not_found", "not_found", "conflict"]


class AssetImportanceError(Exception):
    """Bounded, caller-safe importance failure."""

    def __init__(self, kind: AssetImportanceErrorKind, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind
        self.detail = detail


def _bounded_page(limit: int, offset: int) -> tuple[int, int]:
    return max(1, min(limit, MAX_IMPORTANCE_PAGE)), max(0, min(offset, MAX_IMPORTANCE_OFFSET))


def history_agrees(row: dict[str, Any], latest_event: dict[str, Any] | None) -> bool:
    """True when the current record is exactly what its latest event wrote.

    Every authoritative field must match: revision, value, reason, principal,
    actor label, actor verification, and time. A missing, older, or altered
    event, or an altered record, fails the check.
    """

    if latest_event is None:
        return False
    return (
        int(latest_event["revision"]) == int(row["revision"])
        and latest_event["importance"] == row["importance"]
        and latest_event["reason"] == row["reason"]
        and latest_event["principal"] == row["principal"]
        and latest_event["actor_label"] == row["actor_label"]
        and latest_event["actor_verification"] == row["actor_verification"]
        and latest_event["occurred_at"] == row["updated_at"]
        and latest_event["occurred_at"] == row["reviewed_at"]
    )


def project_assignment(
    site_id: str,
    asset_id: str,
    row: dict[str, Any] | None,
    latest_event: dict[str, Any] | None,
    *,
    now: datetime,
) -> dict[str, Any]:
    """Effective importance for one asset. Fails safe to `unknown`."""

    if row is None:
        return {
            "site_id": site_id,
            "asset_id": asset_id,
            "importance": "unknown",
            "importance_source": "unassigned",
            "assignment_state": "none",
            "integrity_state": "not-applicable",
            "recorded_importance": None,
            "revision": None,
            "reason": None,
            "principal": None,
            "actor_label": None,
            "actor_verification": None,
            "created_at": None,
            "reviewed_at": None,
            "updated_at": None,
            "review_state": "not-applicable",
        }
    consistent = history_agrees(row, latest_event)
    effective = row["importance"] if consistent and row["assignment_state"] == "assigned" else "unknown"
    return {
        "site_id": site_id,
        "asset_id": asset_id,
        "importance": effective,
        "importance_source": effective_source(effective),
        "assignment_state": row["assignment_state"],
        "integrity_state": "consistent" if consistent else "inconsistent",
        "recorded_importance": row["importance"],
        "revision": int(row["revision"]),
        "reason": row["reason"],
        "principal": row["principal"],
        "actor_label": row["actor_label"],
        "actor_verification": row["actor_verification"],
        "created_at": row["created_at"],
        "reviewed_at": row["reviewed_at"],
        "updated_at": row["updated_at"],
        "review_state": review_state(effective, row["reviewed_at"], now),
    }


def project_event(row: dict[str, Any]) -> dict[str, Any]:
    moved = direction(row["previous_importance"], row["importance"])
    sensitive = moved in {"lowered", "withdrawn"}
    return {
        "event_id": int(row["event_id"]),
        "site_id": row["site_id"],
        "asset_id": row["asset_id"],
        "revision": int(row["revision"]),
        "event_type": row["event_type"],
        "previous_importance": row["previous_importance"],
        "importance": row["importance"],
        "direction": moved,
        "security_sensitive": sensitive,
        "independent_review": "recommended-not-enforced" if sensitive else "not-required",
        "reason": row["reason"],
        "principal": row["principal"],
        "actor_label": row["actor_label"],
        "actor_verification": row["actor_verification"],
        "occurred_at": row["occurred_at"],
    }


_LATEST_EVENT = """
    SELECT event_id, site_id, asset_id, revision, event_type, previous_importance,
           importance, reason, principal, actor_label, actor_verification, occurred_at
    FROM asset_importance_events
    WHERE site_id = :site_id AND asset_id = :asset_id
    ORDER BY revision DESC
    LIMIT 1
"""


class SqlAssetImportanceStore:
    def _engine(self):
        from .database import get_engine

        return get_engine()

    def ensure_schema(self) -> None:
        from .database import ensure_database_schema

        ensure_database_schema()

    # ------------------------------------------------------------------ reads

    @staticmethod
    def _asset_exists(connection: Any, site_id: str, asset_id: str, *, lock: bool = False) -> bool:
        row = connection.execute(
            text(
                "SELECT 1 FROM control_tower_assets WHERE site_id = :site_id AND asset_id = :asset_id"
                + (" FOR KEY SHARE" if lock else "")
            ),
            {"site_id": site_id, "asset_id": asset_id},
        ).first()
        return row is not None

    @staticmethod
    def _assignment(connection: Any, site_id: str, asset_id: str, *, lock: bool = False) -> dict[str, Any] | None:
        row = connection.execute(
            text(
                "SELECT * FROM asset_importance_assignments"
                " WHERE site_id = :site_id AND asset_id = :asset_id"
                + (" FOR UPDATE" if lock else "")
            ),
            {"site_id": site_id, "asset_id": asset_id},
        ).mappings().first()
        return dict(row) if row is not None else None

    @staticmethod
    def _latest_event(connection: Any, site_id: str, asset_id: str) -> dict[str, Any] | None:
        row = connection.execute(
            text(_LATEST_EVENT), {"site_id": site_id, "asset_id": asset_id}
        ).mappings().first()
        return dict(row) if row is not None else None

    def get_importance(self, site_id: str, asset_id: str, *, now: datetime) -> dict[str, Any] | None:
        """Effective importance, or None when the asset does not exist in that site."""

        self.ensure_schema()
        with self._engine().begin() as connection:
            if not self._asset_exists(connection, site_id, asset_id):
                return None
            row = self._assignment(connection, site_id, asset_id)
            latest = self._latest_event(connection, site_id, asset_id) if row else None
            return project_assignment(site_id, asset_id, row, latest, now=now)

    def list_importance(
        self,
        *,
        site_id: str | None = None,
        importance: str | None = None,
        limit: int = 50,
        offset: int = 0,
        now: datetime,
    ) -> dict[str, Any]:
        """Assets that have an assignment record. Assets with none are unknown."""

        self.ensure_schema()
        if importance is not None and importance not in EFFECTIVE_FILTER_VALUES:
            raise ValueError("invalid importance")
        bounded_limit, bounded_offset = _bounded_page(limit, offset)
        clauses: list[str] = []
        params: dict[str, Any] = {}
        if site_id is not None:
            clauses.append("a.site_id = :site_id")
            params["site_id"] = site_id
        if importance is not None:
            clauses.append("a.importance = :importance")
            params["importance"] = importance
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._engine().begin() as connection:
            total = int(
                connection.execute(
                    text("SELECT COUNT(*) FROM asset_importance_assignments AS a" + where), params
                ).scalar_one()
            )
            rows = connection.execute(
                text(
                    """
                    SELECT a.*, latest.revision AS latest_revision,
                           latest.importance AS latest_importance,
                           latest.reason AS latest_reason,
                           latest.principal AS latest_principal,
                           latest.actor_label AS latest_actor_label,
                           latest.actor_verification AS latest_actor_verification,
                           latest.occurred_at AS latest_occurred_at
                    FROM asset_importance_assignments AS a
                    LEFT JOIN LATERAL (
                        SELECT e.revision, e.importance, e.reason, e.principal,
                               e.actor_label, e.actor_verification, e.occurred_at
                        FROM asset_importance_events AS e
                        WHERE e.site_id = a.site_id AND e.asset_id = a.asset_id
                        ORDER BY e.revision DESC
                        LIMIT 1
                    ) AS latest ON TRUE
                    """
                    + where
                    + " ORDER BY CASE a.importance WHEN 'critical' THEN 1 WHEN 'high' THEN 2"
                    " WHEN 'standard' THEN 3 WHEN 'low' THEN 4 ELSE 5 END,"
                    " a.site_id, a.asset_id LIMIT :limit OFFSET :offset"
                ),
                {**params, "limit": bounded_limit, "offset": bounded_offset},
            ).mappings().all()
        items = []
        for raw in rows:
            row = dict(raw)
            latest = (
                {
                    field: row[f"latest_{field}"]
                    for field in (
                        "revision", "importance", "reason", "principal",
                        "actor_label", "actor_verification", "occurred_at",
                    )
                }
                if row["latest_revision"] is not None
                else None
            )
            items.append(project_assignment(row["site_id"], row["asset_id"], row, latest, now=now))
        return {
            "items": items,
            "total": total,
            "limit": bounded_limit,
            "offset": bounded_offset,
            "truncated": bounded_offset + len(items) < total,
        }

    def list_history(
        self, site_id: str, asset_id: str, *, limit: int = 50, offset: int = 0
    ) -> dict[str, Any] | None:
        self.ensure_schema()
        bounded_limit, bounded_offset = _bounded_page(limit, offset)
        with self._engine().begin() as connection:
            if not self._asset_exists(connection, site_id, asset_id):
                return None
            params = {"site_id": site_id, "asset_id": asset_id}
            total = int(
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM asset_importance_events"
                        " WHERE site_id = :site_id AND asset_id = :asset_id"
                    ),
                    params,
                ).scalar_one()
            )
            rows = connection.execute(
                text(
                    """
                    SELECT event_id, site_id, asset_id, revision, event_type,
                           previous_importance, importance, reason, principal,
                           actor_label, actor_verification, occurred_at
                    FROM asset_importance_events
                    WHERE site_id = :site_id AND asset_id = :asset_id
                    ORDER BY revision
                    LIMIT :limit OFFSET :offset
                    """
                ),
                {**params, "limit": bounded_limit, "offset": bounded_offset},
            ).mappings().all()
        items = [project_event(dict(row)) for row in rows]
        return {
            "items": items,
            "total": total,
            "limit": bounded_limit,
            "offset": bounded_offset,
            "truncated": bounded_offset + len(items) < total,
        }

    # --------------------------------------------------------------- mutations

    @staticmethod
    def _append_event(
        connection: Any,
        *,
        site_id: str,
        asset_id: str,
        revision: int,
        event_type: str,
        previous: str | None,
        importance: str,
        reason: str,
        actor: str,
        at: datetime,
    ) -> dict[str, Any]:
        row = connection.execute(
            text(
                """
                INSERT INTO asset_importance_events (
                    site_id, asset_id, revision, event_type, previous_importance,
                    importance, reason, principal, actor_label, actor_verification,
                    occurred_at
                ) VALUES (
                    :site_id, :asset_id, :revision, :event_type, :previous,
                    :importance, :reason, :principal, :actor, 'unverified', :at
                )
                RETURNING *
                """
            ),
            {
                "site_id": site_id,
                "asset_id": asset_id,
                "revision": revision,
                "event_type": event_type,
                "previous": previous,
                "importance": importance,
                "reason": reason,
                "principal": IMPORTANCE_PRINCIPAL,
                "actor": actor,
                "at": at,
            },
        ).mappings().one()
        return dict(row)

    def _locked_current(
        self,
        connection: Any,
        site_id: str,
        asset_id: str,
        expected_revision: int | None,
        *,
        require_existing: bool = False,
    ) -> dict[str, Any] | None:
        if not self._asset_exists(connection, site_id, asset_id, lock=True):
            raise AssetImportanceError("asset_not_found", "asset not found in this site")
        row = self._assignment(connection, site_id, asset_id, lock=True)
        if row is None:
            if require_existing:
                raise AssetImportanceError("not_found", "asset has no importance assignment")
            if expected_revision is not None:
                raise AssetImportanceError(
                    "conflict", "asset has no importance record; omit expected_revision"
                )
            return None
        if expected_revision is None or int(row["revision"]) != expected_revision:
            raise AssetImportanceError(
                "conflict", "importance revision does not match expected_revision"
            )
        latest = self._latest_event(connection, site_id, asset_id)
        if not history_agrees(row, latest):
            # Never build on a record that disagrees with its history.
            raise AssetImportanceError(
                "conflict", "importance record disagrees with its history; changes are refused"
            )
        return row

    @staticmethod
    def _update(connection: Any, row: dict[str, Any], values: dict[str, Any]) -> None:
        result = connection.execute(
            text(
                """
                UPDATE asset_importance_assignments SET
                    importance = :importance,
                    assignment_state = :assignment_state,
                    reason = :reason,
                    actor_label = :actor,
                    revision = :revision,
                    reviewed_at = :at,
                    updated_at = :at
                WHERE site_id = :site_id AND asset_id = :asset_id
                  AND revision = :previous_revision
                """
            ),
            {
                **values,
                "site_id": row["site_id"],
                "asset_id": row["asset_id"],
                "previous_revision": int(row["revision"]),
            },
        )
        if result.rowcount != 1:
            raise AssetImportanceError(
                "conflict", "importance revision does not match expected_revision"
            )

    def assign(
        self,
        site_id: str,
        asset_id: str,
        *,
        importance: str,
        reason: str,
        actor: str,
        expected_revision: int | None,
        at: datetime,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Assign, change, or re-affirm importance. Returns (current, event)."""

        self.ensure_schema()
        importance = validate_assignable(importance)
        with self._engine().begin() as connection:
            row = self._locked_current(connection, site_id, asset_id, expected_revision)
            if row is None:
                created = connection.execute(
                    text(
                        """
                        INSERT INTO asset_importance_assignments (
                            site_id, asset_id, importance, assignment_state, source,
                            reason, revision, principal, actor_label,
                            actor_verification, created_at, reviewed_at, updated_at
                        ) VALUES (
                            :site_id, :asset_id, :importance, 'assigned', 'operator',
                            :reason, 1, :principal, :actor, 'unverified', :at, :at, :at
                        )
                        ON CONFLICT (site_id, asset_id) DO NOTHING
                        RETURNING site_id
                        """
                    ),
                    {
                        "site_id": site_id,
                        "asset_id": asset_id,
                        "importance": importance,
                        "reason": reason,
                        "principal": IMPORTANCE_PRINCIPAL,
                        "actor": actor,
                        "at": at,
                    },
                ).first()
                if created is None:
                    raise AssetImportanceError(
                        "conflict", "importance was assigned concurrently; reload and retry"
                    )
                event = self._append_event(
                    connection,
                    site_id=site_id,
                    asset_id=asset_id,
                    revision=1,
                    event_type="assigned",
                    previous=None,
                    importance=importance,
                    reason=reason,
                    actor=actor,
                    at=at,
                )
            else:
                event_type = assignment_event_type(row["importance"], importance)
                revision = int(row["revision"]) + 1
                # Timestamps never move backwards, even with a skewed caller clock.
                effective_at = max(at, row["updated_at"])
                self._update(
                    connection,
                    row,
                    {
                        "importance": importance,
                        "assignment_state": "assigned",
                        "reason": reason,
                        "actor": actor,
                        "revision": revision,
                        "at": effective_at,
                    },
                )
                event = self._append_event(
                    connection,
                    site_id=site_id,
                    asset_id=asset_id,
                    revision=revision,
                    event_type=event_type,
                    previous=row["importance"],
                    importance=importance,
                    reason=reason,
                    actor=actor,
                    at=effective_at,
                )
            current = self._assignment(connection, site_id, asset_id)
            latest = self._latest_event(connection, site_id, asset_id)
            return project_assignment(site_id, asset_id, current, latest, now=at), project_event(event)

    def withdraw(
        self,
        site_id: str,
        asset_id: str,
        *,
        reason: str,
        actor: str,
        expected_revision: int,
        at: datetime,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Make effective importance unknown while keeping all history."""

        self.ensure_schema()
        with self._engine().begin() as connection:
            row = self._locked_current(
                connection, site_id, asset_id, expected_revision, require_existing=True
            )
            assert row is not None
            if row["assignment_state"] != "assigned":
                raise AssetImportanceError("conflict", "importance is already withdrawn")
            revision = int(row["revision"]) + 1
            effective_at = max(at, row["updated_at"])
            self._update(
                connection,
                row,
                {
                    "importance": "unknown",
                    "assignment_state": "withdrawn",
                    "reason": reason,
                    "actor": actor,
                    "revision": revision,
                    "at": effective_at,
                },
            )
            event = self._append_event(
                connection,
                site_id=site_id,
                asset_id=asset_id,
                revision=revision,
                event_type="withdrawn",
                previous=row["importance"],
                importance="unknown",
                reason=reason,
                actor=actor,
                at=effective_at,
            )
            current = self._assignment(connection, site_id, asset_id)
            latest = self._latest_event(connection, site_id, asset_id)
            return project_assignment(site_id, asset_id, current, latest, now=at), project_event(event)


__all__ = [
    "AssetImportanceError",
    "SqlAssetImportanceStore",
    "history_agrees",
    "project_assignment",
    "project_event",
]
