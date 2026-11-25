"""Persistence for manual finding work tracking.

Work items are coordination metadata attached to a deterministic finding.
This store never writes to ``findings``, ``finding_evidence``, or any risk
table: finding status and risk remain owned exclusively by the evidence-based
reconciliation path in ``finding_store``. The work item's site is always
derived from the referenced finding row (and enforced by a composite foreign
key), never taken from a request.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import uuid4

from sqlalchemy import text

from .finding_work_contracts import (
    MAX_ACTIVE_WORK_REFERENCES,
    WORK_ACTOR_PRINCIPAL,
    WORK_STATUS_TRANSITIONS,
)
from .verification_store import capture_baseline


MAX_WORK_PAGE = 200
MAX_WORK_OFFSET = 10_000
WORK_STATUSES = frozenset(WORK_STATUS_TRANSITIONS)

FindingWorkErrorKind = Literal["finding_not_found", "not_found", "conflict"]


class FindingWorkError(Exception):
    """Bounded, caller-safe work-tracking failure."""

    def __init__(self, kind: FindingWorkErrorKind, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind
        self.detail = detail


def validate_status_transition(current: str, target: str) -> None:
    if target not in WORK_STATUSES:
        raise FindingWorkError("conflict", "unknown work status")
    if current == target:
        raise FindingWorkError("conflict", "work item already has this status")
    if target not in WORK_STATUS_TRANSITIONS.get(current, frozenset()):
        raise FindingWorkError(
            "conflict",
            f"work status cannot change from {current} to {target}",
        )


def _bounded_page(limit: int, offset: int) -> tuple[int, int]:
    return max(1, min(limit, MAX_WORK_PAGE)), max(0, min(offset, MAX_WORK_OFFSET))


class SqlFindingWorkStore:
    def _engine(self):
        from .database import get_engine

        return get_engine()

    def ensure_schema(self) -> None:
        from .database import ensure_database_schema

        ensure_database_schema()

    # ------------------------------------------------------------------ reads

    @staticmethod
    def _project_item(row: dict[str, Any]) -> dict[str, Any]:
        owner = None
        if row.get("owner_kind") is not None:
            owner = {
                "kind": row["owner_kind"],
                "label": row["owner_label"],
                "verification": row["owner_verification"],
            }
        return {
            "work_item_id": row["work_item_id"],
            "finding_id": row["finding_id"],
            "site_id": row["site_id"],
            "work_status": row["work_status"],
            "owner": owner,
            "revision": int(row["revision"]),
            "finding_status": row["finding_status"],
            "created_principal": row["created_principal"],
            "created_actor_label": row["created_actor_label"],
            "actor_verification": row["actor_verification"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "references": [],
        }

    @staticmethod
    def _attach_references(connection: Any, items: list[dict[str, Any]]) -> None:
        if not items:
            return
        by_item = {item["work_item_id"]: item for item in items}
        rows = connection.execute(
            text(
                """
                SELECT reference_id, work_item_id, reference_type,
                       reference_system, reference_label,
                       reference_verification, added_actor_label, added_at
                FROM finding_work_references
                WHERE work_item_id = ANY(:work_item_ids)
                  AND removed_at IS NULL
                ORDER BY work_item_id, added_at, reference_id
                """
            ),
            {"work_item_ids": list(by_item)},
        ).mappings().all()
        for row in rows:
            by_item[row["work_item_id"]]["references"].append(
                {
                    "reference_id": row["reference_id"],
                    "reference_type": row["reference_type"],
                    "reference_system": row["reference_system"],
                    "reference_label": row["reference_label"],
                    "verification": row["reference_verification"],
                    "added_actor_label": row["added_actor_label"],
                    "added_at": row["added_at"],
                }
            )

    _ITEM_SELECT = """
        SELECT work.*, findings.status AS finding_status
        FROM finding_work_items AS work
        JOIN findings
          ON findings.finding_id = work.finding_id
         AND findings.site_id = work.site_id
    """

    def _load_item(self, connection: Any, finding_id: str) -> dict[str, Any] | None:
        row = connection.execute(
            text(self._ITEM_SELECT + " WHERE work.finding_id = :finding_id"),
            {"finding_id": finding_id},
        ).mappings().first()
        if row is None:
            return None
        item = self._project_item(dict(row))
        self._attach_references(connection, [item])
        return item

    def get_work_item(self, finding_id: str) -> dict[str, Any] | None:
        self.ensure_schema()
        with self._engine().begin() as connection:
            return self._load_item(connection, finding_id)

    def list_work_items(
        self,
        *,
        site_id: str | None = None,
        work_status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        self.ensure_schema()
        if work_status is not None and work_status not in WORK_STATUSES:
            raise ValueError("invalid work status")
        bounded_limit, bounded_offset = _bounded_page(limit, offset)
        clauses: list[str] = []
        params: dict[str, Any] = {}
        if site_id is not None:
            clauses.append("work.site_id = :site_id")
            params["site_id"] = site_id
        if work_status is not None:
            clauses.append("work.work_status = :work_status")
            params["work_status"] = work_status
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._engine().begin() as connection:
            total = int(
                connection.execute(
                    text("SELECT COUNT(*) FROM finding_work_items AS work" + where),
                    params,
                ).scalar_one()
            )
            rows = connection.execute(
                text(
                    self._ITEM_SELECT
                    + where
                    + " ORDER BY work.updated_at DESC, work.work_item_id"
                    " LIMIT :limit OFFSET :offset"
                ),
                {**params, "limit": bounded_limit, "offset": bounded_offset},
            ).mappings().all()
            items = [self._project_item(dict(row)) for row in rows]
            self._attach_references(connection, items)
        return {
            "items": items,
            "total": total,
            "limit": bounded_limit,
            "offset": bounded_offset,
            "truncated": bounded_offset + len(items) < total,
        }

    def list_events(
        self,
        finding_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any] | None:
        self.ensure_schema()
        bounded_limit, bounded_offset = _bounded_page(limit, offset)
        with self._engine().begin() as connection:
            work_item_id = connection.execute(
                text(
                    "SELECT work_item_id FROM finding_work_items "
                    "WHERE finding_id = :finding_id"
                ),
                {"finding_id": finding_id},
            ).scalar_one_or_none()
            if work_item_id is None:
                return None
            total = int(
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM finding_work_events "
                        "WHERE work_item_id = :work_item_id"
                    ),
                    {"work_item_id": work_item_id},
                ).scalar_one()
            )
            rows = connection.execute(
                text(
                    """
                    SELECT event_id, work_item_id, finding_id, site_id, revision,
                           event_type, from_status, to_status, owner_kind,
                           owner_label, reference_id, note, finding_status,
                           principal, actor_label, actor_verification, occurred_at
                    FROM finding_work_events
                    WHERE work_item_id = :work_item_id
                    ORDER BY revision, event_id
                    LIMIT :limit OFFSET :offset
                    """
                ),
                {
                    "work_item_id": work_item_id,
                    "limit": bounded_limit,
                    "offset": bounded_offset,
                },
            ).mappings().all()
        items = [dict(row) for row in rows]
        return {
            "items": items,
            "total": total,
            "limit": bounded_limit,
            "offset": bounded_offset,
            "truncated": bounded_offset + len(items) < total,
        }

    # --------------------------------------------------------------- mutations

    @staticmethod
    def _finding_for_work(connection: Any, finding_id: str) -> dict[str, Any]:
        # FOR KEY SHARE keeps the finding's identity stable for this
        # transaction without blocking evidence reconciliation's
        # non-key updates of finding status.
        row = connection.execute(
            text(
                """
                SELECT finding_id, site_id, status
                FROM findings
                WHERE finding_id = :finding_id
                FOR KEY SHARE
                """
            ),
            {"finding_id": finding_id},
        ).mappings().first()
        if row is None:
            raise FindingWorkError("finding_not_found", "finding not found")
        return dict(row)

    @staticmethod
    def _lock_item(
        connection: Any,
        finding_id: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        row = connection.execute(
            text(
                """
                SELECT *
                FROM finding_work_items
                WHERE finding_id = :finding_id
                FOR UPDATE
                """
            ),
            {"finding_id": finding_id},
        ).mappings().first()
        if row is None:
            raise FindingWorkError("not_found", "work item not found")
        item = dict(row)
        if int(item["revision"]) != expected_revision:
            raise FindingWorkError(
                "conflict",
                "work item revision does not match expected_revision",
            )
        return item

    @staticmethod
    def _append_event(
        connection: Any,
        *,
        item: dict[str, Any],
        revision: int,
        event_type: str,
        finding_status: str,
        actor: str,
        at: datetime,
        from_status: str | None = None,
        to_status: str | None = None,
        owner_kind: str | None = None,
        owner_label: str | None = None,
        reference_id: str | None = None,
        note: str | None = None,
    ) -> None:
        connection.execute(
            text(
                """
                INSERT INTO finding_work_events (
                    work_item_id, finding_id, site_id, revision, event_type,
                    from_status, to_status, owner_kind, owner_label,
                    reference_id, note, finding_status, principal,
                    actor_label, actor_verification, occurred_at
                ) VALUES (
                    :work_item_id, :finding_id, :site_id, :revision, :event_type,
                    :from_status, :to_status, :owner_kind, :owner_label,
                    :reference_id, :note, :finding_status, :principal,
                    :actor_label, 'unverified', :occurred_at
                )
                """
            ),
            {
                "work_item_id": item["work_item_id"],
                "finding_id": item["finding_id"],
                "site_id": item["site_id"],
                "revision": revision,
                "event_type": event_type,
                "from_status": from_status,
                "to_status": to_status,
                "owner_kind": owner_kind,
                "owner_label": owner_label,
                "reference_id": reference_id,
                "note": note,
                "finding_status": finding_status,
                "principal": WORK_ACTOR_PRINCIPAL,
                "actor_label": actor,
                "occurred_at": at,
            },
        )

    @staticmethod
    def _bump(
        connection: Any,
        item: dict[str, Any],
        *,
        at: datetime,
        work_status: str | None = None,
        owner: tuple[str | None, str | None] | None = None,
    ) -> int:
        revision = int(item["revision"]) + 1
        assignments = ["revision = :revision", "updated_at = GREATEST(updated_at, :at)"]
        params: dict[str, Any] = {
            "work_item_id": item["work_item_id"],
            "revision": revision,
            "previous_revision": int(item["revision"]),
            "at": at,
        }
        if work_status is not None:
            assignments.append("work_status = :work_status")
            params["work_status"] = work_status
        if owner is not None:
            assignments.append("owner_kind = :owner_kind")
            assignments.append("owner_label = :owner_label")
            params["owner_kind"], params["owner_label"] = owner
        result = connection.execute(
            text(
                "UPDATE finding_work_items SET "
                + ", ".join(assignments)
                + " WHERE work_item_id = :work_item_id"
                " AND revision = :previous_revision"
            ),
            params,
        )
        if result.rowcount != 1:
            raise FindingWorkError(
                "conflict",
                "work item revision does not match expected_revision",
            )
        return revision

    def create_work_item(
        self,
        finding_id: str,
        *,
        actor: str,
        owner_kind: str | None,
        owner_label: str | None,
        note: str | None,
        at: datetime,
    ) -> dict[str, Any]:
        self.ensure_schema()
        if (owner_kind is None) != (owner_label is None):
            raise ValueError("owner_kind and owner_label must be supplied together")
        with self._engine().begin() as connection:
            finding = self._finding_for_work(connection, finding_id)
            if finding["status"] == "resolved":
                raise FindingWorkError(
                    "conflict",
                    "work tracking cannot be started for a resolved finding",
                )
            work_item_id = "fwi_" + uuid4().hex
            created = connection.execute(
                text(
                    """
                    INSERT INTO finding_work_items (
                        work_item_id, finding_id, site_id, work_status,
                        owner_kind, owner_label, owner_verification, revision,
                        created_principal, created_actor_label,
                        actor_verification, created_at, updated_at
                    ) VALUES (
                        :work_item_id, :finding_id, :site_id, 'open',
                        :owner_kind, :owner_label, 'unverified', 1,
                        :principal, :actor, 'unverified', :at, :at
                    )
                    ON CONFLICT (finding_id) DO NOTHING
                    RETURNING *
                    """
                ),
                {
                    "work_item_id": work_item_id,
                    "finding_id": finding["finding_id"],
                    # Site comes from the finding row, never from the request.
                    "site_id": finding["site_id"],
                    "owner_kind": owner_kind,
                    "owner_label": owner_label,
                    "principal": WORK_ACTOR_PRINCIPAL,
                    "actor": actor,
                    "at": at,
                },
            ).mappings().first()
            if created is None:
                raise FindingWorkError("conflict", "work item already exists for this finding")
            item = dict(created)
            self._append_event(
                connection,
                item=item,
                revision=1,
                event_type="created",
                finding_status=finding["status"],
                actor=actor,
                at=at,
                to_status="open",
                owner_kind=owner_kind,
                owner_label=owner_label,
                note=note,
            )
            loaded = self._load_item(connection, finding_id)
        assert loaded is not None
        return loaded

    def change_status(
        self,
        finding_id: str,
        *,
        actor: str,
        status: str,
        expected_revision: int,
        note: str | None,
        at: datetime,
    ) -> dict[str, Any]:
        self.ensure_schema()
        with self._engine().begin() as connection:
            finding = self._finding_for_work(connection, finding_id)
            item = self._lock_item(connection, finding_id, expected_revision)
            validate_status_transition(str(item["work_status"]), status)
            revision = self._bump(connection, item, at=at, work_status=status)
            self._append_event(
                connection,
                item=item,
                revision=revision,
                event_type="status_changed",
                finding_status=finding["status"],
                actor=actor,
                at=at,
                from_status=item["work_status"],
                to_status=status,
                note=note,
            )
            if status == "done":
                # Marking work done is a remediation report, not proof. Copy
                # the evidence present now so later evidence can be compared;
                # the finding itself is unchanged and stays unresolved until
                # deterministic evaluation proves otherwise.
                capture_baseline(
                    connection,
                    work_item_id=item["work_item_id"],
                    finding_id=finding["finding_id"],
                    site_id=finding["site_id"],
                    report_revision=revision,
                    reported_at=at,
                )
            loaded = self._load_item(connection, finding_id)
        assert loaded is not None
        return loaded

    def change_owner(
        self,
        finding_id: str,
        *,
        actor: str,
        owner_kind: str | None,
        owner_label: str | None,
        expected_revision: int,
        at: datetime,
    ) -> dict[str, Any]:
        self.ensure_schema()
        if (owner_kind is None) != (owner_label is None):
            raise ValueError("owner_kind and owner_label must be supplied together")
        with self._engine().begin() as connection:
            finding = self._finding_for_work(connection, finding_id)
            item = self._lock_item(connection, finding_id, expected_revision)
            if (item["owner_kind"], item["owner_label"]) == (owner_kind, owner_label):
                raise FindingWorkError("conflict", "work item already has this owner")
            revision = self._bump(
                connection,
                item,
                at=at,
                owner=(owner_kind, owner_label),
            )
            self._append_event(
                connection,
                item=item,
                revision=revision,
                event_type="owner_changed",
                finding_status=finding["status"],
                actor=actor,
                at=at,
                owner_kind=owner_kind,
                owner_label=owner_label,
            )
            loaded = self._load_item(connection, finding_id)
        assert loaded is not None
        return loaded

    def add_reference(
        self,
        finding_id: str,
        *,
        actor: str,
        reference_type: str,
        reference_system: str,
        reference_label: str,
        expected_revision: int,
        at: datetime,
    ) -> dict[str, Any]:
        self.ensure_schema()
        with self._engine().begin() as connection:
            finding = self._finding_for_work(connection, finding_id)
            item = self._lock_item(connection, finding_id, expected_revision)
            active = connection.execute(
                text(
                    """
                    SELECT reference_type, reference_system, reference_label
                    FROM finding_work_references
                    WHERE work_item_id = :work_item_id AND removed_at IS NULL
                    """
                ),
                {"work_item_id": item["work_item_id"]},
            ).all()
            if (reference_type, reference_system, reference_label) in {
                tuple(row) for row in active
            }:
                raise FindingWorkError("conflict", "reference is already attached")
            if len(active) >= MAX_ACTIVE_WORK_REFERENCES:
                raise FindingWorkError("conflict", "work item reference limit reached")
            revision = self._bump(connection, item, at=at)
            reference_id = "fwr_" + uuid4().hex
            connection.execute(
                text(
                    """
                    INSERT INTO finding_work_references (
                        reference_id, work_item_id, site_id, reference_type,
                        reference_system, reference_label,
                        reference_verification, added_actor_label, added_at
                    ) VALUES (
                        :reference_id, :work_item_id, :site_id, :reference_type,
                        :reference_system, :reference_label,
                        'unverified', :actor, :at
                    )
                    """
                ),
                {
                    "reference_id": reference_id,
                    "work_item_id": item["work_item_id"],
                    "site_id": item["site_id"],
                    "reference_type": reference_type,
                    "reference_system": reference_system,
                    "reference_label": reference_label,
                    "actor": actor,
                    "at": at,
                },
            )
            self._append_event(
                connection,
                item=item,
                revision=revision,
                event_type="reference_added",
                finding_status=finding["status"],
                actor=actor,
                at=at,
                reference_id=reference_id,
            )
            loaded = self._load_item(connection, finding_id)
        assert loaded is not None
        return loaded

    def remove_reference(
        self,
        finding_id: str,
        reference_id: str,
        *,
        actor: str,
        expected_revision: int,
        at: datetime,
    ) -> dict[str, Any]:
        self.ensure_schema()
        with self._engine().begin() as connection:
            finding = self._finding_for_work(connection, finding_id)
            item = self._lock_item(connection, finding_id, expected_revision)
            removed = connection.execute(
                text(
                    """
                    UPDATE finding_work_references
                    SET removed_at = GREATEST(added_at, :at),
                        removed_actor_label = :actor
                    WHERE reference_id = :reference_id
                      AND work_item_id = :work_item_id
                      AND removed_at IS NULL
                    """
                ),
                {
                    "reference_id": reference_id,
                    "work_item_id": item["work_item_id"],
                    "actor": actor,
                    "at": at,
                },
            )
            if removed.rowcount != 1:
                raise FindingWorkError("not_found", "active reference not found")
            revision = self._bump(connection, item, at=at)
            self._append_event(
                connection,
                item=item,
                revision=revision,
                event_type="reference_removed",
                finding_status=finding["status"],
                actor=actor,
                at=at,
                reference_id=reference_id,
            )
            loaded = self._load_item(connection, finding_id)
        assert loaded is not None
        return loaded

    def add_note(
        self,
        finding_id: str,
        *,
        actor: str,
        note: str,
        expected_revision: int,
        at: datetime,
    ) -> dict[str, Any]:
        self.ensure_schema()
        with self._engine().begin() as connection:
            finding = self._finding_for_work(connection, finding_id)
            item = self._lock_item(connection, finding_id, expected_revision)
            revision = self._bump(connection, item, at=at)
            self._append_event(
                connection,
                item=item,
                revision=revision,
                event_type="note_added",
                finding_status=finding["status"],
                actor=actor,
                at=at,
                note=note,
            )
            loaded = self._load_item(connection, finding_id)
        assert loaded is not None
        return loaded
