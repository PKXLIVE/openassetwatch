"""Database-backed advisory feed synchronization lifecycle and audit store."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Callable, Sequence
from uuid import uuid4

from sqlalchemy import bindparam, text
from sqlalchemy.exc import IntegrityError

from .advisory_catalog import AdvisoryCatalog
from .advisory_store import import_catalog


RUN_STATES = (
    "created",
    "downloading",
    "downloaded",
    "verifying",
    "verified",
    "preview_ready",
    "pending_approval",
    "approved",
    "importing",
    "activated",
    "activated_degraded",
    "rejected",
    "failed",
    "expired",
)
ACTIVE_RUN_STATES = (
    "created",
    "downloading",
    "downloaded",
    "verifying",
    "verified",
    "preview_ready",
    "pending_approval",
    "approved",
    "importing",
)
TERMINAL_RUN_STATES = ("activated", "activated_degraded", "rejected", "failed", "expired")
MAX_RUN_PAGE = 100
MAX_RUN_OFFSET = 10_000
MAX_ERROR_SUMMARY = 240
MAX_ACTOR = 120
MAX_RETAINED_CATALOGS_PER_SOURCE = 100


def _require_activation_preview_baseline(
    expected_catalog_id: str | None,
    current_catalog_id: str | None,
) -> None:
    if expected_catalog_id != current_catalog_id:
        raise AdvisorySyncStoreError(
            "activation-preview-stale",
            "active catalog changed after preview; synchronize and review a fresh preview",
        )


ADVISORY_SYNC_SCHEMA_SQL = (
    """
    CREATE TABLE IF NOT EXISTS advisory_feed_runs (
        run_id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL,
        request_mode TEXT NOT NULL,
        state TEXT NOT NULL,
        requested_by TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        started_at TIMESTAMPTZ,
        completed_at TIMESTAMPTZ,
        manifest_digest TEXT,
        payload_digest TEXT,
        publisher_key_id TEXT,
        catalog_version TEXT,
        catalog_sequence BIGINT,
        license_identifier TEXT,
        signature_status TEXT,
        license_status TEXT,
        attribution_status TEXT,
        advisory_count INTEGER,
        alias_count INTEGER,
        reference_count INTEGER,
        preview_json JSONB,
        active_catalog_before TEXT,
        activated_catalog_after TEXT,
        approved_by TEXT,
        approved_at TIMESTAMPTZ,
        rejected_by TEXT,
        rejected_at TIMESTAMPTZ,
        rejection_reason TEXT,
        reevaluation_status TEXT NOT NULL DEFAULT 'not-started',
        reevaluation_run_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        error_code TEXT,
        error_summary TEXT,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CHECK (request_mode IN ('remote-sync', 'local-reviewed-bundle')),
        CHECK (state IN (
            'created', 'downloading', 'downloaded', 'verifying', 'verified',
            'preview_ready', 'pending_approval', 'approved', 'importing',
            'activated', 'activated_degraded', 'rejected', 'failed', 'expired'
        )),
        CHECK (reevaluation_status IN ('not-started', 'pending', 'running', 'completed', 'failed')),
        CHECK (manifest_digest IS NULL OR manifest_digest ~ '^[0-9a-f]{64}$'),
        CHECK (payload_digest IS NULL OR payload_digest ~ '^[0-9a-f]{64}$'),
        CHECK (catalog_sequence IS NULL OR catalog_sequence > 0),
        CHECK (error_summary IS NULL OR LENGTH(error_summary) <= 240),
        CHECK (rejection_reason IS NULL OR LENGTH(rejection_reason) <= 240)
    )
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS idx_advisory_feed_runs_active_source
        ON advisory_feed_runs (source_id)
        WHERE state IN (
            'created', 'downloading', 'downloaded', 'verifying', 'verified',
            'preview_ready', 'pending_approval', 'approved', 'importing'
        )
    """,
    "CREATE INDEX IF NOT EXISTS idx_advisory_feed_runs_created ON advisory_feed_runs (created_at DESC, run_id)",
    "CREATE INDEX IF NOT EXISTS idx_advisory_feed_runs_source_created ON advisory_feed_runs (source_id, created_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS advisory_feed_catalogs (
        catalog_id TEXT PRIMARY KEY,
        run_id TEXT NOT NULL UNIQUE REFERENCES advisory_feed_runs(run_id),
        source_id TEXT NOT NULL,
        catalog_version TEXT NOT NULL,
        catalog_sequence BIGINT NOT NULL,
        manifest_digest TEXT NOT NULL,
        payload_digest TEXT NOT NULL,
        catalog_checksum TEXT NOT NULL,
        publisher_key_id TEXT NOT NULL,
        license_identifier TEXT NOT NULL,
        attribution TEXT NOT NULL,
        provenance_json JSONB NOT NULL,
        manifest_created_at TIMESTAMPTZ NOT NULL,
        manifest_expires_at TIMESTAMPTZ NOT NULL,
        manifest_bytes BYTEA NOT NULL,
        signature_bytes BYTEA NOT NULL,
        payload_bytes BYTEA NOT NULL,
        catalog_bytes BYTEA NOT NULL,
        preview_json JSONB NOT NULL,
        active BOOLEAN NOT NULL DEFAULT FALSE,
        activation_count INTEGER NOT NULL DEFAULT 0,
        first_activated_at TIMESTAMPTZ,
        last_activated_at TIMESTAMPTZ,
        retained_at TIMESTAMPTZ NOT NULL,
        UNIQUE (source_id, catalog_sequence),
        UNIQUE (source_id, catalog_version),
        UNIQUE (source_id, manifest_digest),
        UNIQUE (source_id, payload_digest),
        CHECK (catalog_sequence > 0),
        CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
        CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
        CHECK (catalog_checksum ~ '^[0-9a-f]{64}$'),
        CHECK (activation_count >= 0)
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_advisory_feed_catalogs_active_source ON advisory_feed_catalogs (source_id) WHERE active = TRUE",
    "CREATE INDEX IF NOT EXISTS idx_advisory_feed_catalogs_retained ON advisory_feed_catalogs (source_id, retained_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS advisory_catalog_activations (
        activation_id TEXT PRIMARY KEY,
        action TEXT NOT NULL,
        source_id TEXT NOT NULL,
        catalog_id TEXT NOT NULL REFERENCES advisory_feed_catalogs(catalog_id),
        previous_catalog_id TEXT REFERENCES advisory_feed_catalogs(catalog_id),
        requested_by TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        reevaluation_status TEXT NOT NULL DEFAULT 'pending',
        reevaluation_run_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        impact_json JSONB NOT NULL DEFAULT '{}'::jsonb,
        affected_before INTEGER,
        affected_after INTEGER,
        findings_before INTEGER,
        findings_after INTEGER,
        risk_before INTEGER,
        risk_after INTEGER,
        error_code TEXT,
        CHECK (action IN ('activate', 'rollback')),
        CHECK (reevaluation_status IN ('pending', 'running', 'completed', 'failed')),
        CHECK (error_code IS NULL OR LENGTH(error_code) <= 80)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_advisory_catalog_activations_created ON advisory_catalog_activations (created_at DESC, activation_id)",
    "CREATE INDEX IF NOT EXISTS idx_advisory_catalog_activations_source ON advisory_catalog_activations (source_id, created_at DESC)",
)


class AdvisorySyncStoreError(ValueError):
    def __init__(self, code: str, summary: str) -> None:
        super().__init__(summary)
        self.code = code[:80]
        self.summary = summary[:MAX_ERROR_SUMMARY]


def ensure_advisory_sync_schema(connection: Any) -> None:
    """Temporary compatibility seam; versioned migrations own durable DDL."""

    from .schema_migrations import ensure_schema_ready

    ensure_schema_ready(connection.engine)


def _json(value: Any) -> str:
    return json.dumps(value, default=str, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _json_value(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return default


def _safe_actor(value: str) -> str:
    actor = str(value or "").strip()
    if not actor or len(actor) > MAX_ACTOR:
        raise AdvisorySyncStoreError("actor-invalid", "operator identity must be between 1 and 120 characters")
    return actor


def _project_run(row: Any, *, include_preview: bool = False) -> dict[str, Any]:
    item = dict(row)
    preview = _json_value(item.pop("preview_json", None), None)
    item["reevaluation_run_ids"] = _json_value(item.pop("reevaluation_run_ids_json", []), [])[:100]
    if include_preview:
        item["preview"] = preview
    return item


def _project_catalog(row: Any, *, include_bytes: bool = False) -> dict[str, Any]:
    item = dict(row)
    item["provenance"] = _json_value(item.pop("provenance_json", {}), {})
    item["preview"] = _json_value(item.pop("preview_json", {}), {})
    if not include_bytes:
        for name in ("manifest_bytes", "signature_bytes", "payload_bytes", "catalog_bytes"):
            item.pop(name, None)
    return item


class SqlAdvisorySyncStore:
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

    def create_run(
        self,
        *,
        source_id: str,
        requested_by: str,
        request_mode: str,
        minimum_interval_seconds: int,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        self.ensure_schema()
        created = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        actor = _safe_actor(requested_by)
        if request_mode not in {"remote-sync", "local-reviewed-bundle"}:
            raise AdvisorySyncStoreError("request-mode-invalid", "advisory sync request mode is invalid")
        run_id = "afrun_" + uuid4().hex
        try:
            with self._engine().begin() as connection:
                connection.execute(
                    text("SELECT pg_advisory_xact_lock(hashtext(:key)::bigint)"),
                    {"key": f"openassetwatch-advisory-sync:{source_id}"},
                )
                active = connection.execute(
                    text(
                        """
                        SELECT run_id
                        FROM advisory_feed_runs
                        WHERE source_id = :source_id
                          AND state IN (
                            'created', 'downloading', 'downloaded', 'verifying',
                            'verified', 'preview_ready', 'pending_approval',
                            'approved', 'importing'
                          )
                        ORDER BY created_at DESC
                        LIMIT 1
                        """
                    ),
                    {"source_id": source_id},
                ).scalar_one_or_none()
                if active:
                    raise AdvisorySyncStoreError("sync-already-active", "an advisory synchronization is already active for this source")
                recent = connection.execute(
                    text(
                        """
                        SELECT created_at
                        FROM advisory_feed_runs
                        WHERE source_id = :source_id
                        ORDER BY created_at DESC
                        LIMIT 1
                        """
                    ),
                    {"source_id": source_id},
                ).scalar_one_or_none()
                if recent is not None and (created - recent).total_seconds() < minimum_interval_seconds:
                    raise AdvisorySyncStoreError("sync-rate-limited", "advisory synchronization was requested too recently")
                connection.execute(
                    text(
                        """
                        INSERT INTO advisory_feed_runs (
                            run_id, source_id, request_mode, state,
                            requested_by, created_at, updated_at
                        ) VALUES (
                            :run_id, :source_id, :request_mode, 'created',
                            :requested_by, :created_at, :created_at
                        )
                        """
                    ),
                    {
                        "run_id": run_id,
                        "source_id": source_id,
                        "request_mode": request_mode,
                        "requested_by": actor,
                        "created_at": created,
                    },
                )
        except IntegrityError as exc:
            raise AdvisorySyncStoreError("sync-already-active", "an advisory synchronization is already active for this source") from exc
        return self.get_run(run_id)

    def get_run(self, run_id: str, *, include_preview: bool = False) -> dict[str, Any]:
        self.ensure_schema()
        with self._engine().begin() as connection:
            row = connection.execute(
                text("SELECT * FROM advisory_feed_runs WHERE run_id = :run_id"),
                {"run_id": run_id},
            ).mappings().one_or_none()
        if row is None:
            raise AdvisorySyncStoreError("run-not-found", "advisory synchronization run was not found")
        return _project_run(row, include_preview=include_preview)

    def list_runs(
        self,
        *,
        source_id: str | None = None,
        state: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        self.ensure_schema()
        if state is not None and state not in RUN_STATES:
            raise AdvisorySyncStoreError("state-invalid", "advisory synchronization state is invalid")
        if not 1 <= limit <= MAX_RUN_PAGE or not 0 <= offset <= MAX_RUN_OFFSET:
            raise AdvisorySyncStoreError("pagination-invalid", "advisory synchronization pagination is outside allowed bounds")
        params = {"source_id": source_id, "state": state, "limit": limit, "offset": offset}
        where = "WHERE (:source_id IS NULL OR source_id = :source_id) AND (:state IS NULL OR state = :state)"
        with self._engine().begin() as connection:
            rows = connection.execute(
                text(f"SELECT * FROM advisory_feed_runs {where} ORDER BY created_at DESC, run_id LIMIT :limit OFFSET :offset"),
                params,
            ).mappings().all()
            total = int(connection.execute(text(f"SELECT COUNT(*) FROM advisory_feed_runs {where}"), params).scalar_one())
        return {
            "items": [_project_run(row) for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
            "truncated": offset + len(rows) < total,
        }

    def transition(
        self,
        run_id: str,
        *,
        expected_states: Sequence[str],
        state: str,
        values: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> None:
        self.ensure_schema()
        if state not in RUN_STATES or not expected_states or any(item not in RUN_STATES for item in expected_states):
            raise AdvisorySyncStoreError("state-invalid", "advisory synchronization state transition is invalid")
        allowed_columns = {
            "started_at",
            "completed_at",
            "manifest_digest",
            "payload_digest",
            "publisher_key_id",
            "catalog_version",
            "catalog_sequence",
            "license_identifier",
            "signature_status",
            "license_status",
            "attribution_status",
            "advisory_count",
            "alias_count",
            "reference_count",
            "active_catalog_before",
            "activated_catalog_after",
            "reevaluation_status",
            "reevaluation_run_ids_json",
            "error_code",
            "error_summary",
        }
        supplied = dict(values or {})
        if any(key not in allowed_columns for key in supplied):
            raise AdvisorySyncStoreError("state-metadata-invalid", "advisory synchronization transition metadata is invalid")
        updated = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        assignments = ["state = :state", "updated_at = :updated_at"]
        params: dict[str, Any] = {"run_id": run_id, "state": state, "updated_at": updated}
        for key, value in supplied.items():
            assignments.append(f"{key} = :{key}")
            params[key] = _json(value) if key.endswith("_json") else value
        statement = text(
            f"UPDATE advisory_feed_runs SET {', '.join(assignments)} WHERE run_id = :run_id AND state IN :expected_states RETURNING run_id"
        ).bindparams(bindparam("expected_states", expanding=True))
        params["expected_states"] = list(expected_states)
        with self._engine().begin() as connection:
            changed = connection.execute(statement, params).scalar_one_or_none()
        if changed is None:
            raise AdvisorySyncStoreError("run-state-conflict", "advisory synchronization run changed state concurrently")

    def fail_run(self, run_id: str, *, code: str, summary: str, now: datetime | None = None) -> None:
        try:
            self.transition(
                run_id,
                expected_states=ACTIVE_RUN_STATES,
                state="failed",
                values={
                    "completed_at": (now or datetime.now(timezone.utc)).astimezone(timezone.utc),
                    "error_code": str(code)[:80],
                    "error_summary": str(summary)[:MAX_ERROR_SUMMARY],
                },
                now=now,
            )
        except AdvisorySyncStoreError as exc:
            if exc.code != "run-state-conflict":
                raise

    def active_catalog(self, source_id: str, *, include_bytes: bool = False) -> dict[str, Any] | None:
        self.ensure_schema()
        with self._engine().begin() as connection:
            row = connection.execute(
                text("SELECT * FROM advisory_feed_catalogs WHERE source_id = :source_id AND active = TRUE"),
                {"source_id": source_id},
            ).mappings().one_or_none()
        return _project_catalog(row, include_bytes=include_bytes) if row else None

    def save_verified_bundle(
        self,
        *,
        run_id: str,
        source_id: str,
        catalog_version: str,
        catalog_sequence: int,
        manifest_digest: str,
        payload_digest: str,
        catalog_checksum: str,
        publisher_key_id: str,
        license_identifier: str,
        attribution: str,
        provenance: dict[str, Any],
        manifest_created_at: datetime,
        manifest_expires_at: datetime,
        manifest_bytes: bytes,
        signature_bytes: bytes,
        payload_bytes: bytes,
        catalog_bytes: bytes,
        preview: dict[str, Any],
        advisory_count: int,
        alias_count: int,
        reference_count: int,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        self.ensure_schema()
        retained = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        catalog_id = "afcat_" + uuid4().hex
        try:
            with self._engine().begin() as connection:
                connection.execute(
                    text("SELECT pg_advisory_xact_lock(hashtext(:key)::bigint)"),
                    {"key": f"openassetwatch-advisory-manifest:{source_id}"},
                )
                run = connection.execute(
                    text("SELECT state FROM advisory_feed_runs WHERE run_id = :run_id AND source_id = :source_id FOR UPDATE"),
                    {"run_id": run_id, "source_id": source_id},
                ).scalar_one_or_none()
                if run != "verifying":
                    raise AdvisorySyncStoreError("run-state-conflict", "advisory synchronization run is not awaiting verification")
                prior = connection.execute(
                    text(
                        """
                        SELECT afc.manifest_digest, afc.payload_digest,
                            afc.catalog_sequence, afc.catalog_version
                        FROM advisory_feed_catalogs afc
                        WHERE afc.source_id = :source_id
                          AND EXISTS (
                              SELECT 1
                              FROM advisory_catalog_activations aca
                              WHERE aca.catalog_id = afc.catalog_id
                          )
                        ORDER BY afc.catalog_sequence DESC
                        LIMIT 1
                        """
                    ),
                    {"source_id": source_id},
                ).mappings().one_or_none()
                retained_count = int(connection.execute(
                    text("SELECT COUNT(*) FROM advisory_feed_catalogs WHERE source_id = :source_id"),
                    {"source_id": source_id},
                ).scalar_one())
                if retained_count >= MAX_RETAINED_CATALOGS_PER_SOURCE:
                    raise AdvisorySyncStoreError(
                        "catalog-retention-limit",
                        "retained advisory catalog limit requires operator cleanup",
                    )
                if prior:
                    if catalog_sequence <= int(prior["catalog_sequence"]):
                        raise AdvisorySyncStoreError("catalog-downgrade", "catalog sequence is not newer than retained state")
                    if catalog_version == prior["catalog_version"]:
                        raise AdvisorySyncStoreError("catalog-version-replay", "catalog version has already been retained")
                replay = connection.execute(
                    text("SELECT catalog_id FROM advisory_feed_catalogs WHERE source_id = :source_id AND manifest_digest = :digest"),
                    {"source_id": source_id, "digest": manifest_digest},
                ).scalar_one_or_none()
                if replay:
                    raise AdvisorySyncStoreError("manifest-replay", "signed manifest has already been retained")
                conflicting_payload = connection.execute(
                    text("SELECT manifest_digest FROM advisory_feed_catalogs WHERE source_id = :source_id AND payload_digest = :payload_digest"),
                    {"source_id": source_id, "payload_digest": payload_digest},
                ).scalar_one_or_none()
                if conflicting_payload and conflicting_payload != manifest_digest:
                    raise AdvisorySyncStoreError("payload-metadata-conflict", "identical payload was presented under different signed metadata")
                active_before = connection.execute(
                    text("SELECT catalog_id FROM advisory_feed_catalogs WHERE source_id = :source_id AND active = TRUE"),
                    {"source_id": source_id},
                ).scalar_one_or_none()
                connection.execute(
                    text(
                        """
                        INSERT INTO advisory_feed_catalogs (
                            catalog_id, run_id, source_id, catalog_version,
                            catalog_sequence, manifest_digest, payload_digest,
                            catalog_checksum, publisher_key_id,
                            license_identifier, attribution, provenance_json,
                            manifest_created_at, manifest_expires_at,
                            manifest_bytes, signature_bytes, payload_bytes,
                            catalog_bytes, preview_json, retained_at
                        ) VALUES (
                            :catalog_id, :run_id, :source_id, :catalog_version,
                            :catalog_sequence, :manifest_digest, :payload_digest,
                            :catalog_checksum, :publisher_key_id,
                            :license_identifier, :attribution,
                            CAST(:provenance_json AS JSONB),
                            :manifest_created_at, :manifest_expires_at,
                            :manifest_bytes, :signature_bytes, :payload_bytes,
                            :catalog_bytes, CAST(:preview_json AS JSONB), :retained_at
                        )
                        """
                    ),
                    {
                        "catalog_id": catalog_id,
                        "run_id": run_id,
                        "source_id": source_id,
                        "catalog_version": catalog_version,
                        "catalog_sequence": catalog_sequence,
                        "manifest_digest": manifest_digest,
                        "payload_digest": payload_digest,
                        "catalog_checksum": catalog_checksum,
                        "publisher_key_id": publisher_key_id,
                        "license_identifier": license_identifier,
                        "attribution": attribution,
                        "provenance_json": _json(provenance),
                        "manifest_created_at": manifest_created_at,
                        "manifest_expires_at": manifest_expires_at,
                        "manifest_bytes": manifest_bytes,
                        "signature_bytes": signature_bytes,
                        "payload_bytes": payload_bytes,
                        "catalog_bytes": catalog_bytes,
                        "preview_json": _json(preview),
                        "retained_at": retained,
                    },
                )
                connection.execute(
                    text(
                        """
                        UPDATE advisory_feed_runs
                        SET state = 'pending_approval',
                            manifest_digest = :manifest_digest,
                            payload_digest = :payload_digest,
                            publisher_key_id = :publisher_key_id,
                            catalog_version = :catalog_version,
                            catalog_sequence = :catalog_sequence,
                            license_identifier = :license_identifier,
                            signature_status = 'verified',
                            license_status = 'approved',
                            attribution_status = 'present',
                            advisory_count = :advisory_count,
                            alias_count = :alias_count,
                            reference_count = :reference_count,
                            preview_json = CAST(:preview_json AS JSONB),
                            active_catalog_before = :active_before,
                            updated_at = :retained_at
                        WHERE run_id = :run_id AND state = 'verifying'
                        """
                    ),
                    {
                        "run_id": run_id,
                        "manifest_digest": manifest_digest,
                        "payload_digest": payload_digest,
                        "publisher_key_id": publisher_key_id,
                        "catalog_version": catalog_version,
                        "catalog_sequence": catalog_sequence,
                        "license_identifier": license_identifier,
                        "advisory_count": advisory_count,
                        "alias_count": alias_count,
                        "reference_count": reference_count,
                        "preview_json": _json(preview),
                        "active_before": active_before,
                        "retained_at": retained,
                    },
                )
        except IntegrityError as exc:
            raise AdvisorySyncStoreError("catalog-replay", "catalog replay or conflicting metadata was rejected") from exc
        return self.get_catalog(catalog_id)

    def get_catalog(self, catalog_id: str, *, include_bytes: bool = False) -> dict[str, Any]:
        self.ensure_schema()
        with self._engine().begin() as connection:
            row = connection.execute(
                text("SELECT * FROM advisory_feed_catalogs WHERE catalog_id = :catalog_id"),
                {"catalog_id": catalog_id},
            ).mappings().one_or_none()
        if row is None:
            raise AdvisorySyncStoreError("catalog-not-found", "retained advisory catalog was not found")
        return _project_catalog(row, include_bytes=include_bytes)

    def catalog_for_run(self, run_id: str, *, include_bytes: bool = False) -> dict[str, Any]:
        self.ensure_schema()
        with self._engine().begin() as connection:
            row = connection.execute(
                text("SELECT * FROM advisory_feed_catalogs WHERE run_id = :run_id"),
                {"run_id": run_id},
            ).mappings().one_or_none()
        if row is None:
            raise AdvisorySyncStoreError("catalog-not-found", "run has no retained verified catalog")
        return _project_catalog(row, include_bytes=include_bytes)

    def approve(self, run_id: str, *, actor: str, now: datetime | None = None) -> dict[str, Any]:
        approved = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        operator = _safe_actor(actor)
        self.ensure_schema()
        with self._engine().begin() as connection:
            changed = connection.execute(
                text(
                    """
                    UPDATE advisory_feed_runs
                    SET state = 'approved', approved_by = :actor,
                        approved_at = :approved_at, updated_at = :approved_at
                    WHERE run_id = :run_id AND state = 'pending_approval'
                    RETURNING run_id
                    """
                ),
                {"run_id": run_id, "actor": operator, "approved_at": approved},
            ).scalar_one_or_none()
        if changed is None:
            raise AdvisorySyncStoreError("run-state-conflict", "only a pending verified run can be approved")
        return self.get_run(run_id)

    def reject(self, run_id: str, *, actor: str, reason: str, now: datetime | None = None) -> dict[str, Any]:
        rejected = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        operator = _safe_actor(actor)
        bounded_reason = str(reason or "").strip()[:MAX_ERROR_SUMMARY]
        if not bounded_reason:
            raise AdvisorySyncStoreError("rejection-reason-invalid", "rejection requires a bounded reason")
        self.ensure_schema()
        with self._engine().begin() as connection:
            changed = connection.execute(
                text(
                    """
                    UPDATE advisory_feed_runs
                    SET state = 'rejected', rejected_by = :actor,
                        rejected_at = :rejected_at,
                        rejection_reason = :reason,
                        completed_at = :rejected_at,
                        updated_at = :rejected_at
                    WHERE run_id = :run_id AND state = 'pending_approval'
                    RETURNING run_id
                    """
                ),
                {"run_id": run_id, "actor": operator, "reason": bounded_reason, "rejected_at": rejected},
            ).scalar_one_or_none()
        if changed is None:
            raise AdvisorySyncStoreError("run-state-conflict", "only a pending verified run can be rejected")
        return self.get_run(run_id)

    def activate_run(
        self,
        run_id: str,
        *,
        catalog: Any,
        catalog_checksum: str,
        actor: str,
        catalog_importer: Callable[..., dict[str, Any]] = import_catalog,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        activated = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        operator = _safe_actor(actor)
        activation_id = "afact_" + uuid4().hex
        self.ensure_schema()
        expired = False
        with self._engine().begin() as connection:
            connection.execute(text("SELECT pg_advisory_xact_lock(hashtext('openassetwatch-advisory-activation')::bigint)"))
            row = connection.execute(
                text(
                    """
                    SELECT afr.state,
                        afr.active_catalog_before AS preview_active_catalog,
                        afc.*
                    FROM advisory_feed_runs afr
                    JOIN advisory_feed_catalogs afc ON afc.run_id = afr.run_id
                    WHERE afr.run_id = :run_id
                    FOR UPDATE OF afr, afc
                    """
                ),
                {"run_id": run_id},
            ).mappings().one_or_none()
            if row is None or row["state"] != "approved":
                raise AdvisorySyncStoreError("run-state-conflict", "only an approved verified run can be activated")
            if row["manifest_expires_at"] <= activated:
                connection.execute(
                    text("UPDATE advisory_feed_runs SET state = 'expired', completed_at = :now, updated_at = :now WHERE run_id = :run_id"),
                    {"run_id": run_id, "now": activated},
                )
                expired = True
            elif hashlib.sha256(bytes(row["catalog_bytes"])).hexdigest() != catalog_checksum or row["catalog_checksum"] != catalog_checksum:
                raise AdvisorySyncStoreError("retained-catalog-digest-invalid", "retained catalog digest verification failed")
            if expired:
                source_id = str(row["source_id"])
                previous = None
                import_result = None
            else:
                source_id = str(row["source_id"])
                previous = connection.execute(
                    text("SELECT catalog_id FROM advisory_feed_catalogs WHERE source_id = :source_id AND active = TRUE FOR UPDATE"),
                    {"source_id": source_id},
                ).scalar_one_or_none()
                _require_activation_preview_baseline(row["preview_active_catalog"], previous)
                connection.execute(
                    text("UPDATE advisory_feed_runs SET state = 'importing', updated_at = :now WHERE run_id = :run_id"),
                    {"run_id": run_id, "now": activated},
                )
                import_result = catalog_importer(
                    connection,
                    catalog=catalog,
                    checksum=catalog_checksum,
                    imported_at=activated,
                    reactivate_existing=True,
                )
                connection.execute(
                    text("UPDATE advisory_feed_catalogs SET active = FALSE WHERE source_id = :source_id AND active = TRUE"),
                    {"source_id": source_id},
                )
                connection.execute(
                    text(
                        """
                        UPDATE advisory_feed_catalogs
                        SET active = TRUE,
                            activation_count = activation_count + 1,
                            first_activated_at = COALESCE(first_activated_at, :now),
                            last_activated_at = :now
                        WHERE catalog_id = :catalog_id
                        """
                    ),
                    {"catalog_id": row["catalog_id"], "now": activated},
                )
                connection.execute(
                    text(
                        """
                        UPDATE advisory_feed_runs
                        SET state = 'activated', activated_catalog_after = :catalog_id,
                            reevaluation_status = 'pending', completed_at = :now,
                            updated_at = :now
                        WHERE run_id = :run_id AND state = 'importing'
                        """
                    ),
                    {"run_id": run_id, "catalog_id": row["catalog_id"], "now": activated},
                )
                connection.execute(
                    text(
                        """
                        INSERT INTO advisory_catalog_activations (
                            activation_id, action, source_id, catalog_id,
                            previous_catalog_id, requested_by, created_at
                        ) VALUES (
                            :activation_id, 'activate', :source_id, :catalog_id,
                            :previous_catalog_id, :requested_by, :created_at
                        )
                        """
                    ),
                    {
                        "activation_id": activation_id,
                        "source_id": source_id,
                        "catalog_id": row["catalog_id"],
                        "previous_catalog_id": previous,
                        "requested_by": operator,
                        "created_at": activated,
                    },
                )
        if expired:
            raise AdvisorySyncStoreError("manifest-expired", "approved manifest expired before activation")
        return {
            "activation_id": activation_id,
            "action": "activate",
            "source_id": source_id,
            "catalog_id": row["catalog_id"],
            "previous_catalog_id": previous,
            "catalog_version": row["catalog_version"],
            "catalog_sequence": row["catalog_sequence"],
            "preview": _json_value(row["preview_json"], {}),
            "import": import_result,
            "reevaluation_status": "pending",
        }

    def rollback_catalog(
        self,
        catalog_id: str,
        *,
        catalog: Any,
        catalog_checksum: str,
        actor: str,
        cooldown_seconds: int,
        catalog_importer: Callable[..., dict[str, Any]] = import_catalog,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        rolled_back = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        operator = _safe_actor(actor)
        activation_id = "afact_" + uuid4().hex
        self.ensure_schema()
        with self._engine().begin() as connection:
            connection.execute(text("SELECT pg_advisory_xact_lock(hashtext('openassetwatch-advisory-activation')::bigint)"))
            target = connection.execute(
                text("SELECT * FROM advisory_feed_catalogs WHERE catalog_id = :catalog_id FOR UPDATE"),
                {"catalog_id": catalog_id},
            ).mappings().one_or_none()
            if target is None or int(target["activation_count"] or 0) < 1:
                raise AdvisorySyncStoreError("rollback-target-invalid", "rollback target is not a previously activated retained catalog")
            if target["active"]:
                raise AdvisorySyncStoreError("rollback-target-active", "rollback target is already active")
            source_id = str(target["source_id"])
            recent = connection.execute(
                text("SELECT created_at FROM advisory_catalog_activations WHERE source_id = :source_id ORDER BY created_at DESC LIMIT 1"),
                {"source_id": source_id},
            ).scalar_one_or_none()
            if recent is not None and (rolled_back - recent).total_seconds() < cooldown_seconds:
                raise AdvisorySyncStoreError("control-action-rate-limited", "catalog control action was requested too recently")
            if hashlib.sha256(bytes(target["catalog_bytes"])).hexdigest() != catalog_checksum or target["catalog_checksum"] != catalog_checksum:
                raise AdvisorySyncStoreError("retained-catalog-digest-invalid", "retained rollback catalog digest verification failed")
            previous = connection.execute(
                text("SELECT catalog_id FROM advisory_feed_catalogs WHERE source_id = :source_id AND active = TRUE FOR UPDATE"),
                {"source_id": source_id},
            ).scalar_one_or_none()
            import_result = catalog_importer(
                connection,
                catalog=catalog,
                checksum=catalog_checksum,
                imported_at=rolled_back,
                reactivate_existing=True,
            )
            connection.execute(
                text("UPDATE advisory_feed_catalogs SET active = FALSE WHERE source_id = :source_id AND active = TRUE"),
                {"source_id": source_id},
            )
            connection.execute(
                text(
                    """
                    UPDATE advisory_feed_catalogs
                    SET active = TRUE, activation_count = activation_count + 1,
                        last_activated_at = :now
                    WHERE catalog_id = :catalog_id
                    """
                ),
                {"catalog_id": catalog_id, "now": rolled_back},
            )
            connection.execute(
                text(
                    """
                    INSERT INTO advisory_catalog_activations (
                        activation_id, action, source_id, catalog_id,
                        previous_catalog_id, requested_by, created_at
                    ) VALUES (
                        :activation_id, 'rollback', :source_id, :catalog_id,
                        :previous_catalog_id, :requested_by, :created_at
                    )
                    """
                ),
                {
                    "activation_id": activation_id,
                    "source_id": source_id,
                    "catalog_id": catalog_id,
                    "previous_catalog_id": previous,
                    "requested_by": operator,
                    "created_at": rolled_back,
                },
            )
        return {
            "activation_id": activation_id,
            "action": "rollback",
            "source_id": source_id,
            "catalog_id": catalog_id,
            "previous_catalog_id": previous,
            "catalog_version": target["catalog_version"],
            "catalog_sequence": target["catalog_sequence"],
            "preview": _json_value(target["preview_json"], {}),
            "import": import_result,
            "reevaluation_status": "pending",
        }

    def mark_reevaluation(
        self,
        activation_id: str,
        *,
        status: str,
        run_ids: Sequence[str] = (),
        error_code: str | None = None,
        impact: dict[str, Any] | None = None,
    ) -> None:
        if status not in {"running", "completed", "failed"}:
            raise AdvisorySyncStoreError("reevaluation-state-invalid", "reevaluation state is invalid")
        safe_ids = [str(value)[:80] for value in run_ids[:100]]
        self.ensure_schema()
        with self._engine().begin() as connection:
            activation = connection.execute(
                text("SELECT action, catalog_id FROM advisory_catalog_activations WHERE activation_id = :activation_id FOR UPDATE"),
                {"activation_id": activation_id},
            ).mappings().one_or_none()
            if activation is None:
                raise AdvisorySyncStoreError("activation-not-found", "catalog activation was not found")
            connection.execute(
                text(
                    """
                    UPDATE advisory_catalog_activations
                    SET reevaluation_status = :status,
                        reevaluation_run_ids_json = CAST(:run_ids AS JSONB),
                        impact_json = CAST(:impact AS JSONB),
                        error_code = :error_code
                    WHERE activation_id = :activation_id
                    """
                ),
                {
                    "activation_id": activation_id,
                    "status": status,
                    "run_ids": _json(safe_ids),
                    "impact": _json(impact or {}),
                    "error_code": str(error_code)[:80] if error_code else None,
                },
            )
            if activation["action"] == "activate":
                connection.execute(
                    text(
                        """
                        UPDATE advisory_feed_runs afr
                        SET reevaluation_status = :status,
                            reevaluation_run_ids_json = CAST(:run_ids AS JSONB),
                            state = CASE
                                WHEN :status = 'failed' THEN 'activated_degraded'
                                WHEN :status = 'completed' THEN 'activated'
                                ELSE afr.state
                            END,
                            updated_at = NOW()
                        FROM advisory_feed_catalogs afc
                        WHERE afc.run_id = afr.run_id
                          AND afc.catalog_id = :catalog_id
                        """
                    ),
                    {"status": status, "run_ids": _json(safe_ids), "catalog_id": activation["catalog_id"]},
                )

    def get_activation(self, activation_id: str) -> dict[str, Any]:
        self.ensure_schema()
        with self._engine().begin() as connection:
            row = connection.execute(
                text("SELECT * FROM advisory_catalog_activations WHERE activation_id = :activation_id"),
                {"activation_id": activation_id},
            ).mappings().one_or_none()
        if row is None:
            raise AdvisorySyncStoreError("activation-not-found", "catalog activation was not found")
        item = dict(row)
        item["reevaluation_run_ids"] = _json_value(item.pop("reevaluation_run_ids_json", []), [])[:100]
        item["impact"] = _json_value(item.pop("impact_json", {}), {})
        return item

    def list_catalogs(self, *, source_id: str, limit: int = 50) -> list[dict[str, Any]]:
        self.ensure_schema()
        safe_limit = max(1, min(limit, 100))
        with self._engine().begin() as connection:
            rows = connection.execute(
                text(
                    """
                    SELECT catalog_id, run_id, source_id, catalog_version,
                        catalog_sequence, manifest_digest, payload_digest,
                        catalog_checksum, publisher_key_id, license_identifier,
                        manifest_created_at, manifest_expires_at, active,
                        activation_count, first_activated_at,
                        last_activated_at, retained_at
                    FROM advisory_feed_catalogs
                    WHERE source_id = :source_id AND activation_count > 0
                    ORDER BY last_activated_at DESC NULLS LAST, retained_at DESC
                    LIMIT :limit
                    """
                ),
                {"source_id": source_id, "limit": safe_limit},
            ).mappings().all()
        return [dict(row) for row in rows]

    def source_status(self, source_id: str) -> dict[str, Any]:
        self.ensure_schema()
        with self._engine().begin() as connection:
            latest = connection.execute(
                text("SELECT * FROM advisory_feed_runs WHERE source_id = :source_id ORDER BY created_at DESC LIMIT 1"),
                {"source_id": source_id},
            ).mappings().one_or_none()
            success = connection.execute(
                text("SELECT * FROM advisory_feed_runs WHERE source_id = :source_id AND state IN ('activated', 'activated_degraded') ORDER BY completed_at DESC LIMIT 1"),
                {"source_id": source_id},
            ).mappings().one_or_none()
            active = connection.execute(
                text(
                    """
                    SELECT catalog_id, catalog_version, catalog_sequence,
                        publisher_key_id, license_identifier, manifest_digest,
                        payload_digest, last_activated_at
                    FROM advisory_feed_catalogs
                    WHERE source_id = :source_id AND active = TRUE
                    """
                ),
                {"source_id": source_id},
            ).mappings().one_or_none()
            pending = int(connection.execute(
                text("SELECT COUNT(*) FROM advisory_feed_runs WHERE source_id = :source_id AND state IN ('pending_approval', 'approved')"),
                {"source_id": source_id},
            ).scalar_one())
            last_good = connection.execute(
                text(
                    """
                    SELECT catalog_id, catalog_version, catalog_sequence,
                        publisher_key_id, last_activated_at, active
                    FROM advisory_feed_catalogs
                    WHERE source_id = :source_id AND activation_count > 0
                    ORDER BY last_activated_at DESC NULLS LAST
                    LIMIT 2
                    """
                ),
                {"source_id": source_id},
            ).mappings().all()
        return {
            "source_id": source_id,
            "last_attempt": _project_run(latest) if latest else None,
            "last_success": _project_run(success) if success else None,
            "active_catalog": dict(active) if active else None,
            "pending_approval_count": pending,
            "last_known_good_catalogs": [dict(row) for row in last_good],
        }

    def ai_snapshot(self, *, limit: int = 20) -> list[dict[str, Any]]:
        self.ensure_schema()
        safe_limit = max(1, min(limit, 20))
        with self._engine().begin() as connection:
            rows = connection.execute(
                text(
                    """
                    SELECT afr.run_id, afr.source_id, afr.state,
                        afr.created_at, afr.completed_at,
                        afr.manifest_digest, afr.payload_digest,
                        afr.publisher_key_id, afr.catalog_version,
                        afr.catalog_sequence, afr.license_identifier,
                        afr.signature_status, afr.license_status,
                        afr.attribution_status, afr.preview_json,
                        afr.activated_catalog_after AS catalog_id,
                        afr.reevaluation_status, afr.error_code
                    FROM advisory_feed_runs afr
                    ORDER BY afr.created_at DESC, afr.run_id
                    LIMIT :limit
                    """
                ),
                {"limit": safe_limit},
            ).mappings().all()
            activations = connection.execute(
                text(
                    """
                    SELECT aca.activation_id, aca.action, aca.source_id,
                        aca.catalog_id, aca.previous_catalog_id,
                        aca.created_at, aca.reevaluation_status,
                        aca.reevaluation_run_ids_json, aca.impact_json,
                        aca.error_code, afc.run_id, afc.catalog_version,
                        afc.catalog_sequence, afc.publisher_key_id,
                        afc.manifest_digest, afc.payload_digest,
                        afc.license_identifier, afc.preview_json
                    FROM advisory_catalog_activations aca
                    JOIN advisory_feed_catalogs afc
                      ON afc.catalog_id = aca.catalog_id
                    ORDER BY aca.created_at DESC, aca.activation_id
                    LIMIT :limit
                    """
                ),
                {"limit": safe_limit},
            ).mappings().all()
        items = []
        for row in rows:
            item = dict(row)
            item["preview"] = _json_value(item.pop("preview_json", {}), {})
            items.append(item)
        for row in activations:
            item = dict(row)
            item["state"] = "activated" if item["reevaluation_status"] == "completed" else "activated_degraded"
            item["signature_status"] = "verified"
            item["license_status"] = "approved"
            item["attribution_status"] = "present"
            item["preview"] = _json_value(item.pop("preview_json", {}), {})
            item["reevaluation_run_ids"] = _json_value(item.pop("reevaluation_run_ids_json", []), [])[:100]
            item["activation_impact"] = _json_value(item.pop("impact_json", {}), {})
            items.append(item)
        items.sort(key=lambda item: (item.get("created_at") or datetime.min.replace(tzinfo=timezone.utc)), reverse=True)
        return items[:safe_limit]
