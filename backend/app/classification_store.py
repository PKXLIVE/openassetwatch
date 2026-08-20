"""Persistence, provenance, history, and conflict lifecycle for classification."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence
from uuid import uuid4

from sqlalchemy import bindparam, text

from .classification import (
    CLASSIFIER_VERSION,
    MAX_CLASSIFICATION_EVIDENCE,
    MAX_CLASSIFICATION_EVIDENCE_PER_SOURCE,
    ClassificationEvidence,
    ClassificationResult,
    bounded_text,
    classification_changed,
    evidence_id_for,
)
from .vendor_catalog import VendorCatalog


CLASSIFICATION_RAW_EVIDENCE_KINDS = frozenset(
    {
        "asset-category",
        "category",
        "device-category",
        "device-role",
        "device-urn",
        "dhcp-vendor-class",
        "dns-name",
        "hardware-vendor",
        "host-name",
        "hostname",
        "mac-vendor",
        "manufacturer",
        "mdns-service",
        "model",
        "nbns-name",
        "netbios-name",
        "os",
        "os-family",
        "os-version",
        "platform",
        "platform-os",
        "platform-version",
        "product",
        "product-model",
        "role",
        "security-coverage",
        "service",
        "service-name",
        "ssdp-device-type",
        "ssdp-server",
        "subtype",
        "vendor",
        "vendor-class",
    }
)
SENSITIVE_EVIDENCE_KIND_FRAGMENTS = frozenset(
    {
        "api-key",
        "apikey",
        "authorization",
        "bearer",
        "body",
        "cookie",
        "credential",
        "frame",
        "header",
        "hexdump",
        "packet",
        "password",
        "payload",
        "pcap",
        "private-key",
        "raw-byte",
        "secret",
        "session",
        "token",
    }
)


CLASSIFICATION_SCHEMA_SQL = (
    """
    CREATE TABLE IF NOT EXISTS classification_evidence (
        evidence_id TEXT PRIMARY KEY,
        site_id TEXT NOT NULL REFERENCES sites(site_id),
        asset_id TEXT NOT NULL,
        source_id TEXT NOT NULL,
        source_type TEXT NOT NULL,
        collection_method TEXT NOT NULL,
        evidence_kind TEXT NOT NULL,
        observed_value TEXT NOT NULL,
        observed_at TIMESTAMPTZ NOT NULL,
        first_seen_at TIMESTAMPTZ NOT NULL,
        last_seen_at TIMESTAMPTZ NOT NULL,
        direct BOOLEAN NOT NULL,
        strength TEXT NOT NULL,
        source_confidence DOUBLE PRECISION NOT NULL,
        observation_count INTEGER NOT NULL DEFAULT 1,
        agreement_state TEXT NOT NULL DEFAULT 'unassessed',
        classifier_used BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        FOREIGN KEY (site_id, asset_id)
            REFERENCES control_tower_assets(site_id, asset_id) ON DELETE CASCADE,
        CHECK (strength IN ('direct', 'medium', 'weak')),
        CHECK (source_confidence >= 0.0 AND source_confidence <= 1.0),
        CHECK (observation_count >= 1),
        CHECK (agreement_state IN ('unassessed', 'supporting', 'conflicting', 'unused'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS classification_runs (
        run_id TEXT PRIMARY KEY,
        classifier_version TEXT NOT NULL,
        trigger_type TEXT NOT NULL,
        requested_by TEXT,
        scope_site_id TEXT,
        scope_asset_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        status TEXT NOT NULL,
        started_at TIMESTAMPTZ NOT NULL,
        completed_at TIMESTAMPTZ,
        assets_evaluated INTEGER NOT NULL DEFAULT 0,
        assets_changed INTEGER NOT NULL DEFAULT 0,
        conflicts_found INTEGER NOT NULL DEFAULT 0,
        finding_evaluations INTEGER NOT NULL DEFAULT 0,
        bounded_errors_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        CHECK (status IN ('running', 'completed', 'failed'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS asset_classifications (
        classification_id TEXT PRIMARY KEY,
        site_id TEXT NOT NULL REFERENCES sites(site_id),
        asset_id TEXT NOT NULL,
        classifier_version TEXT NOT NULL,
        category TEXT NOT NULL,
        subtype TEXT,
        manufacturer TEXT,
        product_hint TEXT,
        os_family TEXT,
        os_version_hint TEXT,
        managed_capability_json JSONB NOT NULL,
        confidence DOUBLE PRECISION NOT NULL,
        status TEXT NOT NULL,
        supporting_evidence_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        conflicting_evidence_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        independent_source_count INTEGER NOT NULL DEFAULT 0,
        evidence_count INTEGER NOT NULL DEFAULT 0,
        first_classified_at TIMESTAMPTZ NOT NULL,
        last_classified_at TIMESTAMPTZ NOT NULL,
        evaluated_at TIMESTAMPTZ NOT NULL,
        superseded_at TIMESTAMPTZ,
        freshness TEXT NOT NULL,
        reason_codes_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        conflicts_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        last_run_id TEXT NOT NULL REFERENCES classification_runs(run_id),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (site_id, asset_id),
        FOREIGN KEY (site_id, asset_id)
            REFERENCES control_tower_assets(site_id, asset_id) ON DELETE CASCADE,
        CHECK (confidence >= 0.0 AND confidence <= 1.0),
        CHECK (status IN (
            'classified', 'partially-classified', 'unknown',
            'conflicting', 'insufficient-evidence'
        )),
        CHECK (freshness IN ('fresh', 'aging', 'stale', 'unknown'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS asset_classification_history (
        history_id BIGSERIAL PRIMARY KEY,
        classification_id TEXT NOT NULL,
        site_id TEXT NOT NULL,
        asset_id TEXT NOT NULL,
        classifier_version TEXT NOT NULL,
        snapshot_json JSONB NOT NULL,
        valid_from TIMESTAMPTZ NOT NULL,
        superseded_at TIMESTAMPTZ NOT NULL,
        superseded_by_run_id TEXT NOT NULL REFERENCES classification_runs(run_id),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS asset_classification_evidence (
        classification_id TEXT NOT NULL
            REFERENCES asset_classifications(classification_id) ON DELETE CASCADE,
        evidence_id TEXT NOT NULL
            REFERENCES classification_evidence(evidence_id) ON DELETE CASCADE,
        relation TEXT NOT NULL,
        ordinal INTEGER NOT NULL,
        PRIMARY KEY (classification_id, evidence_id, relation),
        CHECK (relation IN ('supporting', 'conflicting'))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS classification_conflicts (
        conflict_id TEXT PRIMARY KEY,
        classification_id TEXT NOT NULL
            REFERENCES asset_classifications(classification_id) ON DELETE CASCADE,
        site_id TEXT NOT NULL,
        asset_id TEXT NOT NULL,
        conflict_type TEXT NOT NULL,
        selected_value TEXT NOT NULL,
        conflicting_value TEXT NOT NULL,
        supporting_evidence_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        conflicting_evidence_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        reason_code TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        first_seen_at TIMESTAMPTZ NOT NULL,
        last_seen_at TIMESTAMPTZ NOT NULL,
        resolved_at TIMESTAMPTZ,
        last_run_id TEXT NOT NULL REFERENCES classification_runs(run_id),
        CHECK (status IN ('open', 'resolved'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_classification_evidence_asset ON classification_evidence (site_id, asset_id, last_seen_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_classification_evidence_source ON classification_evidence (source_type, source_id, last_seen_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_asset_classifications_filters ON asset_classifications (site_id, category, status, confidence DESC)",
    "CREATE INDEX IF NOT EXISTS idx_asset_classifications_manufacturer ON asset_classifications (manufacturer) WHERE manufacturer IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS idx_asset_classifications_os ON asset_classifications (os_family) WHERE os_family IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS idx_classification_history_asset ON asset_classification_history (site_id, asset_id, superseded_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_classification_conflicts_open ON classification_conflicts (site_id, asset_id, last_seen_at DESC) WHERE status = 'open'",
    "CREATE INDEX IF NOT EXISTS idx_classification_runs_started ON classification_runs (started_at DESC)",
)


def ensure_classification_schema(connection: Any) -> None:
    """Temporary compatibility seam; versioned migrations own durable DDL."""

    from .schema_migrations import ensure_schema_ready

    ensure_schema_ready(connection.engine)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, default=str, sort_keys=True)


def _json_value(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return default


def _utc(value: Any, *, fallback: datetime) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return fallback
    else:
        return fallback
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return fallback
    return parsed.astimezone(timezone.utc)


def _confidence(value: Any, *, default: float) -> float:
    if not isinstance(value, (int, float)):
        return default
    number = float(value)
    if not math.isfinite(number):
        return default
    return max(0.0, min(number, 1.0))


def _source_type(payload: Mapping[str, Any]) -> str:
    declared = bounded_text(payload.get("sensor_type"), limit=64).casefold()
    if declared:
        return declared
    source = bounded_text(payload.get("observation_source"), limit=64).casefold()
    if source == "endpoint-inventory" or payload.get("agent_id"):
        return "endpoint-collector"
    if source == "passive-network" or payload.get("sensor_id"):
        return "passive-network-sensor"
    return "connector"


def classification_evidence_for_asset(
    *,
    asset: Mapping[str, Any],
    payload: Mapping[str, Any],
    observed_at: datetime,
    catalog: VendorCatalog | None = None,
    source_authenticated: bool = False,
) -> tuple[ClassificationEvidence, ...]:
    """Project one accepted normalized asset into bounded durable evidence."""

    site_id = bounded_text(asset.get("site_id"), limit=128)
    asset_id = bounded_text(asset.get("asset_id"), limit=160)
    source_type = _source_type(payload)
    source_id = bounded_text(
        payload.get("sensor_id") or payload.get("agent_id") or asset.get("source_agent_id"),
        limit=160,
    ) or "source-unknown"
    if not source_authenticated:
        source_type = "untrusted-ingestion"
        source_id = "untrusted-local-inventory"
    collection_method = bounded_text(
        payload.get("observation_source") or "local-inventory",
        limit=64,
    ).casefold()
    direct_source = source_authenticated and source_type in {
        "endpoint-collector",
        "endpoint-agent",
        "collector",
    }
    metadata = asset.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    records: list[ClassificationEvidence] = []

    def add(
        *,
        method: str,
        kind: str,
        value: Any,
        direct: bool,
        strength: str,
        confidence: Any,
        item_source_id: str | None = None,
        item_source_type: str | None = None,
    ) -> None:
        safe_value = bounded_text(value)
        safe_method = bounded_text(method, limit=64).casefold()
        safe_kind = bounded_text(kind, limit=80).casefold()
        safe_source_id = bounded_text(item_source_id or source_id, limit=160)
        safe_source_type = bounded_text(item_source_type or source_type, limit=64).casefold()
        if (
            not site_id
            or not asset_id
            or not safe_value
            or not safe_method
            or not safe_kind
            or len(records) >= 64
            or any(
                sensitive in safe_kind
                for sensitive in SENSITIVE_EVIDENCE_KIND_FRAGMENTS
            )
        ):
            return
        resolved_strength = strength if strength in {"direct", "medium", "weak"} else "weak"
        record = ClassificationEvidence(
            evidence_id=evidence_id_for(
                site_id=site_id,
                asset_id=asset_id,
                source_type=safe_source_type,
                source_id=safe_source_id,
                collection_method=safe_method,
                kind=safe_kind,
                value=safe_value,
            ),
            site_id=site_id,
            asset_id=asset_id,
            source_id=safe_source_id,
            source_type=safe_source_type,
            collection_method=safe_method,
            kind=safe_kind,
            value=safe_value,
            observed_at=observed_at,
            direct=direct,
            strength=resolved_strength,  # type: ignore[arg-type]
            source_confidence=_confidence(confidence, default=0.7),
            first_seen_at=observed_at,
            last_seen_at=observed_at,
        )
        if record.evidence_id not in {existing.evidence_id for existing in records}:
            records.append(record)

    add(
        method=collection_method,
        kind="hostname",
        value=asset.get("hostname"),
        direct=direct_source,
        strength="weak",
        confidence=payload.get("confidence"),
    )
    add(
        method=collection_method,
        kind="ip-address",
        value=asset.get("primary_ip"),
        direct=False,
        strength="weak",
        confidence=payload.get("confidence"),
    )
    add(
        method=collection_method,
        kind="mac-address",
        value=asset.get("mac"),
        direct=False,
        strength="weak",
        confidence=payload.get("confidence"),
    )
    add(
        method=collection_method,
        kind="os",
        value=asset.get("os"),
        direct=direct_source,
        strength="direct" if direct_source else "medium",
        confidence=payload.get("confidence"),
    )
    add(
        method=collection_method,
        kind="platform",
        value=asset.get("platform"),
        direct=direct_source,
        strength="direct" if direct_source else "medium",
        confidence=payload.get("confidence"),
    )
    for key, kind in (
        ("category", "category"),
        ("device_role", "device-role"),
        ("role", "device-role"),
        ("subtype", "subtype"),
        ("manufacturer", "manufacturer"),
        ("vendor", "manufacturer"),
        ("product", "product"),
        ("model", "model"),
        ("os_version", "os-version"),
        ("security_coverage", "security-coverage"),
        ("coverage_status", "security-coverage"),
    ):
        add(
            method=collection_method,
            kind=kind,
            value=metadata.get(key),
            direct=direct_source,
            strength="direct" if direct_source else "medium",
            confidence=payload.get("confidence"),
        )

    raw_evidence = metadata.get("evidence")
    if isinstance(raw_evidence, list):
        for item in raw_evidence[:32]:
            if not isinstance(item, Mapping):
                continue
            kind = bounded_text(item.get("kind"), limit=80).casefold().replace("_", "-")
            if (
                kind not in CLASSIFICATION_RAW_EVIDENCE_KINDS
                or any(
                    sensitive in kind
                    for sensitive in SENSITIVE_EVIDENCE_KIND_FRAGMENTS
                )
            ):
                continue
            item_direct = direct_source and kind.casefold() in {
                "category",
                "asset-category",
                "device-category",
                "device-role",
                "os",
                "os-family",
                "os-version",
                "platform",
                "manufacturer",
                "hardware-vendor",
                "product",
                "model",
                "security-coverage",
            }
            add(
                method=bounded_text(item.get("protocol"), limit=64) or collection_method,
                kind=kind,
                value=item.get("value"),
                direct=item_direct,
                strength="direct" if item_direct else "medium",
                confidence=item.get("confidence"),
            )

    software = metadata.get("software")
    if isinstance(software, list):
        for item in software[:16]:
            if isinstance(item, Mapping):
                value = item.get("name")
            else:
                value = item
            add(
                method=collection_method,
                kind="software-name",
                value=value,
                direct=direct_source,
                strength="direct" if direct_source else "weak",
                confidence=payload.get("confidence"),
            )

    mac = bounded_text(asset.get("mac"), limit=64)
    if catalog and mac:
        manufacturer = catalog.lookup(mac)
        if manufacturer:
            add(
                method="oui",
                kind="oui-manufacturer",
                value=manufacturer,
                direct=False,
                strength="medium",
                confidence=0.85,
                item_source_id=f"catalog:{catalog.catalog_version}",
                item_source_type="vendor-catalog",
            )
    return tuple(records)


def persist_classification_evidence(
    connection: Any,
    *,
    records: Sequence[ClassificationEvidence],
) -> None:
    statement = text(
        """
        INSERT INTO classification_evidence (
            evidence_id, site_id, asset_id, source_id, source_type,
            collection_method, evidence_kind, observed_value,
            observed_at, first_seen_at, last_seen_at, direct, strength,
            source_confidence, observation_count
        )
        VALUES (
            :evidence_id, :site_id, :asset_id, :source_id, :source_type,
            :collection_method, :evidence_kind, :observed_value,
            :observed_at, :observed_at, :observed_at, :direct, :strength,
            :source_confidence, 1
        )
        ON CONFLICT (evidence_id) DO UPDATE SET
            observed_at = GREATEST(classification_evidence.observed_at, EXCLUDED.observed_at),
            first_seen_at = LEAST(classification_evidence.first_seen_at, EXCLUDED.observed_at),
            last_seen_at = GREATEST(classification_evidence.last_seen_at, EXCLUDED.observed_at),
            source_confidence = GREATEST(
                classification_evidence.source_confidence,
                EXCLUDED.source_confidence
            ),
            observation_count = LEAST(
                classification_evidence.observation_count + 1,
                2147483647
            ),
            updated_at = NOW()
        """
    )
    for record in records[:MAX_CLASSIFICATION_EVIDENCE]:
        connection.execute(
            statement,
            {
                "evidence_id": record.evidence_id,
                "site_id": record.site_id,
                "asset_id": record.asset_id,
                "source_id": record.source_id,
                "source_type": record.source_type,
                "collection_method": record.collection_method,
                "evidence_kind": record.kind,
                "observed_value": record.value,
                "observed_at": record.observed_at,
                "direct": record.direct,
                "strength": record.strength,
                "source_confidence": record.source_confidence,
            },
        )


def conflict_id_for(
    *,
    classification_id: str,
    conflict_type: str,
    selected_value: str,
    conflicting_value: str,
) -> str:
    values = sorted((selected_value.casefold(), conflicting_value.casefold()))
    canonical = "\x00".join((classification_id, conflict_type, *values))
    return "ccf_" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class ClassificationReconcileResult:
    changed: bool
    conflict_count: int


class SqlClassificationStore:
    def __init__(self) -> None:
        self._schema_ready = False

    def _engine(self) -> Any:
        from .database import get_engine

        return get_engine()

    def ensure_schema(self) -> None:
        if self._schema_ready:
            return
        from .schema_migrations import ensure_schema_ready

        ensure_schema_ready(self._engine())
        self._schema_ready = True

    def begin_run(
        self,
        *,
        trigger_type: str,
        requested_by: str | None,
        site_id: str | None,
        asset_ids: Sequence[str],
        started_at: datetime,
    ) -> str:
        self.ensure_schema()
        run_id = "crun_" + uuid4().hex
        with self._engine().begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO classification_runs (
                        run_id, classifier_version, trigger_type, requested_by,
                        scope_site_id, scope_asset_ids_json, status, started_at
                    )
                    VALUES (
                        :run_id, :classifier_version, :trigger_type, :requested_by,
                        :scope_site_id, CAST(:scope_asset_ids_json AS JSONB),
                        'running', :started_at
                    )
                    """
                ),
                {
                    "run_id": run_id,
                    "classifier_version": CLASSIFIER_VERSION,
                    "trigger_type": bounded_text(trigger_type, limit=64),
                    "requested_by": bounded_text(requested_by, limit=120) or None,
                    "scope_site_id": bounded_text(site_id, limit=128) or None,
                    "scope_asset_ids_json": _json(list(asset_ids[:500])),
                    "started_at": started_at,
                },
            )
        return run_id

    def fail_run(
        self,
        run_id: str,
        *,
        completed_at: datetime,
        error_code: str,
    ) -> None:
        with self._engine().begin() as connection:
            connection.execute(
                text(
                    """
                    UPDATE classification_runs
                    SET status = 'failed',
                        completed_at = :completed_at,
                        bounded_errors_json = CAST(:errors AS JSONB)
                    WHERE run_id = :run_id
                    """
                ),
                {
                    "run_id": run_id,
                    "completed_at": completed_at,
                    "errors": _json([bounded_text(error_code, limit=80)]),
                },
            )

    def complete_run(
        self,
        run_id: str,
        *,
        completed_at: datetime,
        assets_evaluated: int,
        assets_changed: int,
        conflicts_found: int,
        finding_evaluations: int,
        bounded_errors: Sequence[str],
    ) -> None:
        with self._engine().begin() as connection:
            connection.execute(
                text(
                    """
                    UPDATE classification_runs
                    SET status = 'completed',
                        completed_at = :completed_at,
                        assets_evaluated = :assets_evaluated,
                        assets_changed = :assets_changed,
                        conflicts_found = :conflicts_found,
                        finding_evaluations = :finding_evaluations,
                        bounded_errors_json = CAST(:errors AS JSONB)
                    WHERE run_id = :run_id
                    """
                ),
                {
                    "run_id": run_id,
                    "completed_at": completed_at,
                    "assets_evaluated": assets_evaluated,
                    "assets_changed": assets_changed,
                    "conflicts_found": conflicts_found,
                    "finding_evaluations": finding_evaluations,
                    "errors": _json(
                        [bounded_text(error, limit=80) for error in bounded_errors[:20]]
                    ),
                },
            )

    def current(
        self,
        *,
        site_id: str,
        asset_id: str,
    ) -> dict[str, Any] | None:
        self.ensure_schema()
        with self._engine().begin() as connection:
            row = connection.execute(
                text(
                    """
                    SELECT *
                    FROM asset_classifications
                    WHERE site_id = :site_id AND asset_id = :asset_id
                    """
                ),
                {"site_id": site_id, "asset_id": asset_id},
            ).mappings().first()
            if row is None:
                return None
            return self._project_classification(dict(row))

    def load_evidence(
        self,
        *,
        site_id: str,
        asset_ids: Sequence[str],
    ) -> dict[str, list[ClassificationEvidence]]:
        self.ensure_schema()
        if not asset_ids:
            return {}
        bounded = list(dict.fromkeys(asset_ids))[:500]
        statement = text(
            """
            WITH latest_source_kind AS (
                SELECT
                    ce.*,
                    ROW_NUMBER() OVER (
                        PARTITION BY
                            ce.site_id, ce.asset_id, ce.source_id,
                            ce.source_type, ce.collection_method, ce.evidence_kind
                        ORDER BY ce.last_seen_at DESC, ce.evidence_id
                    ) AS source_kind_rank
                FROM classification_evidence ce
                WHERE ce.site_id = :site_id AND ce.asset_id IN :asset_ids
            ),
            source_bounded AS (
                SELECT
                    latest_source_kind.*,
                    ROW_NUMBER() OVER (
                        PARTITION BY site_id, asset_id, source_type, source_id
                        ORDER BY
                            direct DESC,
                            CASE strength
                                WHEN 'direct' THEN 2
                                WHEN 'medium' THEN 1
                                ELSE 0
                            END DESC,
                            source_confidence DESC,
                            last_seen_at DESC,
                            evidence_id
                    ) AS source_rank
                FROM latest_source_kind
                WHERE source_kind_rank = 1
            ),
            ranked_evidence AS (
                SELECT
                    source_bounded.*,
                    ROW_NUMBER() OVER (
                        PARTITION BY site_id, asset_id
                        ORDER BY
                            direct DESC,
                            CASE strength
                                WHEN 'direct' THEN 2
                                WHEN 'medium' THEN 1
                                ELSE 0
                            END DESC,
                            source_confidence DESC,
                            last_seen_at DESC,
                            evidence_id
                    ) AS asset_rank
                FROM source_bounded
                WHERE source_rank <= :source_limit
            )
            SELECT
                ranked_evidence.evidence_id,
                ranked_evidence.site_id,
                ranked_evidence.asset_id,
                ranked_evidence.source_id,
                ranked_evidence.source_type,
                ranked_evidence.collection_method,
                ranked_evidence.evidence_kind,
                ranked_evidence.observed_value,
                ranked_evidence.observed_at,
                ranked_evidence.first_seen_at,
                ranked_evidence.last_seen_at,
                ranked_evidence.direct,
                ranked_evidence.strength,
                ranked_evidence.source_confidence,
                ranked_evidence.observation_count,
                CASE WHEN ae.identity_status = 'revoked' THEN TRUE ELSE FALSE END
                    AS source_revoked
            FROM ranked_evidence
            LEFT JOIN agent_enrollments ae
              ON ae.site_id = ranked_evidence.site_id
             AND ae.agent_id = ranked_evidence.source_id
            WHERE ranked_evidence.asset_rank <= :evidence_limit
            ORDER BY
                ranked_evidence.asset_id,
                ranked_evidence.asset_rank
            """
        ).bindparams(bindparam("asset_ids", expanding=True))
        with self._engine().begin() as connection:
            rows = connection.execute(
                statement,
                {
                    "site_id": site_id,
                    "asset_ids": bounded,
                    "evidence_limit": MAX_CLASSIFICATION_EVIDENCE,
                    "source_limit": MAX_CLASSIFICATION_EVIDENCE_PER_SOURCE,
                },
            ).mappings().all()
        grouped: dict[str, list[ClassificationEvidence]] = {asset_id: [] for asset_id in bounded}
        for row in rows:
            asset_id = str(row["asset_id"])
            values = grouped.setdefault(asset_id, [])
            if len(values) >= MAX_CLASSIFICATION_EVIDENCE:
                continue
            values.append(
                ClassificationEvidence(
                    evidence_id=str(row["evidence_id"]),
                    site_id=str(row["site_id"]),
                    asset_id=asset_id,
                    source_id=str(row["source_id"]),
                    source_type=str(row["source_type"]),
                    collection_method=str(row["collection_method"]),
                    kind=str(row["evidence_kind"]),
                    value=str(row["observed_value"]),
                    observed_at=row["observed_at"],
                    first_seen_at=row["first_seen_at"],
                    last_seen_at=row["last_seen_at"],
                    direct=bool(row["direct"]),
                    strength=str(row["strength"]),  # type: ignore[arg-type]
                    source_confidence=float(row["source_confidence"]),
                    observation_count=int(row["observation_count"]),
                    source_revoked=bool(row["source_revoked"]),
                )
            )
        return grouped

    def reconcile(
        self,
        *,
        run_id: str,
        result: ClassificationResult,
    ) -> ClassificationReconcileResult:
        self.ensure_schema()
        payload = result.as_dict()
        with self._engine().begin() as connection:
            connection.execute(
                text(
                    "SELECT pg_advisory_xact_lock("
                    "hashtextextended(:lock_key, 0))"
                ),
                {
                    "lock_key": (
                        "openassetwatch-classification:"
                        f"{result.site_id}:{result.asset_id}"
                    )
                },
            )
            previous_row = connection.execute(
                text(
                    """
                    SELECT *
                    FROM asset_classifications
                    WHERE site_id = :site_id AND asset_id = :asset_id
                    FOR UPDATE
                    """
                ),
                {"site_id": result.site_id, "asset_id": result.asset_id},
            ).mappings().first()
            previous = (
                self._project_classification(dict(previous_row))
                if previous_row is not None
                else None
            )
            if (
                previous is not None
                and previous.get("evaluated_at") is not None
                and previous["evaluated_at"] > result.evaluated_at
            ):
                return ClassificationReconcileResult(
                    changed=False,
                    conflict_count=0,
                )
            changed = classification_changed(previous, result)
            first_classified_at = (
                previous["first_classified_at"]
                if previous is not None
                else result.first_classified_at
            )
            if changed and previous is not None:
                connection.execute(
                    text(
                        """
                        INSERT INTO asset_classification_history (
                            classification_id, site_id, asset_id,
                            classifier_version, snapshot_json, valid_from,
                            superseded_at, superseded_by_run_id
                        )
                        VALUES (
                            :classification_id, :site_id, :asset_id,
                            :classifier_version, CAST(:snapshot_json AS JSONB),
                            :valid_from, :superseded_at, :run_id
                        )
                        """
                    ),
                    {
                        "classification_id": result.classification_id,
                        "site_id": result.site_id,
                        "asset_id": result.asset_id,
                        "classifier_version": previous["classifier_version"],
                        "snapshot_json": _json(previous),
                        "valid_from": previous_row["updated_at"],
                        "superseded_at": result.evaluated_at,
                        "run_id": run_id,
                    },
                )
            connection.execute(
                text(
                    """
                    INSERT INTO asset_classifications (
                        classification_id, site_id, asset_id, classifier_version,
                        category, subtype, manufacturer, product_hint,
                        os_family, os_version_hint, managed_capability_json,
                        confidence, status, supporting_evidence_ids_json,
                        conflicting_evidence_ids_json, independent_source_count,
                        evidence_count, first_classified_at, last_classified_at,
                        evaluated_at, superseded_at, freshness,
                        reason_codes_json, conflicts_json, last_run_id
                    )
                    VALUES (
                        :classification_id, :site_id, :asset_id, :classifier_version,
                        :category, :subtype, :manufacturer, :product_hint,
                        :os_family, :os_version_hint, CAST(:managed AS JSONB),
                        :confidence, :status, CAST(:supporting AS JSONB),
                        CAST(:conflicting AS JSONB), :independent_source_count,
                        :evidence_count, :first_classified_at, :last_classified_at,
                        :evaluated_at, NULL, :freshness,
                        CAST(:reasons AS JSONB), CAST(:conflicts AS JSONB), :run_id
                    )
                    ON CONFLICT (classification_id) DO UPDATE SET
                        classifier_version = EXCLUDED.classifier_version,
                        category = EXCLUDED.category,
                        subtype = EXCLUDED.subtype,
                        manufacturer = EXCLUDED.manufacturer,
                        product_hint = EXCLUDED.product_hint,
                        os_family = EXCLUDED.os_family,
                        os_version_hint = EXCLUDED.os_version_hint,
                        managed_capability_json = EXCLUDED.managed_capability_json,
                        confidence = EXCLUDED.confidence,
                        status = EXCLUDED.status,
                        supporting_evidence_ids_json = EXCLUDED.supporting_evidence_ids_json,
                        conflicting_evidence_ids_json = EXCLUDED.conflicting_evidence_ids_json,
                        independent_source_count = EXCLUDED.independent_source_count,
                        evidence_count = EXCLUDED.evidence_count,
                        first_classified_at = EXCLUDED.first_classified_at,
                        last_classified_at = EXCLUDED.last_classified_at,
                        evaluated_at = EXCLUDED.evaluated_at,
                        superseded_at = NULL,
                        freshness = EXCLUDED.freshness,
                        reason_codes_json = EXCLUDED.reason_codes_json,
                        conflicts_json = EXCLUDED.conflicts_json,
                        last_run_id = EXCLUDED.last_run_id,
                        updated_at = CASE
                            WHEN :changed THEN NOW()
                            ELSE asset_classifications.updated_at
                        END
                    WHERE asset_classifications.evaluated_at <= EXCLUDED.evaluated_at
                    """
                ),
                {
                    "classification_id": result.classification_id,
                    "site_id": result.site_id,
                    "asset_id": result.asset_id,
                    "classifier_version": result.classifier_version,
                    "category": result.category,
                    "subtype": result.subtype,
                    "manufacturer": result.manufacturer,
                    "product_hint": result.product_hint,
                    "os_family": result.os_family,
                    "os_version_hint": result.os_version_hint,
                    "managed": _json(result.managed_capability.as_dict()),
                    "confidence": result.confidence,
                    "status": result.status,
                    "supporting": _json(result.supporting_evidence_ids),
                    "conflicting": _json(result.conflicting_evidence_ids),
                    "independent_source_count": result.independent_source_count,
                    "evidence_count": result.evidence_count,
                    "first_classified_at": first_classified_at,
                    "last_classified_at": result.last_classified_at,
                    "evaluated_at": result.evaluated_at,
                    "freshness": result.freshness,
                    "reasons": _json(result.reason_codes),
                    "conflicts": _json([conflict.as_dict() for conflict in result.conflicts]),
                    "run_id": run_id,
                    "changed": changed,
                },
            )
            connection.execute(
                text(
                    "DELETE FROM asset_classification_evidence "
                    "WHERE classification_id = :classification_id"
                ),
                {"classification_id": result.classification_id},
            )
            references = (
                ("supporting", result.supporting_evidence_ids),
                ("conflicting", result.conflicting_evidence_ids),
            )
            for relation, evidence_ids in references:
                for ordinal, evidence_id in enumerate(evidence_ids):
                    connection.execute(
                        text(
                            """
                            INSERT INTO asset_classification_evidence (
                                classification_id, evidence_id, relation, ordinal
                            )
                            VALUES (
                                :classification_id, :evidence_id, :relation, :ordinal
                            )
                            ON CONFLICT DO NOTHING
                            """
                        ),
                        {
                            "classification_id": result.classification_id,
                            "evidence_id": evidence_id,
                            "relation": relation,
                            "ordinal": ordinal,
                        },
                    )
            connection.execute(
                text(
                    """
                    UPDATE classification_evidence
                    SET classifier_used = FALSE,
                        agreement_state = 'unused',
                        updated_at = NOW()
                    WHERE site_id = :site_id AND asset_id = :asset_id
                    """
                ),
                {"site_id": result.site_id, "asset_id": result.asset_id},
            )
            for relation, evidence_ids in references:
                if not evidence_ids:
                    continue
                update_statement = text(
                    """
                    UPDATE classification_evidence
                    SET classifier_used = TRUE,
                        agreement_state = :agreement_state,
                        updated_at = NOW()
                    WHERE evidence_id IN :evidence_ids
                    """
                ).bindparams(bindparam("evidence_ids", expanding=True))
                connection.execute(
                    update_statement,
                    {
                        "agreement_state": relation,
                        "evidence_ids": list(evidence_ids),
                    },
                )
            connection.execute(
                text(
                    """
                    UPDATE classification_conflicts
                    SET status = 'resolved',
                        resolved_at = :evaluated_at,
                        last_run_id = :run_id
                    WHERE classification_id = :classification_id
                      AND status = 'open'
                    """
                ),
                {
                    "classification_id": result.classification_id,
                    "evaluated_at": result.evaluated_at,
                    "run_id": run_id,
                },
            )
            for conflict in result.conflicts:
                conflict_id = conflict_id_for(
                    classification_id=result.classification_id,
                    conflict_type=conflict.conflict_type,
                    selected_value=conflict.selected_value,
                    conflicting_value=conflict.conflicting_value,
                )
                connection.execute(
                    text(
                        """
                        INSERT INTO classification_conflicts (
                            conflict_id, classification_id, site_id, asset_id,
                            conflict_type, selected_value, conflicting_value,
                            supporting_evidence_ids_json,
                            conflicting_evidence_ids_json, reason_code, status,
                            first_seen_at, last_seen_at, resolved_at, last_run_id
                        )
                        VALUES (
                            :conflict_id, :classification_id, :site_id, :asset_id,
                            :conflict_type, :selected_value, :conflicting_value,
                            CAST(:supporting AS JSONB), CAST(:conflicting AS JSONB),
                            :reason_code, 'open', :evaluated_at, :evaluated_at,
                            NULL, :run_id
                        )
                        ON CONFLICT (conflict_id) DO UPDATE SET
                            selected_value = EXCLUDED.selected_value,
                            conflicting_value = EXCLUDED.conflicting_value,
                            supporting_evidence_ids_json = EXCLUDED.supporting_evidence_ids_json,
                            conflicting_evidence_ids_json = EXCLUDED.conflicting_evidence_ids_json,
                            reason_code = EXCLUDED.reason_code,
                            status = 'open',
                            last_seen_at = EXCLUDED.last_seen_at,
                            resolved_at = NULL,
                            last_run_id = EXCLUDED.last_run_id
                        """
                    ),
                    {
                        "conflict_id": conflict_id,
                        "classification_id": result.classification_id,
                        "site_id": result.site_id,
                        "asset_id": result.asset_id,
                        "conflict_type": conflict.conflict_type,
                        "selected_value": conflict.selected_value,
                        "conflicting_value": conflict.conflicting_value,
                        "supporting": _json(conflict.supporting_evidence_ids),
                        "conflicting": _json(conflict.conflicting_evidence_ids),
                        "reason_code": conflict.reason_code,
                        "evaluated_at": result.evaluated_at,
                        "run_id": run_id,
                    },
                )
        return ClassificationReconcileResult(
            changed=changed,
            conflict_count=len(result.conflicts),
        )

    @staticmethod
    def _project_classification(item: dict[str, Any]) -> dict[str, Any]:
        item["managed_capability"] = _json_value(
            item.pop("managed_capability_json", item.get("managed_capability")),
            {},
        )
        item["supporting_evidence_ids"] = _json_value(
            item.pop(
                "supporting_evidence_ids_json",
                item.get("supporting_evidence_ids"),
            ),
            [],
        )
        item["conflicting_evidence_ids"] = _json_value(
            item.pop(
                "conflicting_evidence_ids_json",
                item.get("conflicting_evidence_ids"),
            ),
            [],
        )
        item["reason_codes"] = _json_value(
            item.pop("reason_codes_json", item.get("reason_codes")),
            [],
        )
        item["conflicts"] = _json_value(
            item.pop("conflicts_json", item.get("conflicts")),
            [],
        )
        for field in ("last_run_id", "created_at", "updated_at"):
            item.pop(field, None)
        return item

    def list_classifications(
        self,
        *,
        site_id: str | None = None,
        category: str | None = None,
        manufacturer: str | None = None,
        os_family: str | None = None,
        managed_capability: str | None = None,
        status: str | None = None,
        minimum_confidence: float | None = None,
        conflict_state: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        self.ensure_schema()
        bounded_limit = max(1, min(limit, 200))
        bounded_offset = max(0, min(offset, 10_000))
        clauses = ["1 = 1"]
        params: dict[str, Any] = {}
        if site_id:
            clauses.append("site_id = :site_id")
            params["site_id"] = site_id
        if category:
            clauses.append("category = :category")
            params["category"] = category
        if manufacturer:
            clauses.append("LOWER(manufacturer) = LOWER(:manufacturer)")
            params["manufacturer"] = manufacturer
        if os_family:
            clauses.append("LOWER(os_family) = LOWER(:os_family)")
            params["os_family"] = os_family
        if managed_capability:
            clauses.append(
                "managed_capability_json ->> 'endpoint_collector' = :managed_capability"
            )
            params["managed_capability"] = managed_capability
        if status:
            clauses.append("status = :status")
            params["status"] = status
        if minimum_confidence is not None:
            clauses.append("confidence >= :minimum_confidence")
            params["minimum_confidence"] = max(0.0, min(minimum_confidence, 1.0))
        if conflict_state == "open":
            clauses.append(
                "EXISTS (SELECT 1 FROM classification_conflicts cc "
                "WHERE cc.classification_id = asset_classifications.classification_id "
                "AND cc.status = 'open')"
            )
        elif conflict_state == "none":
            clauses.append(
                "NOT EXISTS (SELECT 1 FROM classification_conflicts cc "
                "WHERE cc.classification_id = asset_classifications.classification_id "
                "AND cc.status = 'open')"
            )
        where = " AND ".join(clauses)
        with self._engine().begin() as connection:
            total = int(
                connection.execute(
                    text(f"SELECT COUNT(*) FROM asset_classifications WHERE {where}"),  # noqa: S608 - fixed clauses only.
                    params,
                ).scalar_one()
            )
            rows = connection.execute(
                text(
                    f"""
                    SELECT *
                    FROM asset_classifications
                    WHERE {where}
                    ORDER BY confidence DESC, site_id, asset_id
                    LIMIT :limit OFFSET :offset
                    """  # noqa: S608 - fixed clauses only.
                ),
                {**params, "limit": bounded_limit, "offset": bounded_offset},
            ).mappings().all()
        items = [self._project_classification(dict(row)) for row in rows]
        return {
            "items": items,
            "total": total,
            "limit": bounded_limit,
            "offset": bounded_offset,
            "truncated": bounded_offset + len(items) < total,
        }

    def get_classification(
        self,
        *,
        site_id: str,
        asset_id: str,
    ) -> dict[str, Any] | None:
        return self.current(site_id=site_id, asset_id=asset_id)

    def list_evidence(
        self,
        *,
        site_id: str,
        asset_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        self.ensure_schema()
        bounded_limit = max(1, min(limit, 200))
        bounded_offset = max(0, min(offset, 10_000))
        params = {"site_id": site_id, "asset_id": asset_id}
        with self._engine().begin() as connection:
            total = int(
                connection.execute(
                    text(
                        """
                        SELECT COUNT(*) FROM classification_evidence
                        WHERE site_id = :site_id AND asset_id = :asset_id
                        """
                    ),
                    params,
                ).scalar_one()
            )
            rows = connection.execute(
                text(
                    """
                    SELECT
                        ce.evidence_id, ce.site_id, ce.asset_id, ce.source_id,
                        ce.source_type, ce.collection_method,
                        ce.evidence_kind AS kind, ce.observed_value AS value,
                        ce.observed_at, ce.first_seen_at, ce.last_seen_at,
                        ce.direct, ce.strength, ce.source_confidence,
                        ce.observation_count, ce.agreement_state,
                        ce.classifier_used,
                        CASE WHEN ae.identity_status = 'revoked'
                            THEN TRUE ELSE FALSE END AS source_revoked
                    FROM classification_evidence ce
                    LEFT JOIN agent_enrollments ae
                      ON ae.site_id = ce.site_id AND ae.agent_id = ce.source_id
                    WHERE ce.site_id = :site_id AND ce.asset_id = :asset_id
                    ORDER BY ce.last_seen_at DESC, ce.evidence_id
                    LIMIT :limit OFFSET :offset
                    """
                ),
                {**params, "limit": bounded_limit, "offset": bounded_offset},
            ).mappings().all()
        items = [dict(row) for row in rows]
        return {
            "items": items,
            "total": total,
            "limit": bounded_limit,
            "offset": bounded_offset,
            "truncated": bounded_offset + len(items) < total,
        }

    def evidence_snapshot(
        self,
        *,
        site_id: str | None = None,
        limit: int = 1_000,
    ) -> list[dict[str, Any]]:
        """Load one bounded evidence snapshot without per-asset queries."""

        self.ensure_schema()
        bounded_limit = max(1, min(limit, 5_000))
        with self._engine().begin() as connection:
            rows = connection.execute(
                text(
                    """
                    SELECT
                        ce.evidence_id, ce.site_id, ce.asset_id, ce.source_id,
                        ce.source_type, ce.collection_method,
                        ce.evidence_kind AS kind, ce.observed_value AS value,
                        ce.observed_at, ce.first_seen_at, ce.last_seen_at,
                        ce.direct, ce.strength, ce.source_confidence,
                        ce.observation_count, ce.agreement_state,
                        ce.classifier_used,
                        CASE WHEN ae.identity_status = 'revoked'
                            THEN TRUE ELSE FALSE END AS source_revoked
                    FROM classification_evidence ce
                    LEFT JOIN agent_enrollments ae
                      ON ae.site_id = ce.site_id AND ae.agent_id = ce.source_id
                    WHERE (:site_id IS NULL OR ce.site_id = :site_id)
                    ORDER BY ce.last_seen_at DESC, ce.evidence_id
                    LIMIT :limit
                    """
                ),
                {"site_id": site_id, "limit": bounded_limit},
            ).mappings().all()
        return [dict(row) for row in rows]

    def site_summary(self, *, site_id: str | None = None) -> dict[str, Any]:
        self.ensure_schema()
        params = {"site_id": site_id}
        with self._engine().begin() as connection:
            rows = connection.execute(
                text(
                    """
                    SELECT category, status,
                           managed_capability_json ->> 'endpoint_collector'
                               AS endpoint_expectation,
                           COUNT(*) AS count,
                           MAX(evaluated_at) AS data_as_of
                    FROM asset_classifications
                    WHERE (:site_id IS NULL OR site_id = :site_id)
                    GROUP BY category, status, endpoint_expectation
                    ORDER BY category, status, endpoint_expectation
                    """
                ),
                params,
            ).mappings().all()
            conflict_count = int(
                connection.execute(
                    text(
                        """
                        SELECT COUNT(*)
                        FROM classification_conflicts
                        WHERE status = 'open'
                          AND (:site_id IS NULL OR site_id = :site_id)
                        """
                    ),
                    params,
                ).scalar_one()
            )
        categories: dict[str, int] = {}
        statuses: dict[str, int] = {}
        expectations: dict[str, int] = {}
        total = 0
        data_as_of: datetime | None = None
        for row in rows:
            count = int(row["count"])
            total += count
            categories[str(row["category"])] = categories.get(str(row["category"]), 0) + count
            statuses[str(row["status"])] = statuses.get(str(row["status"]), 0) + count
            expectation = str(row["endpoint_expectation"] or "unknown")
            expectations[expectation] = expectations.get(expectation, 0) + count
            timestamp = row["data_as_of"]
            if timestamp is not None and (data_as_of is None or timestamp > data_as_of):
                data_as_of = timestamp
        return {
            "site_id": site_id,
            "classification_count": total,
            "conflict_count": conflict_count,
            "unknown_count": categories.get("unknown", 0),
            "categories": categories,
            "statuses": statuses,
            "endpoint_collector_expectations": expectations,
            "data_as_of": data_as_of,
            "classifier_version": CLASSIFIER_VERSION,
        }


class InMemoryClassificationStore:
    """Small deterministic store used by service and lifecycle tests."""

    def __init__(self) -> None:
        self.current_records: dict[tuple[str, str], dict[str, Any]] = {}
        self.history: list[dict[str, Any]] = []
        self.runs: dict[str, dict[str, Any]] = {}
        self.evidence: dict[tuple[str, str], list[ClassificationEvidence]] = {}

    def begin_run(self, **values: Any) -> str:
        run_id = f"crun_{len(self.runs) + 1:032x}"
        self.runs[run_id] = {"status": "running", **values}
        return run_id

    def fail_run(self, run_id: str, **values: Any) -> None:
        self.runs[run_id].update(status="failed", **values)

    def complete_run(self, run_id: str, **values: Any) -> None:
        self.runs[run_id].update(status="completed", **values)

    def current(self, *, site_id: str, asset_id: str) -> dict[str, Any] | None:
        item = self.current_records.get((site_id, asset_id))
        return dict(item) if item else None

    def load_evidence(
        self,
        *,
        site_id: str,
        asset_ids: Sequence[str],
    ) -> dict[str, list[ClassificationEvidence]]:
        return {
            asset_id: list(self.evidence.get((site_id, asset_id), []))
            for asset_id in asset_ids
        }

    def reconcile(
        self,
        *,
        run_id: str,
        result: ClassificationResult,
    ) -> ClassificationReconcileResult:
        key = (result.site_id, result.asset_id)
        previous = self.current_records.get(key)
        if (
            previous
            and previous.get("evaluated_at") is not None
            and previous["evaluated_at"] > result.evaluated_at
        ):
            return ClassificationReconcileResult(
                changed=False,
                conflict_count=0,
            )
        changed = classification_changed(previous, result)
        if changed and previous:
            self.history.append(
                {
                    **previous,
                    "superseded_at": result.evaluated_at,
                    "superseded_by_run_id": run_id,
                }
            )
        payload = result.as_dict()
        if previous:
            payload["first_classified_at"] = previous["first_classified_at"]
        self.current_records[key] = payload
        return ClassificationReconcileResult(
            changed=changed,
            conflict_count=len(result.conflicts),
        )
