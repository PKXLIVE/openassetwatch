"""Transactional persistence for server-owned canonical inventory envelopes."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text

from . import database as db


LOGGER = logging.getLogger(__name__)
CANONICAL_ADMISSION_WINDOW = timedelta(minutes=1)
CANONICAL_ADMISSION_LIMITS = {
    "endpoint-agent": 12,
    "passive-sensor": 120,
    "python-collector": 30,
    "transitional-local": 30,
}
LOWER_TRUST_GLOBAL_ADMISSION_MULTIPLIER = 10
LOWER_TRUST_ADMISSION_LOCK_IDS = {
    "passive-sensor": 0x4F415701,
    "python-collector": 0x4F415702,
    "transitional-local": 0x4F415703,
}


def _event(
    connection: Any,
    *,
    envelope: Any,
    event_type: str,
    outcome: str,
    metadata: dict[str, Any],
) -> None:
    connection.execute(
        text(
            """
            INSERT INTO ingestion_compatibility_events (
                event_type, outcome, route_name, adapter_type, site_id,
                source_id, canonical_collection_id, metadata_json, created_at
            ) VALUES (
                :event_type, :outcome, :route_name, :adapter_type, :site_id,
                :source_id, :canonical_collection_id,
                CAST(:metadata_json AS JSONB), :created_at
            )
            """
        ),
        {
            "event_type": event_type,
            "outcome": outcome,
            "route_name": envelope.route_name,
            "adapter_type": envelope.adapter_type,
            "site_id": envelope.site_id,
            "source_id": envelope.source_id,
            "canonical_collection_id": envelope.canonical_collection_id,
            "metadata_json": db._json_payload(metadata),
            "created_at": envelope.ingested_at,
        },
    )


def _verify_bound_credential(connection: Any, *, envelope: Any) -> None:
    from .canonical_ingestion import CanonicalAuthorizationRejected

    if envelope.source_authority == "authenticated-endpoint":
        row = connection.execute(
            text(
                """
                SELECT 1
                FROM endpoint_agent_credentials c
                JOIN agent_enrollments a
                  ON a.agent_id = c.agent_id
                 AND a.site_id = c.site_id
                 AND a.agent_type = c.agent_type
                WHERE c.credential_id = :credential_id
                  AND c.agent_id = :identity_id
                  AND c.site_id = :site_id
                  AND c.agent_type = 'endpoint-agent'
                  AND c.status = 'active'
                  AND (c.expires_at IS NULL OR c.expires_at > :received_at)
                  AND a.identity_status = 'active'
                FOR UPDATE OF c, a
                """
            ),
            {
                "credential_id": envelope.credential_id,
                "identity_id": envelope.bound_identity_id,
                "site_id": envelope.site_id,
                "received_at": envelope.ingested_at,
            },
        ).scalar_one_or_none()
        if row is None:
            raise CanonicalAuthorizationRejected(
                "bound endpoint-agent credential is no longer active"
            )
    elif envelope.source_authority == "authenticated-passive-sensor":
        row = connection.execute(
            text(
                """
                SELECT 1
                FROM sensor_credentials c
                JOIN agent_enrollments a
                  ON a.agent_id = c.sensor_id
                 AND a.site_id = c.site_id
                WHERE c.credential_id = :credential_id
                  AND c.sensor_id = :identity_id
                  AND c.site_id = :site_id
                  AND c.sensor_type = 'passive-network-sensor'
                  AND c.status = 'active'
                  AND (c.expires_at IS NULL OR c.expires_at > :received_at)
                  AND a.agent_type = 'network-sensor'
                  AND a.identity_status = 'active'
                FOR UPDATE OF c, a
                """
            ),
            {
                "credential_id": envelope.credential_id,
                "identity_id": envelope.bound_identity_id,
                "site_id": envelope.site_id,
                "received_at": envelope.ingested_at,
            },
        ).scalar_one_or_none()
        if row is None:
            raise CanonicalAuthorizationRejected(
                "bound passive-sensor credential is no longer active"
            )


def _upsert_source(connection: Any, *, envelope: Any) -> None:
    result = connection.execute(
        text(
            """
            INSERT INTO canonical_ingestion_sources (
                source_id, site_id, source_identity, source_type,
                adapter_type, authentication_class, source_authority,
                trust_rank, compatibility_status, first_seen_at, last_seen_at
            ) VALUES (
                :source_id, :site_id, :source_identity, :source_type,
                :adapter_type, :authentication_class, :source_authority,
                :trust_rank, :compatibility_status, :seen_at, :seen_at
            )
            ON CONFLICT (source_id) DO UPDATE SET
                last_seen_at = GREATEST(
                    canonical_ingestion_sources.last_seen_at,
                    EXCLUDED.last_seen_at
                ),
                updated_at = NOW()
            WHERE canonical_ingestion_sources.site_id = EXCLUDED.site_id
              AND canonical_ingestion_sources.source_identity = EXCLUDED.source_identity
              AND canonical_ingestion_sources.source_type = EXCLUDED.source_type
              AND canonical_ingestion_sources.adapter_type = EXCLUDED.adapter_type
              AND canonical_ingestion_sources.authentication_class = EXCLUDED.authentication_class
              AND canonical_ingestion_sources.source_authority = EXCLUDED.source_authority
              AND canonical_ingestion_sources.trust_rank = EXCLUDED.trust_rank
              AND canonical_ingestion_sources.compatibility_status = EXCLUDED.compatibility_status
            """
        ),
        {
            "source_id": envelope.source_id,
            "site_id": envelope.site_id,
            "source_identity": envelope.source_identity,
            "source_type": envelope.source_type,
            "adapter_type": envelope.adapter_type,
            "authentication_class": envelope.authentication_class,
            "source_authority": envelope.source_authority,
            "trust_rank": envelope.trust_rank,
            "compatibility_status": envelope.compatibility_status,
            "seen_at": envelope.ingested_at,
        },
    )
    if result.rowcount != 1:
        from .canonical_ingestion import CanonicalAuthorizationRejected

        raise CanonicalAuthorizationRejected(
            "canonical source identity conflicts with its persisted trust domain"
        )


def _update_sensor_status(connection: Any, *, envelope: Any) -> None:
    if envelope.adapter_type != "passive-sensor":
        return
    agent_id = (
        envelope.bound_identity_id
        if envelope.source_authority == "authenticated-passive-sensor"
        else envelope.source_id
    )
    identity_status = (
        "active"
        if envelope.source_authority == "authenticated-passive-sensor"
        else "legacy"
    )
    result = connection.execute(
        text(
            """
            INSERT INTO agent_enrollments (
                agent_id, site_id, display_name, agent_type, version,
                hostname, mode, last_seen_at, identity_status
            ) VALUES (
                :agent_id, :site_id, :display_name, 'network-sensor',
                :version, :display_name, 'passive-network', :last_seen_at,
                :identity_status
            )
            ON CONFLICT (agent_id) DO UPDATE SET
                display_name = EXCLUDED.display_name,
                version = EXCLUDED.version,
                hostname = EXCLUDED.hostname,
                mode = EXCLUDED.mode,
                last_seen_at = GREATEST(
                    COALESCE(agent_enrollments.last_seen_at, EXCLUDED.last_seen_at),
                    EXCLUDED.last_seen_at
                ),
                updated_at = GREATEST(agent_enrollments.updated_at, EXCLUDED.last_seen_at)
            WHERE agent_enrollments.site_id = EXCLUDED.site_id
              AND agent_enrollments.agent_type = 'network-sensor'
              AND agent_enrollments.identity_status = :identity_status
            """
        ),
        {
            "agent_id": agent_id,
            "site_id": envelope.site_id,
            "display_name": envelope.provenance.get("sensor_name") or agent_id,
            "version": envelope.provenance.get("sensor_version"),
            "last_seen_at": envelope.ingested_at,
            "identity_status": identity_status,
        },
    )
    if result.rowcount != 1:
        from .canonical_ingestion import CanonicalAuthorizationRejected

        raise CanonicalAuthorizationRejected(
            "observation identity no longer matches its trust domain"
        )


def _store_legacy_submission(connection: Any, *, envelope: Any) -> int | None:
    """Retain one non-authoritative collector submission and status projection."""

    legacy = envelope.legacy_submission
    if not isinstance(legacy, dict):
        return None
    submission_id = int(
        connection.execute(
            text(
                """
                INSERT INTO collector_inventory_submissions (
                    collector_guid, collector_id, collector_name, mode,
                    schema_version, collector_version, collected_at, received_at,
                    device_count, network_observation_count, software_count,
                    payload_json
                ) VALUES (
                    :collector_guid, :collector_id, :collector_name, :mode,
                    :schema_version, :collector_version, :collected_at, :received_at,
                    :device_count, :network_observation_count, :software_count,
                    CAST(:payload_json AS JSONB)
                )
                RETURNING id
                """
            ),
            {
                "collector_guid": legacy.get("collector_guid"),
                "collector_id": legacy.get("collector_id"),
                "collector_name": legacy.get("collector_name"),
                "mode": legacy.get("mode"),
                "schema_version": legacy.get("schema_version"),
                "collector_version": legacy.get("collector_version"),
                "collected_at": db._parse_datetime(legacy.get("collected_at")),
                "received_at": envelope.ingested_at,
                "device_count": int(legacy.get("device_count") or 0),
                "network_observation_count": int(legacy.get("network_observation_count") or 0),
                "software_count": int(legacy.get("software_count") or 0),
                "payload_json": db._json_payload(legacy.get("payload") or {}),
            },
        ).scalar_one()
    )
    db._upsert_collector(
        connection,
        collector_guid=db._clean_text(legacy.get("collector_guid")),
        collector_id=db._clean_text(legacy.get("collector_id")),
        collector_name=db._clean_text(legacy.get("collector_name")),
        collector_version=db._clean_text(legacy.get("collector_version")),
        deployment=db._metadata_object(legacy.get("deployment")),
        labels=db._metadata_object(legacy.get("labels")),
        supported_capabilities=db._capability_list(legacy.get("supported_capabilities")),
        enabled_capabilities=db._capability_list(legacy.get("enabled_capabilities")),
        mode=db._clean_text(legacy.get("mode")),
        seen_at=envelope.ingested_at,
        last_submission_id=submission_id,
    )
    return submission_id


def should_replace_asset_authority(
    *,
    current_trust_rank: int | None,
    current_observed_at: datetime | None,
    incoming_trust_rank: int,
    incoming_observed_at: datetime,
) -> bool:
    """Return the deterministic field-authority decision for one asset."""

    if current_trust_rank is None or current_observed_at is None:
        return True
    return incoming_trust_rank > current_trust_rank or (
        incoming_trust_rank == current_trust_rank
        and incoming_observed_at >= current_observed_at
    )


def _persist_asset(
    connection: Any,
    *,
    envelope: Any,
    asset: dict[str, Any],
) -> bool:
    """Update canonical asset state under the persisted trust decision."""

    current = connection.execute(
        text(
            """
            SELECT trust_rank, observed_at
            FROM canonical_asset_authority
            WHERE asset_key = :asset_key
            FOR UPDATE
            """
        ),
        {"asset_key": asset["asset_key"]},
    ).mappings().one_or_none()
    current_trust_rank = int(current["trust_rank"]) if current else None
    replace_current = should_replace_asset_authority(
        current_trust_rank=current_trust_rank,
        current_observed_at=(current["observed_at"] if current else None),
        incoming_trust_rank=envelope.trust_rank,
        incoming_observed_at=envelope.observed_at,
    )
    if not replace_current:
        # The accepted collection retains this observation and provenance, but
        # a lower-trust source must not alter authoritative freshness, counts,
        # identity, or descriptive state in the current asset projection.
        return False

    db._upsert_control_tower_asset(connection, asset)
    if current_trust_rank is None or envelope.trust_rank > current_trust_rank:
        # The compatibility projection's legacy helper prefers newer timestamps.
        # Canonical authority has already made the stronger persisted trust
        # decision, so a higher-trust observation must replace every current
        # descriptive field even when a lower-trust observation claimed a
        # later timestamp. Historical lower-trust evidence remains in its
        # immutable collection and compatibility mapping.
        connection.execute(
            text(
                """
                UPDATE control_tower_assets
                SET hostname = :hostname,
                    primary_ip = :primary_ip,
                    mac = :mac,
                    os = :os,
                    platform = :platform,
                    source_agent_id = :source_agent_id,
                    last_seen_at = :last_seen_at,
                    evidence_count = :evidence_count,
                    observation_batch_id = :observation_batch_id,
                    observation_source = :observation_source,
                    observed_at = :observed_at,
                    delivery_state = :delivery_state,
                    confidence = :confidence,
                    metadata_json = CAST(:metadata_json AS JSONB),
                    updated_at = NOW()
                WHERE asset_key = :asset_key
                """
            ),
            {
                "asset_key": asset["asset_key"],
                "hostname": asset["hostname"],
                "primary_ip": asset["primary_ip"],
                "mac": asset["mac"],
                "os": asset["os"],
                "platform": asset["platform"],
                "source_agent_id": asset["source_agent_id"],
                "last_seen_at": asset["last_seen_at"],
                "evidence_count": asset["evidence_count"],
                "observation_batch_id": asset["observation_batch_id"],
                "observation_source": asset["observation_source"],
                "observed_at": asset["observed_at"],
                "delivery_state": asset["delivery_state"],
                "confidence": asset["confidence"],
                "metadata_json": db._json_payload(asset["metadata"]),
            },
        )
    connection.execute(
        text(
            """
            INSERT INTO canonical_asset_authority (
                asset_key, site_id, asset_id, canonical_collection_id,
                source_id, adapter_type, source_authority, trust_rank,
                compatibility_status, observed_at, updated_at
            ) VALUES (
                :asset_key, :site_id, :asset_id, :collection_id,
                :source_id, :adapter_type, :source_authority, :trust_rank,
                :compatibility_status, :observed_at, :updated_at
            )
            ON CONFLICT (asset_key) DO UPDATE SET
                canonical_collection_id = EXCLUDED.canonical_collection_id,
                source_id = EXCLUDED.source_id,
                adapter_type = EXCLUDED.adapter_type,
                source_authority = EXCLUDED.source_authority,
                trust_rank = EXCLUDED.trust_rank,
                compatibility_status = EXCLUDED.compatibility_status,
                observed_at = EXCLUDED.observed_at,
                updated_at = EXCLUDED.updated_at
            """
        ),
        {
            "asset_key": asset["asset_key"],
            "site_id": asset["site_id"],
            "asset_id": asset["asset_id"],
            "collection_id": envelope.canonical_collection_id,
            "source_id": envelope.source_id,
            "adapter_type": envelope.adapter_type,
            "source_authority": envelope.source_authority,
            "trust_rank": envelope.trust_rank,
            "compatibility_status": envelope.compatibility_status,
            "observed_at": envelope.observed_at,
            "updated_at": envelope.ingested_at,
        },
    )
    return True


def _existing_replay(connection: Any, *, envelope: Any) -> dict[str, Any] | None:
    from .canonical_ingestion import CanonicalReplayConflict

    existing = connection.execute(
        text(
            """
            SELECT canonical_collection_id, payload_sha256,
                   compatibility_collection_id, legacy_submission_id,
                   canonical_asset_count, evidence_count, component_count,
                   evaluation_state, evaluation_asset_ids_json, replay_count
            FROM canonical_inventory_collections
            WHERE source_id = :source_id
              AND idempotency_key = :idempotency_key
            """
        ),
        {
            "source_id": envelope.source_id,
            "idempotency_key": envelope.idempotency_key,
        },
    ).mappings().one_or_none()
    if existing is None:
        return None
    if (
        str(existing["canonical_collection_id"])
        != envelope.canonical_collection_id
        or str(existing["payload_sha256"]) != envelope.payload_sha256
    ):
        raise CanonicalReplayConflict("canonical idempotency content conflict")
    replay_updated = False
    # Retain bounded replay audit evidence without allowing an identical
    # delivery loop to amplify event-table growth indefinitely.
    if int(existing["replay_count"]) < 16:
        replay_updated = bool(
            connection.execute(
                text(
                    """
                    UPDATE canonical_inventory_collections
                    SET replay_count = replay_count + 1,
                        updated_at = NOW()
                    WHERE canonical_collection_id = :collection_id
                      AND replay_count < 16
                    """
                ),
                {"collection_id": envelope.canonical_collection_id},
            ).rowcount
        )
        if replay_updated:
            _event(
                connection,
                envelope=envelope,
                event_type="replay",
                outcome="success",
                metadata={"replay_state": "identical"},
            )
    endpoint_storage_id = None
    if envelope.adapter_type == "endpoint-agent":
        endpoint_storage_id = connection.execute(
            text(
                """
                SELECT storage_id
                FROM endpoint_agent_inventory_batches
                WHERE site_id = :site_id
                  AND agent_id = :agent_id
                  AND inventory_batch_id = :batch_id
                """
            ),
            {
                "site_id": envelope.site_id,
                "agent_id": envelope.bound_identity_id,
                "batch_id": envelope.original_identifier,
            },
        ).scalar_one()
    return {
        "duplicate": True,
        "compatibility_collection_id": int(
            existing["compatibility_collection_id"]
        ),
        "legacy_submission_id": existing["legacy_submission_id"],
        "endpoint_storage_id": endpoint_storage_id,
        "normalized_asset_count": int(existing["canonical_asset_count"]),
        "evidence_count": int(existing["evidence_count"]),
        "component_count": int(existing["component_count"]),
        "evaluation_state": str(existing["evaluation_state"]),
        "asset_ids": list(existing["evaluation_asset_ids_json"] or []),
    }


def _admit_collection(
    connection: Any,
    *,
    envelope: Any,
    normalized_asset_count: int,
) -> str:
    from .canonical_ingestion import CanonicalAdmissionRejected

    lower_trust_site_scope = not envelope.source_authenticated
    if lower_trust_site_scope:
        connection.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": LOWER_TRUST_ADMISSION_LOCK_IDS[envelope.adapter_type]},
        )
        global_batches = int(
            connection.execute(
                text(
                    """
                    SELECT COUNT(*)
                    FROM canonical_inventory_collections c
                    JOIN canonical_ingestion_sources s
                      ON s.source_id = c.source_id
                    WHERE c.ingested_at > :window_start
                      AND c.adapter_type = :adapter_type
                      AND s.authentication_class <> 'bound-credential'
                    """
                ),
                {
                    "window_start": envelope.ingested_at
                    - CANONICAL_ADMISSION_WINDOW,
                    "adapter_type": envelope.adapter_type,
                },
            ).scalar_one()
        )
        if global_batches >= (
            CANONICAL_ADMISSION_LIMITS[envelope.adapter_type]
            * LOWER_TRUST_GLOBAL_ADMISSION_MULTIPLIER
        ):
            raise CanonicalAdmissionRejected(
                "canonical compatibility admission window exceeded"
            )
    recent_batches = int(
        connection.execute(
            text(
                """
                SELECT COUNT(*)
                FROM canonical_inventory_collections
                WHERE ingested_at > :window_start
                  AND (
                      (:site_scope = TRUE
                       AND site_id = :site_id
                       AND adapter_type = :adapter_type)
                      OR
                      (:site_scope = FALSE AND source_id = :source_id)
                  )
                """
            ),
            {
                "window_start": envelope.ingested_at
                - CANONICAL_ADMISSION_WINDOW,
                "site_scope": lower_trust_site_scope,
                "site_id": envelope.site_id,
                "adapter_type": envelope.adapter_type,
                "source_id": envelope.source_id,
            },
        ).scalar_one()
    )
    if recent_batches >= CANONICAL_ADMISSION_LIMITS[envelope.adapter_type]:
        raise CanonicalAdmissionRejected(
            "canonical adapter admission window exceeded"
        )
    evaluation_state = "queued" if normalized_asset_count else "not-required"
    connection.execute(
        text(
            """
            INSERT INTO canonical_inventory_collections (
                canonical_collection_id, site_id, source_id, adapter_type,
                route_name, idempotency_key, payload_sha256, schema_version,
                observed_at, ingested_at, inventory_mode,
                original_identifier, observed_asset_count,
                canonical_asset_count, evidence_count, component_count,
                evaluation_state, warning_codes_json
            ) VALUES (
                :collection_id, :site_id, :source_id, :adapter_type,
                :route_name, :idempotency_key, :payload_sha256, :schema_version,
                :observed_at, :ingested_at, :inventory_mode,
                :original_identifier, :observed_asset_count,
                :canonical_asset_count, :evidence_count, :component_count,
                :evaluation_state, CAST(:warning_codes_json AS JSONB)
            )
            """
        ),
        {
            "collection_id": envelope.canonical_collection_id,
            "site_id": envelope.site_id,
            "source_id": envelope.source_id,
            "adapter_type": envelope.adapter_type,
            "route_name": envelope.route_name,
            "idempotency_key": envelope.idempotency_key,
            "payload_sha256": envelope.payload_sha256,
            "schema_version": envelope.schema_version,
            "observed_at": envelope.observed_at,
            "ingested_at": envelope.ingested_at,
            "inventory_mode": envelope.inventory_mode,
            "original_identifier": envelope.original_identifier,
            "observed_asset_count": len(envelope.assets),
            "canonical_asset_count": normalized_asset_count,
            "evidence_count": envelope.evidence_count,
            "component_count": envelope.component_count,
            "evaluation_state": evaluation_state,
            "warning_codes_json": "[]",
        },
    )
    return evaluation_state


def _store_endpoint_projection(
    connection: Any,
    *,
    envelope: Any,
    compatibility_collection_id: int,
    normalized_asset_count: int,
    evaluation_state: str,
) -> int | None:
    if envelope.adapter_type != "endpoint-agent":
        return None
    storage_id = int(
        connection.execute(
            text(
                """
                INSERT INTO endpoint_agent_inventory_batches (
                    inventory_batch_id, payload_sha256, site_id, agent_id,
                    credential_id, inventory_mode, observed_at, received_at,
                    collection_id, observed_asset_count,
                    normalized_asset_count, component_count,
                    reevaluation_state
                ) VALUES (
                    :batch_id, :payload_sha256, :site_id, :agent_id,
                    :credential_id, :inventory_mode, :observed_at, :received_at,
                    :collection_id, :observed_asset_count,
                    :normalized_asset_count, :component_count,
                    :reevaluation_state
                )
                RETURNING storage_id
                """
            ),
            {
                "batch_id": envelope.original_identifier,
                "payload_sha256": envelope.payload_sha256,
                "site_id": envelope.site_id,
                "agent_id": envelope.bound_identity_id,
                "credential_id": envelope.credential_id,
                "inventory_mode": envelope.inventory_mode,
                "observed_at": envelope.observed_at,
                "received_at": envelope.ingested_at,
                "collection_id": compatibility_collection_id,
                "observed_asset_count": len(envelope.assets),
                "normalized_asset_count": normalized_asset_count,
                "component_count": envelope.component_count,
                "reevaluation_state": evaluation_state,
            },
        ).scalar_one()
    )
    connection.execute(
        text(
            """
            INSERT INTO endpoint_agent_identity_audit_events (
                event_type, outcome, actor, credential_id, agent_id,
                site_id, reason_code, metadata_json, created_at
            ) VALUES (
                'inventory_accepted', 'success', 'endpoint-agent',
                :credential_id, :agent_id, :site_id, NULL,
                CAST(:metadata_json AS JSONB), :created_at
            )
            """
        ),
        {
            "credential_id": envelope.credential_id,
            "agent_id": envelope.bound_identity_id,
            "site_id": envelope.site_id,
            "metadata_json": db._json_payload(
                {
                    "canonical_collection_id": envelope.canonical_collection_id,
                    "inventory_batch_id": envelope.original_identifier,
                    "inventory_mode": envelope.inventory_mode,
                }
            ),
            "created_at": envelope.ingested_at,
        },
    )
    return storage_id


def _finalize_mappings(
    connection: Any,
    *,
    envelope: Any,
    compatibility_collection_id: int,
    legacy_submission_id: int | None,
) -> None:
    connection.execute(
        text(
            """
            UPDATE canonical_inventory_collections
            SET compatibility_collection_id = :compatibility_collection_id,
                legacy_submission_id = :legacy_submission_id,
                updated_at = NOW()
            WHERE canonical_collection_id = :collection_id
            """
        ),
        {
            "compatibility_collection_id": compatibility_collection_id,
            "legacy_submission_id": legacy_submission_id,
            "collection_id": envelope.canonical_collection_id,
        },
    )
    if legacy_submission_id is not None:
        connection.execute(
            text(
                """
                INSERT INTO legacy_submission_mappings (
                    legacy_submission_id, canonical_collection_id,
                    mapping_status
                ) VALUES (
                    :legacy_submission_id, :collection_id, 'mapped-on-ingest'
                )
                """
            ),
            {
                "legacy_submission_id": legacy_submission_id,
                "collection_id": envelope.canonical_collection_id,
            },
        )


def persist_canonical_inventory(*, envelope: Any) -> dict[str, Any]:
    """Atomically accept canonical collection, asset authority, and projections."""

    db.ensure_database_schema()
    payload = envelope.persistence_payload()
    normalized_assets = db.normalize_local_inventory_assets(
        payload,
        site_id=envelope.site_id,
        received_at=envelope.ingested_at,
    )
    with db.get_engine().begin() as connection:
        if (
            envelope.adapter_type == "python-collector"
            and envelope.site_id == "legacy-collector-default"
        ):
            connection.execute(
                text(
                    """
                    INSERT INTO sites (site_id, name, description)
                    VALUES (:site_id, :site_id, NULL)
                    ON CONFLICT (site_id) DO NOTHING
                    """
                ),
                {"site_id": envelope.site_id},
            )
        if not envelope.source_authenticated:
            replay = _existing_replay(connection, envelope=envelope)
            if replay is not None:
                return replay
        # A site-row lock serializes all canonical authority and replay
        # decisions for that site, including first observation of an asset.
        site_row = connection.execute(
            text("SELECT site_id FROM sites WHERE site_id = :site_id FOR UPDATE"),
            {"site_id": envelope.site_id},
        ).scalar_one_or_none()
        if site_row is None:
            from .canonical_ingestion import CanonicalIngestionRejected

            raise CanonicalIngestionRejected(
                "canonical ingestion site is not configured"
            )
        _verify_bound_credential(connection, envelope=envelope)
        _upsert_source(connection, envelope=envelope)
        _update_sensor_status(connection, envelope=envelope)
        if envelope.source_authenticated:
            replay = _existing_replay(connection, envelope=envelope)
            if replay is not None:
                return replay

        evaluation_state = _admit_collection(
            connection,
            envelope=envelope,
            normalized_asset_count=len(normalized_assets),
        )
        legacy_submission_id = _store_legacy_submission(
            connection,
            envelope=envelope,
        )
        compatibility = db._store_local_inventory_collection(
            connection,
            payload=payload,
            site_id=envelope.site_id,
            received_at=envelope.ingested_at,
            observed_asset_count=len(envelope.assets),
            normalized_assets=normalized_assets,
            deduplicate=False,
            store_assets=False,
        )
        authoritative_assets = [
            asset
            for asset in normalized_assets
            if _persist_asset(connection, envelope=envelope, asset=asset)
        ]
        evaluation_state = "queued" if authoritative_assets else "not-required"
        connection.execute(
            text(
                """
                UPDATE canonical_inventory_collections
                SET evaluation_state = :evaluation_state,
                    evaluation_asset_ids_json = CAST(:asset_ids_json AS JSONB),
                    updated_at = NOW()
                WHERE canonical_collection_id = :collection_id
                """
            ),
            {
                "collection_id": envelope.canonical_collection_id,
                "evaluation_state": evaluation_state,
                "asset_ids_json": db._json_payload(
                    [asset["asset_id"] for asset in authoritative_assets]
                ),
            },
        )
        endpoint_storage_id = _store_endpoint_projection(
            connection,
            envelope=envelope,
            compatibility_collection_id=int(compatibility["collection_id"]),
            normalized_asset_count=len(normalized_assets),
            evaluation_state=evaluation_state,
        )
        _finalize_mappings(
            connection,
            envelope=envelope,
            compatibility_collection_id=int(compatibility["collection_id"]),
            legacy_submission_id=legacy_submission_id,
        )
        _event(
            connection,
            envelope=envelope,
            event_type="accepted",
            outcome="success",
            metadata={
                "asset_count": len(normalized_assets),
                "evaluation_state": evaluation_state,
            },
        )

    return {
        "duplicate": False,
        "compatibility_collection_id": int(compatibility["collection_id"]),
        "legacy_submission_id": legacy_submission_id,
        "endpoint_storage_id": endpoint_storage_id,
        "normalized_asset_count": len(normalized_assets),
        "evidence_count": envelope.evidence_count,
        "component_count": envelope.component_count,
        "evaluation_state": evaluation_state,
        "asset_ids": [asset["asset_id"] for asset in authoritative_assets],
    }


def set_evaluation_state(
    *,
    canonical_collection_id: str,
    state: str,
    error_code: str | None = None,
) -> None:
    if state not in {
        "queued",
        "running",
        "completed",
        "retryable-failure",
        "not-required",
    }:
        raise ValueError("unsupported canonical evaluation state")
    db.ensure_database_schema()
    with db.get_engine().begin() as connection:
        row = connection.execute(
            text(
                """
                UPDATE canonical_inventory_collections
                SET evaluation_state = :state,
                    evaluation_error_code = :error_code,
                    updated_at = NOW()
                WHERE canonical_collection_id = :collection_id
                RETURNING adapter_type, site_id, source_id,
                          compatibility_collection_id
                """
            ),
            {
                "collection_id": canonical_collection_id,
                "state": state,
                "error_code": error_code,
            },
        ).mappings().one_or_none()
        if row is None:
            raise ValueError("canonical collection does not exist")
        if row["adapter_type"] == "endpoint-agent":
            connection.execute(
                text(
                    """
                    UPDATE endpoint_agent_inventory_batches
                    SET reevaluation_state = :state,
                        reevaluation_error_code = :error_code,
                        reevaluation_updated_at = NOW()
                    WHERE collection_id = :compatibility_collection_id
                    """
                ),
                {
                    "compatibility_collection_id": row[
                        "compatibility_collection_id"
                    ],
                    "state": state,
                    "error_code": error_code,
                },
            )
        connection.execute(
            text(
                """
                INSERT INTO ingestion_compatibility_events (
                    event_type, outcome, route_name, adapter_type, site_id,
                    source_id, canonical_collection_id, metadata_json,
                    created_at
                ) VALUES (
                    'evaluation-state', :outcome, 'internal-evaluation',
                    :adapter_type, :site_id, :source_id, :collection_id,
                    CAST(:metadata_json AS JSONB), :created_at
                )
                """
            ),
            {
                "outcome": (
                    "retryable" if state == "retryable-failure" else "success"
                ),
                "adapter_type": row["adapter_type"],
                "site_id": row["site_id"],
                "source_id": row["source_id"],
                "collection_id": canonical_collection_id,
                "metadata_json": db._json_payload(
                    {
                        "state": state,
                        **({"error_code": error_code} if error_code else {}),
                    }
                ),
                "created_at": datetime.now(timezone.utc),
            },
        )


def claim_evaluation_work(
    *, canonical_collection_id: str
) -> dict[str, Any] | None:
    """Atomically claim one queued collection and reconstruct bounded work."""

    db.ensure_database_schema()
    with db.get_engine().begin() as connection:
        row = connection.execute(
            text(
                """
                UPDATE canonical_inventory_collections
                SET evaluation_state = 'running',
                    evaluation_error_code = NULL,
                    updated_at = NOW()
                WHERE canonical_collection_id = :collection_id
                  AND evaluation_state = 'queued'
                RETURNING site_id, source_id, adapter_type,
                          compatibility_collection_id,
                          evaluation_asset_ids_json, ingested_at
                """
            ),
            {"collection_id": canonical_collection_id},
        ).mappings().one_or_none()
        if row is None:
            return None
        if row["adapter_type"] == "endpoint-agent":
            connection.execute(
                text(
                    """
                    UPDATE endpoint_agent_inventory_batches
                    SET reevaluation_state = 'running',
                        reevaluation_error_code = NULL,
                        reevaluation_updated_at = NOW()
                    WHERE collection_id = :compatibility_collection_id
                    """
                ),
                {
                    "compatibility_collection_id": row[
                        "compatibility_collection_id"
                    ]
                },
            )
        connection.execute(
            text(
                """
                INSERT INTO ingestion_compatibility_events (
                    event_type, outcome, route_name, adapter_type, site_id,
                    source_id, canonical_collection_id, metadata_json,
                    created_at
                ) VALUES (
                    'evaluation-state', 'success', 'internal-evaluation',
                    :adapter_type, :site_id, :source_id, :collection_id,
                    '{"state":"running"}'::jsonb, NOW()
                )
                """
            ),
            {
                "adapter_type": row["adapter_type"],
                "site_id": row["site_id"],
                "source_id": row["source_id"],
                "collection_id": canonical_collection_id,
            },
        )
        details = connection.execute(
            text(
                """
                SELECT l.payload_json, s.source_authority
                FROM local_inventory_collections l
                JOIN canonical_ingestion_sources s
                  ON s.source_id = :source_id
                WHERE l.id = :compatibility_collection_id
                """
            ),
            {
                "source_id": row["source_id"],
                "compatibility_collection_id": row[
                    "compatibility_collection_id"
                ],
            },
        ).mappings().one()
    payload = details["payload_json"]
    if not isinstance(payload, dict):
        raise RuntimeError("canonical evaluation payload is invalid")
    normalized_assets = db.normalize_local_inventory_assets(
        payload,
        site_id=str(row["site_id"]),
        received_at=row["ingested_at"],
    )
    selected_ids = {
        str(item)
        for item in (row["evaluation_asset_ids_json"] or [])
        if isinstance(item, str)
    }
    selected_assets = [
        asset for asset in normalized_assets if asset["asset_id"] in selected_ids
    ]
    return {
        "site_id": str(row["site_id"]),
        "asset_ids": [asset["asset_id"] for asset in selected_assets],
        "normalized_assets": selected_assets,
        "payload": payload,
        "received_at": row["ingested_at"],
        "source_authenticated": str(details["source_authority"]).startswith(
            "authenticated-"
        ),
    }


def requeue_evaluation(*, canonical_collection_id: str) -> bool:
    """Move one retryable collection back to the durable queued state."""

    db.ensure_database_schema()
    with db.get_engine().begin() as connection:
        row = connection.execute(
            text(
                """
                UPDATE canonical_inventory_collections
                SET evaluation_state = 'queued',
                    evaluation_error_code = NULL,
                    updated_at = NOW()
                WHERE canonical_collection_id = :collection_id
                  AND evaluation_state = 'retryable-failure'
                  AND jsonb_array_length(evaluation_asset_ids_json) > 0
                RETURNING adapter_type, compatibility_collection_id
                """
            ),
            {"collection_id": canonical_collection_id},
        ).mappings().one_or_none()
        if row is None:
            return False
        if row["adapter_type"] == "endpoint-agent":
            connection.execute(
                text(
                    """
                    UPDATE endpoint_agent_inventory_batches
                    SET reevaluation_state = 'queued',
                        reevaluation_error_code = NULL,
                        reevaluation_updated_at = NOW()
                    WHERE collection_id = :compatibility_collection_id
                    """
                ),
                {
                    "compatibility_collection_id": row[
                        "compatibility_collection_id"
                    ]
                },
            )
        return True


def compatibility_status(*, limit: int = 20) -> dict[str, Any]:
    db.ensure_database_schema()
    safe_limit = max(1, min(int(limit), 100))
    with db.get_engine().begin() as connection:
        rows = connection.execute(
            text(
                """
                SELECT adapter_type, route_name, COUNT(*) AS submissions,
                       MAX(ingested_at) AS last_submission,
                       COUNT(*) FILTER (
                           WHERE compatibility_collection_id IS NOT NULL
                       ) AS canonical_mappings
                FROM canonical_inventory_collections
                GROUP BY adapter_type, route_name
                ORDER BY adapter_type, route_name
                """
            )
        ).mappings().all()
        legacy_total = int(
            connection.execute(
                text("SELECT COUNT(*) FROM collector_inventory_submissions")
            ).scalar_one()
        )
        mapped = int(
            connection.execute(
                text("SELECT COUNT(*) FROM legacy_submission_mappings")
            ).scalar_one()
        )
        recent = connection.execute(
            text(
                """
                SELECT canonical_collection_id, adapter_type, site_id,
                       source_id, evaluation_state, ingested_at
                FROM canonical_inventory_collections
                ORDER BY ingested_at DESC, canonical_collection_id
                LIMIT :limit
                """
            ),
            {"limit": safe_limit},
        ).mappings().all()
    defaults = {
        "/api/v1/agents/inventory": (
            "endpoint-agent",
            "authenticated-endpoint",
            "canonical",
        ),
        "/api/v1/observations/batches": (
            "passive-sensor",
            "authenticated-passive-sensor-or-untrusted",
            "canonical-or-deprecated",
        ),
        "/api/v1/collectors/inventory": (
            "python-collector",
            "legacy-collector",
            "compatibility",
        ),
        "/api/v1/collections/local-inventory": (
            "transitional-local",
            "untrusted-transitional",
            "deprecated",
        ),
    }
    counts = {
        (str(row["adapter_type"]), str(row["route_name"])): dict(row)
        for row in rows
    }
    routes = []
    for route, (adapter, authority, status) in defaults.items():
        row = counts.get((adapter, route), {})
        routes.append(
            {
                "route": route,
                "adapter_type": adapter,
                "trust_classification": authority,
                "submissions": int(row.get("submissions") or 0),
                "canonical_mappings": int(row.get("canonical_mappings") or 0),
                "last_submission": row.get("last_submission"),
                "deprecation_status": status,
            }
        )
    return {
        "schema_version": "oaw.ingestion-compatibility-status.v1",
        "canonical_write_authority": "control-tower",
        "routes": routes,
        "unmapped_historical_records": max(0, legacy_total - mapped),
        "conflicting_mappings": 0,
        "recent_collections": [dict(row) for row in recent],
    }


def historical_preview() -> dict[str, Any]:
    db.ensure_database_schema()
    with db.get_engine().begin() as connection:
        row = connection.execute(
            text(
                """
                SELECT
                    COUNT(*) AS legacy_records,
                    COUNT(m.mapping_id) AS already_mapped,
                    COUNT(*) FILTER (
                        WHERE m.mapping_id IS NULL
                          AND (
                              s.collector_guid IS NOT NULL
                              OR s.collector_id IS NOT NULL
                          )
                          AND jsonb_typeof(s.payload_json) = 'object'
                    ) AS safely_mappable,
                    COUNT(*) FILTER (
                        WHERE m.mapping_id IS NULL
                          AND s.collector_guid IS NULL
                          AND s.collector_id IS NULL
                    ) AS ambiguous_records
                FROM collector_inventory_submissions s
                LEFT JOIN legacy_submission_mappings m
                  ON m.legacy_submission_id = s.id
                """
            )
        ).mappings().one()
    total = int(row["legacy_records"])
    mapped = int(row["already_mapped"])
    safe = int(row["safely_mappable"])
    ambiguous = int(row["ambiguous_records"])
    return {
        "schema_version": "oaw.historical-ingestion-preview.v1",
        "legacy_records": total,
        "already_mapped": mapped,
        "safely_mappable": safe,
        "ambiguous_records": ambiguous,
        "conflicts": 0,
        "historical_only": max(0, total - mapped - safe),
        "mutation_performed": False,
    }
