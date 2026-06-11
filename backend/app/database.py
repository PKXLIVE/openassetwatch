"""Database helpers for the OpenAssetWatch backend MVP."""

from __future__ import annotations

import json
import os
from datetime import datetime
from functools import lru_cache
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine


DEFAULT_DATABASE_URL = (
    "postgresql+psycopg2://openassetwatch:"
    "openassetwatch_change_me@postgres:5432/openassetwatch"
)


CREATE_INVENTORY_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS collector_inventory_submissions (
    id BIGSERIAL PRIMARY KEY,
    collector_id TEXT,
    collector_name TEXT,
    mode TEXT,
    schema_version TEXT,
    collector_version TEXT,
    collected_at TIMESTAMPTZ,
    received_at TIMESTAMPTZ NOT NULL,
    device_count INTEGER NOT NULL DEFAULT 0,
    network_observation_count INTEGER NOT NULL DEFAULT 0,
    software_count INTEGER NOT NULL DEFAULT 0,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
"""


CREATE_RECEIVED_AT_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_collector_inventory_submissions_received_at
    ON collector_inventory_submissions (received_at DESC)
"""


CREATE_COLLECTOR_ID_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_collector_inventory_submissions_collector_id
    ON collector_inventory_submissions (collector_id)
"""

CREATE_COLLECTORS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS collectors (
    id BIGSERIAL PRIMARY KEY,
    collector_id TEXT NOT NULL UNIQUE,
    collector_name TEXT,
    collector_version TEXT,
    last_mode TEXT,
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
"""

CREATE_ASSETS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS assets (
    id BIGSERIAL PRIMARY KEY,
    asset_key TEXT NOT NULL UNIQUE,
    asset_kind TEXT NOT NULL,
    hostname TEXT,
    primary_ip TEXT,
    mac_address TEXT,
    source TEXT,
    collector_id TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    last_submission_id BIGINT REFERENCES collector_inventory_submissions(id),
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
"""

CREATE_ASSET_IP_HISTORY_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS asset_ip_history (
    id BIGSERIAL PRIMARY KEY,
    asset_id BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    ip_address TEXT,
    mac_address TEXT,
    interface TEXT,
    state TEXT,
    source TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    observations_count INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
"""

CREATE_ASSET_SOFTWARE_DETECTIONS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS asset_software_detections (
    id BIGSERIAL PRIMARY KEY,
    asset_id BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    category TEXT,
    detected BOOLEAN,
    version TEXT,
    evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    confidence TEXT,
    scope TEXT,
    source TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (asset_id, name, category)
)
"""

NORMALIZATION_INDEX_SQL = [
    "CREATE INDEX IF NOT EXISTS idx_assets_collector_id ON assets (collector_id)",
    "CREATE INDEX IF NOT EXISTS idx_assets_mac_address ON assets (mac_address)",
    "CREATE INDEX IF NOT EXISTS idx_assets_primary_ip ON assets (primary_ip)",
    "CREATE INDEX IF NOT EXISTS idx_asset_ip_history_asset_id ON asset_ip_history (asset_id)",
    "CREATE INDEX IF NOT EXISTS idx_asset_ip_history_ip_address ON asset_ip_history (ip_address)",
    "CREATE INDEX IF NOT EXISTS idx_asset_software_detections_asset_id ON asset_software_detections (asset_id)",
]


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    return create_engine(os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL), pool_pre_ping=True)


def ensure_database_schema() -> None:
    with get_engine().begin() as connection:
        connection.execute(text(CREATE_INVENTORY_TABLE_SQL))
        connection.execute(text(CREATE_RECEIVED_AT_INDEX_SQL))
        connection.execute(text(CREATE_COLLECTOR_ID_INDEX_SQL))
        connection.execute(text(CREATE_COLLECTORS_TABLE_SQL))
        connection.execute(text(CREATE_ASSETS_TABLE_SQL))
        connection.execute(text(CREATE_ASSET_IP_HISTORY_TABLE_SQL))
        connection.execute(text(CREATE_ASSET_SOFTWARE_DETECTIONS_TABLE_SQL))
        for statement in NORMALIZATION_INDEX_SQL:
            connection.execute(text(statement))


def save_inventory_submission(
    *,
    collector_id: str | None,
    collector_name: str | None,
    mode: str | None,
    schema_version: str | None,
    collector_version: str | None,
    collected_at: datetime | None,
    received_at: datetime,
    device_count: int,
    network_observation_count: int,
    software_count: int,
    payload: dict[str, Any],
) -> int:
    ensure_database_schema()
    payload_json = json.dumps(payload, default=str)
    statement = text(
        """
        INSERT INTO collector_inventory_submissions (
            collector_id,
            collector_name,
            mode,
            schema_version,
            collector_version,
            collected_at,
            received_at,
            device_count,
            network_observation_count,
            software_count,
            payload_json
        )
        VALUES (
            :collector_id,
            :collector_name,
            :mode,
            :schema_version,
            :collector_version,
            :collected_at,
            :received_at,
            :device_count,
            :network_observation_count,
            :software_count,
            CAST(:payload_json AS JSONB)
        )
        RETURNING id
        """
    )
    with get_engine().begin() as connection:
        submission_id = connection.execute(
            statement,
            {
                "collector_id": collector_id,
                "collector_name": collector_name,
                "mode": mode,
                "schema_version": schema_version,
                "collector_version": collector_version,
                "collected_at": collected_at,
                "received_at": received_at,
                "device_count": device_count,
                "network_observation_count": network_observation_count,
                "software_count": software_count,
                "payload_json": payload_json,
            },
        ).scalar_one()
    return int(submission_id)


def latest_inventory_submission() -> dict[str, Any] | None:
    ensure_database_schema()
    statement = text(
        """
        SELECT
            id,
            collector_id,
            collector_name,
            mode,
            schema_version,
            collector_version,
            collected_at,
            received_at,
            device_count,
            network_observation_count,
            software_count,
            payload_json,
            created_at
        FROM collector_inventory_submissions
        ORDER BY received_at DESC, id DESC
        LIMIT 1
        """
    )
    with get_engine().begin() as connection:
        row = connection.execute(statement).mappings().first()

    if row is None:
        return None

    payload = row["payload_json"]
    if isinstance(payload, str):
        payload = json.loads(payload)

    return {
        "submission_id": row["id"],
        "collector_id": row["collector_id"],
        "collector_name": row["collector_name"],
        "mode": row["mode"],
        "schema_version": row["schema_version"],
        "collector_version": row["collector_version"],
        "collected_at": row["collected_at"],
        "received_at": row["received_at"],
        "device_count": row["device_count"],
        "network_observation_count": row["network_observation_count"],
        "software_count": row["software_count"],
        "created_at": row["created_at"],
        "payload": payload,
    }


def _json_payload(value: Any) -> str:
    return json.dumps(value, default=str)


def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text_value = str(value).strip()
    return text_value or None


def _network_entries(payload: dict[str, Any]) -> list[dict[str, Any]]:
    network = payload.get("network")
    if isinstance(network, list):
        return [entry for entry in network if isinstance(entry, dict)]
    if isinstance(network, dict):
        neighbors = network.get("neighbors")
        if isinstance(neighbors, list):
            return [entry for entry in neighbors if isinstance(entry, dict)]
        observations = network.get("observations")
        if isinstance(observations, list):
            return [entry for entry in observations if isinstance(entry, dict)]
    return []


def _software_entries(payload: dict[str, Any]) -> list[dict[str, Any]]:
    software = payload.get("software")
    if isinstance(software, list):
        return [entry for entry in software if isinstance(entry, dict)]
    return []


def _upsert_collector(
    connection: Any,
    *,
    collector_id: str | None,
    collector_name: str | None,
    collector_version: str | None,
    mode: str | None,
    seen_at: datetime,
) -> int | None:
    if not collector_id:
        return None

    statement = text(
        """
        INSERT INTO collectors (
            collector_id,
            collector_name,
            collector_version,
            last_mode,
            last_seen_at
        )
        VALUES (
            :collector_id,
            :collector_name,
            :collector_version,
            :last_mode,
            :last_seen_at
        )
        ON CONFLICT (collector_id) DO UPDATE SET
            collector_name = COALESCE(EXCLUDED.collector_name, collectors.collector_name),
            collector_version = COALESCE(EXCLUDED.collector_version, collectors.collector_version),
            last_mode = COALESCE(EXCLUDED.last_mode, collectors.last_mode),
            last_seen_at = EXCLUDED.last_seen_at,
            updated_at = NOW()
        RETURNING id
        """
    )
    return int(
        connection.execute(
            statement,
            {
                "collector_id": collector_id,
                "collector_name": collector_name,
                "collector_version": collector_version,
                "last_mode": mode,
                "last_seen_at": seen_at,
            },
        ).scalar_one()
    )


def _upsert_asset(
    connection: Any,
    *,
    asset_key: str,
    asset_kind: str,
    hostname: str | None,
    primary_ip: str | None,
    mac_address: str | None,
    source: str,
    collector_id: str | None,
    seen_at: datetime,
    submission_id: int,
    metadata: dict[str, Any],
) -> int:
    statement = text(
        """
        INSERT INTO assets (
            asset_key,
            asset_kind,
            hostname,
            primary_ip,
            mac_address,
            source,
            collector_id,
            first_seen_at,
            last_seen_at,
            last_submission_id,
            metadata_json
        )
        VALUES (
            :asset_key,
            :asset_kind,
            :hostname,
            :primary_ip,
            :mac_address,
            :source,
            :collector_id,
            :seen_at,
            :seen_at,
            :submission_id,
            CAST(:metadata_json AS JSONB)
        )
        ON CONFLICT (asset_key) DO UPDATE SET
            hostname = COALESCE(EXCLUDED.hostname, assets.hostname),
            primary_ip = COALESCE(EXCLUDED.primary_ip, assets.primary_ip),
            mac_address = COALESCE(EXCLUDED.mac_address, assets.mac_address),
            source = EXCLUDED.source,
            collector_id = COALESCE(EXCLUDED.collector_id, assets.collector_id),
            last_seen_at = EXCLUDED.last_seen_at,
            last_submission_id = EXCLUDED.last_submission_id,
            metadata_json = EXCLUDED.metadata_json,
            updated_at = NOW()
        RETURNING id
        """
    )
    return int(
        connection.execute(
            statement,
            {
                "asset_key": asset_key,
                "asset_kind": asset_kind,
                "hostname": hostname,
                "primary_ip": primary_ip,
                "mac_address": mac_address,
                "source": source,
                "collector_id": collector_id,
                "seen_at": seen_at,
                "submission_id": submission_id,
                "metadata_json": _json_payload(metadata),
            },
        ).scalar_one()
    )


def _record_ip_observation(
    connection: Any,
    *,
    asset_id: int,
    ip_address: str | None,
    mac_address: str | None,
    interface: str | None,
    state: str | None,
    source: str | None,
    seen_at: datetime,
) -> None:
    if not ip_address and not mac_address:
        return

    existing = connection.execute(
        text(
            """
            SELECT id
            FROM asset_ip_history
            WHERE asset_id = :asset_id
              AND COALESCE(ip_address, '') = COALESCE(:ip_address, '')
              AND COALESCE(mac_address, '') = COALESCE(:mac_address, '')
            LIMIT 1
            """
        ),
        {
            "asset_id": asset_id,
            "ip_address": ip_address,
            "mac_address": mac_address,
        },
    ).scalar_one_or_none()

    if existing:
        connection.execute(
            text(
                """
                UPDATE asset_ip_history
                SET
                    interface = COALESCE(:interface, interface),
                    state = COALESCE(:state, state),
                    source = COALESCE(:source, source),
                    last_seen_at = :seen_at,
                    observations_count = observations_count + 1,
                    updated_at = NOW()
                WHERE id = :id
                """
            ),
            {
                "id": existing,
                "interface": interface,
                "state": state,
                "source": source,
                "seen_at": seen_at,
            },
        )
        return

    connection.execute(
        text(
            """
            INSERT INTO asset_ip_history (
                asset_id,
                ip_address,
                mac_address,
                interface,
                state,
                source,
                first_seen_at,
                last_seen_at
            )
            VALUES (
                :asset_id,
                :ip_address,
                :mac_address,
                :interface,
                :state,
                :source,
                :seen_at,
                :seen_at
            )
            """
        ),
        {
            "asset_id": asset_id,
            "ip_address": ip_address,
            "mac_address": mac_address,
            "interface": interface,
            "state": state,
            "source": source,
            "seen_at": seen_at,
        },
    )


def _upsert_software_detection(
    connection: Any,
    *,
    asset_id: int,
    software: dict[str, Any],
    seen_at: datetime,
) -> int:
    name = _clean_text(software.get("name"))
    if not name:
        return 0

    statement = text(
        """
        INSERT INTO asset_software_detections (
            asset_id,
            name,
            category,
            detected,
            version,
            evidence,
            confidence,
            scope,
            source,
            first_seen_at,
            last_seen_at
        )
        VALUES (
            :asset_id,
            :name,
            :category,
            :detected,
            :version,
            CAST(:evidence AS JSONB),
            :confidence,
            :scope,
            :source,
            :seen_at,
            :seen_at
        )
        ON CONFLICT (asset_id, name, category) DO UPDATE SET
            detected = EXCLUDED.detected,
            version = COALESCE(EXCLUDED.version, asset_software_detections.version),
            evidence = EXCLUDED.evidence,
            confidence = COALESCE(EXCLUDED.confidence, asset_software_detections.confidence),
            scope = COALESCE(EXCLUDED.scope, asset_software_detections.scope),
            source = COALESCE(EXCLUDED.source, asset_software_detections.source),
            last_seen_at = EXCLUDED.last_seen_at,
            updated_at = NOW()
        RETURNING id
        """
    )
    evidence = software.get("evidence")
    if not isinstance(evidence, list):
        evidence = []

    connection.execute(
        statement,
        {
            "asset_id": asset_id,
            "name": name,
            "category": _clean_text(software.get("category")),
            "detected": software.get("detected"),
            "version": _clean_text(software.get("version")),
            "evidence": _json_payload(evidence),
            "confidence": _clean_text(software.get("confidence")),
            "scope": _clean_text(software.get("scope")),
            "source": _clean_text(software.get("source")),
            "seen_at": seen_at,
        },
    )
    return 1


def normalize_inventory_submission(
    *,
    submission_id: int,
    payload: dict[str, Any],
    collector_id: str | None,
    collector_name: str | None,
    collector_version: str | None,
    mode: str | None,
    received_at: datetime,
) -> dict[str, int]:
    ensure_database_schema()
    normalized_asset_ids: set[int] = set()
    normalized_software_count = 0

    with get_engine().begin() as connection:
        _upsert_collector(
            connection,
            collector_id=collector_id,
            collector_name=collector_name,
            collector_version=collector_version,
            mode=mode,
            seen_at=received_at,
        )

        device = payload.get("device")
        local_asset_id: int | None = None
        if isinstance(device, dict):
            hostname = _clean_text(device.get("hostname"))
            primary_ip = _clean_text(device.get("primary_ip"))
            mac_address = _clean_text(device.get("mac_address"))
            asset_key = f"collector:{collector_id}:device" if collector_id else f"device:{hostname or primary_ip or submission_id}"
            local_asset_id = _upsert_asset(
                connection,
                asset_key=asset_key,
                asset_kind="collector_device",
                hostname=hostname,
                primary_ip=primary_ip,
                mac_address=mac_address,
                source="collector_device",
                collector_id=collector_id,
                seen_at=received_at,
                submission_id=submission_id,
                metadata=device,
            )
            normalized_asset_ids.add(local_asset_id)
            _record_ip_observation(
                connection,
                asset_id=local_asset_id,
                ip_address=primary_ip,
                mac_address=mac_address,
                interface=None,
                state=None,
                source="collector_device",
                seen_at=received_at,
            )

        for neighbor in _network_entries(payload):
            ip_address = _clean_text(neighbor.get("ip_address") or neighbor.get("ip"))
            mac_address = _clean_text(neighbor.get("mac_address") or neighbor.get("mac"))
            if not ip_address and not mac_address:
                continue

            if mac_address:
                asset_key = f"mac:{mac_address.lower()}"
            else:
                asset_key = f"ip:{ip_address}"

            asset_id = _upsert_asset(
                connection,
                asset_key=asset_key,
                asset_kind="network_neighbor",
                hostname=None,
                primary_ip=ip_address,
                mac_address=mac_address,
                source=_clean_text(neighbor.get("source")) or "network",
                collector_id=collector_id,
                seen_at=received_at,
                submission_id=submission_id,
                metadata=neighbor,
            )
            normalized_asset_ids.add(asset_id)
            _record_ip_observation(
                connection,
                asset_id=asset_id,
                ip_address=ip_address,
                mac_address=mac_address,
                interface=_clean_text(neighbor.get("interface")),
                state=_clean_text(neighbor.get("state")),
                source=_clean_text(neighbor.get("source")),
                seen_at=received_at,
            )

        if local_asset_id is not None:
            for software in _software_entries(payload):
                normalized_software_count += _upsert_software_detection(
                    connection,
                    asset_id=local_asset_id,
                    software=software,
                    seen_at=received_at,
                )

    return {
        "normalized_asset_count": len(normalized_asset_ids),
        "normalized_software_count": normalized_software_count,
    }


def list_collectors() -> list[dict[str, Any]]:
    ensure_database_schema()
    statement = text(
        """
        SELECT
            id,
            collector_id,
            collector_name,
            collector_version,
            last_mode,
            last_seen_at,
            created_at,
            updated_at
        FROM collectors
        ORDER BY last_seen_at DESC NULLS LAST, id DESC
        """
    )
    with get_engine().begin() as connection:
        rows = connection.execute(statement).mappings().all()
    return [dict(row) for row in rows]


def list_assets() -> list[dict[str, Any]]:
    ensure_database_schema()
    statement = text(
        """
        SELECT
            id,
            asset_key,
            asset_kind,
            hostname,
            primary_ip,
            mac_address,
            source,
            collector_id,
            first_seen_at,
            last_seen_at,
            last_submission_id,
            metadata_json,
            created_at,
            updated_at
        FROM assets
        ORDER BY last_seen_at DESC, id DESC
        """
    )
    with get_engine().begin() as connection:
        rows = connection.execute(statement).mappings().all()

    assets: list[dict[str, Any]] = []
    for row in rows:
        asset = dict(row)
        metadata = asset.pop("metadata_json")
        if isinstance(metadata, str):
            metadata = json.loads(metadata)
        asset["metadata"] = metadata
        assets.append(asset)
    return assets
