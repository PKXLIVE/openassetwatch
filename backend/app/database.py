"""Database helpers for the OpenAssetWatch backend MVP."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from functools import lru_cache
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine


DEFAULT_DATABASE_PASSWORD = os.getenv("OAW_POSTGRES_PASSWORD", "openassetwatch_local_only_change_me")
DEFAULT_DATABASE_URL = f"postgresql+psycopg2://openassetwatch:{DEFAULT_DATABASE_PASSWORD}@postgres:5432/openassetwatch"
INVALID_MAC_TEXT_VALUES = {
    "(incomplete)",
    "<incomplete>",
    "incomplete",
    "none",
    "null",
}


CREATE_INVENTORY_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS collector_inventory_submissions (
    id BIGSERIAL PRIMARY KEY,
    collector_guid TEXT,
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
    collector_guid TEXT,
    collector_name TEXT,
    collector_version TEXT,
    deployment_id TEXT,
    deployment_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    labels_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    supported_capabilities_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled_capabilities_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    last_mode TEXT,
    last_seen_at TIMESTAMPTZ,
    last_submission_id BIGINT REFERENCES collector_inventory_submissions(id),
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

CREATE_COLLECTOR_POLICIES_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS collector_policies (
    id BIGSERIAL PRIMARY KEY,
    policy_id TEXT NOT NULL UNIQUE,
    policy_name TEXT,
    policy_version INTEGER NOT NULL DEFAULT 1,
    policy_json JSONB NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
"""

CREATE_POLICY_ASSIGNMENTS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS policy_assignments (
    id BIGSERIAL PRIMARY KEY,
    assignment_name TEXT,
    policy_id TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    priority INTEGER NOT NULL DEFAULT 0,
    collector_guid TEXT,
    collector_id TEXT,
    deployment_id TEXT,
    platform TEXT,
    label_selector JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
"""

CREATE_SITES_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS sites (
    site_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
"""

CREATE_AGENT_ENROLLMENTS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS agent_enrollments (
    agent_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    display_name TEXT,
    agent_type TEXT NOT NULL,
    platform TEXT,
    architecture TEXT,
    version TEXT,
    hostname TEXT,
    mode TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ,
    CHECK (agent_type IN ('endpoint-agent', 'network-sensor'))
)
"""

CREATE_AGENT_CHECKINS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS agent_checkins (
    id BIGSERIAL PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    agent_id TEXT,
    version TEXT,
    platform TEXT,
    architecture TEXT,
    hostname TEXT,
    mode TEXT,
    checked_in_at TIMESTAMPTZ,
    received_at TIMESTAMPTZ NOT NULL,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
"""

CREATE_LOCAL_INVENTORY_COLLECTIONS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS local_inventory_collections (
    id BIGSERIAL PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    source_agent_id TEXT,
    schema_version TEXT,
    collected_at TIMESTAMPTZ,
    received_at TIMESTAMPTZ NOT NULL,
    observed_asset_count INTEGER NOT NULL DEFAULT 0,
    normalized_asset_count INTEGER NOT NULL DEFAULT 0,
    payload_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)
"""

CREATE_CONTROL_TOWER_ASSETS_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS control_tower_assets (
    asset_key TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    hostname TEXT,
    primary_ip TEXT,
    mac TEXT,
    os TEXT,
    platform TEXT,
    source_agent_id TEXT,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    evidence_count INTEGER NOT NULL DEFAULT 0,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (site_id, asset_id)
)
"""

NORMALIZATION_INDEX_SQL = [
    "ALTER TABLE collector_inventory_submissions ADD COLUMN IF NOT EXISTS collector_guid TEXT",
    "CREATE INDEX IF NOT EXISTS idx_collector_inventory_submissions_collector_guid ON collector_inventory_submissions (collector_guid)",
    "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS collector_guid TEXT",
    "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS deployment_id TEXT",
    "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS deployment_json JSONB NOT NULL DEFAULT '{}'::jsonb",
    "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS labels_json JSONB NOT NULL DEFAULT '{}'::jsonb",
    "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS supported_capabilities_json JSONB NOT NULL DEFAULT '[]'::jsonb",
    "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS enabled_capabilities_json JSONB NOT NULL DEFAULT '[]'::jsonb",
    "ALTER TABLE collectors ADD COLUMN IF NOT EXISTS last_submission_id BIGINT REFERENCES collector_inventory_submissions(id)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_collectors_collector_guid ON collectors (collector_guid) WHERE collector_guid IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS idx_assets_collector_id ON assets (collector_id)",
    "CREATE INDEX IF NOT EXISTS idx_assets_mac_address ON assets (mac_address)",
    "CREATE INDEX IF NOT EXISTS idx_assets_primary_ip ON assets (primary_ip)",
    "CREATE INDEX IF NOT EXISTS idx_asset_ip_history_asset_id ON asset_ip_history (asset_id)",
    "CREATE INDEX IF NOT EXISTS idx_asset_ip_history_ip_address ON asset_ip_history (ip_address)",
    "CREATE INDEX IF NOT EXISTS idx_asset_software_detections_asset_id ON asset_software_detections (asset_id)",
    "CREATE INDEX IF NOT EXISTS idx_collector_policies_enabled ON collector_policies (enabled)",
    "CREATE INDEX IF NOT EXISTS idx_policy_assignments_enabled_priority ON policy_assignments (enabled, priority DESC)",
    "CREATE INDEX IF NOT EXISTS idx_policy_assignments_policy_id ON policy_assignments (policy_id)",
    "CREATE INDEX IF NOT EXISTS idx_agent_enrollments_site_id ON agent_enrollments (site_id)",
    "CREATE INDEX IF NOT EXISTS idx_agent_enrollments_last_seen_at ON agent_enrollments (last_seen_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_agent_checkins_site_id_received_at ON agent_checkins (site_id, received_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_agent_checkins_agent_id_received_at ON agent_checkins (agent_id, received_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_local_inventory_collections_site_id_received_at ON local_inventory_collections (site_id, received_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_control_tower_assets_site_id ON control_tower_assets (site_id)",
    "CREATE INDEX IF NOT EXISTS idx_control_tower_assets_last_seen_at ON control_tower_assets (last_seen_at DESC)",
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
        connection.execute(text(CREATE_COLLECTOR_POLICIES_TABLE_SQL))
        connection.execute(text(CREATE_POLICY_ASSIGNMENTS_TABLE_SQL))
        connection.execute(text(CREATE_SITES_TABLE_SQL))
        connection.execute(text(CREATE_AGENT_ENROLLMENTS_TABLE_SQL))
        connection.execute(text(CREATE_AGENT_CHECKINS_TABLE_SQL))
        connection.execute(text(CREATE_LOCAL_INVENTORY_COLLECTIONS_TABLE_SQL))
        connection.execute(text(CREATE_CONTROL_TOWER_ASSETS_TABLE_SQL))
        for statement in NORMALIZATION_INDEX_SQL:
            connection.execute(text(statement))


def save_inventory_submission(
    *,
    collector_guid: str | None,
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
            collector_guid,
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
            :collector_guid,
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
                "collector_guid": collector_guid,
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
            collector_guid,
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
        "collector_guid": row["collector_guid"],
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


def _normalize_mac_address(value: Any) -> str | None:
    text_value = _clean_text(value)
    if not text_value:
        return None

    cleaned = text_value.lower().replace("-", ":")
    if cleaned in INVALID_MAC_TEXT_VALUES:
        return None

    compact = re.sub(r"[^0-9a-f]", "", cleaned)
    if len(compact) != 12:
        return None

    mac_address = ":".join(compact[index : index + 2] for index in range(0, 12, 2))
    if (
        mac_address == "00:00:00:00:00:00"
        or mac_address == "ff:ff:ff:ff:ff:ff"
        or mac_address.startswith("01:00:5e:")
        or mac_address.startswith("33:33:")
    ):
        return None

    return mac_address


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


def _metadata_object(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _capability_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    capabilities: list[str] = []
    for item in value:
        text_value = _clean_text(item)
        if text_value and text_value not in capabilities:
            capabilities.append(text_value)
    return capabilities


def _upsert_collector(
    connection: Any,
    *,
    collector_guid: str | None,
    collector_id: str | None,
    collector_name: str | None,
    collector_version: str | None,
    deployment: dict[str, Any],
    labels: dict[str, Any],
    supported_capabilities: list[str],
    enabled_capabilities: list[str],
    mode: str | None,
    seen_at: datetime,
    last_submission_id: int | None = None,
) -> int | None:
    if not collector_id:
        return None

    existing_id: int | None = None
    if collector_guid:
        existing_id = connection.execute(
            text("SELECT id FROM collectors WHERE collector_guid = :collector_guid LIMIT 1"),
            {"collector_guid": collector_guid},
        ).scalar_one_or_none()

    if existing_id is None and collector_id:
        existing_id = connection.execute(
            text("SELECT id FROM collectors WHERE collector_id = :collector_id LIMIT 1"),
            {"collector_id": collector_id},
        ).scalar_one_or_none()

    if existing_id is not None:
        connection.execute(
            text(
                """
                UPDATE collectors
                SET
                    collector_guid = COALESCE(:collector_guid, collector_guid),
                    collector_id = COALESCE(:collector_id, collector_id),
                    collector_name = COALESCE(:collector_name, collector_name),
                    collector_version = COALESCE(:collector_version, collector_version),
                    deployment_id = COALESCE(:deployment_id, deployment_id),
                    deployment_json = CAST(:deployment_json AS JSONB),
                    labels_json = CAST(:labels_json AS JSONB),
                    supported_capabilities_json = CAST(:supported_capabilities_json AS JSONB),
                    enabled_capabilities_json = CAST(:enabled_capabilities_json AS JSONB),
                    last_mode = COALESCE(:last_mode, last_mode),
                    last_seen_at = :last_seen_at,
                    last_submission_id = COALESCE(:last_submission_id, last_submission_id),
                    updated_at = NOW()
                WHERE id = :id
                """
            ),
            {
                "id": existing_id,
                "collector_guid": collector_guid,
                "collector_id": collector_id,
                "collector_name": collector_name,
                "collector_version": collector_version,
                "deployment_id": _clean_text(deployment.get("deployment_id")),
                "deployment_json": _json_payload(deployment),
                "labels_json": _json_payload(labels),
                "supported_capabilities_json": _json_payload(_capability_list(supported_capabilities)),
                "enabled_capabilities_json": _json_payload(_capability_list(enabled_capabilities)),
                "last_mode": mode,
                "last_seen_at": seen_at,
                "last_submission_id": last_submission_id,
            },
        )
        return int(existing_id)

    statement = text(
        """
        INSERT INTO collectors (
            collector_id,
            collector_guid,
            collector_name,
            collector_version,
            deployment_id,
            deployment_json,
            labels_json,
            supported_capabilities_json,
            enabled_capabilities_json,
            last_mode,
            last_seen_at,
            last_submission_id
        )
        VALUES (
            :collector_id,
            :collector_guid,
            :collector_name,
            :collector_version,
            :deployment_id,
            CAST(:deployment_json AS JSONB),
            CAST(:labels_json AS JSONB),
            CAST(:supported_capabilities_json AS JSONB),
            CAST(:enabled_capabilities_json AS JSONB),
            :last_mode,
            :last_seen_at,
            :last_submission_id
        )
        RETURNING id
        """
    )
    return int(
        connection.execute(
            statement,
            {
                "collector_id": collector_id,
                "collector_guid": collector_guid,
                "collector_name": collector_name,
                "collector_version": collector_version,
                "deployment_id": _clean_text(deployment.get("deployment_id")),
                "deployment_json": _json_payload(deployment),
                "labels_json": _json_payload(labels),
                "supported_capabilities_json": _json_payload(_capability_list(supported_capabilities)),
                "enabled_capabilities_json": _json_payload(_capability_list(enabled_capabilities)),
                "last_mode": mode,
                "last_seen_at": seen_at,
                "last_submission_id": last_submission_id,
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
    collector_guid: str | None,
    collector_id: str | None,
    collector_name: str | None,
    collector_version: str | None,
    mode: str | None,
    received_at: datetime,
    supported_capabilities: list[str] | None = None,
    enabled_capabilities: list[str] | None = None,
) -> dict[str, int]:
    ensure_database_schema()
    normalized_asset_ids: set[int] = set()
    normalized_software_count = 0

    with get_engine().begin() as connection:
        _upsert_collector(
            connection,
            collector_guid=collector_guid,
            collector_id=collector_id,
            collector_name=collector_name,
            collector_version=collector_version,
            deployment=_metadata_object(payload.get("deployment")),
            labels=_metadata_object(payload.get("labels")),
            supported_capabilities=_capability_list(supported_capabilities or payload.get("supported_capabilities")),
            enabled_capabilities=_capability_list(enabled_capabilities or payload.get("enabled_capabilities")),
            mode=mode,
            seen_at=received_at,
            last_submission_id=submission_id,
        )

        device = payload.get("device")
        local_asset_id: int | None = None
        if isinstance(device, dict):
            hostname = _clean_text(device.get("hostname"))
            primary_ip = _clean_text(device.get("primary_ip"))
            mac_address = _normalize_mac_address(device.get("mac_address"))
            if collector_guid:
                asset_key = f"collector_guid:{collector_guid}:device"
            elif collector_id:
                asset_key = f"collector:{collector_id}:device"
            else:
                asset_key = f"device:{hostname or primary_ip or submission_id}"
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
            mac_address = _normalize_mac_address(neighbor.get("mac_address") or neighbor.get("mac"))
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


def upsert_collector_metadata(
    *,
    collector_guid: str | None,
    collector_id: str | None,
    collector_name: str | None,
    collector_version: str | None,
    deployment: dict[str, Any] | None,
    labels: dict[str, Any] | None,
    supported_capabilities: list[str] | None,
    enabled_capabilities: list[str] | None,
    mode: str | None,
    seen_at: datetime,
) -> int | None:
    ensure_database_schema()
    with get_engine().begin() as connection:
        return _upsert_collector(
            connection,
            collector_guid=collector_guid,
            collector_id=collector_id,
            collector_name=collector_name,
            collector_version=collector_version,
            deployment=deployment or {},
            labels=labels or {},
            supported_capabilities=_capability_list(supported_capabilities),
            enabled_capabilities=_capability_list(enabled_capabilities),
            mode=mode,
            seen_at=seen_at,
            last_submission_id=None,
        )


def list_collectors() -> list[dict[str, Any]]:
    ensure_database_schema()
    statement = text(
        """
        SELECT
            id,
            collector_guid,
            collector_id,
            collector_name,
            collector_version,
            deployment_id,
            deployment_json,
            labels_json,
            supported_capabilities_json,
            enabled_capabilities_json,
            last_mode,
            last_seen_at,
            last_submission_id,
            created_at,
            updated_at
        FROM collectors
        ORDER BY last_seen_at DESC NULLS LAST, id DESC
        """
    )
    with get_engine().begin() as connection:
        rows = connection.execute(statement).mappings().all()

    collectors: list[dict[str, Any]] = []
    for row in rows:
        collector = dict(row)
        deployment = collector.pop("deployment_json")
        labels = collector.pop("labels_json")
        supported_capabilities = collector.pop("supported_capabilities_json")
        enabled_capabilities = collector.pop("enabled_capabilities_json")
        if isinstance(deployment, str):
            deployment = json.loads(deployment)
        if isinstance(labels, str):
            labels = json.loads(labels)
        if isinstance(supported_capabilities, str):
            supported_capabilities = json.loads(supported_capabilities)
        if isinstance(enabled_capabilities, str):
            enabled_capabilities = json.loads(enabled_capabilities)
        collector["deployment"] = deployment
        collector["labels"] = labels
        collector["supported_capabilities"] = _capability_list(supported_capabilities)
        collector["enabled_capabilities"] = _capability_list(enabled_capabilities)
        collector["last_seen"] = collector.get("last_seen_at")
        collectors.append(collector)
    return collectors


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


def _load_json_value(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, str):
        return json.loads(value)
    return value


def upsert_collector_policy(
    *,
    policy_id: str,
    policy_name: str | None,
    policy_version: int,
    policy_json: dict[str, Any],
    enabled: bool,
) -> dict[str, Any]:
    ensure_database_schema()
    statement = text(
        """
        INSERT INTO collector_policies (
            policy_id,
            policy_name,
            policy_version,
            policy_json,
            enabled
        )
        VALUES (
            :policy_id,
            :policy_name,
            :policy_version,
            CAST(:policy_json AS JSONB),
            :enabled
        )
        ON CONFLICT (policy_id) DO UPDATE SET
            policy_name = EXCLUDED.policy_name,
            policy_version = EXCLUDED.policy_version,
            policy_json = EXCLUDED.policy_json,
            enabled = EXCLUDED.enabled,
            updated_at = NOW()
        RETURNING
            id,
            policy_id,
            policy_name,
            policy_version,
            policy_json,
            enabled,
            created_at,
            updated_at
        """
    )
    with get_engine().begin() as connection:
        row = connection.execute(
            statement,
            {
                "policy_id": policy_id,
                "policy_name": policy_name,
                "policy_version": policy_version,
                "policy_json": _json_payload(policy_json),
                "enabled": enabled,
            },
        ).mappings().one()
    policy = dict(row)
    policy["policy_json"] = _load_json_value(policy["policy_json"], {})
    return policy


def list_collector_policies() -> list[dict[str, Any]]:
    ensure_database_schema()
    statement = text(
        """
        SELECT
            id,
            policy_id,
            policy_name,
            policy_version,
            policy_json,
            enabled,
            created_at,
            updated_at
        FROM collector_policies
        ORDER BY updated_at DESC, id DESC
        """
    )
    with get_engine().begin() as connection:
        rows = connection.execute(statement).mappings().all()

    policies: list[dict[str, Any]] = []
    for row in rows:
        policy = dict(row)
        policy["policy_json"] = _load_json_value(policy["policy_json"], {})
        policies.append(policy)
    return policies


def create_policy_assignment(
    *,
    assignment_name: str | None,
    policy_id: str,
    enabled: bool,
    priority: int,
    collector_guid: str | None,
    collector_id: str | None,
    deployment_id: str | None,
    platform: str | None,
    label_selector: dict[str, Any] | None,
) -> dict[str, Any]:
    ensure_database_schema()
    statement = text(
        """
        INSERT INTO policy_assignments (
            assignment_name,
            policy_id,
            enabled,
            priority,
            collector_guid,
            collector_id,
            deployment_id,
            platform,
            label_selector
        )
        VALUES (
            :assignment_name,
            :policy_id,
            :enabled,
            :priority,
            :collector_guid,
            :collector_id,
            :deployment_id,
            :platform,
            CAST(:label_selector AS JSONB)
        )
        RETURNING
            id,
            assignment_name,
            policy_id,
            enabled,
            priority,
            collector_guid,
            collector_id,
            deployment_id,
            platform,
            label_selector,
            created_at,
            updated_at
        """
    )
    with get_engine().begin() as connection:
        row = connection.execute(
            statement,
            {
                "assignment_name": assignment_name,
                "policy_id": policy_id,
                "enabled": enabled,
                "priority": priority,
                "collector_guid": collector_guid,
                "collector_id": collector_id,
                "deployment_id": deployment_id,
                "platform": platform,
                "label_selector": _json_payload(label_selector) if label_selector is not None else None,
            },
        ).mappings().one()
    assignment = dict(row)
    assignment["label_selector"] = _load_json_value(assignment["label_selector"], None)
    return assignment


def list_policy_assignments() -> list[dict[str, Any]]:
    ensure_database_schema()
    statement = text(
        """
        SELECT
            id,
            assignment_name,
            policy_id,
            enabled,
            priority,
            collector_guid,
            collector_id,
            deployment_id,
            platform,
            label_selector,
            created_at,
            updated_at
        FROM policy_assignments
        ORDER BY priority DESC, id ASC
        """
    )
    with get_engine().begin() as connection:
        rows = connection.execute(statement).mappings().all()

    assignments: list[dict[str, Any]] = []
    for row in rows:
        assignment = dict(row)
        assignment["label_selector"] = _load_json_value(assignment["label_selector"], None)
        assignments.append(assignment)
    return assignments


def policy_assignment_matches(
    assignment: dict[str, Any],
    *,
    collector_guid: str | None,
    collector_id: str | None,
    deployment_id: str | None,
    platform: str | None,
    labels: dict[str, Any] | None,
) -> bool:
    if not assignment.get("enabled", True):
        return False

    matched_any = False
    for field_name, requested_value in (
        ("collector_guid", collector_guid),
        ("collector_id", collector_id),
        ("deployment_id", deployment_id),
    ):
        assignment_value = _clean_text(assignment.get(field_name))
        if assignment_value is None:
            continue
        matched_any = True
        if assignment_value != _clean_text(requested_value):
            return False

    assignment_platform = _clean_text(assignment.get("platform"))
    if assignment_platform is not None:
        matched_any = True
        if assignment_platform.lower() != (_clean_text(platform) or "").lower():
            return False

    label_selector = _load_json_value(assignment.get("label_selector"), None)
    if isinstance(label_selector, dict) and label_selector:
        matched_any = True
        if not isinstance(labels, dict):
            return False
        for key, value in label_selector.items():
            if labels.get(key) != value:
                return False

    return matched_any


def select_matching_policy_assignment(
    rows: list[dict[str, Any]],
    *,
    collector_guid: str | None,
    collector_id: str | None,
    deployment_id: str | None,
    platform: str | None,
    labels: dict[str, Any] | None,
) -> dict[str, Any] | None:
    enabled_rows = [row for row in rows if row.get("policy_enabled", row.get("enabled", True))]
    ordered_rows = sorted(enabled_rows, key=lambda row: (int(row.get("priority") or 0), -int(row.get("id") or 0)), reverse=True)
    for row in ordered_rows:
        if policy_assignment_matches(
            row,
            collector_guid=collector_guid,
            collector_id=collector_id,
            deployment_id=deployment_id,
            platform=platform,
            labels=labels,
        ):
            return row
    return None


def find_assigned_collector_policy(
    *,
    collector_guid: str | None,
    collector_id: str | None,
    deployment_id: str | None,
    platform: str | None,
    labels: dict[str, Any] | None,
) -> dict[str, Any] | None:
    ensure_database_schema()
    statement = text(
        """
        SELECT
            a.id,
            a.assignment_name,
            a.policy_id,
            a.enabled,
            a.priority,
            a.collector_guid,
            a.collector_id,
            a.deployment_id,
            a.platform,
            a.label_selector,
            a.created_at AS assigned_at,
            p.policy_name,
            p.policy_version,
            p.policy_json,
            p.enabled AS policy_enabled
        FROM policy_assignments a
        JOIN collector_policies p ON p.policy_id = a.policy_id
        WHERE a.enabled = TRUE
          AND p.enabled = TRUE
        ORDER BY a.priority DESC, a.id ASC
        """
    )
    with get_engine().begin() as connection:
        rows = [dict(row) for row in connection.execute(statement).mappings().all()]

    for row in rows:
        row["label_selector"] = _load_json_value(row.get("label_selector"), None)
        row["policy_json"] = _load_json_value(row.get("policy_json"), {})

    return select_matching_policy_assignment(
        rows,
        collector_guid=collector_guid,
        collector_id=collector_id,
        deployment_id=deployment_id,
        platform=platform,
        labels=labels,
    )


def _row_dicts(rows: Any) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def _platform_text(value: Any) -> str | None:
    if isinstance(value, dict):
        platform = _clean_text(value.get("platform"))
        if platform:
            return platform
        system = _clean_text(value.get("os") or value.get("system"))
        architecture = _clean_text(value.get("architecture") or value.get("arch"))
        if system and architecture:
            return f"{system}/{architecture}"
        return system
    return _clean_text(value)


def _architecture_text(value: Any) -> str | None:
    if isinstance(value, dict):
        return _clean_text(value.get("architecture") or value.get("arch"))
    return None


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def create_site(*, site_id: str, name: str, description: str | None) -> dict[str, Any]:
    ensure_database_schema()
    statement = text(
        """
        INSERT INTO sites (site_id, name, description)
        VALUES (:site_id, :name, :description)
        ON CONFLICT (site_id) DO UPDATE SET
            name = EXCLUDED.name,
            description = EXCLUDED.description,
            updated_at = NOW()
        RETURNING site_id, name, description, created_at, updated_at
        """
    )
    with get_engine().begin() as connection:
        row = connection.execute(
            statement,
            {"site_id": site_id, "name": name, "description": description},
        ).mappings().one()
    return dict(row)


def ensure_site_record(*, site_id: str, name: str | None = None, description: str | None = None) -> dict[str, Any]:
    return create_site(site_id=site_id, name=name or site_id, description=description)


def list_sites() -> list[dict[str, Any]]:
    ensure_database_schema()
    statement = text(
        """
        SELECT site_id, name, description, created_at, updated_at
        FROM sites
        ORDER BY updated_at DESC, site_id ASC
        """
    )
    with get_engine().begin() as connection:
        rows = connection.execute(statement).mappings().all()
    return _row_dicts(rows)


def create_agent_enrollment(
    *,
    agent_id: str,
    site_id: str,
    display_name: str | None,
    agent_type: str,
    platform: str | None,
    architecture: str | None,
    version: str | None = None,
    hostname: str | None = None,
    mode: str | None = None,
    last_seen_at: datetime | None = None,
) -> dict[str, Any]:
    ensure_site_record(site_id=site_id)
    statement = text(
        """
        INSERT INTO agent_enrollments (
            agent_id,
            site_id,
            display_name,
            agent_type,
            platform,
            architecture,
            version,
            hostname,
            mode,
            last_seen_at
        )
        VALUES (
            :agent_id,
            :site_id,
            :display_name,
            :agent_type,
            :platform,
            :architecture,
            :version,
            :hostname,
            :mode,
            :last_seen_at
        )
        ON CONFLICT (agent_id) DO UPDATE SET
            site_id = EXCLUDED.site_id,
            display_name = COALESCE(EXCLUDED.display_name, agent_enrollments.display_name),
            agent_type = EXCLUDED.agent_type,
            platform = COALESCE(EXCLUDED.platform, agent_enrollments.platform),
            architecture = COALESCE(EXCLUDED.architecture, agent_enrollments.architecture),
            version = COALESCE(EXCLUDED.version, agent_enrollments.version),
            hostname = COALESCE(EXCLUDED.hostname, agent_enrollments.hostname),
            mode = COALESCE(EXCLUDED.mode, agent_enrollments.mode),
            last_seen_at = COALESCE(EXCLUDED.last_seen_at, agent_enrollments.last_seen_at),
            updated_at = NOW()
        RETURNING
            agent_id,
            site_id,
            display_name,
            agent_type,
            platform,
            architecture,
            version,
            hostname,
            mode,
            created_at,
            updated_at,
            last_seen_at
        """
    )
    with get_engine().begin() as connection:
        row = connection.execute(
            statement,
            {
                "agent_id": agent_id,
                "site_id": site_id,
                "display_name": display_name,
                "agent_type": agent_type,
                "platform": platform,
                "architecture": architecture,
                "version": version,
                "hostname": hostname,
                "mode": mode,
                "last_seen_at": last_seen_at,
            },
        ).mappings().one()
    return dict(row)


def list_agent_enrollments() -> list[dict[str, Any]]:
    ensure_database_schema()
    statement = text(
        """
        SELECT
            agent_id,
            site_id,
            display_name,
            agent_type,
            platform,
            architecture,
            version,
            hostname,
            mode,
            created_at,
            updated_at,
            last_seen_at
        FROM agent_enrollments
        ORDER BY last_seen_at DESC NULLS LAST, updated_at DESC, agent_id ASC
        """
    )
    with get_engine().begin() as connection:
        rows = connection.execute(statement).mappings().all()
    return _row_dicts(rows)


def record_agent_checkin(
    *,
    payload: dict[str, Any],
    site_id: str,
    agent_id: str | None,
    received_at: datetime,
) -> int:
    ensure_site_record(site_id=site_id)
    platform = _platform_text(payload.get("platform"))
    architecture = _architecture_text(payload.get("platform"))
    version = _clean_text(payload.get("version") or payload.get("agent_version"))
    hostname = _clean_text(payload.get("hostname"))
    mode = _clean_text(payload.get("mode"))
    checked_in_at = _parse_datetime(payload.get("timestamp") or payload.get("check_in_at"))
    stored_payload = {key: value for key, value in payload.items() if key != "enrollment_token"}

    statement = text(
        """
        INSERT INTO agent_checkins (
            site_id,
            agent_id,
            version,
            platform,
            architecture,
            hostname,
            mode,
            checked_in_at,
            received_at,
            payload_json
        )
        VALUES (
            :site_id,
            :agent_id,
            :version,
            :platform,
            :architecture,
            :hostname,
            :mode,
            :checked_in_at,
            :received_at,
            CAST(:payload_json AS JSONB)
        )
        RETURNING id
        """
    )
    with get_engine().begin() as connection:
        checkin_id = connection.execute(
            statement,
            {
                "site_id": site_id,
                "agent_id": agent_id,
                "version": version,
                "platform": platform,
                "architecture": architecture,
                "hostname": hostname,
                "mode": mode,
                "checked_in_at": checked_in_at,
                "received_at": received_at,
                "payload_json": _json_payload(stored_payload),
            },
        ).scalar_one()

    if agent_id:
        create_agent_enrollment(
            agent_id=agent_id,
            site_id=site_id,
            display_name=hostname or agent_id,
            agent_type="endpoint-agent",
            platform=platform,
            architecture=architecture,
            version=version,
            hostname=hostname,
            mode=mode,
            last_seen_at=received_at,
        )
    return int(checkin_id)


def _first_nested_text(values: list[Any], *field_names: str) -> str | None:
    for value in values:
        if not isinstance(value, dict):
            continue
        for field_name in field_names:
            text_value = _clean_text(value.get(field_name))
            if text_value:
                return text_value
    return None


def _asset_primary_ip(asset: dict[str, Any]) -> str | None:
    direct_value = _clean_text(asset.get("primary_ip"))
    if direct_value:
        return direct_value
    ip_addresses = asset.get("ip_addresses")
    if isinstance(ip_addresses, list):
        value = _first_nested_text(ip_addresses, "address", "ip_address", "ip")
        if value:
            return value
    interfaces = asset.get("primary_interfaces")
    if isinstance(interfaces, list):
        for interface in interfaces:
            if isinstance(interface, dict) and isinstance(interface.get("ip_addresses"), list):
                value = _first_nested_text(interface["ip_addresses"], "address", "ip_address", "ip")
                if value:
                    return value
    return None


def _asset_mac(asset: dict[str, Any]) -> str | None:
    direct_value = _normalize_mac_address(asset.get("mac") or asset.get("mac_address"))
    if direct_value:
        return direct_value
    mac_addresses = asset.get("mac_addresses")
    if isinstance(mac_addresses, list):
        value = _first_nested_text(mac_addresses, "address", "mac_address", "mac")
        if value:
            return _normalize_mac_address(value)
    interfaces = asset.get("primary_interfaces")
    if isinstance(interfaces, list):
        value = _first_nested_text(interfaces, "mac_address", "mac")
        if value:
            return _normalize_mac_address(value)
    return None


def _asset_evidence_count(asset: dict[str, Any]) -> int:
    count = 1
    for field_name in (
        "host",
        "platform_info",
        "primary_interfaces",
        "ip_addresses",
        "mac_addresses",
        "default_gateway",
        "network_neighbors",
        "software",
    ):
        value = asset.get(field_name)
        if isinstance(value, list):
            count += len([entry for entry in value if entry is not None])
        elif value:
            count += 1
    return count


def normalize_local_inventory_assets(payload: dict[str, Any], *, site_id: str, received_at: datetime) -> list[dict[str, Any]]:
    assets = payload.get("assets")
    if not isinstance(assets, list):
        return []
    source_agent_id = _clean_text(payload.get("agent_id"))
    normalized: list[dict[str, Any]] = []
    for index, asset in enumerate(assets):
        if not isinstance(asset, dict):
            continue
        hostname = _clean_text(asset.get("hostname") or _metadata_object(asset.get("host")).get("hostname"))
        primary_ip = _asset_primary_ip(asset)
        mac = _asset_mac(asset)
        asset_id = _clean_text(asset.get("asset_id")) or hostname or mac or primary_ip
        if not asset_id:
            asset_id = f"observed-{index + 1}"
        platform_info = _metadata_object(asset.get("platform_info"))
        normalized.append(
            {
                "asset_key": f"{site_id}:{asset_id}",
                "asset_id": asset_id,
                "site_id": site_id,
                "hostname": hostname,
                "primary_ip": primary_ip,
                "mac": mac,
                "os": _clean_text(asset.get("os") or platform_info.get("os")),
                "platform": _clean_text(asset.get("platform") or platform_info.get("platform")),
                "source_agent_id": source_agent_id,
                "first_seen_at": received_at,
                "last_seen_at": received_at,
                "evidence_count": _asset_evidence_count(asset),
                "metadata": asset,
            }
        )
    return normalized


def _upsert_control_tower_asset(connection: Any, asset: dict[str, Any]) -> None:
    connection.execute(
        text(
            """
            INSERT INTO control_tower_assets (
                asset_key,
                asset_id,
                site_id,
                hostname,
                primary_ip,
                mac,
                os,
                platform,
                source_agent_id,
                first_seen_at,
                last_seen_at,
                evidence_count,
                metadata_json
            )
            VALUES (
                :asset_key,
                :asset_id,
                :site_id,
                :hostname,
                :primary_ip,
                :mac,
                :os,
                :platform,
                :source_agent_id,
                :first_seen_at,
                :last_seen_at,
                :evidence_count,
                CAST(:metadata_json AS JSONB)
            )
            ON CONFLICT (asset_key) DO UPDATE SET
                hostname = COALESCE(EXCLUDED.hostname, control_tower_assets.hostname),
                primary_ip = COALESCE(EXCLUDED.primary_ip, control_tower_assets.primary_ip),
                mac = COALESCE(EXCLUDED.mac, control_tower_assets.mac),
                os = COALESCE(EXCLUDED.os, control_tower_assets.os),
                platform = COALESCE(EXCLUDED.platform, control_tower_assets.platform),
                source_agent_id = COALESCE(EXCLUDED.source_agent_id, control_tower_assets.source_agent_id),
                last_seen_at = EXCLUDED.last_seen_at,
                evidence_count = control_tower_assets.evidence_count + EXCLUDED.evidence_count,
                metadata_json = EXCLUDED.metadata_json,
                updated_at = NOW()
            """
        ),
        {
            "asset_key": asset["asset_key"],
            "asset_id": asset["asset_id"],
            "site_id": asset["site_id"],
            "hostname": asset["hostname"],
            "primary_ip": asset["primary_ip"],
            "mac": asset["mac"],
            "os": asset["os"],
            "platform": asset["platform"],
            "source_agent_id": asset["source_agent_id"],
            "first_seen_at": asset["first_seen_at"],
            "last_seen_at": asset["last_seen_at"],
            "evidence_count": asset["evidence_count"],
            "metadata_json": _json_payload(asset["metadata"]),
        },
    )


def record_local_inventory_collection(
    *,
    payload: dict[str, Any],
    site_id: str,
    received_at: datetime,
    observed_asset_count: int,
) -> dict[str, int]:
    ensure_site_record(site_id=site_id)
    normalized_assets = normalize_local_inventory_assets(payload, site_id=site_id, received_at=received_at)
    statement = text(
        """
        INSERT INTO local_inventory_collections (
            site_id,
            source_agent_id,
            schema_version,
            collected_at,
            received_at,
            observed_asset_count,
            normalized_asset_count,
            payload_json
        )
        VALUES (
            :site_id,
            :source_agent_id,
            :schema_version,
            :collected_at,
            :received_at,
            :observed_asset_count,
            :normalized_asset_count,
            CAST(:payload_json AS JSONB)
        )
        RETURNING id
        """
    )
    with get_engine().begin() as connection:
        collection_id = connection.execute(
            statement,
            {
                "site_id": site_id,
                "source_agent_id": _clean_text(payload.get("agent_id")),
                "schema_version": _clean_text(payload.get("schema_version")),
                "collected_at": _parse_datetime(payload.get("collected_at")),
                "received_at": received_at,
                "observed_asset_count": observed_asset_count,
                "normalized_asset_count": len(normalized_assets),
                "payload_json": _json_payload(payload),
            },
        ).scalar_one()
        for asset in normalized_assets:
            _upsert_control_tower_asset(connection, asset)
    return {"collection_id": int(collection_id), "normalized_asset_count": len(normalized_assets)}


def list_agent_checkins(limit: int = 25) -> list[dict[str, Any]]:
    ensure_database_schema()
    statement = text(
        """
        SELECT
            id,
            site_id,
            agent_id,
            version,
            platform,
            architecture,
            hostname,
            mode,
            checked_in_at,
            received_at,
            created_at
        FROM agent_checkins
        ORDER BY received_at DESC, id DESC
        LIMIT :limit
        """
    )
    with get_engine().begin() as connection:
        rows = connection.execute(statement, {"limit": limit}).mappings().all()
    return _row_dicts(rows)


def list_control_tower_assets() -> list[dict[str, Any]]:
    ensure_database_schema()
    statement = text(
        """
        SELECT
            asset_id,
            site_id,
            hostname,
            primary_ip,
            mac,
            os,
            platform,
            source_agent_id,
            first_seen_at,
            last_seen_at,
            evidence_count,
            metadata_json,
            created_at,
            updated_at
        FROM control_tower_assets
        ORDER BY last_seen_at DESC, asset_id ASC
        """
    )
    with get_engine().begin() as connection:
        rows = connection.execute(statement).mappings().all()

    assets: list[dict[str, Any]] = []
    for row in rows:
        asset = dict(row)
        metadata = asset.pop("metadata_json")
        asset["metadata"] = _load_json_value(metadata, {})
        assets.append(asset)
    return assets


def control_tower_summary() -> dict[str, int]:
    ensure_database_schema()
    statement = text(
        """
        SELECT
            (SELECT COUNT(*) FROM sites) AS site_count,
            (SELECT COUNT(*) FROM agent_enrollments) AS agent_count,
            (SELECT COUNT(*) FROM agent_checkins) AS checkin_count,
            (SELECT COUNT(*) FROM control_tower_assets) AS asset_count,
            (SELECT COALESCE(SUM(evidence_count), 0) FROM control_tower_assets) AS evidence_count
        """
    )
    with get_engine().begin() as connection:
        row = connection.execute(statement).mappings().one()
    return {key: int(value or 0) for key, value in dict(row).items()}
