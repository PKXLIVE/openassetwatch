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


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    return create_engine(os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL), pool_pre_ping=True)


def ensure_database_schema() -> None:
    with get_engine().begin() as connection:
        connection.execute(text(CREATE_INVENTORY_TABLE_SQL))
        connection.execute(text(CREATE_RECEIVED_AT_INDEX_SQL))
        connection.execute(text(CREATE_COLLECTOR_ID_INDEX_SQL))


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
