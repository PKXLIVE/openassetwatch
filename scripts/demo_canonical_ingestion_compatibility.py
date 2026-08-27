#!/usr/bin/env python3
"""Run the fictional canonical-ingestion consolidation demonstration."""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app import main as backend_main  # noqa: E402
from app.canonical_ingestion import (  # noqa: E402
    endpoint_envelope,
    ingest,
    legacy_collector_envelope,
    transitional_envelope,
)
from app.canonical_ingestion_store import (  # noqa: E402
    compatibility_status,
    historical_preview,
)
from app.database import latest_inventory_submission  # noqa: E402
from app.endpoint_agent_contracts import EndpointInventoryRequest  # noqa: E402
from app.main import CollectorInventoryRequest  # noqa: E402
from app.schema_migrations import migrate_database_schema  # noqa: E402


DEMO_ENABLED = os.getenv("OPENASSETWATCH_CANONICAL_INGESTION_DEMO") == "1"
DATABASE_NAME = re.compile(r"^openassetwatch_canonical_demo_[0-9a-f]{16}$")


def _counts(engine) -> dict[str, int]:
    with engine.connect() as connection:
        return {
            "assets": int(
                connection.execute(text("SELECT COUNT(*) FROM control_tower_assets")).scalar_one()
            ),
            "components": int(
                connection.execute(text("SELECT COUNT(*) FROM asset_components")).scalar_one()
            ),
            "matches": int(
                connection.execute(text("SELECT COUNT(*) FROM vulnerability_matches")).scalar_one()
            ),
            "findings": int(
                connection.execute(text("SELECT COUNT(*) FROM findings")).scalar_one()
            ),
            "asset_risk": int(
                connection.execute(text("SELECT COUNT(*) FROM asset_risk_scores")).scalar_one()
            ),
        }


def _endpoint_payload(now: datetime) -> EndpointInventoryRequest:
    return EndpointInventoryRequest.model_validate(
        {
            "schema_version": "oaw.endpoint-inventory.v1",
            "inventory_batch_id": "fictional-endpoint-batch-0001",
            "observed_at": now.isoformat(),
            "inventory_mode": "complete",
            "agent_version": "0.1.0",
            "platform": "linux",
            "architecture": "amd64",
            "assets": [
                {
                    "asset_id": "fictional-shared-asset",
                    "hostname": "endpoint-authority.example.test",
                    "os": "FictionalOS 1",
                    "platform": "linux",
                    "interfaces": [],
                    "evidence": [
                        {
                            "kind": "operating-system",
                            "value": "FictionalOS 1",
                        }
                    ],
                    "components": [
                        {
                            "component_type": "application",
                            "ecosystem": "pypi",
                            "name": "fictional-package",
                            "version": "1.0.0",
                            "purl": "pkg:pypi/fictional-package@1.0.0",
                        }
                    ],
                }
            ],
        }
    )


def run_demo(database_url: str) -> dict[str, object]:
    parsed = make_url(database_url)
    database_name = f"openassetwatch_canonical_demo_{uuid4().hex[:16]}"
    if not DATABASE_NAME.fullmatch(database_name):
        raise RuntimeError("demo database name is outside the disposable prefix")
    admin_engine = create_engine(
        parsed.set(database="postgres"),
        isolation_level="AUTOCOMMIT",
        poolclass=NullPool,
    )
    database_engine = None
    try:
        with admin_engine.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{database_name}"')
        database_engine = create_engine(
            parsed.set(database=database_name),
            poolclass=NullPool,
        )
        migration = migrate_database_schema(database_engine)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        endpoint_context = SimpleNamespace(
            site_id="fictional-site",
            agent_id="agent_" + "1" * 32,
            deployment_id="fictional-deployment",
            credential_id="acred_" + "2" * 32,
        )
        with database_engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO sites (site_id, name) "
                    "VALUES ('fictional-site', 'Fictional Site')"
                )
            )
            connection.execute(
                text(
                    """
                    INSERT INTO agent_enrollments (
                        agent_id, site_id, display_name, agent_type,
                        updated_at, identity_status
                    ) VALUES (
                        :agent_id, :site_id, 'Fictional Endpoint',
                        'endpoint-agent', :now, 'active'
                    )
                    """
                ),
                {
                    "agent_id": endpoint_context.agent_id,
                    "site_id": endpoint_context.site_id,
                    "now": now,
                },
            )
            connection.execute(
                text(
                    """
                    INSERT INTO endpoint_agent_credentials (
                        credential_id, token_lookup_id, credential_digest,
                        agent_id, site_id, deployment_id, agent_type, status
                    ) VALUES (
                        :credential_id, :lookup_id, :digest, :agent_id,
                        :site_id, :deployment_id, 'endpoint-agent', 'active'
                    )
                    """
                ),
                {
                    "credential_id": endpoint_context.credential_id,
                    "lookup_id": "3" * 32,
                    "digest": "4" * 64,
                    "agent_id": endpoint_context.agent_id,
                    "site_id": endpoint_context.site_id,
                    "deployment_id": endpoint_context.deployment_id,
                },
            )

        with (
            patch("app.database.get_engine", return_value=database_engine),
            patch("app.database.ensure_database_schema"),
        ):
            endpoint = endpoint_envelope(
                payload=_endpoint_payload(now),
                context=endpoint_context,
                received_at=now,
            )
            endpoint_ack = ingest(endpoint)
            collector = legacy_collector_envelope(
                payload=CollectorInventoryRequest.model_validate(
                    {
                        "collector_id": "fictional-python-collector",
                        "collector_name": "Fictional Python Collector",
                        "mode": "device",
                        "collected_at": (now + timedelta(seconds=1)).isoformat(),
                        "deployment": {"site_id": "fictional-site"},
                        "device": {
                            "asset_id": "fictional-shared-asset",
                            "hostname": "collector-claim.example.test",
                        },
                        "software": [
                            {
                                "name": "fictional-package",
                                "version": "1.0.0",
                                "ecosystem": "pypi",
                                "purl": "pkg:pypi/fictional-package@1.0.0",
                            }
                        ],
                    }
                ),
                received_at=now + timedelta(seconds=1),
                authentication_class="legacy-shared",
            )
            collector_ack = ingest(collector)
            transitional_ack = ingest(
                transitional_envelope(
                    payload={
                        "site_id": "fictional-site",
                        "observation_batch_id": "fictional-transition-0001",
                        "observed_at": (now + timedelta(days=1)).isoformat(),
                        "source_authority": "authenticated-endpoint",
                        "assets": [
                            {
                                "asset_id": "fictional-shared-asset",
                                "hostname": "untrusted-claim.example.test",
                                "trust_rank": 100,
                            }
                        ],
                    },
                    received_at=now + timedelta(days=1),
                )
            )
            backend_main._run_canonical_inventory_evaluation(
                canonical_collection_id=endpoint_ack.canonical_collection_id,
            )
            before_replay = _counts(database_engine)
            collector_replay = ingest(collector)
            after_replay = _counts(database_engine)

            with database_engine.connect() as connection:
                authority = connection.execute(
                    text(
                        """
                        SELECT cta.hostname, caa.source_authority, caa.trust_rank
                        FROM control_tower_assets cta
                        JOIN canonical_asset_authority caa
                          ON caa.asset_key=cta.asset_key
                        WHERE cta.site_id='fictional-site'
                          AND cta.asset_id='fictional-shared-asset'
                        """
                    )
                ).mappings().one()
                classification_sources = connection.execute(
                    text(
                        """
                        SELECT DISTINCT source_type
                        FROM classification_evidence
                        WHERE site_id='fictional-site'
                          AND asset_id='fictional-shared-asset'
                        ORDER BY source_type
                        """
                    )
                ).scalars().all()
            tools = backend_main.build_read_only_hub_tools()
            ai_ids = [
                item.evidence_id
                for item in tools.evidence_catalog(
                    site_id="fictional-site",
                    asset_id="fictional-shared-asset",
                )
                if item.evidence_type == "canonical_inventory_collection"
            ]
            latest = latest_inventory_submission()
            status = compatibility_status(limit=10)
            history = historical_preview()

        return {
            "demo_status": "passed",
            "schema_version": migration.current_version,
            "canonical_collection_ids": {
                "authenticated_endpoint": endpoint_ack.canonical_collection_id,
                "python_collector": collector_ack.canonical_collection_id,
                "transitional": transitional_ack.canonical_collection_id,
            },
            "current_asset_authority": dict(authority),
            "classification_source_types": list(classification_sources),
            "replay": {
                "status": collector_replay.status,
                "same_acknowledgement": (
                    collector_replay.canonical_collection_id
                    == collector_ack.canonical_collection_id
                ),
                "counts_unchanged": before_replay == after_replay,
                "counts": after_replay,
            },
            "legacy_operational_status": {
                "latest_submission_id": latest["submission_id"] if latest else None,
                "canonical_collection_id": (
                    latest["canonical_collection_id"] if latest else None
                ),
                "historical_records": history["legacy_records"],
            },
            "compatibility_routes": len(status["routes"]),
            "ai_canonical_evidence_ids": ai_ids,
            "ai_read_only": True,
        }
    finally:
        if database_engine is not None:
            database_engine.dispose()
        with admin_engine.connect() as connection:
            connection.execute(
                text(
                    """
                    SELECT pg_terminate_backend(pid)
                    FROM pg_stat_activity
                    WHERE datname = :database_name
                      AND pid <> pg_backend_pid()
                    """
                ),
                {"database_name": database_name},
            )
            connection.exec_driver_sql(f'DROP DATABASE IF EXISTS "{database_name}"')
        admin_engine.dispose()


def main() -> int:
    if not DEMO_ENABLED or not os.getenv("DATABASE_URL"):
        print(
            json.dumps(
                {
                    "demo_status": "disabled",
                    "error_code": "explicit-demo-environment-required",
                },
                sort_keys=True,
            )
        )
        return 2
    try:
        result = run_demo(os.environ["DATABASE_URL"])
    except Exception as exc:  # noqa: BLE001 - never print raw driver/config errors.
        print(
            json.dumps(
                {
                    "demo_status": "failed",
                    "error_code": f"demo-{type(exc).__name__.lower()}"[:80],
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
