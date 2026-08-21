from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import unittest
from datetime import datetime, timezone
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.pool import NullPool

from app.advisory_catalog import load_catalog
from app.advisory_store import SqlAdvisoryStore
from app.ai_advisor import AdvisorQueryRequest, ProviderConfig, run_advisor
from app.component_store import SqlComponentStore
from app.database import (
    EndpointInventoryAuthorizationRejected,
    LegacyAgentIdentityConflict,
    create_agent_enrollment as create_legacy_agent_enrollment,
    EndpointInventoryReplayConflict,
    record_agent_checkin,
    record_authenticated_endpoint_inventory,
    record_local_inventory_collection,
    record_observation_batch,
)
from app.endpoint_agent_identity import (
    AgentAuthenticationRejected,
    AgentEnrollmentRejected,
    authenticate_agent_request,
    create_agent_enrollment,
    exchange_agent_enrollment,
    issue_agent_credential,
    record_authenticated_agent_checkin,
    revoke_agent_credential,
    rotate_agent_credential,
)
from app.finding_store import SqlFindingStore
from app.main import _run_endpoint_inventory_reevaluation, build_read_only_hub_tools
from app.schema_migrations import migrate_database_schema
from app.vulnerability_store import SqlVulnerabilityStore


ENABLED = os.getenv("OPENASSETWATCH_ENDPOINT_AGENT_POSTGRES_TEST") == "1"
DATABASE_NAME = re.compile(r"^openassetwatch_agent_test_[0-9a-f]{16}$")


@unittest.skipUnless(ENABLED, "requires an explicitly isolated disposable PostgreSQL server")
class EndpointAgentPostgresTests(unittest.TestCase):
    admin_engine: Engine
    database_engine: Engine
    database_name: str

    def setUp(self) -> None:
        source_url = os.environ["DATABASE_URL"]
        parsed = make_url(source_url)
        self.database_name = f"openassetwatch_agent_test_{uuid4().hex[:16]}"
        self.assertRegex(self.database_name, DATABASE_NAME)
        self.admin_engine = create_engine(
            parsed.set(database="postgres"),
            isolation_level="AUTOCOMMIT",
            poolclass=NullPool,
        )
        with self.admin_engine.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{self.database_name}"')
        self.database_engine = create_engine(
            parsed.set(database=self.database_name), poolclass=NullPool
        )
        migrate_database_schema(self.database_engine)
        with self.database_engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO sites (site_id, name) VALUES ('site-agent-test', 'Endpoint Agent Test')"
                )
            )
        self.patchers = [
            patch("app.endpoint_agent_identity.get_engine", return_value=self.database_engine),
            patch("app.endpoint_agent_identity.ensure_database_schema"),
            patch("app.database.get_engine", return_value=self.database_engine),
            patch("app.database.ensure_database_schema"),
        ]
        for patcher in self.patchers:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.patchers):
            patcher.stop()
        self.database_engine.dispose()
        if not DATABASE_NAME.fullmatch(self.database_name):
            self.fail("refusing to drop a database outside the disposable prefix")
        with self.admin_engine.connect() as connection:
            connection.execute(
                text(
                    """
                    SELECT pg_terminate_backend(pid)
                    FROM pg_stat_activity
                    WHERE datname = :database_name AND pid <> pg_backend_pid()
                    """
                ),
                {"database_name": self.database_name},
            )
            connection.exec_driver_sql(f'DROP DATABASE "{self.database_name}"')
        self.admin_engine.dispose()

    def test_full_identity_replay_rotation_and_persistence_lifecycle(self) -> None:
        now = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
        with self.database_engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO agent_enrollments ("
                    "agent_id, site_id, display_name, agent_type, identity_status, updated_at"
                    ") VALUES ("
                    "'sensor-bound-test', 'site-agent-test', 'Bound Sensor', "
                    "'network-sensor', 'active', :now)"
                ),
                {"now": now},
            )
        sensor_result = record_observation_batch(
            payload={
                "schema_version": "oaw.observation-batch.v1",
                "observation_batch_id": "sensor-bound-test:20260820T120000Z:0001",
                "site_id": "site-agent-test",
                "sensor_id": "sensor-bound-test",
                "sensor_name": "Bound Sensor",
                "sensor_type": "passive-network-sensor",
                "sensor_version": "0.1.0",
                "observed_at": now.isoformat(),
                "collected_at": now.isoformat(),
                "observation_source": "passive-network",
                "assets": [
                    {
                        "asset_id": "sensor-observed-asset",
                        "hostname": "sensor-observed.example.test",
                    }
                ],
            },
            received_at=now,
            source_authenticated=True,
        )
        self.assertFalse(sensor_result["duplicate"])
        with self.database_engine.connect() as connection:
            sensor_identity = connection.execute(
                text(
                    "SELECT site_id, agent_type, identity_status, last_seen_at "
                    "FROM agent_enrollments WHERE agent_id='sensor-bound-test'"
                )
            ).mappings().one()
        self.assertEqual(sensor_identity["site_id"], "site-agent-test")
        self.assertEqual(sensor_identity["agent_type"], "network-sensor")
        self.assertEqual(sensor_identity["identity_status"], "active")
        self.assertEqual(sensor_identity["last_seen_at"], now)

        enrollment = create_agent_enrollment(
            site_id="site-agent-test",
            requested_deployment_id="deployment-test",
            requested_display_name="Fictional Workstation",
            requested_agent_type="endpoint-agent",
            expires_in_minutes=60,
            actor="api-admin-token",
            now=now,
        )
        raw_enrollment = enrollment["enrollment_token"]
        with self.database_engine.connect() as connection:
            stored = connection.execute(
                text(
                    "SELECT token_lookup_id, token_digest FROM endpoint_agent_enrollments WHERE enrollment_id=:id"
                ),
                {"id": enrollment["enrollment_id"]},
            ).mappings().one()
        self.assertNotIn(raw_enrollment, stored.values())
        self.assertEqual(len(stored["token_digest"]), 64)

        barrier = threading.Barrier(2)
        exchanges: list[dict[str, object] | Exception] = []

        def exchange() -> None:
            barrier.wait(timeout=5)
            try:
                exchanges.append(
                    exchange_agent_enrollment(
                        enrollment_token=raw_enrollment,
                        installation_id="deployment-test",
                        display_name="Fictional Workstation",
                        agent_version="0.1.0",
                        platform="linux",
                        architecture="amd64",
                        agent_type="endpoint-agent",
                        now=now,
                    )
                )
            except Exception as exc:  # surfaced below.
                exchanges.append(exc)

        workers = [threading.Thread(target=exchange) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=10)
        self.assertFalse(any(worker.is_alive() for worker in workers))
        successes = [item for item in exchanges if isinstance(item, dict)]
        failures = [item for item in exchanges if isinstance(item, Exception)]
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], AgentEnrollmentRejected)
        issued = successes[0]
        raw_credential = str(issued["agent_credential"])
        agent_id = str(issued["agent_id"])
        credential_id = str(issued["credential_id"])
        with self.database_engine.connect() as connection:
            count, digest = connection.execute(
                text(
                    "SELECT COUNT(*), MAX(credential_digest) FROM endpoint_agent_credentials WHERE agent_id=:agent_id"
                ),
                {"agent_id": agent_id},
            ).one()
        self.assertEqual(count, 1)
        self.assertNotEqual(digest, raw_credential)

        with self.assertRaises(LegacyAgentIdentityConflict):
            create_legacy_agent_enrollment(
                agent_id=agent_id,
                site_id="site-agent-test",
                display_name="Attacker-selected legacy identity",
                agent_type="network-sensor",
                platform="unknown",
                architecture="unknown",
            )
        with self.assertRaises(LegacyAgentIdentityConflict):
            record_agent_checkin(
                payload={
                    "site_id": "site-agent-test",
                    "agent_id": agent_id,
                    "hostname": "attacker-selected.example.test",
                },
                site_id="site-agent-test",
                agent_id=agent_id,
                received_at=now,
            )
        with self.database_engine.connect() as connection:
            protected_identity = connection.execute(
                text(
                    "SELECT site_id, agent_type, identity_status, display_name "
                    "FROM agent_enrollments WHERE agent_id=:agent_id"
                ),
                {"agent_id": agent_id},
            ).mappings().one()
            rejected_legacy_checkins = connection.execute(
                text(
                    "SELECT COUNT(*) FROM agent_checkins "
                    "WHERE agent_id=:agent_id AND hostname='attacker-selected.example.test'"
                ),
                {"agent_id": agent_id},
            ).scalar_one()
        self.assertEqual(protected_identity["site_id"], "site-agent-test")
        self.assertEqual(protected_identity["agent_type"], "endpoint-agent")
        self.assertEqual(protected_identity["identity_status"], "active")
        self.assertNotEqual(
            protected_identity["display_name"],
            "Attacker-selected legacy identity",
        )
        self.assertEqual(rejected_legacy_checkins, 0)

        context = authenticate_agent_request(
            provided_token=raw_credential,
            claimed_site_id="site-agent-test",
            claimed_agent_id=agent_id,
            claimed_deployment_id="deployment-test",
            claimed_agent_type="endpoint-agent",
            now=now,
        )
        with self.assertRaises(AgentAuthenticationRejected):
            authenticate_agent_request(
                provided_token=raw_credential,
                claimed_site_id="site-other",
                now=now,
            )
        with self.assertRaises(AgentAuthenticationRejected):
            authenticate_agent_request(
                provided_token=issue_agent_credential().raw,
                claimed_site_id="site-agent-test",
                now=now,
            )
        record_authenticated_agent_checkin(
            context=context,
            payload={
                "agent_version": "0.1.0",
                "platform": "linux",
                "architecture": "amd64",
                "hostname": "fictional-host.example.test",
                "supported_capabilities": ["endpoint-inventory-v1"],
                "inventory_schema_version": "oaw.endpoint-inventory.v1",
                "health": "healthy",
                "observed_at": now.isoformat(),
            },
            received_at=now,
        )

        payload = {
            "schema_version": "oaw.endpoint-inventory.v1",
            "observation_batch_id": "batch_agent_postgres_0001",
            "inventory_batch_id": "batch_agent_postgres_0001",
            "observed_at": now.isoformat(),
            "collected_at": now.isoformat(),
            "inventory_mode": "complete",
            "component_inventory_complete": True,
            "agent_id": agent_id,
            "site_id": "site-agent-test",
            "sensor_type": "endpoint-agent",
            "observation_source": "endpoint-inventory",
            "source_authenticated": True,
            "source_authority": "authenticated-endpoint",
            "credential_id": credential_id,
            "assets": [
                {
                    "asset_id": "fictional-host",
                    "hostname": "fictional-host.example.test",
                    "os": "FictionalOS 1",
                    "category": "workstation",
                    "evidence": [
                        {
                            "kind": "operating-system",
                            "value": "FictionalOS 1",
                            "method": "endpoint-inventory",
                            "confidence": 0.95,
                        }
                    ],
                    "components": [
                        {
                            "component_type": "application",
                            "ecosystem": "pypi",
                            "name": "asterion-agent",
                            "version": "1.2.0",
                            "purl": "pkg:pypi/asterion-agent",
                            "confidence": 0.95,
                        }
                    ],
                    "component_inventory_complete": True,
                }
            ],
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        legacy_collection = record_local_inventory_collection(
            payload={
                "schema_version": "oaw.inventory.v1",
                "observation_batch_id": "batch_agent_postgres_0001",
                "observed_at": now.isoformat(),
                "collected_at": now.isoformat(),
                "agent_id": agent_id,
                "site_id": "site-agent-test",
                "observation_source": "local-inventory",
                "assets": [
                    {
                        "asset_id": "fictional-host",
                        "hostname": "lower-trust.example.test",
                    }
                ],
            },
            site_id="site-agent-test",
            received_at=now,
            observed_asset_count=1,
            source_authenticated=False,
        )
        first = record_authenticated_endpoint_inventory(
            payload=payload,
            payload_sha256=digest,
            site_id="site-agent-test",
            agent_id=agent_id,
            credential_id=credential_id,
            inventory_batch_id="batch_agent_postgres_0001",
            inventory_mode="complete",
            observed_at=now,
            received_at=now,
        )
        replay = record_authenticated_endpoint_inventory(
            payload=payload,
            payload_sha256=digest,
            site_id="site-agent-test",
            agent_id=agent_id,
            credential_id=credential_id,
            inventory_batch_id="batch_agent_postgres_0001",
            inventory_mode="complete",
            observed_at=now,
            received_at=now,
        )
        self.assertFalse(first["duplicate"])
        self.assertNotEqual(first["collection_id"], legacy_collection["collection_id"])
        self.assertTrue(replay["duplicate"])
        self.assertEqual(first["storage_id"], replay["storage_id"])
        with self.assertRaises(EndpointInventoryReplayConflict):
            record_authenticated_endpoint_inventory(
                payload=payload,
                payload_sha256="f" * 64,
                site_id="site-agent-test",
                agent_id=agent_id,
                credential_id=credential_id,
                inventory_batch_id="batch_agent_postgres_0001",
                inventory_mode="complete",
                observed_at=now,
                received_at=now,
            )

        catalog, checksum = load_catalog(
            os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                "catalogs",
                "synthetic-advisory-catalog.json",
            )
        )
        SqlAdvisoryStore().import_catalog(catalog=catalog, checksum=checksum, imported_at=now)
        _run_endpoint_inventory_reevaluation(
            storage_id=int(first["storage_id"]),
            site_id="site-agent-test",
            asset_ids=["fictional-host"],
        )
        components = SqlComponentStore().list_components(
            site_id="site-agent-test", asset_id="fictional-host"
        )["items"]
        matches = SqlVulnerabilityStore().list_matches(
            site_id="site-agent-test", asset_id="fictional-host"
        )["items"]
        finding_store = SqlFindingStore()
        findings = finding_store.list_findings(
            site_id="site-agent-test", asset_id="fictional-host", status="active"
        )["items"]
        risk = finding_store.get_asset_risk(
            site_id="site-agent-test", asset_id="fictional-host"
        )
        self.assertEqual(len(components), 1)
        self.assertEqual(matches[0]["match_status"], "affected")
        self.assertEqual(findings[0]["rule_id"], "vulnerable-component")
        self.assertIsNotNone(risk)
        tools = build_read_only_hub_tools()
        advisor = run_advisor(
            request=AdvisorQueryRequest(
                question=(
                    "Explain endpoint agent identity, classification evidence, component "
                    "vulnerability, finding, and deterministic risk contribution for "
                    "fictional-host"
                ),
                site_id="site-agent-test",
                asset_id="fictional-host",
            ),
            tools=tools,
            config=ProviderConfig("demo", False, None, None, None, 10),
        )
        evidence_ids = {item.evidence_id for item in advisor.evidence}
        self.assertIn(f"agent:{agent_id}:identity", evidence_ids)
        self.assertIn(components[0]["component_id"], evidence_ids)
        self.assertIn(matches[0]["match_id"], evidence_ids)
        self.assertIn(f"finding:{findings[0]['finding_id']}", evidence_ids)
        self.assertTrue(any(item.startswith("risk:asset:") for item in evidence_ids))
        self.assertTrue(any(item.startswith("cev_") for item in evidence_ids))
        rotated = rotate_agent_credential(agent_id, actor="api-admin-token", now=now)
        with self.assertRaises(AgentAuthenticationRejected):
            authenticate_agent_request(provided_token=raw_credential, now=now)
        with self.assertRaises(AgentAuthenticationRejected):
            record_authenticated_agent_checkin(
                context=context,
                payload={"agent_version": "stale-credential"},
                received_at=now,
            )
        stale_payload = dict(payload)
        stale_payload["observation_batch_id"] = "batch_agent_postgres_stale"
        stale_payload["inventory_batch_id"] = "batch_agent_postgres_stale"
        with self.assertRaises(EndpointInventoryAuthorizationRejected):
            record_authenticated_endpoint_inventory(
                payload=stale_payload,
                payload_sha256="e" * 64,
                site_id="site-agent-test",
                agent_id=agent_id,
                credential_id=credential_id,
                inventory_batch_id="batch_agent_postgres_stale",
                inventory_mode="complete",
                observed_at=now,
                received_at=now,
            )
        new_context = authenticate_agent_request(
            provided_token=str(rotated["agent_credential"]), now=now
        )
        revoke_agent_credential(
            agent_id,
            str(rotated["credential_id"]),
            actor="api-admin-token",
            now=now,
        )
        with self.assertRaises(AgentAuthenticationRejected):
            authenticate_agent_request(
                provided_token=str(rotated["agent_credential"]), now=now
            )
        self.assertEqual(new_context.agent_id, agent_id)

        self.database_engine.dispose()
        self.database_engine = create_engine(
            make_url(os.environ["DATABASE_URL"]).set(database=self.database_name),
            poolclass=NullPool,
        )
        for patcher in self.patchers:
            patcher.stop()
        self.patchers = [
            patch("app.endpoint_agent_identity.get_engine", return_value=self.database_engine),
            patch("app.endpoint_agent_identity.ensure_database_schema"),
            patch("app.database.get_engine", return_value=self.database_engine),
            patch("app.database.ensure_database_schema"),
        ]
        for patcher in self.patchers:
            patcher.start()
        with self.database_engine.connect() as connection:
            batch = connection.execute(
                text(
                    "SELECT collection_id, reevaluation_state FROM endpoint_agent_inventory_batches WHERE storage_id=:id"
                ),
                {"id": first["storage_id"]},
            ).mappings().one()
            history = connection.execute(
                text(
                    "SELECT COUNT(*) FROM endpoint_agent_identity_audit_events WHERE agent_id=:agent_id"
                ),
                {"agent_id": agent_id},
            ).scalar_one()
            evidence = connection.execute(
                text(
                    "SELECT COUNT(*) FROM classification_evidence WHERE site_id='site-agent-test' AND asset_id='fictional-host'"
                )
            ).scalar_one()
            components = connection.execute(
                text(
                    "SELECT COUNT(*) FROM asset_components WHERE site_id='site-agent-test' AND asset_id='fictional-host'"
                )
            ).scalar_one()
        self.assertEqual(batch["reevaluation_state"], "completed")
        self.assertIsNotNone(batch["collection_id"])
        self.assertGreaterEqual(history, 6)
        self.assertGreaterEqual(evidence, 1)
        self.assertEqual(components, 1)


if __name__ == "__main__":
    unittest.main()
