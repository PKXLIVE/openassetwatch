from __future__ import annotations

import os
import re
import threading
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.pool import NullPool

from app import main
from app.canonical_ingestion import (
    CanonicalIngestionRejected,
    CanonicalReplayConflict,
    endpoint_envelope,
    ingest,
    legacy_collector_envelope,
    sensor_envelope,
    transitional_envelope,
)
from app.endpoint_agent_contracts import EndpointInventoryRequest
from app.hub_contracts import ObservationBatchRequest
from app.main import CollectorInventoryRequest
from app.schema_migrations import migrate_database_schema


ENABLED = os.getenv("OPENASSETWATCH_CANONICAL_INGESTION_POSTGRES_TEST") == "1"
DATABASE_NAME = re.compile(r"^openassetwatch_canonical_test_[0-9a-f]{16}$")


@unittest.skipUnless(
    ENABLED,
    "requires an explicitly isolated disposable PostgreSQL server",
)
class CanonicalIngestionPostgresTests(unittest.TestCase):
    admin_engine: Engine
    database_engine: Engine
    database_name: str

    def setUp(self) -> None:
        parsed = make_url(os.environ["DATABASE_URL"])
        self.database_name = f"openassetwatch_canonical_test_{uuid4().hex[:16]}"
        self.assertRegex(self.database_name, DATABASE_NAME)
        self.admin_engine = create_engine(
            parsed.set(database="postgres"),
            isolation_level="AUTOCOMMIT",
            poolclass=NullPool,
        )
        with self.admin_engine.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{self.database_name}"')
        self.database_engine = create_engine(
            parsed.set(database=self.database_name),
            poolclass=NullPool,
        )
        migration = migrate_database_schema(self.database_engine)
        self.assertEqual(migration.current_version, 3)
        self.patchers = [
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
                    WHERE datname = :database_name
                      AND pid <> pg_backend_pid()
                    """
                ),
                {"database_name": self.database_name},
            )
            connection.exec_driver_sql(f'DROP DATABASE "{self.database_name}"')
        self.admin_engine.dispose()

    def _provision_bound_sources(self, now: datetime) -> tuple[SimpleNamespace, SimpleNamespace]:
        endpoint = SimpleNamespace(
            site_id="site-canonical-a",
            agent_id="agent_" + "1" * 32,
            deployment_id="deployment-fictional-a",
            credential_id="acred_" + "2" * 32,
        )
        sensor = SimpleNamespace(
            mode="bound-sensor",
            site_id="site-canonical-a",
            sensor_id="sensor-fictional-a",
            credential_id="scred_" + "3" * 32,
        )
        with self.database_engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO sites (site_id, name)
                    VALUES
                        ('site-canonical-a', 'Canonical Site A'),
                        ('site-canonical-b', 'Canonical Site B')
                    """
                )
            )
            connection.execute(
                text(
                    """
                    INSERT INTO agent_enrollments (
                        agent_id, site_id, display_name, agent_type,
                        updated_at, identity_status
                    ) VALUES
                        (:agent_id, :site_id, 'Fictional Endpoint',
                         'endpoint-agent', :now, 'active'),
                        (:sensor_id, :site_id, 'Fictional Sensor',
                         'network-sensor', :now, 'active')
                    """
                ),
                {
                    "agent_id": endpoint.agent_id,
                    "sensor_id": sensor.sensor_id,
                    "site_id": endpoint.site_id,
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
                    "credential_id": endpoint.credential_id,
                    "lookup_id": "4" * 32,
                    "digest": "5" * 64,
                    "agent_id": endpoint.agent_id,
                    "site_id": endpoint.site_id,
                    "deployment_id": endpoint.deployment_id,
                },
            )
            connection.execute(
                text(
                    """
                    INSERT INTO sensor_credentials (
                        credential_id, sensor_id, site_id, sensor_type,
                        token_lookup_id, credential_digest, status
                    ) VALUES (
                        :credential_id, :sensor_id, :site_id,
                        'passive-network-sensor', :lookup_id, :digest, 'active'
                    )
                    """
                ),
                {
                    "credential_id": sensor.credential_id,
                    "sensor_id": sensor.sensor_id,
                    "site_id": sensor.site_id,
                    "lookup_id": "6" * 32,
                    "digest": "7" * 64,
                },
            )
        return endpoint, sensor

    @staticmethod
    def _endpoint_payload(
        *,
        now: datetime,
        batch_id: str,
        asset_id: str,
        hostname: str,
    ) -> EndpointInventoryRequest:
        return EndpointInventoryRequest.model_validate(
            {
                "schema_version": "oaw.endpoint-inventory.v1",
                "inventory_batch_id": batch_id,
                "observed_at": now.isoformat(),
                "inventory_mode": "complete",
                "agent_version": "0.1.0",
                "platform": "linux",
                "architecture": "amd64",
                "assets": [
                    {
                        "asset_id": asset_id,
                        "hostname": hostname,
                        "os": "FictionalOS 1",
                        "platform": "linux",
                        "interfaces": [
                            {
                                "name": "eth0",
                                "mac_address": "02:00:5e:10:00:01",
                                "ip_addresses": [
                                    {"address": "192.0.2.10", "family": "ipv4"}
                                ],
                            }
                        ],
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

    def test_authenticated_first_authority_replaces_stale_legacy_projection(self) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        endpoint_context, _ = self._provision_bound_sources(now)
        with self.database_engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO control_tower_assets (
                        asset_key, asset_id, site_id, hostname, first_seen_at,
                        last_seen_at, observed_at, evidence_count, metadata_json
                    ) VALUES (
                        'site-canonical-a:historical-asset',
                        'historical-asset', 'site-canonical-a',
                        'stale-legacy.example.test', :first_seen_at,
                        :last_seen_at, :last_seen_at, 99, '{}'::jsonb
                    )
                    """
                ),
                {
                    "first_seen_at": now - timedelta(days=30),
                    "last_seen_at": now + timedelta(days=2),
                },
            )

        acknowledgement = ingest(
            endpoint_envelope(
                payload=self._endpoint_payload(
                    now=now,
                    batch_id="canonical-authority-adoption-0001",
                    asset_id="historical-asset",
                    hostname="authenticated-authority.example.test",
                ),
                context=endpoint_context,
                received_at=now,
            )
        )

        self.assertEqual(acknowledgement.canonical_asset_ids, ("historical-asset",))
        with self.database_engine.connect() as connection:
            authority = connection.execute(
                text(
                    """
                    SELECT a.hostname, a.evidence_count, c.source_authority,
                           c.trust_rank, c.canonical_collection_id
                    FROM control_tower_assets a
                    JOIN canonical_asset_authority c
                      ON c.asset_key = a.asset_key
                    WHERE a.asset_key='site-canonical-a:historical-asset'
                    """
                )
            ).mappings().one()
        self.assertEqual(authority["hostname"], "authenticated-authority.example.test")
        self.assertNotEqual(int(authority["evidence_count"]), 99)
        self.assertEqual(authority["source_authority"], "authenticated-endpoint")
        self.assertEqual(int(authority["trust_rank"]), 90)
        self.assertEqual(
            authority["canonical_collection_id"],
            acknowledgement.canonical_collection_id,
        )

    def test_lower_trust_component_collision_cannot_reach_authoritative_stores(self) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        endpoint_context, _ = self._provision_bound_sources(now)
        endpoint_ack = ingest(
            endpoint_envelope(
                payload=self._endpoint_payload(
                    now=now,
                    batch_id="canonical-component-authority-0001",
                    asset_id="component-authority-asset",
                    hostname="component-authority.example.test",
                ),
                context=endpoint_context,
                received_at=now,
            )
        )
        main._run_canonical_inventory_evaluation(
            canonical_collection_id=endpoint_ack.canonical_collection_id,
        )
        lower_trust = ingest(
            transitional_envelope(
                payload={
                    "site_id": "site-canonical-a",
                    "observation_batch_id": "canonical-component-poison-0001",
                    "observed_at": (now + timedelta(days=1)).isoformat(),
                    "assets": [
                        {
                            "asset_id": "component-authority-asset",
                            "hostname": "lower-trust.example.test",
                            "components": [
                                {
                                    "component_type": "application",
                                    "ecosystem": "pypi",
                                    "name": "lower-trust-poison",
                                    "version": "99.0.0",
                                    "purl": "pkg:pypi/lower-trust-poison@99.0.0",
                                }
                            ],
                        }
                    ],
                },
                received_at=now + timedelta(days=1),
            )
        )

        self.assertEqual(lower_trust.canonical_asset_ids, ())
        self.assertEqual(lower_trust.evaluation_state, "not-required")
        main._run_canonical_inventory_evaluation(
            canonical_collection_id=lower_trust.canonical_collection_id,
        )
        with self.database_engine.connect() as connection:
            poison_count = int(
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM asset_components "
                        "WHERE site_id='site-canonical-a' "
                        "AND asset_id='component-authority-asset' "
                        "AND name='lower-trust-poison'"
                    )
                ).scalar_one()
            )
            authority = connection.execute(
                text(
                    """
                    SELECT source_authority
                    FROM canonical_asset_authority
                    WHERE asset_key='site-canonical-a:component-authority-asset'
                    """
                )
            ).scalar_one()
        self.assertEqual(poison_count, 0)
        self.assertEqual(authority, "authenticated-endpoint")

    def test_untrusted_site_must_be_server_configured(self) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        envelope = transitional_envelope(
            payload={
                "site_id": "payload-selected-site",
                "observation_batch_id": "canonical-unknown-site-0001",
                "assets": [{"asset_id": "untrusted-asset"}],
            },
            received_at=now,
        )

        with self.assertRaisesRegex(
            CanonicalIngestionRejected,
            "site is not configured",
        ):
            ingest(envelope)
        with self.database_engine.connect() as connection:
            site_count = int(
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM sites "
                        "WHERE site_id='payload-selected-site'"
                    )
                ).scalar_one()
            )
        self.assertEqual(site_count, 0)

    def test_identical_replay_audit_is_saturating_and_bounded(self) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        self._provision_bound_sources(now)
        envelope = transitional_envelope(
            payload={
                "site_id": "site-canonical-a",
                "observation_batch_id": "canonical-bounded-replay-0001",
                "assets": [{"asset_id": "bounded-replay-asset"}],
            },
            received_at=now,
        )
        acknowledgement = ingest(envelope)
        for _ in range(24):
            replay = ingest(envelope)
            self.assertEqual(replay.status, "duplicate")

        with self.database_engine.connect() as connection:
            replay_count = int(
                connection.execute(
                    text(
                        "SELECT replay_count FROM canonical_inventory_collections "
                        "WHERE canonical_collection_id=:collection_id"
                    ),
                    {"collection_id": acknowledgement.canonical_collection_id},
                ).scalar_one()
            )
            replay_events = int(
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM ingestion_compatibility_events "
                        "WHERE canonical_collection_id=:collection_id "
                        "AND event_type='replay'"
                    ),
                    {"collection_id": acknowledgement.canonical_collection_id},
                ).scalar_one()
            )
        self.assertEqual(replay_count, 16)
        self.assertEqual(replay_events, 16)

    def test_retryable_evaluation_is_durably_requeued_and_completed(self) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        endpoint_context, _ = self._provision_bound_sources(now)
        acknowledgement = ingest(
            endpoint_envelope(
                payload=self._endpoint_payload(
                    now=now,
                    batch_id="canonical-retry-0001",
                    asset_id="retry-asset",
                    hostname="retry.example.test",
                ),
                context=endpoint_context,
                received_at=now,
            )
        )
        with patch.object(
            main.database_module,
            "_persist_classification_evidence_best_effort",
            return_value=False,
        ):
            main._run_canonical_inventory_evaluation(
                canonical_collection_id=acknowledgement.canonical_collection_id,
            )
        with self.database_engine.connect() as connection:
            failed_state = connection.execute(
                text(
                    "SELECT evaluation_state FROM canonical_inventory_collections "
                    "WHERE canonical_collection_id=:collection_id"
                ),
                {"collection_id": acknowledgement.canonical_collection_id},
            ).scalar_one()
        self.assertEqual(failed_state, "retryable-failure")
        self.assertTrue(
            main.requeue_canonical_evaluation(
                canonical_collection_id=acknowledgement.canonical_collection_id
            )
        )
        with (
            patch.object(
                main.database_module,
                "_persist_classification_evidence_best_effort",
                return_value=True,
            ),
            patch.object(
                main.database_module,
                "_persist_component_inventory_best_effort",
                return_value=True,
            ),
            patch.object(main, "evaluate_classifications"),
            patch.object(main, "evaluate_vulnerabilities"),
            patch.object(main, "evaluate_findings"),
        ):
            main._run_canonical_inventory_evaluation(
                canonical_collection_id=acknowledgement.canonical_collection_id,
            )
        with self.database_engine.connect() as connection:
            final_state = connection.execute(
                text(
                    "SELECT evaluation_state FROM canonical_inventory_collections "
                    "WHERE canonical_collection_id=:collection_id"
                ),
                {"collection_id": acknowledgement.canonical_collection_id},
            ).scalar_one()
        self.assertEqual(final_state, "completed")

    def test_all_adapters_share_one_authority_and_replay_model(self) -> None:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        endpoint_context, sensor_context = self._provision_bound_sources(now)
        endpoint_payload = self._endpoint_payload(
            now=now,
            batch_id="canonical-endpoint-batch-0001",
            asset_id="shared-asset",
            hostname="endpoint-authority.example.test",
        )
        endpoint = endpoint_envelope(
            payload=endpoint_payload,
            context=endpoint_context,
            received_at=now,
        )
        endpoint_ack = ingest(endpoint)
        self.assertEqual(endpoint_ack.status, "accepted")
        self.assertEqual(endpoint_ack.evaluation_state, "queued")

        sensor_payload = ObservationBatchRequest.model_validate(
            {
                "schema_version": "oaw.observation-batch.v1",
                "observation_batch_id": "canonical-sensor-batch-0001",
                "site_id": "site-canonical-a",
                "sensor_id": "sensor-fictional-a",
                "sensor_name": "Fictional Sensor",
                "sensor_type": "passive-network-sensor",
                "observed_at": (now + timedelta(seconds=1)).isoformat(),
                "observation_source": "passive-network",
                "assets": [
                    {
                        "asset_id": "shared-asset",
                        "hostname": "passive-claim.example.test",
                    }
                ],
            }
        )
        sensor_ack = ingest(
            sensor_envelope(
                payload=sensor_payload,
                context=sensor_context,
                received_at=now + timedelta(seconds=1),
            )
        )
        self.assertEqual(sensor_ack.source_authority, "authenticated-passive-sensor")

        transitional_ack = ingest(
            transitional_envelope(
                payload={
                    "site_id": "site-canonical-a",
                    "observation_batch_id": "canonical-transitional-batch-0001",
                    "observed_at": (now + timedelta(days=1)).isoformat(),
                    "source_authority": "authenticated-endpoint",
                    "assets": [
                        {
                            "asset_id": "shared-asset",
                            "hostname": "untrusted-claim.example.test",
                            "trust_rank": 100,
                        }
                    ],
                },
                received_at=now + timedelta(days=1),
            )
        )
        self.assertEqual(transitional_ack.source_authority, "untrusted-transitional")

        collector_ack = ingest(
            legacy_collector_envelope(
                payload=CollectorInventoryRequest.model_validate(
                    {
                        "collector_id": "fictional-collector",
                        "mode": "device",
                        "collected_at": (now + timedelta(seconds=2)).isoformat(),
                        "deployment": {"site_id": "site-canonical-a"},
                        "device": {
                            "asset_id": "shared-asset",
                            "hostname": "collector-claim.example.test",
                        },
                    }
                ),
                received_at=now + timedelta(seconds=2),
                authentication_class="legacy-shared",
            )
        )
        self.assertEqual(collector_ack.source_authority, "legacy-collector")

        with self.database_engine.connect() as connection:
            authority = connection.execute(
                text(
                    """
                    SELECT cta.hostname, caa.source_authority, caa.trust_rank,
                           caa.canonical_collection_id
                    FROM control_tower_assets cta
                    JOIN canonical_asset_authority caa
                      ON caa.asset_key = cta.asset_key
                    WHERE cta.site_id = 'site-canonical-a'
                      AND cta.asset_id = 'shared-asset'
                    """
                )
            ).mappings().one()
            source_count = int(
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM canonical_ingestion_sources "
                        "WHERE site_id='site-canonical-a'"
                    )
                ).scalar_one()
            )
            collection_count = int(
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM canonical_inventory_collections "
                        "WHERE site_id='site-canonical-a'"
                    )
                ).scalar_one()
            )
            mapped_legacy = int(
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM legacy_submission_mappings "
                        "WHERE canonical_collection_id=:collection_id"
                    ),
                    {"collection_id": collector_ack.canonical_collection_id},
                ).scalar_one()
            )
        self.assertEqual(authority["hostname"], "endpoint-authority.example.test")
        self.assertEqual(authority["source_authority"], "authenticated-endpoint")
        self.assertEqual(authority["trust_rank"], 90)
        self.assertEqual(authority["canonical_collection_id"], endpoint_ack.canonical_collection_id)
        self.assertEqual(source_count, 4)
        self.assertEqual(collection_count, 4)
        self.assertEqual(mapped_legacy, 1)

        main._run_canonical_inventory_evaluation(
            canonical_collection_id=endpoint_ack.canonical_collection_id,
        )
        with self.database_engine.connect() as connection:
            before_replay = {
                table: int(
                    connection.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar_one()
                )
                for table in (
                    "control_tower_assets",
                    "asset_components",
                    "vulnerability_matches",
                    "findings",
                    "asset_risk_scores",
                )
            }
        replay = ingest(endpoint)
        self.assertEqual(replay.status, "duplicate")
        self.assertEqual(replay.canonical_collection_id, endpoint_ack.canonical_collection_id)
        self.assertEqual(replay.endpoint_storage_id, endpoint_ack.endpoint_storage_id)
        self.assertEqual(replay.evaluation_state, "completed")
        with self.database_engine.connect() as connection:
            after_replay = {
                table: int(
                    connection.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar_one()
                )
                for table in before_replay
            }
        self.assertEqual(after_replay, before_replay)

        conflict = endpoint_envelope(
            payload=self._endpoint_payload(
                now=now,
                batch_id="canonical-endpoint-batch-0001",
                asset_id="shared-asset",
                hostname="conflicting-replay.example.test",
            ),
            context=endpoint_context,
            received_at=now + timedelta(seconds=3),
        )
        with self.assertRaises(CanonicalReplayConflict):
            ingest(conflict)

        site_b = ingest(
            transitional_envelope(
                payload={
                    "site_id": "site-canonical-b",
                    "observation_batch_id": "canonical-site-b-batch-0001",
                    "assets": [
                        {
                            "asset_id": "shared-asset",
                            "hostname": "site-b.example.test",
                        }
                    ],
                },
                received_at=now,
            )
        )
        self.assertEqual(site_b.status, "accepted")
        with self.database_engine.connect() as connection:
            site_rows = int(
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM control_tower_assets "
                        "WHERE asset_id='shared-asset'"
                    )
                ).scalar_one()
            )
        self.assertEqual(site_rows, 2)

        race_endpoint = endpoint_envelope(
            payload=self._endpoint_payload(
                now=now,
                batch_id="canonical-endpoint-race-0001",
                asset_id="race-asset",
                hostname="race-endpoint.example.test",
            ),
            context=endpoint_context,
            received_at=now,
        )
        race_transitional = transitional_envelope(
            payload={
                "site_id": "site-canonical-a",
                "observation_batch_id": "canonical-transitional-race-0001",
                "observed_at": (now + timedelta(days=2)).isoformat(),
                "assets": [
                    {
                        "asset_id": "race-asset",
                        "hostname": "race-untrusted.example.test",
                    }
                ],
            },
            received_at=now + timedelta(days=2),
        )
        barrier = threading.Barrier(2)
        results: list[object] = []

        def submit(envelope: object) -> None:
            barrier.wait(timeout=5)
            try:
                results.append(ingest(envelope))  # type: ignore[arg-type]
            except Exception as exc:  # surfaced below.
                results.append(exc)

        workers = [
            threading.Thread(target=submit, args=(race_endpoint,)),
            threading.Thread(target=submit, args=(race_transitional,)),
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=15)
        self.assertFalse(any(worker.is_alive() for worker in workers))
        self.assertEqual(len(results), 2)
        self.assertFalse(any(isinstance(result, Exception) for result in results))
        with self.database_engine.connect() as connection:
            race_authority = connection.execute(
                text(
                    """
                    SELECT cta.hostname, caa.source_authority, caa.trust_rank
                    FROM control_tower_assets cta
                    JOIN canonical_asset_authority caa
                      ON caa.asset_key=cta.asset_key
                    WHERE cta.site_id='site-canonical-a'
                      AND cta.asset_id='race-asset'
                    """
                )
            ).mappings().one()
            duplicate_authority = int(
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM canonical_asset_authority "
                        "WHERE site_id='site-canonical-a' AND asset_id='race-asset'"
                    )
                ).scalar_one()
            )
        self.assertEqual(race_authority["hostname"], "race-endpoint.example.test")
        self.assertEqual(race_authority["source_authority"], "authenticated-endpoint")
        self.assertEqual(race_authority["trust_rank"], 90)
        self.assertEqual(duplicate_authority, 1)

        # A backend pool restart must not change canonical authority,
        # acknowledgement, evaluation, or compatibility history.
        self.database_engine.dispose()
        with self.database_engine.connect() as connection:
            persisted = connection.execute(
                text(
                    """
                    SELECT c.evaluation_state, a.source_authority,
                           a.canonical_collection_id,
                           COUNT(m.mapping_id) OVER () AS legacy_mapping_count
                    FROM canonical_inventory_collections c
                    JOIN canonical_asset_authority a
                      ON a.canonical_collection_id=c.canonical_collection_id
                    LEFT JOIN legacy_submission_mappings m ON TRUE
                    WHERE c.canonical_collection_id=:collection_id
                    LIMIT 1
                    """
                ),
                {"collection_id": endpoint_ack.canonical_collection_id},
            ).mappings().one()
        self.assertEqual(persisted["evaluation_state"], "completed")
        self.assertEqual(persisted["source_authority"], "authenticated-endpoint")
        self.assertEqual(
            persisted["canonical_collection_id"],
            endpoint_ack.canonical_collection_id,
        )
        self.assertGreaterEqual(int(persisted["legacy_mapping_count"]), 1)


if __name__ == "__main__":
    unittest.main()
