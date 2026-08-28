from __future__ import annotations

import os
import re
import unittest
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.pool import NullPool

from app.schema_migrations import migrate_database_schema
from app.temporal_contracts import TEMPORAL_METRICS
from app.temporal_projection import TemporalProjectionService
from app.temporal_store import SqlTemporalStore


ENABLED = os.getenv("OPENASSETWATCH_TEMPORAL_POSTGRES_TEST") == "1"
DATABASE_NAME = re.compile(r"^openassetwatch_temporal_test_[0-9a-f]{16}$")
UTC = timezone.utc
START = datetime(2026, 8, 24, tzinfo=UTC)
END = datetime(2026, 8, 26, tzinfo=UTC)
GENERATED_AT = datetime(2026, 8, 27, 12, tzinfo=UTC)


@unittest.skipUnless(
    ENABLED,
    "requires an explicitly isolated disposable PostgreSQL server",
)
class TemporalPostgresTests(unittest.TestCase):
    admin_engine: Engine
    database_engine: Engine
    database_name: str

    def setUp(self) -> None:
        parsed = make_url(os.environ["DATABASE_URL"])
        self.database_name = f"openassetwatch_temporal_test_{uuid4().hex[:16]}"
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
        self._seed_authoritative_history()

    def tearDown(self) -> None:
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

    def _seed_authoritative_history(self) -> None:
        with self.database_engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO sites (site_id, name)
                    VALUES
                        ('site-temporal-a', 'Temporal Site A'),
                        ('site-temporal-b', 'Temporal Site B')
                    """
                )
            )
            connection.execute(
                text(
                    """
                    INSERT INTO canonical_ingestion_sources (
                        source_id, site_id, source_identity, source_type,
                        adapter_type, authentication_class, source_authority,
                        trust_rank, compatibility_status, first_seen_at, last_seen_at
                    ) VALUES
                        (
                            'src_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                            'site-temporal-a', 'agent-temporal-a', 'endpoint-agent',
                            'endpoint-agent', 'bound-credential',
                            'authenticated-endpoint', 90, 'canonical',
                            :observed_at, :observed_at
                        ),
                        (
                            'src_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                            'site-temporal-b', 'agent-temporal-b', 'endpoint-agent',
                            'endpoint-agent', 'bound-credential',
                            'authenticated-endpoint', 90, 'canonical',
                            :observed_at, :observed_at
                        )
                    """
                ),
                {"observed_at": START.replace(hour=8)},
            )
            connection.execute(
                text(
                    """
                    INSERT INTO canonical_inventory_collections (
                        canonical_collection_id, site_id, source_id, adapter_type,
                        route_name, idempotency_key, payload_sha256, schema_version,
                        observed_at, ingested_at, inventory_mode,
                        observed_asset_count, canonical_asset_count,
                        evidence_count, component_count, evaluation_state,
                        replay_count
                    ) VALUES
                        (
                            'col_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                            'site-temporal-a',
                            'src_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                            'endpoint-agent', '/api/v1/agent/inventory',
                            'temporal-a-collection', :payload_a,
                            'oaw.endpoint-inventory.v1', :observed_at,
                            :late_ingested_at, 'complete', 3, 3, 3, 0,
                            'completed', 12
                        ),
                        (
                            'col_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                            'site-temporal-b',
                            'src_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                            'endpoint-agent', '/api/v1/agent/inventory',
                            'temporal-b-collection', :payload_b,
                            'oaw.endpoint-inventory.v1', :observed_at,
                            :observed_at, 'complete', 7, 7, 7, 0,
                            'completed', 0
                        )
                    """
                ),
                {
                    "payload_a": "a" * 64,
                    "payload_b": "b" * 64,
                    "observed_at": START.replace(hour=8),
                    "late_ingested_at": END.replace(hour=2),
                },
            )
            connection.execute(
                text(
                    """
                    INSERT INTO control_tower_assets (
                        asset_key, asset_id, site_id, hostname, first_seen_at,
                        last_seen_at, evidence_count, metadata_json
                    ) VALUES
                        (
                            'site-temporal-a:asset-a', 'asset-a',
                            'site-temporal-a', 'asset-a.example.test',
                            :observed_at, :observed_at, 1, '{}'::jsonb
                        ),
                        (
                            'site-temporal-b:asset-b', 'asset-b',
                            'site-temporal-b', 'asset-b.example.test',
                            :observed_at, :observed_at, 1, '{}'::jsonb
                        )
                    """
                ),
                {"observed_at": START.replace(hour=8)},
            )
            connection.execute(
                text(
                    """
                    INSERT INTO agent_enrollments (
                        agent_id, site_id, display_name, agent_type,
                        updated_at, identity_status
                    ) VALUES
                        (
                            'agent-temporal-a', 'site-temporal-a',
                            'Temporal Agent A', 'endpoint-agent',
                            :observed_at, 'active'
                        ),
                        (
                            'agent-temporal-b', 'site-temporal-b',
                            'Temporal Agent B', 'endpoint-agent',
                            :observed_at, 'active'
                        )
                    """
                ),
                {"observed_at": START.replace(hour=8)},
            )
            connection.execute(
                text(
                    """
                    INSERT INTO agent_checkins (
                        site_id, agent_id, checked_in_at, received_at, payload_json
                    ) VALUES
                        (
                            'site-temporal-a', 'agent-temporal-a',
                            :observed_at, :observed_at, '{}'::jsonb
                        ),
                        (
                            'site-temporal-a', 'agent-temporal-a',
                            :second_checkin, :second_checkin, '{}'::jsonb
                        ),
                        (
                            'site-temporal-b', 'agent-temporal-b',
                            :observed_at, :observed_at, '{}'::jsonb
                        )
                    """
                ),
                {
                    "observed_at": START.replace(hour=8),
                    "second_checkin": START.replace(hour=18),
                },
            )
            connection.execute(
                text(
                    """
                    INSERT INTO finding_evaluation_runs (
                        run_id, trigger_type, scope_site_id, ruleset_version,
                        status, started_at, completed_at, data_as_of
                    ) VALUES
                        (
                            'finding-run-temporal-a', 'manual', 'site-temporal-a',
                            'temporal-test-v1', 'completed', :started_at,
                            :completed_at, :completed_at
                        ),
                        (
                            'finding-run-temporal-b', 'manual', 'site-temporal-b',
                            'temporal-test-v1', 'completed', :started_at,
                            :completed_at, :completed_at
                        )
                    """
                ),
                {
                    "started_at": START.replace(hour=7),
                    "completed_at": START.replace(hour=9),
                },
            )
            connection.execute(
                text(
                    """
                    INSERT INTO findings (
                        finding_id, dedupe_key, rule_id, rule_version,
                        engine_version, category, subject_type, site_id, title,
                        description, recommendation, severity, confidence, status,
                        evidence_freshness, first_seen_at, last_seen_at,
                        evaluated_at, last_evaluation_run_id
                    ) VALUES
                        (
                            'finding-temporal-a', 'finding-dedupe-temporal-a',
                            'temporal-test', 1, 'oaw.findings.v1', 'inventory',
                            'site', 'site-temporal-a', 'Temporal A',
                            'Temporal test finding A', 'No action', 'low', 1.0,
                            'active', 'fresh', :observed_at, :observed_at,
                            :observed_at, 'finding-run-temporal-a'
                        ),
                        (
                            'finding-temporal-b', 'finding-dedupe-temporal-b',
                            'temporal-test', 1, 'oaw.findings.v1', 'inventory',
                            'site', 'site-temporal-b', 'Temporal B',
                            'Temporal test finding B', 'No action', 'low', 1.0,
                            'active', 'fresh', :observed_at, :observed_at,
                            :observed_at, 'finding-run-temporal-b'
                        )
                    """
                ),
                {"observed_at": START.replace(hour=8)},
            )
            connection.execute(
                text(
                    """
                    INSERT INTO vulnerability_evaluation_runs (
                        run_id, trigger_type, scope_site_id, engine_version,
                        status, started_at, completed_at
                    ) VALUES
                        (
                            'vulnerability-run-temporal-a', 'manual',
                            'site-temporal-a', 'oaw.vulnerability.v1',
                            'completed', :started_at, :completed_at
                        ),
                        (
                            'vulnerability-run-temporal-b', 'manual',
                            'site-temporal-b', 'oaw.vulnerability.v1',
                            'completed', :started_at, :completed_at
                        )
                    """
                ),
                {
                    "started_at": START.replace(hour=7),
                    "completed_at": START.replace(hour=9),
                },
            )

    def _service(self) -> TemporalProjectionService:
        store = SqlTemporalStore()
        store._schema_ready = True
        store._engine = lambda: self.database_engine
        return TemporalProjectionService(store=store)

    def _series(self, metric_key: str, site_id: str = "site-temporal-a"):
        return self._service().series(
            metric_key=metric_key,
            site_id=site_id,
            start=START,
            end=END,
            generated_at=GENERATED_AT,
        )

    def test_all_registered_queries_are_site_scoped_and_quality_aware(self) -> None:
        expected = {
            "site.assets.new.count": 1,
            "site.collectors.active.count": 1,
            "site.findings.new.count": 1,
            "site.vulnerabilities.new.count": 0,
            "site.inventory.collections.count": 1,
            "site.inventory.asset_observations.count": 3,
        }
        self.assertEqual(
            {metric.metric_key for metric in TEMPORAL_METRICS},
            set(expected),
        )

        for metric_key, value in expected.items():
            with self.subTest(metric_key=metric_key):
                response = self._series(metric_key)
                self.assertEqual(response.bucket_count, 2)
                self.assertEqual(response.signals[0].value, value)
                self.assertTrue(response.signals[0].complete)
                self.assertEqual(response.signals[1].data_quality, "missing")
                self.assertIsNone(response.signals[1].value)

        vulnerability = self._series("site.vulnerabilities.new.count").signals[0]
        self.assertEqual(vulnerability.value, 0)
        self.assertEqual(vulnerability.data_quality, "observed")
        collection = self._series("site.inventory.collections.count").signals[0]
        self.assertEqual(collection.backfill_state, "late-arriving")
        self.assertEqual(collection.evidence_count, 1)

        site_b = self._series(
            "site.inventory.asset_observations.count",
            "site-temporal-b",
        )
        self.assertEqual(site_b.signals[0].value, 7)
        self.assertEqual(site_b.signals[0].evidence_count, 1)

    def test_projection_is_stable_across_fresh_service_instances(self) -> None:
        first = self._series("site.inventory.collections.count")
        second = self._series("site.inventory.collections.count")

        self.assertEqual(first, second)
        self.assertEqual(first.signals[0].value, 1)
        self.assertEqual(first.signals[0].evidence_count, 1)
        self.assertEqual(first.signals[0].signal_id, second.signals[0].signal_id)

    def test_as_of_projection_excludes_evidence_received_at_or_after_cutoff(self) -> None:
        site_a = self._service().series(
            metric_key="site.inventory.collections.count",
            site_id="site-temporal-a",
            start=START,
            end=END,
            generated_at=END,
            knowledge_cutoff=END,
        )
        site_b = self._service().series(
            metric_key="site.inventory.collections.count",
            site_id="site-temporal-b",
            start=START,
            end=END,
            generated_at=END,
            knowledge_cutoff=END,
        )

        self.assertIsNone(site_a.signals[0].value)
        self.assertEqual(site_a.signals[0].data_quality, "missing")
        self.assertEqual(site_b.signals[0].value, 1)
        self.assertEqual(site_b.signals[0].data_quality, "observed")


if __name__ == "__main__":
    unittest.main()
