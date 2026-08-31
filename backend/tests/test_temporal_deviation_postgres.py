from __future__ import annotations

import hashlib
import os
import re
import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.pool import NullPool

from app.schema_migrations import migrate_database_schema
from app.temporal_deviations import TemporalDeviationService
from app.temporal_store import SqlTemporalStore


ENABLED = os.getenv("OPENASSETWATCH_TEMPORAL_POSTGRES_TEST") == "1"
DATABASE_NAME = re.compile(
    r"^openassetwatch_temporal_deviation_test_[0-9a-f]{16}$"
)
UTC = timezone.utc
TARGET = datetime(2026, 8, 28, tzinfo=UTC)
CALCULATION_TIME = TARGET + timedelta(days=2, hours=12)
METRIC_KEY = "site.inventory.collections.count"


def stable_id(prefix: str, value: str, length: int = 32) -> str:
    return prefix + hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]


@unittest.skipUnless(
    ENABLED,
    "requires an explicitly isolated disposable PostgreSQL server",
)
class TemporalDeviationPostgresTests(unittest.TestCase):
    admin_engine: Engine
    database_engine: Engine
    database_name: str

    def setUp(self) -> None:
        parsed = make_url(os.environ["DATABASE_URL"])
        self.database_name = (
            f"openassetwatch_temporal_deviation_test_{uuid4().hex[:16]}"
        )
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
        self.assertEqual(migration.current_version, 4)
        self._seed_history()

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

    def _seed_history(self) -> None:
        sources = {
            "site-deviation-a": "src_" + "a" * 32,
            "site-deviation-b": "src_" + "b" * 32,
        }
        first_observed = TARGET - timedelta(days=57) + timedelta(hours=12)
        with self.database_engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO sites (site_id, name)
                    VALUES
                        ('site-deviation-a', 'Deviation Site A'),
                        ('site-deviation-b', 'Deviation Site B')
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
                    ) VALUES (
                        :source_id, :site_id, :source_identity, 'endpoint-agent',
                        'endpoint-agent', 'bound-credential',
                        'authenticated-endpoint', 90, 'canonical',
                        :first_seen_at, :last_seen_at
                    )
                    """
                ),
                [
                    {
                        "source_id": source_id,
                        "site_id": site_id,
                        "source_identity": f"agent-{site_id}",
                        "first_seen_at": first_observed,
                        "last_seen_at": TARGET + timedelta(days=1, hours=12),
                    }
                    for site_id, source_id in sources.items()
                ],
            )

            rows: list[dict[str, object]] = []
            first_day = TARGET - timedelta(days=57)
            last_day = TARGET + timedelta(days=1)
            day = first_day
            while day <= last_day:
                for site_id, source_id in sources.items():
                    if site_id == "site-deviation-a" and day in {
                        TARGET - timedelta(days=1),
                        TARGET,
                    }:
                        count = 2
                    elif site_id == "site-deviation-a" and day == TARGET + timedelta(days=1):
                        count = 3
                    else:
                        count = 1
                    for ordinal in range(count):
                        key = f"{site_id}|{day.isoformat()}|{ordinal}"
                        ingested_at = day + timedelta(hours=13, minutes=ordinal)
                        if day == TARGET and ordinal == count - 1:
                            ingested_at = day + timedelta(days=1) - timedelta(seconds=1)
                        rows.append(
                            {
                                "canonical_collection_id": stable_id("col_", key),
                                "site_id": site_id,
                                "source_id": source_id,
                                "idempotency_key": stable_id("temporal-", key, 40),
                                "payload_sha256": hashlib.sha256(
                                    f"payload|{key}".encode("utf-8")
                                ).hexdigest(),
                                "observed_at": day + timedelta(hours=12, minutes=ordinal),
                                "ingested_at": ingested_at,
                            }
                        )
                day += timedelta(days=1)

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
                    ) VALUES (
                        :canonical_collection_id, :site_id, :source_id,
                        'endpoint-agent', '/api/v1/agent/inventory',
                        :idempotency_key, :payload_sha256,
                        'oaw.endpoint-inventory.v1', :observed_at, :ingested_at,
                        'complete', 1, 1, 1, 0, 'completed', 0
                    )
                    """
                ),
                rows,
            )

    def _service(self) -> TemporalDeviationService:
        store = SqlTemporalStore()
        store._schema_ready = True
        store._engine = lambda: self.database_engine
        return TemporalDeviationService.from_projection_store(store=store)

    def _assessment(
        self,
        *,
        site_id: str = "site-deviation-a",
        target: datetime = TARGET,
    ):
        return self._service().assessment(
            metric_key=METRIC_KEY,
            site_id=site_id,
            target_start=target,
            generated_at=CALCULATION_TIME,
        )

    def _authority_counts(self) -> dict[str, int]:
        tables = (
            "findings",
            "asset_risk_scores",
            "site_risk_scores",
            "risk_factors",
        )
        with self.database_engine.connect() as connection:
            return {
                table: int(
                    connection.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar_one()
                )
                for table in tables
            }

    def _insert_cutoff_excluded_target_evidence(self) -> None:
        target_end = TARGET + timedelta(days=1)
        rows = []
        for label, ingested_at in (
            ("exact", target_end),
            ("after", target_end + timedelta(seconds=1)),
        ):
            key = f"site-deviation-a|target-cutoff-{label}"
            rows.append(
                {
                    "canonical_collection_id": stable_id("col_", key),
                    "site_id": "site-deviation-a",
                    "source_id": "src_" + "a" * 32,
                    "idempotency_key": stable_id("temporal-", key, 40),
                    "payload_sha256": hashlib.sha256(
                        f"payload|{key}".encode("utf-8")
                    ).hexdigest(),
                    "observed_at": TARGET + timedelta(hours=18),
                    "ingested_at": ingested_at,
                }
            )
        with self.database_engine.begin() as connection:
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
                    ) VALUES (
                        :canonical_collection_id, :site_id, :source_id,
                        'endpoint-agent', '/api/v1/agent/inventory',
                        :idempotency_key, :payload_sha256,
                        'oaw.endpoint-inventory.v1', :observed_at, :ingested_at,
                        'complete', 1, 1, 1, 0, 'completed', 0
                    )
                    """
                ),
                rows,
            )

    def test_site_isolation_persistence_repeatability_and_read_only_authority(self) -> None:
        authority_before = self._authority_counts()
        site_a_first = self._assessment()
        site_a_second = self._assessment()
        site_b = self._assessment(site_id="site-deviation-b")
        authority_after = self._authority_counts()

        self.assertEqual(site_a_first.assessment_state, "candidate")
        self.assertEqual(site_a_first.direction, "above")
        self.assertEqual(site_a_first.observed_value, 2)
        self.assertEqual(site_a_first.persistence_observed_buckets, 2)
        self.assertEqual(len(site_a_first.supporting_assessment_ids), 1)
        self.assertEqual(site_a_first, site_a_second)
        self.assertEqual(site_b.assessment_state, "within-range")
        self.assertEqual(site_b.observed_value, 1)
        self.assertNotEqual(site_a_first.observation_digest, site_b.observation_digest)
        self.assertNotEqual(site_a_first.assessment_id, site_b.assessment_id)
        self.assertEqual(authority_before, authority_after)

    def test_exact_and_after_close_evidence_cannot_rewrite_historical_identity(self) -> None:
        baseline = self._assessment()
        self.assertEqual(baseline.observed_value, 2)
        self._insert_cutoff_excluded_target_evidence()
        recalculated = self._assessment()

        self.assertEqual(recalculated.observed_value, 2)
        self.assertEqual(baseline.observation_digest, recalculated.observation_digest)
        self.assertEqual(baseline.input_digest, recalculated.input_digest)
        self.assertEqual(baseline.assessment_id, recalculated.assessment_id)

        later = self._assessment(target=TARGET + timedelta(days=1))
        self.assertEqual(later.observed_value, 3)
        self.assertEqual(later.assessment_state, "candidate")
        self.assertNotEqual(later.observation_digest, baseline.observation_digest)
        self.assertNotEqual(later.assessment_id, baseline.assessment_id)

    def test_fresh_service_instances_release_all_database_sessions(self) -> None:
        for _ in range(3):
            self._assessment()
        self.database_engine.dispose()
        with self.admin_engine.connect() as connection:
            sessions = connection.execute(
                text(
                    """
                    SELECT COUNT(*)
                    FROM pg_stat_activity
                    WHERE datname = :database_name
                      AND pid <> pg_backend_pid()
                    """
                ),
                {"database_name": self.database_name},
            ).scalar_one()
        self.assertEqual(int(sessions), 0)


if __name__ == "__main__":
    unittest.main()
