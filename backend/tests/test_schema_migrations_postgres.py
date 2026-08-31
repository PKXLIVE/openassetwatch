from __future__ import annotations

import hashlib
import os
import re
import threading
import unittest
from uuid import uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.pool import NullPool

from app.schema_migrations import (
    MIGRATION_LOCK_ID,
    Migration,
    SchemaMigrationError,
    discover_migrations,
    migrate_database_schema,
    verify_database_schema,
)


ENABLED = os.getenv("OPENASSETWATCH_SCHEMA_POSTGRES_TEST") == "1"
DATABASE_NAME = re.compile(r"^openassetwatch_schema_test_[0-9a-f]{16}$")


@unittest.skipUnless(
    ENABLED, "requires an explicitly isolated disposable PostgreSQL server"
)
class SchemaMigrationPostgresTests(unittest.TestCase):
    admin_engine: Engine
    database_engine: Engine
    database_name: str

    def setUp(self) -> None:
        source_url = os.environ["DATABASE_URL"]
        parsed = make_url(source_url)
        self.database_name = f"openassetwatch_schema_test_{uuid4().hex[:16]}"
        self.assertRegex(self.database_name, DATABASE_NAME)
        admin_url = parsed.set(database="postgres")
        database_url = parsed.set(database=self.database_name)
        self.admin_engine = create_engine(
            admin_url, isolation_level="AUTOCOMMIT", poolclass=NullPool
        )
        with self.admin_engine.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{self.database_name}"')
        self.database_engine = create_engine(database_url, poolclass=NullPool)

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

    def _state_count(self) -> int:
        with self.database_engine.connect() as connection:
            exists = connection.execute(
                text("SELECT to_regclass('public.oaw_schema_migrations')")
            ).scalar_one()
            if exists is None:
                return 0
            return int(
                connection.execute(
                    text("SELECT COUNT(*) FROM public.oaw_schema_migrations")
                ).scalar_one()
            )

    def test_fresh_database_and_repeated_migration_are_idempotent(self) -> None:
        first = migrate_database_schema(self.database_engine)
        second = migrate_database_schema(self.database_engine)

        self.assertEqual(first.state, "ready")
        self.assertEqual(first.current_version, 4)
        self.assertEqual(second, first)
        self.assertEqual(self._state_count(), 4)
        with self.database_engine.connect() as connection:
            table_count = int(
                connection.execute(
                    text(
                        """
                        SELECT COUNT(*)
                        FROM information_schema.tables
                        WHERE table_schema = 'public'
                        """
                    )
                ).scalar_one()
            )
        self.assertGreaterEqual(table_count, 50)

    def test_existing_compatible_schema_is_adopted_without_data_loss(self) -> None:
        migration = discover_migrations()[0]
        with self.database_engine.begin() as connection:
            connection.exec_driver_sql(migration.sql)
            connection.execute(
                text(
                    "INSERT INTO sites (site_id, name) "
                    "VALUES ('schema-adoption-site', 'Schema Adoption Site')"
                )
            )
            connection.exec_driver_sql("DROP TABLE public.oaw_schema_migrations")
            historical_additions = {
                "collector_inventory_submissions": ("collector_guid",),
                "collectors": (
                    "collector_guid",
                    "deployment_id",
                    "deployment_json",
                    "labels_json",
                    "supported_capabilities_json",
                    "enabled_capabilities_json",
                    "last_submission_id",
                ),
                "agent_enrollments": ("identity_status",),
                "local_inventory_collections": (
                    "observation_batch_id",
                    "observation_source",
                    "observed_at",
                    "delivery_state",
                    "confidence",
                ),
                "control_tower_assets": (
                    "observation_batch_id",
                    "observation_source",
                    "observed_at",
                    "delivery_state",
                    "confidence",
                ),
                "finding_evaluation_runs": ("scope_sensor_id",),
                "findings": (
                    "previous_rule_version",
                    "rule_version_changed_at",
                    "engine_version",
                    "evaluated_at",
                ),
                "risk_factors": ("evidence_ref", "match_id"),
                "advisory_version_ranges": ("introduced_unbounded",),
            }
            for table_name, column_names in historical_additions.items():
                for column_name in column_names:
                    connection.exec_driver_sql(
                        f"ALTER TABLE public.{table_name} "
                        f"DROP COLUMN {column_name} CASCADE"
                    )

        status = migrate_database_schema(self.database_engine)

        self.assertEqual(status.state, "ready")
        self.assertEqual(self._state_count(), 4)
        with self.database_engine.connect() as connection:
            preserved = connection.execute(
                text(
                    "SELECT name FROM sites "
                    "WHERE site_id = 'schema-adoption-site'"
                )
            ).scalar_one()
        self.assertEqual(preserved, "Schema Adoption Site")
        with self.database_engine.connect() as connection:
            restored_count = int(
                connection.execute(
                    text(
                        """
                        SELECT COUNT(*)
                        FROM information_schema.columns
                        WHERE table_schema = 'public'
                          AND (
                              (table_name = 'collectors'
                               AND column_name = 'deployment_json')
                              OR (table_name = 'risk_factors'
                                  AND column_name = 'match_id')
                              OR (table_name = 'advisory_version_ranges'
                                  AND column_name = 'introduced_unbounded')
                          )
                        """
                    )
                ).scalar_one()
            )
        self.assertEqual(restored_count, 3)

    def test_incompatible_existing_schema_is_rejected_without_baselining(self) -> None:
        with self.database_engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TABLE public.sites "
                "(site_id INTEGER PRIMARY KEY, name TEXT NOT NULL)"
            )

        with self.assertRaises(SchemaMigrationError) as raised:
            migrate_database_schema(self.database_engine)

        self.assertEqual(raised.exception.code, "schema-column-incompatible")
        self.assertEqual(self._state_count(), 0)

    def test_conflicting_index_keys_and_predicates_are_rejected(self) -> None:
        migrate_database_schema(self.database_engine)
        with self.database_engine.begin() as connection:
            connection.exec_driver_sql("DROP INDEX public.idx_assets_primary_ip")
            connection.exec_driver_sql(
                "CREATE INDEX idx_assets_primary_ip ON assets (mac_address)"
            )

        with self.assertRaises(SchemaMigrationError) as wrong_keys:
            verify_database_schema(self.database_engine)
        self.assertEqual(wrong_keys.exception.code, "schema-index-incompatible")

        with self.database_engine.begin() as connection:
            connection.exec_driver_sql("DROP INDEX public.idx_assets_primary_ip")
            connection.exec_driver_sql(
                "CREATE INDEX idx_assets_primary_ip ON assets (primary_ip)"
            )
            connection.exec_driver_sql(
                "DROP INDEX public.idx_advisories_known_exploited"
            )
            connection.exec_driver_sql(
                "CREATE INDEX idx_advisories_known_exploited "
                "ON advisories (known_exploited, current)"
            )

        with self.assertRaises(SchemaMigrationError) as missing_predicate:
            verify_database_schema(self.database_engine)
        self.assertEqual(
            missing_predicate.exception.code, "schema-index-incompatible"
        )

    def test_defaults_validated_checks_and_public_foreign_keys_are_required(
        self,
    ) -> None:
        migrate_database_schema(self.database_engine)
        with self.database_engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER TABLE collector_inventory_submissions "
                "ALTER COLUMN id DROP DEFAULT"
            )
        with self.assertRaises(SchemaMigrationError) as missing_default:
            verify_database_schema(self.database_engine)
        self.assertEqual(
            missing_default.exception.code, "schema-column-incompatible"
        )

        with self.database_engine.begin() as connection:
            connection.exec_driver_sql("CREATE SCHEMA attacker_defaults")
            connection.exec_driver_sql(
                "CREATE SEQUENCE attacker_defaults.untrusted_id_seq"
            )
            connection.exec_driver_sql(
                "ALTER TABLE collector_inventory_submissions "
                "ALTER COLUMN id SET DEFAULT "
                "nextval('attacker_defaults.untrusted_id_seq'::regclass)"
            )
        with self.assertRaises(SchemaMigrationError) as wrong_sequence:
            verify_database_schema(self.database_engine)
        self.assertEqual(
            wrong_sequence.exception.code, "schema-column-incompatible"
        )

        with self.database_engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE SEQUENCE public.unowned_inventory_submission_id_seq"
            )
            connection.exec_driver_sql(
                "ALTER TABLE collector_inventory_submissions "
                "ALTER COLUMN id SET DEFAULT "
                "nextval('public.unowned_inventory_submission_id_seq'::regclass)"
            )
        with self.assertRaises(SchemaMigrationError) as unowned_sequence:
            verify_database_schema(self.database_engine)
        self.assertEqual(
            unowned_sequence.exception.code, "schema-column-incompatible"
        )

        with self.database_engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER TABLE collector_inventory_submissions "
                "ALTER COLUMN id SET DEFAULT "
                "nextval('collector_inventory_submissions_id_seq'::regclass) + 1"
            )
        with self.assertRaises(SchemaMigrationError) as altered_expression:
            verify_database_schema(self.database_engine)
        self.assertEqual(
            altered_expression.exception.code, "schema-column-incompatible"
        )

        with self.database_engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER TABLE collector_inventory_submissions "
                "ALTER COLUMN id SET DEFAULT "
                "nextval('collector_inventory_submissions_id_seq'::regclass)"
            )
            connection.exec_driver_sql(
                "ALTER TABLE agent_enrollments "
                "DROP CONSTRAINT agent_enrollments_agent_type_check"
            )
            connection.exec_driver_sql(
                "ALTER TABLE agent_enrollments ADD CONSTRAINT "
                "agent_enrollments_agent_type_check CHECK "
                "(agent_type IN ('endpoint-agent', 'network-sensor')) NOT VALID"
            )
        with self.assertRaises(SchemaMigrationError) as unvalidated_check:
            verify_database_schema(self.database_engine)
        self.assertEqual(
            unvalidated_check.exception.code, "schema-check-incompatible"
        )

        with self.database_engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER TABLE agent_enrollments VALIDATE CONSTRAINT "
                "agent_enrollments_agent_type_check"
            )
            connection.exec_driver_sql(
                "ALTER TABLE agent_enrollments "
                "DROP CONSTRAINT agent_enrollments_site_id_fkey"
            )
            connection.exec_driver_sql("CREATE SCHEMA attacker_schema")
            connection.exec_driver_sql(
                "CREATE TABLE attacker_schema.sites "
                "(site_id TEXT PRIMARY KEY)"
            )
            connection.exec_driver_sql(
                "ALTER TABLE agent_enrollments ADD CONSTRAINT "
                "agent_enrollments_site_id_fkey FOREIGN KEY (site_id) "
                "REFERENCES attacker_schema.sites(site_id)"
            )
        with self.assertRaises(SchemaMigrationError) as wrong_schema:
            verify_database_schema(self.database_engine)
        self.assertEqual(
            wrong_schema.exception.code, "schema-foreign-key-incompatible"
        )

    def test_failed_migration_rolls_back_and_is_not_marked_applied(self) -> None:
        sql = (
            "CREATE TABLE migration_rollback_probe "
            "(probe_id INTEGER PRIMARY KEY);\n"
            "SELECT 1 / 0;\n"
        )
        migration = Migration(
            version=1,
            name="rollback_probe",
            checksum=hashlib.sha256(sql.encode("utf-8")).hexdigest(),
            sql=sql,
        )

        with self.assertRaises(SchemaMigrationError) as raised:
            migrate_database_schema(self.database_engine, migrations=(migration,))

        self.assertEqual(raised.exception.code, "migration-application-failed")
        self.assertEqual(self._state_count(), 0)
        with self.database_engine.connect() as connection:
            exists = connection.execute(
                text("SELECT to_regclass('public.migration_rollback_probe')")
            ).scalar_one()
        self.assertIsNone(exists)

    def test_checksum_mismatch_and_unknown_applied_version_fail_closed(self) -> None:
        migrate_database_schema(self.database_engine)
        original = discover_migrations()[0]
        changed = Migration(
            version=original.version,
            name=original.name,
            checksum="f" * 64,
            sql=original.sql,
        )
        with self.assertRaises(SchemaMigrationError) as mismatch:
            verify_database_schema(self.database_engine, migrations=(changed,))
        self.assertEqual(mismatch.exception.code, "migration-checksum-mismatch")

        with self.database_engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO oaw_schema_migrations (
                        version, name, checksum, execution_duration_ms,
                        application_version, minimum_application_version
                    ) VALUES (5, 'unknown', :checksum, 0, '0.1.0', '0.1.0')
                    """
                ),
                {"checksum": "a" * 64},
            )
        with self.assertRaises(SchemaMigrationError) as unknown:
            verify_database_schema(self.database_engine)
        self.assertEqual(unknown.exception.code, "unknown-applied-version")

    def test_concurrent_migrators_serialize_and_record_once(self) -> None:
        barrier = threading.Barrier(2)
        results: list[object] = []

        def migrate() -> None:
            barrier.wait(timeout=5)
            try:
                results.append(migrate_database_schema(self.database_engine))
            except BaseException as exc:  # surfaced in the parent assertion.
                results.append(exc)

        workers = [threading.Thread(target=migrate) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=30)

        self.assertFalse(any(worker.is_alive() for worker in workers))
        self.assertEqual(len(results), 2)
        self.assertTrue(all(isinstance(item, type(results[0])) for item in results))
        self.assertTrue(all(getattr(item, "state", None) == "ready" for item in results))
        self.assertEqual(self._state_count(), 4)

    def test_version_one_database_upgrades_through_canonical_ingestion(self) -> None:
        migrations = discover_migrations()
        first = migrate_database_schema(self.database_engine, migrations=(migrations[0],))

        self.assertEqual(first.current_version, 1)
        upgraded = migrate_database_schema(self.database_engine, migrations=migrations)

        self.assertEqual(upgraded.state, "ready")
        self.assertEqual(upgraded.current_version, 4)
        self.assertEqual(self._state_count(), 4)
        with self.database_engine.connect() as connection:
            tables = {
                connection.execute(text("SELECT to_regclass('public.endpoint_agent_enrollments')")).scalar_one(),
                connection.execute(text("SELECT to_regclass('public.endpoint_agent_credentials')")).scalar_one(),
                connection.execute(text("SELECT to_regclass('public.endpoint_agent_identity_audit_events')")).scalar_one(),
                connection.execute(text("SELECT to_regclass('public.endpoint_agent_inventory_batches')")).scalar_one(),
                connection.execute(text("SELECT to_regclass('public.canonical_inventory_collections')")).scalar_one(),
                connection.execute(text("SELECT to_regclass('public.canonical_asset_authority')")).scalar_one(),
            }
        self.assertNotIn(None, tables)

    def test_version_two_database_upgrades_to_canonical_ingestion(self) -> None:
        migrations = discover_migrations()
        version_two = migrate_database_schema(
            self.database_engine,
            migrations=migrations[:2],
        )

        self.assertEqual(version_two.current_version, 2)
        upgraded = migrate_database_schema(self.database_engine, migrations=migrations)

        self.assertEqual(upgraded.current_version, 4)
        self.assertEqual(self._state_count(), 4)
        with self.database_engine.connect() as connection:
            tables = {
                connection.execute(text("SELECT to_regclass('public.canonical_ingestion_sources')")).scalar_one(),
                connection.execute(text("SELECT to_regclass('public.canonical_inventory_collections')")).scalar_one(),
                connection.execute(text("SELECT to_regclass('public.canonical_asset_authority')")).scalar_one(),
                connection.execute(text("SELECT to_regclass('public.legacy_submission_mappings')")).scalar_one(),
                connection.execute(text("SELECT to_regclass('public.ingestion_compatibility_events')")).scalar_one(),
            }
        self.assertNotIn(None, tables)

    def test_version_three_database_upgrades_to_native_source_presence(self) -> None:
        migrations = discover_migrations()
        version_three = migrate_database_schema(
            self.database_engine,
            migrations=migrations[:3],
        )

        self.assertEqual(version_three.current_version, 3)
        upgraded = migrate_database_schema(self.database_engine, migrations=migrations)

        self.assertEqual(upgraded.current_version, 4)
        self.assertEqual(self._state_count(), 4)
        with self.database_engine.connect() as connection:
            tables = {
                connection.execute(
                    text("SELECT to_regclass('public.component_source_snapshots')")
                ).scalar_one(),
                connection.execute(
                    text("SELECT to_regclass('public.component_collection_sources')")
                ).scalar_one(),
                connection.execute(
                    text("SELECT to_regclass('public.component_source_presence')")
                ).scalar_one(),
            }
        self.assertNotIn(None, tables)

    def test_lock_contention_times_out_without_schema_change(self) -> None:
        with self.database_engine.connect() as blocker:
            blocker.execute(
                text("SELECT pg_advisory_lock(:lock_id)"),
                {"lock_id": MIGRATION_LOCK_ID},
            )
            blocker.commit()
            try:
                with self.assertRaises(SchemaMigrationError) as raised:
                    migrate_database_schema(
                        self.database_engine, lock_timeout_seconds=0.2
                    )
                self.assertEqual(
                    raised.exception.code, "migration-lock-timeout"
                )
            finally:
                blocker.execute(
                    text("SELECT pg_advisory_unlock(:lock_id)"),
                    {"lock_id": MIGRATION_LOCK_ID},
                )
                blocker.commit()

        with self.database_engine.connect() as connection:
            state_exists = connection.execute(
                text("SELECT to_regclass('public.oaw_schema_migrations')")
            ).scalar_one()
        self.assertIsNone(state_exists)
