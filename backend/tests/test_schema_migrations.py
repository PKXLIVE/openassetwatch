from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

from app.main import app, application_lifespan, readiness
from app.schema_migrations import (
    MIGRATION_DIRECTORY,
    Migration,
    SchemaMigrationError,
    SchemaStatus,
    _validate_applied_history,
    _unsafe_posix_write_permissions,
    _set_search_path,
    _normalize_sql_fragment,
    database_schema_status,
    discover_migrations,
    ensure_schema_ready,
    operator_main,
    reset_schema_runtime_for_tests,
    schema_contract,
    set_runtime_migration_failure,
)


ROOT = Path(__file__).resolve().parents[2]
SAMPLE_SQL = b"CREATE TABLE IF NOT EXISTS sample (id INTEGER PRIMARY KEY);\n"
DDL_PATTERN = re.compile(
    r"(?i)\b(?:CREATE\s+(?:TABLE|INDEX|UNIQUE\s+INDEX)|ALTER\s+TABLE)\b"
)


def _legacy_ddl_inventory() -> dict[str, dict[str, object]]:
    inventory: dict[str, dict[str, object]] = {}
    manifest_path = ROOT / "database" / "legacy-ddl-compatibility.json"
    declared = json.loads(manifest_path.read_text(encoding="utf-8"))["files"]
    for relative_path in declared:
        tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
        string_nodes = sorted(
            (
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and DDL_PATTERN.search(node.value)
            ),
            key=lambda node: (node.lineno, node.col_offset),
        )
        statements = [" ".join(str(node.value).split()) for node in string_nodes]
        payload = ("\n".join(statements) + "\n").encode("utf-8")
        inventory[relative_path] = {
            "statement_count": len(statements),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    return inventory


class MigrationDiscoveryTests(unittest.TestCase):
    def _write(self, root: Path, name: str, payload: bytes = SAMPLE_SQL) -> Path:
        target = root / name
        target.write_bytes(payload)
        return target

    def test_packaged_baseline_is_ordered_checksummed_and_complete(self) -> None:
        migrations = discover_migrations()

        self.assertEqual([item.version for item in migrations], [1, 2, 3])
        self.assertEqual(migrations[0].name, "current_schema_baseline")
        self.assertEqual(migrations[1].name, "endpoint_agent_identity")
        self.assertEqual(migrations[2].name, "canonical_ingestion_compatibility")
        self.assertEqual(
            migrations[0].checksum,
            hashlib.sha256(
                (MIGRATION_DIRECTORY / "0001_current_schema_baseline.sql").read_bytes()
            ).hexdigest(),
        )
        self.assertEqual(
            migrations[1].checksum,
            hashlib.sha256(
                (MIGRATION_DIRECTORY / "0002_endpoint_agent_identity.sql").read_bytes()
            ).hexdigest(),
        )
        self.assertEqual(
            migrations[2].checksum,
            hashlib.sha256(
                (
                    MIGRATION_DIRECTORY
                    / "0003_canonical_ingestion_compatibility.sql"
                ).read_bytes()
            ).hexdigest(),
        )
        contract = schema_contract(migrations)
        self.assertIn("oaw_schema_migrations", contract.columns)
        self.assertIn("classification_evidence", contract.columns)
        self.assertIn("vulnerability_priority_factors", contract.columns)
        self.assertIn("endpoint_agent_enrollments", contract.columns)
        self.assertIn("endpoint_agent_credentials", contract.columns)
        self.assertIn("endpoint_agent_identity_audit_events", contract.columns)
        self.assertIn("endpoint_agent_inventory_batches", contract.columns)
        self.assertIn("canonical_ingestion_sources", contract.columns)
        self.assertIn("canonical_inventory_collections", contract.columns)
        self.assertIn("canonical_asset_authority", contract.columns)
        self.assertIn("legacy_submission_mappings", contract.columns)
        self.assertIn("ingestion_compatibility_events", contract.columns)
        self.assertGreaterEqual(len(contract.columns), 50)

    def test_duplicate_version_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oaw-migrations-") as temporary:
            root = Path(temporary)
            self._write(root, "0001_first.sql")
            self._write(root, "0001_second.sql")

            with self.assertRaisesRegex(
                SchemaMigrationError, "unique and positive"
            ) as raised:
                discover_migrations(root)

        self.assertEqual(raised.exception.code, "migration-version-duplicate")

    def test_discovery_orders_contiguous_versions_deterministically(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oaw-migrations-") as temporary:
            root = Path(temporary)
            self._write(root, "0002_second.sql")
            self._write(root, "0001_first.sql")

            discovered = discover_migrations(root)

        self.assertEqual(
            [item.identifier for item in discovered],
            ["0001_first", "0002_second"],
        )

    def test_version_gap_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oaw-migrations-") as temporary:
            root = Path(temporary)
            self._write(root, "0001_first.sql")
            self._write(root, "0003_third.sql")

            with self.assertRaises(SchemaMigrationError) as raised:
                discover_migrations(root)

        self.assertEqual(raised.exception.code, "migration-version-gap")

    def test_malformed_filename_or_metadata_is_rejected(self) -> None:
        for invalid_name in ("1_short.sql", "0001_Bad.sql", "README.md"):
            with self.subTest(invalid_name=invalid_name), tempfile.TemporaryDirectory(
                prefix="oaw-migrations-"
            ) as temporary:
                root = Path(temporary)
                self._write(root, invalid_name)
                with self.assertRaises(SchemaMigrationError) as raised:
                    discover_migrations(root)
                self.assertEqual(
                    raised.exception.code, "migration-filename-invalid"
                )

    def test_hard_linked_migration_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oaw-migrations-") as temporary:
            root = Path(temporary)
            migration = self._write(root, "0001_first.sql")
            outside = root.parent / f"{root.name}-hardlink.sql"
            try:
                os.link(migration, outside)
            except OSError as exc:
                self.skipTest(f"hard links unavailable: {type(exc).__name__}")
            try:
                with self.assertRaises(SchemaMigrationError) as raised:
                    discover_migrations(root)
                self.assertEqual(
                    raised.exception.code, "migration-file-invalid"
                )
            finally:
                outside.unlink(missing_ok=True)

    def test_symbolic_linked_migration_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oaw-migrations-") as temporary:
            root = Path(temporary)
            source = root.parent / f"{root.name}-source.sql"
            source.write_bytes(SAMPLE_SQL)
            migration = root / "0001_first.sql"
            try:
                migration.symlink_to(source)
            except OSError as exc:
                source.unlink(missing_ok=True)
                self.skipTest(f"symbolic links unavailable: {type(exc).__name__}")
            try:
                with self.assertRaises(SchemaMigrationError) as raised:
                    discover_migrations(root)
                self.assertEqual(
                    raised.exception.code, "migration-file-invalid"
                )
            finally:
                source.unlink(missing_ok=True)

    def test_client_side_include_and_unknown_entries_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="oaw-migrations-") as temporary:
            root = Path(temporary)
            self._write(root, "0001_first.sql", b"\\ir unsafe.sql\n")
            with self.assertRaises(SchemaMigrationError) as raised:
                discover_migrations(root)
            self.assertEqual(raised.exception.code, "migration-content-invalid")

    def test_posix_write_bits_are_accepted_only_on_read_only_filesystems(
        self,
    ) -> None:
        writable = Mock(f_flag=0)
        read_only = Mock(f_flag=getattr(os, "ST_RDONLY", 1))
        with patch("app.schema_migrations.os.name", "posix"), patch(
            "app.schema_migrations.os.statvfs", return_value=writable, create=True
        ):
            self.assertTrue(_unsafe_posix_write_permissions(Path("migration.sql"), 0o666))
        with patch("app.schema_migrations.os.name", "posix"), patch(
            "app.schema_migrations.os.statvfs", return_value=read_only, create=True
        ):
            self.assertFalse(_unsafe_posix_write_permissions(Path("migration.sql"), 0o666))

        self.assertFalse(_unsafe_posix_write_permissions(Path("migration.sql"), 0o644))

    def test_check_normalization_preserves_boolean_grouping(self) -> None:
        expected = _normalize_sql_fragment("a OR (b AND c)")
        conflicting = _normalize_sql_fragment("(a OR b) AND c")

        self.assertNotEqual(expected, conflicting)

    def test_check_normalization_accepts_postgres_typed_array_deparse(self) -> None:
        expected = _normalize_sql_fragment("adapter_type IN ('one', 'two')")
        actual = _normalize_sql_fragment(
            "adapter_type = ANY (ARRAY['one'::text, 'two'::text]::text[])"
        )

        self.assertEqual(actual, expected)

    def test_static_schema_is_only_a_reference_to_the_canonical_migration(self) -> None:
        reference = (ROOT / "database" / "schema.sql").read_text(encoding="utf-8")
        migration_path = MIGRATION_DIRECTORY / "0001_current_schema_baseline.sql"
        checksum = hashlib.sha256(migration_path.read_bytes()).hexdigest()

        self.assertIn(
            "Canonical migration: ../backend/app/migration_sql/"
            "0001_current_schema_baseline.sql",
            reference,
        )
        self.assertIn(f"Canonical SHA-256: {checksum}", reference)
        self.assertIn("\\quit 3", reference)
        self.assertNotIn("\\ir ", reference)
        self.assertNotRegex(reference, r"(?i)\bCREATE\s+TABLE\b")

    def test_application_owned_ddl_is_frozen_to_the_compatibility_inventory(
        self,
    ) -> None:
        manifest = json.loads(
            (ROOT / "database" / "legacy-ddl-compatibility.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(manifest["schema_version"], "oaw.legacy-ddl-compatibility.v1")
        self.assertEqual(_legacy_ddl_inventory(), manifest["files"])

        files_with_ddl = {
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "backend" / "app").glob("*.py")
            if DDL_PATTERN.search(path.read_text(encoding="utf-8"))
        }
        self.assertEqual(
            files_with_ddl,
            set(manifest["files"]) | {"backend/app/schema_migrations.py"},
        )


class MigrationHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.migration = discover_migrations()[0]
        self.row = {
            "version": self.migration.version,
            "name": self.migration.name,
            "checksum": self.migration.checksum,
        }

    def test_checksum_mismatch_after_application_is_rejected(self) -> None:
        changed = Migration(
            version=1,
            name=self.migration.name,
            checksum="f" * 64,
            sql=self.migration.sql,
        )

        with self.assertRaises(SchemaMigrationError) as raised:
            _validate_applied_history([self.row], [changed])

        self.assertEqual(raised.exception.code, "migration-checksum-mismatch")

    def test_unknown_applied_version_is_rejected(self) -> None:
        row = {"version": 2, "name": "unknown", "checksum": "a" * 64}

        with self.assertRaises(SchemaMigrationError) as raised:
            _validate_applied_history([row], [self.migration])

        self.assertEqual(raised.exception.code, "applied-version-gap")

    def test_unknown_contiguous_applied_version_is_rejected(self) -> None:
        unknown = {"version": 2, "name": "unknown", "checksum": "a" * 64}

        with self.assertRaises(SchemaMigrationError) as raised:
            _validate_applied_history(
                [self.row, unknown],
                [self.migration],
            )

        self.assertEqual(raised.exception.code, "unknown-applied-version")

    def test_applied_name_is_immutable(self) -> None:
        changed = dict(self.row, name="renamed")

        with self.assertRaises(SchemaMigrationError) as raised:
            _validate_applied_history([changed], [self.migration])

        self.assertEqual(raised.exception.code, "applied-name-mismatch")


class MigrationRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_schema_runtime_for_tests()

    def tearDown(self) -> None:
        reset_schema_runtime_for_tests()

    def test_ready_engine_is_cached_before_normal_service_use(self) -> None:
        engine = Mock()
        status = SchemaStatus(
            state="ready",
            current_version=1,
            latest_available_version=1,
            pending_migration_count=0,
            compatibility_state="compatible",
            checksum_integrity="verified",
        )
        with patch(
            "app.schema_migrations.migrate_database_schema", return_value=status
        ) as migrate:
            self.assertIs(ensure_schema_ready(engine), status)
            self.assertIs(ensure_schema_ready(engine), status)

        migrate.assert_called_once_with(engine)

    def test_migration_search_path_keeps_catalog_resolution_implicit(self) -> None:
        connection = Mock()

        _set_search_path(connection)

        connection.exec_driver_sql.assert_called_once_with(
            "SET LOCAL search_path TO public, pg_temp"
        )

    def test_status_redacts_driver_error_and_local_details(self) -> None:
        engine = Mock()
        engine.connect.side_effect = RuntimeError(
            "password=do-not-leak C:\\private\\database.dump"
        )

        status = database_schema_status(engine)

        rendered = json.dumps(status.as_dict(), default=str)
        self.assertEqual(status.state, "failed")
        self.assertNotIn("do-not-leak", rendered)
        self.assertNotIn("private", rendered)
        self.assertNotIn("password", rendered)

    def test_startup_migration_wraps_unexpected_driver_details(self) -> None:
        engine = Mock()
        with patch(
            "app.schema_migrations.migrate_database_schema",
            side_effect=RuntimeError(
                "password=do-not-leak C:\\private\\database.dump"
            ),
        ):
            with self.assertRaises(SchemaMigrationError) as raised:
                ensure_schema_ready(engine)

        self.assertEqual(raised.exception.code, "database-runtimeerror")
        self.assertNotIn("do-not-leak", str(raised.exception))
        self.assertNotIn("private", str(raised.exception))

    def test_readiness_returns_bounded_failure_code(self) -> None:
        set_runtime_migration_failure("migration-checksum-mismatch")

        response = readiness()
        body = json.loads(response.body)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(body["status"], "unready")
        self.assertEqual(body["failure_code"], "migration-checksum-mismatch")
        self.assertNotIn("sql", json.dumps(body).lower())

    def test_operator_status_is_bounded_read_only_json(self) -> None:
        status = SchemaStatus(
            state="ready",
            current_version=1,
            latest_available_version=1,
            pending_migration_count=0,
            compatibility_state="compatible",
            checksum_integrity="verified",
        )
        output = StringIO()
        with patch("app.database.get_engine", return_value=Mock()), patch(
            "app.schema_migrations.database_schema_status", return_value=status
        ), redirect_stdout(output):
            exit_code = operator_main(["status"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(output.getvalue())["current_version"], 1)
        self.assertNotIn("sql", output.getvalue().lower())

    def test_operator_redacts_engine_construction_errors(self) -> None:
        output = StringIO()
        with patch(
            "app.database.get_engine",
            side_effect=RuntimeError(
                "password=do-not-leak C:\\private\\database.dump"
            ),
        ), redirect_stdout(output):
            exit_code = operator_main(["status"])

        rendered = output.getvalue()
        self.assertEqual(exit_code, 2)
        self.assertIn("database-runtimeerror", rendered)
        self.assertNotIn("do-not-leak", rendered)
        self.assertNotIn("private", rendered)


class StartupMigrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        reset_schema_runtime_for_tests()

    async def asyncTearDown(self) -> None:
        reset_schema_runtime_for_tests()

    async def test_startup_is_blocked_on_migration_failure(self) -> None:
        with patch(
            "app.main.ensure_schema_ready",
            side_effect=SchemaMigrationError(
                "migration-checksum-mismatch", "reviewed bytes changed"
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "migration-checksum-mismatch"
            ):
                async with application_lifespan(app):
                    self.fail("startup must not reach request-serving state")

    async def test_startup_succeeds_after_valid_migration(self) -> None:
        status = SchemaStatus(
            state="ready",
            current_version=1,
            latest_available_version=1,
            pending_migration_count=0,
            compatibility_state="compatible",
            checksum_integrity="verified",
        )
        with patch("app.main.ensure_schema_ready", return_value=status):
            async with application_lifespan(app):
                self.assertTrue(True)

    async def test_engine_construction_failure_is_bounded(self) -> None:
        with patch(
            "app.main.get_engine",
            side_effect=RuntimeError(
                "password=do-not-leak C:\\private\\database.dump"
            ),
        ):
            with self.assertRaises(RuntimeError) as raised:
                async with application_lifespan(app):
                    self.fail("startup must not reach request-serving state")

        rendered = str(raised.exception)
        self.assertIn("database-runtimeerror", rendered)
        self.assertNotIn("do-not-leak", rendered)
        self.assertNotIn("private", rendered)
