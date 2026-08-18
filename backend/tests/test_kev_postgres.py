from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sqlalchemy import text


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cisa-kev"
ENABLED = os.getenv("OPENASSETWATCH_KEV_POSTGRES_TEST") == "1"
if ENABLED:
    database_name = os.environ["OPENASSETWATCH_KEV_POSTGRES_DATABASE"]
    base_url = os.environ["DATABASE_URL"].rsplit("/", 1)[0]
    os.environ["DATABASE_URL"] = f"{base_url}/{database_name}"

from app.database import ensure_database_schema, get_engine  # noqa: E402
from app.advisory_sync_service import AdvisorySyncService  # noqa: E402
from app.kev_catalog import (  # noqa: E402
    canonical_kev_bytes,
    normalize_cisa_kev_catalog,
    parse_cisa_kev_bytes,
)
from app.kev_store import (  # noqa: E402
    SqlKevStore,
    import_kev_catalog,
    refresh_match_priority_factors,
)
from app.advisory_transport import PrivateStagingArea  # noqa: E402
from app.kev_publisher import _verification_registry, sign_kev_bundle  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


NOW = datetime(2099, 1, 4, 12, 0, tzinfo=timezone.utc)
SITE_ID = "site-kev-postgres"
ASSET_ID = "asset-kev-postgres"
COMPONENT_ID = "cmp_" + "1" * 32
ADVISORY_ID = "adv_" + "2" * 32
MATCH_ID = "vmt_" + "3" * 32
SITE_ID_B = "site-kev-postgres-b"
ASSET_ID_B = "asset-kev-postgres-b"
COMPONENT_ID_B = "cmp_" + "4" * 32
MATCH_ID_B = "vmt_" + "5" * 32


def _catalog(name: str):
    return normalize_cisa_kev_catalog(parse_cisa_kev_bytes((FIXTURES / name).read_bytes()))


def _checksum(catalog) -> str:
    return hashlib.sha256(canonical_kev_bytes(catalog)).hexdigest()


def _seed_authoritative_match(connection) -> None:
    connection.execute(
        text("INSERT INTO sites (site_id, name) VALUES (:site_id, 'Synthetic KEV Site')"),
        {"site_id": SITE_ID},
    )
    connection.execute(
        text(
            """
            INSERT INTO control_tower_assets (
                asset_key, asset_id, site_id, hostname,
                first_seen_at, last_seen_at, observed_at,
                observation_source, confidence, metadata_json
            ) VALUES (
                :asset_key, :asset_id, :site_id, 'synthetic-kev-host',
                :now, :now, :now, 'synthetic-postgres-test', 1.0,
                '{}'::jsonb
            )
            """
        ),
        {
            "asset_key": f"{SITE_ID}:{ASSET_ID}",
            "asset_id": ASSET_ID,
            "site_id": SITE_ID,
            "now": NOW,
        },
    )
    connection.execute(
        text(
            """
            INSERT INTO asset_components (
                component_id, asset_id, site_id, component_type,
                ecosystem, name, normalized_name, version,
                normalized_version, canonical_identifier, install_scope,
                source_type, source_id, firmware_evidence_type,
                first_seen_at, last_seen_at, observed_at, freshness,
                confidence, normalization_status, metadata_json, model_version
            ) VALUES (
                :component_id, :asset_id, :site_id, 'application',
                'generic', 'Fictional Orbit Component',
                'fictional-orbit-component', '1.0.0', '1.0.0',
                'pkg:generic/fictional-orbit-component', 'system',
                'endpoint-collector', 'agent-kev-postgres', 'unknown',
                :now, :now, :now, 'fresh', 1.0, 'normalized',
                '{}'::jsonb, 'oaw.component-normalization.v1'
            )
            """
        ),
        {
            "component_id": COMPONENT_ID,
            "asset_id": ASSET_ID,
            "site_id": SITE_ID,
            "now": NOW,
        },
    )
    connection.execute(
        text(
            """
            INSERT INTO advisory_catalog_imports (
                import_id, catalog_version, source, source_version,
                source_license, provenance, checksum, generated_at,
                imported_at, advisory_count, status
            ) VALUES (
                'acimp_kev_postgres', 'synthetic-2099.1',
                'Synthetic Advisory Laboratory', '1', 'Apache-2.0',
                'Fictional offline test data.', :checksum, :now, :now, 1,
                'completed'
            )
            """
        ),
        {"checksum": "a" * 64, "now": NOW},
    )
    connection.execute(
        text(
            """
            INSERT INTO advisories (
                advisory_id, source, source_record_id, source_version,
                title, summary, severity, known_exploited, published_at,
                modified_at, current, catalog_import_id, checksum
            ) VALUES (
                :advisory_id, 'Synthetic Advisory Laboratory',
                'OAW-SYNTH-2099-0001', '1', 'Synthetic affected advisory',
                'Fictional offline test advisory.', 'high', FALSE,
                :now, :now, TRUE, 'acimp_kev_postgres', :checksum
            )
            """
        ),
        {"advisory_id": ADVISORY_ID, "now": NOW, "checksum": "b" * 64},
    )
    connection.execute(
        text("INSERT INTO advisory_aliases (advisory_id, alias) VALUES (:advisory_id, 'cve-2099-10001')"),
        {"advisory_id": ADVISORY_ID},
    )
    connection.execute(
        text(
            """
            INSERT INTO vulnerability_evaluation_runs (
                run_id, trigger_type, engine_version, status, started_at,
                completed_at, component_count, advisory_count,
                candidate_count, affected_count, changed_count
            ) VALUES (
                'vrun_kev_postgres', 'synthetic-test', 'oaw.vulnerability.v1',
                'completed', :now, :now, 1, 1, 1, 1, 1
            )
            """
        ),
        {"now": NOW},
    )
    connection.execute(
        text(
            """
            INSERT INTO vulnerability_matches (
                match_id, asset_id, site_id, component_id, advisory_id,
                affected_id, match_status, match_confidence,
                matched_identifier, installed_version, affected_range,
                fixed_version, first_matched_at, last_matched_at,
                evaluated_at, evidence_ids_json, reason_codes_json,
                engine_version, last_run_id
            ) VALUES (
                :match_id, :asset_id, :site_id, :component_id, :advisory_id,
                'aff_kev_postgres', 'affected', 1.0,
                'pkg:generic/fictional-orbit-component', '1.0.0', '<2.0.0',
                '2.0.0', :now, :now, :now, '[]'::jsonb,
                '["installed-version-in-affected-range"]'::jsonb,
                'oaw.vulnerability.v1', 'vrun_kev_postgres'
            )
            """
        ),
        {
            "match_id": MATCH_ID,
            "asset_id": ASSET_ID,
            "site_id": SITE_ID,
            "component_id": COMPONENT_ID,
            "advisory_id": ADVISORY_ID,
            "now": NOW,
        },
    )


def _seed_second_site_match(connection) -> None:
    connection.execute(
        text("INSERT INTO sites (site_id, name) VALUES (:site_id, 'Synthetic KEV Site B')"),
        {"site_id": SITE_ID_B},
    )
    connection.execute(
        text(
            """
            INSERT INTO control_tower_assets (
                asset_key, asset_id, site_id, hostname,
                first_seen_at, last_seen_at, observed_at,
                observation_source, confidence, metadata_json
            )
            SELECT :asset_key, :asset_id, :site_id, 'synthetic-kev-host-b',
                first_seen_at, last_seen_at, observed_at,
                observation_source, confidence, metadata_json
            FROM control_tower_assets WHERE asset_id = :source_asset_id
            """
        ),
        {
            "asset_key": f"{SITE_ID_B}:{ASSET_ID_B}",
            "asset_id": ASSET_ID_B,
            "site_id": SITE_ID_B,
            "source_asset_id": ASSET_ID,
        },
    )
    connection.execute(
        text(
            """
            INSERT INTO asset_components (
                component_id, asset_id, site_id, component_type,
                ecosystem, vendor, name, normalized_name, version,
                normalized_version, canonical_identifier, architecture,
                install_scope, source_type, source_id, firmware_evidence_type,
                first_seen_at, last_seen_at, observed_at, freshness,
                confidence, normalization_status, metadata_json, model_version
            )
            SELECT :component_id, :asset_id, :site_id, component_type,
                ecosystem, vendor, name, normalized_name, version,
                normalized_version, canonical_identifier, architecture,
                install_scope, source_type, 'agent-kev-postgres-b', firmware_evidence_type,
                first_seen_at, last_seen_at, observed_at, freshness,
                confidence, normalization_status, metadata_json, model_version
            FROM asset_components WHERE component_id = :source_component_id
            """
        ),
        {
            "component_id": COMPONENT_ID_B,
            "asset_id": ASSET_ID_B,
            "site_id": SITE_ID_B,
            "source_component_id": COMPONENT_ID,
        },
    )
    connection.execute(
        text(
            """
            INSERT INTO vulnerability_matches (
                match_id, asset_id, site_id, component_id, advisory_id,
                affected_id, match_status, match_confidence,
                matched_identifier, installed_version, affected_range,
                fixed_version, first_matched_at, last_matched_at,
                evaluated_at, evidence_ids_json, reason_codes_json,
                engine_version, last_run_id
            )
            SELECT :match_id, :asset_id, :site_id, :component_id, advisory_id,
                affected_id, match_status, match_confidence,
                matched_identifier, installed_version, affected_range,
                fixed_version, first_matched_at, last_matched_at,
                evaluated_at, evidence_ids_json, reason_codes_json,
                engine_version, last_run_id
            FROM vulnerability_matches WHERE match_id = :source_match_id
            """
        ),
        {
            "match_id": MATCH_ID_B,
            "asset_id": ASSET_ID_B,
            "site_id": SITE_ID_B,
            "component_id": COMPONENT_ID_B,
            "source_match_id": MATCH_ID,
        },
    )


def _write_signed_fixture(
    fixture_root: Path,
    *,
    catalog,
    private_key: Ed25519PrivateKey,
    sequence: int,
    created_at: datetime,
) -> None:
    payload, manifest, signature, _ = sign_kev_bundle(
        catalog,
        source_digest=hashlib.sha256(canonical_kev_bytes(catalog)).hexdigest(),
        key_id="unit-test-cisa-kev-key",
        private_key=private_key,
        sequence=sequence,
        created_at=created_at,
        validity_days=30,
    )
    fixture = fixture_root / "cisa-kev-official"
    fixture.mkdir(parents=True, exist_ok=True)
    (fixture / "catalog.json").write_bytes(payload)
    (fixture / "manifest.json").write_bytes(manifest)
    (fixture / "manifest.ed25519").write_bytes(signature)


class _RetryScopeStore:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def get_catalog(self, catalog_id, include_bytes=False):
        return {"catalog_id": catalog_id, "source_id": "cisa-kev-official"}

    def mark_reevaluation(self, activation_id, *, status, run_ids=(), error_code=None, impact=None):
        self.calls.append(
            {
                "activation_id": activation_id,
                "status": status,
                "run_ids": list(run_ids),
                "error_code": error_code,
                "impact": impact or {},
            }
        )


class KevRetryScopeTests(unittest.TestCase):
    def test_failed_reevaluation_persists_scope_and_retry_reuses_it(self) -> None:
        key = Ed25519PrivateKey.generate()
        registry, _ = _verification_registry(key_id="unit-test-cisa-kev-key", private_key=key)
        store = _RetryScopeStore()
        service = AdvisorySyncService(registry=registry, store=store, now=lambda: NOW)
        activation = {
            "activation_id": "afact_" + "a" * 32,
            "action": "activate",
            "catalog_id": "afcat_" + "b" * 32,
            "previous_catalog_id": None,
            "import": {
                "affected_site_ids": ["site-a", "site-b"],
                "changed_cve_count": 2,
                "correlation_count": 2,
                "priority_factor_count": 2,
            },
        }
        with patch("app.advisory_sync_service._parse_retained_catalog", return_value=(_catalog("catalog-v1.json"), "c" * 64)), patch(
            "app.advisory_sync_service.evaluate_findings",
            side_effect=RuntimeError("synthetic reevaluation failure"),
        ):
            first = service._reevaluate_activation(activation, actor="unit-test")
        self.assertEqual(first["status"], "failed")
        failed = next(item for item in reversed(store.calls) if item["status"] == "failed")
        self.assertEqual(failed["impact"]["affected_site_ids"], ["site-a", "site-b"])

        retried = {key: value for key, value in activation.items() if key != "import"}
        retried["impact"] = failed["impact"]
        with patch("app.advisory_sync_service._parse_retained_catalog", return_value=(_catalog("catalog-v1.json"), "c" * 64)), patch(
            "app.advisory_sync_service.evaluate_findings",
            side_effect=[SimpleNamespace(run_id="frun-a"), SimpleNamespace(run_id="frun-b")],
        ) as evaluator:
            second = service._reevaluate_activation(retried, actor="unit-test")
        self.assertEqual(second["status"], "completed")
        self.assertEqual(second["run_ids"], ["frun-a", "frun-b"])
        self.assertEqual(evaluator.call_count, 2)


@unittest.skipUnless(ENABLED, "requires an explicitly isolated PostgreSQL validation database")
class KevPostgresLifecycleTests(unittest.TestCase):
    def test_activation_update_rollback_fixed_and_restart_preserve_history(self) -> None:
        ensure_database_schema()
        first = _catalog("catalog-v1.json")
        second = _catalog("catalog-v2.json")
        engine = get_engine()
        with engine.begin() as connection:
            _seed_authoritative_match(connection)
            _seed_second_site_match(connection)
            first_result = import_kev_catalog(
                connection,
                catalog=first,
                checksum=_checksum(first),
                imported_at=NOW,
                catalog_sequence=1,
                source_digest="c" * 64,
                provenance={"source": first.source.model_dump(mode="json")},
            )
        self.assertEqual(first_result["priority_factor_count"], 2)
        self.assertEqual(first_result["changed_cve_count"], 3)

        refreshed = first.model_copy(
            update={
                "catalog_version": "2099.01.24",
                "catalog_date_released": NOW + timedelta(days=20),
            }
        )
        with engine.begin() as connection:
            freshness_result = import_kev_catalog(
                connection,
                catalog=refreshed,
                checksum=_checksum(refreshed),
                imported_at=NOW + timedelta(days=20),
                catalog_sequence=2,
                source_digest="e" * 64,
                provenance={"source": refreshed.source.model_dump(mode="json")},
            )
        self.assertEqual(freshness_result["changed_cve_count"], 0)
        self.assertEqual(
            freshness_result["affected_site_ids"],
            [SITE_ID, SITE_ID_B],
        )

        store = SqlKevStore()
        correctly_scoped = store.asset_records(
            asset_id=ASSET_ID_B,
            site_id=SITE_ID_B,
            limit=20,
        )
        cross_site_mismatch = store.asset_records(
            asset_id=ASSET_ID_B,
            site_id=SITE_ID,
            limit=20,
        )
        self.assertEqual(correctly_scoped["total"], 1)
        self.assertEqual(cross_site_mismatch["total"], 0)

        with engine.begin() as connection:
            connection.execute(
                text("DELETE FROM vulnerability_priority_factors WHERE match_id = :match_id"),
                {"match_id": MATCH_ID_B},
            )
            connection.execute(
                text("DELETE FROM vulnerability_matches WHERE match_id = :match_id"),
                {"match_id": MATCH_ID_B},
            )
            connection.execute(
                text("DELETE FROM asset_components WHERE component_id = :component_id"),
                {"component_id": COMPONENT_ID_B},
            )
            connection.execute(
                text("DELETE FROM control_tower_assets WHERE asset_id = :asset_id"),
                {"asset_id": ASSET_ID_B},
            )
            connection.execute(
                text("DELETE FROM sites WHERE site_id = :site_id"),
                {"site_id": SITE_ID_B},
            )

        with engine.begin() as connection:
            second_result = import_kev_catalog(
                connection,
                catalog=second,
                checksum=_checksum(second),
                imported_at=NOW + timedelta(days=21),
                catalog_sequence=3,
                source_digest="d" * 64,
                provenance={"source": second.source.model_dump(mode="json")},
            )
            current_factors = int(
                connection.execute(
                    text("SELECT COUNT(*) FROM vulnerability_priority_factors WHERE current = TRUE")
                ).scalar_one()
            )
            deactivation_history = int(
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM vulnerability_priority_factor_history "
                        "WHERE current_current = FALSE"
                    )
                ).scalar_one()
            )
        self.assertEqual(second_result["changed_cve_count"], 3)
        self.assertEqual(current_factors, 1)
        self.assertGreaterEqual(deactivation_history, 1)

        with engine.begin() as connection:
            rollback_result = import_kev_catalog(
                connection,
                catalog=first,
                checksum=_checksum(first),
                imported_at=NOW + timedelta(days=22),
                reactivate_existing=True,
                catalog_sequence=1,
                source_digest="c" * 64,
                provenance={"source": first.source.model_dump(mode="json")},
            )
            connection.execute(
                text("UPDATE vulnerability_matches SET match_status = 'fixed' WHERE match_id = :match_id"),
                {"match_id": MATCH_ID},
            )
            fixed_result = refresh_match_priority_factors(
                connection, match_ids=[MATCH_ID], now=NOW
            )
            active_after_fix = int(
                connection.execute(
                    text("SELECT COUNT(*) FROM vulnerability_priority_factors WHERE current = TRUE")
                ).scalar_one()
            )
            match_history = int(
                connection.execute(
                    text(
                        "SELECT COUNT(*) FROM vulnerability_priority_factor_history "
                        "WHERE match_id = :match_id"
                    ),
                    {"match_id": MATCH_ID},
                ).scalar_one()
            )
        self.assertTrue(rollback_result["reactivated"])
        self.assertEqual(active_after_fix, 0)
        self.assertEqual(fixed_result["deactivated_factor_count"], 1)
        self.assertGreaterEqual(match_history, 5)

        restarted = SqlKevStore()
        status = restarted.status(now=NOW)
        self.assertEqual(status["active_catalog"]["catalog_version"], "2099.01.01")
        self.assertEqual(status["current_match_count"], 0)
        record = restarted.get_record("cve-2099-10001")
        self.assertIsNotNone(record)
        self.assertEqual(record["ransomware_campaign_status"], "Known")
        with engine.begin() as connection:
            imports = int(connection.execute(text("SELECT COUNT(*) FROM kev_catalog_imports")).scalar_one())
            record_history = int(connection.execute(text("SELECT COUNT(*) FROM kev_record_history")).scalar_one())
        self.assertEqual(imports, 3)
        self.assertGreaterEqual(record_history, 7)

        with engine.begin() as connection:
            connection.execute(text("DELETE FROM vulnerability_priority_factor_history"))
            connection.execute(text("DELETE FROM vulnerability_priority_factors"))
            connection.execute(text("DELETE FROM advisory_kev_correlations"))
            connection.execute(text("DELETE FROM kev_record_history"))
            connection.execute(text("DELETE FROM kev_records"))
            connection.execute(text("DELETE FROM kev_catalog_imports"))
            connection.execute(
                text("UPDATE vulnerability_matches SET match_status = 'affected' WHERE match_id = :match_id"),
                {"match_id": MATCH_ID},
            )

        key = Ed25519PrivateKey.generate()
        registry, _ = _verification_registry(
            key_id="unit-test-cisa-kev-key",
            private_key=key,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture_root = root / "fixtures"
            current_time = [NOW + timedelta(days=1)]
            service = AdvisorySyncService(
                registry=registry,
                staging=PrivateStagingArea(root / "staging"),
                fixture_root=fixture_root,
                now=lambda: current_time[0],
            )

            _write_signed_fixture(
                fixture_root,
                catalog=first,
                private_key=key,
                sequence=3,
                created_at=current_time[0],
            )
            first_run = service.request_local_bundle(
                source_id="cisa-kev-official",
                requested_by="postgres-lifecycle-test",
            )
            first_preview = service.execute_local_run(first_run["run_id"])
            self.assertEqual(first_preview["state"], "pending_approval")
            self.assertEqual(first_preview["preview"]["signature_status"], "verified")
            service.approve(first_run["run_id"], actor="postgres-lifecycle-reviewer")
            first_activation = service.activate(
                first_run["run_id"],
                actor="postgres-lifecycle-reviewer",
            )
            self.assertEqual(first_activation["reevaluation"]["status"], "completed")

            current_time[0] += timedelta(hours=1)
            _write_signed_fixture(
                fixture_root,
                catalog=second,
                private_key=key,
                sequence=4,
                created_at=current_time[0],
            )
            second_run = service.request_local_bundle(
                source_id="cisa-kev-official",
                requested_by="postgres-lifecycle-test",
            )
            second_preview = service.execute_local_run(second_run["run_id"])
            self.assertEqual(second_preview["preview"]["added_records"], 1)
            self.assertEqual(second_preview["preview"]["updated_records"], 1)
            self.assertEqual(second_preview["preview"]["removed_records"], 1)
            service.approve(second_run["run_id"], actor="postgres-lifecycle-reviewer")
            second_activation = service.activate(
                second_run["run_id"],
                actor="postgres-lifecycle-reviewer",
            )
            self.assertEqual(second_activation["reevaluation"]["status"], "completed")

            current_time[0] += timedelta(hours=1)
            rollback = service.rollback(
                first_activation["catalog_id"],
                actor="postgres-lifecycle-reviewer",
            )
            self.assertEqual(rollback["action"], "rollback")
            self.assertEqual(rollback["reevaluation"]["status"], "completed")

            restarted_service = AdvisorySyncService(registry=registry, now=lambda: current_time[0])
            restarted_status = restarted_service.source_status("cisa-kev-official")
            self.assertEqual(
                restarted_status["active_catalog"]["catalog_id"],
                first_activation["catalog_id"],
            )

        with engine.begin() as connection:
            lifecycle_runs = int(
                connection.execute(
                    text("SELECT COUNT(*) FROM advisory_feed_runs WHERE source_id = 'cisa-kev-official'")
                ).scalar_one()
            )
            activations = int(
                connection.execute(
                    text("SELECT COUNT(*) FROM advisory_catalog_activations WHERE source_id = 'cisa-kev-official'")
                ).scalar_one()
            )
            finding_runs = int(
                connection.execute(
                    text("SELECT COUNT(*) FROM finding_evaluation_runs WHERE trigger_type LIKE 'kev-catalog-%'")
                ).scalar_one()
            )
            current_factors = int(
                connection.execute(
                    text("SELECT COUNT(*) FROM vulnerability_priority_factors WHERE current = TRUE")
                ).scalar_one()
            )
            persisted_risk_citations = connection.execute(
                text(
                    "SELECT evidence_ref, match_id FROM risk_factors "
                    "WHERE factor_type = 'kev-priority' AND subject_type = 'asset'"
                )
            ).mappings().all()
        self.assertEqual(lifecycle_runs, 2)
        self.assertEqual(activations, 3)
        self.assertEqual(finding_runs, 3)
        self.assertEqual(current_factors, 1)
        self.assertTrue(persisted_risk_citations)
        self.assertTrue(
            all(item["evidence_ref"] and item["match_id"] == MATCH_ID for item in persisted_risk_citations)
        )


if __name__ == "__main__":
    unittest.main()
