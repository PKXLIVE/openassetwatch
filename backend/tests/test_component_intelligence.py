from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timezone

from app.component_intelligence import (
    complete_component_inventory_scope,
    normalize_components_for_asset,
    parse_purl,
    purl_identity,
)
from app.component_store import _history_event, persist_components
from app.component_store import _should_replace_component
from app.hub_contracts import ObservationBatchRequest
from app.version_intelligence import (
    compare_versions,
    version_satisfies_range,
)


NOW = datetime(2026, 1, 15, 15, 0, tzinfo=timezone.utc)


def normalize(
    entry: dict,
    *,
    authenticated: bool = True,
    sensor_type: str = "endpoint-collector",
):
    return normalize_components_for_asset(
        asset={
            "site_id": "site-test",
            "asset_id": "asset-test",
            "source_agent_id": "agent-test",
            "components": [entry],
            "component_inventory_complete": True,
        },
        payload={
            "site_id": "site-test",
            "sensor_id": "agent-test",
            "sensor_type": sensor_type,
            "observation_source": (
                "endpoint-inventory"
                if sensor_type == "endpoint-collector"
                else "passive-network"
            ),
            "component_inventory_complete": True,
            "confidence": 0.95,
        },
        received_at=NOW,
        source_authenticated=authenticated,
    )


class PackageUrlTests(unittest.TestCase):
    def test_parses_and_removes_version_for_identity(self) -> None:
        parsed = parse_purl("pkg:pypi/asterion-agent@1.2.0")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.ecosystem, "pypi")
        self.assertEqual(
            purl_identity(parsed.canonical),
            "pkg:pypi/asterion-agent",
        )

    def test_rejects_qualifiers_fragments_paths_and_unknown_types(self) -> None:
        for value in (
            "pkg:pypi/example?download_url=https://example.invalid",
            "pkg:pypi/example#fragment",
            "pkg:pypi/a/b/c",
            "pkg:unknown/example",
            "pkg:pypi/example%2Fother",
        ):
            with self.subTest(value=value):
                self.assertIsNone(parse_purl(value))

    def test_purl_identity_preserves_case_sensitive_and_nested_namespaces(
        self,
    ) -> None:
        self.assertIsNone(parse_purl("pkg:python/Requests"))
        self.assertNotEqual(
            purl_identity("pkg:maven/com.example/Widget"),
            purl_identity("pkg:maven/com.example/widget"),
        )
        self.assertEqual(
            purl_identity("pkg:golang/github.com/acme/module@v1.2.3"),
            "pkg:golang/github.com/acme/module",
        )


class ComponentNormalizationTests(unittest.TestCase):
    def test_stable_component_identity_does_not_include_version(self) -> None:
        first = normalize(
            {
                "component_type": "application",
                "ecosystem": "pypi",
                "name": "Asterion Agent",
                "version": "1.2.0",
                "purl": "pkg:pypi/asterion-agent",
            }
        )[0]
        second = normalize(
            {
                "component_type": "application",
                "ecosystem": "pypi",
                "name": "Asterion Agent",
                "version": "1.4.2",
                "purl": "pkg:pypi/asterion-agent",
            }
        )[0]
        self.assertEqual(first.component_id, second.component_id)
        self.assertNotEqual(first.version, second.version)
        self.assertEqual(first.normalization_status, "normalized")

    def test_missing_version_is_inventory_gap(self) -> None:
        component = normalize(
            {
                "component_type": "library",
                "ecosystem": "npm",
                "name": "lumina-widget",
                "purl": "pkg:npm/lumina-widget",
            }
        )[0]
        self.assertEqual(component.normalization_status, "version-unknown")
        self.assertIsNone(component.version)

    def test_passive_firmware_claim_is_downgraded(self) -> None:
        component = normalize(
            {
                "component_type": "firmware",
                "ecosystem": "firmware",
                "vendor": "Fictional Beacon Works",
                "name": "Beacon Router Firmware",
                "version": "5.0.8",
                "firmware_evidence_type": "direct",
            },
            sensor_type="passive-network-sensor",
        )[0]
        self.assertEqual(component.firmware_evidence_type, "inferred")
        self.assertEqual(
            component.normalization_status,
            "insufficient-firmware-evidence",
        )

    def test_precise_collector_firmware_is_normalized(self) -> None:
        component = normalize(
            {
                "component_type": "firmware",
                "ecosystem": "firmware",
                "vendor": "Fictional Beacon Works",
                "name": "Beacon Router Firmware",
                "version": "5.0.8",
                "firmware_evidence_type": "collector-reported",
            }
        )[0]
        self.assertEqual(component.normalization_status, "normalized")

    def test_untrusted_source_cannot_claim_complete_inventory(self) -> None:
        asset = {
            "site_id": "site-test",
            "asset_id": "asset-test",
            "source_agent_id": "claimed-agent",
            "components": [],
            "component_inventory_complete": True,
        }
        payload = {
            "sensor_id": "claimed-agent",
            "sensor_type": "endpoint-collector",
            "component_inventory_complete": True,
        }
        self.assertIsNone(
            complete_component_inventory_scope(
                asset=asset,
                payload=payload,
                received_at=NOW,
                source_authenticated=False,
            )
        )
        self.assertIsNotNone(
            complete_component_inventory_scope(
                asset=asset,
                payload=payload,
                received_at=NOW,
                source_authenticated=True,
            )
        )

    def test_authenticated_passive_source_cannot_elevate_with_source_label(
        self,
    ) -> None:
        component = normalize_components_for_asset(
            asset={
                "site_id": "site-test",
                "asset_id": "asset-test",
                "source_agent_id": "sensor-test",
                "components": [
                    {
                        "component_type": "application",
                        "ecosystem": "pypi",
                        "name": "asterion-agent",
                        "version": "1.2.0",
                        "purl": "pkg:pypi/asterion-agent",
                    }
                ],
                "component_inventory_complete": True,
            },
            payload={
                "sensor_id": "sensor-test",
                "sensor_type": "passive-network-sensor",
                "observation_source": "endpoint-inventory",
                "component_inventory_complete": True,
            },
            received_at=NOW,
            source_authenticated=True,
        )[0]
        self.assertEqual(component.source_type, "passive-network-sensor")
        self.assertFalse(component.inventory_complete)

    def test_observation_contract_binds_source_to_sensor_type(self) -> None:
        with self.assertRaises(ValueError):
            ObservationBatchRequest.model_validate(
                {
                    "schema_version": "oaw.observation-batch.v1",
                    "observation_batch_id": "batch-test",
                    "site_id": "site-test",
                    "sensor_id": "sensor-test",
                    "sensor_name": "Synthetic sensor",
                    "sensor_type": "passive-network-sensor",
                    "observed_at": NOW.isoformat(),
                    "observation_source": "endpoint-inventory",
                    "assets": [],
                }
            )

    def test_control_characters_and_missing_names_are_dropped(self) -> None:
        self.assertEqual(
            normalize(
                {
                    "component_type": "application",
                    "ecosystem": "generic",
                    "name": "unsafe\x00name",
                    "version": "1.0",
                }
            ),
            (),
        )

    def test_safe_metadata_is_whitelisted(self) -> None:
        component = normalize(
            {
                "component_type": "application",
                "ecosystem": "pypi",
                "name": "asterion-agent",
                "version": "1.2.0",
                "purl": "pkg:pypi/asterion-agent",
                "metadata": {
                    "channel": "stable",
                    "install_path": "C:\\private\\path",
                    "token": "not-retained",
                },
            }
        )[0]
        self.assertEqual(component.metadata, {"channel": "stable"})

    def test_client_evidence_ids_are_namespaced_and_stable(self) -> None:
        first = normalize(
            {
                "component_type": "application",
                "ecosystem": "pypi",
                "name": "asterion-agent",
                "version": "1.2.0",
                "purl": "pkg:pypi/asterion-agent",
                "evidence_ids": ["finding_external"],
            }
        )[0]
        second = normalize(
            {
                "component_type": "application",
                "ecosystem": "pypi",
                "name": "asterion-agent",
                "version": "1.2.0",
                "purl": "pkg:pypi/asterion-agent",
                "evidence_ids": ["finding_external"],
                "observed_at": "2026-01-15T14:00:00+00:00",
            }
        )[0]
        self.assertEqual(first.evidence_ids, second.evidence_ids)
        self.assertRegex(first.evidence_ids[0], r"^cpe_[0-9a-f]{32}$")
        self.assertNotIn("finding_external", first.evidence_ids)


class FakeResult:
    def __init__(self, *, one=None, rows=(), scalar=None):
        self.one = one
        self.rows = list(rows)
        self.scalar = scalar

    def mappings(self):
        return self

    def one_or_none(self):
        return self.one

    def all(self):
        return self.rows

    def scalar_one_or_none(self):
        return self.scalar


class FakeComponentConnection:
    def __init__(self, *, previous=None, removal_rows=()):
        self.previous = previous
        self.removal_rows = list(removal_rows)
        self.calls = []

    def execute(self, statement, params=None):
        sql = str(statement)
        self.calls.append((sql, params or {}))
        if "SELECT *" in sql and "FROM asset_components" in sql:
            return FakeResult(one=self.previous)
        if "SELECT component_id, version, metadata_json" in sql:
            return FakeResult(rows=self.removal_rows)
        if "RETURNING component_id" in sql:
            return FakeResult(scalar=(params or {}).get("component_id"))
        return FakeResult()


class ComponentHistoryTests(unittest.TestCase):
    def test_material_changes_have_explicit_history_events(self) -> None:
        current = normalize(
            {
                "component_type": "application",
                "ecosystem": "pypi",
                "name": "asterion-agent",
                "version": "1.2.0",
                "purl": "pkg:pypi/asterion-agent",
            }
        )[0]
        self.assertEqual(_history_event(None, current), "first-observed")
        previous = current.as_dict()
        previous["active"] = False
        self.assertEqual(_history_event(previous, current), "observed-again")
        previous["active"] = True
        previous["normalized_version"] = "1.1.0"
        self.assertEqual(_history_event(previous, current), "version-changed")
        previous["normalized_version"] = current.normalized_version
        previous["source_id"] = "agent-other"
        self.assertEqual(_history_event(previous, current), "source-changed")
        previous["source_id"] = current.source_id
        previous["confidence"] = 0.5
        self.assertEqual(
            _history_event(previous, current),
            "confidence-changed",
        )

    def test_older_or_weaker_evidence_cannot_replace_current_state(self) -> None:
        current = normalize(
            {
                "component_type": "application",
                "ecosystem": "pypi",
                "name": "asterion-agent",
                "version": "1.2.0",
                "purl": "pkg:pypi/asterion-agent",
            }
        )[0]
        previous = current.as_dict()
        older = replace(
            current,
            version="1.4.2",
            normalized_version="1.4.2",
            observed_at=NOW.replace(hour=14),
        )
        self.assertFalse(_should_replace_component(previous, older))
        weaker = replace(
            current,
            source_type="passive-network-sensor",
            source_id="sensor-passive",
            observed_at=NOW.replace(hour=16),
        )
        self.assertFalse(_should_replace_component(previous, weaker))
        newer = replace(
            current,
            version="1.4.2",
            normalized_version="1.4.2",
            observed_at=NOW.replace(hour=16),
        )
        self.assertTrue(_should_replace_component(previous, newer))

    def test_atomic_upsert_rechecks_monotonic_source_trust(self) -> None:
        component = normalize(
            {
                "component_type": "application",
                "ecosystem": "pypi",
                "name": "asterion-agent",
                "version": "1.2.0",
                "purl": "pkg:pypi/asterion-agent",
            }
        )[0]
        connection = FakeComponentConnection()

        persist_components(connection, components=[component])

        upsert_sql = next(
            sql for sql, _ in connection.calls if "RETURNING component_id" in sql
        )
        self.assertIn("EXCLUDED.observed_at > GREATEST", upsert_sql)
        self.assertIn("CASE EXCLUDED.source_type", upsert_sql)
        self.assertIn("CASE asset_components.source_type", upsert_sql)
        self.assertIn("EXCLUDED.confidence", upsert_sql)
        self.assertIn("RETURNING component_id", upsert_sql)

    def test_only_complete_current_inventory_confirms_not_observed(self) -> None:
        connection = FakeComponentConnection(
            removal_rows=[
                {
                    "component_id": "cmp_" + "d" * 32,
                    "version": "1.2.0",
                    "metadata_json": {},
                }
            ]
        )
        result = persist_components(
            connection,
            components=[],
            complete_assets=[
                ("site-test", "asset-test", "agent-test", NOW)
            ],
        )
        self.assertEqual(result["not_observed"], 1)
        sql = "\n".join(call[0] for call in connection.calls)
        self.assertIn("SET active = FALSE", sql)
        self.assertIn("'not-observed'", sql)
        history_call = next(
            call
            for call in connection.calls
            if "'not-observed'" in call[0]
        )
        self.assertEqual(
            history_call[1]["snapshot_json"],
            (
                '{"active": false, "component_id": '
                '"cmp_dddddddddddddddddddddddddddddddd", '
                '"reason": "complete-inventory-omission"}'
            ),
        )


class VersionComparisonTests(unittest.TestCase):
    def assert_order(
        self,
        ecosystem: str,
        left: str,
        right: str,
        expected: int,
    ) -> None:
        result = compare_versions(ecosystem, left, right)
        self.assertEqual(result.status, "supported", result)
        self.assertEqual(result.order, expected)

    def test_semver_and_prerelease_ordering(self) -> None:
        self.assert_order("npm", "1.10.0", "1.9.9", 1)
        self.assert_order("golang", "v1.2.0-rc.1", "v1.2.0", -1)
        self.assert_order("npm", "1.0.0-1", "1.0.0-alpha", -1)
        self.assert_order("npm", "1.0.0-alpha", "1.0.0-alpha.1", -1)
        self.assert_order("nuget", "2.0.0", "2.0.0", 0)

    def test_pep440_epoch_and_prerelease(self) -> None:
        self.assert_order("pypi", "1!1.0", "2.0", 1)
        self.assert_order("pypi", "2.0rc1", "2.0", -1)
        self.assert_order("pypi", "1.0rc1.dev1", "1.0rc1", -1)
        self.assert_order("pypi", "1.0.dev1", "1.0a1", -1)

    def test_distro_epoch_revision_and_tilde(self) -> None:
        self.assert_order("deb", "1:1.0-2", "1:1.0-1", 1)
        self.assert_order("deb", "1.0~rc1-1", "1.0-1", -1)
        self.assert_order("rpm", "2:1.0-1", "1:9.9-9", 1)
        self.assert_order("alpine", "1.2.3-r2", "1.2.3-r1", 1)

    def test_maven_qualifiers(self) -> None:
        self.assert_order("maven", "1.0-rc1", "1.0", -1)
        self.assert_order("maven", "1.0-sp1", "1.0", 1)

    def test_inclusive_exclusive_and_fixed_boundaries(self) -> None:
        self.assertEqual(
            version_satisfies_range(
                ecosystem="npm",
                installed_version="1.0.0",
                introduced="1.0.0",
                introduced_inclusive=False,
                fixed="2.0.0",
            )[0],
            "not-affected",
        )
        self.assertEqual(
            version_satisfies_range(
                ecosystem="npm",
                installed_version="1.9.9",
                introduced="1.0.0",
                fixed="2.0.0",
            )[0],
            "affected",
        )
        self.assertEqual(
            version_satisfies_range(
                ecosystem="npm",
                installed_version="2.0.0",
                introduced="1.0.0",
                fixed="2.0.0",
            )[0],
            "fixed",
        )

    def test_unparseable_is_unsupported_not_lexically_compared(self) -> None:
        result = compare_versions("pypi", "release-next", "release-old")
        self.assertNotEqual(result.status, "supported")
        self.assertIsNone(result.order)

        long_pre = "1.0.0-" + ".".join(["a"] * 65)
        result = compare_versions("npm", long_pre + ".x", long_pre + ".y")
        self.assertNotEqual(result.status, "supported")
        self.assertIsNone(result.order)

        result = compare_versions("maven", "1.0+unsafe", "1.0")
        self.assertNotEqual(result.status, "supported")


if __name__ == "__main__":
    unittest.main()
