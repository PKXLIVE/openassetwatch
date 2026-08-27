from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pydantic import ValidationError

from app.component_intelligence import (
    ComponentSourceSnapshot,
    component_source_snapshots_for_asset,
    normalize_components_for_asset,
)
from app.component_store import _apply_complete_source_snapshot
from app.endpoint_agent_contracts import EndpointInventoryRequest


NOW = datetime.now(timezone.utc).replace(microsecond=0)
COLLECTION_ID = "col_" + "1" * 32
AGENT_SOURCE_ID = "src_" + "2" * 32


def endpoint_payload(
    *,
    status: str = "complete",
    component: bool = True,
    source_id: str = "linux-dpkg",
    observed_at: datetime = NOW,
) -> dict[str, object]:
    components = []
    if component:
        components.append(
            {
                "component_type": "operating-system-package",
                "ecosystem": "deb",
                "name": "fictional-package",
                "version": "1:2.3-1",
                "package_manager": "dpkg",
                "install_scope": "system",
                "collection_source_id": source_id,
                "source_record_id": "fictional-package:amd64",
                "evidence_method": "dpkg-native-query",
                "observed_at": observed_at.isoformat(),
                "confidence": 0.95,
            }
        )
    source: dict[str, object] = {
        "source_id": source_id,
        "platform": "linux",
        "status": status,
        "observed_at": observed_at.isoformat(),
        "record_count": len(components),
        "truncated": False,
    }
    if status == "partial":
        source["limitations"] = ["malformed-records-skipped"]
    if status in {"failed", "unsupported"}:
        source["error_code"] = "package-manager-unavailable"
    return {
        "schema_version": "oaw.endpoint-inventory.v1",
        "inventory_batch_id": "batch_native_software_0001",
        "observed_at": observed_at.isoformat(),
        "inventory_mode": "complete",
        "platform": "linux",
        "software_sources": [source],
        "assets": [{"asset_id": "asset-fictional", "components": components}],
    }


def windows_endpoint_payload() -> dict[str, object]:
    payload = endpoint_payload(source_id="windows-uninstall-64")
    payload["platform"] = "windows"
    payload["software_sources"][0]["platform"] = "windows"
    component = payload["assets"][0]["components"][0]
    component.update(
        {
            "component_type": "application",
            "ecosystem": "generic",
            "package_manager": "windows-registry",
            "source_record_id": "{00000000-0000-0000-0000-000000000001}",
            "evidence_method": "windows-uninstall-registry",
        }
    )
    return payload


class NativeSoftwareContractTests(unittest.TestCase):
    def test_complete_source_is_bounded_and_component_linkage_is_required(self) -> None:
        request = EndpointInventoryRequest.model_validate(endpoint_payload())
        self.assertEqual(request.software_sources[0].record_count, 1)
        self.assertEqual(
            request.assets[0].components[0].collection_source_id,
            "linux-dpkg",
        )

        invalid = endpoint_payload()
        invalid["assets"][0]["components"][0]["evidence_ids"] = ["client-id"]
        with self.assertRaisesRegex(ValidationError, "server-issued"):
            EndpointInventoryRequest.model_validate(invalid)

    def test_unreviewed_cross_platform_and_count_mismatches_fail_closed(self) -> None:
        unreviewed = endpoint_payload(source_id="linux-shell")
        cross_platform = endpoint_payload()
        cross_platform["software_sources"][0]["platform"] = "windows"
        mismatch = endpoint_payload()
        mismatch["software_sources"][0]["record_count"] = 0
        for payload in (unreviewed, cross_platform, mismatch):
            with self.subTest(payload=payload), self.assertRaises(ValidationError):
                EndpointInventoryRequest.model_validate(payload)

    def test_native_source_scope_cannot_span_multiple_endpoint_assets(self) -> None:
        payload = endpoint_payload()
        payload["assets"].append({"asset_id": "asset-fictional-second"})
        with self.assertRaisesRegex(ValidationError, "exactly one endpoint asset"):
            EndpointInventoryRequest.model_validate(payload)

    def test_native_component_must_match_reviewed_source_contract(self) -> None:
        wrong_ecosystem = endpoint_payload()
        wrong_ecosystem["assets"][0]["components"][0]["ecosystem"] = "pypi"
        wrong_manager = endpoint_payload()
        wrong_manager["assets"][0]["components"][0]["package_manager"] = "rpm"
        wrong_method = endpoint_payload()
        wrong_method["assets"][0]["components"][0]["evidence_method"] = "shell"
        wrong_scope = endpoint_payload()
        wrong_scope["assets"][0]["components"][0]["install_scope"] = "user"
        for payload in (wrong_ecosystem, wrong_manager, wrong_method, wrong_scope):
            with self.subTest(payload=payload), self.assertRaises(ValidationError):
                EndpointInventoryRequest.model_validate(payload)

    def test_windows_registry_view_cannot_claim_package_architecture(self) -> None:
        valid = EndpointInventoryRequest.model_validate(windows_endpoint_payload())
        self.assertIsNone(valid.assets[0].components[0].architecture)

        asserted_architecture = windows_endpoint_payload()
        asserted_architecture["assets"][0]["components"][0]["architecture"] = "amd64"
        with self.assertRaisesRegex(
            ValidationError,
            "native component fields do not match the reviewed source contract",
        ):
            EndpointInventoryRequest.model_validate(asserted_architecture)

    def test_native_component_time_and_source_record_are_bound_to_snapshot(self) -> None:
        future_component = endpoint_payload()
        future_component["assets"][0]["components"][0]["observed_at"] = (
            NOW + timedelta(seconds=1)
        ).isoformat()
        duplicate_record = endpoint_payload()
        duplicate_record["assets"][0]["components"].append(
            dict(duplicate_record["assets"][0]["components"][0])
        )
        duplicate_record["software_sources"][0]["record_count"] = 2
        for payload in (future_component, duplicate_record):
            with self.subTest(payload=payload), self.assertRaises(ValidationError):
                EndpointInventoryRequest.model_validate(payload)

    def test_component_metadata_is_bounded_and_control_character_free(self) -> None:
        oversized = endpoint_payload()
        oversized["assets"][0]["components"][0]["metadata"] = {
            "install_state": "x" * 241
        }
        unsafe_key = endpoint_payload()
        unsafe_key["assets"][0]["components"][0]["metadata"] = {
            "Install Path": "not retained"
        }
        with self.assertRaises(ValidationError):
            EndpointInventoryRequest.model_validate(oversized)
        with self.assertRaises(ValidationError):
            EndpointInventoryRequest.model_validate(unsafe_key)

    def test_unsuccessful_or_ambiguous_complete_status_cannot_withdraw(self) -> None:
        failed_with_record = endpoint_payload(status="failed")
        complete_truncated = endpoint_payload()
        complete_truncated["software_sources"][0]["truncated"] = True
        partial_without_reason = endpoint_payload(status="partial")
        partial_without_reason["software_sources"][0].pop("limitations")
        for payload in (failed_with_record, complete_truncated, partial_without_reason):
            with self.subTest(payload=payload), self.assertRaises(ValidationError):
                EndpointInventoryRequest.model_validate(payload)

    def test_stale_or_future_source_time_is_rejected(self) -> None:
        stale = endpoint_payload(observed_at=NOW)
        stale["software_sources"][0]["observed_at"] = (
            NOW + timedelta(minutes=6)
        ).isoformat()
        with self.assertRaises(ValidationError):
            EndpointInventoryRequest.model_validate(stale)


class NativeSoftwareNormalizationTests(unittest.TestCase):
    def _asset_payload(self, request: EndpointInventoryRequest) -> tuple[dict, dict]:
        raw = request.model_dump(mode="json")
        asset = {
            **raw["assets"][0],
            "site_id": "site-fictional",
            "asset_id": "asset-fictional",
            "source_agent_id": AGENT_SOURCE_ID,
        }
        payload = {
            **raw,
            "site_id": "site-fictional",
            "sensor_id": AGENT_SOURCE_ID,
            "sensor_type": "endpoint-collector",
            "observation_source": "endpoint-inventory",
        }
        return asset, payload

    def test_snapshot_and_evidence_ids_are_server_derived_and_stable(self) -> None:
        request = EndpointInventoryRequest.model_validate(endpoint_payload())
        asset, payload = self._asset_payload(request)
        components = normalize_components_for_asset(
            asset=asset,
            payload=payload,
            received_at=NOW,
            source_authenticated=True,
        )
        snapshots = component_source_snapshots_for_asset(
            asset=asset,
            payload=payload,
            received_at=NOW,
            source_authenticated=True,
            canonical_collection_id=COLLECTION_ID,
        )
        self.assertEqual(len(components), 1)
        self.assertRegex(components[0].evidence_ids[0], r"^cpe_[0-9a-f]{32}$")
        self.assertEqual(len(snapshots), 1)
        self.assertRegex(snapshots[0].source_snapshot_id, r"^css_[0-9a-f]{32}$")
        self.assertEqual(snapshots[0].record_count, 1)

        repeated = component_source_snapshots_for_asset(
            asset=asset,
            payload=payload,
            received_at=NOW,
            source_authenticated=True,
            canonical_collection_id=COLLECTION_ID,
        )
        self.assertEqual(repeated, snapshots)

    def test_untrusted_or_noncanonical_input_cannot_create_source_snapshot(self) -> None:
        request = EndpointInventoryRequest.model_validate(endpoint_payload())
        asset, payload = self._asset_payload(request)
        for authenticated, collection_id in (
            (False, COLLECTION_ID),
            (True, None),
            (True, "client-chosen-id"),
        ):
            with self.subTest(authenticated=authenticated, collection_id=collection_id):
                self.assertEqual(
                    component_source_snapshots_for_asset(
                        asset=asset,
                        payload=payload,
                        received_at=NOW,
                        source_authenticated=authenticated,
                        canonical_collection_id=collection_id,
                    ),
                    (),
                )

    def test_authorized_two_thousand_record_snapshot_is_not_silently_truncated(self) -> None:
        payload = endpoint_payload()
        prototype = payload["assets"][0]["components"][0]
        payload["assets"][0]["components"] = [
            {
                **prototype,
                "name": f"fictional-package-{index:04d}",
                "source_record_id": f"fictional-package-{index:04d}:amd64",
            }
            for index in range(2_000)
        ]
        payload["software_sources"][0]["record_count"] = 2_000
        request = EndpointInventoryRequest.model_validate(payload)
        asset, canonical_payload = self._asset_payload(request)

        components = normalize_components_for_asset(
            asset=asset,
            payload=canonical_payload,
            received_at=NOW,
            source_authenticated=True,
        )
        snapshots = component_source_snapshots_for_asset(
            asset=asset,
            payload=canonical_payload,
            received_at=NOW,
            source_authenticated=True,
            canonical_collection_id=COLLECTION_ID,
        )

        self.assertEqual(len(components), 2_000)
        self.assertEqual(snapshots[0].record_count, 2_000)


class _Result:
    def __init__(self, *, rows=(), scalar=None) -> None:
        self.rows = list(rows)
        self.scalar = scalar

    def mappings(self) -> "_Result":
        return self

    def all(self) -> list[dict[str, object]]:
        return self.rows

    def scalar_one_or_none(self) -> object:
        return self.scalar


class _PresenceConnection:
    def __init__(self, *, any_active: bool) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.any_active = any_active

    def execute(self, statement: object, params: dict[str, object] | None = None) -> _Result:
        sql = str(statement)
        values = params or {}
        self.calls.append((sql, values))
        if "SELECT component_id, source_record_id" in sql:
            return _Result(rows=[{"component_id": "cmp_" + "3" * 32, "source_record_id": "pkg:amd64"}])
        if "UPDATE component_source_presence" in sql:
            return _Result(scalar=values["component_id"])
        if "SELECT 1" in sql and "component_source_presence" in sql:
            return _Result(scalar=1 if self.any_active else None)
        return _Result()


class NativeSoftwarePresenceTests(unittest.TestCase):
    def _snapshot(self, status: str) -> ComponentSourceSnapshot:
        return ComponentSourceSnapshot(
            source_snapshot_id="css_" + "4" * 32,
            canonical_collection_id=COLLECTION_ID,
            site_id="site-fictional",
            asset_id="asset-fictional",
            agent_source_id=AGENT_SOURCE_ID,
            collection_source_id="linux-dpkg",
            platform="linux",
            collection_status=status,
            observed_at=NOW,
            record_count=0,
            truncated=False,
            error_code=None,
            limitations=(),
        )

    def test_only_complete_source_omission_retires_presence(self) -> None:
        partial = _PresenceConnection(any_active=False)
        self.assertEqual(
            _apply_complete_source_snapshot(
                partial,
                snapshot=self._snapshot("partial"),
                observed_ids=set(),
            ),
            0,
        )
        self.assertEqual(partial.calls, [])

        complete = _PresenceConnection(any_active=False)
        self.assertEqual(
            _apply_complete_source_snapshot(
                complete,
                snapshot=self._snapshot("complete"),
                observed_ids=set(),
            ),
            1,
        )
        sql = "\n".join(call[0] for call in complete.calls)
        self.assertIn("UPDATE component_source_presence", sql)
        self.assertIn("AND site_id = :site_id", sql)
        self.assertIn("AND asset_id = :asset_id", sql)
        self.assertIn("AND agent_source_id = :agent_source_id", sql)
        self.assertIn("AND collection_source_id = :collection_source_id", sql)
        self.assertIn("AND last_observed_at <= :observed_at", sql)
        self.assertIn("UPDATE asset_components", sql)
        self.assertIn("'not-observed'", sql)
        self.assertNotIn("DELETE FROM", sql)

    def test_shared_component_stays_active_while_another_source_is_present(self) -> None:
        connection = _PresenceConnection(any_active=True)
        self.assertEqual(
            _apply_complete_source_snapshot(
                connection,
                snapshot=self._snapshot("complete"),
                observed_ids=set(),
            ),
            1,
        )
        sql = "\n".join(call[0] for call in connection.calls)
        self.assertNotIn("UPDATE asset_components", sql)
        history = next(params for query, params in connection.calls if "'not-observed'" in query)
        self.assertTrue(history["any_active"])


class NativeSoftwareUiTests(unittest.TestCase):
    def test_native_source_and_component_state_use_text_safe_rendering(self) -> None:
        page = (
            Path(__file__).resolve().parents[1] / "app" / "static" / "index.html"
        ).read_text(encoding="utf-8")
        component_render = page[
            page.index('const componentSection = document.createElement("section")') :
            page.index('const vulnerabilitySection = document.createElement("section")')
        ]
        source_render = page[
            page.index("const softwareSources = Array.isArray(agent.software_sources)") :
            page.index("function renderEvidence(data)")
        ]
        for rendered in (component_render, source_render):
            self.assertNotIn("innerHTML", rendered)
            self.assertIn("textContent", rendered)
            self.assertIn("text(source.", rendered)
        self.assertIn('component.active ? "current" : "no longer observed"', component_render)
        self.assertIn("last_successful_complete_at", source_render)


if __name__ == "__main__":
    unittest.main()
