from __future__ import annotations

import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app.classification import (
    CLASSIFIER_VERSION,
    ClassificationEvidence,
    classify_asset,
    evidence_id_for,
    managed_capability_for,
)
from app.classification_service import _load_assets, evaluate_classifications
from app.classification_store import (
    InMemoryClassificationStore,
    classification_evidence_for_asset,
)


NOW = datetime(2026, 7, 30, 16, 0, tzinfo=timezone.utc)


def evidence(
    *,
    source_id: str = "source-a",
    source_type: str = "passive-network-sensor",
    method: str = "mdns",
    kind: str = "mdns-service",
    value: str = "_ipp._tcp.local",
    observed_at: datetime = NOW,
    direct: bool = False,
    strength: str = "medium",
    confidence: float = 0.9,
    observation_count: int = 1,
    source_revoked: bool = False,
) -> ClassificationEvidence:
    return ClassificationEvidence(
        evidence_id=evidence_id_for(
            site_id="site-a",
            asset_id="asset-a",
            source_type=source_type,
            source_id=source_id,
            collection_method=method,
            kind=kind,
            value=value,
        ),
        site_id="site-a",
        asset_id="asset-a",
        source_id=source_id,
        source_type=source_type,
        collection_method=method,
        kind=kind,
        value=value,
        observed_at=observed_at,
        first_seen_at=observed_at,
        last_seen_at=observed_at,
        direct=direct,
        strength=strength,  # type: ignore[arg-type]
        source_confidence=confidence,
        observation_count=observation_count,
        source_revoked=source_revoked,
    )


def direct(
    *,
    kind: str,
    value: str,
    source_id: str = "endpoint-a",
    observed_at: datetime = NOW,
    confidence: float = 0.95,
) -> ClassificationEvidence:
    return evidence(
        source_id=source_id,
        source_type="endpoint-collector",
        method="endpoint-inventory",
        kind=kind,
        value=value,
        observed_at=observed_at,
        direct=True,
        strength="direct",
        confidence=confidence,
    )


class DeterministicClassificationTests(unittest.TestCase):
    def classify(
        self,
        values: list[ClassificationEvidence],
        *,
        now: datetime = NOW,
    ):
        return classify_asset(
            site_id="site-a",
            asset_id="asset-a",
            evidence=values,
            now=now,
        )

    def test_direct_endpoint_windows_and_linux_server_evidence(self) -> None:
        workstation = self.classify([direct(kind="os", value="Windows 11")])
        server = self.classify(
            [
                direct(kind="os", value="Linux Demo"),
                direct(kind="device-role", value="server"),
            ]
        )

        self.assertEqual(workstation.category, "workstation")
        self.assertEqual(workstation.os_family, "Windows")
        self.assertEqual(workstation.status, "classified")
        self.assertEqual(server.category, "server")
        self.assertEqual(server.os_family, "Linux")
        self.assertIn("direct-device-role", server.reason_codes)

    def test_dhcp_vendor_class_is_medium_inference(self) -> None:
        result = self.classify(
            [
                evidence(
                    method="dhcp",
                    kind="dhcp-vendor-class",
                    value="android-demo-client",
                )
            ]
        )

        self.assertEqual(result.category, "mobile")
        self.assertEqual(result.status, "partially-classified")
        self.assertIn("passive-dhcp-vendor-class", result.reason_codes)

    def test_mdns_and_ssdp_protocol_signals(self) -> None:
        printer = self.classify(
            [
                evidence(value="_ipp._tcp.local"),
                evidence(
                    source_id="source-b",
                    method="ssdp",
                    kind="ssdp-device-type",
                    value="urn:schemas-upnp-org:device:Printer:1",
                ),
            ]
        )
        router = self.classify(
            [
                evidence(
                    method="ssdp",
                    kind="ssdp-device-type",
                    value="urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                )
            ]
        )

        self.assertEqual(printer.category, "printer")
        self.assertEqual(printer.independent_source_count, 2)
        self.assertIn("independent-source-agreement", printer.reason_codes)
        self.assertEqual(router.category, "network-device")
        self.assertIn("passive-ssdp-device-type", router.reason_codes)

    def test_nbns_and_hostname_remain_weak(self) -> None:
        result = self.classify(
            [
                evidence(
                    method="nbns",
                    kind="nbns-name",
                    value="DEMO-PRINTER",
                    confidence=0.8,
                )
            ]
        )

        self.assertEqual(result.category, "unknown")
        self.assertEqual(result.status, "insufficient-evidence")
        self.assertIn("passive-nbns-name", result.reason_codes)
        self.assertLess(result.confidence, 0.45)

    def test_oui_sets_manufacturer_but_never_device_type(self) -> None:
        result = self.classify(
            [
                evidence(
                    source_id="catalog:synthetic-1",
                    source_type="vendor-catalog",
                    method="oui",
                    kind="oui-manufacturer",
                    value="Example Camera Works",
                    confidence=0.85,
                )
            ]
        )

        self.assertEqual(result.manufacturer, "Example Camera Works")
        self.assertEqual(result.category, "unknown")
        self.assertIn("vendor-catalog-match", result.reason_codes)

    def test_ip_address_is_not_identity_or_classification(self) -> None:
        result = self.classify(
            [
                evidence(
                    method="network",
                    kind="ip-address",
                    value="192.0.2.25",
                    confidence=1.0,
                )
            ]
        )

        self.assertEqual(result.category, "unknown")
        self.assertEqual(result.status, "unknown")
        self.assertEqual(result.supporting_evidence_ids, ())

    def test_direct_evidence_outranks_passive_inference(self) -> None:
        result = self.classify(
            [
                direct(kind="category", value="server"),
                evidence(
                    method="mdns",
                    kind="mdns-service",
                    value="_smb._tcp.local",
                    confidence=0.55,
                ),
            ]
        )

        self.assertEqual(result.category, "server")
        self.assertEqual(result.status, "classified")
        self.assertFalse(result.conflicts)

    def test_material_independent_disagreement_is_persistable_conflict(self) -> None:
        result = self.classify(
            [
                direct(kind="category", value="server"),
                evidence(
                    source_id="passive-a",
                    method="mdns",
                    kind="mdns-service",
                    value="_ipp._tcp.local",
                    confidence=0.95,
                ),
            ]
        )

        self.assertEqual(result.category, "server")
        self.assertEqual(result.status, "conflicting")
        self.assertEqual(len(result.conflicts), 1)
        self.assertEqual(result.conflicts[0].conflicting_value, "printer")
        self.assertTrue(result.conflicting_evidence_ids)
        self.assertLess(result.confidence, 0.8)

    def test_fresh_direct_os_family_disagreement_is_a_typed_conflict(self) -> None:
        result = self.classify(
            [
                direct(kind="category", value="server", source_id="endpoint-a"),
                direct(kind="os", value="Linux", source_id="endpoint-a"),
                direct(
                    kind="os",
                    value="Windows Server 2025",
                    source_id="endpoint-b",
                ),
            ]
        )

        self.assertEqual(result.status, "conflicting")
        os_conflict = next(
            conflict
            for conflict in result.conflicts
            if conflict.conflict_type == "os-family"
        )
        self.assertEqual(
            {os_conflict.selected_value, os_conflict.conflicting_value},
            {"Linux", "Windows"},
        )
        self.assertTrue(os_conflict.supporting_evidence_ids)
        self.assertTrue(os_conflict.conflicting_evidence_ids)

    def test_stale_direct_os_does_not_override_fresh_os_evidence(self) -> None:
        result = self.classify(
            [
                direct(
                    kind="os",
                    value="Linux",
                    source_id="endpoint-old",
                    observed_at=NOW - timedelta(days=5),
                ),
                evidence(
                    source_id="sensor-fresh",
                    method="observation",
                    kind="os",
                    value="Windows",
                    observed_at=NOW,
                ),
            ]
        )

        self.assertEqual(result.os_family, "Windows")
        self.assertFalse(
            any(
                conflict.conflict_type == "os-family"
                for conflict in result.conflicts
            )
        )

    def test_fresh_inference_outranks_stale_direct_evidence(self) -> None:
        result = self.classify(
            [
                direct(
                    kind="category",
                    value="server",
                    observed_at=NOW - timedelta(days=30),
                ),
                evidence(
                    source_id="passive-current",
                    method="mdns",
                    kind="mdns-service",
                    value="_ipp._tcp.local",
                    observed_at=NOW,
                    confidence=0.95,
                ),
            ]
        )

        self.assertEqual(result.category, "printer")
        self.assertIn("stale-evidence-discounted", result.reason_codes)

    def test_unrelated_fresh_evidence_does_not_freshen_stale_classification(self) -> None:
        result = classify_asset(
            site_id="site-a",
            asset_id="asset-a",
            evidence=[
                evidence(
                    kind="category",
                    value="server",
                    source_id="endpoint-a",
                    direct=True,
                    observed_at=NOW - timedelta(days=5),
                ),
                evidence(
                    kind="ip-address",
                    value="192.0.2.90",
                    source_id="sensor-a",
                    method="arp",
                    observed_at=NOW,
                ),
            ],
            now=NOW,
        )

        self.assertEqual(result.category, "unknown")
        self.assertEqual(result.freshness, "stale")

    def test_latest_same_source_value_replaces_older_value(self) -> None:
        result = self.classify(
            [
                direct(
                    kind="category",
                    value="server",
                    observed_at=NOW - timedelta(hours=2),
                ),
                direct(
                    kind="category",
                    value="workstation",
                    observed_at=NOW,
                ),
            ]
        )

        self.assertEqual(result.category, "workstation")
        self.assertEqual(result.status, "classified")
        self.assertFalse(result.conflicts)

    def test_repeated_same_source_does_not_inflate_independence(self) -> None:
        repeated = evidence(observation_count=50_000)
        one = self.classify([repeated])
        two_independent = self.classify(
            [
                repeated,
                evidence(
                    source_id="source-b",
                    method="ssdp",
                    kind="ssdp-device-type",
                    value="urn:schemas-upnp-org:device:Printer:1",
                ),
            ]
        )

        self.assertEqual(one.independent_source_count, 1)
        self.assertEqual(two_independent.independent_source_count, 2)
        self.assertGreater(two_independent.confidence, one.confidence)

    def test_revoked_sensor_evidence_is_retained_but_discounted(self) -> None:
        result = self.classify(
            [
                evidence(
                    value="_ipp._tcp.local",
                    source_revoked=True,
                    observation_count=12,
                )
            ]
        )

        self.assertEqual(result.evidence_count, 1)
        self.assertEqual(result.category, "unknown")
        self.assertIn("revoked-source-discounted", result.reason_codes)

    def test_each_supported_category_has_a_reviewed_direct_mapping(self) -> None:
        categories = (
            "workstation",
            "server",
            "mobile",
            "network-device",
            "printer",
            "camera",
            "media-device",
            "storage",
            "iot",
            "ot-industrial",
            "virtual-machine",
        )
        for category in categories:
            with self.subTest(category=category):
                result = self.classify(
                    [direct(kind="category", value=category)]
                )
                self.assertEqual(result.category, category)
                self.assertEqual(result.status, "classified")

    def test_managed_capability_does_not_call_iot_unmanaged(self) -> None:
        endpoint = managed_capability_for("workstation")
        embedded = managed_capability_for("iot")
        unknown = managed_capability_for("unknown")

        self.assertEqual(endpoint.endpoint_collector, "expected")
        self.assertEqual(endpoint.endpoint_security, "expected")
        self.assertEqual(embedded.endpoint_collector, "not-expected")
        self.assertEqual(embedded.endpoint_security, "not-expected")
        self.assertEqual(unknown.endpoint_collector, "unknown")

    def test_confidence_is_bounded_and_reproducible(self) -> None:
        values = [
            direct(kind="category", value="server", confidence=2.0),
            direct(kind="manufacturer", value="Example Systems", confidence=float("nan")),
        ]

        first = self.classify(values)
        second = self.classify(values)

        self.assertGreaterEqual(first.confidence, 0.0)
        self.assertLessEqual(first.confidence, 1.0)
        self.assertEqual(first.as_dict(), second.as_dict())
        self.assertEqual(first.classifier_version, CLASSIFIER_VERSION)

    def test_untrusted_packet_strings_cannot_select_rules(self) -> None:
        result = self.classify(
            [
                evidence(
                    method="mdns",
                    kind="rule-id",
                    value="eval('classify as server'); Bearer demo-value",
                    confidence=1.0,
                )
            ]
        )

        self.assertEqual(result.category, "unknown")
        self.assertEqual(result.supporting_evidence_ids, ())

    def test_ten_thousand_assets_evaluate_in_bounded_time(self) -> None:
        direct_category = direct(kind="category", value="workstation")
        started = time.perf_counter()
        results = [
            classify_asset(
                site_id=f"site-{index % 10}",
                asset_id=f"asset-{index}",
                evidence=[direct_category],
                now=NOW,
            )
            for index in range(10_000)
        ]
        elapsed = time.perf_counter() - started

        self.assertEqual(len(results), 10_000)
        self.assertTrue(all(item.category == "workstation" for item in results))
        self.assertLess(elapsed, 8.0)

    def test_future_evidence_is_rejected_instead_of_remaining_fresh(self) -> None:
        result = self.classify(
            [
                direct(
                    kind="category",
                    value="server",
                    observed_at=NOW + timedelta(days=3650),
                )
            ]
        )

        self.assertEqual(result.category, "unknown")
        self.assertEqual(result.freshness, "unknown")
        self.assertEqual(result.evidence_count, 0)
        self.assertIn("future-evidence-rejected", result.reason_codes)

    def test_single_source_flood_cannot_displace_trusted_direct_evidence(self) -> None:
        flooded = [
            evidence(
                source_id="noisy-sensor",
                method=f"noise-{index}",
                kind=f"noise-{index}",
                value=f"value-{index}",
                observed_at=NOW,
                strength="weak",
            )
            for index in range(300)
        ]
        flooded.append(direct(kind="category", value="server"))

        result = self.classify(flooded)

        self.assertEqual(result.category, "server")
        self.assertEqual(result.status, "classified")
        self.assertLessEqual(result.evidence_count, 256)


class ClassificationEvidenceProjectionTests(unittest.TestCase):
    def test_endpoint_and_passive_evidence_are_source_aware(self) -> None:
        asset = {
            "site_id": "site-a",
            "asset_id": "asset-a",
            "hostname": "demo-workstation",
            "os": "Windows 11",
            "platform": "Windows/amd64",
            "source_agent_id": "endpoint-a",
            "metadata": {
                "category": "workstation",
                "evidence": [
                    {
                        "protocol": "mdns",
                        "kind": "mdns-service",
                        "value": "_workstation._tcp.local",
                        "confidence": 0.7,
                    }
                ],
            },
        }
        endpoint = classification_evidence_for_asset(
            asset=asset,
            payload={
                "site_id": "site-a",
                "sensor_id": "endpoint-a",
                "sensor_type": "endpoint-collector",
                "observation_source": "endpoint-inventory",
                "confidence": 0.9,
            },
            observed_at=NOW,
            source_authenticated=True,
        )
        passive = classification_evidence_for_asset(
            asset=asset,
            payload={
                "site_id": "site-a",
                "sensor_id": "sensor-a",
                "sensor_type": "passive-network-sensor",
                "observation_source": "passive-network",
                "confidence": 0.8,
            },
            observed_at=NOW,
            source_authenticated=True,
        )

        endpoint_category = next(item for item in endpoint if item.kind == "category")
        passive_category = next(item for item in passive if item.kind == "category")
        self.assertTrue(endpoint_category.direct)
        self.assertFalse(passive_category.direct)
        self.assertNotEqual(endpoint_category.evidence_id, passive_category.evidence_id)

    def test_payload_claims_do_not_create_direct_endpoint_authority(self) -> None:
        asset = {
            "site_id": "site-a",
            "asset_id": "asset-a",
            "source_agent_id": "claimed-agent",
            "metadata": {"category": "server"},
        }
        payload = {
            "site_id": "site-a",
            "agent_id": "claimed-agent",
            "sensor_type": "endpoint-collector",
            "observation_source": "endpoint-inventory",
        }

        untrusted = classification_evidence_for_asset(
            asset=asset,
            payload=payload,
            observed_at=NOW,
        )
        authenticated = classification_evidence_for_asset(
            asset=asset,
            payload=payload,
            observed_at=NOW,
            source_authenticated=True,
        )

        self.assertFalse(next(item for item in untrusted if item.kind == "category").direct)
        self.assertTrue(next(item for item in authenticated if item.kind == "category").direct)
        self.assertEqual(
            {item.source_id for item in untrusted},
            {"untrusted-local-inventory"},
        )
        self.assertEqual(
            {item.source_type for item in untrusted},
            {"untrusted-ingestion"},
        )
        self.assertEqual(
            classify_asset(
                site_id="site-a",
                asset_id="asset-a",
                evidence=untrusted,
                now=NOW,
            ).category,
            "unknown",
        )

    def test_untrusted_payloads_cannot_inflate_independent_source_agreement(self) -> None:
        def records_for(claimed_agent: str) -> tuple[ClassificationEvidence, ...]:
            return classification_evidence_for_asset(
                asset={
                    "site_id": "site-a",
                    "asset_id": "asset-a",
                    "source_agent_id": claimed_agent,
                    "os": "Windows 11",
                },
                payload={
                    "agent_id": claimed_agent,
                    "sensor_type": "endpoint-collector",
                    "observation_source": "endpoint-inventory",
                },
                observed_at=NOW,
            )

        first = records_for("claimed-agent-a")
        second = records_for("claimed-agent-b")

        self.assertEqual(
            {item.source_key for item in (*first, *second)},
            {"untrusted-ingestion\0untrusted-local-inventory"},
        )
        self.assertEqual(
            len({item.evidence_id for item in (*first, *second)}),
            len({item.evidence_id for item in first}),
        )

    def test_sensitive_evidence_kinds_are_not_persisted(self) -> None:
        records = classification_evidence_for_asset(
            asset={
                "site_id": "site-a",
                "asset_id": "asset-a",
                "source_agent_id": "sensor-a",
                "metadata": {
                    "evidence": [
                        {
                            "protocol": "http",
                            "kind": "authorization-token",
                            "value": "not-a-real-secret",
                            "confidence": 1.0,
                        },
                        {
                            "protocol": "ethernet",
                            "kind": "raw-packet",
                            "value": "deadbeef",
                            "confidence": 1.0,
                        },
                        {
                            "protocol": "http",
                            "kind": "api-key",
                            "value": "synthetic-sensitive-marker",
                            "confidence": 1.0,
                        },
                        {
                            "protocol": "http",
                            "kind": "session-cookie",
                            "value": "synthetic-sensitive-marker",
                            "confidence": 1.0,
                        },
                        {
                            "protocol": "ethernet",
                            "kind": "packet-bytes",
                            "value": "deadbeef",
                            "confidence": 1.0,
                        },
                        {
                            "protocol": "custom",
                            "kind": "unreviewed-kind",
                            "value": "must-not-be-retained",
                            "confidence": 1.0,
                        },
                        {
                            "protocol": "mdns",
                            "kind": "mdns-service",
                            "value": "_ipp._tcp.local",
                            "confidence": 0.8,
                        },
                    ]
                },
            },
            payload={
                "site_id": "site-a",
                "sensor_id": "sensor-a",
                "sensor_type": "passive-network-sensor",
                "observation_source": "passive-network",
            },
            observed_at=NOW,
        )

        self.assertNotIn("authorization-token", {item.kind for item in records})
        self.assertNotIn("raw-packet", {item.kind for item in records})
        self.assertNotIn("api-key", {item.kind for item in records})
        self.assertNotIn("session-cookie", {item.kind for item in records})
        self.assertNotIn("packet-bytes", {item.kind for item in records})
        self.assertNotIn("unreviewed-kind", {item.kind for item in records})
        self.assertIn("mdns-service", {item.kind for item in records})


class ClassificationLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryClassificationStore()
        self.asset = {"site_id": "site-a", "asset_id": "asset-a"}

    def evaluate(
        self,
        values: list[ClassificationEvidence],
        *,
        now: datetime,
    ):
        self.store.evidence[("site-a", "asset-a")] = values
        return evaluate_classifications(
            trigger_type="unit-test",
            requested_by="unit-test",
            site_id="site-a",
            asset_id="asset-a",
            now=now,
            store=self.store,
            assets=[self.asset],
            reevaluate_findings=False,
        )

    def test_stable_repeat_and_reclassification_preserve_history(self) -> None:
        first = self.evaluate(
            [evidence(value="_ipp._tcp.local")],
            now=NOW,
        )
        repeated = self.evaluate(
            [evidence(value="_ipp._tcp.local")],
            now=NOW,
        )
        reclassified = self.evaluate(
            [direct(kind="category", value="server", observed_at=NOW + timedelta(minutes=1))],
            now=NOW + timedelta(minutes=1),
        )

        self.assertEqual(first.assets_changed, 1)
        self.assertEqual(repeated.assets_changed, 0)
        self.assertEqual(reclassified.assets_changed, 1)
        self.assertEqual(len(self.store.history), 1)
        current = self.store.current(site_id="site-a", asset_id="asset-a")
        self.assertEqual(current["category"], "server")
        self.assertEqual(current["first_classified_at"], NOW)

    def test_targeted_scope_does_not_evaluate_unrequested_asset(self) -> None:
        other = {"site_id": "site-a", "asset_id": "asset-b"}
        self.store.evidence[("site-a", "asset-a")] = [
            direct(kind="category", value="server")
        ]

        result = evaluate_classifications(
            trigger_type="unit-test",
            site_id="site-a",
            asset_id="asset-a",
            now=NOW,
            store=self.store,
            assets=[self.asset, other],
            reevaluate_findings=False,
        )

        self.assertEqual(result.assets_evaluated, 1)
        self.assertIsNone(
            self.store.current(site_id="site-a", asset_id="asset-b")
        )

    def test_site_evaluation_loads_evidence_in_bounded_batches(self) -> None:
        class RecordingStore(InMemoryClassificationStore):
            def __init__(self) -> None:
                super().__init__()
                self.load_sizes: list[int] = []

            def load_evidence(self, *, site_id, asset_ids):
                self.load_sizes.append(len(asset_ids))
                return super().load_evidence(
                    site_id=site_id,
                    asset_ids=asset_ids,
                )

        store = RecordingStore()
        assets = [
            {"site_id": "site-a", "asset_id": f"asset-{index:04d}"}
            for index in range(1001)
        ]

        result = evaluate_classifications(
            trigger_type="site-rebuild",
            site_id="site-a",
            now=NOW,
            store=store,
            assets=assets,
            reevaluate_findings=False,
        )

        self.assertEqual(result.assets_evaluated, 1001)
        self.assertEqual(store.load_sizes, [500, 500, 1])

    def test_targeted_asset_load_pushes_scope_into_database_query(self) -> None:
        with patch(
            "app.database.list_control_tower_assets",
            return_value=[self.asset],
        ) as list_assets:
            loaded = _load_assets(site_id="site-a", asset_ids=["asset-a"])

        self.assertEqual(loaded, [self.asset])
        list_assets.assert_called_once_with(
            limit=2,
            site_id="site-a",
            asset_ids=["asset-a"],
        )

    def test_older_evaluation_cannot_overwrite_newer_classification(self) -> None:
        newer = self.evaluate(
            [
                direct(
                    kind="category",
                    value="server",
                    observed_at=NOW + timedelta(minutes=2),
                )
            ],
            now=NOW + timedelta(minutes=2),
        )
        older = self.evaluate(
            [direct(kind="category", value="printer", observed_at=NOW)],
            now=NOW,
        )

        self.assertEqual(newer.assets_changed, 1)
        self.assertEqual(older.assets_changed, 0)
        self.assertEqual(
            self.store.current(site_id="site-a", asset_id="asset-a")["category"],
            "server",
        )

    def test_semantic_change_triggers_one_targeted_finding_and_risk_evaluation(
        self,
    ) -> None:
        self.store.evidence[("site-a", "asset-a")] = [
            direct(kind="category", value="server")
        ]
        with patch(
            "app.finding_service.evaluate_findings",
        ) as evaluate_findings:
            first = evaluate_classifications(
                trigger_type="endpoint-ingestion",
                site_id="site-a",
                asset_id="asset-a",
                now=NOW,
                store=self.store,
                assets=[self.asset],
            )
            repeated = evaluate_classifications(
                trigger_type="endpoint-ingestion",
                site_id="site-a",
                asset_id="asset-a",
                now=NOW,
                store=self.store,
                assets=[self.asset],
            )

        self.assertEqual(first.finding_evaluations, 1)
        self.assertEqual(repeated.finding_evaluations, 0)
        evaluate_findings.assert_called_once_with(
            trigger_type="classification:endpoint-ingestion",
            requested_by="classification-engine",
            site_id="site-a",
            asset_id="asset-a",
        )

    def test_multi_asset_change_uses_one_site_finding_and_risk_evaluation(
        self,
    ) -> None:
        second = {"site_id": "site-a", "asset_id": "asset-b"}
        evidence_by_asset = {
            ("site-a", "asset-a"): [
                direct(kind="category", value="server", source_id="endpoint-a")
            ],
            ("site-a", "asset-b"): [
                ClassificationEvidence(
                    **{
                        **direct(
                            kind="category",
                            value="workstation",
                            source_id="endpoint-b",
                        ).__dict__,
                        "asset_id": "asset-b",
                        "evidence_id": evidence_id_for(
                            site_id="site-a",
                            asset_id="asset-b",
                            source_type="endpoint-collector",
                            source_id="endpoint-b",
                            collection_method="endpoint-inventory",
                            kind="category",
                            value="workstation",
                        ),
                    }
                )
            ],
        }
        with patch(
            "app.finding_service.evaluate_findings",
        ) as evaluate_findings:
            result = evaluate_classifications(
                trigger_type="observation-ingestion",
                requested_by="sensor-a",
                site_id="site-a",
                now=NOW,
                store=self.store,
                assets=[self.asset, second],
                evidence_by_asset=evidence_by_asset,
            )

        self.assertEqual(result.assets_changed, 2)
        self.assertEqual(result.finding_evaluations, 1)
        evaluate_findings.assert_called_once_with(
            trigger_type="classification:observation-ingestion",
            requested_by="sensor-a",
            site_id="site-a",
            asset_id=None,
        )


if __name__ == "__main__":
    unittest.main()
