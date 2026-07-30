from __future__ import annotations

import time
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app.finding_service import evaluate_findings
from app.finding_store import InMemoryFindingStore
from app.findings import (
    RULE_REGISTRY,
    FindingsConfig,
    evaluate_rules,
    load_findings_config,
)


NOW = datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc)


def site(site_id: str = "site-a") -> dict:
    return {"site_id": site_id, "name": site_id}


def sensor(
    sensor_id: str = "sensor-a",
    *,
    site_id: str = "site-a",
    agent_type: str = "network-sensor",
    minutes_ago: int = 5,
) -> dict:
    return {
        "agent_id": sensor_id,
        "site_id": site_id,
        "agent_type": agent_type,
        "identity_status": "active",
        "last_seen_at": NOW - timedelta(minutes=minutes_ago),
    }


def asset(
    asset_id: str,
    *,
    site_id: str = "site-a",
    category: str = "server",
    source_agent_id: str = "agent-a",
    hours_ago: int = 1,
    first_seen_hours_ago: int = 2,
    mac: str | None = None,
    security_coverage: str | None = None,
    confidence: float = 0.9,
) -> dict:
    metadata = {"category": category}
    if security_coverage is not None:
        metadata["security_coverage"] = security_coverage
    return {
        "asset_id": asset_id,
        "site_id": site_id,
        "source_agent_id": source_agent_id,
        "mac": mac,
        "observed_at": NOW - timedelta(hours=hours_ago),
        "last_seen_at": NOW - timedelta(hours=hours_ago),
        "first_seen_at": NOW - timedelta(hours=first_seen_hours_ago),
        "confidence": confidence,
        "metadata": metadata,
    }


class FindingRuleTests(unittest.TestCase):
    def test_registry_is_explicit_unique_and_has_no_dynamic_loader(self) -> None:
        rule_ids = [rule.rule_id for rule in RULE_REGISTRY]

        self.assertEqual(len(rule_ids), len(set(rule_ids)))
        self.assertEqual(
            set(rule_ids),
            {
                "sensor-stale",
                "asset-stale",
                "unknown-asset",
                "passive-only-asset",
                "security-coverage-gap",
                "identity-conflict",
            },
        )
        self.assertTrue(all(rule.required_evidence for rule in RULE_REGISTRY))
        self.assertTrue(all(rule.remediation_guidance for rule in RULE_REGISTRY))
        self.assertTrue(all(rule.resolution_behavior for rule in RULE_REGISTRY))

    def test_rules_detect_supported_conditions_with_separate_confidence(self) -> None:
        snapshot = evaluate_rules(
            sites=[site()],
            sensors=[
                sensor("sensor-stale", minutes_ago=180),
                sensor("agent-a", agent_type="endpoint-agent"),
                sensor("passive-a", agent_type="network-sensor"),
            ],
            assets=[
                asset("unknown-a", category="unknown", source_agent_id="agent-a"),
                asset("stale-a", source_agent_id="agent-a", hours_ago=96),
                asset("passive-a", category="workstation", source_agent_id="passive-a"),
                asset(
                    "coverage-a",
                    source_agent_id="agent-a",
                    security_coverage="missing",
                    confidence=0.63,
                ),
            ],
            now=NOW,
        )
        by_rule = {candidate.rule_id: candidate for candidate in snapshot.candidates}

        self.assertIn("sensor-stale", by_rule)
        self.assertIn("asset-stale", by_rule)
        self.assertIn("unknown-asset", by_rule)
        self.assertIn("passive-only-asset", by_rule)
        self.assertIn("security-coverage-gap", by_rule)
        self.assertEqual(by_rule["security-coverage-gap"].severity, "high")
        self.assertAlmostEqual(by_rule["security-coverage-gap"].confidence, 0.63)

    def test_iot_category_alone_does_not_create_security_gap_or_unmanaged_rule(self) -> None:
        snapshot = evaluate_rules(
            sites=[site()],
            sensors=[sensor("agent-a", agent_type="endpoint-agent")],
            assets=[asset("camera-a", category="iot", source_agent_id="agent-a")],
            now=NOW,
        )

        self.assertNotIn("security-coverage-gap", {item.rule_id for item in snapshot.candidates})
        self.assertNotIn("passive-only-asset", {item.rule_id for item in snapshot.candidates})

    def test_passive_sensor_cannot_assert_endpoint_security_coverage_gap(self) -> None:
        snapshot = evaluate_rules(
            sites=[site()],
            sensors=[sensor("passive-a", agent_type="network-sensor")],
            assets=[
                asset(
                    "camera-a",
                    category="workstation",
                    source_agent_id="passive-a",
                    security_coverage="missing",
                )
            ],
            now=NOW,
        )

        self.assertNotIn("security-coverage-gap", {item.rule_id for item in snapshot.candidates})
        self.assertIn("passive-only-asset", {item.rule_id for item in snapshot.candidates})

    def test_passive_only_requires_fresh_managed_device_evidence(self) -> None:
        snapshot = evaluate_rules(
            sites=[site()],
            sensors=[sensor("passive-a", agent_type="network-sensor")],
            assets=[
                asset("camera-a", category="camera", source_agent_id="passive-a"),
                asset(
                    "stale-server",
                    category="server",
                    source_agent_id="passive-a",
                    hours_ago=100,
                ),
            ],
            now=NOW,
            rule_ids=["passive-only-asset"],
        )

        self.assertEqual(snapshot.candidates, ())

    def test_security_gap_requires_fresh_endpoint_evidence(self) -> None:
        snapshot = evaluate_rules(
            sites=[site()],
            sensors=[sensor("agent-a", agent_type="endpoint-agent")],
            assets=[
                asset(
                    "stale-server",
                    source_agent_id="agent-a",
                    security_coverage="missing",
                    hours_ago=100,
                )
            ],
            now=NOW,
            rule_ids=["security-coverage-gap"],
        )

        self.assertEqual(snapshot.candidates, ())

    def test_identity_correlation_is_site_scoped_and_ignores_hostname_ip_and_invalid_mac(self) -> None:
        same_site_a = asset("asset-a", site_id="site-a", mac=None)
        same_site_b = asset("asset-b", site_id="site-a", mac="not-a-mac")
        other_site = asset(
            "asset-c",
            site_id="site-b",
            mac="02:00:5e:10:20:30",
        )
        same_site_a.update(hostname="shared-name", primary_ip="192.0.2.50")
        same_site_b.update(hostname="shared-name", primary_ip="192.0.2.50")

        snapshot = evaluate_rules(
            sites=[site("site-a"), site("site-b")],
            sensors=[],
            assets=[same_site_a, same_site_b, other_site],
            now=NOW,
            rule_ids=["identity-conflict"],
        )

        self.assertEqual(snapshot.candidates, ())

    def test_non_identity_mac_values_do_not_create_identity_conflicts(self) -> None:
        for value in (
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
            "01:00:5e:00:00:fb",
            "33:33:00:00:00:fb",
        ):
            with self.subTest(mac=value):
                snapshot = evaluate_rules(
                    sites=[site()],
                    sensors=[],
                    assets=[
                        asset("asset-a", mac=value),
                        asset("asset-b", mac=value),
                    ],
                    now=NOW,
                    rule_ids=["identity-conflict"],
                )

                self.assertEqual(snapshot.candidates, ())

    def test_only_the_stale_sensor_gets_a_sensor_scoped_finding(self) -> None:
        snapshot = evaluate_rules(
            sites=[site()],
            sensors=[
                sensor("healthy", minutes_ago=2),
                sensor("stale", minutes_ago=180),
            ],
            assets=[],
            now=NOW,
            rule_ids=["sensor-stale"],
        )

        self.assertEqual(
            [(item.subject_type, item.sensor_id) for item in snapshot.candidates],
            [("sensor", "stale")],
        )

    def test_identity_conflict_does_not_persist_raw_hardware_address(self) -> None:
        shared_mac = "02:00:5e:10:20:30"
        snapshot = evaluate_rules(
            sites=[site()],
            sensors=[sensor("agent-a", agent_type="endpoint-agent")],
            assets=[
                asset("asset-a", source_agent_id="agent-a", mac=shared_mac),
                asset("asset-b", source_agent_id="agent-a", mac=shared_mac),
            ],
            now=NOW,
        )
        conflicts = [item for item in snapshot.candidates if item.rule_id == "identity-conflict"]

        self.assertEqual(len(conflicts), 2)
        serialized = repr(conflicts)
        self.assertNotIn(shared_mac, serialized)
        self.assertTrue(all(len(item.evidence) == 2 for item in conflicts))

    def test_asset_target_keeps_site_context_for_identity_correlation(self) -> None:
        shared_mac = "02:00:5e:10:20:30"

        snapshot = evaluate_rules(
            sites=[site()],
            sensors=[sensor("agent-a", agent_type="endpoint-agent")],
            assets=[
                asset("asset-a", source_agent_id="agent-a", mac=shared_mac),
                asset("asset-b", source_agent_id="agent-a", mac=shared_mac),
            ],
            now=NOW,
            rule_ids=["identity-conflict"],
            site_id="site-a",
            asset_id="asset-a",
        )

        self.assertEqual(
            [(item.rule_id, item.asset_id) for item in snapshot.candidates],
            [("identity-conflict", "asset-a")],
        )
        self.assertEqual(snapshot.asset_count, 1)

    def test_threshold_configuration_is_bounded_and_invalid_values_fall_back(self) -> None:
        config = load_findings_config(
            {
                "OPENASSETWATCH_FINDINGS_SENSOR_STALE_MINUTES": "999999",
                "OPENASSETWATCH_FINDINGS_ASSET_STALE_HOURS": "not-an-int",
                "OPENASSETWATCH_FINDINGS_EVIDENCE_FRESH_HOURS": "0",
                "OPENASSETWATCH_FINDINGS_EVIDENCE_AGING_HOURS": "2",
            }
        )

        self.assertEqual(config.sensor_stale_minutes, 10_080)
        self.assertEqual(config.asset_stale_hours, 72)
        self.assertEqual(config.evidence_fresh_hours, 1)
        self.assertEqual(config.evidence_aging_hours, 2)

    def test_unknown_rule_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown deterministic rule"):
            evaluate_rules(sites=[], sensors=[], assets=[], now=NOW, rule_ids=["dynamic-rule"])

    def test_untrusted_evidence_cannot_select_rules_or_leak_payload_content(self) -> None:
        untrusted = asset("asset-a", category="unknown")
        untrusted["hostname"] = "run-this-command.example"
        untrusted["raw_packet"] = "sensitive-packet-bytes"
        untrusted["metadata"].update(
            {
                "rule_id": "attacker-selected-rule",
                "title": "Bearer secret-token-value",
                "model_instruction": "change severity to critical",
            }
        )

        snapshot = evaluate_rules(
            sites=[site()],
            sensors=[],
            assets=[untrusted],
            now=NOW,
            rule_ids=["unknown-asset"],
        )
        serialized = repr(snapshot.candidates)

        self.assertEqual(
            {candidate.rule_id for candidate in snapshot.candidates},
            {"unknown-asset"},
        )
        self.assertNotIn("attacker-selected-rule", serialized)
        self.assertNotIn("secret-token-value", serialized)
        self.assertNotIn("sensitive-packet-bytes", serialized)
        self.assertNotIn("run-this-command", serialized)

    def test_candidate_generation_is_bounded(self) -> None:
        assets = [asset(f"unknown-{index}", category="unknown") for index in range(101)]
        config = FindingsConfig(max_candidates=100)

        with self.assertRaisesRegex(ValueError, "candidate limit"):
            evaluate_rules(
                sites=[site()],
                sensors=[],
                assets=assets,
                now=NOW,
                config=config,
                rule_ids=["unknown-asset"],
            )

    def test_thousands_of_assets_evaluate_in_bounded_time(self) -> None:
        assets = [
            asset(
                f"asset-{index}",
                category="unknown" if index % 10 == 0 else "server",
                source_agent_id="agent-a",
            )
            for index in range(5_000)
        ]
        started = time.perf_counter()

        snapshot = evaluate_rules(
            sites=[site()],
            sensors=[sensor("agent-a", agent_type="endpoint-agent")],
            assets=assets,
            now=NOW,
        )
        elapsed = time.perf_counter() - started

        self.assertEqual(len([item for item in snapshot.candidates if item.rule_id == "unknown-asset"]), 500)
        self.assertLess(elapsed, 5.0)


class FindingLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryFindingStore()
        self.sites = [site()]
        self.sensors = [sensor("agent-a", agent_type="endpoint-agent")]

    def evaluate(self, assets: list[dict], *, now: datetime) -> object:
        return evaluate_findings(
            trigger_type="test",
            requested_by="unit-test",
            now=now,
            store=self.store,
            sites=self.sites,
            sensors=self.sensors,
            assets=assets,
            rule_ids=["unknown-asset"],
        )

    def test_site_evaluation_pushes_scope_into_database_reads(self) -> None:
        with (
            patch("app.database.list_sites", return_value=self.sites) as list_sites,
            patch(
                "app.database.list_agent_enrollments",
                return_value=self.sensors,
            ) as list_sensors,
            patch(
                "app.database.list_control_tower_assets",
                return_value=[asset("asset-a")],
            ) as list_assets,
        ):
            evaluate_findings(
                trigger_type="test",
                now=NOW,
                store=self.store,
                site_id="site-a",
                rule_ids=["asset-stale"],
            )

        self.assertEqual(list_sites.call_args.kwargs["site_id"], "site-a")
        self.assertEqual(list_sensors.call_args.kwargs["site_id"], "site-a")
        self.assertEqual(list_assets.call_args.kwargs["site_id"], "site-a")

    def test_open_update_resolve_and_reopen_are_idempotent(self) -> None:
        unknown = asset("asset-a", category="unknown")
        first = self.evaluate([unknown], now=NOW)
        second = self.evaluate([unknown], now=NOW + timedelta(minutes=1))

        self.assertEqual(first.opened_count, 1)
        self.assertEqual(second.updated_count, 1)
        finding = next(iter(self.store.findings.values()))
        finding_id = finding["finding_id"]
        first_seen = finding["first_seen_at"]

        known_fresh = asset("asset-a", category="server")
        known_fresh["observed_at"] = NOW + timedelta(minutes=2)
        known_fresh["last_seen_at"] = NOW + timedelta(minutes=2)
        resolved = self.evaluate([known_fresh], now=NOW + timedelta(minutes=2))

        self.assertEqual(resolved.resolved_count, 1)
        self.assertEqual(self.store.findings[finding_id]["status"], "resolved")
        self.assertEqual(self.store.findings[finding_id]["first_seen_at"], first_seen)

        unknown_fresh = asset("asset-a", category="unknown")
        unknown_fresh["observed_at"] = NOW + timedelta(minutes=3)
        unknown_fresh["last_seen_at"] = NOW + timedelta(minutes=3)
        reopened = self.evaluate([unknown_fresh], now=NOW + timedelta(minutes=3))

        self.assertEqual(reopened.reopened_count, 1)
        self.assertEqual(self.store.findings[finding_id]["status"], "active")
        self.assertEqual(self.store.findings[finding_id]["reopen_count"], 1)

    def test_rule_version_change_remains_visible_on_logical_finding(self) -> None:
        initial = evaluate_rules(
            sites=self.sites,
            sensors=self.sensors,
            assets=[asset("asset-a", category="unknown")],
            now=NOW,
            rule_ids=["unknown-asset"],
        )
        first_run = self.store.begin_run()
        self.store.reconcile(
            run_id=first_run,
            snapshot=initial,
            evaluated_at=NOW,
            site_id=None,
            asset_id=None,
            sensor_id=None,
        )
        version_two = replace(
            initial,
            candidates=(replace(initial.candidates[0], rule_version=2),),
        )
        second_run = self.store.begin_run()
        self.store.reconcile(
            run_id=second_run,
            snapshot=version_two,
            evaluated_at=NOW + timedelta(minutes=1),
            site_id=None,
            asset_id=None,
            sensor_id=None,
        )

        finding = next(iter(self.store.findings.values()))
        self.assertEqual(finding["rule_version"], 2)
        self.assertEqual(finding["previous_rule_version"], 1)
        self.assertEqual(
            finding["rule_version_changed_at"],
            NOW + timedelta(minutes=1),
        )

    def test_missing_or_stale_evidence_does_not_false_resolve(self) -> None:
        self.evaluate([asset("asset-a", category="unknown")], now=NOW)
        stale_known = asset("asset-a", category="server", hours_ago=100)

        result = self.evaluate([stale_known], now=NOW)

        self.assertEqual(result.resolved_count, 0)
        self.assertEqual(next(iter(self.store.findings.values()))["status"], "active")

    def test_older_snapshot_cannot_overwrite_newer_finding_state(self) -> None:
        newer_unknown = asset("asset-a", category="unknown")
        newer_unknown["observed_at"] = NOW + timedelta(minutes=2)
        newer_unknown["last_seen_at"] = NOW + timedelta(minutes=2)
        self.evaluate([newer_unknown], now=NOW + timedelta(minutes=2))

        older_known = asset("asset-a", category="server")
        evaluated = self.evaluate([older_known], now=NOW + timedelta(minutes=1))

        self.assertEqual(evaluated.resolved_count, 0)
        finding = next(iter(self.store.findings.values()))
        self.assertEqual(finding["status"], "active")
        self.assertEqual(finding["evaluated_at"], NOW + timedelta(minutes=2))

    def test_passive_evidence_does_not_resolve_endpoint_coverage_gap(self) -> None:
        endpoint_asset = asset(
            "asset-a",
            source_agent_id="agent-a",
            security_coverage="missing",
        )
        opened = evaluate_findings(
            trigger_type="test",
            now=NOW,
            store=self.store,
            sites=self.sites,
            sensors=self.sensors,
            assets=[endpoint_asset],
            rule_ids=["security-coverage-gap"],
        )
        self.assertEqual(opened.opened_count, 1)

        passive_asset = asset(
            "asset-a",
            source_agent_id="passive-a",
            security_coverage=None,
        )
        passive_asset["observed_at"] = NOW + timedelta(minutes=1)
        passive_asset["last_seen_at"] = NOW + timedelta(minutes=1)
        evaluated = evaluate_findings(
            trigger_type="test",
            now=NOW + timedelta(minutes=1),
            store=self.store,
            sites=self.sites,
            sensors=[sensor("passive-a", agent_type="network-sensor")],
            assets=[passive_asset],
            rule_ids=["security-coverage-gap"],
        )

        self.assertEqual(evaluated.resolved_count, 0)
        self.assertEqual(next(iter(self.store.findings.values()))["status"], "active")

    def test_missing_endpoint_status_does_not_resolve_coverage_gap(self) -> None:
        opened_asset = asset(
            "asset-a",
            source_agent_id="agent-a",
            security_coverage="missing",
        )
        evaluate_findings(
            trigger_type="test",
            now=NOW,
            store=self.store,
            sites=self.sites,
            sensors=self.sensors,
            assets=[opened_asset],
            rule_ids=["security-coverage-gap"],
        )

        missing_status = asset("asset-a", source_agent_id="agent-a")
        missing_status["observed_at"] = NOW + timedelta(minutes=1)
        missing_status["last_seen_at"] = NOW + timedelta(minutes=1)
        evaluated = evaluate_findings(
            trigger_type="test",
            now=NOW + timedelta(minutes=1),
            store=self.store,
            sites=self.sites,
            sensors=self.sensors,
            assets=[missing_status],
            rule_ids=["security-coverage-gap"],
        )

        self.assertEqual(evaluated.resolved_count, 0)
        self.assertEqual(next(iter(self.store.findings.values()))["status"], "active")

    def test_explicit_healthy_endpoint_status_resolves_coverage_gap(self) -> None:
        evaluate_findings(
            trigger_type="test",
            now=NOW,
            store=self.store,
            sites=self.sites,
            sensors=self.sensors,
            assets=[
                asset(
                    "asset-a",
                    source_agent_id="agent-a",
                    security_coverage="missing",
                )
            ],
            rule_ids=["security-coverage-gap"],
        )
        healthy = asset(
            "asset-a",
            source_agent_id="agent-a",
            security_coverage="healthy",
        )
        healthy["observed_at"] = NOW + timedelta(minutes=1)
        healthy["last_seen_at"] = NOW + timedelta(minutes=1)

        evaluated = evaluate_findings(
            trigger_type="test",
            now=NOW + timedelta(minutes=1),
            store=self.store,
            sites=self.sites,
            sensors=self.sensors,
            assets=[healthy],
            rule_ids=["security-coverage-gap"],
        )

        self.assertEqual(evaluated.resolved_count, 1)
        self.assertEqual(next(iter(self.store.findings.values()))["status"], "resolved")

    def test_identity_conflict_does_not_resolve_when_counterpart_disappears(self) -> None:
        shared_mac = "02:00:5e:10:20:30"
        evaluate_findings(
            trigger_type="test",
            now=NOW,
            store=self.store,
            sites=self.sites,
            sensors=self.sensors,
            assets=[
                asset("asset-a", mac=shared_mac),
                asset("asset-b", mac=shared_mac),
            ],
            rule_ids=["identity-conflict"],
        )

        evaluated = evaluate_findings(
            trigger_type="test",
            now=NOW + timedelta(minutes=1),
            store=self.store,
            sites=self.sites,
            sensors=self.sensors,
            assets=[asset("asset-a", mac=shared_mac)],
            rule_ids=["identity-conflict"],
        )

        self.assertEqual(evaluated.resolved_count, 0)
        self.assertTrue(
            all(item["status"] == "active" for item in self.store.findings.values())
        )

    def test_revoked_sensor_does_not_erase_historical_stale_finding(self) -> None:
        stale = sensor("sensor-a", minutes_ago=180)
        evaluate_findings(
            trigger_type="test",
            now=NOW,
            store=self.store,
            sites=self.sites,
            sensors=[stale],
            assets=[],
            rule_ids=["sensor-stale"],
        )
        revoked = dict(stale)
        revoked["identity_status"] = "revoked"
        revoked["last_seen_at"] = NOW + timedelta(minutes=1)

        evaluated = evaluate_findings(
            trigger_type="test",
            now=NOW + timedelta(minutes=1),
            store=self.store,
            sites=self.sites,
            sensors=[revoked],
            assets=[],
            rule_ids=["sensor-stale"],
        )

        self.assertEqual(evaluated.resolved_count, 0)
        self.assertEqual(next(iter(self.store.findings.values()))["status"], "active")

    def test_acknowledge_and_suppress_are_audited_and_excluded_from_active_risk(self) -> None:
        self.evaluate([asset("asset-a", category="unknown")], now=NOW)
        finding_id = next(iter(self.store.findings))

        acknowledged = self.store.acknowledge(finding_id, actor="reviewer", at=NOW)
        self.assertEqual(acknowledged["status"], "acknowledged")
        self.assertEqual(acknowledged["acknowledged_by"], "reviewer")
        repeated = self.evaluate(
            [asset("asset-a", category="unknown")],
            now=NOW + timedelta(minutes=1),
        )
        self.assertEqual(repeated.updated_count, 1)
        self.assertEqual(self.store.findings[finding_id]["status"], "acknowledged")
        self.assertEqual(self.store.findings[finding_id]["acknowledged_by"], "reviewer")

        suppressed = self.store.suppress(
            finding_id,
            actor="reviewer",
            reason="approved lab exception",
            until=NOW + timedelta(days=1),
            at=NOW,
        )
        self.assertEqual(suppressed["status"], "suppressed")
        self.assertEqual(self.store.active_findings(), [])


if __name__ == "__main__":
    unittest.main()
