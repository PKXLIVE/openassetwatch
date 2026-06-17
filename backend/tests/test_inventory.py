from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError

from app.database import (
    _normalize_mac_address,
    _upsert_collector,
    policy_assignment_matches,
    select_matching_policy_assignment,
)
from app.main import (
    AdminPolicyAssignmentRequest,
    AdminPolicyRequest,
    CollectorCheckInRequest,
    CollectorPolicyStatusRequest,
    COLLECTOR_TOKEN_ENV,
    admin_create_policy,
    admin_create_policy_assignment,
    assets,
    assigned_policy_payload,
    calculate_policy_hash,
    collector_checkin,
    collector_inventory,
    collector_policy,
    collector_policy_status,
    collectors,
    default_collector_policy_payload,
    latest_collector_inventory,
)


class CollectorInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.token_env = patch.dict("os.environ", {COLLECTOR_TOKEN_ENV: ""})
        self.token_env.start()

    def tearDown(self) -> None:
        self.token_env.stop()

    def test_checkin_allows_request_when_token_not_configured(self) -> None:
        with patch.dict("os.environ", {COLLECTOR_TOKEN_ENV: ""}):
            with patch("app.main.upsert_collector_metadata", return_value=1):
                response = collector_checkin(
                    CollectorCheckInRequest(
                        collector_id="local-dev-collector-01",
                        hostname="test-host",
                    collector_version="0.1.0",
                    mode="device",
                    supported_capabilities=["device_inventory", "open_detector"],
                    enabled_capabilities=["device_inventory", "open_detector"],
                )
                )

        self.assertEqual(response.status, "accepted")

    def test_checkin_rejects_missing_token_when_configured(self) -> None:
        with patch.dict("os.environ", {COLLECTOR_TOKEN_ENV: "change-me-dev-token"}):
            with self.assertRaises(HTTPException) as raised:
                collector_checkin(
                    CollectorCheckInRequest(
                        collector_id="local-dev-collector-01",
                        hostname="test-host",
                        collector_version="0.1.0",
                        mode="device",
                    )
                )

        self.assertEqual(raised.exception.status_code, 401)
        self.assertNotIn("change-me-dev-token", str(raised.exception.detail))

    def test_inventory_rejects_wrong_token_when_configured(self) -> None:
        with patch.dict("os.environ", {COLLECTOR_TOKEN_ENV: "change-me-dev-token"}):
            with self.assertRaises(HTTPException) as raised:
                collector_inventory(
                    {
                        "collector_id": "collector-token-test",
                        "mode": "device",
                        "device": {"hostname": "test-host"},
                    },
                    collector_token="wrong-token",
                )

        self.assertEqual(raised.exception.status_code, 401)
        self.assertNotIn("change-me-dev-token", str(raised.exception.detail))

    def test_inventory_accepts_correct_token_when_configured(self) -> None:
        with patch.dict("os.environ", {COLLECTOR_TOKEN_ENV: "change-me-dev-token"}):
            with patch("app.main.save_inventory_submission", return_value=9):
                with patch(
                    "app.main.normalize_inventory_submission",
                    return_value={"normalized_asset_count": 1, "normalized_software_count": 0},
                ):
                    response = collector_inventory(
                        {
                            "collector_id": "collector-token-test",
                            "mode": "device",
                            "device": {"hostname": "test-host"},
                        },
                        collector_token="change-me-dev-token",
                    )

        self.assertEqual(response.status, "accepted")

    def test_policy_endpoint_returns_default_safe_policy(self) -> None:
        with patch("app.main.find_assigned_collector_policy", return_value=None):
            response = collector_policy()

        self.assertEqual(response["policy_id"], "default-local-collector")
        self.assertEqual(response["policy_version"], 1)
        self.assertTrue(response["policy_hash"].startswith("sha256:"))
        self.assertIsNone(response["assigned_at"])
        self.assertIsNone(response["minimum_collector_version"])
        self.assertEqual(response["license_status"], "dev_mode")
        self.assertIn("device_inventory", response["assigned_capabilities"])
        self.assertIn("network_neighbors", response["assigned_capabilities"])
        self.assertIn("open_detector", response["assigned_capabilities"])
        self.assertEqual(response["denied_capabilities"], [])
        self.assertEqual(response["policy"]["mode"], "hybrid")
        self.assertNotIn("nmap_light", response["policy"]["modules"])
        self.assertNotIn("passive_sensor", response["policy"]["modules"])

    def test_policy_endpoint_rejects_missing_token_when_configured(self) -> None:
        with patch.dict("os.environ", {COLLECTOR_TOKEN_ENV: "change-me-dev-token"}):
            with self.assertRaises(HTTPException) as raised:
                collector_policy()

        self.assertEqual(raised.exception.status_code, 401)
        self.assertNotIn("change-me-dev-token", str(raised.exception.detail))

    def test_policy_endpoint_accepts_correct_token_when_configured(self) -> None:
        with patch.dict("os.environ", {COLLECTOR_TOKEN_ENV: "change-me-dev-token"}):
            with patch("app.main.find_assigned_collector_policy", return_value=None):
                response = collector_policy(collector_token="change-me-dev-token")

        self.assertEqual(response["policy_id"], "default-local-collector")

    def test_policy_endpoint_returns_collector_guid_assignment_match(self) -> None:
        assigned_record = {
            "policy_id": "lab-policy",
            "policy_version": 3,
            "assigned_at": "2026-06-12T05:00:00+00:00",
            "policy_json": {
                "minimum_collector_version": "0.1.0",
                "license_status": "dev_mode",
                "assigned_capabilities": ["device_inventory"],
                "denied_capabilities": ["legacy_raw_scanner"],
                "policy": {"mode": "device"},
            },
        }
        with patch("app.main.find_assigned_collector_policy", return_value=assigned_record) as find_policy:
            response = collector_policy(
                collector_guid="11111111-1111-4111-8111-111111111111",
                collector_id="collector-1",
            )

        self.assertEqual(response["policy_id"], "lab-policy")
        self.assertEqual(response["policy_version"], 3)
        self.assertEqual(response["policy"]["mode"], "device")
        self.assertEqual(response["minimum_collector_version"], "0.1.0")
        find_policy.assert_called_once()
        self.assertEqual(find_policy.call_args.kwargs["collector_guid"], "11111111-1111-4111-8111-111111111111")

    def test_policy_endpoint_parses_label_query(self) -> None:
        with patch("app.main.find_assigned_collector_policy", return_value=None) as find_policy:
            collector_policy(labels='{"owner":"dion","site":"home"}')

        self.assertEqual(find_policy.call_args.kwargs["labels"], {"owner": "dion", "site": "home"})

    def test_policy_endpoint_rejects_invalid_label_query(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            collector_policy(labels="not-json")

        self.assertEqual(raised.exception.status_code, 400)

    def test_admin_policy_creation_saves_policy(self) -> None:
        saved_policy = {
            "id": 1,
            "policy_id": "lab-policy",
            "policy_name": "Lab Policy",
            "policy_version": 2,
            "policy_json": {"policy": {"mode": "device"}},
            "enabled": True,
        }
        with patch("app.main.upsert_collector_policy", return_value=saved_policy) as upsert:
            response = admin_create_policy(
                AdminPolicyRequest(
                    policy_id="lab-policy",
                    policy_name="Lab Policy",
                    policy_version=2,
                    assigned_capabilities=["device_inventory"],
                    policy={"mode": "device"},
                )
            )

        self.assertEqual(response["status"], "accepted")
        self.assertEqual(response["policy"]["policy_id"], "lab-policy")
        self.assertEqual(upsert.call_args.kwargs["policy_json"]["policy"]["mode"], "device")

    def test_admin_assignment_creation_saves_assignment(self) -> None:
        saved_assignment = {
            "id": 1,
            "assignment_name": "Collector GUID",
            "policy_id": "lab-policy",
            "enabled": True,
            "priority": 100,
            "collector_guid": "11111111-1111-4111-8111-111111111111",
        }
        with patch("app.main.create_policy_assignment", return_value=saved_assignment) as create_assignment:
            response = admin_create_policy_assignment(
                AdminPolicyAssignmentRequest(
                    assignment_name="Collector GUID",
                    policy_id="lab-policy",
                    priority=100,
                    collector_guid="11111111-1111-4111-8111-111111111111",
                )
            )

        self.assertEqual(response["status"], "accepted")
        self.assertEqual(response["policy_assignment"]["policy_id"], "lab-policy")
        self.assertEqual(create_assignment.call_args.kwargs["collector_guid"], "11111111-1111-4111-8111-111111111111")

    def test_policy_assignment_matches_collector_id_deployment_platform_and_labels(self) -> None:
        self.assertTrue(
            policy_assignment_matches(
                {
                    "enabled": True,
                    "collector_id": "collector-1",
                    "deployment_id": "home-lab",
                    "platform": "windows",
                    "label_selector": {"owner": "dion"},
                },
                collector_guid=None,
                collector_id="collector-1",
                deployment_id="home-lab",
                platform="Windows",
                labels={"owner": "dion", "ring": "pilot"},
            )
        )

    def test_policy_assignment_does_not_match_wrong_deployment(self) -> None:
        self.assertFalse(
            policy_assignment_matches(
                {"enabled": True, "deployment_id": "prod"},
                collector_guid=None,
                collector_id="collector-1",
                deployment_id="home-lab",
                platform="linux",
                labels={},
            )
        )

    def test_policy_assignment_priority_selection_uses_highest_priority(self) -> None:
        rows = [
            {
                "id": 1,
                "policy_id": "low-policy",
                "enabled": True,
                "policy_enabled": True,
                "priority": 10,
                "collector_id": "collector-1",
            },
            {
                "id": 2,
                "policy_id": "high-policy",
                "enabled": True,
                "policy_enabled": True,
                "priority": 50,
                "collector_id": "collector-1",
            },
        ]

        selected = select_matching_policy_assignment(
            rows,
            collector_guid=None,
            collector_id="collector-1",
            deployment_id=None,
            platform=None,
            labels=None,
        )

        self.assertEqual(selected["policy_id"], "high-policy")

    def test_disabled_assignment_and_policy_are_ignored(self) -> None:
        rows = [
            {
                "id": 1,
                "policy_id": "disabled-assignment",
                "enabled": False,
                "policy_enabled": True,
                "priority": 100,
                "collector_id": "collector-1",
            },
            {
                "id": 2,
                "policy_id": "disabled-policy",
                "enabled": True,
                "policy_enabled": False,
                "priority": 90,
                "collector_id": "collector-1",
            },
            {
                "id": 3,
                "policy_id": "enabled-policy",
                "enabled": True,
                "policy_enabled": True,
                "priority": 10,
                "collector_id": "collector-1",
            },
        ]

        selected = select_matching_policy_assignment(
            rows,
            collector_guid=None,
            collector_id="collector-1",
            deployment_id=None,
            platform=None,
            labels=None,
        )

        self.assertEqual(selected["policy_id"], "enabled-policy")

    def test_assigned_policy_hash_is_stable_and_correct(self) -> None:
        record = {
            "policy_id": "stable-policy",
            "policy_version": 1,
            "assigned_at": "2026-06-12T05:00:00+00:00",
            "policy_json": {
                "license_status": "dev_mode",
                "assigned_capabilities": ["device_inventory"],
                "denied_capabilities": [],
                "policy": {"mode": "device"},
            },
        }

        first = assigned_policy_payload(record)
        second = assigned_policy_payload(record)
        policy_hash = first.pop("policy_hash")

        self.assertEqual(policy_hash, second["policy_hash"])
        self.assertEqual(policy_hash, calculate_policy_hash(first))

    def test_default_policy_hash_matches_payload(self) -> None:
        policy = default_collector_policy_payload()
        policy_hash = policy.pop("policy_hash")

        from app.main import calculate_policy_hash

        self.assertEqual(policy_hash, calculate_policy_hash(policy))

    def test_policy_status_accepts_valid_status(self) -> None:
        response = collector_policy_status(
            CollectorPolicyStatusRequest(
                collector_guid="11111111-1111-4111-8111-111111111111",
                collector_id="collector-1",
                policy_id="default-local-collector",
                policy_version=1,
                policy_hash="sha256:test",
                policy_status="applied",
            )
        )

        self.assertEqual(response.status, "accepted")
        self.assertEqual(response.policy_status, "applied")

    def test_policy_status_rejects_wrong_token_when_configured(self) -> None:
        with patch.dict("os.environ", {COLLECTOR_TOKEN_ENV: "change-me-dev-token"}):
            with self.assertRaises(HTTPException) as raised:
                collector_policy_status(
                    CollectorPolicyStatusRequest(
                        collector_id="collector-1",
                        policy_id="default-local-collector",
                        policy_version=1,
                        policy_hash="sha256:test",
                        policy_status="applied",
                    ),
                    collector_token="wrong-token",
                )

        self.assertEqual(raised.exception.status_code, 401)

    def test_policy_status_rejects_invalid_status(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            collector_policy_status(
                CollectorPolicyStatusRequest(
                    collector_id="collector-1",
                    policy_id="default-local-collector",
                    policy_version=1,
                    policy_hash="sha256:test",
                    policy_status="unknown",
                )
            )

        self.assertEqual(raised.exception.status_code, 400)

    def test_checkin_updates_collector_metadata(self) -> None:
        with patch("app.main.upsert_collector_metadata", return_value=1) as upsert:
            response = collector_checkin(
                CollectorCheckInRequest(
                    collector_id="local-dev-collector-01",
                    collector_guid="11111111-1111-4111-8111-111111111111",
                    collector_name="Local Dev Collector",
                    hostname="test-host",
                    collector_version="0.1.0",
                    mode="hybrid",
                    deployment={"deployment_id": "home-lab"},
                    labels={"owner": "dion"},
                    supported_capabilities=["device_inventory", "open_detector"],
                    enabled_capabilities=["device_inventory", "open_detector"],
                )
            )

        self.assertEqual(response.collector_id, "local-dev-collector-01")
        upsert.assert_called_once()
        self.assertEqual(upsert.call_args.kwargs["collector_guid"], "11111111-1111-4111-8111-111111111111")
        self.assertEqual(upsert.call_args.kwargs["deployment"]["deployment_id"], "home-lab")
        self.assertEqual(upsert.call_args.kwargs["labels"]["owner"], "dion")
        self.assertEqual(upsert.call_args.kwargs["supported_capabilities"], ["device_inventory", "open_detector"])
        self.assertEqual(upsert.call_args.kwargs["enabled_capabilities"], ["device_inventory", "open_detector"])

    def test_upsert_collector_matches_existing_guid_before_collector_id(self) -> None:
        connection = Mock()
        connection.execute.side_effect = [
            Mock(scalar_one_or_none=Mock(return_value=7)),
            Mock(),
        ]

        collector_pk = _upsert_collector(
            connection,
            collector_guid="11111111-1111-4111-8111-111111111111",
            collector_id="renamed-collector",
            collector_name="Renamed Collector",
            collector_version="0.1.0",
            deployment={"deployment_id": "home-lab"},
            labels={"owner": "dion"},
            supported_capabilities=["device_inventory", "network_neighbors", "open_detector"],
            enabled_capabilities=["device_inventory", "network_neighbors"],
            mode="hybrid",
            seen_at=datetime.now(timezone.utc),
        )

        self.assertEqual(collector_pk, 7)
        self.assertEqual(connection.execute.call_count, 2)
        update_sql = str(connection.execute.call_args_list[1].args[0])
        self.assertIn("UPDATE collectors", update_sql)
        self.assertIn("supported_capabilities_json", update_sql)
        self.assertIn("enabled_capabilities_json", update_sql)
        self.assertNotIn("INSERT INTO collectors", update_sql)

    def test_backend_mac_normalization_rejects_non_host_values(self) -> None:
        for value in (
            "(incomplete)",
            "incomplete",
            "<incomplete>",
            "",
            None,
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
            "01:00:5e:00:00:01",
            "33:33:00:00:00:01",
        ):
            with self.subTest(value=value):
                self.assertIsNone(_normalize_mac_address(value))

    def test_backend_mac_normalization_accepts_common_formats(self) -> None:
        self.assertEqual(_normalize_mac_address("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(_normalize_mac_address("aabb.ccdd.eeff"), "aa:bb:cc:dd:ee:ff")

    def test_valid_device_only_inventory_returns_accepted(self) -> None:
        with patch("app.main.save_inventory_submission", return_value=1) as save:
            with patch(
                "app.main.normalize_inventory_submission",
                return_value={"normalized_asset_count": 1, "normalized_software_count": 0},
            ) as normalize:
                response = collector_inventory(
                    {
                        "collector": {"id": "local-dev-collector-01"},
                        "collector_name": "Local Dev Collector",
                        "mode": "device",
                        "device": {"hostname": "test-host"},
                    }
                )

        self.assertEqual(response.status, "accepted")
        self.assertEqual(response.submission_id, 1)
        self.assertEqual(response.collector_id, "local-dev-collector-01")
        self.assertEqual(response.mode, "device")
        self.assertEqual(response.device_count, 1)
        self.assertEqual(response.network_observation_count, 0)
        self.assertEqual(response.software_count, 0)
        self.assertEqual(response.normalized_asset_count, 1)
        self.assertEqual(response.normalized_software_count, 0)
        save.assert_called_once()
        self.assertEqual(save.call_args.kwargs["collector_name"], "Local Dev Collector")
        normalize.assert_called_once()

    def test_valid_software_only_inventory_returns_accepted(self) -> None:
        with patch("app.main.save_inventory_submission", return_value=2):
            with patch(
                "app.main.normalize_inventory_submission",
                return_value={"normalized_asset_count": 0, "normalized_software_count": 0},
            ):
                response = collector_inventory(
                    {
                        "collector_id": "collector-software",
                        "mode": "device",
                        "software": [
                            {
                                "name": "Microsoft Defender",
                                "category": "edr",
                                "detected": True,
                            }
                        ],
                    }
                )

        self.assertEqual(response.submission_id, 2)
        self.assertEqual(response.collector_id, "collector-software")
        self.assertEqual(response.device_count, 0)
        self.assertEqual(response.software_count, 1)
        self.assertEqual(response.normalized_asset_count, 0)
        self.assertEqual(response.normalized_software_count, 0)

    def test_valid_hybrid_inventory_returns_accepted(self) -> None:
        with patch("app.main.save_inventory_submission", return_value=3):
            with patch(
                "app.main.normalize_inventory_submission",
                return_value={"normalized_asset_count": 3, "normalized_software_count": 1},
            ) as normalize:
                response = collector_inventory(
                    {
                        "schema_version": "1.0",
                        "collector": {"id": "collector-hybrid", "name": "Hybrid Collector"},
                        "collector_guid": "11111111-1111-4111-8111-111111111111",
                        "collector_version": "0.1.0",
                        "mode": "hybrid",
                        "platform": {"system": "windows", "architecture": "amd64"},
                        "deployment": {"deployment_id": "home-lab"},
                        "labels": {"owner": "dion"},
                        "supported_capabilities": [
                            "device_inventory",
                            "network_neighbors",
                            "open_detector",
                        ],
                        "enabled_capabilities": [
                            "device_inventory",
                            "network_neighbors",
                            "open_detector",
                        ],
                        "device": {"hostname": "test-host"},
                        "network": [
                            {
                                "ip_address": "192.168.1.1",
                                "mac_address": "00:11:22:33:44:55",
                            },
                            {
                                "ip_address": "192.168.1.2",
                                "mac_address": "00:11:22:33:44:66",
                            },
                        ],
                        "software": [
                            {
                                "name": "Docker Desktop",
                                "category": "container_runtime",
                                "detected": True,
                            }
                        ],
                        "future_field": {"kept": "flexible"},
                    }
                )

        self.assertEqual(response.status, "accepted")
        self.assertEqual(response.submission_id, 3)
        self.assertEqual(response.collector_guid, "11111111-1111-4111-8111-111111111111")
        self.assertEqual(response.collector_id, "collector-hybrid")
        self.assertEqual(response.mode, "hybrid")
        self.assertEqual(response.device_count, 1)
        self.assertEqual(response.network_observation_count, 2)
        self.assertEqual(response.software_count, 1)
        self.assertEqual(response.normalized_asset_count, 3)
        self.assertEqual(response.normalized_software_count, 1)
        self.assertEqual(
            normalize.call_args.kwargs["supported_capabilities"],
            ["device_inventory", "network_neighbors", "open_detector"],
        )
        self.assertEqual(
            normalize.call_args.kwargs["enabled_capabilities"],
            ["device_inventory", "network_neighbors", "open_detector"],
        )

    def test_empty_payload_returns_400(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            collector_inventory({})

        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("device, network, software", raised.exception.detail)

    def test_database_error_returns_500(self) -> None:
        with patch("app.main.save_inventory_submission", side_effect=SQLAlchemyError("db down")):
            with self.assertRaises(HTTPException) as raised:
                collector_inventory(
                    {
                        "collector": {"id": "collector-db-error"},
                        "mode": "device",
                        "device": {"hostname": "test-host"},
                    }
                )

        self.assertEqual(raised.exception.status_code, 500)
        self.assertIn("failed to persist inventory submission", raised.exception.detail)

    def test_normalization_error_returns_500(self) -> None:
        with patch("app.main.save_inventory_submission", return_value=4):
            with patch("app.main.normalize_inventory_submission", side_effect=SQLAlchemyError("db down")):
                with self.assertRaises(HTTPException) as raised:
                    collector_inventory(
                        {
                            "collector": {"id": "collector-normalize-error"},
                            "mode": "device",
                            "device": {"hostname": "test-host"},
                        }
                    )

        self.assertEqual(raised.exception.status_code, 500)
        self.assertIn("failed to normalize inventory submission", raised.exception.detail)

    def test_latest_endpoint_returns_stored_submission(self) -> None:
        received_at = datetime.now(timezone.utc)
        created_at = datetime.now(timezone.utc)
        with patch(
            "app.main.latest_inventory_submission",
            return_value={
                "submission_id": 7,
                "collector_guid": "11111111-1111-4111-8111-111111111111",
                "collector_id": "latest-collector",
                "collector_name": "Latest Collector",
                "mode": "hybrid",
                "schema_version": "1.0",
                "collector_version": "0.1.0",
                "collected_at": None,
                "received_at": received_at,
                "device_count": 1,
                "network_observation_count": 2,
                "software_count": 3,
                "created_at": created_at,
                "payload": {"mode": "hybrid", "device": {"hostname": "test-host"}},
            },
        ):
            response = latest_collector_inventory()

        self.assertEqual(response["submission_id"], 7)
        self.assertEqual(response["collector_id"], "latest-collector")
        self.assertEqual(response["payload"]["mode"], "hybrid")

    def test_latest_endpoint_database_error_returns_500(self) -> None:
        with patch("app.main.latest_inventory_submission", side_effect=SQLAlchemyError("db down")):
            with self.assertRaises(HTTPException) as raised:
                latest_collector_inventory()

        self.assertEqual(raised.exception.status_code, 500)
        self.assertIn("failed to load latest inventory submission", raised.exception.detail)

    def test_assets_endpoint_returns_assets(self) -> None:
        with patch("app.main.list_assets", return_value=[{"id": 1, "hostname": "test-host"}]):
            response = assets()

        self.assertEqual(response["assets"][0]["hostname"], "test-host")

    def test_collectors_endpoint_returns_collectors(self) -> None:
        with patch(
            "app.main.list_collectors",
            return_value=[
                {
                    "id": 1,
                    "collector_id": "collector-1",
                    "supported_capabilities": ["device_inventory"],
                    "enabled_capabilities": ["device_inventory"],
                }
            ],
        ):
            response = collectors()

        self.assertEqual(response["collectors"][0]["collector_id"], "collector-1")
        self.assertEqual(response["collectors"][0]["supported_capabilities"], ["device_inventory"])
        self.assertEqual(response["collectors"][0]["enabled_capabilities"], ["device_inventory"])

    def test_non_object_payload_returns_400(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            collector_inventory([])

        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("JSON object", raised.exception.detail)

    def test_payload_without_inventory_sections_returns_400(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            collector_inventory(
                {
                    "collector": {"id": "collector-no-inventory"},
                    "mode": "hybrid",
                    "platform": {"system": "windows"},
                }
            )

        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("device, network, software", raised.exception.detail)


if __name__ == "__main__":
    unittest.main()
