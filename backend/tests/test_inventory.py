from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError

from app.database import _normalize_mac_address, _upsert_collector
from app.main import (
    CollectorCheckInRequest,
    assets,
    collector_checkin,
    collector_inventory,
    collectors,
    latest_collector_inventory,
)


class CollectorInventoryTests(unittest.TestCase):
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
                )
            )

        self.assertEqual(response.collector_id, "local-dev-collector-01")
        upsert.assert_called_once()
        self.assertEqual(upsert.call_args.kwargs["collector_guid"], "11111111-1111-4111-8111-111111111111")
        self.assertEqual(upsert.call_args.kwargs["deployment"]["deployment_id"], "home-lab")
        self.assertEqual(upsert.call_args.kwargs["labels"]["owner"], "dion")

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
            mode="hybrid",
            seen_at=datetime.now(timezone.utc),
        )

        self.assertEqual(collector_pk, 7)
        self.assertEqual(connection.execute.call_count, 2)
        update_sql = str(connection.execute.call_args_list[1].args[0])
        self.assertIn("UPDATE collectors", update_sql)
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
            ):
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
        with patch("app.main.list_collectors", return_value=[{"id": 1, "collector_id": "collector-1"}]):
            response = collectors()

        self.assertEqual(response["collectors"][0]["collector_id"], "collector-1")

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
