from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError

from app.main import collector_inventory, latest_collector_inventory


class CollectorInventoryTests(unittest.TestCase):
    def test_valid_device_only_inventory_returns_accepted(self) -> None:
        with patch("app.main.save_inventory_submission", return_value=1) as save:
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
        save.assert_called_once()
        self.assertEqual(save.call_args.kwargs["collector_name"], "Local Dev Collector")

    def test_valid_software_only_inventory_returns_accepted(self) -> None:
        with patch("app.main.save_inventory_submission", return_value=2):
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

    def test_valid_hybrid_inventory_returns_accepted(self) -> None:
        with patch("app.main.save_inventory_submission", return_value=3):
            response = collector_inventory(
                {
                    "schema_version": "1.0",
                    "collector": {"id": "collector-hybrid", "name": "Hybrid Collector"},
                    "collector_version": "0.1.0",
                    "mode": "hybrid",
                    "platform": {"system": "windows", "architecture": "amd64"},
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
        self.assertEqual(response.collector_id, "collector-hybrid")
        self.assertEqual(response.mode, "hybrid")
        self.assertEqual(response.device_count, 1)
        self.assertEqual(response.network_observation_count, 2)
        self.assertEqual(response.software_count, 1)

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

    def test_latest_endpoint_returns_stored_submission(self) -> None:
        received_at = datetime.now(timezone.utc)
        created_at = datetime.now(timezone.utc)
        with patch(
            "app.main.latest_inventory_submission",
            return_value={
                "submission_id": 7,
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
