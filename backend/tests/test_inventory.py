from __future__ import annotations

import unittest

from fastapi import HTTPException

from app.main import collector_inventory


class CollectorInventoryTests(unittest.TestCase):
    def test_valid_device_only_inventory_returns_accepted(self) -> None:
        response = collector_inventory(
            {
                "collector": {"id": "local-dev-collector-01"},
                "mode": "device",
                "device": {"hostname": "test-host"},
            }
        )

        self.assertEqual(response.status, "accepted")
        self.assertEqual(response.collector_id, "local-dev-collector-01")
        self.assertEqual(response.mode, "device")
        self.assertEqual(response.device_count, 1)
        self.assertEqual(response.network_observation_count, 0)
        self.assertEqual(response.software_count, 0)

    def test_valid_software_only_inventory_returns_accepted(self) -> None:
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

        self.assertEqual(response.collector_id, "collector-software")
        self.assertEqual(response.device_count, 0)
        self.assertEqual(response.software_count, 1)

    def test_valid_hybrid_inventory_returns_accepted(self) -> None:
        response = collector_inventory(
            {
                "schema_version": "1.0",
                "collector": {"id": "collector-hybrid"},
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
