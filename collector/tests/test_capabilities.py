from __future__ import annotations

import unittest
from unittest.mock import patch

from openassetwatch_collector.main import (
    collect_enabled_capabilities,
    collect_supported_capabilities,
    build_payload,
)
from openassetwatch_collector.capabilities import passive_inventory_sources


def linux_platform(commands: list[str] | None = None) -> dict[str, object]:
    return {
        "system_key": "linux",
        "available_commands": commands or ["ip", "arp"],
    }


class CapabilityReportingTests(unittest.TestCase):
    def test_supported_capabilities_include_safe_local_features(self) -> None:
        capabilities = collect_supported_capabilities(linux_platform())

        self.assertIn("device_inventory", capabilities)
        self.assertIn("network_neighbors", capabilities)
        self.assertIn("open_detector", capabilities)
        self.assertNotIn("nmap_light", capabilities)
        self.assertNotIn("passive_sensor", capabilities)

    def test_supported_capabilities_omit_network_when_no_neighbor_collector_available(self) -> None:
        capabilities = collect_supported_capabilities(
            {"system_key": "linux", "available_commands": []}
        )

        self.assertIn("device_inventory", capabilities)
        self.assertIn("open_detector", capabilities)
        self.assertNotIn("network_neighbors", capabilities)

    def test_passive_inventory_sources_do_not_report_scanner_buckets(self) -> None:
        sources = passive_inventory_sources("linux", ["ip", "arp", "nmap", "tcpdump"])

        self.assertIn("neighbor_cache", sources)
        self.assertNotIn("active_light", sources)
        self.assertNotIn("nmap", str(sources))
        self.assertNotIn("tcpdump", str(sources))

    def test_device_mode_enabled_capabilities(self) -> None:
        supported = ["device_inventory", "network_neighbors", "open_detector"]

        enabled = collect_enabled_capabilities("device", supported, open_detector_enabled=True)

        self.assertEqual(enabled, ["device_inventory", "open_detector"])

    def test_network_mode_enabled_capabilities(self) -> None:
        supported = ["device_inventory", "network_neighbors", "open_detector"]

        enabled = collect_enabled_capabilities("network", supported, open_detector_enabled=True)

        self.assertEqual(enabled, ["network_neighbors"])

    def test_hybrid_mode_enabled_capabilities(self) -> None:
        supported = ["device_inventory", "network_neighbors", "open_detector"]

        enabled = collect_enabled_capabilities("hybrid", supported, open_detector_enabled=True)

        self.assertEqual(enabled, ["device_inventory", "network_neighbors", "open_detector"])

    def test_hybrid_mode_omits_open_detector_when_disabled(self) -> None:
        supported = ["device_inventory", "network_neighbors", "open_detector"]

        enabled = collect_enabled_capabilities("hybrid", supported, open_detector_enabled=False)

        self.assertEqual(enabled, ["device_inventory", "network_neighbors"])

    def test_payload_includes_capability_fields(self) -> None:
        with patch("openassetwatch_collector.main.collect_platform_capabilities", return_value=linux_platform()):
            with patch("openassetwatch_collector.main.collect_device", return_value={"hostname": "test-host"}):
                with patch("openassetwatch_collector.main.scan_software", return_value=[]):
                    payload = build_payload("device")

        self.assertEqual(
            payload["supported_capabilities"],
            ["device_inventory", "network_neighbors", "open_detector"],
        )
        self.assertEqual(payload["enabled_capabilities"], ["device_inventory", "open_detector"])

    def test_network_payload_enabled_capabilities_reflect_mode(self) -> None:
        with patch("openassetwatch_collector.main.collect_platform_capabilities", return_value=linux_platform()):
            with patch("openassetwatch_collector.main.collect_network", return_value=[]):
                payload = build_payload("network")

        self.assertEqual(payload["enabled_capabilities"], ["network_neighbors"])

    def test_hybrid_payload_enabled_capabilities_reflect_mode(self) -> None:
        with patch("openassetwatch_collector.main.collect_platform_capabilities", return_value=linux_platform()):
            with patch("openassetwatch_collector.main.collect_device", return_value={"hostname": "test-host"}):
                with patch("openassetwatch_collector.main.scan_software", return_value=[]):
                    with patch("openassetwatch_collector.main.collect_network", return_value=[]):
                        payload = build_payload("hybrid")

        self.assertEqual(
            payload["enabled_capabilities"],
            ["device_inventory", "network_neighbors", "open_detector"],
        )


if __name__ == "__main__":
    unittest.main()
