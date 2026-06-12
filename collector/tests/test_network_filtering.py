from __future__ import annotations

import unittest

from openassetwatch_collector.main import is_non_host_mac_address, normalize_mac


class NetworkFilteringTests(unittest.TestCase):
    def test_normalize_mac_rejects_incomplete_placeholders(self) -> None:
        for value in ("(incomplete)", "incomplete", "<incomplete>", "", None):
            with self.subTest(value=value):
                self.assertIsNone(normalize_mac(value))

    def test_normalize_mac_rejects_malformed_values(self) -> None:
        self.assertIsNone(normalize_mac("not-a-mac"))
        self.assertIsNone(normalize_mac("aa:bb:cc"))

    def test_normalize_mac_accepts_common_formats(self) -> None:
        self.assertEqual(normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(normalize_mac("aabb.ccdd.eeff"), "aa:bb:cc:dd:ee:ff")

    def test_non_host_mac_filter_rejects_zero_broadcast_and_multicast(self) -> None:
        for value in (
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
            "01:00:5e:00:00:01",
            "33:33:00:00:00:01",
            "(incomplete)",
        ):
            with self.subTest(value=value):
                self.assertTrue(is_non_host_mac_address(value))


if __name__ == "__main__":
    unittest.main()
