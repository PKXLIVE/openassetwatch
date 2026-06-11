from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openassetwatch_collector.open_detector import scanner
from openassetwatch_collector.open_detector.detectors import DETECTORS
from openassetwatch_collector.open_detector.models import DetectorResult
from openassetwatch_collector.open_detector.platform import (
    PlatformContext,
    normalize_system,
    privilege_level,
)
from openassetwatch_collector.open_detector.safety import (
    is_path_within_base,
    safe_path_exists,
)


class FakeDetector:
    def __init__(self, result: DetectorResult) -> None:
        self.name = result.name
        self.category = result.category
        self.result = result

    def detect(self, platform: PlatformContext) -> DetectorResult:
        return self.result


class DetectorResultTests(unittest.TestCase):
    def test_detector_result_fields_are_serialized(self) -> None:
        result = DetectorResult(
            name="Example Agent",
            category="edr",
            detected=True,
            version="1.2.3",
            evidence=["command_found:example"],
            confidence="high",
            scope="system",
            source="command",
        )

        self.assertEqual(result.name, "Example Agent")
        self.assertEqual(result.category, "edr")
        self.assertTrue(result.detected)
        self.assertEqual(result.version, "1.2.3")
        self.assertEqual(result.evidence, ["command_found:example"])
        self.assertEqual(result.confidence, "high")
        self.assertEqual(result.scope, "system")
        self.assertEqual(result.source, "command")
        self.assertEqual(
            result.to_dict(),
            {
                "name": "Example Agent",
                "category": "edr",
                "detected": True,
                "version": "1.2.3",
                "evidence": ["command_found:example"],
                "confidence": "high",
                "scope": "system",
                "source": "command",
            },
        )

    def test_detector_result_version_is_optional(self) -> None:
        result = DetectorResult(
            name="Example Agent",
            category="edr",
            detected=False,
            evidence=[],
            confidence="none",
            scope="system",
            source="path",
        )

        self.assertIsNone(result.version)
        self.assertFalse(result.detected)


class ScannerTests(unittest.TestCase):
    def test_scan_software_includes_detected_results(self) -> None:
        detected = DetectorResult(
            name="Detected Agent",
            category="edr",
            detected=True,
            evidence=["command_found:detected"],
            confidence="medium",
            scope="system",
            source="command",
        )

        with patch.object(scanner, "registered_detectors", return_value=[FakeDetector(detected)]):
            results = scanner.scan_software({"system_key": "linux"})

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "Detected Agent")
        self.assertEqual(results[0]["evidence"], ["command_found:detected"])
        self.assertEqual(results[0]["confidence"], "medium")

    def test_scan_software_omits_non_detected_results_by_default(self) -> None:
        missing = DetectorResult(
            name="Missing Agent",
            category="edr",
            detected=False,
            evidence=[],
            confidence="none",
            scope="system",
            source="path",
        )

        with patch.object(scanner, "registered_detectors", return_value=[FakeDetector(missing)]):
            self.assertEqual(scanner.scan_software({"system_key": "linux"}), [])
            results = scanner.scan_software({"system_key": "linux"}, include_not_detected=True)

        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["detected"])

    def test_scan_handles_empty_registry(self) -> None:
        with patch.object(scanner, "registered_detectors", return_value=[]):
            self.assertEqual(scanner.scan({"system_key": "linux"}), [])
            self.assertEqual(scanner.scan_software({"system_key": "linux"}), [])


class PlatformContextTests(unittest.TestCase):
    def test_normalize_system_keys(self) -> None:
        self.assertEqual(normalize_system("Windows"), "windows")
        self.assertEqual(normalize_system("Darwin"), "darwin")
        self.assertEqual(normalize_system("Linux"), "linux")
        self.assertEqual(normalize_system(""), "unknown")

    def test_current_uses_platform_info_system_key(self) -> None:
        context = PlatformContext.current({"system_key": "darwin"})
        self.assertEqual(context.system_key, "darwin")

    def test_command_lookup_handles_found_and_missing_commands(self) -> None:
        context = PlatformContext("linux")

        with patch(
            "openassetwatch_collector.open_detector.platform.shutil.which",
            return_value="/usr/bin/example",
        ):
            self.assertTrue(context.command_exists("example"))
            self.assertEqual(context.command_path("example"), "/usr/bin/example")

        with patch(
            "openassetwatch_collector.open_detector.platform.shutil.which",
            return_value=None,
        ):
            self.assertFalse(context.command_exists("missing-example-command"))
            self.assertIsNone(context.command_path("missing-example-command"))

    def test_privilege_level_is_admin_or_standard(self) -> None:
        with patch("openassetwatch_collector.open_detector.platform.is_admin", return_value=True):
            self.assertEqual(privilege_level("linux"), "admin")

        with patch("openassetwatch_collector.open_detector.platform.is_admin", return_value=False):
            self.assertEqual(privilege_level("linux"), "standard")
            self.assertEqual(PlatformContext("linux").privilege_level(), "standard")


class SafetyHelperTests(unittest.TestCase):
    def test_safe_path_exists_handles_missing_and_invalid_paths(self) -> None:
        self.assertFalse(safe_path_exists("__openassetwatch_missing_path__"))
        self.assertFalse(safe_path_exists("bad\0path"))

    def test_path_containment_allows_inside_and_blocks_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as base:
            inside = Path(base) / "inside.txt"
            outside = Path(base).parent / "outside.txt"
            inside.write_text("ok", encoding="utf-8")
            outside.write_text("outside", encoding="utf-8")
            try:
                self.assertTrue(is_path_within_base(str(inside), base))
                self.assertFalse(is_path_within_base(str(outside), base))
                self.assertFalse(is_path_within_base(str(Path(base) / ".." / outside.name), base))
            finally:
                outside.unlink(missing_ok=True)

    def test_symlink_resolution_stays_within_base_when_possible(self) -> None:
        with tempfile.TemporaryDirectory() as base, tempfile.TemporaryDirectory() as outside_base:
            base_path = Path(base)
            target = base_path / "target.txt"
            link = base_path / "link.txt"
            outside_target = Path(outside_base) / "outside.txt"
            outside_link = base_path / "outside-link.txt"
            target.write_text("ok", encoding="utf-8")
            outside_target.write_text("outside", encoding="utf-8")
            try:
                os.symlink(target, link)
                os.symlink(outside_target, outside_link)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation is not available")

            self.assertTrue(is_path_within_base(str(link), base))
            self.assertFalse(is_path_within_base(str(outside_link), base))


class RegistryContentTests(unittest.TestCase):
    def test_initial_detector_registry_contains_expected_tools(self) -> None:
        names = {detector.name for detector in DETECTORS}
        expected = {
            "Splunk Universal Forwarder",
            "CrowdStrike Falcon",
            "Microsoft Defender",
            "Docker Desktop",
            "OpenTelemetry Collector",
            "Qualys Cloud Agent",
            "Nessus Agent",
            "Workspace ONE",
            "Intune Company Portal",
            "Zscaler",
        }

        self.assertTrue(expected.issubset(names))


if __name__ == "__main__":
    unittest.main()
