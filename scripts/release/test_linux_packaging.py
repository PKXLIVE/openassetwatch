#!/usr/bin/env python3
"""Deterministic tests for committed Linux package source metadata."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import linux_packaging as linuxsrc
from release_common import validate_version


class LinuxPackagingSourceTests(unittest.TestCase):
    def test_installed_paths_are_consistent(self) -> None:
        self.assertEqual(linuxsrc.TARGET_OS, "linux")
        self.assertEqual(linuxsrc.TARGET_ARCH, "amd64")
        self.assertEqual(linuxsrc.DEBIAN_ARCH, "amd64")
        self.assertEqual(linuxsrc.RPM_ARCH, "x86_64")
        self.assertEqual(linuxsrc.OPT_BINARY, "/opt/openassetwatch/agent/bin/oaw-agent")
        self.assertEqual(linuxsrc.USR_BIN_LINK_TARGET, linuxsrc.OPT_BINARY)
        self.assertEqual(linuxsrc.SUDOERS_INSTALL_PATH, "/etc/sudoers.d/openassetwatch-agent")
        self.assertEqual(
            linuxsrc.APPROVED_SUDOERS_COMMANDS,
            (
                "/usr/lib/openassetwatch/agent/libexec/oaw-ip-neigh-show",
                "/usr/lib/openassetwatch/agent/libexec/oaw-ip-addr-show",
            ),
        )

    def test_root_owned_executable_and_service_owned_state(self) -> None:
        self.assertIn(linuxsrc.OPT_BINARY_PACKAGE_PATH, linuxsrc.ROOT_OWNED_DIRS)
        self.assertIn("./usr/bin/oaw-agent", linuxsrc.ROOT_OWNED_DIRS)
        self.assertNotIn(linuxsrc.OPT_BINARY_PACKAGE_PATH, linuxsrc.SERVICE_OWNED_DIRS)
        self.assertEqual(
            set(linuxsrc.SERVICE_OWNED_DIRS),
            {"./var/lib/openassetwatch/agent", "./var/log/openassetwatch/agent"},
        )

    def test_helper_scripts_are_exact_no_argument_wrappers(self) -> None:
        helpers = {
            "oaw-ip-neigh-show": (linuxsrc.ip_neigh_helper_script(), "/usr/sbin/ip neigh show"),
            "oaw-ip-addr-show": (linuxsrc.ip_addr_helper_script(), "/usr/sbin/ip addr show"),
        }
        for name, (script, command) in helpers.items():
            text = script.decode("utf-8")
            with self.subTest(helper=name):
                self.assertIn('if [ "$#" -ne 0 ]; then', text)
                self.assertIn(f"exec {command}", text)
                self.assertNotIn("$@", text)
                self.assertNotIn("curl", text)
                self.assertNotIn("wget", text)
                self.assertNotIn("systemctl", text)

    def test_sudoers_allows_only_helpers(self) -> None:
        text = linuxsrc.sudoers_file().decode("utf-8")
        rules = [line for line in text.splitlines() if line.strip() and not line.startswith("#")]
        self.assertEqual(
            rules,
            [
                'openassetwatch ALL=(root) NOPASSWD: /usr/lib/openassetwatch/agent/libexec/oaw-ip-neigh-show ""',
                'openassetwatch ALL=(root) NOPASSWD: /usr/lib/openassetwatch/agent/libexec/oaw-ip-addr-show ""',
            ],
        )
        self.assertNotIn("NOPASSWD: ALL", text)
        self.assertNotIn("/usr/sbin/ip neigh show", "\n".join(rules))
        self.assertNotIn("/usr/sbin/ip addr show", "\n".join(rules))

    def test_systemd_units_use_timer_run_once_model(self) -> None:
        for unit in (linuxsrc.deb_service_unit(), linuxsrc.rpm_service_unit()):
            text = unit.decode("utf-8")
            with self.subTest(unit=text.splitlines()[0]):
                self.assertIn("Type=oneshot", text)
                self.assertIn(f"ExecStart={linuxsrc.SERVICE_COMMAND}", text)
                self.assertIn("NoNewPrivileges=true", text)
                self.assertIn("ProtectSystem=strict", text)
                self.assertIn("CapabilityBoundingSet=", text)
                self.assertIn("AmbientCapabilities=", text)
                self.assertNotIn("/bin/sh", text)
                self.assertNotIn("ExecStartPre", text)
                self.assertNotIn("ExecStartPost", text)
        for timer in (linuxsrc.deb_timer_unit(), linuxsrc.rpm_timer_unit()):
            text = timer.decode("utf-8")
            self.assertIn("OnBootSec=5min", text)
            self.assertIn("OnUnitActiveSec=1h", text)
            self.assertIn("RandomizedDelaySec=10min", text)
            self.assertIn("Persistent=true", text)

    def test_package_templates_are_not_scaffold_only(self) -> None:
        root = linuxsrc.linux_source_root()
        for relative in (
            "deb/manifest-template.yaml",
            "rpm/manifest-template.yaml",
            "targz/manifest-template.yaml",
        ):
            text = (root / relative).read_text(encoding="utf-8")
            with self.subTest(template=relative):
                self.assertNotIn("scaffold_only", text)
                self.assertIn("/opt/openassetwatch/agent/bin/oaw-agent", text)

    def test_version_validation_rejects_path_like_values(self) -> None:
        self.assertEqual(validate_version("0.1.0-linuxpkg"), "0.1.0-linuxpkg")
        for bad in ("../0.1.0", "0.1.0/linux", "C:\\temp\\0.1.0"):
            with self.subTest(version=bad):
                with self.assertRaises(ValueError):
                    validate_version(bad)


if __name__ == "__main__":
    unittest.main()
