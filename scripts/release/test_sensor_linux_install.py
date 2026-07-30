from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALLER_PATH = REPO_ROOT / "scripts" / "release" / "install_sensor_linux.py"


def load_installer():
    spec = importlib.util.spec_from_file_location("install_sensor_linux", INSTALLER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load Linux sensor installer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SensorLinuxInstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.installer = load_installer()

    def setUp(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX installer lifecycle runs in Linux container validation")

    def fake_binary(self, directory: Path, marker: bytes = b"v1") -> Path:
        path = directory / f"oaw-sensor-{marker.decode()}"
        path.write_bytes(b"\x7fELF" + marker)
        path.chmod(0o755)
        return path

    def args(self, root: Path, binary: Path, **overrides):
        values = {
            "root": str(root),
            "binary": str(binary),
            "unit_template": str(self.installer.DEFAULT_UNIT_TEMPLATE),
            "hub_url": "https://hub.example.test",
            "site_id": "site-demo",
            "interface": "eth1",
            "sensor_name": "OpenAssetWatch Passive Sensor",
            "start": False,
            "confirm_purge": False,
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def reporter(self, action: str, dry_run: bool = False):
        return self.installer.Reporter(action, dry_run, True)

    def target(self, root: Path, absolute: str) -> Path:
        return self.installer.rooted(root, absolute)

    def assert_mode(self, path: Path, expected: int) -> None:
        self.assertEqual(stat.S_IMODE(path.lstat().st_mode), expected, path)

    def test_install_repair_upgrade_uninstall_and_purge_preserve_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            root = workspace / "root"
            root.mkdir(mode=0o700)
            first = self.fake_binary(workspace, b"v1")
            second = self.fake_binary(workspace, b"v2")

            install_reporter = self.reporter("install")
            self.installer.install_or_repair(self.args(root, first), install_reporter)

            binary = self.target(root, self.installer.BINARY_PATH)
            config = self.target(root, self.installer.CONFIG_PATH)
            unit = self.target(root, self.installer.UNIT_PATH)
            state = self.target(root, self.installer.STATE_DIR)
            spool = self.target(root, self.installer.SPOOL_PATH)
            self.assertEqual(binary.read_bytes(), b"\x7fELFv1")
            self.assert_mode(binary, 0o755)
            self.assert_mode(config, 0o640)
            self.assert_mode(unit, 0o644)
            self.assert_mode(state, 0o700)
            self.assert_mode(spool, 0o700)
            config_value = json.loads(config.read_text(encoding="utf-8"))
            self.assertEqual(config_value["capture_interface"], "eth1")
            self.assertEqual(config_value["capture_mode"], "live")
            for secret_field in ("credential", "token", "enrollment_token", "sensor_credential"):
                self.assertNotIn(secret_field, config_value)

            preserved = {
                self.installer.IDENTITY_PATH: b'{"identity":"stable"}\n',
                self.installer.CREDENTIAL_PATH: b'{"credential":"deterministic-test-only"}\n',
                self.installer.STATUS_PATH: b'{"running":false}\n',
            }
            for absolute, contents in preserved.items():
                path = self.target(root, absolute)
                path.write_bytes(contents)
                path.chmod(0o600)
            queued = spool / "queued.json"
            queued.write_text('{"bounded":"normalized-only"}\n', encoding="utf-8")
            queued.chmod(0o600)

            repair_reporter = self.reporter("repair")
            self.installer.install_or_repair(
                self.args(root, first, hub_url=None, site_id=None, interface=None),
                repair_reporter,
            )
            upgrade_reporter = self.reporter("upgrade")
            self.installer.install_or_repair(
                self.args(root, second, hub_url=None, site_id=None, interface=None),
                upgrade_reporter,
            )
            self.assertEqual(binary.read_bytes(), b"\x7fELFv2")
            for absolute, contents in preserved.items():
                self.assertEqual(self.target(root, absolute).read_bytes(), contents)
            self.assertTrue(queued.is_file())
            self.assertEqual(config_value, json.loads(config.read_text(encoding="utf-8")))

            uninstall_reporter = self.reporter("uninstall")
            self.installer.uninstall(self.args(root, second), uninstall_reporter)
            self.assertFalse(binary.exists())
            self.assertFalse(unit.exists())
            self.assertTrue(config.is_file())
            self.assertTrue(state.is_dir())
            self.assertTrue(queued.is_file())

            purge_reporter = self.reporter("purge")
            self.installer.purge(
                self.args(root, second, confirm_purge=True),
                purge_reporter,
            )
            self.assertFalse(self.target(root, self.installer.CONFIG_DIR).exists())
            self.assertFalse(state.exists())

    def test_install_is_idempotent_and_agent_paths_remain_separate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            root = workspace / "root"
            root.mkdir(mode=0o700)
            binary = self.fake_binary(workspace)
            for action in ("install", "repair"):
                self.installer.install_or_repair(self.args(root, binary), self.reporter(action))
            unit_text = self.target(root, self.installer.UNIT_PATH).read_text(encoding="utf-8")
            self.assertIn("openassetwatch-sensor", unit_text)
            self.assertNotIn("oaw-agent", unit_text)
            self.assertNotIn("/var/lib/openassetwatch/agent", unit_text)
            self.assertNotIn("/etc/openassetwatch/agent", unit_text)

    def test_unit_requires_only_net_raw_and_never_root(self) -> None:
        data = self.installer.DEFAULT_UNIT_TEMPLATE.read_bytes()
        text = self.installer.validate_unit_text(data, self.reporter("install"))
        self.assertIn("CapabilityBoundingSet=CAP_NET_RAW", text)
        self.assertIn("AmbientCapabilities=CAP_NET_RAW", text)
        self.assertNotIn("CAP_NET_ADMIN", text)
        self.assertNotIn("CAP_SYS_ADMIN", text)
        self.assertNotIn("User=root", text)
        self.assertNotIn("Environment=", text)

    def test_unsafe_destination_parent_and_unit_fail_before_activation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            binary = self.fake_binary(workspace)

            invalid_unit = workspace / "invalid.service"
            invalid_unit.write_text("[Service]\nUser=root\n", encoding="utf-8")
            invalid_root = workspace / "invalid-root"
            invalid_root.mkdir(mode=0o700)
            with self.assertRaises(self.installer.InstallError):
                self.installer.install_or_repair(
                    self.args(invalid_root, binary, unit_template=str(invalid_unit)),
                    self.reporter("install"),
                )
            self.assertEqual(list(invalid_root.iterdir()), [])

            unsafe_root = workspace / "unsafe-root"
            (unsafe_root / "usr" / "bin").mkdir(parents=True)
            (unsafe_root / "etc").mkdir()
            (unsafe_root / "etc").chmod(0o777)
            with self.assertRaises(self.installer.InstallError):
                self.installer.install_or_repair(self.args(unsafe_root, binary), self.reporter("install"))
            self.assertFalse((unsafe_root / "usr" / "bin" / "oaw-sensor").exists())

    def test_symlink_destination_and_unconfirmed_purge_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            root = workspace / "root"
            root.mkdir(mode=0o700)
            binary = self.fake_binary(workspace)
            self.installer.install_or_repair(self.args(root, binary), self.reporter("install"))
            target = self.target(root, self.installer.BINARY_PATH)
            target.unlink()
            target.symlink_to(binary)
            with self.assertRaises(self.installer.InstallError):
                self.installer.install_or_repair(
                    self.args(root, binary, hub_url=None, site_id=None, interface=None),
                    self.reporter("repair"),
                )
            with self.assertRaises(self.installer.InstallError):
                self.installer.purge(self.args(root, binary), self.reporter("purge"))

    def test_symlinked_sources_and_noncanonical_unit_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            root = workspace / "root"
            root.mkdir(mode=0o700)
            binary = self.fake_binary(workspace)
            binary_link = workspace / "sensor-link"
            binary_link.symlink_to(binary)
            with self.assertRaises(self.installer.InstallError):
                self.installer.install_or_repair(self.args(root, binary_link), self.reporter("install"))
            self.assertEqual(list(root.iterdir()), [])

            unit = workspace / "sensor.service"
            unit.write_bytes(self.installer.DEFAULT_UNIT_TEMPLATE.read_bytes() + b"\nReadWritePaths=/\n")
            with self.assertRaises(self.installer.InstallError):
                self.installer.install_or_repair(
                    self.args(root, binary, unit_template=str(unit)),
                    self.reporter("install"),
                )
            self.assertEqual(list(root.iterdir()), [])

    def test_hard_linked_binary_and_symlinked_private_state_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            root = workspace / "root"
            root.mkdir(mode=0o700)
            binary = self.fake_binary(workspace)
            self.installer.install_or_repair(self.args(root, binary), self.reporter("install"))

            installed = self.target(root, self.installer.BINARY_PATH)
            hard_link = installed.with_name("oaw-sensor-hard-link")
            os.link(installed, hard_link)
            with self.assertRaises(self.installer.InstallError):
                self.installer.install_or_repair(
                    self.args(root, binary, hub_url=None, site_id=None, interface=None),
                    self.reporter("repair"),
                )
            hard_link.unlink()

            identity = self.target(root, self.installer.IDENTITY_PATH)
            identity.symlink_to(binary)
            with self.assertRaises(self.installer.InstallError):
                self.installer.install_or_repair(
                    self.args(root, binary, hub_url=None, site_id=None, interface=None),
                    self.reporter("repair"),
                )

    def test_dry_run_has_fixed_paths_and_no_secret_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            root = workspace / "root"
            root.mkdir(mode=0o700)
            binary = self.fake_binary(workspace)
            reporter = self.reporter("install", dry_run=True)
            self.installer.install_or_repair(self.args(root, binary), reporter)
            output = json.dumps(reporter.summary(True))
            for path in (
                self.installer.BINARY_PATH,
                self.installer.CONFIG_PATH,
                self.installer.STATE_DIR,
                self.installer.SPOOL_PATH,
                self.installer.UNIT_PATH,
            ):
                self.assertIn(path, output)
            self.assertNotIn("enrollment_token", output)
            self.assertNotIn("sensor_credential", output)
            self.assertEqual(list(root.iterdir()), [])

    def test_failed_upgrade_rolls_back_managed_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            root = workspace / "root"
            root.mkdir(mode=0o700)
            first = self.fake_binary(workspace, b"v1")
            second = self.fake_binary(workspace, b"v2")
            self.installer.install_or_repair(self.args(root, first), self.reporter("install"))
            managed = [
                self.target(root, self.installer.BINARY_PATH),
                self.target(root, self.installer.CONFIG_PATH),
                self.target(root, self.installer.UNIT_PATH),
            ]
            before = {path: path.read_bytes() for path in managed}
            with mock.patch.object(
                self.installer,
                "systemd_verify",
                side_effect=self.installer.InstallError("synthetic validation failure"),
            ):
                with self.assertRaises(self.installer.InstallError):
                    self.installer.install_or_repair(
                        self.args(root, second, hub_url=None, site_id=None, interface=None),
                        self.reporter("upgrade"),
                    )
            self.assertEqual(before, {path: path.read_bytes() for path in managed})

    def test_purge_rejects_nested_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            root = workspace / "root"
            root.mkdir(mode=0o700)
            binary = self.fake_binary(workspace)
            self.installer.install_or_repair(self.args(root, binary), self.reporter("install"))
            spool = self.target(root, self.installer.SPOOL_PATH)
            (spool / "unsafe-link").symlink_to(binary)
            installed_binary = self.target(root, self.installer.BINARY_PATH)
            installed_unit = self.target(root, self.installer.UNIT_PATH)
            with self.assertRaises(self.installer.InstallError):
                self.installer.purge(
                    self.args(root, binary, confirm_purge=True),
                    self.reporter("purge"),
                )
            self.assertTrue(installed_binary.is_file())
            self.assertTrue(installed_unit.is_file())


if __name__ == "__main__":
    unittest.main()
