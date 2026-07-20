from __future__ import annotations

import importlib.util
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def load_installer_module():
    module_path = Path(__file__).resolve().parents[1] / "install" / "install.py"
    spec = importlib.util.spec_from_file_location("openassetwatch_installer", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load installer module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class InstallerTokenTests(unittest.TestCase):
    def test_redact_config_text_hides_backend_token(self) -> None:
        installer = load_installer_module()
        text = "\n".join(
            [
                "backend:",
                "  url: http://localhost:8000",
                "  token: change-me-dev-token",
                "checkin:",
                "  enabled: true",
            ]
        )

        redacted = installer.redact_config_text(text)

        self.assertIn('token: "<redacted>"', redacted)
        self.assertNotIn("change-me-dev-token", redacted)


class LinuxInstallerSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.installer = load_installer_module()

    def test_linux_installer_log_is_separate_from_collector_runtime_logs(self) -> None:
        paths = self.installer.InstallPaths(
            install_dir=Path("/opt/openassetwatch/collector"),
            config_path=Path("/etc/openassetwatch/collector.yaml"),
            logs_dir=Path("/var/log/openassetwatch"),
            state_dir=Path("/var/lib/openassetwatch"),
        )

        privileged_log = self.installer.installer_log_path(paths, "linux")

        self.assertEqual(privileged_log, self.installer.LINUX_INSTALLER_LOG_PATH)
        self.assertNotEqual(privileged_log.parent, paths.logs_dir)
        self.assertEqual(
            self.installer.installer_log_path(paths, "windows"),
            paths.logs_dir / "install.log",
        )

    @unittest.skipUnless(os.name == "posix", "secure descriptor checks require POSIX")
    def test_secure_linux_installer_log_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            log_dir = root / "installer"
            log_dir.mkdir(mode=0o700)
            victim = root / "victim"
            victim.write_text("unchanged\n", encoding="utf-8")
            log_path = log_dir / "collector-install.log"
            log_path.symlink_to(victim)

            with self.assertRaises(OSError):
                self.installer.open_secure_linux_installer_log(
                    log_path,
                    expected_uid=os.geteuid(),
                )

            self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged\n")

    @unittest.skipUnless(os.name == "posix", "secure descriptor checks require POSIX")
    def test_secure_linux_installer_log_appends_with_restrictive_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "installer" / "collector-install.log"

            with self.installer.open_secure_linux_installer_log(
                log_path,
                expected_uid=os.geteuid(),
            ) as log_file:
                log_file.write("first\n")
            with self.installer.open_secure_linux_installer_log(
                log_path,
                expected_uid=os.geteuid(),
            ) as log_file:
                log_file.write("second\n")

            self.assertEqual(log_path.read_text(encoding="utf-8"), "first\nsecond\n")
            self.assertEqual(stat.S_IMODE(log_path.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(log_path.stat().st_mode), 0o600)

    @unittest.skipUnless(os.name == "posix", "atomic sudoers replacement requires POSIX")
    def test_linux_sudoers_replaces_symlink_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sudoers_path = root / "openassetwatch-collector"
            victim = root / "victim"
            victim.write_text("unchanged\n", encoding="utf-8")
            sudoers_path.symlink_to(victim)
            commands: list[list[str]] = []

            with (
                patch.object(
                    self.installer,
                    "sudoers_entries",
                    return_value=["openassetwatch ALL=(root) NOPASSWD: /usr/sbin/ip neigh show"],
                ),
                patch.object(self.installer, "command_exists", return_value=True),
                patch.object(
                    self.installer,
                    "run",
                    side_effect=lambda command, **_kwargs: commands.append(command),
                ),
                patch.object(self.installer, "linux_chown"),
                patch.object(self.installer, "linux_chmod"),
            ):
                self.installer.write_linux_sudoers(
                    dry_run=False,
                    sudoers_path=sudoers_path,
                )

            self.assertFalse(sudoers_path.is_symlink())
            self.assertIn("openassetwatch ALL=(root)", sudoers_path.read_text(encoding="utf-8"))
            self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged\n")
            self.assertEqual(commands[-1], ["visudo", "-cf", str(sudoers_path)])
            validated_temp = Path(commands[0][-1])
            self.assertEqual(validated_temp.parent, sudoers_path.parent)
            self.assertTrue(validated_temp.name.startswith(".openassetwatch-collector."))
            self.assertFalse(validated_temp.exists())


if __name__ == "__main__":
    unittest.main()
