from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


def load_service_manager_module():
    module_path = Path(__file__).resolve().parents[1] / "install" / "service_manager.py"
    spec = importlib.util.spec_from_file_location("openassetwatch_service_manager", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load service manager module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ServiceManagerPlanTests(unittest.TestCase):
    def test_windows_status_uses_schtasks_query(self) -> None:
        manager = load_service_manager_module()

        plan = manager.build_service_plan("status", "windows")

        self.assertEqual(plan.system, "windows")
        self.assertEqual(plan.commands[0].args[:3], ("schtasks.exe", "/Query", "/TN"))
        self.assertIn("OpenAssetWatch Collector", plan.commands[0].args)
        self.assertTrue(any("Task Scheduler" in note for note in plan.notes))

    def test_windows_restart_stops_then_starts_task(self) -> None:
        manager = load_service_manager_module()

        plan = manager.build_service_plan("restart", "windows")

        self.assertEqual(plan.commands[0].args[:2], ("schtasks.exe", "/End"))
        self.assertFalse(plan.commands[0].check)
        self.assertEqual(plan.commands[1].args[:2], ("schtasks.exe", "/Run"))

    def test_linux_restart_uses_systemctl(self) -> None:
        manager = load_service_manager_module()

        plan = manager.build_service_plan("restart", "linux")

        self.assertEqual(
            plan.commands[0].args,
            ("systemctl", "restart", "openassetwatch-collector"),
        )

    def test_macos_start_uses_launchctl_bootstrap(self) -> None:
        manager = load_service_manager_module()

        plan = manager.build_service_plan("start", "darwin")

        self.assertEqual(plan.commands[0].args[:3], ("launchctl", "bootstrap", "system"))
        self.assertIn(
            "/Library/LaunchDaemons/com.openassetwatch.collector.plist",
            plan.commands[0].args,
        )

    def test_logs_actions_do_not_require_native_commands_on_windows_or_macos(self) -> None:
        manager = load_service_manager_module()

        windows_plan = manager.build_service_plan("logs", "windows")
        macos_plan = manager.build_service_plan("logs", "darwin")

        self.assertEqual(windows_plan.commands, ())
        self.assertTrue(any("install.log" in note for note in windows_plan.notes))
        self.assertEqual(macos_plan.commands, ())
        self.assertTrue(any("collector.out.log" in note for note in macos_plan.notes))

    def test_execute_plan_uses_mocked_command_runner(self) -> None:
        manager = load_service_manager_module()
        plan = manager.build_service_plan("status", "linux")

        with patch.object(manager.subprocess, "run") as mock_run, patch("builtins.print"):
            mock_run.return_value.returncode = 0
            exit_code = manager.execute_plan(plan)

        self.assertEqual(exit_code, 0)
        mock_run.assert_called_once_with(
            ["systemctl", "status", "openassetwatch-collector"],
            check=False,
        )

    def test_unsupported_system_fails_cleanly(self) -> None:
        manager = load_service_manager_module()

        with self.assertRaises(ValueError):
            manager.build_service_plan("status", "plan9")


if __name__ == "__main__":
    unittest.main()
