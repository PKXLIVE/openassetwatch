from __future__ import annotations

import argparse
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

from openassetwatch_collector.main import ConfigError, apply_config_defaults, main, run_scheduler


def make_args(**overrides: object) -> argparse.Namespace:
    defaults = {
        "mode": "hybrid",
        "backend_url": "http://localhost:8000",
        "collector_id": "local-dev-collector-01",
        "collector_name": "Local Dev Collector",
        "heartbeat_interval_seconds": 10,
        "inventory_interval_seconds": 20,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def make_config_args(config: str | None = None, **overrides: object) -> argparse.Namespace:
    defaults = {
        "config": config,
        "mode": None,
        "backend_url": None,
        "collector_id": None,
        "collector_name": None,
        "checkin": False,
        "upload_inventory": False,
        "run_forever": False,
        "heartbeat_interval_seconds": None,
        "inventory_interval_seconds": None,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class SchedulerTests(unittest.TestCase):
    def test_config_scheduler_values_map_to_args(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "collector.yaml"
            config_path.write_text(
                "\n".join(
                    [
                        "collector:",
                        "  id: local-dev-collector-01",
                        "  mode: hybrid",
                        "backend:",
                        "  url: http://localhost:8000",
                        "scheduler:",
                        "  enabled: true",
                        "  heartbeat_interval_seconds: 11",
                        "  inventory_interval_seconds: 22",
                    ]
                ),
                encoding="utf-8",
            )

            args = apply_config_defaults(make_config_args(str(config_path)))

        self.assertTrue(args.run_forever)
        self.assertEqual(args.heartbeat_interval_seconds, 11)
        self.assertEqual(args.inventory_interval_seconds, 22)

    def test_config_scheduler_interval_strings_are_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "collector.yaml"
            config_path.write_text(
                "\n".join(
                    [
                        "scheduler:",
                        "  heartbeat_interval_seconds: '12'",
                        "  inventory_interval_seconds: '24'",
                    ]
                ),
                encoding="utf-8",
            )

            args = apply_config_defaults(make_config_args(str(config_path)))

        self.assertEqual(args.heartbeat_interval_seconds, 12)
        self.assertEqual(args.inventory_interval_seconds, 24)

    def test_config_scheduler_invalid_interval_is_clear_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "collector.yaml"
            config_path.write_text(
                "\n".join(
                    [
                        "scheduler:",
                        "  heartbeat_interval_seconds: 0",
                    ]
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ConfigError, "scheduler.heartbeat_interval_seconds"):
                apply_config_defaults(make_config_args(str(config_path)))

    def test_cli_scheduler_values_override_config(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "collector.yaml"
            config_path.write_text(
                "\n".join(
                    [
                        "scheduler:",
                        "  enabled: true",
                        "  heartbeat_interval_seconds: 3600",
                        "  inventory_interval_seconds: 86400",
                    ]
                ),
                encoding="utf-8",
            )

            args = apply_config_defaults(
                make_config_args(
                    str(config_path),
                    run_forever=True,
                    heartbeat_interval_seconds=5,
                    inventory_interval_seconds=9,
                )
            )

        self.assertTrue(args.run_forever)
        self.assertEqual(args.heartbeat_interval_seconds, 5)
        self.assertEqual(args.inventory_interval_seconds, 9)

    def test_scheduler_runs_initial_cycle_immediately(self) -> None:
        calls = []

        def fake_cycle(args: argparse.Namespace, *, checkin: bool, upload_inventory: bool) -> dict[str, object]:
            calls.append((checkin, upload_inventory))
            return {"mode": args.mode}

        with patch("openassetwatch_collector.main.run_backend_cycle", side_effect=fake_cycle):
            with patch("sys.stderr", new_callable=io.StringIO):
                exit_code = run_scheduler(make_args(), sleep_func=lambda seconds: None, max_cycles=1)

        self.assertEqual(exit_code, 0)
        self.assertEqual(calls, [(True, True)])

    def test_scheduler_runs_due_intervals_with_mocked_time(self) -> None:
        calls = []
        current_time = {"value": 0.0}

        def fake_cycle(args: argparse.Namespace, *, checkin: bool, upload_inventory: bool) -> dict[str, object]:
            calls.append((checkin, upload_inventory))
            return {"mode": args.mode}

        def fake_sleep(seconds: float) -> None:
            current_time["value"] += seconds

        with patch("openassetwatch_collector.main.run_backend_cycle", side_effect=fake_cycle):
            with patch("sys.stderr", new_callable=io.StringIO):
                exit_code = run_scheduler(
                    make_args(heartbeat_interval_seconds=10, inventory_interval_seconds=20),
                    sleep_func=fake_sleep,
                    monotonic_func=lambda: current_time["value"],
                    max_cycles=3,
                )

        self.assertEqual(exit_code, 0)
        self.assertEqual(calls, [(True, True), (True, False), (True, True)])

    def test_scheduler_backend_errors_do_not_crash(self) -> None:
        args = make_args()
        payload = {"mode": "hybrid", "device": {"hostname": "test-host"}}

        with patch("openassetwatch_collector.main.build_payload", return_value=payload):
            with patch("openassetwatch_collector.main.send_checkin", side_effect=URLError("down")):
                with patch("openassetwatch_collector.main.send_inventory", side_effect=URLError("down")):
                    with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                        exit_code = run_scheduler(args, sleep_func=lambda seconds: None, max_cycles=1)

        self.assertEqual(exit_code, 0)
        self.assertIn("collector check-in failed", stderr.getvalue())
        self.assertIn("collector inventory upload failed", stderr.getvalue())

    def test_scheduler_keyboard_interrupt_exits_cleanly(self) -> None:
        with patch("openassetwatch_collector.main.run_backend_cycle", side_effect=KeyboardInterrupt):
            with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                exit_code = run_scheduler(make_args())

        self.assertEqual(exit_code, 0)
        self.assertIn("scheduler stopped", stderr.getvalue())

    def test_one_shot_behavior_still_does_not_start_scheduler(self) -> None:
        with patch("sys.argv", ["openassetwatch-collector", "--mode", "device"]):
            with patch("openassetwatch_collector.main.build_payload", return_value={"mode": "device", "device": {}}):
                with patch("openassetwatch_collector.main.run_scheduler") as scheduler:
                    with patch("sys.stdout", new_callable=io.StringIO):
                        exit_code = main()

        self.assertEqual(exit_code, 0)
        scheduler.assert_not_called()

    def test_scheduled_mode_requires_backend_url(self) -> None:
        with patch("sys.argv", ["openassetwatch-collector", "--run-forever", "--collector-id", "collector-1"]):
            with self.assertRaises(SystemExit) as raised:
                main()

        self.assertEqual(str(raised.exception), "--backend-url is required when scheduled mode is enabled")


if __name__ == "__main__":
    unittest.main()
