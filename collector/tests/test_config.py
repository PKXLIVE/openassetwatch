from __future__ import annotations

import argparse
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openassetwatch_collector.main import (
    ConfigError,
    DEFAULT_MODE,
    apply_config_defaults,
    load_config,
    parse_args,
)


def make_args(config: str | None = None, **overrides: object) -> argparse.Namespace:
    defaults = {
        "config": config,
        "mode": None,
        "backend_url": None,
        "collector_id": None,
        "collector_name": None,
        "checkin": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class ConfigLoadingTests(unittest.TestCase):
    def test_load_yaml_config_reads_expected_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "collector.yaml"
            config_path.write_text(
                "\n".join(
                    [
                        "collector:",
                        "  id: local-dev-collector-01",
                        "  name: Local Dev Collector",
                        "  mode: hybrid",
                        "backend:",
                        "  url: http://localhost:8000",
                        "checkin:",
                        "  enabled: true",
                    ]
                ),
                encoding="utf-8",
            )

            config = load_config(str(config_path))

        self.assertEqual(config["collector"]["id"], "local-dev-collector-01")
        self.assertEqual(config["collector"]["name"], "Local Dev Collector")
        self.assertEqual(config["collector"]["mode"], "hybrid")
        self.assertEqual(config["backend"]["url"], "http://localhost:8000")
        self.assertTrue(config["checkin"]["enabled"])

    def test_load_json_config_reads_expected_values(self) -> None:
        payload = {
            "collector": {"id": "collector-json", "name": "JSON Collector", "mode": "network"},
            "backend": {"url": "http://localhost:8000"},
            "checkin": {"enabled": True},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "collector.json"
            config_path.write_text(json.dumps(payload), encoding="utf-8")

            config = load_config(str(config_path))

        self.assertEqual(config["collector"]["id"], "collector-json")
        self.assertEqual(config["collector"]["mode"], "network")
        self.assertTrue(config["checkin"]["enabled"])

    def test_missing_config_file_raises_clear_error(self) -> None:
        with self.assertRaisesRegex(ConfigError, "unable to read config file"):
            load_config("__missing-openassetwatch-config.yaml")

    def test_invalid_config_raises_clear_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "collector.json"
            config_path.write_text("{not valid json", encoding="utf-8")

            with self.assertRaisesRegex(ConfigError, "invalid config file"):
                load_config(str(config_path))

    def test_non_object_config_raises_clear_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "collector.json"
            config_path.write_text("[1, 2, 3]", encoding="utf-8")

            with self.assertRaisesRegex(ConfigError, "must contain an object"):
                load_config(str(config_path))


class ConfigDefaultsTests(unittest.TestCase):
    def test_apply_config_defaults_uses_config_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "collector.yaml"
            config_path.write_text(
                "\n".join(
                    [
                        "collector:",
                        "  id: local-dev-collector-01",
                        "  name: Local Dev Collector",
                        "  mode: hybrid",
                        "backend:",
                        "  url: http://localhost:8000",
                        "checkin:",
                        "  enabled: true",
                    ]
                ),
                encoding="utf-8",
            )

            args = apply_config_defaults(make_args(str(config_path)))

        self.assertEqual(args.mode, "hybrid")
        self.assertEqual(args.backend_url, "http://localhost:8000")
        self.assertEqual(args.collector_id, "local-dev-collector-01")
        self.assertEqual(args.collector_name, "Local Dev Collector")
        self.assertTrue(args.checkin)

    def test_cli_values_override_config_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "collector.yaml"
            config_path.write_text(
                "\n".join(
                    [
                        "collector:",
                        "  id: config-id",
                        "  name: Config Collector",
                        "  mode: hybrid",
                        "backend:",
                        "  url: http://localhost:8000",
                        "checkin:",
                        "  enabled: true",
                    ]
                ),
                encoding="utf-8",
            )

            args = apply_config_defaults(
                make_args(
                    str(config_path),
                    mode="device",
                    backend_url="http://example.test:8000",
                    collector_id="cli-id",
                    collector_name="CLI Collector",
                    checkin=True,
                )
            )

        self.assertEqual(args.mode, "device")
        self.assertEqual(args.backend_url, "http://example.test:8000")
        self.assertEqual(args.collector_id, "cli-id")
        self.assertEqual(args.collector_name, "CLI Collector")
        self.assertTrue(args.checkin)

    def test_no_config_preserves_default_mode_and_no_checkin(self) -> None:
        args = apply_config_defaults(make_args())

        self.assertEqual(args.mode, DEFAULT_MODE)
        self.assertIsNone(args.backend_url)
        self.assertIsNone(args.collector_id)
        self.assertIsNone(args.collector_name)
        self.assertFalse(args.checkin)

    def test_parse_args_reports_config_error_with_system_exit(self) -> None:
        with patch("sys.argv", ["openassetwatch-collector", "--config", "__missing.yaml"]):
            with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                with self.assertRaises(SystemExit) as raised:
                    parse_args()

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("unable to read config file", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
