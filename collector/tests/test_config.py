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
    load_or_create_collector_identity,
    parse_args,
)


def make_args(config: str | None = None, **overrides: object) -> argparse.Namespace:
    defaults = {
        "config": config,
        "mode": None,
        "backend_url": None,
        "collector_id": None,
        "collector_name": None,
        "collector_guid": None,
        "identity_file": None,
        "deployment_id": None,
        "business_unit": None,
        "site": None,
        "deployment_environment": None,
        "install_ring": None,
        "label": [],
        "labels": None,
        "deployment": None,
        "checkin": False,
        "upload_inventory": False,
        "run_forever": False,
        "heartbeat_interval_seconds": None,
        "inventory_interval_seconds": None,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class ConfigLoadingTests(unittest.TestCase):
    def test_identity_file_is_created_if_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            identity_path = Path(temp_dir) / "identity.json"

            identity = load_or_create_collector_identity(str(identity_path), "unit-test")

            self.assertTrue(identity_path.exists())
            self.assertEqual(identity["install_source"], "unit-test")
            self.assertEqual(identity, json.loads(identity_path.read_text(encoding="utf-8")))

    def test_identity_file_is_preserved_on_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            identity_path = Path(temp_dir) / "identity.json"
            first = load_or_create_collector_identity(str(identity_path), "unit-test")
            second = load_or_create_collector_identity(str(identity_path), "unit-test")

        self.assertEqual(first["collector_guid"], second["collector_guid"])
        self.assertEqual(first["created_at"], second["created_at"])

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
                        "deployment:",
                        "  deployment_id: home-lab-cincinnati",
                        "labels:",
                        "  owner: dion",
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
        self.assertEqual(config["deployment"]["deployment_id"], "home-lab-cincinnati")
        self.assertEqual(config["labels"]["owner"], "dion")
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
                        "identity:",
                        "  path: ./identity.json",
                        "deployment:",
                        "  deployment_id: home-lab-cincinnati",
                        "  business_unit: lab",
                        "  site: home",
                        "  environment: test",
                        "  install_ring: pilot",
                        "labels:",
                        "  owner: dion",
                        "  device_group: mac-test",
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
        self.assertEqual(args.identity_file, "./identity.json")
        self.assertEqual(args.deployment["deployment_id"], "home-lab-cincinnati")
        self.assertEqual(args.deployment["business_unit"], "lab")
        self.assertEqual(args.labels["owner"], "dion")
        self.assertEqual(args.labels["device_group"], "mac-test")
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
                    deployment_id="cli-deployment",
                    label=["owner=cli"],
                    checkin=True,
                )
            )

        self.assertEqual(args.mode, "device")
        self.assertEqual(args.backend_url, "http://example.test:8000")
        self.assertEqual(args.collector_id, "cli-id")
        self.assertEqual(args.collector_name, "CLI Collector")
        self.assertEqual(args.deployment["deployment_id"], "cli-deployment")
        self.assertEqual(args.labels["owner"], "cli")
        self.assertTrue(args.checkin)

    def test_no_config_preserves_default_mode_and_no_checkin(self) -> None:
        args = apply_config_defaults(make_args())

        self.assertEqual(args.mode, DEFAULT_MODE)
        self.assertIsNone(args.backend_url)
        self.assertIsNone(args.collector_id)
        self.assertIsNone(args.collector_name)
        self.assertIsNone(args.collector_guid)
        self.assertIsNone(args.identity_file)
        self.assertIsNone(args.deployment)
        self.assertIsNone(args.labels)
        self.assertFalse(args.checkin)
        self.assertFalse(args.run_forever)
        self.assertEqual(args.heartbeat_interval_seconds, 3600)
        self.assertEqual(args.inventory_interval_seconds, 86400)

    def test_parse_args_reports_config_error_with_system_exit(self) -> None:
        with patch("sys.argv", ["openassetwatch-collector", "--config", "__missing.yaml"]):
            with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                with self.assertRaises(SystemExit) as raised:
                    parse_args()

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("unable to read config file", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
