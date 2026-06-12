from __future__ import annotations

import argparse
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError

from openassetwatch_collector.main import (
    COLLECTOR_TOKEN_HEADER,
    ConfigError,
    apply_config_defaults,
    calculate_policy_hash,
    retrieve_and_apply_policy,
    run_scheduler,
    send_policy_request,
    validate_policy_payload,
)


def make_policy(**overrides: object) -> dict[str, object]:
    policy: dict[str, object] = {
        "policy_id": "default-local-collector",
        "policy_version": 1,
        "license_status": "dev_mode",
        "assigned_capabilities": [
            "device_inventory",
            "network_neighbors",
            "open_detector",
        ],
        "denied_capabilities": [],
        "policy": {
            "mode": "hybrid",
            "scheduler": {
                "heartbeat_interval_seconds": 3600,
                "inventory_interval_seconds": 86400,
            },
            "modules": {
                "open_detector": {"enabled": True},
                "reverse_dns": {"enabled": False},
                "mdns": {"enabled": False},
                "ssdp": {"enabled": False},
                "snmp": {"enabled": False},
                "nmap_light": {"enabled": False},
                "passive_sensor": {"enabled": False},
            },
            "actions": {
                "run_inventory_now": False,
            },
        },
    }
    policy.update(overrides)
    policy["policy_hash"] = calculate_policy_hash(policy)
    return policy


def make_args(**overrides: object) -> argparse.Namespace:
    defaults = {
        "mode": "device",
        "backend_url": "http://localhost:8000",
        "backend_token": None,
        "collector_id": "local-dev-collector-01",
        "collector_name": "Local Dev Collector",
        "collector_guid": "11111111-1111-4111-8111-111111111111",
        "deployment": None,
        "labels": None,
        "heartbeat_interval_seconds": 10,
        "inventory_interval_seconds": 20,
        "policy_enabled": True,
        "policy_cache_path": None,
        "policy_hold_file_path": None,
        "policy_check_interval_seconds": 3600,
        "open_detector_enabled": True,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def header_value(headers: dict[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


class PolicyTests(unittest.TestCase):
    def test_policy_hash_validation_accepts_matching_hash(self) -> None:
        policy = make_policy()

        validate_policy_payload(policy)

    def test_policy_hash_validation_rejects_tampered_policy(self) -> None:
        policy = make_policy()
        policy["policy"]["mode"] = "network"  # type: ignore[index]

        with self.assertRaisesRegex(ConfigError, "hash validation failed"):
            validate_policy_payload(policy)

    def test_send_policy_request_sends_token_header(self) -> None:
        response_body = json.dumps(make_policy()).encode("utf-8")

        class FakeResponse:
            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
                return None

            def read(self) -> bytes:
                return response_body

        captured = {}

        def fake_urlopen(request: object, timeout: int) -> FakeResponse:
            captured["url"] = request.full_url
            captured["headers"] = dict(request.header_items())
            captured["timeout"] = timeout
            return FakeResponse()

        with patch("openassetwatch_collector.main.urlopen", side_effect=fake_urlopen):
            policy = send_policy_request("http://localhost:8000/", "change-me-dev-token")

        self.assertEqual(captured["url"], "http://localhost:8000/api/v1/collectors/policy")
        self.assertEqual(header_value(captured["headers"], COLLECTOR_TOKEN_HEADER), "change-me-dev-token")
        self.assertEqual(captured["timeout"], 15)
        self.assertEqual(policy["policy_id"], "default-local-collector")

    def test_config_policy_values_map_to_args(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "policy-cache.json"
            hold_path = Path(temp_dir) / "policy.hold"
            config_path = Path(temp_dir) / "collector.yaml"
            config_path.write_text(
                "\n".join(
                    [
                        "backend:",
                        "  url: http://localhost:8000",
                        "policy:",
                        "  enabled: true",
                        f"  cache_path: {cache_path}",
                        f"  hold_file_path: {hold_path}",
                        "  check_interval_seconds: 44",
                    ]
                ),
                encoding="utf-8",
            )

            args = apply_config_defaults(make_config_args(str(config_path)))

        self.assertTrue(args.policy_enabled)
        self.assertEqual(args.policy_cache_path, str(cache_path))
        self.assertEqual(args.policy_hold_file_path, str(hold_path))
        self.assertEqual(args.policy_check_interval_seconds, 44)

    def test_retrieval_is_skipped_when_policy_disabled(self) -> None:
        args = make_args(policy_enabled=False)

        with patch("openassetwatch_collector.main.send_policy_request") as send_policy:
            run_inventory_now = retrieve_and_apply_policy(args)

        self.assertFalse(run_inventory_now)
        send_policy.assert_not_called()

    def test_hold_file_blocks_retrieval_and_reports_held(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            hold_path = Path(temp_dir) / "policy.hold"
            hold_path.write_text("hold", encoding="utf-8")
            args = make_args(policy_hold_file_path=str(hold_path))

            with patch("openassetwatch_collector.main.send_policy_request") as send_policy:
                with patch("openassetwatch_collector.main.send_policy_status", return_value={"status": "accepted"}) as status:
                    with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                        with patch("sys.stdout", new_callable=io.StringIO):
                            run_inventory_now = retrieve_and_apply_policy(args)

        self.assertFalse(run_inventory_now)
        send_policy.assert_not_called()
        self.assertEqual(status.call_args.args[1]["policy_status"], "held")
        self.assertIn("collector policy held", stderr.getvalue())

    def test_retrieved_policy_updates_safe_runtime_settings_and_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "policy-cache.json"
            policy = make_policy(
                policy={
                    "mode": "network",
                    "scheduler": {
                        "heartbeat_interval_seconds": 30,
                        "inventory_interval_seconds": 60,
                    },
                    "modules": {"open_detector": {"enabled": False}},
                    "actions": {"run_inventory_now": True},
                }
            )
            args = make_args(policy_cache_path=str(cache_path))

            with patch("openassetwatch_collector.main.send_policy_request", return_value=policy):
                with patch("openassetwatch_collector.main.send_policy_status", return_value={"status": "accepted"}):
                    with patch("builtins.print"):
                        run_inventory_now = retrieve_and_apply_policy(args)

            self.assertTrue(cache_path.exists())

        self.assertTrue(run_inventory_now)
        self.assertEqual(args.mode, "network")
        self.assertEqual(args.heartbeat_interval_seconds, 30)
        self.assertEqual(args.inventory_interval_seconds, 60)
        self.assertFalse(args.open_detector_enabled)

    def test_retrieval_failure_uses_cached_policy_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "policy-cache.json"
            cached_policy = make_policy(policy={"mode": "network", "actions": {"run_inventory_now": False}})
            cache_path.write_text(json.dumps(cached_policy), encoding="utf-8")
            args = make_args(policy_cache_path=str(cache_path))

            with patch("openassetwatch_collector.main.send_policy_request", side_effect=URLError("down")):
                with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                    run_inventory_now = retrieve_and_apply_policy(args)

        self.assertFalse(run_inventory_now)
        self.assertEqual(args.mode, "network")
        self.assertIn("collector policy retrieval failed", stderr.getvalue())
        self.assertIn("collector using cached policy", stderr.getvalue())

    def test_scheduler_policy_retrieval_failure_does_not_crash(self) -> None:
        args = make_args(policy_cache_path=None)
        payload = {"mode": "device", "device": {"hostname": "test-host"}}

        with patch("openassetwatch_collector.main.build_payload", return_value=payload):
            with patch("openassetwatch_collector.main.send_checkin", return_value={"status": "accepted"}):
                with patch("openassetwatch_collector.main.send_inventory", return_value={"status": "accepted"}):
                    with patch("openassetwatch_collector.main.send_policy_request", side_effect=URLError("down")):
                        with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                            exit_code = run_scheduler(args, sleep_func=lambda seconds: None, max_cycles=1)

        self.assertEqual(exit_code, 0)
        self.assertIn("collector policy retrieval failed", stderr.getvalue())


def make_config_args(config: str | None = None, **overrides: object) -> argparse.Namespace:
    defaults = {
        "config": config,
        "mode": None,
        "backend_url": None,
        "backend_token": None,
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
        "policy_enabled": False,
        "policy_cache_path": None,
        "policy_hold_file_path": None,
        "policy_check_interval_seconds": None,
        "open_detector_enabled": None,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


if __name__ == "__main__":
    unittest.main()
