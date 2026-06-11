from __future__ import annotations

import argparse
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from openassetwatch_collector.main import (
    apply_config_defaults,
    build_inventory_payload,
    main,
    send_inventory,
)


def make_args(config: str | None = None, **overrides: object) -> argparse.Namespace:
    defaults = {
        "config": config,
        "mode": None,
        "backend_url": None,
        "collector_id": None,
        "collector_name": None,
        "checkin": False,
        "upload_inventory": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class InventoryUploadTests(unittest.TestCase):
    def test_build_inventory_payload_adds_collector_metadata(self) -> None:
        payload = {"mode": "hybrid", "device": {"hostname": "test-host"}}

        inventory_payload = build_inventory_payload(
            payload,
            "local-dev-collector-01",
            "Local Dev Collector",
        )

        self.assertEqual(inventory_payload["mode"], "hybrid")
        self.assertEqual(inventory_payload["device"], {"hostname": "test-host"})
        self.assertEqual(inventory_payload["collector_id"], "local-dev-collector-01")
        self.assertEqual(inventory_payload["collector_name"], "Local Dev Collector")
        self.assertNotIn("collector_id", payload)

    def test_send_inventory_posts_payload(self) -> None:
        response_body = json.dumps({"status": "accepted", "software_count": 1}).encode("utf-8")

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
            captured["method"] = request.get_method()
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["timeout"] = timeout
            return FakeResponse()

        with patch("openassetwatch_collector.main.urlopen", side_effect=fake_urlopen):
            response = send_inventory(
                "http://localhost:8000/",
                {"mode": "device", "device": {"hostname": "test-host"}},
            )

        self.assertEqual(captured["url"], "http://localhost:8000/api/v1/collectors/inventory")
        self.assertEqual(captured["method"], "POST")
        self.assertEqual(captured["body"]["mode"], "device")
        self.assertEqual(captured["timeout"], 15)
        self.assertEqual(response["status"], "accepted")

    def test_missing_backend_url_returns_clear_error(self) -> None:
        with patch("sys.argv", ["openassetwatch-collector", "--upload-inventory"]):
            with self.assertRaises(SystemExit) as raised:
                main()

        self.assertEqual(str(raised.exception), "--backend-url is required when --upload-inventory is provided")

    def test_backend_error_returns_nonzero_and_clear_error(self) -> None:
        error = HTTPError(
            url="http://localhost:8000/api/v1/collectors/inventory",
            code=500,
            msg="server error",
            hdrs=None,
            fp=None,
        )

        with patch(
            "sys.argv",
            [
                "openassetwatch-collector",
                "--mode",
                "device",
                "--upload-inventory",
                "--backend-url",
                "http://localhost:8000",
            ],
        ):
            with patch("openassetwatch_collector.main.build_payload", return_value={"mode": "device", "device": {}}):
                with patch("openassetwatch_collector.main.send_inventory", side_effect=error):
                    with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                        exit_code = main()

        self.assertEqual(exit_code, 1)
        self.assertIn("collector inventory upload failed: HTTP 500", stderr.getvalue())

    def test_config_inventory_upload_enabled_maps_to_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "collector.yaml"
            config_path.write_text(
                "\n".join(
                    [
                        "collector:",
                        "  mode: hybrid",
                        "backend:",
                        "  url: http://localhost:8000",
                        "inventory:",
                        "  upload_enabled: true",
                    ]
                ),
                encoding="utf-8",
            )

            args = apply_config_defaults(make_args(str(config_path)))

        self.assertEqual(args.mode, "hybrid")
        self.assertEqual(args.backend_url, "http://localhost:8000")
        self.assertTrue(args.upload_inventory)

    def test_cli_values_override_config_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "collector.yaml"
            config_path.write_text(
                "\n".join(
                    [
                        "collector:",
                        "  mode: hybrid",
                        "backend:",
                        "  url: http://localhost:8000",
                        "inventory:",
                        "  upload_enabled: true",
                    ]
                ),
                encoding="utf-8",
            )

            args = apply_config_defaults(
                make_args(
                    str(config_path),
                    mode="device",
                    backend_url="http://example.test:8000",
                    upload_inventory=True,
                )
            )

        self.assertEqual(args.mode, "device")
        self.assertEqual(args.backend_url, "http://example.test:8000")
        self.assertTrue(args.upload_inventory)

    def test_no_upload_behavior_still_prints_payload_only(self) -> None:
        with patch("sys.argv", ["openassetwatch-collector", "--mode", "device"]):
            with patch("openassetwatch_collector.main.build_payload", return_value={"mode": "device", "device": {}}):
                with patch("openassetwatch_collector.main.send_inventory") as send_inventory_mock:
                    with patch("sys.stdout", new_callable=io.StringIO) as stdout:
                        exit_code = main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(json.loads(stdout.getvalue()), {"mode": "device", "device": {}})
        send_inventory_mock.assert_not_called()

    def test_checkin_runs_before_inventory_upload(self) -> None:
        calls = []

        def fake_checkin(backend_url: str, checkin_payload: dict[str, object]) -> dict[str, object]:
            calls.append("checkin")
            return {"status": "accepted"}

        def fake_inventory(backend_url: str, inventory_payload: dict[str, object]) -> dict[str, object]:
            calls.append("inventory")
            return {"status": "accepted"}

        with patch(
            "sys.argv",
            [
                "openassetwatch-collector",
                "--mode",
                "device",
                "--checkin",
                "--upload-inventory",
                "--backend-url",
                "http://localhost:8000",
                "--collector-id",
                "local-dev-collector-01",
            ],
        ):
            with patch("openassetwatch_collector.main.build_payload", return_value={"mode": "device", "device": {}}):
                with patch("openassetwatch_collector.main.send_checkin", side_effect=fake_checkin):
                    with patch("openassetwatch_collector.main.send_inventory", side_effect=fake_inventory):
                        with patch("sys.stderr", new_callable=io.StringIO):
                            with patch("sys.stdout", new_callable=io.StringIO):
                                exit_code = main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(calls, ["checkin", "inventory"])


if __name__ == "__main__":
    unittest.main()
