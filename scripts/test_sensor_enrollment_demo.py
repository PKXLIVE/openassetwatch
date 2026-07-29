from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO_SCRIPT = REPO_ROOT / "scripts" / "demo_sensor_enrollment.py"


def load_demo_module():
    spec = importlib.util.spec_from_file_location("demo_sensor_enrollment", DEMO_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load sensor enrollment demo")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeClient:
    enrollment_token = "oaw_enroll_v1." + "a" * 32 + "." + "B" * 43
    first_credential = "oaw_sensor_v1." + "c" * 32 + "." + "D" * 43
    replacement_credential = "oaw_sensor_v1." + "e" * 32 + "." + "F" * 43

    def __init__(self, _base_url: str, _admin_token: str) -> None:
        self.exchange_count = 0
        self.batch_count = 0
        self.rotated = False
        self.revoked = False
        self.asset_id = ""

    def request(
        self,
        method: str,
        path: str,
        payload=None,
        *,
        admin: bool = False,
        sensor_credential: str | None = None,
        expected=None,
    ):
        del method, admin, expected
        if path == "/api/v1/sites":
            return 200, {"status": "ok"}
        if path == "/api/v1/admin/sensor-enrollments" and payload is not None:
            return 200, {"enrollment_token": self.enrollment_token}
        if path == "/api/v1/sensors/enroll":
            self.exchange_count += 1
            if self.exchange_count == 1:
                return 200, {
                    "sensor_credential": self.first_credential,
                    "status": "enrolled",
                }
            return 401, {"detail": "sensor enrollment failed"}
        if path == "/api/v1/observations/batches":
            if payload["site_id"] == "other-site" or payload["sensor_id"] == "other-sensor":
                return 401, {"detail": "valid sensor credential required"}
            if self.revoked:
                return 401, {"detail": "valid sensor credential required"}
            if self.rotated and sensor_credential == self.first_credential:
                return 401, {"detail": "valid sensor credential required"}
            self.asset_id = payload["assets"][0]["asset_id"]
            self.batch_count += 1
            return 200, {"status": "accepted" if self.batch_count == 1 else "duplicate"}
        if path.endswith("/credentials/rotate"):
            self.rotated = True
            return 200, {"sensor_credential": self.replacement_credential}
        if path.endswith("/revoke"):
            self.revoked = True
            return 200, {"status": "revoked"}
        if path == "/api/v1/control-tower/assets":
            return 200, {"assets": [{"asset_id": self.asset_id}]}
        if path == "/api/v1/ai/advisor/query":
            return 200, {"evidence": [{"asset_id": self.asset_id}]}
        if path.startswith("/api/v1/admin/sensor-identity/audit"):
            return 200, {"events": [{"event_type": "sensor_revoked"}]}
        if path in {"/api/v1/admin/sensor-enrollments", "/api/v1/admin/sensors"}:
            return 200, {"items": []}
        raise AssertionError(f"unexpected demo request path: {path}")


class SensorEnrollmentDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.demo = load_demo_module()

    def test_remote_cleartext_and_url_credentials_are_rejected(self) -> None:
        for value in ("http://192.0.2.10:8000", "https://user:password@example.test"):
            with self.subTest(value=value), self.assertRaises(self.demo.DemoFailure):
                self.demo.safe_base_url(value)
        self.assertEqual(self.demo.safe_base_url("http://127.0.0.1:8000"), "http://127.0.0.1:8000")

    def test_synthetic_flow_returns_only_non_secret_results(self) -> None:
        args = SimpleNamespace(
            admin_token_env="OPENASSETWATCH_ADMIN_TOKEN",
            server_url="http://127.0.0.1:8000",
            site_id="site-demo",
            sensor_id="sensor-demo",
        )
        with (
            patch.dict(os.environ, {"OPENASSETWATCH_ADMIN_TOKEN": "admin-placeholder"}, clear=False),
            patch.object(self.demo, "Client", FakeClient),
        ):
            result = self.demo.run(args)

        serialized = str(result)
        for secret in (
            FakeClient.enrollment_token,
            FakeClient.first_credential,
            FakeClient.replacement_credential,
            "admin-placeholder",
        ):
            self.assertNotIn(secret, serialized)
        self.assertTrue(result["enrollment_replay_rejected"])
        self.assertTrue(result["site_mismatch_rejected"])
        self.assertTrue(result["sensor_mismatch_rejected"])
        self.assertTrue(result["old_credential_rejected"])
        self.assertTrue(result["revoked_credential_rejected"])
        self.assertTrue(result["ai_evidence_visible"])


if __name__ == "__main__":
    unittest.main()
