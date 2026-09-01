from __future__ import annotations

import importlib.util
import io
import os
import socket
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
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


class FakeSocket:
    def __init__(self) -> None:
        self.connected_address = None
        self.timeout = None

    def settimeout(self, timeout) -> None:
        self.timeout = timeout

    def bind(self, _address) -> None:
        return None

    def connect(self, address) -> None:
        self.connected_address = address

    def close(self) -> None:
        return None


class FakeClient:
    enrollment_token = "oaw_enroll_v1." + "a" * 32 + "." + "B" * 43
    first_credential = "oaw_sensor_v1." + "c" * 32 + "." + "D" * 43
    replacement_credential = "oaw_sensor_v1." + "e" * 32 + "." + "F" * 43
    authorization_value = "Authorization: Bearer deterministic-demo-secret"

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


class FailingClient(FakeClient):
    fail_path = ""

    def request(self, method: str, path: str, payload=None, **kwargs):
        if self.fail_path and self.fail_path in path:
            raise OSError(
                " ".join(
                    (
                        self.enrollment_token,
                        self.first_credential,
                        self.replacement_credential,
                        self.authorization_value,
                    )
                )
            )
        return super().request(method, path, payload, **kwargs)


class EnrollmentFailureClient(FailingClient):
    fail_path = "/api/v1/sensors/enroll"


class RotationFailureClient(FailingClient):
    fail_path = "/credentials/rotate"


class RevocationFailureClient(FailingClient):
    fail_path = "/revoke"


class UnsafeAdminViewClient(FakeClient):
    def request(self, method: str, path: str, payload=None, **kwargs):
        if path.startswith("/api/v1/admin/sensor-identity/audit"):
            return 200, {"events": [{"note": self.replacement_credential}]}
        return super().request(method, path, payload, **kwargs)


class SensorEnrollmentDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.demo = load_demo_module()

    def test_remote_cleartext_and_url_credentials_are_rejected(self) -> None:
        for value in ("http://192.0.2.10:8000", "https://user:password@example.test"):
            with self.subTest(value=value), self.assertRaises(self.demo.DemoFailure):
                self.demo.safe_base_url(value)
        self.assertEqual(self.demo.safe_base_url("http://127.0.0.1:8000"), "http://127.0.0.1:8000")

    def test_localhost_must_resolve_only_to_loopback_addresses(self) -> None:
        loopback = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 8000, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8000)),
        ]
        with patch.object(self.demo.socket, "getaddrinfo", return_value=loopback):
            self.assertEqual(
                self.demo.safe_base_url("http://localhost:8000"),
                "http://localhost:8000",
            )

        ambiguous = loopback + [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 8000)),
        ]
        with patch.object(self.demo.socket, "getaddrinfo", return_value=ambiguous):
            with self.assertRaises(self.demo.DemoFailure) as raised:
                self.demo.safe_base_url("http://localhost:8000")
        self.assertEqual(raised.exception.code, "cleartext-remote-url")

    def test_credentialed_demo_client_refuses_redirects(self) -> None:
        handler = self.demo._NoCredentialRedirectHandler()
        request = self.demo.urllib.request.Request(
            "https://hub.example.test/api/v1/observations/batches",
            headers={self.demo.SENSOR_HEADER: FakeClient.first_credential},
        )
        self.assertIsNone(
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {},
                "http://192.0.2.10/api/v1/observations/batches",
            )
        )

    def test_loopback_is_reverified_and_bound_at_connection_time(self) -> None:
        loopback = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8000)),
        ]
        fake_socket = FakeSocket()
        connection = self.demo._VerifiedLoopbackHTTPConnection("localhost", 8000, timeout=3)
        with patch.object(self.demo.socket, "getaddrinfo", return_value=loopback):
            with patch.object(self.demo.socket, "socket", return_value=fake_socket):
                connection.connect()
        self.assertIs(connection.sock, fake_socket)
        self.assertEqual(fake_socket.connected_address, ("127.0.0.1", 8000))

        ambiguous = loopback + [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 8000)),
        ]
        with patch.object(self.demo.socket, "getaddrinfo", return_value=ambiguous):
            with patch.object(self.demo.socket, "socket") as socket_mock:
                with self.assertRaises(self.demo.DemoFailure) as raised:
                    self.demo._VerifiedLoopbackHTTPConnection(
                        "localhost", 8000, timeout=3
                    ).connect()
        socket_mock.assert_not_called()
        self.assertEqual(raised.exception.code, "cleartext-remote-url")

    def test_invalid_header_credentials_fail_before_request_without_echo(self) -> None:
        invalid_admin = "admin-token\nsecret"
        with self.assertRaises(self.demo.DemoFailure) as raised:
            self.demo.Client("https://hub.example.test", invalid_admin)
        self.assertEqual(raised.exception.code, "invalid-credential")
        self.assertNotIn(invalid_admin, str(raised.exception))

        client = self.demo.Client("https://hub.example.test", "valid-admin-token")
        invalid_sensor = "sensor-token\nsecret"
        with patch.object(client.opener, "open") as open_mock:
            with self.assertRaises(self.demo.DemoFailure) as raised:
                client.request(
                    "POST",
                    "/api/v1/observations/batches",
                    payload={},
                    sensor_credential=invalid_sensor,
                )
        open_mock.assert_not_called()
        self.assertEqual(raised.exception.code, "invalid-credential")
        self.assertNotIn(invalid_sensor, str(raised.exception))

    def test_synthetic_flow_returns_only_non_secret_results(self) -> None:
        args = self.demo_args()
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

    def demo_args(self):
        return SimpleNamespace(
            admin_token_env="OPENASSETWATCH_ADMIN_TOKEN",
            server_url="http://127.0.0.1:8000",
            site_id="site-demo",
            sensor_id="sensor-demo",
        )

    def assert_secret_free_output(self, stdout: str, stderr: str) -> None:
        output = stdout + stderr
        for secret in (
            FakeClient.enrollment_token,
            FakeClient.first_credential,
            FakeClient.replacement_credential,
            FakeClient.authorization_value,
            "admin-placeholder",
            "oaw_enroll_v1",
            "oaw_sensor_v1",
        ):
            self.assertNotIn(secret, output)

    def run_main(self, client_type) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.dict(os.environ, {"OPENASSETWATCH_ADMIN_TOKEN": "admin-placeholder"}, clear=False),
            patch.object(self.demo, "Client", client_type),
            patch.object(self.demo, "parse_args", return_value=self.demo_args()),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = self.demo.main()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_main_success_prints_only_allowlisted_summary(self) -> None:
        code, stdout, stderr = self.run_main(FakeClient)
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        decoded = self.demo.json.loads(stdout)
        self.assertEqual(decoded["first_batch"], "accepted")
        self.assertEqual(decoded["duplicate_batch"], "duplicate")
        self.assert_secret_free_output(stdout, stderr)

    def test_main_failure_paths_never_print_secrets(self) -> None:
        for client_type in (
            EnrollmentFailureClient,
            RotationFailureClient,
            RevocationFailureClient,
            UnsafeAdminViewClient,
        ):
            with self.subTest(client=client_type.__name__):
                code, stdout, stderr = self.run_main(client_type)
                self.assertEqual(code, 1)
                self.assertEqual(stdout, "")
                self.assertIn("sensor enrollment demo failed:", stderr)
                self.assert_secret_free_output(stdout, stderr)

    def test_main_ignores_secret_fields_outside_public_result_allowlist(self) -> None:
        unsafe_result = {
            "site_id": "site-demo",
            "sensor_id": "sensor-demo",
            "enrollment_replay_rejected": True,
            "first_batch": "accepted",
            "duplicate_batch": "duplicate",
            "site_mismatch_rejected": True,
            "sensor_mismatch_rejected": True,
            "old_credential_rejected": True,
            "new_credential_accepted": True,
            "revoked_credential_rejected": True,
            "historical_evidence_retained": True,
            "ai_evidence_visible": True,
            "admin_views_secret_free": True,
            "complete_response": {
                "enrollment_token": FakeClient.enrollment_token,
                "sensor_credential": FakeClient.first_credential,
            },
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.object(self.demo, "run", return_value=unsafe_result),
            patch.object(self.demo, "parse_args", return_value=self.demo_args()),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = self.demo.main()
        self.assertEqual(code, 0)
        self.assert_secret_free_output(stdout.getvalue(), stderr.getvalue())

    def test_main_never_prints_arbitrary_demo_failure_text(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        unsafe_exception = self.demo.DemoFailure(
            f"{FakeClient.enrollment_token} {FakeClient.authorization_value}"
        )
        with (
            patch.object(self.demo, "run", side_effect=unsafe_exception),
            patch.object(self.demo, "parse_args", return_value=self.demo_args()),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = self.demo.main()
        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("demonstration operation failed", stderr.getvalue())
        self.assert_secret_free_output(stdout.getvalue(), stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
