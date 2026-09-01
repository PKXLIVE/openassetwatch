from __future__ import annotations

import io
import socket
import unittest
from unittest.mock import patch
from urllib.request import Request

from openassetwatch_collector.main import (
    COLLECTOR_TOKEN_HEADER,
    COLLECTOR_TOKEN_INVALID_ERROR,
    COLLECTOR_TOKEN_REDIRECT_ERROR,
    COLLECTOR_TOKEN_TRANSPORT_ERROR,
    CollectorTokenError,
    CollectorTokenRedirectError,
    CollectorTokenTransportError,
    _CollectorTokenRedirectHandler,
    _VerifiedLoopbackHTTPConnection,
    backend_headers,
    main,
    perform_checkin,
    send_checkin,
    send_inventory,
    send_policy_request,
    send_policy_status,
)


TEST_TOKEN = "collector-token-value-that-must-not-appear"


def header_value(headers: dict[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.casefold() == name.casefold():
            return value
    return None


class FakeResponse:
    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        return None

    def read(self) -> bytes:
        return b'{"status":"accepted"}'


class FakeOpener:
    def __init__(self) -> None:
        self.requests: list[Request] = []

    def open(self, request: Request, timeout: int) -> FakeResponse:
        self.requests.append(request)
        return FakeResponse()


class FakeSocket:
    def __init__(self) -> None:
        self.bound_address = None
        self.connected_address = None
        self.timeout = None
        self.closed = False

    def settimeout(self, timeout) -> None:
        self.timeout = timeout

    def bind(self, address) -> None:
        self.bound_address = address

    def connect(self, address) -> None:
        self.connected_address = address

    def close(self) -> None:
        self.closed = True


class CollectorTokenTransportTests(unittest.TestCase):
    def test_https_remote_destination_is_allowed(self) -> None:
        opener = FakeOpener()
        with patch("openassetwatch_collector.main.build_opener", return_value=opener):
            send_inventory(
                "https://hub.example.test",
                {"mode": "device", "device": {"hostname": "test-host"}},
                TEST_TOKEN,
            )

        self.assertEqual(len(opener.requests), 1)
        self.assertEqual(opener.requests[0].full_url, "https://hub.example.test/api/v1/collectors/inventory")
        self.assertEqual(
            header_value(dict(opener.requests[0].header_items()), COLLECTOR_TOKEN_HEADER),
            TEST_TOKEN,
        )

    def test_http_ipv4_loopback_destination_is_allowed(self) -> None:
        opener = FakeOpener()
        with patch("openassetwatch_collector.main.build_opener", return_value=opener):
            send_checkin(
                "http://127.0.0.2:8000",
                {"collector_id": "collector-1"},
                TEST_TOKEN,
            )

        self.assertEqual(len(opener.requests), 1)
        self.assertEqual(opener.requests[0].full_url, "http://127.0.0.2:8000/api/v1/collectors/checkin")

    def test_http_ipv6_loopback_destination_is_allowed(self) -> None:
        opener = FakeOpener()
        with patch("openassetwatch_collector.main.build_opener", return_value=opener):
            send_policy_request("http://[::1]:8000", TEST_TOKEN)

        self.assertEqual(len(opener.requests), 1)
        self.assertEqual(opener.requests[0].full_url, "http://[::1]:8000/api/v1/collectors/policy")

    def test_http_localhost_requires_only_loopback_resolutions(self) -> None:
        opener = FakeOpener()
        loopback_results = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 8000, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8000)),
        ]
        with patch("openassetwatch_collector.main.socket.getaddrinfo", return_value=loopback_results):
            with patch("openassetwatch_collector.main.build_opener", return_value=opener):
                send_inventory("http://localhost:8000", {"mode": "device"}, TEST_TOKEN)

        self.assertEqual(len(opener.requests), 1)

        ambiguous_results = loopback_results + [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 8000)),
        ]
        with patch("openassetwatch_collector.main.socket.getaddrinfo", return_value=ambiguous_results):
            with patch("openassetwatch_collector.main.build_opener") as build_opener_mock:
                with self.assertRaisesRegex(
                    CollectorTokenTransportError,
                    "credentials cannot be sent over non-loopback plaintext HTTP",
                ):
                    send_inventory("http://localhost:8000", {"mode": "device"}, TEST_TOKEN)
        build_opener_mock.assert_not_called()

    def test_all_token_bearing_operations_block_non_loopback_http_before_open(self) -> None:
        operations = {
            "check-in": lambda: send_checkin(
                "http://192.0.2.10:8000", {"collector_id": "collector-1"}, TEST_TOKEN
            ),
            "inventory": lambda: send_inventory(
                "http://192.0.2.10:8000", {"mode": "device"}, TEST_TOKEN
            ),
            "policy": lambda: send_policy_request("http://192.0.2.10:8000", TEST_TOKEN),
            "policy status": lambda: send_policy_status(
                "http://192.0.2.10:8000", {"policy_status": "applied"}, TEST_TOKEN
            ),
        }
        for name, operation in operations.items():
            with self.subTest(name=name):
                with patch("openassetwatch_collector.main.build_opener") as build_opener_mock:
                    with patch("openassetwatch_collector.main.urlopen") as urlopen_mock:
                        with self.assertRaises(CollectorTokenTransportError) as raised:
                            operation()
                build_opener_mock.assert_not_called()
                urlopen_mock.assert_not_called()
                self.assertEqual(str(raised.exception), COLLECTOR_TOKEN_TRANSPORT_ERROR)
                self.assertNotIn(TEST_TOKEN, str(raised.exception))

    def test_http_non_loopback_hostname_and_malformed_destination_fail_closed(self) -> None:
        for backend_url in (
            "http://hub.example.test:8000",
            "not-a-url",
            "http://[::1",
            "ftp://127.0.0.1/resource",
        ):
            with self.subTest(backend_url=backend_url):
                with patch("openassetwatch_collector.main.build_opener") as build_opener_mock:
                    with self.assertRaises(CollectorTokenTransportError):
                        send_inventory(backend_url, {"mode": "device"}, TEST_TOKEN)
                build_opener_mock.assert_not_called()

    def test_redirect_cannot_downgrade_or_bypass_transport_policy(self) -> None:
        handler = _CollectorTokenRedirectHandler()
        request = Request(
            "https://hub.example.test/api/v1/collectors/inventory",
            headers=backend_headers(TEST_TOKEN),
            method="GET",
        )
        for redirect_url in (
            "https://hub.example.test/redirected",
            "https://other.example.test/api/v1/collectors/inventory",
            "http://192.0.2.10/api/v1/collectors/inventory",
            "http://127.0.0.1:8000/api/v1/collectors/inventory",
        ):
            with self.subTest(redirect_url=redirect_url):
                with self.assertRaises(CollectorTokenRedirectError) as raised:
                    handler.redirect_request(request, None, 302, "Found", {}, redirect_url)
                self.assertEqual(str(raised.exception), COLLECTOR_TOKEN_REDIRECT_ERROR)
                self.assertNotIn(TEST_TOKEN, str(raised.exception))

    def test_loopback_is_reverified_and_bound_at_connection_time(self) -> None:
        loopback = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8000)),
        ]
        fake_socket = FakeSocket()
        connection = _VerifiedLoopbackHTTPConnection("localhost", 8000, timeout=3)
        with patch("openassetwatch_collector.main.socket.getaddrinfo", return_value=loopback):
            with patch("openassetwatch_collector.main.socket.socket", return_value=fake_socket):
                connection.connect()
        self.assertIs(connection.sock, fake_socket)
        self.assertEqual(fake_socket.connected_address, ("127.0.0.1", 8000))

        ambiguous = loopback + [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", 8000)),
        ]
        with patch("openassetwatch_collector.main.socket.getaddrinfo", return_value=ambiguous):
            with patch("openassetwatch_collector.main.socket.socket") as socket_mock:
                with self.assertRaises(CollectorTokenTransportError) as raised:
                    _VerifiedLoopbackHTTPConnection("localhost", 8000, timeout=3).connect()
        socket_mock.assert_not_called()
        self.assertEqual(str(raised.exception), COLLECTOR_TOKEN_TRANSPORT_ERROR)

    def test_invalid_tokens_fail_before_request_and_are_not_echoed(self) -> None:
        for token in (
            " leading-token",
            "trailing-token ",
            "line\nbreak-token",
            "non-ascii-\u00e9-token",
            "x" * 4097,
        ):
            with self.subTest(token_length=len(token)):
                with patch("openassetwatch_collector.main.build_opener") as build_opener_mock:
                    with patch("openassetwatch_collector.main.urlopen") as urlopen_mock:
                        with self.assertRaises(CollectorTokenError) as raised:
                            send_checkin(
                                "https://hub.example.test",
                                {"collector_id": "collector-1"},
                                token,
                            )
                build_opener_mock.assert_not_called()
                urlopen_mock.assert_not_called()
                self.assertEqual(str(raised.exception), COLLECTOR_TOKEN_INVALID_ERROR)
                self.assertNotIn(token, str(raised.exception))

    def test_hub_response_cannot_echo_token_into_collector_output(self) -> None:
        token = 'collector-token-with-"quote\\slash'
        response = {"status": "accepted", "message": f"reflected {token}"}
        with patch("openassetwatch_collector.main.send_checkin", return_value=response):
            with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                success = perform_checkin(
                    backend_url="https://hub.example.test",
                    backend_token=token,
                    payload={"mode": "device"},
                    collector_id="collector-1",
                    collector_name=None,
                )
        self.assertTrue(success)
        self.assertNotIn(token, stderr.getvalue())
        self.assertNotIn(token.replace("\\", "\\\\").replace('"', '\\"'), stderr.getvalue())
        self.assertIn("[redacted]", stderr.getvalue())

    def test_cli_error_is_safe_and_never_opens_blocked_request(self) -> None:
        with patch(
            "sys.argv",
            [
                "openassetwatch-collector",
                "--mode",
                "device",
                "--upload-inventory",
                "--backend-url",
                "http://hub.example.test:8000",
                "--backend-token",
                TEST_TOKEN,
            ],
        ):
            with patch("openassetwatch_collector.main.build_payload", return_value={"mode": "device"}):
                with patch("openassetwatch_collector.main.build_opener") as build_opener_mock:
                    with patch("sys.stderr", new_callable=io.StringIO) as stderr:
                        with patch("sys.stdout", new_callable=io.StringIO):
                            exit_code = main()

        self.assertEqual(exit_code, 1)
        build_opener_mock.assert_not_called()
        self.assertIn(COLLECTOR_TOKEN_TRANSPORT_ERROR, stderr.getvalue())
        self.assertNotIn(TEST_TOKEN, stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
