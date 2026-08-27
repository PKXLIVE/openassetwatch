from __future__ import annotations

import socket
import unittest

from app.local_ai_transport import (
    LocalAITransportSecurityError,
    PinnedLocalAITransport,
    resolve_local_provider_addresses,
)


def answer(address: str, port: int = 8080) -> tuple:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sockaddr = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
    return (family, socket.SOCK_STREAM, 6, "", sockaddr)


class FakeSocket:
    def __init__(self, peer_ip: str) -> None:
        self.peer_ip = peer_ip
        self.timeout: float | None = None

    def getpeername(self) -> tuple[str, int]:
        return self.peer_ip, 8080

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout


class FakeHTTPResponse:
    def __init__(
        self,
        *,
        status: int = 200,
        headers: tuple[tuple[str, str], ...] = (),
        body: bytes = b'{"status":"ok"}',
    ) -> None:
        self.status = status
        self.headers = headers
        self.body = body

    def getheaders(self) -> tuple[tuple[str, str], ...]:
        return self.headers

    def read(self, amount: int) -> bytes:
        return self.body[:amount]


class FakeConnection:
    def __init__(self, peer_ip: str, response: FakeHTTPResponse) -> None:
        self.sock = FakeSocket(peer_ip)
        self.response = response
        self.closed = False
        self.request: tuple[str, str] | None = None
        self.headers: list[tuple[str, str]] = []
        self.body: bytes | None = None

    def connect(self) -> None:
        return None

    def putrequest(self, method: str, target: str, **kwargs) -> None:  # noqa: ANN003
        self.request = method, target

    def putheader(self, name: str, value: str) -> None:
        self.headers.append((name, value))

    def endheaders(self, body: bytes | None = None) -> None:
        self.body = body

    def getresponse(self) -> FakeHTTPResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


class LocalAITransportTests(unittest.TestCase):
    def test_private_and_loopback_answers_are_allowed_for_an_exact_local_name(self) -> None:
        addresses = resolve_local_provider_addresses(
            "rocmfpx",
            8080,
            resolver=lambda *args, **kwargs: [
                answer("172.20.0.5"),
                answer("127.0.0.1"),
                answer("::1"),
            ],
        )

        self.assertEqual(addresses, ("127.0.0.1", "172.20.0.5", "::1"))

    def test_link_local_metadata_answer_is_rejected(self) -> None:
        for address_value in (
            "169.254.169.254",
            "::ffff:169.254.169.254",
            "fe80::a9fe:a9fe",
        ):
            with self.subTest(address=address_value):
                with self.assertRaisesRegex(LocalAITransportSecurityError, "prohibited"):
                    resolve_local_provider_addresses(
                        "rocmfpx",
                        8080,
                        resolver=lambda *args, **kwargs: [answer(address_value)],
                    )

    def test_mixed_safe_and_link_local_answers_fail_closed(self) -> None:
        with self.assertRaises(LocalAITransportSecurityError):
            resolve_local_provider_addresses(
                "rocmfpx",
                8080,
                resolver=lambda *args, **kwargs: [
                    answer("172.20.0.5"),
                    answer("169.254.169.254"),
                ],
            )

    def test_public_answer_is_not_reclassified_as_local(self) -> None:
        with self.assertRaises(LocalAITransportSecurityError):
            resolve_local_provider_addresses(
                "rocmfpx",
                8080,
                resolver=lambda *args, **kwargs: [answer("8.8.8.8")],
            )

    def test_request_pins_peer_and_preserves_original_host_header(self) -> None:
        response = FakeHTTPResponse(body=b'{"data":[]}')
        connection = FakeConnection("172.20.0.5", response)
        factory_calls: list[dict] = []

        def factory(**kwargs) -> FakeConnection:  # noqa: ANN003
            factory_calls.append(kwargs)
            return connection

        transport = PinnedLocalAITransport(
            resolver=lambda *args, **kwargs: [answer("172.20.0.5")],
            connection_factory=factory,
        )

        result = transport.request(
            url="http://rocmfpx:8080/v1/models",
            method="GET",
            headers={"Accept": "application/json"},
            body=None,
            timeout_seconds=2,
            maximum_response_bytes=1024,
        )

        self.assertEqual(result.peer_ip, "172.20.0.5")
        self.assertEqual(factory_calls[0]["pinned_ip"], "172.20.0.5")
        self.assertEqual(connection.request, ("GET", "/v1/models"))
        self.assertIn(("Host", "rocmfpx:8080"), connection.headers)
        self.assertTrue(connection.closed)

    def test_peer_mismatch_is_rejected(self) -> None:
        connection = FakeConnection("172.20.0.6", FakeHTTPResponse())
        transport = PinnedLocalAITransport(
            resolver=lambda *args, **kwargs: [answer("172.20.0.5")],
            connection_factory=lambda **kwargs: connection,
        )

        with self.assertRaisesRegex(LocalAITransportSecurityError, "peer"):
            transport.request(
                url="http://rocmfpx:8080/v1/models",
                method="GET",
                headers={},
                body=None,
                timeout_seconds=2,
                maximum_response_bytes=1024,
            )
        self.assertTrue(connection.closed)

    def test_redirect_is_rejected_without_following_location(self) -> None:
        connection = FakeConnection(
            "172.20.0.5",
            FakeHTTPResponse(
                status=302,
                headers=(("Location", "http://169.254.169.254/latest"),),
            ),
        )
        transport = PinnedLocalAITransport(
            resolver=lambda *args, **kwargs: [answer("172.20.0.5")],
            connection_factory=lambda **kwargs: connection,
        )

        with self.assertRaisesRegex(LocalAITransportSecurityError, "redirect"):
            transport.request(
                url="http://rocmfpx:8080/v1/models",
                method="GET",
                headers={},
                body=None,
                timeout_seconds=2,
                maximum_response_bytes=1024,
            )

    def test_oversized_response_is_rejected(self) -> None:
        connection = FakeConnection(
            "172.20.0.5",
            FakeHTTPResponse(body=b"x" * 10),
        )
        transport = PinnedLocalAITransport(
            resolver=lambda *args, **kwargs: [answer("172.20.0.5")],
            connection_factory=lambda **kwargs: connection,
        )

        with self.assertRaisesRegex(LocalAITransportSecurityError, "safety limit"):
            transport.request(
                url="http://rocmfpx:8080/v1/models",
                method="GET",
                headers={},
                body=None,
                timeout_seconds=2,
                maximum_response_bytes=4,
            )


if __name__ == "__main__":
    unittest.main()
