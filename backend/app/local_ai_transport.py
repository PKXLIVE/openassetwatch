"""Pinned, proxy-free transport for explicitly trusted local AI providers."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from typing import Callable, Mapping
from urllib.parse import urlsplit


MAX_DNS_ANSWERS = 32
MAX_RESPONSE_HEADERS = 100
MAX_RESPONSE_HEADER_BYTES = 32_768


class LocalAITransportSecurityError(ValueError):
    """A bounded, non-secret local-provider transport rejection."""

    def __init__(self, code: str, summary: str) -> None:
        super().__init__(summary)
        self.code = code[:80]
        self.summary = summary[:240]


@dataclass(frozen=True)
class LocalAITransportResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    peer_ip: str


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, *, port: int, pinned_ip: str, timeout: float) -> None:
        super().__init__(host, port=port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        host: str,
        *,
        port: int,
        pinned_ip: str,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        raw = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def _normalized_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError as exc:
        raise LocalAITransportSecurityError(
            "dns-answer-invalid",
            "local provider hostname returned an invalid address",
        ) from exc


def _is_allowed_local_address(value: str) -> bool:
    address = _normalized_ip(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.is_loopback:
        return True
    return (
        address.is_private
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_reserved
    )


def resolve_local_provider_addresses(
    host: str,
    port: int,
    *,
    resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
) -> tuple[str, ...]:
    """Resolve one trusted name into a bounded, entirely local answer set."""

    try:
        literal = _normalized_ip(host)
    except LocalAITransportSecurityError:
        literal = None
    if literal is not None:
        values = [str(literal)]
    else:
        try:
            answers = resolver(host, port, type=socket.SOCK_STREAM)
        except (OSError, socket.gaierror) as exc:
            raise LocalAITransportSecurityError(
                "dns-resolution-failed",
                "local provider hostname could not be resolved",
            ) from exc
        values: list[str] = []
        for answer in answers[: MAX_DNS_ANSWERS + 1]:
            if len(answer) < 5 or not answer[4]:
                continue
            value = str(answer[4][0]).split("%", 1)[0]
            if value not in values:
                values.append(value)
    if not values or len(values) > MAX_DNS_ANSWERS:
        raise LocalAITransportSecurityError(
            "dns-answer-invalid",
            "local provider hostname returned no bounded address set",
        )
    if any(not _is_allowed_local_address(value) for value in values):
        raise LocalAITransportSecurityError(
            "dns-address-prohibited",
            "local provider hostname resolved to a prohibited address",
        )
    return tuple(
        sorted(
            (str(_normalized_ip(value)) for value in values),
            key=lambda value: (_normalized_ip(value).version, value),
        )
    )


ConnectionFactory = Callable[..., http.client.HTTPConnection]


def _default_connection_factory(
    *,
    scheme: str,
    host: str,
    port: int,
    pinned_ip: str,
    timeout: float,
    ssl_context: ssl.SSLContext,
) -> http.client.HTTPConnection:
    if scheme == "https":
        return _PinnedHTTPSConnection(
            host,
            port=port,
            pinned_ip=pinned_ip,
            timeout=timeout,
            context=ssl_context,
        )
    return _PinnedHTTPConnection(
        host,
        port=port,
        pinned_ip=pinned_ip,
        timeout=timeout,
    )


def _host_header(host: str, port: int, scheme: str) -> str:
    rendered_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    return rendered_host if port == default_port else f"{rendered_host}:{port}"


class PinnedLocalAITransport:
    """Resolve, validate, pin, and peer-check one local HTTP(S) request."""

    def __init__(
        self,
        *,
        resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
        connection_factory: ConnectionFactory = _default_connection_factory,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.resolver = resolver
        self.connection_factory = connection_factory
        self.ssl_context = ssl_context or ssl.create_default_context()

    def request(
        self,
        *,
        url: str,
        method: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout_seconds: float,
        maximum_response_bytes: int,
    ) -> LocalAITransportResponse:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise LocalAITransportSecurityError(
                "url-invalid",
                "local provider request URL is invalid",
            )
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise LocalAITransportSecurityError(
                "url-components-rejected",
                "local provider request URL contains unsupported components",
            )
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise LocalAITransportSecurityError(
                "url-port-invalid",
                "local provider request URL contains an invalid port",
            ) from exc
        addresses = resolve_local_provider_addresses(
            parsed.hostname,
            port,
            resolver=self.resolver,
        )
        pinned_ip = addresses[0]
        connection = self.connection_factory(
            scheme=parsed.scheme,
            host=parsed.hostname,
            port=port,
            pinned_ip=pinned_ip,
            timeout=timeout_seconds,
            ssl_context=self.ssl_context,
        )
        try:
            connection.connect()
            if connection.sock is None:
                raise LocalAITransportSecurityError(
                    "connection-failed",
                    "local provider connection did not establish safely",
                )
            peer_ip = str(connection.sock.getpeername()[0]).split("%", 1)[0]
            if _normalized_ip(peer_ip) != _normalized_ip(pinned_ip):
                raise LocalAITransportSecurityError(
                    "dns-peer-mismatch",
                    "local provider peer did not match the validated DNS address",
                )
            connection.sock.settimeout(timeout_seconds)
            target = parsed.path or "/"
            if parsed.query:
                target = f"{target}?{parsed.query}"
            connection.putrequest(
                method,
                target,
                skip_host=True,
                skip_accept_encoding=True,
            )
            connection.putheader("Host", _host_header(parsed.hostname, port, parsed.scheme))
            blocked_headers = {"host", "content-length", "connection", "accept-encoding"}
            for name, value in headers.items():
                if name.casefold() in blocked_headers:
                    continue
                if "\r" in name or "\n" in name or "\r" in value or "\n" in value:
                    raise LocalAITransportSecurityError(
                        "header-invalid",
                        "local provider request contained an invalid header",
                    )
                connection.putheader(name, value)
            connection.putheader("Accept-Encoding", "identity")
            connection.putheader("Connection", "close")
            if body is not None:
                connection.putheader("Content-Length", str(len(body)))
            connection.endheaders(body)
            response = connection.getresponse()
            response_headers = tuple((name, value) for name, value in response.getheaders())
            if len(response_headers) > MAX_RESPONSE_HEADERS:
                raise LocalAITransportSecurityError(
                    "response-headers-too-large",
                    "local provider returned too many response headers",
                )
            header_bytes = sum(
                len(name.encode("utf-8", "replace"))
                + len(value.encode("utf-8", "replace"))
                + 4
                for name, value in response_headers
            )
            if header_bytes > MAX_RESPONSE_HEADER_BYTES:
                raise LocalAITransportSecurityError(
                    "response-headers-too-large",
                    "local provider response headers exceeded the safety limit",
                )
            if 300 <= response.status <= 399:
                raise LocalAITransportSecurityError(
                    "redirect-rejected",
                    "local provider redirects are disabled",
                )
            response_body = response.read(maximum_response_bytes + 1)
            if len(response_body) > maximum_response_bytes:
                raise LocalAITransportSecurityError(
                    "response-too-large",
                    "local provider response exceeded the safety limit",
                )
            return LocalAITransportResponse(
                status=response.status,
                headers=response_headers,
                body=response_body,
                peer_ip=peer_ip,
            )
        finally:
            connection.close()


def local_ai_request(
    *,
    url: str,
    method: str,
    headers: Mapping[str, str],
    body: bytes | None,
    timeout_seconds: float,
    maximum_response_bytes: int,
) -> LocalAITransportResponse:
    return PinnedLocalAITransport().request(
        url=url,
        method=method,
        headers=headers,
        body=body,
        timeout_seconds=timeout_seconds,
        maximum_response_bytes=maximum_response_bytes,
    )
