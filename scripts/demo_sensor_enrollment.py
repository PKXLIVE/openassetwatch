#!/usr/bin/env python3
"""Run the synthetic bound-sensor enrollment demonstration.

The script deliberately never prints the one-time enrollment token, issued
credentials, request headers, or response bodies that may contain them.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from uuid import uuid4


ADMIN_HEADER = "X-OpenAssetWatch-Admin-Token"
SENSOR_HEADER = "X-OpenAssetWatch-Collector-Token"
MAX_RESPONSE_BYTES = 1 << 20
SECRET_VALUE_PREFIXES = ("oaw_enroll_v1.", "oaw_sensor_v1.")
FORBIDDEN_RESPONSE_KEYS = frozenset(
    {
        "authorization",
        "credential",
        "credential_digest",
        "enrollment_token",
        "sensor_credential",
        "token_digest",
        "token_lookup_id",
        ADMIN_HEADER.lower().replace("-", "_"),
        SENSOR_HEADER.lower().replace("-", "_"),
    }
)
SAFE_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")
SAFE_FAILURE_MESSAGES = {
    "cleartext-remote-url": "HTTP is allowed only for a loopback demonstration hub",
    "evidence-not-visible": "historical evidence was not visible to assets and deterministic AI",
    "invalid-hub-json": "hub returned invalid JSON",
    "invalid-hub-response": "hub returned an invalid response",
    "invalid-server-url": "server URL is invalid",
    "missing-admin-token": "the configured admin-token environment variable is empty",
    "missing-enrollment-token": "hub did not issue an enrollment token",
    "missing-replacement-credential": "hub did not issue a replacement credential",
    "missing-sensor-credential": "hub did not issue a sensor credential",
    "oversized-hub-response": "hub response exceeded the demonstration size limit",
    "unexpected-http-status": "hub returned an unexpected HTTP status",
    "unsafe-admin-response": "hub returned an unsafe administrative response",
    "unsafe-public-result": "demonstration result failed safe-output validation",
    "unsafe-server-url": "server URL contains a disallowed component",
}


class DemoFailure(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    @property
    def safe_message(self) -> str:
        return SAFE_FAILURE_MESSAGES.get(self.code, "demonstration operation failed")


def safe_base_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise DemoFailure("invalid-server-url")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise DemoFailure("unsafe-server-url")
    if parsed.path not in {"", "/"}:
        raise DemoFailure("unsafe-server-url")
    if parsed.scheme == "http":
        host = parsed.hostname.rstrip(".").lower()
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not loopback:
            raise DemoFailure("cleartext-remote-url")
    return value.rstrip("/")


def assert_secret_free_response(value: object) -> None:
    """Reject secret-bearing administrative data without returning tainted values."""

    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized in FORBIDDEN_RESPONSE_KEYS or "authorization" in normalized:
                raise DemoFailure("unsafe-admin-response")
            assert_secret_free_response(child)
        return
    if isinstance(value, list):
        for child in value:
            assert_secret_free_response(child)
        return
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized.startswith(SECRET_VALUE_PREFIXES) or "authorization:" in normalized:
            raise DemoFailure("unsafe-admin-response")


def _safe_identifier(value: object) -> str:
    if not isinstance(value, str) or not SAFE_IDENTIFIER_PATTERN.fullmatch(value):
        raise DemoFailure("unsafe-public-result")
    if value.lower().startswith(SECRET_VALUE_PREFIXES):
        raise DemoFailure("unsafe-public-result")
    return value


def public_summary(result: dict[str, object]) -> dict[str, object]:
    """Build the only object that main is permitted to serialize."""

    first_batch = result.get("first_batch")
    duplicate_batch = result.get("duplicate_batch")
    if first_batch != "accepted" or duplicate_batch != "duplicate":
        raise DemoFailure("unsafe-public-result")
    return {
        "site_id": _safe_identifier(result.get("site_id")),
        "sensor_id": _safe_identifier(result.get("sensor_id")),
        "enrollment_replay_rejected": result.get("enrollment_replay_rejected") is True,
        "first_batch": "accepted",
        "duplicate_batch": "duplicate",
        "site_mismatch_rejected": result.get("site_mismatch_rejected") is True,
        "sensor_mismatch_rejected": result.get("sensor_mismatch_rejected") is True,
        "old_credential_rejected": result.get("old_credential_rejected") is True,
        "new_credential_accepted": result.get("new_credential_accepted") is True,
        "revoked_credential_rejected": result.get("revoked_credential_rejected") is True,
        "historical_evidence_retained": result.get("historical_evidence_retained") is True,
        "ai_evidence_visible": result.get("ai_evidence_visible") is True,
        "admin_views_secret_free": result.get("admin_views_secret_free") is True,
    }


class Client:
    def __init__(self, base_url: str, admin_token: str) -> None:
        self.base_url = safe_base_url(base_url)
        self.admin_token = admin_token

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
        *,
        admin: bool = False,
        sensor_credential: str | None = None,
        expected: set[int] | None = None,
    ) -> tuple[int, dict[str, object]]:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=body,
            method=method,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        if admin:
            request.add_header(ADMIN_HEADER, self.admin_token)
        if sensor_credential is not None:
            request.add_header(SENSOR_HEADER, sensor_credential)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                status = response.status
                response_body = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            status = exc.code
            response_body = exc.read(MAX_RESPONSE_BYTES + 1)
        if len(response_body) > MAX_RESPONSE_BYTES:
            raise DemoFailure("oversized-hub-response")
        try:
            decoded = json.loads(response_body or b"{}")
        except json.JSONDecodeError as exc:
            raise DemoFailure("invalid-hub-json") from exc
        if not isinstance(decoded, dict):
            raise DemoFailure("invalid-hub-response")
        allowed = expected or {200}
        if status not in allowed:
            raise DemoFailure("unexpected-http-status")
        return status, decoded


def run(args: argparse.Namespace) -> dict[str, object]:
    admin_token = os.getenv(args.admin_token_env, "")
    if not admin_token:
        raise DemoFailure("missing-admin-token")
    suffix = uuid4().hex[:10]
    site_id = args.site_id or f"sensor-enrollment-demo-{suffix}"
    sensor_id = args.sensor_id or f"sensor-enrollment-demo-{suffix}"
    asset_id = f"asset-enrollment-demo-{suffix}"
    client = Client(args.server_url, admin_token)

    client.request(
        "POST",
        "/api/v1/sites",
        {"site_id": site_id, "name": "Sensor Enrollment Demo", "description": "Synthetic data only"},
    )
    _, enrollment = client.request(
        "POST",
        "/api/v1/admin/sensor-enrollments",
        {
            "site_id": site_id,
            "requested_sensor_id": sensor_id,
            "requested_sensor_name": "Synthetic Enrollment Sensor",
            "sensor_type": "passive-network-sensor",
            "expires_in_minutes": 30,
        },
        admin=True,
    )
    enrollment_token = str(enrollment.pop("enrollment_token", ""))
    if not enrollment_token:
        raise DemoFailure("missing-enrollment-token")
    exchange_payload = {
        "enrollment_token": enrollment_token,
        "sensor_id": sensor_id,
        "sensor_name": "Synthetic Enrollment Sensor",
        "sensor_type": "passive-network-sensor",
        "sensor_version": "demo",
        "platform": sys.platform[:80],
    }
    _, issued = client.request("POST", "/api/v1/sensors/enroll", exchange_payload)
    sensor_credential = str(issued.pop("sensor_credential", ""))
    if not sensor_credential:
        raise DemoFailure("missing-sensor-credential")
    replay_status, _ = client.request(
        "POST",
        "/api/v1/sensors/enroll",
        exchange_payload,
        expected={401},
    )
    exchange_payload["enrollment_token"] = ""
    enrollment_token = ""

    observed_at = datetime.now(timezone.utc).replace(microsecond=0)
    batch = {
        "schema_version": "oaw.observation-batch.v1",
        "observation_batch_id": f"{sensor_id}:{observed_at.strftime('%Y%m%dT%H%M%SZ')}:0001",
        "site_id": site_id,
        "sensor_id": sensor_id,
        "sensor_name": "Synthetic Enrollment Sensor",
        "sensor_type": "passive-network-sensor",
        "sensor_version": "demo",
        "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
        "observation_source": "passive-network",
        "delivery_state": "live",
        "confidence": 0.9,
        "assets": [
            {
                "asset_id": asset_id,
                "hostname": "synthetic-enrollment-host",
                "primary_ip": "192.0.2.240",
                "mac": "02:00:5e:10:20:40",
                "category": "synthetic",
                "evidence": [
                    {
                        "protocol": "mdns",
                        "kind": "address-record",
                        "value": "synthetic-enrollment-host.local=192.0.2.240",
                        "confidence": 0.9,
                    }
                ],
            }
        ],
    }
    _, first = client.request(
        "POST", "/api/v1/observations/batches", batch, sensor_credential=sensor_credential
    )
    _, duplicate = client.request(
        "POST", "/api/v1/observations/batches", batch, sensor_credential=sensor_credential
    )
    mismatch_site = dict(batch)
    mismatch_site["site_id"] = "other-site"
    mismatch_sensor = dict(batch)
    mismatch_sensor["sensor_id"] = "other-sensor"
    site_mismatch, _ = client.request(
        "POST",
        "/api/v1/observations/batches",
        mismatch_site,
        sensor_credential=sensor_credential,
        expected={401},
    )
    sensor_mismatch, _ = client.request(
        "POST",
        "/api/v1/observations/batches",
        mismatch_sensor,
        sensor_credential=sensor_credential,
        expected={401},
    )

    _, rotation = client.request(
        "POST",
        f"/api/v1/admin/sensors/{sensor_id}/credentials/rotate",
        {},
        admin=True,
    )
    replacement = str(rotation.pop("sensor_credential", ""))
    if not replacement:
        raise DemoFailure("missing-replacement-credential")
    old_status, _ = client.request(
        "POST",
        "/api/v1/observations/batches",
        batch,
        sensor_credential=sensor_credential,
        expected={401},
    )
    new_status, _ = client.request(
        "POST", "/api/v1/observations/batches", batch, sensor_credential=replacement
    )
    sensor_credential = ""
    client.request("POST", f"/api/v1/admin/sensors/{sensor_id}/revoke", {}, admin=True)
    revoked_status, _ = client.request(
        "POST",
        "/api/v1/observations/batches",
        batch,
        sensor_credential=replacement,
        expected={401},
    )
    replacement = ""

    _, assets = client.request("GET", "/api/v1/control-tower/assets")
    _, advisor = client.request(
        "POST",
        "/api/v1/ai/advisor/query",
        {"question": "Which assets were observed at this site?", "site_id": site_id},
        admin=True,
    )
    _, enrollments = client.request("GET", "/api/v1/admin/sensor-enrollments", admin=True)
    _, credentials = client.request("GET", "/api/v1/admin/sensors", admin=True)
    _, audit = client.request("GET", "/api/v1/admin/sensor-identity/audit?limit=100", admin=True)
    assert_secret_free_response(enrollments)
    assert_secret_free_response(credentials)
    assert_secret_free_response(audit)
    if asset_id not in json.dumps(assets) or asset_id not in json.dumps(advisor):
        raise DemoFailure("evidence-not-visible")
    client.admin_token = ""
    admin_token = ""

    return {
        "site_id": site_id,
        "sensor_id": sensor_id,
        "enrollment_replay_rejected": replay_status == 401,
        "first_batch": first.get("status"),
        "duplicate_batch": duplicate.get("status"),
        "site_mismatch_rejected": site_mismatch == 401,
        "sensor_mismatch_rejected": sensor_mismatch == 401,
        "old_credential_rejected": old_status == 401,
        "new_credential_accepted": new_status == 200,
        "revoked_credential_rejected": revoked_status == 401,
        "historical_evidence_retained": True,
        "ai_evidence_visible": True,
        "admin_views_secret_free": True,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-url", default="http://127.0.0.1:8000")
    parser.add_argument("--admin-token-env", default="OPENASSETWATCH_ADMIN_TOKEN")
    parser.add_argument("--site-id")
    parser.add_argument("--sensor-id")
    return parser.parse_args()


def main() -> int:
    try:
        result = public_summary(run(parse_args()))
    except DemoFailure as exc:
        print(f"sensor enrollment demo failed: {exc.safe_message}", file=sys.stderr)
        return 1
    except OSError:
        print("sensor enrollment demo failed: hub request failed", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
