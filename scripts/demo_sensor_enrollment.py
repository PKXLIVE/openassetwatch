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
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from uuid import uuid4


ADMIN_HEADER = "X-OpenAssetWatch-Admin-Token"
SENSOR_HEADER = "X-OpenAssetWatch-Collector-Token"
MAX_RESPONSE_BYTES = 1 << 20


class DemoFailure(RuntimeError):
    pass


def safe_base_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise DemoFailure("server URL must use http or https and include a host")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise DemoFailure("server URL must not include credentials, query, or fragment")
    if parsed.path not in {"", "/"}:
        raise DemoFailure("server URL must not include a path")
    if parsed.scheme == "http":
        host = parsed.hostname.rstrip(".").lower()
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        if not loopback:
            raise DemoFailure("HTTP is allowed only for a loopback demonstration hub")
    return value.rstrip("/")


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
            raise DemoFailure("hub response exceeded the demonstration size limit")
        try:
            decoded = json.loads(response_body or b"{}")
        except json.JSONDecodeError as exc:
            raise DemoFailure(f"hub returned invalid JSON for {method} {path}") from exc
        if not isinstance(decoded, dict):
            raise DemoFailure(f"hub returned an invalid response for {method} {path}")
        allowed = expected or {200}
        if status not in allowed:
            raise DemoFailure(f"hub returned HTTP {status} for {method} {path}")
        return status, decoded


def run(args: argparse.Namespace) -> dict[str, object]:
    admin_token = os.getenv(args.admin_token_env, "")
    if not admin_token:
        raise DemoFailure(f"{args.admin_token_env} must contain the configured hub admin token")
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
        raise DemoFailure("hub did not issue an enrollment token")
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
        raise DemoFailure("hub did not issue a sensor credential")
    replay_status, _ = client.request(
        "POST",
        "/api/v1/sensors/enroll",
        exchange_payload,
        expected={401},
    )
    secret_values = [enrollment_token, sensor_credential]
    exchange_payload["enrollment_token"] = ""

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
        raise DemoFailure("hub did not issue a replacement credential")
    secret_values.append(replacement)
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
    client.request("POST", f"/api/v1/admin/sensors/{sensor_id}/revoke", {}, admin=True)
    revoked_status, _ = client.request(
        "POST",
        "/api/v1/observations/batches",
        batch,
        sensor_credential=replacement,
        expected={401},
    )

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
    administrative_views = json.dumps([enrollments, credentials, audit])
    secret_free_views = all(secret not in administrative_views for secret in secret_values)
    secret_values.clear()
    if asset_id not in json.dumps(assets) or asset_id not in json.dumps(advisor):
        raise DemoFailure("historical evidence was not visible to assets and deterministic AI")
    if not secret_free_views:
        raise DemoFailure("an administrative status view disclosed credential material")

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
        "admin_views_secret_free": secret_free_views,
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
        result = run(parse_args())
    except (DemoFailure, OSError) as exc:
        print(f"sensor enrollment demo failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
