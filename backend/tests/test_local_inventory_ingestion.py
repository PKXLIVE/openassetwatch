from __future__ import annotations

import asyncio
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from fastapi import BackgroundTasks, HTTPException

from app.canonical_ingestion import CanonicalIngestionAcknowledgement
from app.database import normalize_local_inventory_assets
from app.main import app, local_inventory_collection


def local_inventory_payload() -> dict[str, object]:
    return {
        "schema_version": "oaw.inventory.v1",
        "site_id": "site-local",
        "collected_at": "2026-06-17T12:00:00Z",
        "assets": [
            {
                "asset_id": "local-host",
                "site_id": "site-local",
                "external_ci_id": "ci-123",
                "external_ci_source": "ServiceNow",
                "hostname": "workstation-01",
                "fqdn": "workstation-01.example.test",
                "os": "windows",
                "platform": "windows/amd64",
                "architecture": "amd64",
                "host": {
                    "hostname": "workstation-01",
                    "fqdn": "workstation-01.example.test",
                    "source": "os_hostname",
                    "collected_at": "2026-06-17T12:00:00Z",
                },
                "platform_info": {
                    "os": "windows",
                    "platform": "windows/amd64",
                    "architecture": "amd64",
                    "architecture_family": "x86_64",
                    "source": "go_runtime",
                    "collected_at": "2026-06-17T12:00:00Z",
                },
                "primary_interfaces": [
                    {
                        "name": "Ethernet",
                        "mac_address": "00:11:22:33:44:55",
                        "flags": ["up", "broadcast"],
                        "ip_addresses": [
                            {
                                "address": "192.0.2.10",
                                "family": "ipv4",
                                "interface": "Ethernet",
                                "source": "go_net_interfaces",
                                "collected_at": "2026-06-17T12:00:00Z",
                            }
                        ],
                        "source": "go_net_interfaces",
                        "collected_at": "2026-06-17T12:00:00Z",
                    }
                ],
                "ip_addresses": [
                    {
                        "address": "192.0.2.10",
                        "family": "ipv4",
                        "interface": "Ethernet",
                        "source": "go_net_interfaces",
                        "collected_at": "2026-06-17T12:00:00Z",
                    }
                ],
                "mac_addresses": [
                    {
                        "address": "00:11:22:33:44:55",
                        "interface": "Ethernet",
                        "source": "go_net_interfaces",
                        "collected_at": "2026-06-17T12:00:00Z",
                    }
                ],
                "default_gateway": {
                    "address": "192.0.2.1",
                    "interface": "Ethernet",
                    "source": "windows_get_net_route",
                    "collected_at": "2026-06-17T12:00:00Z",
                },
                "network_neighbors": [
                    {
                        "ip_address": "192.0.2.1",
                        "mac_address": "66:77:88:99:aa:bb",
                        "interface": "Ethernet",
                        "state": "reachable",
                        "source": "windows_get_net_neighbor",
                        "sources": ["windows_get_net_neighbor"],
                        "collected_at": "2026-06-17T12:00:00Z",
                    }
                ],
            }
        ],
    }


def transitional_acknowledgement() -> CanonicalIngestionAcknowledgement:
    return CanonicalIngestionAcknowledgement(
        status="accepted",
        canonical_collection_id="col_" + "4" * 32,
        canonical_asset_ids=("local-host",),
        replay_state="new",
        evidence_count=0,
        component_count=0,
        evaluation_state="queued",
        warnings=("transitional compatibility input is untrusted and deprecated",),
        adapter_type="transitional-local",
        compatibility_status="deprecated",
        source_authority="untrusted-transitional",
        compatibility_collection_id=1,
        received_at=datetime.now(timezone.utc),
        observed_asset_count=1,
        normalized_asset_count=1,
    )


def post_raw_json(path: str, body: bytes) -> tuple[int, bytes]:
    messages: list[dict[str, object]] = []
    sent_body = False

    async def receive() -> dict[str, object]:
        nonlocal sent_body
        if sent_body:
            return {"type": "http.disconnect"}
        sent_body = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    async def call_app() -> None:
        await app(
            {
                "type": "http",
                "asgi": {"version": "3.0", "spec_version": "2.3"},
                "http_version": "1.1",
                "method": "POST",
                "scheme": "http",
                "path": path,
                "raw_path": path.encode("ascii"),
                "root_path": "",
                "query_string": b"",
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
                "client": ("testclient", 50000),
                "server": ("testserver", 80),
            },
            receive,
            send,
        )

    asyncio.run(call_app())
    status = next(message["status"] for message in messages if message["type"] == "http.response.start")
    response_body = b"".join(
        message.get("body", b"") for message in messages if message["type"] == "http.response.body"
    )
    return int(status), response_body


class LocalInventoryIngestionTests(unittest.TestCase):
    def test_valid_collection_json_is_accepted(self) -> None:
        with patch(
            "app.main.ingest_canonical_inventory",
            return_value=transitional_acknowledgement(),
        ) as ingest:
            response = local_inventory_collection(local_inventory_payload())

        self.assertEqual(response.status, "accepted")
        self.assertEqual(response.observation_batch_id, 1)
        self.assertEqual(response.site_id, "site-local")
        self.assertEqual(response.observed_asset_count, 1)
        self.assertEqual(response.normalized_asset_count, 1)
        envelope = ingest.call_args.args[0]
        self.assertEqual(envelope.site_id, "site-local")
        self.assertEqual(envelope.source_authority, "untrusted-transitional")

    def test_collection_queues_only_persisted_assets_for_classification(self) -> None:
        background = BackgroundTasks()
        with patch(
            "app.main.ingest_canonical_inventory",
            return_value=transitional_acknowledgement(),
        ):
            response = local_inventory_collection(
                local_inventory_payload(),
                background_tasks=background,
            )

        self.assertEqual(response.status, "accepted")
        self.assertEqual(len(background.tasks), 1)
        self.assertEqual(
            background.tasks[0].kwargs,
            {
                "canonical_collection_id": "col_" + "4" * 32,
            },
        )

    def test_malformed_json_is_rejected(self) -> None:
        status, response_body = post_raw_json("/api/v1/collections/local-inventory", b'{"schema_version":')

        self.assertIn(status, {400, 422})
        self.assertIn(b"detail", response_body)

    def test_missing_site_id_is_rejected(self) -> None:
        payload = local_inventory_payload()
        payload.pop("site_id")

        with self.assertRaises(HTTPException) as raised:
            local_inventory_collection(payload)

        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("site_id", raised.exception.detail)

    def test_optional_deployment_agent_and_sensor_ids_are_accepted(self) -> None:
        payload = local_inventory_payload()
        payload["deployment_id"] = "11111111-1111-4111-8111-111111111111"
        payload["agent_id"] = "22222222-2222-4222-8222-222222222222"
        payload["sensor_id"] = "33333333-3333-4333-8333-333333333333"

        with patch(
            "app.main.ingest_canonical_inventory",
            return_value=transitional_acknowledgement(),
        ) as ingest:
            response = local_inventory_collection(payload)

        self.assertEqual(response.status, "accepted")
        envelope = ingest.call_args.args[0]
        self.assertIsNone(envelope.bound_identity_id)
        self.assertIsNone(envelope.credential_id)
        self.assertEqual(envelope.source_authority, "untrusted-transitional")
        self.assertNotIn("agent_id", envelope.provenance)
        self.assertNotIn("sensor_id", envelope.provenance)
        self.assertNotIn("deployment_id", envelope.provenance)

    def test_payload_without_optional_installed_identity_is_accepted(self) -> None:
        payload = local_inventory_payload()

        with patch(
            "app.main.ingest_canonical_inventory",
            return_value=transitional_acknowledgement(),
        ):
            response = local_inventory_collection(payload)

        self.assertEqual(response.status, "accepted")

    def test_external_ci_hints_are_accepted_as_observations(self) -> None:
        payload = local_inventory_payload()

        with patch(
            "app.main.ingest_canonical_inventory",
            return_value=transitional_acknowledgement(),
        ):
            response = local_inventory_collection(payload)

        self.assertEqual(response.status, "accepted")
        asset = payload["assets"][0]
        self.assertEqual(asset["external_ci_id"], "ci-123")
        self.assertEqual(asset["external_ci_source"], "ServiceNow")

    def test_neighbor_and_interface_observations_are_accepted(self) -> None:
        payload = local_inventory_payload()

        with patch(
            "app.main.ingest_canonical_inventory",
            return_value=transitional_acknowledgement(),
        ):
            response = local_inventory_collection(payload)

        self.assertEqual(response.observed_asset_count, 1)
        asset = payload["assets"][0]
        self.assertEqual(asset["primary_interfaces"][0]["source"], "go_net_interfaces")
        self.assertEqual(asset["network_neighbors"][0]["source"], "windows_get_net_neighbor")

    def test_unsafe_top_level_fields_are_rejected(self) -> None:
        for field in ("command", "args", "additional_args", "password", "hash", "script_content"):
            with self.subTest(field=field):
                payload = local_inventory_payload()
                payload[field] = "unsafe"

                with self.assertRaises(HTTPException) as raised:
                    local_inventory_collection(payload)

                self.assertEqual(raised.exception.status_code, 400)
                self.assertIn(field, raised.exception.detail)

    def test_empty_payload_is_rejected(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            local_inventory_collection({})

        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("must not be empty", raised.exception.detail)

    def test_assets_must_be_json_array_when_present(self) -> None:
        payload = local_inventory_payload()
        payload["assets"] = {"asset_id": "local-host"}

        with self.assertRaises(HTTPException) as raised:
            local_inventory_collection(payload)

        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("assets", raised.exception.detail)

    def test_http_valid_collection_returns_json_response(self) -> None:
        with patch(
            "app.main.ingest_canonical_inventory",
            return_value=transitional_acknowledgement(),
        ):
            status, response_body = post_raw_json(
                "/api/v1/collections/local-inventory",
                json.dumps(local_inventory_payload()).encode("utf-8"),
            )

        self.assertEqual(status, 200)
        response = json.loads(response_body)
        self.assertEqual(response["status"], "accepted")
        self.assertEqual(response["site_id"], "site-local")
        self.assertEqual(response["observed_asset_count"], 1)
        self.assertEqual(response["normalized_asset_count"], 1)

    def test_future_local_inventory_time_is_clamped_to_receive_time(self) -> None:
        received_at = datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc)
        payload = local_inventory_payload()
        payload["collected_at"] = (received_at + timedelta(days=365)).isoformat()

        assets = normalize_local_inventory_assets(
            payload,
            site_id="site-local",
            received_at=received_at,
        )

        self.assertEqual(assets[0]["observed_at"], received_at)
        self.assertEqual(assets[0]["last_seen_at"], received_at)


if __name__ == "__main__":
    unittest.main()
