from __future__ import annotations

import json
import os
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError

from app.hub_contracts import ObservationBatchRequest
from app.main import observation_batch
from app.sensor_identity import SensorAuthContext, SensorAuthenticationRejected


def batch_payload() -> dict[str, object]:
    return {
        "schema_version": "oaw.observation-batch.v1",
        "observation_batch_id": "sensor-home:20260720T120000Z:0001",
        "site_id": "home",
        "sensor_id": "sensor-home",
        "sensor_name": "Home Passive Sensor",
        "sensor_type": "passive-network-sensor",
        "sensor_version": "0.1.0",
        "observed_at": "2026-07-20T12:00:00Z",
        "observation_source": "passive-network",
        "delivery_state": "cached-retry",
        "confidence": 0.9,
        "assets": [
            {
                "asset_id": "home-router",
                "hostname": "home-router",
                "primary_ip": "192.0.2.1",
                "mac": "02:00:5e:10:00:01",
                "category": "router",
            }
        ],
    }


class ObservationBatchTests(unittest.TestCase):
    def test_exact_go_sensor_fixture_is_accepted_by_pydantic(self) -> None:
        fixture_path = Path(__file__).parent / "fixtures" / "passive_sensor_batch.json"
        payload = ObservationBatchRequest(**json.loads(fixture_path.read_text(encoding="utf-8")))

        self.assertEqual(payload.sensor_type, "passive-network-sensor")
        self.assertEqual(payload.assets[0].evidence[0].protocol, "dns")
        self.assertEqual(payload.assets[0].evidence[1].protocol, "vlan")
        self.assertFalse(hasattr(payload.assets[0], "raw_packet"))

    def test_valid_batch_is_collector_authenticated_and_normalized(self) -> None:
        payload = ObservationBatchRequest(**batch_payload())
        with (
            patch.dict(os.environ, {"OPENASSETWATCH_COLLECTOR_TOKEN": "collector-test-value"}, clear=False),
            patch(
                "app.main.authenticate_sensor_request",
                return_value=SensorAuthContext(
                    mode="bound-sensor",
                    site_id="home",
                    sensor_id="sensor-home",
                    sensor_type="passive-network-sensor",
                    credential_id="scred_test",
                ),
            ) as authenticate,
            patch(
                "app.main.record_observation_batch",
                return_value={"collection_id": 7, "normalized_asset_count": 1, "duplicate": False},
            ) as record,
        ):
            response = observation_batch(payload, collector_token="collector-test-value")

        self.assertEqual(response.status, "accepted")
        self.assertEqual(response.storage_id, 7)
        self.assertEqual(response.sensor_id, "sensor-home")
        self.assertEqual(record.call_args.kwargs["payload"]["delivery_state"], "cached-retry")
        self.assertEqual(authenticate.call_args.kwargs["claimed_site_id"], "home")
        self.assertEqual(authenticate.call_args.kwargs["claimed_sensor_id"], "sensor-home")

    def test_sensor_authentication_is_required(self) -> None:
        payload = ObservationBatchRequest(**batch_payload())
        with patch(
            "app.main.authenticate_sensor_request",
            side_effect=SensorAuthenticationRejected("valid sensor credential required"),
        ):
            with self.assertRaises(HTTPException) as raised:
                observation_batch(payload, collector_token=None)

        self.assertEqual(raised.exception.status_code, 401)
        self.assertEqual(raised.exception.detail, "valid sensor credential required")

    def test_duplicate_batch_returns_stable_storage_id_without_new_evidence(self) -> None:
        payload = ObservationBatchRequest(**batch_payload())
        with (
            patch.dict(os.environ, {"OPENASSETWATCH_COLLECTOR_TOKEN": "explicit-development-token"}, clear=False),
            patch(
                "app.main.record_observation_batch",
                return_value={"collection_id": 7, "normalized_asset_count": 1, "duplicate": True},
            ),
        ):
            response = observation_batch(payload, collector_token="explicit-development-token")

        self.assertEqual(response.status, "duplicate")
        self.assertIn("no duplicate", response.message)

    def test_contract_rejects_extra_execution_fields_and_too_many_assets(self) -> None:
        unsafe = batch_payload()
        unsafe["command"] = "do-not-run"
        with self.assertRaises(ValidationError):
            ObservationBatchRequest(**unsafe)

        oversized = batch_payload()
        oversized["assets"] = [batch_payload()["assets"][0]] * 501
        with self.assertRaises(ValidationError):
            ObservationBatchRequest(**oversized)

    def test_contract_requires_stable_identity_and_bounded_confidence(self) -> None:
        invalid = batch_payload()
        invalid["sensor_id"] = ""
        with self.assertRaises(ValidationError):
            ObservationBatchRequest(**invalid)

        invalid = batch_payload()
        invalid["confidence"] = 1.5
        with self.assertRaises(ValidationError):
            ObservationBatchRequest(**invalid)

    def test_payload_has_no_raw_packet_or_arbitrary_attribute_channel(self) -> None:
        invalid = batch_payload()
        invalid["assets"][0]["raw_packet"] = "00ff"
        with self.assertRaises(ValidationError):
            ObservationBatchRequest(**invalid)

        hub_owned = batch_payload()
        hub_owned["assets"][0]["risk_score"] = 99
        with self.assertRaises(ValidationError):
            ObservationBatchRequest(**hub_owned)

    def test_bounded_passive_evidence_is_accepted_and_raw_packets_are_not(self) -> None:
        payload = batch_payload()
        payload["assets"][0]["evidence"] = [
            {
                "protocol": "dns",
                "kind": "query-name",
                "value": "printer.example.test",
                "confidence": 0.75,
            }
        ]
        parsed = ObservationBatchRequest(**payload)
        self.assertEqual(parsed.assets[0].evidence[0].protocol, "dns")

        oversized = batch_payload()
        oversized["assets"][0]["evidence"] = [
            {
                "protocol": "dns",
                "kind": "query-name",
                "value": "name",
                "confidence": 0.5,
            }
        ] * 33
        with self.assertRaises(ValidationError):
            ObservationBatchRequest(**oversized)

        unsafe = batch_payload()
        unsafe["assets"][0]["evidence"] = [
            {
                "protocol": "dns",
                "kind": "query-name",
                "value": "name",
                "confidence": 0.5,
                "raw_packet": "00ff",
            }
        ]
        with self.assertRaises(ValidationError):
            ObservationBatchRequest(**unsafe)

    def test_observed_at_is_timezone_aware(self) -> None:
        payload = ObservationBatchRequest(**batch_payload())

        self.assertEqual(payload.observed_at, datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc))

        invalid = batch_payload()
        invalid["observed_at"] = "2026-07-20T12:00:00"
        with self.assertRaises(ValidationError):
            ObservationBatchRequest(**invalid)


if __name__ == "__main__":
    unittest.main()
