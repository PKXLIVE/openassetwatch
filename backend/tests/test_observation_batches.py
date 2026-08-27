from __future__ import annotations

import json
import os
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi import BackgroundTasks, HTTPException
from pydantic import ValidationError

from app.canonical_ingestion import CanonicalIngestionAcknowledgement
from app.database import record_observation_batch as persist_observation_batch
from app.hub_contracts import ObservationBatchRequest
from app.main import observation_batch
from app import main as main_module
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


def sensor_acknowledgement(
    *,
    status: str = "accepted",
    source_authority: str = "authenticated-passive-sensor",
    asset_ids: tuple[str, ...] = ("home-router",),
) -> CanonicalIngestionAcknowledgement:
    return CanonicalIngestionAcknowledgement(
        status=status,
        canonical_collection_id="col_" + "5" * 32,
        canonical_asset_ids=asset_ids if status == "accepted" else (),
        replay_state="new" if status == "accepted" else "identical-replay",
        evidence_count=0,
        component_count=0,
        evaluation_state="queued",
        warnings=("passive observations do not prove endpoint ownership",),
        adapter_type="passive-sensor",
        compatibility_status=(
            "canonical"
            if source_authority == "authenticated-passive-sensor"
            else "deprecated"
        ),
        source_authority=source_authority,
        compatibility_collection_id=7,
        received_at=datetime.now(timezone.utc),
        observed_asset_count=1,
        normalized_asset_count=1,
    )


class ObservationBatchTests(unittest.TestCase):
    def setUp(self) -> None:
        with main_module._canonical_evaluation_lock:
            main_module._canonical_evaluations_pending.clear()

    def tearDown(self) -> None:
        with main_module._canonical_evaluation_lock:
            main_module._canonical_evaluations_pending.clear()

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
                "app.main.ingest_canonical_inventory",
                return_value=sensor_acknowledgement(),
            ) as ingest,
        ):
            response = observation_batch(payload, collector_token="collector-test-value")

        self.assertEqual(response.status, "accepted")
        self.assertEqual(response.storage_id, 7)
        self.assertEqual(response.sensor_id, "sensor-home")
        envelope = ingest.call_args.args[0]
        self.assertEqual(envelope.source_authority, "authenticated-passive-sensor")
        self.assertEqual(envelope.bound_identity_id, "sensor-home")
        self.assertEqual(envelope.credential_id, "scred_test")
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
                "app.main.ingest_canonical_inventory",
                return_value=sensor_acknowledgement(
                    status="duplicate",
                    source_authority="untrusted-transitional",
                ),
            ),
        ):
            response = observation_batch(payload, collector_token="explicit-development-token")

        self.assertEqual(response.status, "duplicate")
        self.assertIn("no duplicate", response.message)

    def test_accepted_batch_queues_only_affected_assets_for_classification(self) -> None:
        payload = ObservationBatchRequest(**batch_payload())
        background = BackgroundTasks()
        with (
            patch.dict(
                os.environ,
                {"OPENASSETWATCH_COLLECTOR_TOKEN": "explicit-development-token"},
                clear=False,
            ),
            patch(
                "app.main.authenticate_sensor_request",
                return_value=SensorAuthContext(
                    mode="bound-sensor",
                    site_id="home",
                    sensor_id="sensor-home",
                    sensor_type="passive-network-sensor",
                    credential_id="scred_test",
                ),
            ),
            patch(
                "app.main.ingest_canonical_inventory",
                return_value=sensor_acknowledgement(),
            ),
        ):
            response = observation_batch(
                payload,
                background_tasks=background,
                collector_token="explicit-development-token",
            )

        self.assertEqual(response.status, "accepted")
        self.assertEqual(len(background.tasks), 1)
        self.assertEqual(
            background.tasks[0].kwargs,
            {
                "canonical_collection_id": "col_" + "5" * 32,
            },
        )

    def test_development_shared_token_remains_untrusted_when_queued(
        self,
    ) -> None:
        payload = ObservationBatchRequest(**batch_payload())
        background = BackgroundTasks()
        with (
            patch.dict(
                os.environ,
                {"OPENASSETWATCH_COLLECTOR_TOKEN": "explicit-development-token"},
                clear=False,
            ),
            patch(
                "app.main.ingest_canonical_inventory",
                return_value=sensor_acknowledgement(
                    source_authority="untrusted-transitional",
                ),
            ) as ingest,
        ):
            response = observation_batch(
                payload,
                background_tasks=background,
                collector_token="explicit-development-token",
            )

        self.assertEqual(response.status, "accepted")
        envelope = ingest.call_args.args[0]
        self.assertFalse(envelope.source_authenticated)
        self.assertEqual(envelope.source_authority, "untrusted-transitional")
        self.assertIsNone(envelope.bound_identity_id)
        self.assertEqual(len(background.tasks), 1)
        self.assertEqual(
            background.tasks[0].kwargs,
            {
                "canonical_collection_id": "col_" + "5" * 32,
            },
        )

    def test_duplicate_batch_does_not_queue_classification(self) -> None:
        payload = ObservationBatchRequest(**batch_payload())
        background = BackgroundTasks()
        with (
            patch.dict(
                os.environ,
                {"OPENASSETWATCH_COLLECTOR_TOKEN": "explicit-development-token"},
                clear=False,
            ),
            patch(
                "app.main.ingest_canonical_inventory",
                return_value=sensor_acknowledgement(
                    status="duplicate",
                    source_authority="untrusted-transitional",
                ),
            ),
        ):
            response = observation_batch(
                payload,
                background_tasks=background,
                collector_token="explicit-development-token",
            )

        self.assertEqual(response.status, "duplicate")
        self.assertEqual(background.tasks, [])

    def test_contract_rejects_extra_execution_fields_and_too_many_assets(self) -> None:
        unsafe = batch_payload()
        unsafe["command"] = "do-not-run"
        with self.assertRaises(ValidationError):
            ObservationBatchRequest(**unsafe)

        oversized = batch_payload()
        oversized["assets"] = [batch_payload()["assets"][0]] * 501
        with self.assertRaises(ValidationError):
            ObservationBatchRequest(**oversized)

    def test_contract_rejects_aggregate_components_before_asset_models(self) -> None:
        payload = batch_payload()
        component = {
            "component_type": "firmware",
            "ecosystem": "generic",
            "name": "example-firmware",
        }
        payload["assets"] = [
            {
                "asset_id": f"asset-{index}",
                "components": [component] * 1_000,
            }
            for index in range(33)
        ]

        with self.assertRaisesRegex(ValidationError, "component limit"):
            ObservationBatchRequest(**payload)

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

    def test_observed_at_rejects_excessive_future_clock_skew(self) -> None:
        invalid = batch_payload()
        invalid["observed_at"] = (
            datetime.now(timezone.utc) + timedelta(minutes=10)
        ).isoformat()

        with self.assertRaisesRegex(ValidationError, "future clock skew"):
            ObservationBatchRequest(**invalid)

    def test_component_observed_at_requires_timezone_and_batch_bound(
        self,
    ) -> None:
        naive = batch_payload()
        naive["assets"][0]["components"] = [
            {
                "component_type": "application",
                "ecosystem": "pypi",
                "name": "asterion-agent",
                "version": "1.2.0",
                "observed_at": "2020-01-01T00:00:00",
            }
        ]
        with self.assertRaisesRegex(ValidationError, "timezone"):
            ObservationBatchRequest(**naive)

        after_batch = batch_payload()
        after_batch["assets"][0]["components"] = [
            {
                "component_type": "application",
                "ecosystem": "pypi",
                "name": "asterion-agent",
                "version": "1.2.0",
                "observed_at": "2026-07-20T12:06:00+00:00",
            }
        ]
        with self.assertRaisesRegex(
            ValidationError,
            "batch observation time",
        ):
            ObservationBatchRequest(**after_batch)

    def test_authenticated_observation_context_is_server_derived(self) -> None:
        payload = batch_payload()
        with (
            patch("app.database.create_agent_enrollment") as legacy_enrollment,
            patch(
                "app.database._refresh_authenticated_observation_agent"
            ) as refresh_identity,
            patch(
                "app.database.record_local_inventory_collection",
                return_value={
                    "collection_id": 7,
                    "normalized_asset_count": 1,
                    "duplicate": False,
                    "asset_ids": ["home-router"],
                },
            ) as record_local,
        ):
            persist_observation_batch(
                payload=payload,
                received_at=datetime.now(timezone.utc),
                source_authenticated=True,
            )

        legacy_enrollment.assert_not_called()
        self.assertEqual(refresh_identity.call_args.kwargs["agent_id"], "sensor-home")
        self.assertEqual(refresh_identity.call_args.kwargs["site_id"], "home")
        self.assertEqual(
            refresh_identity.call_args.kwargs["agent_type"], "network-sensor"
        )
        self.assertTrue(record_local.call_args.kwargs["source_authenticated"])


if __name__ == "__main__":
    unittest.main()
