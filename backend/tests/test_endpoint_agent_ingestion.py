from __future__ import annotations

import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from app.database import (
    EndpointInventoryAuthorizationRejected,
    EndpointInventoryRateLimitExceeded,
    EndpointInventoryReplayConflict,
    MAX_ENDPOINT_INVENTORY_BATCHES_PER_WINDOW,
    record_authenticated_endpoint_inventory,
)


class _Begin:
    def __init__(self, connection: Mock) -> None:
        self.connection = connection

    def __enter__(self) -> Mock:
        return self.connection

    def __exit__(self, *_args: object) -> None:
        return None


def _scalar(value: object) -> Mock:
    result = Mock()
    result.scalar_one_or_none.return_value = value
    return result


def _scalar_one(value: object) -> Mock:
    result = Mock()
    result.scalar_one.return_value = value
    return result


def _row(value: dict[str, object]) -> Mock:
    result = Mock()
    result.mappings.return_value.one.return_value = value
    result.mappings.return_value.one_or_none.return_value = value
    return result


def _no_row() -> Mock:
    result = Mock()
    result.mappings.return_value.one_or_none.return_value = None
    return result


def _payload() -> dict[str, object]:
    return {
        "schema_version": "oaw.endpoint-inventory.v1",
        "observation_batch_id": "batch_0123456789abcdef",
        "observed_at": "2026-08-20T12:00:00+00:00",
        "collected_at": "2026-08-20T12:00:00+00:00",
        "inventory_mode": "complete",
        "site_id": "site-a",
        "agent_id": "agent_" + "1" * 32,
        "sensor_type": "endpoint-agent",
        "observation_source": "endpoint-inventory",
        "component_inventory_complete": True,
        "assets": [{"asset_id": "host-a", "components": []}],
    }


class EndpointAgentIngestionTests(unittest.TestCase):
    def test_identical_replay_returns_original_storage_identity_without_evidence_write(self) -> None:
        received_at = datetime(2026, 8, 20, 12, 1, tzinfo=timezone.utc)
        connection = Mock()
        connection.execute.side_effect = [
            _scalar(1),
            _row(
                {
                    "storage_id": 7,
                    "payload_sha256": "a" * 64,
                    "collection_id": 8,
                    "observed_asset_count": 1,
                    "normalized_asset_count": 1,
                    "component_count": 0,
                    "reevaluation_state": "completed",
                    "received_at": received_at,
                }
            ),
        ]
        engine = Mock()
        engine.begin.return_value = _Begin(connection)
        with (
            patch("app.database.ensure_site_record"),
            patch("app.database.normalize_local_inventory_assets", return_value=[]),
            patch("app.database.get_engine", return_value=engine),
            patch("app.database._persist_classification_evidence_best_effort") as classification,
            patch("app.database._persist_component_inventory_best_effort") as components,
        ):
            result = record_authenticated_endpoint_inventory(
                payload=_payload(), payload_sha256="a" * 64,
                site_id="site-a", agent_id="agent_" + "1" * 32,
                credential_id="acred_" + "2" * 32,
                inventory_batch_id="batch_0123456789abcdef",
                inventory_mode="complete",
                observed_at=received_at, received_at=received_at,
            )
        self.assertTrue(result["duplicate"])
        self.assertEqual(result["storage_id"], 7)
        self.assertEqual(result["collection_id"], 8)
        classification.assert_not_called()
        components.assert_not_called()

    def test_conflicting_replay_fails_closed(self) -> None:
        received_at = datetime(2026, 8, 20, 12, 1, tzinfo=timezone.utc)
        connection = Mock()
        connection.execute.side_effect = [
            _scalar(1),
            _row(
                {
                    "storage_id": 7,
                    "payload_sha256": "b" * 64,
                    "collection_id": 8,
                    "observed_asset_count": 1,
                    "normalized_asset_count": 1,
                    "component_count": 0,
                    "reevaluation_state": "queued",
                    "received_at": received_at,
                }
            ),
        ]
        engine = Mock()
        engine.begin.return_value = _Begin(connection)
        with (
            patch("app.database.ensure_site_record"),
            patch("app.database.normalize_local_inventory_assets", return_value=[]),
            patch("app.database.get_engine", return_value=engine),
            self.assertRaises(EndpointInventoryReplayConflict),
        ):
            record_authenticated_endpoint_inventory(
                payload=_payload(), payload_sha256="a" * 64,
                site_id="site-a", agent_id="agent_" + "1" * 32,
                credential_id="acred_" + "2" * 32,
                inventory_batch_id="batch_0123456789abcdef",
                inventory_mode="complete",
                observed_at=received_at, received_at=received_at,
            )

    def test_inactive_credential_is_rejected_again_at_persistence_boundary(self) -> None:
        received_at = datetime(2026, 8, 20, 12, 1, tzinfo=timezone.utc)
        connection = Mock()
        connection.execute.side_effect = [_scalar(None)]
        engine = Mock()
        engine.begin.return_value = _Begin(connection)
        with (
            patch("app.database.ensure_site_record"),
            patch("app.database.normalize_local_inventory_assets") as normalize,
            patch("app.database.get_engine", return_value=engine),
            self.assertRaises(EndpointInventoryAuthorizationRejected),
        ):
            record_authenticated_endpoint_inventory(
                payload=_payload(), payload_sha256="a" * 64,
                site_id="site-a", agent_id="agent_" + "1" * 32,
                credential_id="acred_" + "2" * 32,
                inventory_batch_id="batch_0123456789abcdef",
                inventory_mode="complete",
                observed_at=received_at, received_at=received_at,
            )
        normalize.assert_not_called()

    def test_new_batch_uses_separate_collection_dedupe_namespace(self) -> None:
        received_at = datetime(2026, 8, 20, 12, 1, tzinfo=timezone.utc)
        connection = Mock()
        connection.execute.side_effect = [
            _scalar(1),
            _no_row(),
            _scalar_one(0),
            _scalar_one(7),
            Mock(),
            Mock(),
        ]
        engine = Mock()
        engine.begin.return_value = _Begin(connection)
        with (
            patch("app.database.ensure_site_record"),
            patch(
                "app.database.normalize_local_inventory_assets",
                return_value=[{"asset_id": "host-a"}],
            ),
            patch("app.database.get_engine", return_value=engine),
            patch(
                "app.database._store_local_inventory_collection",
                return_value={
                    "collection_id": 8,
                    "normalized_asset_count": 1,
                    "duplicate": False,
                    "asset_ids": ["host-a"],
                },
            ) as store_collection,
            patch("app.database._persist_classification_evidence_best_effort"),
            patch("app.database._persist_component_inventory_best_effort"),
        ):
            result = record_authenticated_endpoint_inventory(
                payload=_payload(), payload_sha256="a" * 64,
                site_id="site-a", agent_id="agent_" + "1" * 32,
                credential_id="acred_" + "2" * 32,
                inventory_batch_id="batch_0123456789abcdef",
                inventory_mode="complete",
                observed_at=received_at, received_at=received_at,
            )
        self.assertFalse(result["duplicate"])
        self.assertFalse(store_collection.call_args.kwargs["deduplicate"])

    def test_new_batch_rate_limit_is_persistent_and_precedes_normalization(self) -> None:
        received_at = datetime(2026, 8, 20, 12, 1, tzinfo=timezone.utc)
        connection = Mock()
        connection.execute.side_effect = [
            _scalar(1),
            _no_row(),
            _scalar_one(MAX_ENDPOINT_INVENTORY_BATCHES_PER_WINDOW),
        ]
        engine = Mock()
        engine.begin.return_value = _Begin(connection)
        with (
            patch("app.database.ensure_site_record"),
            patch("app.database.normalize_local_inventory_assets") as normalize,
            patch("app.database.get_engine", return_value=engine),
            self.assertRaises(EndpointInventoryRateLimitExceeded),
        ):
            record_authenticated_endpoint_inventory(
                payload=_payload(), payload_sha256="a" * 64,
                site_id="site-a", agent_id="agent_" + "1" * 32,
                credential_id="acred_" + "2" * 32,
                inventory_batch_id="batch_new_0123456789",
                inventory_mode="complete",
                observed_at=received_at, received_at=received_at,
            )
        normalize.assert_not_called()


if __name__ == "__main__":
    unittest.main()
