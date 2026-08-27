from __future__ import annotations

import unittest
import math
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import BackgroundTasks, HTTPException

from app.canonical_ingestion import (
    CanonicalIngestionRejected,
    endpoint_envelope,
    sensor_envelope,
    transitional_envelope,
)
from app.canonical_ingestion_store import should_replace_asset_authority
from app.endpoint_agent_contracts import (
    EndpointInventoryRequest,
    EndpointInventoryResponse,
)
from app.hub_contracts import ObservationBatchRequest
from app.ai_advisor import ReadOnlyHubTools
from app import main


NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)


def _endpoint_payload() -> EndpointInventoryRequest:
    return EndpointInventoryRequest.model_validate(
        {
            "schema_version": "oaw.endpoint-inventory.v1",
            "inventory_batch_id": "batch-0001",
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "inventory_mode": "complete",
            "assets": [
                {
                    "asset_id": "endpoint-a",
                    "hostname": "endpoint-a.example.test",
                    "os": "linux",
                    "platform": "linux",
                    "interfaces": [],
                    "evidence": [
                        {
                            "kind": "hostname",
                            "value": "endpoint-a.example.test",
                        }
                    ],
                    "components": [],
                }
            ],
        }
    )


class CanonicalEnvelopeTests(unittest.TestCase):
    def test_endpoint_authority_is_derived_from_bound_context(self) -> None:
        context = SimpleNamespace(
            site_id="site-a",
            agent_id="agent_" + "1" * 32,
            deployment_id="deployment-a",
            credential_id="acred_" + "2" * 32,
        )
        envelope = endpoint_envelope(
            payload=_endpoint_payload(),
            context=context,
            received_at=datetime.now(timezone.utc),
        )

        self.assertEqual(envelope.site_id, "site-a")
        self.assertEqual(envelope.source_authority, "authenticated-endpoint")
        self.assertEqual(envelope.trust_rank, 90)
        self.assertTrue(envelope.source_authenticated)
        self.assertRegex(envelope.canonical_collection_id, r"^col_[0-9a-f]{32}$")

    def test_source_identity_is_bound_to_adapter_and_authentication_domain(self) -> None:
        payload = ObservationBatchRequest.model_validate(
            {
                "schema_version": "oaw.observation-batch.v1",
                "observation_batch_id": "batch-0001",
                "site_id": "site-a",
                "sensor_id": "sensor-a",
                "sensor_name": "Fictional Sensor",
                "sensor_type": "passive-network-sensor",
                "observed_at": NOW.isoformat(),
                "observation_source": "passive-network",
                "assets": [],
            }
        )
        bound = sensor_envelope(
            payload=payload,
            context=SimpleNamespace(
                mode="bound-sensor",
                site_id="site-a",
                sensor_id="sensor-a",
                credential_id="scred_" + "1" * 32,
            ),
            received_at=NOW,
        )
        shared = sensor_envelope(
            payload=payload,
            context=SimpleNamespace(mode="development-shared"),
            received_at=NOW,
        )

        self.assertNotEqual(bound.source_id, shared.source_id)
        self.assertEqual(bound.source_authority, "authenticated-passive-sensor")
        self.assertEqual(shared.source_authority, "untrusted-transitional")
        self.assertNotEqual(shared.source_identity, payload.sensor_id)

    def test_transitional_adapter_strips_nested_authority_fields(self) -> None:
        envelope = transitional_envelope(
            payload={
                "site_id": "site-a",
                "source_authority": "authenticated-endpoint",
                "assets": [
                    {
                        "asset_id": "asset-a",
                        "hostname": "untrusted.example.test",
                        "metadata": {"trust_rank": 100},
                    }
                ],
            },
            received_at=NOW,
        )

        self.assertEqual(envelope.source_authority, "untrusted-transitional")
        self.assertEqual(envelope.trust_rank, 10)
        self.assertNotIn("trust_rank", envelope.assets[0].metadata.get("metadata", {}))

    def test_transitional_adapter_rejects_deep_payloads(self) -> None:
        nested: dict[str, object] = {}
        cursor = nested
        for _ in range(12):
            child: dict[str, object] = {}
            cursor["child"] = child
            cursor = child
        with self.assertRaises(CanonicalIngestionRejected):
            transitional_envelope(
                payload={"site_id": "site-a", "assets": [{"asset_id": "a", "metadata": nested}]},
                received_at=NOW,
            )

    def test_transitional_adapter_rejects_nonfinite_numbers(self) -> None:
        with self.assertRaises(CanonicalIngestionRejected):
            transitional_envelope(
                payload={
                    "site_id": "site-a",
                    "assets": [
                        {
                            "asset_id": "asset-a",
                            "metadata": {"confidence": math.nan},
                        }
                    ],
                },
                received_at=NOW,
            )


class AssetAuthorityDecisionTests(unittest.TestCase):
    def test_lower_trust_never_replaces_higher_trust(self) -> None:
        self.assertFalse(
            should_replace_asset_authority(
                current_trust_rank=90,
                current_observed_at=NOW,
                incoming_trust_rank=10,
                incoming_observed_at=NOW + timedelta(days=1),
            )
        )

    def test_newer_equal_trust_replaces_and_older_equal_trust_does_not(self) -> None:
        self.assertTrue(
            should_replace_asset_authority(
                current_trust_rank=75,
                current_observed_at=NOW,
                incoming_trust_rank=75,
                incoming_observed_at=NOW + timedelta(seconds=1),
            )
        )
        self.assertFalse(
            should_replace_asset_authority(
                current_trust_rank=75,
                current_observed_at=NOW,
                incoming_trust_rank=75,
                incoming_observed_at=NOW - timedelta(seconds=1),
            )
        )


class CanonicalEvaluationTests(unittest.TestCase):
    def test_queue_coalesces_collection_and_deduplicates_assets(self) -> None:
        tasks = BackgroundTasks()
        with patch.object(main, "_canonical_evaluations_pending", set()):
            first = main._queue_canonical_evaluation(
                tasks,
                canonical_collection_id="col_" + "7" * 32,
                has_work=True,
            )
            second = main._queue_canonical_evaluation(
                tasks,
                canonical_collection_id="col_" + "7" * 32,
                has_work=True,
            )

        self.assertEqual(first, "queued")
        self.assertEqual(second, "queued")
        self.assertEqual(len(tasks.tasks), 1)
        self.assertEqual(
            tasks.tasks[0].kwargs,
            {"canonical_collection_id": "col_" + "7" * 32},
        )

    def test_queue_capacity_records_retryable_state_without_raising(self) -> None:
        tasks = BackgroundTasks()
        with (
            patch.object(main, "_canonical_evaluations_pending", set()),
            patch.object(main, "MAX_PENDING_CANONICAL_EVALUATIONS", 0),
            patch.object(main, "set_canonical_evaluation_state") as set_state,
        ):
            queued = main._queue_canonical_evaluation(
                tasks,
                canonical_collection_id="col_" + "8" * 32,
                has_work=True,
            )

        self.assertEqual(queued, "retryable-failure")
        self.assertEqual(tasks.tasks, [])
        set_state.assert_called_once_with(
            canonical_collection_id="col_" + "8" * 32,
            state="retryable-failure",
            error_code="reevaluation-queue-capacity",
        )

    def test_evaluation_is_targeted_and_state_is_separate_from_acceptance(self) -> None:
        with (
            patch.object(
                main,
                "claim_canonical_evaluation_work",
                return_value={
                    "site_id": "site-a",
                    "asset_ids": ["asset-a", "asset-b"],
                    "normalized_assets": [],
                    "payload": {},
                    "received_at": NOW,
                    "source_authenticated": True,
                },
            ),
            patch.object(
                main.database_module,
                "_persist_classification_evidence_best_effort",
                return_value=True,
            ),
            patch.object(
                main.database_module,
                "_persist_component_inventory_best_effort",
                return_value=True,
            ),
            patch.object(main, "set_canonical_evaluation_state") as set_state,
            patch.object(main, "evaluate_classifications") as classifications,
            patch.object(main, "evaluate_vulnerabilities") as vulnerabilities,
            patch.object(main, "evaluate_findings") as findings,
        ):
            main._run_canonical_inventory_evaluation(
                canonical_collection_id="col_" + "9" * 32,
            )

        self.assertEqual(
            [call.kwargs["state"] for call in set_state.call_args_list],
            ["completed"],
        )
        classifications.assert_called_once_with(
            trigger_type="canonical-inventory",
            requested_by="canonical-ingestion",
            site_id="site-a",
            asset_ids=["asset-a", "asset-b"],
            reevaluate_findings=False,
        )
        self.assertEqual(
            [call.kwargs["asset_id"] for call in vulnerabilities.call_args_list],
            ["asset-a", "asset-b"],
        )
        self.assertEqual(
            [call.kwargs["asset_id"] for call in findings.call_args_list],
            ["asset-a", "asset-b"],
        )


class CanonicalStatusTests(unittest.TestCase):
    def test_endpoint_acknowledgement_allows_no_authoritative_work(self) -> None:
        response = EndpointInventoryResponse.model_validate(
            {
                "status": "accepted",
                "inventory_batch_id": "canonical-no-op-batch-0001",
                "storage_id": 1,
                "collection_id": 2,
                "canonical_collection_id": "col_" + "4" * 32,
                "site_id": "site-a",
                "agent_id": "agent_" + "3" * 32,
                "credential_id": "acred_" + "2" * 32,
                "received_at": NOW,
                "observed_asset_count": 1,
                "normalized_asset_count": 1,
                "component_count": 0,
                "reevaluation_state": "not-required",
                "message": (
                    "authenticated endpoint inventory accepted; deterministic "
                    "reevaluation not-required"
                ),
            }
        )

        self.assertEqual(response.reevaluation_state, "not-required")

    def test_admin_status_route_preserves_authentication_and_bounded_limit(self) -> None:
        expected = {
            "schema_version": "oaw.ingestion-compatibility-status.v1",
            "routes": [],
        }
        with (
            patch.object(main, "require_admin_token") as require_admin,
            patch.object(
                main,
                "canonical_compatibility_status",
                return_value=expected,
            ) as status,
        ):
            response = main.api_ingestion_compatibility_status(
                limit=20,
                admin_token="configured-admin-token",
            )

        self.assertEqual(response, expected)
        require_admin.assert_called_once_with("configured-admin-token")
        status.assert_called_once_with(limit=20)

    def test_retry_route_requires_configured_admin_and_queues_only_requeued_work(self) -> None:
        collection_id = "col_" + "6" * 32
        tasks = BackgroundTasks()
        with (
            patch.object(main, "require_configured_admin_token") as require_admin,
            patch.object(
                main,
                "requeue_canonical_evaluation",
                return_value=True,
            ) as requeue,
            patch.object(
                main,
                "_queue_canonical_evaluation",
                return_value="queued",
            ) as queue,
        ):
            response = main.api_retry_canonical_ingestion_evaluation(
                background_tasks=tasks,
                canonical_collection_id=collection_id,
                admin_token="configured-admin-token",
            )

        self.assertEqual(response["evaluation_state"], "queued")
        require_admin.assert_called_once_with(
            "configured-admin-token",
            capability="canonical ingestion evaluation retry",
        )
        requeue.assert_called_once_with(canonical_collection_id=collection_id)
        queue.assert_called_once_with(
            tasks,
            canonical_collection_id=collection_id,
            has_work=True,
        )

    def test_retry_route_rejects_worker_finalization_race(self) -> None:
        collection_id = "col_" + "5" * 32
        with (
            patch.object(main, "require_configured_admin_token"),
            patch.object(
                main,
                "_canonical_evaluations_pending",
                {collection_id},
            ),
            patch.object(main, "requeue_canonical_evaluation") as requeue,
        ):
            with self.assertRaises(HTTPException) as context:
                main.api_retry_canonical_ingestion_evaluation(
                    background_tasks=BackgroundTasks(),
                    canonical_collection_id=collection_id,
                    admin_token="configured-admin-token",
                )

        self.assertEqual(context.exception.status_code, 409)
        self.assertEqual(
            context.exception.detail,
            "canonical evaluation is still finalizing",
        )
        requeue.assert_not_called()

    def test_asset_ui_labels_canonical_authority_and_compatibility(self) -> None:
        repository = Path(__file__).parents[2]
        dashboard = (repository / "backend" / "app" / "static" / "index.html").read_text(
            encoding="utf-8"
        )

        self.assertIn("Canonical collection", dashboard)
        self.assertIn("Source authority", dashboard)
        self.assertIn("Ingestion adapter", dashboard)
        self.assertIn("Compatibility status", dashboard)
        self.assertIn("/api/v1/admin/ingestion/compatibility-status", dashboard)
        self.assertIn("selectAsset(asset.asset_key)", dashboard)
        self.assertIn("asset_key: asset.asset_key", dashboard)
        self.assertIn("value.asset_key === item.asset_key", dashboard)
        self.assertIn("item.asset_id === assetId", dashboard)
        self.assertIn("matches.length !== 1", dashboard)
        self.assertNotIn("selectAsset(asset.asset_id)", dashboard)

        preview = (
            repository / "scripts" / "preview_canonical_ingestion_compatibility.py"
        ).read_text(encoding="utf-8")
        self.assertIn("SET TRANSACTION READ ONLY", preview)
        self.assertIn('"mutation_performed": False', preview)
        for statement in (
            "INSERT INTO",
            "UPDATE collector_inventory_submissions",
            "DELETE FROM",
            "ALTER TABLE",
            "DROP TABLE",
        ):
            self.assertNotIn(statement, preview.upper())

        demo = (
            repository / "scripts" / "demo_canonical_ingestion_compatibility.py"
        ).read_text(encoding="utf-8")
        self.assertIn("openassetwatch_canonical_demo_", demo)
        self.assertIn("ai_canonical_evidence_ids", demo)
        self.assertNotIn("print(database_url", demo)

    def test_ai_evidence_uses_only_persisted_canonical_collection_ids(self) -> None:
        collection_id = "col_" + "a" * 32
        tools = ReadOnlyHubTools(
            sites=[{"site_id": "site-a", "name": "Site A"}],
            sensors=[],
            assets=[
                {
                    "asset_id": "asset-a",
                    "site_id": "site-a",
                    "hostname": "asset-a.example.test",
                    "canonical_collection_id": collection_id,
                    "source_authority": "authenticated-endpoint",
                    "ingestion_adapter_type": "endpoint-agent",
                    "compatibility_status": "canonical",
                    "observed_at": NOW,
                },
                {
                    "asset_id": "asset-b",
                    "site_id": "site-a",
                    "hostname": "asset-b.example.test",
                    "canonical_collection_id": "client-fabricated-id",
                    "source_authority": "authenticated-endpoint",
                    "ingestion_adapter_type": "endpoint-agent",
                    "compatibility_status": "canonical",
                    "observed_at": NOW,
                },
            ],
            findings=[],
            now=NOW,
        )

        catalog = tools.evidence_catalog(site_id="site-a")
        canonical = [
            item for item in catalog
            if item.evidence_type == "canonical_inventory_collection"
        ]
        projected = tools.run(
            "asset_evidence",
            site_id="site-a",
            asset_id="asset-a",
        )["items"][0]

        self.assertEqual([item.evidence_id for item in canonical], [collection_id])
        self.assertEqual(canonical[0].authority, "normalized-evidence")
        self.assertEqual(projected["source_authority"], "authenticated-endpoint")

if __name__ == "__main__":
    unittest.main()
