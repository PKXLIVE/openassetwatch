from __future__ import annotations

import os
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from fastapi import HTTPException

from app.classification_contracts import (
    ClassificationEvaluateRequest,
    ClassificationEvaluationResponse,
    ClassificationListResponse,
    ClassificationResponse,
)
from app.classification_service import ClassificationEvaluationResult
from app.main import (
    _FullClassificationLimiter,
    admin_evaluate_classifications,
    api_asset_classification,
    api_asset_classification_evidence,
    api_classifications,
    api_vendor_catalog_status,
)


NOW = datetime(2026, 7, 30, 18, 0, tzinfo=timezone.utc)


def classification() -> dict:
    return {
        "classification_id": "cls_" + "a" * 32,
        "asset_id": "asset-a",
        "site_id": "site-a",
        "classifier_version": "oaw.classifier.v1",
        "category": "server",
        "subtype": "application-server",
        "manufacturer": "Example Systems",
        "product_hint": None,
        "os_family": "Linux",
        "os_version_hint": "Demo",
        "managed_capability": {
            "endpoint_collector": "expected",
            "endpoint_security": "expected",
            "software_inventory": "expected",
            "patch_management": "expected",
        },
        "confidence": 0.93,
        "status": "classified",
        "supporting_evidence_ids": ["cev_" + "b" * 40],
        "conflicting_evidence_ids": [],
        "independent_source_count": 1,
        "evidence_count": 3,
        "first_classified_at": NOW,
        "last_classified_at": NOW,
        "evaluated_at": NOW,
        "superseded_at": None,
        "freshness": "fresh",
        "reason_codes": ["direct-category"],
        "conflicts": [],
    }


class ClassificationApiTests(unittest.TestCase):
    def test_list_filters_and_pagination_are_bounded_and_forwarded(self) -> None:
        page = {
            "items": [classification()],
            "total": 1,
            "limit": 25,
            "offset": 0,
            "truncated": False,
        }
        store = Mock()
        store.list_classifications.return_value = page
        with patch("app.main._classification_store", return_value=store):
            response = api_classifications(
                site_id="site-a",
                category="server",
                manufacturer="Example Systems",
                os_family="Linux",
                managed_capability="expected",
                status="classified",
                minimum_confidence=0.8,
                conflict_state="none",
                limit=25,
                offset=0,
                admin_token=None,
            )

        validated = ClassificationListResponse.model_validate(response)
        self.assertEqual(validated.items[0].category, "server")
        self.assertEqual(store.list_classifications.call_args.kwargs["site_id"], "site-a")
        self.assertEqual(store.list_classifications.call_args.kwargs["limit"], 25)

    def test_invalid_enum_filter_is_rejected_before_repository_use(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            api_classifications(
                site_id=None,
                category="server' OR 1=1 --",
                manufacturer=None,
                os_family=None,
                managed_capability=None,
                status=None,
                minimum_confidence=None,
                conflict_state=None,
                limit=50,
                offset=0,
                admin_token=None,
            )

        self.assertEqual(raised.exception.status_code, 400)

    def test_asset_and_evidence_reads_are_site_scoped(self) -> None:
        store = Mock()
        store.get_classification.return_value = classification()
        store.list_evidence.return_value = {
            "items": [
                {
                    "evidence_id": "cev_" + "b" * 40,
                    "site_id": "site-a",
                    "asset_id": "asset-a",
                    "source_id": "endpoint-a",
                    "source_type": "endpoint-collector",
                    "collection_method": "endpoint-inventory",
                    "kind": "category",
                    "value": "server",
                    "observed_at": NOW,
                    "first_seen_at": NOW,
                    "last_seen_at": NOW,
                    "direct": True,
                    "strength": "direct",
                    "source_confidence": 0.95,
                    "observation_count": 1,
                    "agreement_state": "supporting",
                    "classifier_used": True,
                    "source_revoked": False,
                }
            ],
            "total": 1,
            "limit": 10,
            "offset": 0,
            "truncated": False,
        }
        with patch("app.main._classification_store", return_value=store):
            item = api_asset_classification(
                asset_id="asset-a",
                site_id="site-a",
                admin_token=None,
            )
            evidence = api_asset_classification_evidence(
                asset_id="asset-a",
                site_id="site-a",
                limit=10,
                offset=0,
                admin_token=None,
            )

        self.assertEqual(ClassificationResponse.model_validate(item).asset_id, "asset-a")
        self.assertEqual(evidence["items"][0]["site_id"], "site-a")
        self.assertEqual(
            store.get_classification.call_args.kwargs,
            {"site_id": "site-a", "asset_id": "asset-a"},
        )
        self.assertEqual(store.list_evidence.call_args.kwargs["site_id"], "site-a")

    def test_configured_admin_token_is_required_for_evaluation(self) -> None:
        payload = ClassificationEvaluateRequest(
            requested_by="unit-test",
            site_id="site-a",
            asset_id="asset-a",
        )
        with patch.dict(
            os.environ,
            {"OPENASSETWATCH_ADMIN_TOKEN": "configured-admin-value"},
            clear=False,
        ):
            with self.assertRaises(HTTPException) as raised:
                admin_evaluate_classifications(payload, admin_token=None)

        self.assertEqual(raised.exception.status_code, 401)

    def test_targeted_admin_evaluation_returns_bounded_metadata(self) -> None:
        payload = ClassificationEvaluateRequest(
            requested_by="unit-test",
            site_id="site-a",
            asset_id="asset-a",
        )
        result = ClassificationEvaluationResult(
            run_id="crun_" + "c" * 32,
            trigger_type="admin-request",
            scope_site_id="site-a",
            scope_asset_ids=("asset-a",),
            classifier_version="oaw.classifier.v1",
            status="completed",
            assets_evaluated=1,
            assets_changed=1,
            conflicts_found=0,
            finding_evaluations=1,
            started_at=NOW,
            completed_at=NOW,
            bounded_errors=(),
        )
        with (
            patch.dict(
                os.environ,
                {"OPENASSETWATCH_ADMIN_TOKEN": "configured-admin-value"},
                clear=False,
            ),
            patch(
                "app.main.evaluate_classifications",
                return_value=result,
            ) as evaluate,
        ):
            response = admin_evaluate_classifications(
                payload,
                admin_token="configured-admin-value",
            )

        validated = ClassificationEvaluationResponse.model_validate(response)
        self.assertEqual(validated.assets_changed, 1)
        self.assertEqual(evaluate.call_args.kwargs["asset_id"], "asset-a")

    def test_full_rebuild_limiter_rejects_repeat(self) -> None:
        limiter = _FullClassificationLimiter(cooldown_seconds=60)

        self.assertTrue(limiter.allow(now=100.0))
        self.assertFalse(limiter.allow(now=101.0))
        self.assertTrue(limiter.allow(now=161.0))

    def test_catalog_status_is_local_and_has_no_network_lookup(self) -> None:
        response = api_vendor_catalog_status(admin_token=None)

        self.assertTrue(response["available"])
        self.assertFalse(response["network_lookup"])
        self.assertEqual(response["status"], "ready")
        self.assertEqual(response["source_license"], "synthetic-test-data")


if __name__ == "__main__":
    unittest.main()
