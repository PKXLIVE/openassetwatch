"""Outcome metrics API: authorization, bounded parameters, errors, contracts."""

from __future__ import annotations

import os
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi import HTTPException
from sqlalchemy.exc import OperationalError

from app.main import api_metric, api_metric_catalog
from app.outcome_metrics import METRICS_BY_ID, MetricFilters, MetricInputs, compute_metric, resolve_window
from app.outcome_metrics_contracts import MetricCatalogResponse, MetricResultResponse
from app.outcome_metrics_store import MetricNotFound

TOKEN = "test-admin-token"
NOW = datetime(2026, 11, 20, tzinfo=timezone.utc)


def request(**params: str) -> SimpleNamespace:
    return SimpleNamespace(query_params=params)


def call(metric_id: str = "remediation.reports", token: str | None = TOKEN, query: dict | None = None, **kwargs):
    # Called directly, so every parameter is passed as FastAPI would.
    params = {"site_id": None, "start": None, "end": None, "action_band": None, "verification_state": None, **kwargs}
    return api_metric(request(**(query or {})), metric_id, admin_token=token, **params)


class OutcomeMetricsApiTests(unittest.TestCase):
    def setUp(self) -> None:
        environment = patch.dict(os.environ, {"OPENASSETWATCH_ADMIN_TOKEN": TOKEN})
        environment.start()
        self.addCleanup(environment.stop)
        self.store = Mock()
        store_patch = patch("app.main._outcome_metrics_store", return_value=self.store)
        store_patch.start()
        self.addCleanup(store_patch.stop)

    def test_every_route_fails_closed(self) -> None:
        for route in (lambda token: api_metric_catalog(admin_token=token), lambda token: call(token=token)):
            for token in (None, "wrong"):
                with self.assertRaises(HTTPException) as raised:
                    route(token)
                self.assertEqual(raised.exception.status_code, 401)
            with patch.dict(os.environ, {"OPENASSETWATCH_ADMIN_TOKEN": ""}):
                with self.assertRaises(HTTPException) as raised:
                    route(TOKEN)
                self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(self.store.method_calls, [])

    def test_catalog_matches_its_contract(self) -> None:
        catalog = MetricCatalogResponse.model_validate(api_metric_catalog(admin_token=TOKEN))
        self.assertEqual(len(catalog.metrics), len(METRICS_BY_ID))

    def test_filters_are_typed_and_forwarded(self) -> None:
        self.store.compute.return_value = {"ok": True}
        start, end = NOW - timedelta(days=7), NOW
        call("remediation.outcomes-by-state", site_id="site-a", start=start, end=end, verification_state="verified",
             query={"site_id": "site-a", "start": "x", "end": "y", "verification_state": "verified"})
        self.store.compute.assert_called_once_with(
            "remediation.outcomes-by-state", site_id="site-a", start=start, end=end, action_band=None,
            verification_state="verified",
        )

    def test_unknown_query_parameters_are_rejected(self) -> None:
        for query in ({"asset_id": "asset-a"}, {"sql": "select 1"}, {"site": "site-a"}):
            with self.subTest(query=query):
                with self.assertRaises(HTTPException) as raised:
                    call(query=query)
                self.assertEqual(raised.exception.status_code, 400)
        self.assertEqual(self.store.method_calls, [])

    def test_errors_are_mapped_without_leaking_details(self) -> None:
        self.store.compute.side_effect = MetricNotFound("remediation.unknown")
        with self.assertRaises(HTTPException) as raised:
            call("remediation.unknown")
        self.assertEqual(raised.exception.status_code, 404)
        self.store.compute.side_effect = ValueError("time window must not exceed 366 days")
        with self.assertRaises(HTTPException) as raised:
            call()
        self.assertEqual((raised.exception.status_code, raised.exception.detail),
                         (400, "time window must not exceed 366 days"))
        self.store.compute.side_effect = OperationalError("SELECT secret", {}, Exception("host db01"))
        with self.assertRaises(HTTPException) as raised:
            call()
        self.assertEqual((raised.exception.status_code, raised.exception.detail), (500, "failed to compute metric"))

    def test_every_metric_result_shape_matches_the_contract(self) -> None:
        for definition in METRICS_BY_ID.values():
            with self.subTest(metric=definition.metric_id):
                window = resolve_window(definition, start=None, end=None, now=NOW)
                value = compute_metric(definition, window=window, filters=MetricFilters(), now=NOW,
                                       inputs=MetricInputs(recording_since={key: NOW - timedelta(days=90) for key in (
                                           "work-events", "decision-history", "verification-history",
                                           "verification-runs")}))
                payload = {
                    "catalog_version": "oaw.metrics.catalog.v1", "metric_id": definition.metric_id,
                    "metric_version": definition.version, "display_name": definition.display_name,
                    "unit": definition.unit, "value_kind": definition.value_kind,
                    "counting_grain": definition.counting_grain, "population": definition.population,
                    "numerator_definition": definition.numerator, "denominator_definition": definition.denominator,
                    "time_semantics": definition.time_semantics,
                    "time_range": {"start": window.start, "end": window.end},
                    "filters": {"site_id": None, "action_band": None, "verification_state": None},
                    **value,
                    "source_freshness": [{"source": "finding-evaluation", "latest_record_at": None}],
                    "limitations": list(definition.limitations), "computed_at": NOW,
                }
                MetricResultResponse.model_validate(payload)


if __name__ == "__main__":
    unittest.main()
