from __future__ import annotations

import inspect
import os
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError

from app.main import (
    api_temporal_expectation,
    api_temporal_metrics,
    api_temporal_signals,
)
from app.temporal_projection import TemporalProjectionError, TemporalSiteNotFound


START = datetime(2026, 8, 1, tzinfo=timezone.utc)
END = datetime(2026, 8, 31, tzinfo=timezone.utc)


class TemporalApiTests(unittest.TestCase):
    def setUp(self) -> None:
        environment = patch.dict(
            os.environ,
            {"OPENASSETWATCH_ADMIN_TOKEN": "test-admin-token"},
        )
        environment.start()
        self.addCleanup(environment.stop)

    def test_registry_and_series_require_configured_admin_authentication(self) -> None:
        calls = (
            lambda: api_temporal_metrics(admin_token=None),
            lambda: api_temporal_signals(
                metric_key="site.assets.new.count",
                site_id="site-a",
                start=START,
                end=END,
                granularity="daily",
                asset_id=None,
                admin_token=None,
            ),
            lambda: api_temporal_expectation(
                metric_key="site.assets.new.count",
                site_id="site-a",
                target_start=END,
                granularity="daily",
                asset_id=None,
                admin_token=None,
            ),
        )
        for call in calls:
            with self.subTest(call=call):
                with self.assertRaises(HTTPException) as raised:
                    call()
                self.assertEqual(raised.exception.status_code, 401)

        with patch.dict(os.environ, {"OPENASSETWATCH_ADMIN_TOKEN": ""}):
            with self.assertRaises(HTTPException) as raised:
                api_temporal_metrics(admin_token=None)
        self.assertEqual(raised.exception.status_code, 503)

    def test_registry_exposes_only_the_governed_metrics(self) -> None:
        response = api_temporal_metrics(admin_token="test-admin-token")
        self.assertEqual(response["schema_version"], "oaw.temporal-metric-registry.v1")
        self.assertEqual(len(response["metrics"]), 6)
        self.assertEqual(
            len({metric["metric_key"] for metric in response["metrics"]}),
            6,
        )

    def test_series_forwards_exact_site_scope_and_bounded_parameters(self) -> None:
        service = Mock()
        service.series.return_value = {"schema_version": "oaw.temporal-series.v1"}
        with patch("app.main._temporal_service", return_value=service):
            response = api_temporal_signals(
                metric_key="site.assets.new.count",
                site_id="site-a",
                start=START,
                end=END,
                granularity="daily",
                asset_id=None,
                admin_token="test-admin-token",
            )

        self.assertEqual(response["schema_version"], "oaw.temporal-series.v1")
        self.assertEqual(service.series.call_args.kwargs["site_id"], "site-a")
        self.assertEqual(service.series.call_args.kwargs["metric_key"], "site.assets.new.count")
        self.assertEqual(service.series.call_args.kwargs["start"], START)
        self.assertEqual(service.series.call_args.kwargs["end"], END)
        self.assertIsNone(service.series.call_args.kwargs["asset_id"])

    def test_projection_rejections_are_bounded_api_errors(self) -> None:
        cases = (
            (TemporalProjectionError("unknown-metric", "unknown temporal metric"), 400),
            (TemporalProjectionError("window-too-large", "history is bounded"), 400),
            (TemporalSiteNotFound(), 404),
        )
        for error, status in cases:
            service = Mock()
            service.series.side_effect = error
            with self.subTest(error=error):
                with patch("app.main._temporal_service", return_value=service):
                    with self.assertRaises(HTTPException) as raised:
                        api_temporal_signals(
                            metric_key="site.assets.new.count",
                            site_id="site-a",
                            start=START,
                            end=END,
                            granularity="daily",
                            asset_id=None,
                            admin_token="test-admin-token",
                        )
                self.assertEqual(raised.exception.status_code, status)

    def test_expectation_forwards_only_governed_scope_and_target(self) -> None:
        service = Mock()
        service.expectation.return_value = {
            "schema_version": "oaw.temporal-expectation.v1"
        }
        with patch("app.main._temporal_expectation_service", return_value=service):
            response = api_temporal_expectation(
                metric_key="site.assets.new.count",
                site_id="site-a",
                target_start=END,
                granularity="daily",
                asset_id=None,
                admin_token="test-admin-token",
            )

        self.assertEqual(response["schema_version"], "oaw.temporal-expectation.v1")
        self.assertEqual(service.expectation.call_args.kwargs["site_id"], "site-a")
        self.assertEqual(
            service.expectation.call_args.kwargs["metric_key"],
            "site.assets.new.count",
        )
        self.assertEqual(service.expectation.call_args.kwargs["target_start"], END)
        self.assertIsNone(service.expectation.call_args.kwargs["asset_id"])

    def test_expectation_errors_are_bounded_and_database_details_are_hidden(self) -> None:
        cases = (
            (TemporalProjectionError("future-target", "future target"), 400),
            (TemporalSiteNotFound(), 404),
            (SQLAlchemyError("password=secret host=private"), 500),
        )
        for error, status in cases:
            service = Mock()
            service.expectation.side_effect = error
            with self.subTest(error=error):
                with patch(
                    "app.main._temporal_expectation_service",
                    return_value=service,
                ):
                    with self.assertRaises(HTTPException) as raised:
                        api_temporal_expectation(
                            metric_key="site.assets.new.count",
                            site_id="site-a",
                            target_start=END,
                            granularity="daily",
                            asset_id=None,
                            admin_token="test-admin-token",
                        )
                self.assertEqual(raised.exception.status_code, status)
                if status == 500:
                    self.assertNotIn("secret", str(raised.exception.detail))
                    self.assertNotIn("private", str(raised.exception.detail))

    def test_database_failures_do_not_expose_driver_details(self) -> None:
        service = Mock()
        service.series.side_effect = SQLAlchemyError("password=secret host=private")
        with patch("app.main._temporal_service", return_value=service):
            with self.assertRaises(HTTPException) as raised:
                api_temporal_signals(
                    metric_key="site.assets.new.count",
                    site_id="site-a",
                    start=START,
                    end=END,
                    granularity="daily",
                    asset_id=None,
                    admin_token="test-admin-token",
                )
        self.assertEqual(raised.exception.status_code, 500)
        self.assertNotIn("secret", str(raised.exception.detail))
        self.assertNotIn("private", str(raised.exception.detail))

    def test_api_does_not_accept_tenant_or_arbitrary_aggregation_parameters(self) -> None:
        parameters = inspect.signature(api_temporal_signals).parameters
        self.assertNotIn("tenant_id", parameters)
        self.assertNotIn("group_by", parameters)
        self.assertNotIn("aggregation", parameters)
        self.assertIn("site_id", parameters)
        expectation_parameters = inspect.signature(api_temporal_expectation).parameters
        self.assertNotIn("tenant_id", expectation_parameters)
        self.assertNotIn("method", expectation_parameters)
        self.assertNotIn("history_days", expectation_parameters)
        self.assertIn("site_id", expectation_parameters)


if __name__ == "__main__":
    unittest.main()
