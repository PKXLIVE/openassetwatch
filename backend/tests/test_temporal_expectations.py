from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from pydantic import ValidationError

from app.temporal_contracts import TEMPORAL_EXPECTATION_HISTORY_BUCKETS
from app.temporal_expectations import (
    TemporalExpectationService,
    robust_expected_range,
    temporal_expectation_id,
)
from app.temporal_projection import (
    ProjectionAggregate,
    TemporalProjectionError,
    TemporalProjectionService,
)


UTC = timezone.utc
TARGET = datetime(2026, 8, 28, tzinfo=UTC)
HISTORY_START = TARGET - timedelta(days=TEMPORAL_EXPECTATION_HISTORY_BUCKETS)


class FakeTemporalStore:
    def __init__(self, buckets=None) -> None:
        self.buckets = dict(buckets or {})
        self.calls: list[dict[str, object]] = []

    def metric_buckets(self, **kwargs):
        self.calls.append(kwargs)
        return dict(self.buckets)


def observed(value: int, bucket_start: datetime) -> ProjectionAggregate:
    return ProjectionAggregate(
        value=value,
        evidence_count=max(1, value),
        source_observed_at=bucket_start + timedelta(hours=23),
        source_received_at=bucket_start + timedelta(hours=23, minutes=30),
        complete=True,
    )


def history_with_values(values: list[int]) -> dict[datetime, ProjectionAggregate]:
    return {
        HISTORY_START + timedelta(days=index): observed(
            value,
            HISTORY_START + timedelta(days=index),
        )
        for index, value in enumerate(values)
    }


class TemporalExpectedRangeTests(unittest.TestCase):
    def test_robust_range_uses_median_and_resists_one_large_spike(self) -> None:
        expected, lower, upper = robust_expected_range([10] * 27 + [1000])
        self.assertEqual((expected, lower, upper), (10.0, 10.0, 10.0))

    def test_rolling_expectation_is_deterministic_and_cutoff_safe(self) -> None:
        store = FakeTemporalStore(history_with_values([10] * 55 + [1000]))
        service = TemporalExpectationService.from_projection_store(store=store)

        first = service.expectation(
            metric_key="site.assets.new.count",
            site_id="site-a",
            target_start=TARGET,
            generated_at=TARGET + timedelta(hours=12),
        )
        second = service.expectation(
            metric_key="site.assets.new.count",
            site_id="site-a",
            target_start=TARGET,
            generated_at=TARGET + timedelta(hours=13),
        )

        self.assertEqual(first.method, "rolling_robust_baseline")
        self.assertEqual(first.method_sample_count, 28)
        self.assertEqual((first.expected, first.lower, first.upper), (10.0, 10.0, 10.0))
        self.assertEqual(first.confidence, "high")
        self.assertEqual(first.data_quality, "sufficient")
        self.assertEqual(first.expectation_id, second.expectation_id)
        self.assertEqual(first.expected, second.expected)
        self.assertNotEqual(first.generated_at, second.generated_at)
        for call in store.calls:
            self.assertEqual(call["end"], TARGET)
            self.assertEqual(call["knowledge_cutoff"], TARGET)

    def test_seasonal_policy_uses_only_matching_weekdays(self) -> None:
        values = []
        seasonal_values = [4, 6, 4, 6, 4, 6, 4, 6]
        seasonal_index = 0
        for index in range(TEMPORAL_EXPECTATION_HISTORY_BUCKETS):
            bucket = HISTORY_START + timedelta(days=index)
            if bucket.weekday() == TARGET.weekday():
                values.append(seasonal_values[seasonal_index])
                seasonal_index += 1
            else:
                values.append(100)
        service = TemporalExpectationService.from_projection_store(
            store=FakeTemporalStore(history_with_values(values))
        )

        result = service.expectation(
            metric_key="site.collectors.active.count",
            site_id="site-a",
            target_start=TARGET,
            generated_at=TARGET + timedelta(hours=12),
        )

        self.assertEqual(result.method, "seasonal_robust_baseline")
        self.assertEqual(result.method_sample_count, 8)
        self.assertEqual(result.expected, 5.0)
        self.assertLess(result.lower, result.expected)
        self.assertGreater(result.upper, result.expected)

    def test_seasonal_policy_falls_back_to_rolling_when_seasonal_history_is_sparse(self) -> None:
        buckets = history_with_values([8] * TEMPORAL_EXPECTATION_HISTORY_BUCKETS)
        matching = [
            bucket for bucket in sorted(buckets) if bucket.weekday() == TARGET.weekday()
        ]
        for bucket in matching[:-3]:
            del buckets[bucket]
        result = TemporalExpectationService.from_projection_store(
            store=FakeTemporalStore(buckets)
        ).expectation(
            metric_key="site.inventory.collections.count",
            site_id="site-a",
            target_start=TARGET,
            generated_at=TARGET + timedelta(hours=12),
        )

        self.assertEqual(result.method, "rolling_robust_baseline")
        self.assertGreaterEqual(result.method_sample_count, 7)
        self.assertEqual(result.expected, 8.0)

    def test_missing_incomplete_and_stale_history_are_excluded_not_zeroed(self) -> None:
        buckets: dict[datetime, ProjectionAggregate] = {}
        recent_start = TARGET - timedelta(days=7)
        for index in range(7):
            bucket = recent_start + timedelta(days=index)
            buckets[bucket] = observed(5, bucket)
        incomplete_bucket = HISTORY_START
        buckets[incomplete_bucket] = ProjectionAggregate(
            value=500,
            evidence_count=1,
            source_observed_at=incomplete_bucket + timedelta(hours=1),
            source_received_at=incomplete_bucket + timedelta(hours=2),
            complete=False,
        )
        stale_bucket = HISTORY_START + timedelta(days=1)
        buckets[stale_bucket] = ProjectionAggregate(
            value=500,
            evidence_count=1,
            source_observed_at=stale_bucket - timedelta(days=3),
            source_received_at=stale_bucket + timedelta(hours=2),
            complete=True,
        )
        result = TemporalExpectationService.from_projection_store(
            store=FakeTemporalStore(buckets)
        ).expectation(
            metric_key="site.assets.new.count",
            site_id="site-a",
            target_start=TARGET,
            generated_at=TARGET + timedelta(hours=12),
        )

        self.assertEqual((result.expected, result.lower, result.upper), (5.0, 5.0, 5.0))
        self.assertEqual(result.usable_bucket_count, 7)
        self.assertEqual(result.incomplete_bucket_count, 1)
        self.assertEqual(result.stale_bucket_count, 1)
        self.assertEqual(result.missing_bucket_count, 47)
        self.assertEqual(result.data_quality, "limited")
        self.assertEqual(result.confidence, "low")

    def test_insufficient_history_returns_a_blocked_artifact(self) -> None:
        recent_start = TARGET - timedelta(days=6)
        buckets = {
            recent_start + timedelta(days=index): observed(
                0,
                recent_start + timedelta(days=index),
            )
            for index in range(6)
        }
        result = TemporalExpectationService.from_projection_store(
            store=FakeTemporalStore(buckets)
        ).expectation(
            metric_key="site.findings.new.count",
            site_id="site-a",
            target_start=TARGET,
            generated_at=TARGET + timedelta(hours=12),
        )

        self.assertIsNone(result.expected)
        self.assertIsNone(result.lower)
        self.assertIsNone(result.upper)
        self.assertEqual(result.data_quality, "insufficient")
        self.assertEqual(result.confidence, "none")
        self.assertEqual(result.blocked_reason, "insufficient-usable-history")
        self.assertEqual(result.authority, "analytical-context-only")

    def test_current_open_target_is_allowed_but_future_and_unaligned_targets_fail(self) -> None:
        store = FakeTemporalStore()
        service = TemporalExpectationService.from_projection_store(store=store)
        current = service.expectation(
            metric_key="site.assets.new.count",
            site_id="site-a",
            target_start=TARGET,
            generated_at=TARGET + timedelta(hours=12),
        )
        self.assertEqual(current.history_end, TARGET)
        self.assertTrue(all(call["end"] <= TARGET for call in store.calls))

        for target in (TARGET + timedelta(days=1), TARGET + timedelta(hours=1)):
            with self.subTest(target=target):
                with self.assertRaises(TemporalProjectionError):
                    service.expectation(
                        metric_key="site.assets.new.count",
                        site_id="site-a",
                        target_start=target,
                        generated_at=TARGET + timedelta(hours=12),
                    )

    def test_expectation_identity_is_scope_bound(self) -> None:
        common = {
            "metric_key": "site.assets.new.count",
            "target_bucket_start": TARGET,
            "target_bucket_end": TARGET + timedelta(days=1),
            "history_start": HISTORY_START,
            "history_end": TARGET,
            "method": "rolling_robust_baseline",
            "projection_version": "1",
        }
        first = temporal_expectation_id(site_id="site-a", **common)
        self.assertEqual(first, temporal_expectation_id(site_id="site-a", **common))
        self.assertNotEqual(first, temporal_expectation_id(site_id="site-b", **common))

    def test_contract_rejects_mixed_or_authoritative_range_state(self) -> None:
        result = TemporalExpectationService.from_projection_store(
            store=FakeTemporalStore()
        ).expectation(
            metric_key="site.assets.new.count",
            site_id="site-a",
            target_start=TARGET,
            generated_at=TARGET + timedelta(hours=12),
        )
        payload = result.model_dump()
        payload["expected"] = 1.0
        with self.assertRaises(ValidationError):
            result.__class__.model_validate(payload)
        payload = result.model_dump()
        payload["authority"] = "finding-authority"
        with self.assertRaises(ValidationError):
            result.__class__.model_validate(payload)


class TemporalProjectionCutoffTests(unittest.TestCase):
    def test_projection_passes_exclusive_knowledge_cutoff_to_store(self) -> None:
        store = FakeTemporalStore()
        TemporalProjectionService(store=store).series(
            metric_key="site.assets.new.count",
            site_id="site-a",
            start=HISTORY_START,
            end=TARGET,
            generated_at=TARGET,
            knowledge_cutoff=TARGET,
        )
        self.assertEqual(store.calls[0]["knowledge_cutoff"], TARGET)

    def test_projection_rejects_history_that_crosses_knowledge_cutoff(self) -> None:
        with self.assertRaisesRegex(TemporalProjectionError, "evidence cutoff"):
            TemporalProjectionService(store=FakeTemporalStore()).series(
                metric_key="site.assets.new.count",
                site_id="site-a",
                start=HISTORY_START,
                end=TARGET,
                generated_at=TARGET,
                knowledge_cutoff=TARGET - timedelta(days=1),
            )


if __name__ == "__main__":
    unittest.main()
