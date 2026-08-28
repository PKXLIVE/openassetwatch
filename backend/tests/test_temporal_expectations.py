from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from pydantic import ValidationError

from app.temporal_contracts import (
    TEMPORAL_EXPECTATION_HISTORY_BUCKETS,
    TemporalSignal,
)
from app.temporal_expectations import (
    TemporalExpectationService,
    robust_expected_range,
    temporal_expectation_id,
    temporal_history_digest,
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


def projected_history(
    buckets: dict[datetime, ProjectionAggregate],
    *,
    generated_at: datetime = TARGET,
) -> list[TemporalSignal]:
    return TemporalProjectionService(store=FakeTemporalStore(buckets)).series(
        metric_key="site.assets.new.count",
        site_id="site-a",
        start=HISTORY_START,
        end=TARGET,
        generated_at=generated_at,
        knowledge_cutoff=TARGET,
    ).signals


def expected_artifact(
    buckets: dict[datetime, ProjectionAggregate],
    *,
    generated_at: datetime = TARGET + timedelta(hours=12),
):
    return TemporalExpectationService.from_projection_store(
        store=FakeTemporalStore(buckets)
    ).expectation(
        metric_key="site.assets.new.count",
        site_id="site-a",
        target_start=TARGET,
        generated_at=generated_at,
    )


class TemporalExpectedRangeTests(unittest.TestCase):
    def test_robust_range_uses_median_and_resists_one_large_spike(self) -> None:
        expected, lower, upper = robust_expected_range([10] * 27 + [1000])
        self.assertEqual((expected, lower, upper), (10.0, 10.0, 10.0))

    def test_robust_range_rejects_non_finite_inputs(self) -> None:
        for value in (float("inf"), float("-inf"), float("nan")):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "finite"):
                    robust_expected_range([1, value, 2])

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
        self.assertEqual(first.history_digest, second.history_digest)
        self.assertRegex(first.history_digest, r"^[0-9a-f]{64}$")
        self.assertIn("history_digest", first.model_dump(mode="json"))
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
            "history_digest": "a" * 64,
        }
        first = temporal_expectation_id(site_id="site-a", **common)
        self.assertEqual(first, temporal_expectation_id(site_id="site-a", **common))
        self.assertNotEqual(first, temporal_expectation_id(site_id="site-b", **common))
        self.assertNotEqual(
            first,
            temporal_expectation_id(
                site_id="site-a",
                **{**common, "history_digest": "b" * 64},
            ),
        )

    def test_history_digest_is_canonical_and_excludes_generated_at(self) -> None:
        buckets = history_with_values([10] * TEMPORAL_EXPECTATION_HISTORY_BUCKETS)
        signals = projected_history(buckets)
        regenerated = [
            TemporalSignal.model_validate(
                {
                    **signal.model_dump(),
                    "generated_at": signal.generated_at + timedelta(hours=1),
                }
            )
            for signal in signals
        ]

        digest = temporal_history_digest(signals)
        self.assertEqual(digest, temporal_history_digest(list(reversed(signals))))
        self.assertEqual(digest, temporal_history_digest(regenerated))
        with self.assertRaisesRegex(ValueError, "exactly 56"):
            temporal_history_digest(signals[:-1])

    def test_history_value_and_watermark_changes_bind_expectation_identity(self) -> None:
        buckets = history_with_values([10] * TEMPORAL_EXPECTATION_HISTORY_BUCKETS)
        baseline = expected_artifact(buckets)
        oldest = HISTORY_START
        original = buckets[oldest]
        variants = {
            "usable value": replace(original, value=11),
            "received watermark": replace(
                original,
                source_received_at=original.source_received_at + timedelta(minutes=1),
            ),
            "observed watermark": replace(
                original,
                source_observed_at=original.source_observed_at - timedelta(minutes=1),
            ),
            "evidence count": replace(
                original,
                evidence_count=original.evidence_count + 1,
            ),
        }
        for label, aggregate in variants.items():
            with self.subTest(label=label):
                changed = expected_artifact({**buckets, oldest: aggregate})
                self.assertNotEqual(baseline.history_digest, changed.history_digest)
                self.assertNotEqual(baseline.expectation_id, changed.expectation_id)

    def test_history_quality_changes_bind_expectation_identity(self) -> None:
        buckets = history_with_values([10] * TEMPORAL_EXPECTATION_HISTORY_BUCKETS)
        baseline = expected_artifact(buckets)
        oldest = HISTORY_START
        original = buckets[oldest]
        variants = {
            "missing": {key: value for key, value in buckets.items() if key != oldest},
            "incomplete": {
                **buckets,
                oldest: replace(
                    original,
                    value=0,
                    evidence_count=0,
                    complete=False,
                ),
            },
            "stale": {
                **buckets,
                oldest: replace(
                    original,
                    source_observed_at=oldest - timedelta(days=3),
                ),
            },
        }
        for quality, changed_buckets in variants.items():
            with self.subTest(quality=quality):
                changed = expected_artifact(changed_buckets)
                self.assertNotEqual(baseline.history_digest, changed.history_digest)
                self.assertNotEqual(baseline.expectation_id, changed.expectation_id)

    def test_late_arrival_state_binds_expectation_identity(self) -> None:
        buckets = history_with_values([10] * TEMPORAL_EXPECTATION_HISTORY_BUCKETS)
        baseline = expected_artifact(buckets)
        oldest = HISTORY_START
        late = replace(
            buckets[oldest],
            source_received_at=oldest + timedelta(days=1, hours=1),
        )
        changed = expected_artifact({**buckets, oldest: late})

        self.assertNotEqual(baseline.history_digest, changed.history_digest)
        self.assertNotEqual(baseline.expectation_id, changed.expectation_id)
        self.assertEqual(changed.late_arriving_bucket_count, 1)

    def test_contract_rejects_malformed_history_digests(self) -> None:
        result = expected_artifact(
            history_with_values([10] * TEMPORAL_EXPECTATION_HISTORY_BUCKETS)
        )
        for digest in ("a" * 63, "A" * 64, "g" * 64):
            with self.subTest(digest=digest):
                payload = result.model_dump()
                payload["history_digest"] = digest
                with self.assertRaises(ValidationError):
                    result.__class__.model_validate(payload)

    def test_expectation_contract_rejects_non_finite_outputs(self) -> None:
        result = expected_artifact(
            history_with_values([10] * TEMPORAL_EXPECTATION_HISTORY_BUCKETS)
        )
        for value in (float("inf"), float("-inf"), float("nan")):
            with self.subTest(value=value):
                payload = result.model_dump()
                payload["expected"] = value
                with self.assertRaises(ValidationError):
                    result.__class__.model_validate(payload)

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
