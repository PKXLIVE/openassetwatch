from __future__ import annotations

import hashlib
import unittest
from datetime import datetime, timedelta, timezone

from pydantic import ValidationError

from app.temporal_contracts import (
    MAX_TEMPORAL_DEVIATION_ASSESSMENTS,
    TEMPORAL_DEVIATION_ASSESSMENT_SCHEMA_VERSION,
    TEMPORAL_DEVIATION_POLICY_VERSION,
    TEMPORAL_EXPECTATION_HISTORY_BUCKETS,
    TemporalDeviationAssessment,
    TemporalDeviationPolicy,
    TemporalExpectation,
    TemporalSignal,
    temporal_metric,
)
from app.temporal_deviations import (
    TEMPORAL_DEVIATION_POLICIES,
    TemporalDeviationService,
    _AssessmentInputs,
    temporal_assessment_input_digest,
    temporal_deviation_assessment_id,
    temporal_observation_digest,
)
from app.temporal_expectations import temporal_expectation_id
from app.temporal_projection import (
    TemporalProjectionError,
    temporal_signal_id,
)


UTC = timezone.utc
TARGET = datetime(2026, 8, 28, tzinfo=UTC)
NOW = TARGET + timedelta(days=2, hours=12)


def unit_for(metric_key: str) -> str:
    return temporal_metric(metric_key).unit


def make_signal(
    *,
    metric_key: str = "site.assets.new.count",
    site_id: str = "site-a",
    target: datetime = TARGET,
    value: int | float | None = 10,
    complete: bool = True,
    freshness: str = "current",
    data_quality: str = "observed",
    source_received_at: datetime | None = None,
) -> TemporalSignal:
    target_end = target + timedelta(days=1)
    observed_at = target + timedelta(hours=23) if value is not None else None
    received_at = source_received_at
    if received_at is None and value is not None:
        received_at = target + timedelta(hours=23, minutes=30)
    evidence_count = 0 if value is None else max(1, int(value))
    return TemporalSignal(
        schema_version="oaw.temporal-signal.v1",
        signal_id=temporal_signal_id(
            metric_key=metric_key,
            site_id=site_id,
            asset_id=None,
            bucket_start=target,
            bucket_end=target_end,
            projection_version="1",
        ),
        metric_key=metric_key,
        tenant_id=None,
        site_id=site_id,
        asset_id=None,
        bucket_start=target,
        bucket_end=target_end,
        bucket_granularity="daily",
        value=value,
        unit=unit_for(metric_key),
        evidence_count=evidence_count,
        source=temporal_metric(metric_key).source_authority,
        source_observed_at=observed_at,
        source_received_at=received_at,
        freshness=freshness,
        complete=complete,
        data_quality=data_quality,
        backfill_state="backfilled",
        projection_version="1",
        generated_at=target_end,
    )


def make_missing_signal(
    *,
    metric_key: str = "site.assets.new.count",
    site_id: str = "site-a",
    target: datetime = TARGET,
) -> TemporalSignal:
    return make_signal(
        metric_key=metric_key,
        site_id=site_id,
        target=target,
        value=None,
        complete=False,
        freshness="unknown",
        data_quality="missing",
    )


def make_expectation(
    *,
    metric_key: str = "site.assets.new.count",
    site_id: str = "site-a",
    target: datetime = TARGET,
    expected: float | None = 10.0,
    lower: float | None = 8.0,
    upper: float | None = 12.0,
    confidence: str = "medium",
    data_quality: str = "sufficient",
    history_digest: str | None = None,
) -> TemporalExpectation:
    target_end = target + timedelta(days=1)
    history_start = target - timedelta(days=TEMPORAL_EXPECTATION_HISTORY_BUCKETS)
    digest = history_digest or hashlib.sha256(
        f"{metric_key}|{site_id}|{target.isoformat()}".encode("utf-8")
    ).hexdigest()
    method = (
        "seasonal_robust_baseline"
        if TEMPORAL_DEVIATION_POLICIES[metric_key].required_persistence_buckets == 2
        else "rolling_robust_baseline"
    )
    blocked = expected is None
    return TemporalExpectation(
        schema_version="oaw.temporal-expectation.v1",
        expectation_id=temporal_expectation_id(
            metric_key=metric_key,
            site_id=site_id,
            target_bucket_start=target,
            target_bucket_end=target_end,
            history_start=history_start,
            history_end=target,
            method=method,
            projection_version="1",
            history_digest=digest,
        ),
        history_digest=digest,
        metric_key=metric_key,
        tenant_id=None,
        site_id=site_id,
        asset_id=None,
        target_bucket_start=target,
        target_bucket_end=target_end,
        bucket_granularity="daily",
        knowledge_cutoff=target,
        generated_at=NOW,
        history_start=history_start,
        history_end=target,
        history_bucket_count=TEMPORAL_EXPECTATION_HISTORY_BUCKETS,
        usable_bucket_count=0 if blocked else 40,
        missing_bucket_count=TEMPORAL_EXPECTATION_HISTORY_BUCKETS if blocked else 16,
        incomplete_bucket_count=0,
        stale_bucket_count=0,
        late_arriving_bucket_count=0,
        method=method,
        method_version="1",
        method_sample_count=0 if blocked else 14,
        horizon_buckets=1,
        expected=expected,
        lower=lower,
        upper=upper,
        unit=unit_for(metric_key),
        confidence="none" if blocked else confidence,
        data_quality="insufficient" if blocked else data_quality,
        blocked_reason="insufficient-usable-history" if blocked else None,
        projection_version="1",
        authority="analytical-context-only",
    )


class FakeProjection:
    def __init__(self, signals: dict[datetime, TemporalSignal]) -> None:
        self.signals = dict(signals)
        self.calls: list[dict[str, object]] = []

    def series(self, **kwargs):
        self.calls.append(kwargs)
        signal = self.signals[kwargs["start"]]
        return type("Series", (), {"bucket_count": 1, "signals": [signal]})()


class FakeExpectations:
    def __init__(self, expectations: dict[datetime, TemporalExpectation]) -> None:
        self.expectations = dict(expectations)
        self.calls: list[dict[str, object]] = []

    def expectation(self, **kwargs):
        self.calls.append(kwargs)
        return self.expectations[kwargs["target_start"]]


def service_with(
    *,
    metric_key: str,
    target_signal: TemporalSignal,
    target_expectation: TemporalExpectation,
    prior_signal: TemporalSignal | None = None,
    prior_expectation: TemporalExpectation | None = None,
) -> tuple[TemporalDeviationService, FakeProjection, FakeExpectations]:
    signals = {TARGET: target_signal}
    expectations = {TARGET: target_expectation}
    if prior_signal is not None:
        signals[TARGET - timedelta(days=1)] = prior_signal
    if prior_expectation is not None:
        expectations[TARGET - timedelta(days=1)] = prior_expectation
    projection = FakeProjection(signals)
    expected = FakeExpectations(expectations)
    return (
        TemporalDeviationService(projection=projection, expectations=expected),
        projection,
        expected,
    )


def assess_one_bucket(
    *,
    metric_key: str,
    value: int | float,
    expected: float = 10.0,
    lower: float = 8.0,
    upper: float = 12.0,
) -> TemporalDeviationAssessment:
    service, _, _ = service_with(
        metric_key=metric_key,
        target_signal=make_signal(metric_key=metric_key, value=value),
        target_expectation=make_expectation(
            metric_key=metric_key,
            expected=expected,
            lower=lower,
            upper=upper,
        ),
    )
    return service.assessment(
        metric_key=metric_key,
        site_id="site-a",
        target_start=TARGET,
        generated_at=NOW,
    )


class TemporalDeviationPolicyTests(unittest.TestCase):
    def test_registry_covers_exactly_six_metrics_with_unique_policy_ids(self) -> None:
        self.assertEqual(set(TEMPORAL_DEVIATION_POLICIES), {
            "site.assets.new.count",
            "site.collectors.active.count",
            "site.findings.new.count",
            "site.vulnerabilities.new.count",
            "site.inventory.collections.count",
            "site.inventory.asset_observations.count",
        })
        policies = tuple(TEMPORAL_DEVIATION_POLICIES.values())
        self.assertEqual(len({policy.policy_id for policy in policies}), 6)
        self.assertTrue(
            all(
                policy.policy_version == TEMPORAL_DEVIATION_POLICY_VERSION
                and policy.minimum_expectation_confidence == "medium"
                and policy.required_expectation_data_quality == "sufficient"
                and policy.supported_granularity == "daily"
                and policy.entity_scope == "site"
                and policy.maximum_persistence_lookback
                <= MAX_TEMPORAL_DEVIATION_ASSESSMENTS
                for policy in policies
            )
        )

    def test_direction_and_persistence_mapping_is_conservative(self) -> None:
        expected = {
            "site.assets.new.count": (("above",), 1),
            "site.collectors.active.count": (("below",), 1),
            "site.findings.new.count": (("above",), 1),
            "site.vulnerabilities.new.count": (("above",), 1),
            "site.inventory.collections.count": (("above", "below"), 2),
            "site.inventory.asset_observations.count": (("above", "below"), 2),
        }
        for metric_key, (directions, persistence) in expected.items():
            with self.subTest(metric_key=metric_key):
                policy = TEMPORAL_DEVIATION_POLICIES[metric_key]
                self.assertEqual(policy.allowed_directions, directions)
                self.assertEqual(policy.required_persistence_buckets, persistence)

    def test_policy_contract_rejects_duplicates_and_unbounded_persistence(self) -> None:
        payload = TEMPORAL_DEVIATION_POLICIES[
            "site.assets.new.count"
        ].model_dump()
        with self.assertRaises(ValidationError):
            TemporalDeviationPolicy.model_validate(
                {**payload, "allowed_directions": ["above", "above"]}
            )
        with self.assertRaises(ValidationError):
            TemporalDeviationPolicy.model_validate(
                {
                    **payload,
                    "required_persistence_buckets": 3,
                    "maximum_persistence_lookback": 2,
                }
            )


class TemporalDeviationDirectionTests(unittest.TestCase):
    def test_bounds_are_inclusive_and_outside_directions_are_exact(self) -> None:
        cases = (
            (8, "inside", 0.0, "within-range"),
            (12, "inside", 0.0, "within-range"),
            (7, "below", 1.0, "outside-policy-direction"),
            (13, "above", 1.0, "candidate"),
        )
        for value, direction, distance, state in cases:
            with self.subTest(value=value):
                result = assess_one_bucket(
                    metric_key="site.assets.new.count",
                    value=value,
                )
                self.assertEqual(result.direction, direction)
                self.assertEqual(result.distance_beyond_bound, distance)
                self.assertEqual(result.assessment_state, state)

    def test_metric_directions_are_owned_by_policy(self) -> None:
        cases = (
            ("site.assets.new.count", 13, "candidate"),
            ("site.assets.new.count", 7, "outside-policy-direction"),
            ("site.collectors.active.count", 7, "candidate"),
            ("site.collectors.active.count", 13, "outside-policy-direction"),
            ("site.findings.new.count", 13, "candidate"),
            ("site.vulnerabilities.new.count", 13, "candidate"),
        )
        for metric_key, value, state in cases:
            with self.subTest(metric_key=metric_key, value=value):
                self.assertEqual(
                    assess_one_bucket(metric_key=metric_key, value=value).assessment_state,
                    state,
                )

    def test_relative_change_and_zero_center_behavior(self) -> None:
        result = assess_one_bucket(metric_key="site.assets.new.count", value=13)
        self.assertEqual(result.relative_change, 0.3)

        zero_inside = assess_one_bucket(
            metric_key="site.assets.new.count",
            value=0,
            expected=0,
            lower=0,
            upper=0,
        )
        zero_above = assess_one_bucket(
            metric_key="site.assets.new.count",
            value=1,
            expected=0,
            lower=0,
            upper=0,
        )
        self.assertEqual(zero_inside.assessment_state, "within-range")
        self.assertEqual(zero_above.assessment_state, "candidate")
        self.assertIsNone(zero_inside.relative_change)
        self.assertIsNone(zero_above.relative_change)


class TemporalDeviationTrustTests(unittest.TestCase):
    def test_missing_incomplete_and_stale_observations_block(self) -> None:
        cases = (
            make_missing_signal(),
            make_signal(value=13, complete=False, data_quality="incomplete"),
            make_signal(
                value=13,
                freshness="stale",
                data_quality="stale",
            ).model_copy(
                update={"source_observed_at": TARGET - timedelta(days=2)}
            ),
        )
        for signal in cases:
            with self.subTest(quality=signal.data_quality):
                service, _, _ = service_with(
                    metric_key=signal.metric_key,
                    target_signal=signal,
                    target_expectation=make_expectation(),
                )
                result = service.assessment(
                    metric_key=signal.metric_key,
                    site_id="site-a",
                    target_start=TARGET,
                    generated_at=NOW,
                )
                self.assertEqual(result.assessment_state, "blocked")
                self.assertEqual(result.direction, "unknown")
                self.assertIsNone(result.distance_beyond_bound)
                self.assertFalse(result.candidate)

    def test_low_limited_and_null_expectations_block(self) -> None:
        expectations = (
            make_expectation(confidence="low", data_quality="limited"),
            make_expectation(expected=None, lower=None, upper=None),
        )
        for expectation in expectations:
            with self.subTest(confidence=expectation.confidence):
                service, _, _ = service_with(
                    metric_key=expectation.metric_key,
                    target_signal=make_signal(value=13),
                    target_expectation=expectation,
                )
                result = service.assessment(
                    metric_key=expectation.metric_key,
                    site_id="site-a",
                    target_start=TARGET,
                    generated_at=NOW,
                )
                self.assertEqual(result.assessment_state, "blocked")
                self.assertFalse(result.candidate)

    def test_medium_and_high_sufficient_expectations_pass(self) -> None:
        for confidence in ("medium", "high"):
            with self.subTest(confidence=confidence):
                service, _, _ = service_with(
                    metric_key="site.assets.new.count",
                    target_signal=make_signal(value=13),
                    target_expectation=make_expectation(confidence=confidence),
                )
                result = service.assessment(
                    metric_key="site.assets.new.count",
                    site_id="site-a",
                    target_start=TARGET,
                    generated_at=NOW,
                )
                self.assertEqual(result.assessment_state, "candidate")

    def test_provenance_and_identity_mismatches_fail_closed(self) -> None:
        base_signal = make_signal(value=13)
        base_expectation = make_expectation()
        cases = (
            (
                base_signal.model_copy(update={"signal_id": "sig_" + "f" * 32}),
                base_expectation,
            ),
            (
                base_signal,
                base_expectation.model_copy(
                    update={"expectation_id": "exp_" + "f" * 32}
                ),
            ),
            (
                base_signal,
                base_expectation.model_copy(update={"history_digest": "f" * 64}),
            ),
            (
                base_signal,
                base_expectation.model_copy(update={"site_id": "site-b"}),
            ),
            (
                base_signal,
                base_expectation.model_copy(
                    update={"target_bucket_start": TARGET - timedelta(days=1)}
                ),
            ),
        )
        for signal, expectation in cases:
            with self.subTest(signal_id=signal.signal_id, expectation=expectation.expectation_id):
                service, _, _ = service_with(
                    metric_key="site.assets.new.count",
                    target_signal=signal,
                    target_expectation=expectation,
                )
                with self.assertRaises(TemporalProjectionError):
                    service.assessment(
                        metric_key="site.assets.new.count",
                        site_id="site-a",
                        target_start=TARGET,
                        generated_at=NOW,
                    )

    def test_target_projection_uses_exclusive_bucket_end_cutoff(self) -> None:
        service, projection, expectations = service_with(
            metric_key="site.assets.new.count",
            target_signal=make_signal(value=13),
            target_expectation=make_expectation(),
        )
        service.assessment(
            metric_key="site.assets.new.count",
            site_id="site-a",
            target_start=TARGET,
            generated_at=NOW,
        )
        self.assertEqual(projection.calls[0]["start"], TARGET)
        self.assertEqual(projection.calls[0]["end"], TARGET + timedelta(days=1))
        self.assertEqual(
            projection.calls[0]["knowledge_cutoff"],
            TARGET + timedelta(days=1),
        )
        self.assertEqual(expectations.calls[0]["target_start"], TARGET)

    def test_open_future_unaligned_scope_and_granularity_are_rejected(self) -> None:
        service, projection, _ = service_with(
            metric_key="site.assets.new.count",
            target_signal=make_signal(value=13),
            target_expectation=make_expectation(),
        )
        cases = (
            {"target_start": NOW.replace(hour=0), "granularity": "daily", "asset_id": None},
            {"target_start": NOW.replace(hour=0) + timedelta(days=1), "granularity": "daily", "asset_id": None},
            {"target_start": TARGET + timedelta(hours=1), "granularity": "daily", "asset_id": None},
            {"target_start": TARGET, "granularity": "hourly", "asset_id": None},
            {"target_start": TARGET, "granularity": "daily", "asset_id": "asset-a"},
        )
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(TemporalProjectionError):
                    service.assessment(
                        metric_key="site.assets.new.count",
                        site_id="site-a",
                        generated_at=NOW,
                        **case,
                    )
        self.assertEqual(projection.calls, [])


class TemporalDeviationPersistenceTests(unittest.TestCase):
    metric_key = "site.inventory.collections.count"

    def assessment_with_prior(
        self,
        *,
        current_value: int,
        prior_signal: TemporalSignal,
    ) -> tuple[TemporalDeviationAssessment, FakeProjection, FakeExpectations]:
        prior_target = TARGET - timedelta(days=1)
        service, projection, expectations = service_with(
            metric_key=self.metric_key,
            target_signal=make_signal(metric_key=self.metric_key, value=current_value),
            target_expectation=make_expectation(metric_key=self.metric_key),
            prior_signal=prior_signal,
            prior_expectation=make_expectation(
                metric_key=self.metric_key,
                target=prior_target,
            ),
        )
        result = service.assessment(
            metric_key=self.metric_key,
            site_id="site-a",
            target_start=TARGET,
            generated_at=NOW,
        )
        return result, projection, expectations

    def test_one_outside_bucket_is_pending(self) -> None:
        prior_target = TARGET - timedelta(days=1)
        result, _, _ = self.assessment_with_prior(
            current_value=13,
            prior_signal=make_signal(
                metric_key=self.metric_key,
                target=prior_target,
                value=10,
            ),
        )
        self.assertEqual(result.assessment_state, "pending-persistence")
        self.assertEqual(result.persistence_observed_buckets, 1)
        self.assertEqual(result.supporting_assessment_ids, ())

    def test_two_consecutive_same_direction_buckets_create_candidate(self) -> None:
        prior_target = TARGET - timedelta(days=1)
        result, projection, expectations = self.assessment_with_prior(
            current_value=13,
            prior_signal=make_signal(
                metric_key=self.metric_key,
                target=prior_target,
                value=13,
            ),
        )
        self.assertEqual(result.assessment_state, "candidate")
        self.assertTrue(result.candidate)
        self.assertEqual(result.persistence_observed_buckets, 2)
        self.assertEqual(len(result.supporting_assessment_ids), 1)
        self.assertEqual(
            [call["start"] for call in projection.calls],
            [TARGET, prior_target],
        )
        self.assertEqual(
            [call["target_start"] for call in expectations.calls],
            [TARGET, prior_target],
        )
        self.assertLessEqual(len(projection.calls), MAX_TEMPORAL_DEVIATION_ASSESSMENTS)
        self.assertTrue(all(call["start"] < NOW.replace(hour=0) for call in projection.calls))

    def test_inside_blocked_and_opposite_prior_buckets_reset_persistence(self) -> None:
        prior_target = TARGET - timedelta(days=1)
        cases = (
            make_signal(metric_key=self.metric_key, target=prior_target, value=10),
            make_missing_signal(metric_key=self.metric_key, target=prior_target),
            make_signal(metric_key=self.metric_key, target=prior_target, value=7),
        )
        for prior in cases:
            with self.subTest(prior_quality=prior.data_quality, prior_value=prior.value):
                result, _, _ = self.assessment_with_prior(
                    current_value=13,
                    prior_signal=prior,
                )
                self.assertEqual(result.assessment_state, "pending-persistence")
                self.assertEqual(result.persistence_observed_buckets, 1)
                self.assertEqual(result.supporting_assessment_ids, ())

    def test_both_direction_policy_can_candidate_below(self) -> None:
        prior_target = TARGET - timedelta(days=1)
        result, _, _ = self.assessment_with_prior(
            current_value=7,
            prior_signal=make_signal(
                metric_key=self.metric_key,
                target=prior_target,
                value=7,
            ),
        )
        self.assertEqual(result.assessment_state, "candidate")
        self.assertEqual(result.direction, "below")


class TemporalDeviationDigestTests(unittest.TestCase):
    def test_observation_digest_covers_governed_fields_but_not_generated_at(self) -> None:
        signal = make_signal(value=13)
        baseline = temporal_observation_digest(signal)
        self.assertRegex(baseline, r"^[0-9a-f]{64}$")
        self.assertEqual(
            baseline,
            temporal_observation_digest(
                signal.model_copy(update={"generated_at": signal.generated_at + timedelta(hours=1)})
            ),
        )
        variants = {
            "schema_version": "oaw.temporal-signal.v2",
            "signal_id": "sig_" + "f" * 32,
            "metric_key": "site.findings.new.count",
            "tenant_id": "tenant-a",
            "site_id": "site-b",
            "asset_id": "asset-a",
            "bucket_start": signal.bucket_start - timedelta(days=1),
            "bucket_end": signal.bucket_end + timedelta(days=1),
            "bucket_granularity": "weekly",
            "value": 14,
            "unit": "other-count",
            "evidence_count": signal.evidence_count + 1,
            "source": "another-source",
            "source_observed_at": signal.source_observed_at - timedelta(minutes=1),
            "source_received_at": signal.source_received_at - timedelta(minutes=1),
            "freshness": "stale",
            "complete": False,
            "data_quality": "incomplete",
            "backfill_state": "late-arriving",
            "projection_version": "2",
        }
        for field, value in variants.items():
            with self.subTest(field=field):
                changed = signal.model_copy(update={field: value})
                self.assertNotEqual(baseline, temporal_observation_digest(changed))

    def test_assessment_identity_is_stable_and_binds_every_input_family(self) -> None:
        result = assess_one_bucket(metric_key="site.assets.new.count", value=13)
        service, _, _ = service_with(
            metric_key="site.assets.new.count",
            target_signal=make_signal(value=13),
            target_expectation=make_expectation(),
        )
        regenerated = service.assessment(
            metric_key="site.assets.new.count",
            site_id="site-a",
            target_start=TARGET,
            generated_at=NOW + timedelta(hours=1),
        )
        self.assertEqual(result.observation_digest, regenerated.observation_digest)
        self.assertEqual(result.input_digest, regenerated.input_digest)
        self.assertEqual(result.assessment_id, regenerated.assessment_id)
        self.assertNotEqual(result.generated_at, regenerated.generated_at)

        changed_observation = assess_one_bucket(
            metric_key="site.assets.new.count",
            value=14,
        )
        self.assertNotEqual(result.observation_digest, changed_observation.observation_digest)
        self.assertNotEqual(result.input_digest, changed_observation.input_digest)
        self.assertNotEqual(result.assessment_id, changed_observation.assessment_id)

        expectation = make_expectation()
        policy = TEMPORAL_DEVIATION_POLICIES[expectation.metric_key]
        observation_digest = temporal_observation_digest(make_signal(value=13))
        baseline_input = temporal_assessment_input_digest(
            observation_digest=observation_digest,
            expectation=expectation,
            policy=policy,
            supporting_assessment_ids=(),
        )
        expectation_variants = (
            expectation.model_copy(update={"expectation_id": "exp_" + "f" * 32}),
            expectation.model_copy(update={"history_digest": "f" * 64}),
            expectation.model_copy(update={"expected": 11.0}),
            expectation.model_copy(update={"lower": 7.0}),
            expectation.model_copy(update={"upper": 13.0}),
        )
        for variant in expectation_variants:
            self.assertNotEqual(
                baseline_input,
                temporal_assessment_input_digest(
                    observation_digest=observation_digest,
                    expectation=variant,
                    policy=policy,
                    supporting_assessment_ids=(),
                ),
            )
        self.assertNotEqual(
            baseline_input,
            temporal_assessment_input_digest(
                observation_digest=observation_digest,
                expectation=expectation,
                policy=policy.model_copy(update={"policy_version": "2"}),
                supporting_assessment_ids=(),
            ),
        )

    def test_assessment_id_binds_scope_target_and_policy_version(self) -> None:
        common = {
            "input_digest": "a" * 64,
            "metric_key": "site.assets.new.count",
            "site_id": "site-a",
            "target_bucket_start": TARGET,
            "target_bucket_end": TARGET + timedelta(days=1),
            "policy_version": "1",
        }
        baseline = temporal_deviation_assessment_id(**common)
        self.assertEqual(baseline, temporal_deviation_assessment_id(**common))
        variants = (
            {**common, "input_digest": "b" * 64},
            {**common, "metric_key": "site.findings.new.count"},
            {**common, "site_id": "site-b"},
            {**common, "target_bucket_start": TARGET - timedelta(days=1)},
            {**common, "policy_version": "2"},
        )
        for variant in variants:
            self.assertNotEqual(baseline, temporal_deviation_assessment_id(**variant))

    def test_reordered_support_is_canonicalized_chronologically(self) -> None:
        metric_key = "site.inventory.collections.count"
        policy = TEMPORAL_DEVIATION_POLICIES[metric_key].model_copy(
            update={
                "policy_id": "tdp_test_three_bucket",
                "required_persistence_buckets": 3,
                "maximum_persistence_lookback": 3,
            }
        )
        targets = (TARGET - timedelta(days=2), TARGET - timedelta(days=1), TARGET)
        inputs = [
            _AssessmentInputs(
                observation=make_signal(metric_key=metric_key, target=target, value=13),
                expectation=make_expectation(metric_key=metric_key, target=target),
            )
            for target in targets
        ]
        first_support = TemporalDeviationService._build_assessment(
            inputs=inputs[0], policy=policy, generated_at=NOW, supporting=()
        )
        second_support = TemporalDeviationService._build_assessment(
            inputs=inputs[1], policy=policy, generated_at=NOW, supporting=()
        )
        ordered = TemporalDeviationService._build_assessment(
            inputs=inputs[2],
            policy=policy,
            generated_at=NOW,
            supporting=(first_support, second_support),
        )
        reversed_result = TemporalDeviationService._build_assessment(
            inputs=inputs[2],
            policy=policy,
            generated_at=NOW,
            supporting=(second_support, first_support),
        )
        self.assertEqual(ordered.supporting_assessment_ids, reversed_result.supporting_assessment_ids)
        self.assertEqual(ordered.input_digest, reversed_result.input_digest)
        self.assertEqual(ordered.assessment_id, reversed_result.assessment_id)
        self.assertEqual(ordered.assessment_state, "candidate")

    def test_malformed_digests_are_rejected(self) -> None:
        expectation = make_expectation()
        policy = TEMPORAL_DEVIATION_POLICIES[expectation.metric_key]
        for digest in ("a" * 63, "A" * 64, "g" * 64):
            with self.subTest(digest=digest):
                with self.assertRaises(ValueError):
                    temporal_assessment_input_digest(
                        observation_digest=digest,
                        expectation=expectation,
                        policy=policy,
                        supporting_assessment_ids=(),
                    )
                with self.assertRaises(ValueError):
                    temporal_deviation_assessment_id(
                        input_digest=digest,
                        metric_key=expectation.metric_key,
                        site_id=expectation.site_id,
                        target_bucket_start=TARGET,
                        target_bucket_end=TARGET + timedelta(days=1),
                        policy_version="1",
                    )


class TemporalDeviationContractTests(unittest.TestCase):
    def test_contract_is_strict_bounded_and_has_no_authoritative_fields(self) -> None:
        result = assess_one_bucket(metric_key="site.assets.new.count", value=13)
        payload = result.model_dump()
        with self.assertRaises(ValidationError):
            TemporalDeviationAssessment.model_validate({**payload, "extra": "no"})
        for forbidden in (
            "severity",
            "risk_score",
            "threat_score",
            "compromise_confidence",
            "incident_state",
            "remediation_state",
        ):
            self.assertNotIn(forbidden, TemporalDeviationAssessment.model_fields)
        self.assertEqual(
            result.authority,
            "analytical-investigation-context-only",
        )

    def test_contract_rejects_state_candidate_direction_and_distance_inconsistency(self) -> None:
        result = assess_one_bucket(metric_key="site.assets.new.count", value=13)
        variants = (
            {"candidate": False},
            {"assessment_state": "within-range"},
            {"direction": "inside"},
            {"distance_beyond_bound": 0.0},
            {"relative_change": float("inf")},
            {"authority": "finding-authority"},
            {"reason_codes": ["within-expected-range"]},
            {"supporting_assessment_ids": ["tda_" + "a" * 32] * 3},
        )
        for update in variants:
            with self.subTest(update=update):
                with self.assertRaises(ValidationError):
                    TemporalDeviationAssessment.model_validate(
                        {**result.model_dump(), **update}
                    )

    def test_blocked_contract_rejects_fabricated_distance_and_candidate(self) -> None:
        service, _, _ = service_with(
            metric_key="site.assets.new.count",
            target_signal=make_missing_signal(),
            target_expectation=make_expectation(),
        )
        result = service.assessment(
            metric_key="site.assets.new.count",
            site_id="site-a",
            target_start=TARGET,
            generated_at=NOW,
        )
        self.assertEqual(result.schema_version, TEMPORAL_DEVIATION_ASSESSMENT_SCHEMA_VERSION)
        for update in (
            {"candidate": True},
            {"direction": "above"},
            {"distance_beyond_bound": 1.0},
            {"relative_change": 1.0},
            {"reason_codes": ["deviation-candidate"]},
        ):
            with self.subTest(update=update):
                with self.assertRaises(ValidationError):
                    TemporalDeviationAssessment.model_validate(
                        {**result.model_dump(), **update}
                    )

    def test_no_store_or_provider_authority_is_present(self) -> None:
        import inspect
        import app.temporal_deviations as module

        source = inspect.getsource(module)
        for forbidden in (
            "INSERT INTO",
            "UPDATE findings",
            "UPDATE asset_risk_scores",
            "ai_advisor",
            "model_provider",
            "openai",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
