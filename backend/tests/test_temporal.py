from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, Mock, patch

from pydantic import ValidationError

from app.temporal_contracts import (
    MAX_TEMPORAL_BUCKETS,
    TEMPORAL_METRICS,
    TEMPORAL_SIGNAL_SCHEMA_VERSION,
    TemporalMetricDefinition,
    TemporalSignal,
    temporal_metric,
)
from app.temporal_projection import (
    ProjectionAggregate,
    TemporalProjectionError,
    TemporalProjectionService,
    TemporalSiteNotFound,
    temporal_signal_id,
    utc_daily_bucket,
    validate_temporal_window,
)
from app.temporal_store import (
    COLLECTORS_ACTIVE_SQL,
    INVENTORY_COLLECTIONS_SQL,
    METRIC_QUERIES_AS_OF,
    SqlTemporalStore,
)


UTC = timezone.utc
START = datetime(2026, 8, 24, tzinfo=UTC)
END = datetime(2026, 8, 28, tzinfo=UTC)
GENERATED = datetime(2026, 8, 27, 12, tzinfo=UTC)


class FakeTemporalStore:
    def __init__(self, buckets=None, *, missing_site: bool = False) -> None:
        self.buckets = dict(buckets or {})
        self.missing_site = missing_site
        self.calls: list[dict[str, object]] = []

    def metric_buckets(self, **kwargs):
        self.calls.append(kwargs)
        if self.missing_site:
            raise TemporalSiteNotFound()
        return dict(self.buckets)


class TemporalContractTests(unittest.TestCase):
    def test_registry_is_small_unique_and_site_scoped(self) -> None:
        self.assertEqual(len(TEMPORAL_METRICS), 6)
        self.assertEqual(
            len({metric.metric_key for metric in TEMPORAL_METRICS}),
            len(TEMPORAL_METRICS),
        )
        for metric in TEMPORAL_METRICS:
            with self.subTest(metric=metric.metric_key):
                self.assertEqual(metric.entity_scope, "site")
                self.assertEqual(metric.supported_bucket_granularities, ("daily",))
                self.assertFalse(metric.supports_asset_scope)
                self.assertTrue(metric.source_authority)

    def test_unknown_metrics_are_not_admitted(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown temporal metric"):
            temporal_metric("site.caller.supplied.count")

    def test_signal_contract_rejects_missing_values_claimed_as_complete(self) -> None:
        with self.assertRaises(ValidationError):
            TemporalSignal(
                schema_version=TEMPORAL_SIGNAL_SCHEMA_VERSION,
                signal_id="sig_" + "a" * 32,
                metric_key="site.assets.new.count",
                site_id="site-a",
                bucket_start=START,
                bucket_end=START + timedelta(days=1),
                bucket_granularity="daily",
                value=None,
                unit="count",
                evidence_count=0,
                source="test",
                freshness="unknown",
                complete=True,
                data_quality="missing",
                backfill_state="backfilled",
                projection_version="1",
                generated_at=GENERATED,
            )

    def test_signal_identity_is_stable_and_scope_bound(self) -> None:
        common = {
            "metric_key": "site.assets.new.count",
            "asset_id": None,
            "bucket_start": START,
            "bucket_end": START + timedelta(days=1),
            "projection_version": "1",
        }
        first = temporal_signal_id(site_id="site-a", **common)
        second = temporal_signal_id(site_id="site-a", **common)
        other_site = temporal_signal_id(site_id="site-b", **common)
        self.assertEqual(first, second)
        self.assertNotEqual(first, other_site)


class TemporalBucketingTests(unittest.TestCase):
    def test_exact_boundary_and_offset_inputs_use_utc(self) -> None:
        eastern = timezone(timedelta(hours=-4))
        start, end = utc_daily_bucket(
            datetime(2026, 8, 26, 20, tzinfo=eastern)
        )
        self.assertEqual(start, datetime(2026, 8, 27, tzinfo=UTC))
        self.assertEqual(end, datetime(2026, 8, 28, tzinfo=UTC))

    def test_window_accepts_offset_boundaries_after_utc_normalization(self) -> None:
        eastern = timezone(timedelta(hours=-4))
        start, end, count = validate_temporal_window(
            start=datetime(2026, 8, 25, 20, tzinfo=eastern),
            end=datetime(2026, 8, 27, 20, tzinfo=eastern),
            granularity="daily",
        )
        self.assertEqual(start, datetime(2026, 8, 26, tzinfo=UTC))
        self.assertEqual(end, datetime(2026, 8, 28, tzinfo=UTC))
        self.assertEqual(count, 2)

    def test_window_rejects_naive_unaligned_reversed_and_unbounded_inputs(self) -> None:
        invalid = (
            {
                "start": datetime(2026, 8, 1),
                "end": datetime(2026, 8, 2, tzinfo=UTC),
                "granularity": "daily",
            },
            {
                "start": datetime(2026, 8, 1, 1, tzinfo=UTC),
                "end": datetime(2026, 8, 2, tzinfo=UTC),
                "granularity": "daily",
            },
            {"start": START, "end": START, "granularity": "daily"},
            {"start": END, "end": START, "granularity": "daily"},
            {
                "start": START,
                "end": START + timedelta(days=MAX_TEMPORAL_BUCKETS + 1),
                "granularity": "daily",
            },
            {"start": START, "end": END, "granularity": "hourly"},
        )
        for case in invalid:
            with self.subTest(case=case):
                with self.assertRaises(TemporalProjectionError):
                    validate_temporal_window(**case)


class TemporalProjectionTests(unittest.TestCase):
    def test_empty_source_history_is_missing_and_never_zero(self) -> None:
        response = TemporalProjectionService(store=FakeTemporalStore()).series(
            metric_key="site.assets.new.count",
            site_id="site-a",
            start=START,
            end=START + timedelta(days=2),
            generated_at=GENERATED,
        )

        self.assertEqual([signal.value for signal in response.signals], [None, None])
        self.assertEqual(
            [signal.data_quality for signal in response.signals],
            ["missing", "missing"],
        )
        self.assertTrue(all(not signal.complete for signal in response.signals))

    def test_projection_preserves_observed_zero_missing_and_incomplete_buckets(self) -> None:
        store = FakeTemporalStore(
            {
                START: ProjectionAggregate(
                    value=4,
                    evidence_count=4,
                    source_observed_at=START + timedelta(hours=23),
                    source_received_at=START + timedelta(hours=23, minutes=1),
                    complete=True,
                ),
                START + timedelta(days=1): ProjectionAggregate(
                    value=0,
                    evidence_count=0,
                    source_observed_at=START + timedelta(days=1, hours=6),
                    source_received_at=START + timedelta(days=1, hours=6),
                    complete=False,
                ),
                START + timedelta(days=3): ProjectionAggregate(
                    value=0,
                    evidence_count=0,
                    source_observed_at=START + timedelta(days=3, hours=6),
                    source_received_at=START + timedelta(days=3, hours=6),
                    complete=True,
                ),
            }
        )
        response = TemporalProjectionService(store=store).series(
            metric_key="site.assets.new.count",
            site_id="site-a",
            start=START,
            end=END,
            generated_at=GENERATED,
        )

        self.assertEqual([signal.value for signal in response.signals], [4, None, None, 0])
        self.assertEqual(
            [signal.data_quality for signal in response.signals],
            ["observed", "incomplete", "missing", "observed"],
        )
        self.assertFalse(response.signals[1].complete)
        self.assertEqual(response.signals[2].evidence_count, 0)
        self.assertEqual(response.missing_bucket_count, 1)
        self.assertEqual(response.incomplete_bucket_count, 2)

    def test_delayed_evidence_is_labeled_without_retimestamping_observation(self) -> None:
        observed = START + timedelta(hours=2)
        received = START + timedelta(days=1, hours=3)
        store = FakeTemporalStore(
            {
                START: ProjectionAggregate(
                    value=1,
                    evidence_count=1,
                    source_observed_at=observed,
                    source_received_at=received,
                    complete=True,
                )
            }
        )
        signal = TemporalProjectionService(store=store).series(
            metric_key="site.assets.new.count",
            site_id="site-a",
            start=START,
            end=START + timedelta(days=1),
            generated_at=GENERATED,
        ).signals[0]

        self.assertEqual(signal.source_observed_at, observed)
        self.assertEqual(signal.source_received_at, received)
        self.assertEqual(signal.backfill_state, "late-arriving")

    def test_stale_source_is_explicit_and_does_not_change_value(self) -> None:
        store = FakeTemporalStore(
            {
                START: ProjectionAggregate(
                    value=2,
                    evidence_count=2,
                    source_observed_at=START - timedelta(days=2),
                    source_received_at=START + timedelta(hours=1),
                    complete=True,
                )
            }
        )
        signal = TemporalProjectionService(store=store).series(
            metric_key="site.collectors.active.count",
            site_id="site-a",
            start=START,
            end=START + timedelta(days=1),
            generated_at=GENERATED,
        ).signals[0]

        self.assertEqual(signal.value, 2)
        self.assertEqual(signal.freshness, "stale")
        self.assertEqual(signal.data_quality, "stale")

    def test_rerun_is_idempotent_for_signal_identity_and_values(self) -> None:
        store = FakeTemporalStore(
            {
                START: ProjectionAggregate(
                    value=3,
                    evidence_count=3,
                    source_observed_at=START + timedelta(hours=20),
                    source_received_at=START + timedelta(hours=20),
                    complete=True,
                )
            }
        )
        service = TemporalProjectionService(store=store)
        first = service.series(
            metric_key="site.findings.new.count",
            site_id="site-a",
            start=START,
            end=START + timedelta(days=1),
            generated_at=GENERATED,
        )
        second = service.series(
            metric_key="site.findings.new.count",
            site_id="site-a",
            start=START,
            end=START + timedelta(days=1),
            generated_at=GENERATED + timedelta(minutes=5),
        )

        self.assertEqual(first.signals[0].signal_id, second.signals[0].signal_id)
        self.assertEqual(first.signals[0].value, second.signals[0].value)
        self.assertNotEqual(first.generated_at, second.generated_at)

    def test_asset_scope_is_rejected_for_site_metrics(self) -> None:
        with self.assertRaisesRegex(TemporalProjectionError, "site scope only"):
            TemporalProjectionService(store=FakeTemporalStore()).series(
                metric_key="site.assets.new.count",
                site_id="site-a",
                asset_id="asset-a",
                start=START,
                end=END,
            )

    def test_missing_site_is_not_silently_treated_as_empty_history(self) -> None:
        with self.assertRaises(TemporalSiteNotFound):
            TemporalProjectionService(
                store=FakeTemporalStore(missing_site=True)
            ).series(
                metric_key="site.assets.new.count",
                site_id="site-missing",
                start=START,
                end=END,
            )

    def test_timezone_equivalent_source_buckets_fail_closed(self) -> None:
        eastern = timezone(timedelta(hours=-4))
        aggregate = ProjectionAggregate(
            value=1,
            evidence_count=1,
            source_observed_at=START + timedelta(hours=1),
            source_received_at=START + timedelta(hours=1),
            complete=True,
        )

        class DuplicateBuckets:
            @staticmethod
            def metric_buckets(**_kwargs):
                class SourceBuckets:
                    @staticmethod
                    def items():
                        return (
                            (START, aggregate),
                            (START.astimezone(eastern), aggregate),
                        )

                return SourceBuckets()

        with self.assertRaisesRegex(TemporalProjectionError, "duplicate normalized"):
            TemporalProjectionService(store=DuplicateBuckets()).series(
                metric_key="site.assets.new.count",
                site_id="site-a",
                start=START,
                end=START + timedelta(days=1),
                generated_at=GENERATED,
            )


class SqlTemporalStoreTests(unittest.TestCase):
    def test_store_uses_fixed_query_and_binds_hostile_site_scope(self) -> None:
        site_result = Mock()
        site_result.scalar_one.return_value = True
        query_result = Mock()
        query_result.mappings.return_value.all.return_value = [
            {
                "bucket_start": START,
                "value": 1,
                "evidence_count": 1,
                "source_observed_at": START + timedelta(hours=1),
                "source_received_at": START + timedelta(hours=1),
                "complete": True,
                "coverage_observed": True,
            }
        ]
        connection = Mock()
        connection.execute.side_effect = [site_result, query_result]
        engine = MagicMock()
        engine.begin.return_value.__enter__.return_value = connection
        store = SqlTemporalStore()
        store._schema_ready = True
        hostile = "site-a' OR TRUE --"

        with patch.object(store, "_engine", return_value=engine):
            result = store.metric_buckets(
                metric=temporal_metric("site.inventory.collections.count"),
                site_id=hostile,
                start=START,
                end=END,
            )

        query_call = connection.execute.call_args_list[1]
        self.assertNotIn(hostile, str(query_call.args[0]))
        self.assertEqual(query_call.args[1]["site_id"], hostile)
        self.assertEqual(result[START].value, 1)

    def test_store_rejects_unregistered_query_selection(self) -> None:
        unregistered = TemporalMetricDefinition(
            metric_key="site.unregistered.count",
            name="Unregistered",
            description="Not admitted to the SQL query map.",
            entity_scope="site",
            unit="count",
            source_authority="test",
            projection_version="1",
            freshness_expectation_seconds=60,
            zero_is_meaningful=False,
            missing_bucket_differs_from_zero=True,
        )
        with self.assertRaisesRegex(ValueError, "unsupported temporal metric query"):
            SqlTemporalStore().metric_buckets(
                metric=unregistered,
                site_id="site-a",
                start=START,
                end=END,
            )

    def test_duplicate_source_buckets_fail_closed(self) -> None:
        rows = [
            {
                "bucket_start": START,
                "value": 1,
                "evidence_count": 1,
                "complete": True,
                "coverage_observed": True,
            },
            {
                "bucket_start": START,
                "value": 1,
                "evidence_count": 1,
                "complete": True,
                "coverage_observed": True,
            },
        ]
        with self.assertRaisesRegex(RuntimeError, "duplicate bucket"):
            SqlTemporalStore._project_rows(rows)

    def test_null_and_naive_source_buckets_fail_closed(self) -> None:
        common = {
            "value": 1,
            "evidence_count": 1,
            "complete": True,
            "coverage_observed": True,
        }
        for bucket in (None, datetime(2026, 8, 24)):
            with self.subTest(bucket=bucket):
                with self.assertRaisesRegex(RuntimeError, "bucket|timezone"):
                    SqlTemporalStore._project_rows(
                        [{"bucket_start": bucket, **common}]
                    )

    def test_retry_safe_source_queries_do_not_count_replay_attempts(self) -> None:
        self.assertIn("COUNT(DISTINCT checkins.agent_id)", COLLECTORS_ACTIVE_SQL)
        self.assertIn("COUNT(canonical_collection_id)", INVENTORY_COLLECTIONS_SQL)
        self.assertNotIn("replay_count)", INVENTORY_COLLECTIONS_SQL)


    def test_as_of_queries_bind_an_exclusive_evidence_cutoff(self) -> None:
        self.assertEqual(
            set(METRIC_QUERIES_AS_OF),
            {metric.metric_key for metric in TEMPORAL_METRICS},
        )
        for metric_key, query in METRIC_QUERIES_AS_OF.items():
            with self.subTest(metric_key=metric_key):
                self.assertIn(":knowledge_cutoff", query)
                self.assertIn("< :knowledge_cutoff", query)

    def test_store_selects_as_of_query_and_binds_cutoff(self) -> None:
        site_result = Mock()
        site_result.scalar_one.return_value = True
        query_result = Mock()
        query_result.mappings.return_value.all.return_value = []
        connection = Mock()
        connection.execute.side_effect = [site_result, query_result]
        engine = MagicMock()
        engine.begin.return_value.__enter__.return_value = connection
        store = SqlTemporalStore()
        store._schema_ready = True

        with patch.object(store, "_engine", return_value=engine):
            store.metric_buckets(
                metric=temporal_metric("site.inventory.collections.count"),
                site_id="site-a",
                start=START,
                end=END,
                knowledge_cutoff=END,
            )

        query_call = connection.execute.call_args_list[1]
        self.assertIn("ingested_at < :knowledge_cutoff", str(query_call.args[0]))
        self.assertEqual(query_call.args[1]["knowledge_cutoff"], END)


if __name__ == "__main__":
    unittest.main()
