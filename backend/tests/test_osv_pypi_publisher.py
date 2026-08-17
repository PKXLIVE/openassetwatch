from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import socket
import tempfile
import time
import unittest
from unittest import mock
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.advisory_bundle import BundleVerificationError, verify_bundle
from app.advisory_transport import PinnedHttpsTransport, StagingSecurityError, TransportResponse
from app.osv_pypi_adapter import (
    PRODUCTION_POLICY,
    OsvPublisherError,
    build_catalog,
    canonical_json_bytes,
    format_utc,
    normalize_osv_record,
    parse_modified_index,
    parse_osv_record_bytes,
    record_path,
)
from app.osv_pypi_publisher import (
    OsvHttpClient,
    PublishRequest,
    PublisherLimits,
    build_local_verification_registry,
    load_publisher_state,
    load_signing_key,
    publish_once,
    publisher_report_bytes,
)
from app.version_intelligence import compare_versions, version_satisfies_range


NOW = datetime(2026, 8, 3, 12, 0, tzinfo=timezone.utc)
KEY_ID = "oaw-test-osv-pypi-ed25519-2026-01"
KEY_ENV = "OPENASSETWATCH_TEST_OSV_SIGNING_KEY"


def source_url(record_id: str, package: str = "demo-widget") -> str:
    return (
        "https://github.com/pypa/advisory-database/blob/main/"
        f"vulns/{package}/{record_id}.yaml"
    )


def osv_record(
    record_id: str = "PYSEC-2026-1001",
    *,
    modified: datetime = NOW,
    fixed: str = "2.0.0",
    ecosystem: str = "PyPI",
    purl: str = "pkg:pypi/demo-widget",
    ranges: list[dict] | None = None,
    versions: list[str] | None = None,
    severity: str | None = "HIGH",
) -> dict:
    aliases = (
        ["CVE-2026-1001", "GHSA-2345-6789-cfgh"]
        if record_id == "PYSEC-2026-1001"
        else [f"CVE-{record_id.removeprefix('PYSEC-')}"]
    )
    affected = {
        "package": {
            "ecosystem": ecosystem,
            "name": "demo-widget",
            "purl": purl,
        },
        "ranges": (
            ranges
            if ranges is not None
            else [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": fixed}],
                }
            ]
        ),
        "versions": versions if versions is not None else ["1.0.0", "1.5.0"],
        "ecosystem_specific": ({"severity": severity} if severity else {}),
        "database_specific": {"source": source_url(record_id)},
    }
    return {
        "schema_version": "1.7.3",
        "id": record_id,
        "published": "2026-01-01T00:00:00Z",
        "modified": format_utc(modified),
        "aliases": aliases,
        "upstream": ["CVE-2026-1000"],
        "related": ["CVE-2026-1002"],
        "summary": "Synthetic publisher test advisory",
        "details": "OpenAssetWatch-authored synthetic test data for strict normalization.",
        "affected": [affected],
        "references": [{"type": "WEB", "url": "https://example.com/advisory"}],
        "credits": [
            {
                "name": "Synthetic test author",
                "type": "FINDER",
                "contact": ["https://example.com/researcher"],
            }
        ],
        "database_specific": {},
    }


def record_bytes(**kwargs) -> bytes:
    return canonical_json_bytes(osv_record(**kwargs))


def index_bytes(rows: list[tuple[datetime, str]]) -> bytes:
    return "".join(f"{format_utc(modified)},{record_id}\n" for modified, record_id in rows).encode()


class MemorySource:
    def __init__(self, index: bytes, records: dict[str, bytes]) -> None:
        self.index = index
        self.records = records
        self.requests: list[str] = []

    def fetch_index(self, *, maximum_bytes: int) -> bytes:
        if len(self.index) > maximum_bytes:
            raise OsvPublisherError("fixture-index-too-large", "fixture index exceeds its bound")
        return self.index

    def fetch_record(self, record_id: str, *, maximum_bytes: int) -> bytes:
        self.requests.append(record_id)
        value = self.records[record_id]
        if len(value) > maximum_bytes:
            raise OsvPublisherError("fixture-record-too-large", "fixture record exceeds its bound")
        return value


class FakeTransport:
    def __init__(self, responses) -> None:
        self.responses = list(responses)
        self.calls: list[dict] = []

    def get(self, **kwargs):
        self.calls.append(kwargs)
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


def response(
    body: bytes,
    *,
    status: int = 200,
    content_type: str = "text/csv",
    peer_ip: str = "93.184.216.34",
) -> TransportResponse:
    return TransportResponse(
        status=status,
        headers=(
            ("Content-Type", content_type),
            ("Content-Length", str(len(body))),
        ),
        body_chunks=(body,),
        peer_ip=peer_ip,
        close=lambda: None,
    )


def public_resolver(_host, _port, **_kwargs):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]


def key_material() -> tuple[Ed25519PrivateKey, str]:
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return key, base64.b64encode(raw).decode("ascii")


class ModifiedIndexTests(unittest.TestCase):
    def test_same_timestamp_rows_are_preserved_and_non_pysec_is_reported(self) -> None:
        data = index_bytes(
            [
                (NOW, "GHSA-2345-6789-cfgh"),
                (NOW, "PYSEC-2026-1002"),
                (NOW, "PYSEC-2026-1001"),
            ]
        )
        parsed = parse_modified_index(data)
        self.assertEqual(len(parsed.source_entries), 2)
        self.assertEqual(parsed.highest.record_id, "PYSEC-2026-1002")
        self.assertEqual(parsed.out_of_scope_by_prefix, {"GHSA": 1})
        self.assertEqual(parsed.out_of_scope_total, 1)
        self.assertEqual(parsed.out_of_scope_prefixes_total, 1)
        self.assertIn("GHSA-2345-6789-cfgh", parsed.out_of_scope_samples)

    def test_out_of_scope_report_cardinality_is_truncated_deterministically(self) -> None:
        rows = [(NOW, "PYSEC-2026-1001")]
        rows.extend((NOW, f"X{index:03d}-2026-1") for index in range(100))
        parsed = parse_modified_index(index_bytes(rows), maximum_rows=101)
        self.assertEqual(parsed.out_of_scope_total, 100)
        self.assertEqual(parsed.out_of_scope_prefixes_total, 100)
        self.assertEqual(len(parsed.out_of_scope_by_prefix), 20)
        self.assertEqual(
            list(parsed.out_of_scope_by_prefix),
            [f"X{index:03d}" for index in range(20)],
        )

    def test_duplicate_invalid_traversal_and_wrong_order_fail(self) -> None:
        cases = (
            index_bytes([(NOW, "PYSEC-2026-1001"), (NOW, "PYSEC-2026-1001")]),
            f"{format_utc(NOW)},../PYSEC-2026-1001\n".encode(),
            f"{format_utc(NOW)},https://example.com/x\n".encode(),
            index_bytes(
                [
                    (NOW - timedelta(hours=1), "PYSEC-2026-1001"),
                    (NOW, "PYSEC-2026-1002"),
                ]
            ),
        )
        for data in cases:
            with self.subTest(data=data):
                with self.assertRaises(OsvPublisherError):
                    parse_modified_index(data)

    def test_index_size_and_count_bounds_fail(self) -> None:
        data = index_bytes(
            [(NOW - timedelta(seconds=index), f"PYSEC-2026-{1000 + index}") for index in range(3)]
        )
        with self.assertRaisesRegex(OsvPublisherError, "size"):
            parse_modified_index(data, maximum_bytes=10)
        with self.assertRaisesRegex(OsvPublisherError, "record limit"):
            parse_modified_index(data, maximum_rows=2)

    def test_record_path_accepts_only_bounded_pysec_id(self) -> None:
        self.assertEqual(
            record_path("PYSEC-2026-1001"),
            "/osv-vulnerabilities/PyPI/PYSEC-2026-1001.json",
        )
        for value in ("GHSA-2345-6789-cfgh", "../PYSEC-2026-1", "PYSEC-2026-1?x"):
            with self.assertRaises(OsvPublisherError):
                record_path(value)


class OsvSchemaAndNormalizationTests(unittest.TestCase):
    def parse(self, value: dict | None = None):
        raw = canonical_json_bytes(value or osv_record())
        return parse_osv_record_bytes(raw)

    def test_valid_record_preserves_provenance_ranges_identifiers_and_credits(self) -> None:
        normalized = normalize_osv_record(self.parse(), expected_modified=NOW)
        self.assertEqual(normalized.id, "PYSEC-2026-1001")
        self.assertEqual(normalized.aliases, ["CVE-2026-1001", "GHSA-2345-6789-CFGH"])
        self.assertEqual(normalized.upstream, ["CVE-2026-1000"])
        self.assertEqual(normalized.related, ["CVE-2026-1002"])
        self.assertEqual(normalized.affected[0].identifier, "pkg:pypi/demo-widget")
        self.assertEqual(normalized.affected[0].ranges[0].fixed, "2.0.0")
        self.assertEqual(normalized.affected[0].fixed_versions, ["2.0.0"])
        self.assertEqual(normalized.affected[0].exact_versions, [])
        self.assertEqual(normalized.severity, "high")
        self.assertEqual(normalized.severity_basis, "upstream-categorical")
        self.assertEqual(normalized.source_license, "CC-BY-4.0")
        self.assertEqual(normalized.source_record_url, source_url(normalized.id))
        self.assertEqual(normalized.credits[0].name, "Synthetic test author")

    def test_missing_severity_is_not_invented_and_uses_non_escalating_sentinel(self) -> None:
        normalized = normalize_osv_record(
            self.parse(osv_record(severity=None)),
            expected_modified=NOW,
        )
        self.assertEqual(normalized.severity, "informational")
        self.assertEqual(normalized.severity_basis, "not-reported")
        self.assertIsNone(normalized.upstream_severity)

    def test_explicit_versions_are_preserved_when_no_range_exists(self) -> None:
        normalized = normalize_osv_record(
            self.parse(osv_record(ranges=[], versions=["1.0rc1", "1.0", "1.0.post1"])),
            expected_modified=NOW,
        )
        self.assertEqual(
            normalized.affected[0].exact_versions,
            ["1.0rc1", "1.0", "1.0.post1"],
        )

    def test_ranges_and_explicit_versions_preserve_union_semantics(self) -> None:
        ranges = [
            {
                "type": "ECOSYSTEM",
                "events": [{"introduced": "1.0"}, {"fixed": "2.0"}],
            }
        ]
        normalized = normalize_osv_record(
            self.parse(osv_record(ranges=ranges, versions=["1.5", "3.0"])),
            expected_modified=NOW,
        )
        affected = normalized.affected[0]
        self.assertEqual(affected.exact_versions, ["3.0"])
        self.assertEqual(affected.ranges[0].introduced, "1.0")
        self.assertEqual(
            version_satisfies_range(
                ecosystem="pypi",
                installed_version="3.0",
                introduced=affected.ranges[0].introduced,
                fixed=affected.ranges[0].fixed,
            )[0],
            "fixed",
        )

    def test_introduced_zero_is_an_unbounded_lower_sentinel(self) -> None:
        cases = (
            ([{"introduced": "0"}, {"fixed": "2.0"}], "0.dev1", "affected"),
            ([{"introduced": "0"}, {"last_affected": "2.0"}], "0.dev1", "affected"),
            ([{"introduced": "0"}], "0.dev1", "affected"),
        )
        for events, installed, expected in cases:
            with self.subTest(events=events):
                normalized = normalize_osv_record(
                    self.parse(
                        osv_record(
                            ranges=[{"type": "ECOSYSTEM", "events": events}],
                            versions=[],
                        )
                    ),
                    expected_modified=NOW,
                )
                version_range = normalized.affected[0].ranges[0]
                self.assertTrue(version_range.introduced_unbounded)
                self.assertIsNone(version_range.introduced)
                self.assertEqual(
                    version_satisfies_range(
                        ecosystem="pypi",
                        installed_version=installed,
                        introduced=version_range.introduced,
                        fixed=version_range.fixed,
                        last_affected=version_range.last_affected,
                    )[0],
                    expected,
                )
    def test_compatible_minor_withdrawn_and_vectors_are_supported(self) -> None:
        value = osv_record(severity=None)
        value["schema_version"] = "1.99.0"
        value["withdrawn"] = "2026-08-01T00:00:00Z"
        value["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"}]
        normalized = normalize_osv_record(self.parse(value), expected_modified=NOW)
        self.assertIsNotNone(normalized.withdrawn_at)
        self.assertEqual(normalized.severity_basis, "derived-cvss-v3")
        self.assertEqual(normalized.severity, "medium")
        self.assertEqual(normalized.cvss, 6.5)
        self.assertEqual(normalized.severity_vectors[0].type, "CVSS_V3")

    def test_malformed_or_unsupported_vectors_fail_closed(self) -> None:
        vectors = (
            {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"},
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"},
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N/E:P"},
            {"type": "CVSS_V3", "score": "x" * 301},
        )
        for vector in vectors:
            with self.subTest(vector=vector):
                value = osv_record(severity=None)
                value["severity"] = [vector]
                with self.assertRaises(OsvPublisherError):
                    normalize_osv_record(self.parse(value), expected_modified=NOW)

    def test_wrong_ecosystem_unknown_major_bad_time_bad_purl_and_metadata_fail(self) -> None:
        cases = []
        wrong = osv_record(ecosystem="npm")
        cases.append(wrong)
        major = osv_record()
        major["schema_version"] = "2.0.0"
        cases.append(major)
        bad_time = osv_record()
        bad_time["modified"] = "2026-08-03 12:00:00"
        cases.append(bad_time)
        bad_purl = osv_record(purl="pkg:pypi/other-package")
        cases.append(bad_purl)
        metadata = osv_record()
        metadata["database_specific"] = {"unreviewed": {"nested": "value"}}
        cases.append(metadata)
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(OsvPublisherError):
                    normalize_osv_record(self.parse(value), expected_modified=NOW)

    def test_unsupported_and_inverted_ranges_fail(self) -> None:
        git_range = [
            {
                "type": "GIT",
                "repo": "https://example.com/repo.git",
                "events": [{"introduced": "a" * 40}, {"fixed": "b" * 40}],
            }
        ]
        inverted = [
            {
                "type": "ECOSYSTEM",
                "events": [{"introduced": "2.0.0"}, {"fixed": "1.0.0"}],
            }
        ]
        contradictory = [
            {
                "type": "ECOSYSTEM",
                "events": [{"introduced": "1.0.0"}, {"introduced": "1.1.0"}],
            }
        ]
        for ranges in (git_range, inverted, contradictory):
            with self.subTest(ranges=ranges):
                with self.assertRaises(OsvPublisherError):
                    normalize_osv_record(
                        self.parse(osv_record(ranges=ranges, versions=[])),
                        expected_modified=NOW,
                    )

    def test_duplicate_json_keys_and_oversized_text_fail(self) -> None:
        with self.assertRaisesRegex(OsvPublisherError, "duplicate"):
            parse_osv_record_bytes(
                b'{"schema_version":"1.7.3","schema_version":"1.7.3"}'
            )
        value = osv_record()
        value["details"] = "x" * 64_001
        with self.assertRaises(OsvPublisherError):
            self.parse(value)

    def test_source_and_license_policy_substitution_fails(self) -> None:
        record = self.parse()
        policies = (
            replace(PRODUCTION_POLICY, license_identifier=""),
            replace(PRODUCTION_POLICY, license_identifier="Apache-2.0"),
            replace(PRODUCTION_POLICY, attribution=""),
            replace(PRODUCTION_POLICY, source_name="All OSV sources"),
        )
        for policy in policies:
            with self.subTest(policy=policy):
                with self.assertRaisesRegex(OsvPublisherError, "policy"):
                    normalize_osv_record(record, expected_modified=NOW, policy=policy)
        mismatch = osv_record()
        mismatch["affected"][0]["database_specific"]["source"] = (
            "https://github.com/github/advisory-database/blob/main/advisories/"
            "PYSEC-2026-1001.yaml"
        )
        with self.assertRaisesRegex(OsvPublisherError, "source"):
            normalize_osv_record(self.parse(mismatch), expected_modified=NOW)

    def test_non_pysec_record_is_not_relicensed(self) -> None:
        value = osv_record()
        value["id"] = "GHSA-2345-6789-cfgh"
        with self.assertRaisesRegex(OsvPublisherError, "schema"):
            self.parse(value)

    def test_full_pep440_comparison_includes_local_post_dev_and_epoch(self) -> None:
        cases = (
            ("1.0.dev1", "1.0a1", -1),
            ("1.0", "1.0.post1", -1),
            ("1.0+local.1", "1.0+local.2", -1),
            ("1!1.0", "2.0", 1),
        )
        for left, right, order in cases:
            with self.subTest(left=left, right=right):
                result = compare_versions("pypi", left, right)
                self.assertEqual(result.status, "supported")
                self.assertEqual(result.order, order)


class NetworkBoundaryTests(unittest.TestCase):
    def limits(self, **updates) -> PublisherLimits:
        values = {
            "maximum_records": 10,
            "maximum_index_bytes": 1024,
            "maximum_index_rows": 20,
            "maximum_record_bytes": 1024,
            "maximum_total_bytes": 4096,
            "total_timeout_seconds": 10,
            "retries": 0,
            "concurrency": 1,
        }
        values.update(updates)
        return PublisherLimits(**values)

    def test_valid_exact_host_request_and_descriptive_user_agent(self) -> None:
        body = index_bytes([(NOW, "PYSEC-2026-1001")])
        transport = FakeTransport([response(body)])
        client = OsvHttpClient(
            limits=self.limits(),
            transport=transport,
            resolver=public_resolver,
        )
        self.assertEqual(client.fetch_index(maximum_bytes=1024), body)
        self.assertEqual(transport.calls[0]["host"], "storage.googleapis.com")
        self.assertEqual(transport.calls[0]["path"], "/osv-vulnerabilities/PyPI/modified_id.csv")
        self.assertIn("OSV-PyPI-Publisher", PinnedHttpsTransport(
            user_agent="OpenAssetWatch-OSV-PyPI-Publisher/1"
        ).user_agent)

    def test_redirect_peer_mismatch_content_type_and_size_fail_closed(self) -> None:
        body = b"x"
        cases = (
            response(body, status=302),
            response(body, peer_ip="93.184.216.35"),
            response(body, content_type="text/html"),
            response(b"x" * 1025),
        )
        for item in cases:
            with self.subTest(status=item.status, headers=item.headers):
                client = OsvHttpClient(
                    limits=self.limits(),
                    transport=FakeTransport([item]),
                    resolver=public_resolver,
                )
                with self.assertRaises(OsvPublisherError):
                    client.fetch_index(maximum_bytes=1024)

    def test_mixed_public_private_dns_is_rejected(self) -> None:
        def mixed(_host, _port, **_kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
            ]

        client = OsvHttpClient(
            limits=self.limits(),
            transport=FakeTransport([]),
            resolver=mixed,
        )
        with self.assertRaisesRegex(OsvPublisherError, "prohibited"):
            client.fetch_index(maximum_bytes=1024)

    def test_retry_is_capped_and_jittered(self) -> None:
        body = index_bytes([(NOW, "PYSEC-2026-1001")])
        sleeps: list[float] = []
        transport = FakeTransport(
            [
                response(b"", status=503),
                response(body),
            ]
        )
        client = OsvHttpClient(
            limits=self.limits(retries=1),
            transport=transport,
            resolver=public_resolver,
            sleeper=sleeps.append,
            jitter=lambda _left, _right: 0.1,
        )
        self.assertEqual(client.fetch_index(maximum_bytes=1024), body)
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual(sleeps, [0.35])

    def test_timeout_and_total_byte_budget_fail(self) -> None:
        times = iter([0.0, 0.0, 2.0, 2.0, 2.0])
        client = OsvHttpClient(
            limits=self.limits(total_timeout_seconds=1),
            transport=FakeTransport([response(b"x")]),
            resolver=public_resolver,
            clock=lambda: next(times),
        )
        with self.assertRaisesRegex(OsvPublisherError, "timeout"):
            client.fetch_index(maximum_bytes=1024)

        client = OsvHttpClient(
            limits=self.limits(maximum_total_bytes=1024),
            transport=FakeTransport([response(b"x" * 1024), response(b"x")]),
            resolver=public_resolver,
        )
        client.fetch_index(maximum_bytes=1024)
        with self.assertRaisesRegex(OsvPublisherError, "total download"):
            client.fetch_index(maximum_bytes=1024)

    def test_blocking_resolver_consumes_the_absolute_source_deadline(self) -> None:
        def slow_resolver(*_args, **_kwargs):
            time.sleep(2)
            return []

        client = OsvHttpClient(
            limits=self.limits(total_timeout_seconds=1),
            transport=FakeTransport([]),
            resolver=slow_resolver,
        )
        started = time.monotonic()
        with self.assertRaisesRegex(OsvPublisherError, "deadline"):
            client.fetch_index(maximum_bytes=1024)
        self.assertLess(time.monotonic() - started, 1.5)

    def test_shared_transport_emits_exactly_one_host_header(self) -> None:
        source = (
            Path(__file__).resolve().parents[1] / "app" / "advisory_transport.py"
        ).read_text(encoding="utf-8")
        self.assertIn("skip_host=True", source)
        self.assertIn('connection.putheader("Host", host)', source)


@unittest.skipIf(os.name == "nt", "production signed publishing requires Linux private storage")
class PublisherStateSigningAndOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key, self.key_base64 = key_material()
        self.limits = PublisherLimits(
            maximum_records=10,
            maximum_index_rows=20,
            maximum_total_bytes=5 << 20,
            total_timeout_seconds=30,
            retries=0,
            concurrency=2,
        )

    def publish(
        self,
        source: MemorySource,
        root: Path,
        *,
        full: bool = False,
        now: datetime = NOW,
        sequence_floor: int = 0,
    ):
        return publish_once(
            source,
            PublishRequest(
                state_path=root / "state" / "publisher-state.json",
                output_root=root / "output",
                full=full,
                key_id=KEY_ID,
                signing_key_env=KEY_ENV,
                sequence_floor=sequence_floor,
            ),
            limits=self.limits,
            now=lambda: now,
            environ={KEY_ENV: self.key_base64},
        )

    def test_full_publish_is_atomic_signed_and_accepted_by_existing_verifier(self) -> None:
        source = MemorySource(
            index_bytes([(NOW, "PYSEC-2026-1001")]),
            {"PYSEC-2026-1001": record_bytes()},
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self.publish(source, root, full=True)
            self.assertEqual(result.status, "bundle-complete")
            self.assertIsNotNone(result.bundle_directory)
            output = result.bundle_directory
            assert output is not None
            self.assertEqual(
                {item.name for item in output.iterdir()},
                {"catalog.json", "manifest.json", "manifest.ed25519", "publisher-report.json"},
            )
            self.assertFalse(any(item.name.startswith(".") for item in (root / "output").iterdir()))
            self.assertEqual(result.report["signing"]["key_id"], KEY_ID)
            self.assertEqual(result.report["signing"]["algorithm"], "Ed25519")
            public_key = self.key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            self.assertEqual(
                result.report["signing"]["public_key_base64"],
                base64.b64encode(public_key).decode("ascii"),
            )
            self.assertEqual(
                result.report["signing"]["public_key_sha256"],
                hashlib.sha256(public_key).hexdigest(),
            )
            state = load_publisher_state(root / "state" / "publisher-state.json")
            self.assertIsNotNone(state)
            self.assertEqual(state.run_sequence, 1)
            registry, reviewed_source = build_local_verification_registry(
                policy=PRODUCTION_POLICY,
                key_id=KEY_ID,
                private_key=self.key,
            )
            verified = verify_bundle(
                manifest_bytes=(output / "manifest.json").read_bytes(),
                signature_bytes=(output / "manifest.ed25519").read_bytes(),
                payload_bytes=(output / "catalog.json").read_bytes(),
                source=reviewed_source,
                registry=registry,
                now=NOW,
            )
            self.assertEqual(verified.payload_digest, result.report["catalog"]["payload_sha256"])
            all_output = b"".join(item.read_bytes() for item in output.iterdir())
            self.assertNotIn(self.key_base64.encode(), all_output)
            self.assertNotIn(b"BEGIN PRIVATE KEY", all_output)

    def test_verified_mirror_sequence_floor_seeds_stateless_full_publication(self) -> None:
        source = MemorySource(
            index_bytes([(NOW, "PYSEC-2026-1001")]),
            {"PYSEC-2026-1001": record_bytes()},
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self.publish(source, root, full=True, sequence_floor=41)
            self.assertEqual(result.verified_bundle.manifest.catalog_sequence, 42)
            state = load_publisher_state(root / "state" / "publisher-state.json")
            self.assertEqual(state.run_sequence, 42)

    def test_same_timestamp_new_record_is_not_skipped(self) -> None:
        first = MemorySource(
            index_bytes([(NOW, "PYSEC-2026-1001")]),
            {"PYSEC-2026-1001": record_bytes()},
        )
        second_record = record_bytes(
            record_id="PYSEC-2026-1002",
            modified=NOW,
        )
        second = MemorySource(
            index_bytes(
                [
                    (NOW, "PYSEC-2026-1002"),
                    (NOW, "PYSEC-2026-1001"),
                ]
            ),
            {
                "PYSEC-2026-1001": record_bytes(),
                "PYSEC-2026-1002": second_record,
            },
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.publish(first, root, full=True)
            result = self.publish(second, root, now=NOW + timedelta(minutes=1))
            self.assertEqual(result.report["catalog"]["advisory_count"], 2)
            self.assertIn("PYSEC-2026-1002", second.requests)
            state = load_publisher_state(root / "state" / "publisher-state.json")
            self.assertEqual(state.cursor.record_id, "PYSEC-2026-1002")

    def test_deterministic_payload_and_incremental_overlap(self) -> None:
        parsed = parse_osv_record_bytes(record_bytes())
        normalized = normalize_osv_record(parsed, expected_modified=NOW)
        first = build_catalog([normalized], highest_modified=NOW)
        second = build_catalog([normalized], highest_modified=NOW)
        self.assertEqual(first.payload_bytes, second.payload_bytes)
        self.assertEqual(first.payload_digest, second.payload_digest)

        source = MemorySource(
            index_bytes([(NOW, "PYSEC-2026-1001")]),
            {"PYSEC-2026-1001": record_bytes()},
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.publish(source, root, full=True)
            repeated = MemorySource(source.index, dict(source.records))
            result = self.publish(repeated, root, now=NOW + timedelta(minutes=5))
            self.assertEqual(result.report["mode"], "incremental")
            self.assertEqual(repeated.requests, ["PYSEC-2026-1001"])
            self.assertEqual(
                result.report["catalog"]["payload_sha256"],
                first.payload_digest,
            )

    def test_cursor_corruption_rollback_and_gap_fail_safely(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_dir = root / "state"
            state_dir.mkdir(mode=0o700)
            state_path = state_dir / "publisher-state.json"
            state_path.write_text("{not-json", encoding="utf-8")
            with self.assertRaisesRegex(OsvPublisherError, "invalid"):
                load_publisher_state(state_path)

        source = MemorySource(
            index_bytes([(NOW, "PYSEC-2026-1001")]),
            {"PYSEC-2026-1001": record_bytes()},
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.publish(source, root, full=True)
            older = MemorySource(
                index_bytes([(NOW - timedelta(days=1), "PYSEC-2026-1001")]),
                {
                    "PYSEC-2026-1001": record_bytes(
                        modified=NOW - timedelta(days=1)
                    )
                },
            )
            with self.assertRaisesRegex(OsvPublisherError, "older"):
                self.publish(older, root, now=NOW + timedelta(minutes=1))
            gap = MemorySource(
                index_bytes(
                    [
                        (NOW, "PYSEC-2026-1001"),
                        (NOW - timedelta(days=2), "PYSEC-2025-9999"),
                    ]
                ),
                {
                    "PYSEC-2026-1001": record_bytes(),
                    "PYSEC-2025-9999": record_bytes(
                        record_id="PYSEC-2025-9999",
                        modified=NOW - timedelta(days=2),
                    ),
                },
            )
            with self.assertRaisesRegex(OsvPublisherError, "skip"):
                self.publish(gap, root, now=NOW + timedelta(minutes=1))

    def test_non_cursor_timestamp_and_withdrawal_rollback_preserve_state(self) -> None:
        first_modified = NOW - timedelta(hours=1)
        withdrawn = osv_record(modified=first_modified)
        withdrawn["withdrawn"] = "2026-07-01T00:00:00Z"
        first = MemorySource(
            index_bytes(
                [
                    (NOW, "PYSEC-2026-1002"),
                    (first_modified, "PYSEC-2026-1001"),
                ]
            ),
            {
                "PYSEC-2026-1001": canonical_json_bytes(withdrawn),
                "PYSEC-2026-1002": record_bytes(record_id="PYSEC-2026-1002"),
            },
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.publish(first, root, full=True)
            state_path = root / "state" / "publisher-state.json"
            before = hashlib.sha256(state_path.read_bytes()).hexdigest()

            regressed = MemorySource(
                index_bytes(
                    [
                        (NOW, "PYSEC-2026-1002"),
                        (first_modified - timedelta(days=2), "PYSEC-2026-1001"),
                    ]
                ),
                {"PYSEC-2026-1002": record_bytes(record_id="PYSEC-2026-1002")},
            )
            with self.assertRaisesRegex(OsvPublisherError, "regressed"):
                self.publish(regressed, root, now=NOW + timedelta(minutes=1))
            self.assertEqual(hashlib.sha256(state_path.read_bytes()).hexdigest(), before)

            later = NOW + timedelta(hours=1)
            withdrawal_removed = MemorySource(
                index_bytes(
                    [
                        (later, "PYSEC-2026-1001"),
                        (NOW, "PYSEC-2026-1002"),
                    ]
                ),
                {
                    "PYSEC-2026-1001": record_bytes(modified=later),
                    "PYSEC-2026-1002": record_bytes(record_id="PYSEC-2026-1002"),
                },
            )
            with self.assertRaisesRegex(OsvPublisherError, "withdrawal"):
                self.publish(withdrawal_removed, root, now=later)
            self.assertEqual(hashlib.sha256(state_path.read_bytes()).hexdigest(), before)

    def test_full_rebuild_handles_reviewed_removal(self) -> None:
        first = MemorySource(
            index_bytes([(NOW, "PYSEC-2026-1001")]),
            {"PYSEC-2026-1001": record_bytes()},
        )
        later = NOW + timedelta(hours=1)
        second = MemorySource(
            index_bytes([(later, "PYSEC-2026-1002")]),
            {
                "PYSEC-2026-1002": record_bytes(
                    record_id="PYSEC-2026-1002",
                    modified=later,
                )
            },
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.publish(first, root, full=True)
            with self.assertRaisesRegex(OsvPublisherError, "previously published"):
                self.publish(second, root, now=later)
            rebuilt = self.publish(second, root, full=True, now=later)
            self.assertEqual(rebuilt.report["catalog"]["advisory_count"], 1)
            state = load_publisher_state(root / "state" / "publisher-state.json")
            self.assertEqual([item.id for item in state.records], ["PYSEC-2026-1002"])

    def test_invalid_record_preserves_previous_state_and_output(self) -> None:
        source = MemorySource(
            index_bytes([(NOW, "PYSEC-2026-1001")]),
            {"PYSEC-2026-1001": record_bytes()},
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.publish(source, root, full=True)
            state_path = root / "state" / "publisher-state.json"
            state_before = hashlib.sha256(state_path.read_bytes()).hexdigest()
            output_before = sorted(item.name for item in (root / "output").iterdir())
            later = NOW + timedelta(hours=1)
            bad = osv_record(modified=later)
            bad["affected"][0]["package"]["purl"] = "pkg:pypi/other"
            failing = MemorySource(
                index_bytes([(later, "PYSEC-2026-1001")]),
                {"PYSEC-2026-1001": canonical_json_bytes(bad)},
            )
            with self.assertRaises(OsvPublisherError):
                self.publish(failing, root, now=later)
            self.assertEqual(hashlib.sha256(state_path.read_bytes()).hexdigest(), state_before)
            self.assertEqual(
                sorted(item.name for item in (root / "output").iterdir()),
                output_before,
            )

    def test_dry_run_does_not_write_state_or_output(self) -> None:
        source = MemorySource(
            index_bytes([(NOW, "PYSEC-2026-1001")]),
            {"PYSEC-2026-1001": record_bytes()},
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = publish_once(
                source,
                PublishRequest(
                    state_path=root / "state" / "publisher-state.json",
                    output_root=None,
                    full=True,
                    dry_run=True,
                ),
                limits=self.limits,
                now=lambda: NOW,
            )
            self.assertEqual(result.status, "dry-run-complete")
            self.assertEqual(result.report["signing"], {"status": "not-requested"})
            self.assertFalse((root / "state").exists())
            self.assertFalse((root / "output").exists())

    def test_output_symlink_is_rejected(self) -> None:
        source = MemorySource(
            index_bytes([(NOW, "PYSEC-2026-1001")]),
            {"PYSEC-2026-1001": record_bytes()},
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "destination"
            destination.mkdir()
            output = root / "output"
            try:
                output.symlink_to(destination, target_is_directory=True)
            except OSError:
                self.skipTest("directory symlinks are unavailable")
            with self.assertRaisesRegex(StagingSecurityError, "links"):
                publish_once(
                    source,
                    PublishRequest(
                        state_path=root / "state" / "publisher-state.json",
                        output_root=output,
                        full=True,
                        key_id=KEY_ID,
                        signing_key_env=KEY_ENV,
                    ),
                    limits=self.limits,
                    now=lambda: NOW,
                    environ={KEY_ENV: self.key_base64},
                )

    def test_signing_key_symlink_hardlink_permissions_and_tamper(self) -> None:
        with self.assertRaisesRegex(OsvPublisherError, "canonical base64"):
            load_signing_key(
                key_file=None,
                environment_name=KEY_ENV,
                environ={KEY_ENV: "not-ascii-\N{SNOWMAN}"},
            )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            key_file = root / "key"
            key_file.write_text(self.key_base64, encoding="ascii")
            if os.name != "nt":
                key_file.chmod(0o600)
            loaded = load_signing_key(key_file=key_file, environment_name=None)
            self.assertEqual(
                loaded.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                ),
                self.key.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                ),
            )
            hard = root / "hard"
            os.link(key_file, hard)
            with self.assertRaisesRegex(OsvPublisherError, "single-link"):
                load_signing_key(key_file=hard, environment_name=None)
            try:
                link = root / "link"
                link.symlink_to(key_file)
            except OSError:
                link = None
            if link is not None:
                with self.assertRaisesRegex(OsvPublisherError, "single-link"):
                    load_signing_key(key_file=link, environment_name=None)
            if os.name != "nt":
                solo = root / "solo"
                solo.write_text(self.key_base64, encoding="ascii")
                solo.chmod(0o644)
                with self.assertRaisesRegex(OsvPublisherError, "permissions"):
                    load_signing_key(key_file=solo, environment_name=None)

        source = MemorySource(
            index_bytes([(NOW, "PYSEC-2026-1001")]),
            {"PYSEC-2026-1001": record_bytes()},
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self.publish(source, root, full=True)
            output = result.bundle_directory
            assert output is not None
            registry, reviewed_source = build_local_verification_registry(
                policy=PRODUCTION_POLICY,
                key_id=KEY_ID,
                private_key=self.key,
            )
            payload = bytearray((output / "catalog.json").read_bytes())
            payload[-1] ^= 1
            with self.assertRaises(BundleVerificationError):
                verify_bundle(
                    manifest_bytes=(output / "manifest.json").read_bytes(),
                    signature_bytes=(output / "manifest.ed25519").read_bytes(),
                    payload_bytes=bytes(payload),
                    source=reviewed_source,
                    registry=registry,
                    now=NOW,
                )


class CliIsolationTests(unittest.TestCase):
    def test_cli_is_one_shot_and_endpoints_are_not_configurable(self) -> None:
        cli = (
            Path(__file__).resolve().parents[2]
            / "scripts"
            / "publish_osv_pypi_advisories.py"
        ).read_text(encoding="utf-8")
        self.assertIn('"live-smoke"', cli)
        self.assertIn('"sync"', cli)
        self.assertNotIn("--host", cli)
        self.assertNotIn("--url", cli)
        self.assertNotIn("schedule", cli.casefold())

    def test_publisher_is_not_imported_by_backend_startup_or_ai(self) -> None:
        backend = Path(__file__).resolve().parents[1] / "app"
        for name in ("main.py", "ai_advisor.py", "vulnerability_matching.py"):
            source = (backend / name).read_text(encoding="utf-8")
            self.assertNotIn("osv_pypi_publisher", source)
            self.assertNotIn("api.osv.dev", source)

    def test_raw_filesystem_errors_are_redacted_at_cli_boundary(self) -> None:
        cli_path = (
            Path(__file__).resolve().parents[2]
            / "scripts"
            / "publish_osv_pypi_advisories.py"
        )
        spec = importlib.util.spec_from_file_location("oaw_osv_publisher_cli_test", cli_path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        emitted: list[dict] = []
        private_path = str(Path.cwd() / "private" / "publisher-key.pem")
        with (
            mock.patch.object(module, "_sync", side_effect=PermissionError(private_path)),
            mock.patch.object(
                module,
                "_emit",
                side_effect=lambda value, **_kwargs: emitted.append(value),
            ),
        ):
            result = module.main(
                [
                    "sync",
                    "--state",
                    str(Path.cwd() / "publisher-state.json"),
                    "--dry-run",
                    "--json",
                ]
            )
        self.assertEqual(result, 2)
        self.assertEqual(emitted[0]["code"], "internal-error")
        self.assertNotIn(private_path, json.dumps(emitted[0]))


class PublisherSafetyBoundaryTests(unittest.TestCase):
    def test_native_windows_production_signing_fails_closed(self) -> None:
        source = MemorySource(
            index_bytes([(NOW, "PYSEC-2026-1001")]),
            {"PYSEC-2026-1001": record_bytes()},
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch(
                "app.osv_pypi_publisher._native_windows",
                return_value=True,
            ):
                with self.assertRaisesRegex(OsvPublisherError, "Windows"):
                    publish_once(
                        source,
                        PublishRequest(
                            state_path=root / "state" / "publisher-state.json",
                            output_root=root / "output",
                            full=True,
                            key_id=KEY_ID,
                            signing_key_env=KEY_ENV,
                        ),
                        now=lambda: NOW,
                        environ={KEY_ENV: key_material()[1]},
                    )
            self.assertFalse((root / "state").exists())
            self.assertFalse((root / "output").exists())

    def test_serialized_status_bytes_are_enforced(self) -> None:
        with self.assertRaisesRegex(OsvPublisherError, "byte limit"):
            publisher_report_bytes({"status": "x", "detail": "a" * (256 << 10)})

    @unittest.skipIf(os.name == "nt", "POSIX signal deadline is validated on Linux")
    def test_absolute_run_deadline_covers_non_http_source_work(self) -> None:
        class SlowSource(MemorySource):
            def fetch_index(self, *, maximum_bytes: int) -> bytes:
                time.sleep(2)
                return super().fetch_index(maximum_bytes=maximum_bytes)

        source = SlowSource(
            index_bytes([(NOW, "PYSEC-2026-1001")]),
            {"PYSEC-2026-1001": record_bytes()},
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            started = time.monotonic()
            with self.assertRaisesRegex(OsvPublisherError, "absolute run deadline"):
                publish_once(
                    source,
                    PublishRequest(
                        state_path=root / "state" / "publisher-state.json",
                        output_root=None,
                        full=True,
                        dry_run=True,
                    ),
                    limits=PublisherLimits(total_timeout_seconds=1, retries=0),
                    now=lambda: NOW,
                )
            self.assertLess(time.monotonic() - started, 1.5)


if __name__ == "__main__":
    unittest.main()
