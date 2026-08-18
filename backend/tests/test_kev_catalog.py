from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.advisory_bundle import BundleVerificationError, verify_bundle
from app.advisory_feed_registry import FeedSource
from app.kev_catalog import (
    CISA_KEV_LICENSE,
    KevValidationError,
    canonical_kev_bytes,
    changed_cves,
    normalize_cisa_kev_catalog,
    parse_cisa_kev_bytes,
    parse_kev_catalog_bytes,
    preview_kev_catalog,
)
from app.kev_publisher import (
    FileKevSource,
    KevPublisherError,
    KevPublisherState,
    PublishRequest,
    _publisher_state_lock,
    _source_download_policy,
    _verification_registry,
    load_state,
    publish_once,
    sign_kev_bundle,
    write_state,
)


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cisa-kev"
NOW = datetime(2099, 1, 3, 12, 0, tzinfo=timezone.utc)


def source_value(name: str = "catalog-v1.json") -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class CisaKevCatalogTests(unittest.TestCase):
    def test_valid_current_schema_normalizes_deterministically(self) -> None:
        source = parse_cisa_kev_bytes((FIXTURES / "catalog-v1.json").read_bytes())
        catalog = normalize_cisa_kev_catalog(source)
        parsed, digest = parse_kev_catalog_bytes(canonical_kev_bytes(catalog))

        self.assertEqual(parsed, catalog)
        self.assertEqual([item.cve_id for item in catalog.records], sorted(item.cve_id for item in catalog.records))
        self.assertEqual(catalog.records[0].ransomware_campaign_status, "Known")
        self.assertEqual(catalog.records[1].ransomware_campaign_status, "Unknown")
        self.assertEqual(catalog.records[2].ransomware_campaign_status, "Not supplied")
        self.assertEqual(len(digest), 64)

    def test_count_duplicate_cve_and_duplicate_key_fail_closed(self) -> None:
        value = source_value()
        value["count"] = 2
        with self.assertRaisesRegex(KevValidationError, "reviewed schema"):
            parse_cisa_kev_bytes(json.dumps(value).encode())

        value = source_value()
        value["vulnerabilities"][1]["cveID"] = value["vulnerabilities"][0]["cveID"]
        with self.assertRaisesRegex(KevValidationError, "reviewed schema"):
            parse_cisa_kev_bytes(json.dumps(value).encode())

        duplicate = b'{"catalogVersion":"1","catalogVersion":"2","dateReleased":"2099-01-01T00:00:00Z","count":0,"vulnerabilities":[]}'
        with self.assertRaisesRegex(KevValidationError, "duplicate"):
            parse_cisa_kev_bytes(duplicate)

    def test_invalid_cve_dates_unknown_fields_and_bounds_are_rejected(self) -> None:
        mutations = []
        value = source_value()
        value["vulnerabilities"][0]["cveID"] = "CVE-99-fuzzy"
        mutations.append(value)
        value = source_value()
        value["vulnerabilities"][0]["dueDate"] = "2099-02-30"
        mutations.append(value)
        value = source_value()
        value["vulnerabilities"][0]["unreviewed"] = "field"
        mutations.append(value)
        value = source_value()
        value["vulnerabilities"][0]["requiredAction"] = "x" * 4_001
        mutations.append(value)
        value = source_value()
        value["count"] = 10_001
        mutations.append(value)
        for item in mutations:
            with self.assertRaisesRegex(KevValidationError, "reviewed schema"):
                parse_cisa_kev_bytes(json.dumps(item).encode())

    def test_exact_source_policy_and_disabled_mirror_template_are_reviewed(self) -> None:
        policy = _source_download_policy()
        self.assertEqual(policy.endpoint.host, "raw.githubusercontent.com")
        self.assertEqual(
            policy.endpoint.payload_path,
            "/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
        )
        self.assertEqual(policy.adapter_type, "cisa-kev-v1")
        self.assertEqual(policy.expected_payload_schema, "oaw.kev-catalog.v1")
        self.assertEqual(policy.accepted_licenses, ["CC0-1.0"])

        template_path = (
            Path(__file__).resolve().parents[1]
            / "advisory_feeds"
            / "cisa-kev-official-mirror-source.template.json"
        )
        template = FeedSource.model_validate(json.loads(template_path.read_text(encoding="utf-8")))
        self.assertFalse(template.enabled)
        self.assertEqual(template.retrieval_mode, "signed-mirror-index")
        self.assertTrue(all("replace-with-reviewed" in value for value in template.trusted_publisher_key_ids))
        self.assertNotIn("PRIVATE KEY", template_path.read_text(encoding="utf-8"))

    def test_update_preview_and_changed_cves_are_bounded(self) -> None:
        first = normalize_cisa_kev_catalog(parse_cisa_kev_bytes((FIXTURES / "catalog-v1.json").read_bytes()))
        second = normalize_cisa_kev_catalog(parse_cisa_kev_bytes((FIXTURES / "catalog-v2.json").read_bytes()))
        changed = changed_cves(second, first)
        preview = preview_kev_catalog(second, first)

        self.assertEqual(changed, ["CVE-2099-10001", "CVE-2099-10002", "CVE-2099-10004"])
        self.assertEqual(preview["added_records"], 1)
        self.assertEqual(preview["updated_records"], 1)
        self.assertEqual(preview["removed_records"], 1)
        self.assertFalse(preview["local_compromise_claim"])

    def test_signed_bundle_reuses_manifest_verification_and_cc0(self) -> None:
        catalog = normalize_cisa_kev_catalog(parse_cisa_kev_bytes((FIXTURES / "catalog-v1.json").read_bytes()))
        key = Ed25519PrivateKey.generate()
        payload, manifest, signature, verified = sign_kev_bundle(
            catalog,
            source_digest="a" * 64,
            key_id="unit-test-cisa-kev-key",
            private_key=key,
            sequence=7,
            created_at=NOW,
            validity_days=30,
        )

        self.assertEqual(verified.catalog, catalog)
        self.assertEqual(verified.manifest.payload_kind, "kev-prioritization")
        self.assertEqual(verified.manifest.license_identifier, CISA_KEV_LICENSE)
        registry, source = _verification_registry(key_id="unit-test-cisa-kev-key", private_key=key)
        tampered = bytearray(payload)
        tampered[-1] ^= 1
        with self.assertRaisesRegex(BundleVerificationError, "digest"):
            verify_bundle(
                manifest_bytes=manifest,
                signature_bytes=signature,
                payload_bytes=bytes(tampered),
                source=source,
                registry=registry,
                now=NOW,
            )

        manifest_value = json.loads(manifest)
        manifest_value["license_identifier"] = "Apache-2.0"
        wrong_license = json.dumps(
            manifest_value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        wrong_license_signature = base64.b64encode(key.sign(wrong_license)) + b"\n"
        with self.assertRaisesRegex(BundleVerificationError, "license"):
            verify_bundle(
                manifest_bytes=wrong_license,
                signature_bytes=wrong_license_signature,
                payload_bytes=payload,
                source=source,
                registry=registry,
                now=NOW,
            )

        manifest_value = json.loads(manifest)
        manifest_value["source_id"] = "openassetwatch-synthetic-signed"
        wrong_source = json.dumps(
            manifest_value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        wrong_source_signature = base64.b64encode(key.sign(wrong_source)) + b"\n"
        with self.assertRaisesRegex(BundleVerificationError, "source"):
            verify_bundle(
                manifest_bytes=wrong_source,
                signature_bytes=wrong_source_signature,
                payload_bytes=payload,
                source=source,
                registry=registry,
                now=NOW,
            )

    def test_dry_run_is_offline_and_does_not_write_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "publisher-state.json"
            result = publish_once(
                FileKevSource(FIXTURES / "catalog-v1.json"),
                PublishRequest(state_path=state, dry_run=True),
                now=lambda: NOW,
            )
            self.assertEqual(result.status, "dry-run-complete")
            self.assertFalse(state.exists())
            self.assertFalse(result.report["raw_catalog_persisted"])

    def test_catalog_downgrade_and_same_version_replay_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "publisher-state.json"
            root.chmod(0o700)
            write_state(
                state_path,
                KevPublisherState(
                    schema_version="oaw.cisa-kev-publisher-state.v1",
                    source_id="cisa-kev-official",
                    adapter_version="1",
                    run_sequence=4,
                    catalog_version="2099.01.02",
                    catalog_date_released=datetime(2099, 1, 2, 12, 0, tzinfo=timezone.utc),
                    source_digest="b" * 64,
                    payload_digest="c" * 64,
                    last_successful_run_at=NOW,
                ),
            )
            with self.assertRaisesRegex(KevPublisherError, "regressed"):
                publish_once(
                    FileKevSource(FIXTURES / "catalog-v1.json"),
                    PublishRequest(state_path=state_path, dry_run=True),
                    now=lambda: NOW,
                )

            write_state(
                state_path,
                KevPublisherState(
                    schema_version="oaw.cisa-kev-publisher-state.v1",
                    source_id="cisa-kev-official",
                    adapter_version="1",
                    run_sequence=4,
                    catalog_version="2099.01.01",
                    catalog_date_released=datetime(2099, 1, 1, 12, 0, tzinfo=timezone.utc),
                    source_digest="b" * 64,
                    payload_digest="c" * 64,
                    last_successful_run_at=NOW,
                ),
            )
            with self.assertRaisesRegex(KevPublisherError, "without a new catalog version"):
                publish_once(
                    FileKevSource(FIXTURES / "catalog-v1.json"),
                    PublishRequest(state_path=state_path, dry_run=True),
                    now=lambda: NOW,
                )

    def test_absolute_deadline_includes_post_fetch_processing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            values = iter((0.0, 2.0))
            with self.assertRaisesRegex(KevPublisherError, "absolute run deadline"):
                publish_once(
                    FileKevSource(FIXTURES / "catalog-v1.json"),
                    PublishRequest(state_path=Path(directory) / "publisher-state.json", dry_run=True),
                    now=lambda: NOW,
                    total_timeout_seconds=1.0,
                    clock=lambda: next(values),
                )

    def test_sequence_is_reserved_before_output_and_concurrent_run_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            output = root / "output"
            output.mkdir(mode=0o700)
            state_path = root / "publisher-state.json"
            request = PublishRequest(
                state_path=state_path,
                output_root=output,
                key_id="unit-test-cisa-kev-key",
                signing_key_file=root / "unused-test-key",
            )
            key = Ed25519PrivateKey.generate()
            with patch("app.kev_publisher.load_signing_key", return_value=key), patch(
                "app.kev_publisher._publish_output",
                side_effect=KevPublisherError("forced-output-failure", "forced output failure"),
            ):
                with self.assertRaisesRegex(KevPublisherError, "forced output failure"):
                    publish_once(FileKevSource(FIXTURES / "catalog-v1.json"), request, now=lambda: NOW)
            reserved = load_state(state_path)
            self.assertEqual(reserved.run_sequence, 1)
            self.assertEqual(reserved.publication_status, "reserved")

            with _publisher_state_lock(state_path):
                with self.assertRaisesRegex(KevPublisherError, "already holds"):
                    publish_once(FileKevSource(FIXTURES / "catalog-v2.json"), request, now=lambda: NOW)

            with patch("app.kev_publisher.load_signing_key", return_value=key), patch(
                "app.kev_publisher._fsync_directory"
            ) as fsync_directory:
                result = publish_once(FileKevSource(FIXTURES / "catalog-v2.json"), request, now=lambda: NOW)
            fsync_directory.assert_any_call(output)
            self.assertEqual(result.verified_bundle.manifest.catalog_sequence, 2)
            published = load_state(state_path)
            self.assertEqual(published.run_sequence, 2)
            self.assertEqual(published.publication_status, "published")

    def test_state_write_rejects_multiple_links_without_symlink_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            state_path = root / "publisher-state.json"
            state_path.write_text("placeholder", encoding="utf-8")
            second_link = root / "publisher-state-link.json"
            try:
                os.link(state_path, second_link)
            except OSError:
                self.skipTest("hard links are unavailable")
            state = KevPublisherState(
                schema_version="oaw.cisa-kev-publisher-state.v1",
                source_id="cisa-kev-official",
                adapter_version="1",
                run_sequence=1,
                catalog_version="2099.01.01",
                catalog_date_released=datetime(2099, 1, 1, 12, 0, tzinfo=timezone.utc),
                source_digest="a" * 64,
                payload_digest="b" * 64,
                last_successful_run_at=NOW,
            )
            with self.assertRaisesRegex(KevPublisherError, "single-link regular file"):
                write_state(state_path, state)

    def test_state_write_rejects_symlinks_and_multiple_links(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            victim = root / "victim"
            victim.write_text("untouched", encoding="utf-8")
            symlink = root / "publisher-state.json"
            try:
                symlink.symlink_to(victim)
            except OSError:
                self.skipTest("symbolic links are unavailable")
            state = KevPublisherState(
                schema_version="oaw.cisa-kev-publisher-state.v1",
                source_id="cisa-kev-official",
                adapter_version="1",
                run_sequence=1,
                catalog_version="2099.01.01",
                catalog_date_released=datetime(2099, 1, 1, 12, 0, tzinfo=timezone.utc),
                source_digest="a" * 64,
                payload_digest="b" * 64,
                last_successful_run_at=NOW,
            )
            with self.assertRaisesRegex(KevPublisherError, "single-link regular file"):
                write_state(symlink, state)
            self.assertEqual(victim.read_text(encoding="utf-8"), "untouched")
            symlink.unlink()
            state_path = root / "publisher-state.json"
            state_path.write_text("placeholder", encoding="utf-8")
            second_link = root / "publisher-state-link.json"
            try:
                os.link(state_path, second_link)
            except OSError:
                self.skipTest("hard links are unavailable")
            with self.assertRaisesRegex(KevPublisherError, "single-link regular file"):
                write_state(state_path, state)


if __name__ == "__main__":
    unittest.main()
