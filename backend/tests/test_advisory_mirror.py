from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.advisory_feed_registry import (
    FeedRegistryDocument,
    FeedSource,
    MirrorEndpoint,
    PublisherKey,
    PublisherKeyringDocument,
    RegistryError,
    ReviewedFeedRegistry,
    load_reviewed_feed_registry,
)
from app.advisory_mirror import (
    AdvisoryMirrorIndex,
    MirrorSecurityError,
    build_advisory_mirror,
    canonical_json_bytes,
    load_existing_mirror,
    parse_mirror_index,
    snapshot_advisory_mirror,
    verify_mirror_artifact,
    verify_mirror_index,
    verify_publication_continuity,
)
from app.advisory_sync_service import AdvisorySyncService
from app.advisory_transport import AdvisoryDownloader, DownloadSecurityError, PrivateStagingArea


NOW = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)
FEED_ROOT = Path(__file__).resolve().parents[1] / "advisory_feeds"
CATALOG_FIXTURE = FEED_ROOT / "fixtures" / "openassetwatch-synthetic-signed" / "catalog.json"
BUNDLE_KEY_ID = "oaw-mirror-bundle-test-ed25519-2026-01"
INDEX_KEY_ID = "oaw-mirror-index-test-ed25519-2026-01"


def _mirror_registry(
    bundle_key: Ed25519PrivateKey,
    index_key: Ed25519PrivateKey,
    *,
    enabled: bool = True,
) -> tuple[ReviewedFeedRegistry, FeedSource]:
    direct = load_reviewed_feed_registry().source("openassetwatch-synthetic-signed")
    source_data = direct.model_dump(mode="json")
    source_data.update(
        enabled=enabled,
        retrieval_mode="signed-mirror-index",
        expected_index_schema="oaw.advisory-mirror-index.v1",
        minimum_supported_openassetwatch_version="0.1.0",
        endpoint=None,
        mirror=MirrorEndpoint(
            host="advisories.openassetwatch.invalid",
            index_path="/v1/synthetic/index.json",
            signature_path="/v1/synthetic/index.ed25519",
            trusted_index_key_ids=[INDEX_KEY_ID],
        ).model_dump(mode="json"),
    )
    source_data["trusted_publisher_key_ids"] = [BUNDLE_KEY_ID]
    source_data["expected_content_types"].update(
        index=["application/json"],
        index_signature=["application/octet-stream", "text/plain"],
    )
    source = FeedSource.model_validate(source_data)
    def publisher(key_id: str, name: str, key: Ed25519PrivateKey) -> PublisherKey:
        public = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return PublisherKey(
            key_id=key_id,
            publisher_id="openassetwatch-mirror-tests",
            publisher_name=name,
            algorithm="ed25519",
            public_key_base64=base64.b64encode(public).decode("ascii"),
            status="active",
            not_before=NOW - timedelta(days=1),
            not_after=NOW + timedelta(days=90),
        )
    registry = ReviewedFeedRegistry(
        FeedRegistryDocument(
            schema_version="oaw.advisory-feed-registry.v1",
            registry_version="mirror-test",
            sources=[source],
        ),
        PublisherKeyringDocument(
            schema_version="oaw.advisory-publisher-keyring.v1",
            keyring_version="mirror-test",
            keys=[
                publisher(BUNDLE_KEY_ID, "OpenAssetWatch Ephemeral Bundle Test Key", bundle_key),
                publisher(INDEX_KEY_ID, "OpenAssetWatch Ephemeral Index Test Key", index_key),
            ],
        ),
    )
    return registry, source


def _write_bundle(
    root: Path,
    *,
    key: Ed25519PrivateKey,
    source: FeedSource,
    sequence: int,
) -> Path:
    catalog = json.loads(CATALOG_FIXTURE.read_bytes())
    catalog["catalog_version"] = f"mirror-fixture-{sequence}"
    payload = canonical_json_bytes(catalog)
    created = NOW + timedelta(minutes=sequence)
    aliases = sum(len(item.get("aliases", [])) for item in catalog["advisories"])
    references = sum(len(item.get("references", [])) for item in catalog["advisories"])
    manifest = {
        "schema_id": "oaw.advisory-bundle.manifest.v1",
        "schema_version": 1,
        "source_id": source.source_id,
        "publisher_key_id": BUNDLE_KEY_ID,
        "catalog_version": catalog["catalog_version"],
        "catalog_sequence": sequence,
        "created_at": created.isoformat().replace("+00:00", "Z"),
        "expires_at": (created + timedelta(days=30)).isoformat().replace("+00:00", "Z"),
        "payload_name": "catalog.json",
        "payload_media_type": "application/vnd.openassetwatch.advisory-catalog+json",
        "payload_compression": "none",
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "compressed_bytes": len(payload),
        "uncompressed_bytes": len(payload),
        "advisory_count": len(catalog["advisories"]),
        "alias_count": aliases,
        "reference_count": references,
        "license_identifier": source.accepted_licenses[0],
        "attribution": source.required_attribution,
        "upstream_provenance": {
            "source_name": catalog["source"]["name"],
            "source_version": catalog["source"]["version"],
            "dataset_id": f"mirror-test:{sequence}",
            "retrieved_at": created.isoformat().replace("+00:00", "Z"),
        },
        "adapter_version": source.adapter_version,
        "minimum_supported_catalog_version": 1,
    }
    manifest_bytes = canonical_json_bytes(manifest)
    signature = base64.b64encode(key.sign(manifest_bytes)) + b"\n"
    directory = root / f"bundle-{sequence}"
    directory.mkdir()
    (directory / "manifest.json").write_bytes(manifest_bytes)
    (directory / "manifest.ed25519").write_bytes(signature)
    (directory / "catalog.json").write_bytes(payload)
    return directory.absolute()


class AdvisoryMirrorSchemaAndBuilderTests(unittest.TestCase):
    def test_builder_verifies_exact_bytes_and_retains_three_prior_catalogs(self) -> None:
        key = Ed25519PrivateKey.generate()
        index_key = Ed25519PrivateKey.generate()
        registry, source = _mirror_registry(key, index_key)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundles = [
                _write_bundle(root, key=key, source=source, sequence=sequence)
                for sequence in range(1, 6)
            ]
            output = (root / "public-mirror").absolute()
            result = build_advisory_mirror(
                bundle_directories=bundles,
                output_directory=output,
                source=source,
                registry=registry,
                index_signing_key_id=INDEX_KEY_ID,
                index_signing_key=index_key,
                published_at=NOW + timedelta(hours=1),
                retain_prior=3,
            )
            self.assertEqual([item.catalog_sequence for item in result.index.catalogs], [2, 3, 4, 5])
            self.assertEqual(result.retained_prior_catalogs, 3)
            self.assertEqual(result.index.adapter_version, source.adapter_version)
            self.assertEqual(result.index.minimum_supported_catalog_version, 1)
            self.assertEqual(result.index.minimum_supported_openassetwatch_version, "0.1.0")
            self.assertEqual(result.retained_catalog_sequences, (2, 3, 4, 5))
            self.assertEqual(result.removed_catalog_sequences, (1,))
            self.assertEqual(result.report()["removed_catalog_sequences"], [1])
            verified = load_existing_mirror(
                output,
                source=source,
                registry=registry,
                now=NOW + timedelta(hours=1),
            )
            self.assertEqual([item.bundle.manifest.catalog_sequence for item in verified], [2, 3, 4, 5])
            self.assertEqual(
                sorted(path.name for path in output.iterdir()),
                ["catalogs", "index.ed25519", "index.json"],
            )
            self.assertNotIn("PRIVATE KEY", "\n".join(path.read_text(errors="ignore") for path in output.rglob("*") if path.is_file()))

    def test_index_rejects_noncanonical_tampered_stale_and_unsafe_metadata(self) -> None:
        key = Ed25519PrivateKey.generate()
        index_key = Ed25519PrivateKey.generate()
        registry, source = _mirror_registry(key, index_key)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = _write_bundle(root, key=key, source=source, sequence=1)
            output = (root / "mirror").absolute()
            build_advisory_mirror(
                bundle_directories=[bundle],
                output_directory=output,
                source=source,
                registry=registry,
                index_signing_key_id=INDEX_KEY_ID,
                index_signing_key=index_key,
                published_at=NOW + timedelta(minutes=2),
            )
            index_bytes = (output / "index.json").read_bytes()
            signature = (output / "index.ed25519").read_bytes()
            parsed = parse_mirror_index(index_bytes, maximum_bytes=source.limits.maximum_mirror_index_bytes)
            self.assertEqual(parsed.schema_id, "oaw.advisory-mirror-index.v1")
            with self.assertRaisesRegex(MirrorSecurityError, "canonical"):
                parse_mirror_index(
                    json.dumps(json.loads(index_bytes), indent=2).encode("utf-8"),
                    maximum_bytes=source.limits.maximum_mirror_index_bytes,
                )
            with self.assertRaisesRegex(MirrorSecurityError, "signature"):
                verify_mirror_index(
                    index_bytes=index_bytes,
                    signature_bytes=base64.b64encode(b"x" * 64) + b"\n",
                    source=source,
                    registry=registry,
                    now=NOW + timedelta(minutes=2),
                )
            with self.assertRaisesRegex(MirrorSecurityError, "stale"):
                verify_mirror_index(
                    index_bytes=index_bytes,
                    signature_bytes=signature,
                    source=source,
                    registry=registry,
                    now=NOW + timedelta(days=40),
                )
            unsafe = parsed.model_dump(mode="json")
            unsafe["catalogs"][0]["manifest_path"] = "catalogs/../manifest.json"
            with self.assertRaises(ValueError):
                AdvisoryMirrorIndex.model_validate(unsafe)
            with self.assertRaisesRegex(MirrorSecurityError, "size|digest"):
                verify_mirror_artifact(parsed.latest, "payload", b"substituted")
            with self.assertRaisesRegex(DownloadSecurityError, "artifact kind"):
                AdvisoryDownloader().fetch_mirror_artifact(
                    source,
                    "manifest",
                    parsed.latest.signature_path,
                )

    def test_builder_rejects_output_replacement_hard_links_and_missing_history(self) -> None:
        key = Ed25519PrivateKey.generate()
        index_key = Ed25519PrivateKey.generate()
        registry, source = _mirror_registry(key, index_key)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = _write_bundle(root, key=key, source=source, sequence=1)
            with self.assertRaisesRegex(MirrorSecurityError, "more than once"):
                build_advisory_mirror(
                    bundle_directories=[bundle, bundle],
                    output_directory=(root / "duplicate-output").absolute(),
                    source=source,
                    registry=registry,
                    index_signing_key_id=INDEX_KEY_ID,
                    index_signing_key=index_key,
                    published_at=NOW + timedelta(minutes=2),
                )
            existing_target = (root / "existing").absolute()
            existing_target.mkdir()
            marker = existing_target / "operator-owned.txt"
            marker.write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(MirrorSecurityError, "exists"):
                build_advisory_mirror(
                    bundle_directories=[bundle],
                    output_directory=existing_target,
                    source=source,
                    registry=registry,
                    index_signing_key_id=INDEX_KEY_ID,
                    index_signing_key=index_key,
                    published_at=NOW + timedelta(minutes=2),
                )
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")

            linked = bundle / "manifest-hardlink.json"
            os.link(bundle / "manifest.json", linked)
            with self.assertRaisesRegex(Exception, "single-link"):
                build_advisory_mirror(
                    bundle_directories=[bundle],
                    output_directory=(root / "hardlink-output").absolute(),
                    source=source,
                    registry=registry,
                    index_signing_key_id=INDEX_KEY_ID,
                    index_signing_key=index_key,
                    published_at=NOW + timedelta(minutes=2),
                )
            linked.unlink()

            mirror = (root / "complete").absolute()
            build_advisory_mirror(
                bundle_directories=[bundle],
                output_directory=mirror,
                source=source,
                registry=registry,
                index_signing_key_id=INDEX_KEY_ID,
                index_signing_key=index_key,
                published_at=NOW + timedelta(minutes=2),
            )
            with self.assertRaisesRegex(MirrorSecurityError, "does not advance"):
                build_advisory_mirror(
                    bundle_directories=[bundle],
                    existing_mirror_root=mirror,
                    output_directory=(root / "not-advanced").absolute(),
                    source=source,
                    registry=registry,
                    index_signing_key_id=INDEX_KEY_ID,
                    index_signing_key=index_key,
                    published_at=NOW + timedelta(minutes=3),
                )
            next(mirror.glob("catalogs/*/catalog.json")).unlink()
            with self.assertRaises(Exception):
                load_existing_mirror(
                    mirror,
                    source=source,
                    registry=registry,
                    now=NOW + timedelta(minutes=2),
                )

    def test_official_source_template_is_strict_disabled_and_contains_no_key(self) -> None:
        data = json.loads((FEED_ROOT / "official-mirror-source.template.json").read_bytes())
        source = FeedSource.model_validate(data)
        self.assertFalse(source.enabled)
        self.assertEqual(source.retrieval_mode, "signed-mirror-index")
        self.assertTrue(source.mirror.host.endswith(".invalid"))
        self.assertEqual(
            source.mirror.artifact_path("catalogs/1/catalog.json"),
            "/v1/osv-pypi/catalogs/1/catalog.json",
        )
        text = json.dumps(data)
        self.assertNotIn("PRIVATE KEY", text)
        self.assertNotIn("private_key", text)

    def test_registry_requires_distinct_bundle_and_index_key_material(self) -> None:
        shared_key = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(RegistryError, "material must be distinct"):
            _mirror_registry(shared_key, shared_key)

    def test_publication_checkpoint_rejects_replay_and_sequence_equivocation(self) -> None:
        checkpoint = canonical_json_bytes(
            {
                "schema_version": "oaw.advisory-mirror-publication-checkpoint.v1",
                "source_id": "osv-pypi-pysec-signed",
                "latest_catalog_sequence": 42,
                "index_sha256": "a" * 64,
            }
        )

        def snapshot(sequence: int, digest: str) -> bytes:
            return canonical_json_bytes(
                {
                    "schema_version": "oaw.advisory-mirror-snapshot-report.v1",
                    "status": "snapshot-complete",
                    "source_id": "osv-pypi-pysec-signed",
                    "index_sha256": digest,
                    "catalog_count": 4,
                    "latest_catalog_version": f"catalog-{sequence}",
                    "latest_catalog_sequence": sequence,
                    "output_directory_name": "verified-prior-mirror",
                }
            )

        result = verify_publication_continuity(
            checkpoint_bytes=checkpoint,
            snapshot_report_bytes=snapshot(42, "a" * 64),
            time_floor=1_000,
        )
        self.assertEqual(result["sequence_floor"], 1_000)
        with self.assertRaisesRegex(MirrorSecurityError, "older than trusted checkpoint"):
            verify_publication_continuity(
                checkpoint_bytes=checkpoint,
                snapshot_report_bytes=snapshot(41, "b" * 64),
                time_floor=1_000,
            )
        with self.assertRaisesRegex(MirrorSecurityError, "digest conflicts"):
            verify_publication_continuity(
                checkpoint_bytes=checkpoint,
                snapshot_report_bytes=snapshot(42, "b" * 64),
                time_floor=1_000,
            )


class _MirrorDownloader:
    def __init__(self, root: Path, index: AdvisoryMirrorIndex) -> None:
        self.root = root
        self.index = index
        self.calls: list[tuple[str, str | None]] = []

    def fetch(self, _source, kind, **_kwargs):
        self.calls.append((kind, None))
        name = "index.json" if kind == "index" else "index.ed25519"
        return SimpleNamespace(body=(self.root / name).read_bytes())

    def fetch_mirror_artifact(self, _source, kind, relative_path, **_kwargs):
        self.calls.append((kind, relative_path))
        return SimpleNamespace(body=(self.root / Path(*relative_path.split("/"))).read_bytes())


class _RemoteStore:
    def __init__(self) -> None:
        self.run = {
            "run_id": "afrun_" + "a" * 32,
            "source_id": "openassetwatch-synthetic-signed",
            "request_mode": "remote-sync",
            "state": "created",
        }
        self.saved: dict | None = None

    def get_run(self, _run_id, *, include_preview=False):
        result = dict(self.run)
        if include_preview and self.saved is not None:
            result["preview"] = self.saved["preview"]
        return result

    def transition(self, _run_id, *, expected_states, state, values=None, now=None):
        if self.run["state"] not in expected_states:
            raise ValueError("unexpected test state")
        self.run.update(values or {})
        self.run["state"] = state

    def fail_run(self, _run_id, **_kwargs):
        self.run["state"] = "failed"

    def active_catalog(self, _source_id, *, include_bytes=False):
        return None

    def save_verified_bundle(self, **kwargs):
        self.saved = kwargs
        self.run.update(state="pending_approval", catalog_version=kwargs["catalog_version"])


class AdvisoryMirrorHubContractTests(unittest.TestCase):
    def test_snapshot_preserves_verified_history_and_leaves_no_partial_target(self) -> None:
        key = Ed25519PrivateKey.generate()
        index_key = Ed25519PrivateKey.generate()
        registry, source = _mirror_registry(key, index_key)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundles = [
                _write_bundle(root, key=key, source=source, sequence=sequence)
                for sequence in (1, 2)
            ]
            mirror = (root / "mirror-source").absolute()
            result = build_advisory_mirror(
                bundle_directories=bundles,
                output_directory=mirror,
                source=source,
                registry=registry,
                index_signing_key_id=INDEX_KEY_ID,
                index_signing_key=index_key,
                published_at=NOW + timedelta(minutes=3),
            )
            snapshot = (root / "snapshot").absolute()
            snapshot_advisory_mirror(
                output_directory=snapshot,
                source=source,
                registry=registry,
                downloader=_MirrorDownloader(mirror, result.index),
                now=NOW + timedelta(minutes=3),
            )
            self.assertEqual(
                [item.bundle.manifest.catalog_sequence for item in load_existing_mirror(
                    snapshot,
                    source=source,
                    registry=registry,
                    now=NOW + timedelta(minutes=3),
                )],
                [1, 2],
            )

            next(mirror.glob("catalogs/*/catalog.json")).write_bytes(b"tampered")
            failed_target = (root / "failed-snapshot").absolute()
            with self.assertRaisesRegex(MirrorSecurityError, "size|digest"):
                snapshot_advisory_mirror(
                    output_directory=failed_target,
                    source=source,
                    registry=registry,
                    downloader=_MirrorDownloader(mirror, result.index),
                    now=NOW + timedelta(minutes=3),
                )
            self.assertFalse(failed_target.exists())

    def test_remote_sync_selects_signed_latest_then_uses_existing_bundle_contract(self) -> None:
        key = Ed25519PrivateKey.generate()
        index_key = Ed25519PrivateKey.generate()
        registry, source = _mirror_registry(key, index_key)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundles = [
                _write_bundle(root, key=key, source=source, sequence=sequence)
                for sequence in (1, 2)
            ]
            mirror = (root / "mirror").absolute()
            result = build_advisory_mirror(
                bundle_directories=bundles,
                output_directory=mirror,
                source=source,
                registry=registry,
                index_signing_key_id=INDEX_KEY_ID,
                index_signing_key=index_key,
                published_at=NOW + timedelta(minutes=3),
            )
            downloader = _MirrorDownloader(mirror, result.index)
            store = _RemoteStore()
            service = AdvisorySyncService(
                registry=registry,
                store=store,
                downloader=downloader,
                staging=PrivateStagingArea((root / "private-staging").absolute()),
                now=lambda: NOW + timedelta(minutes=3),
            )
            run = service.execute_remote_run(store.run["run_id"])
            self.assertEqual(run["state"], "pending_approval")
            self.assertEqual(run["catalog_version"], "mirror-fixture-2")
            self.assertEqual(
                [kind for kind, _path in downloader.calls],
                ["index", "index_signature", "manifest", "signature", "payload"],
            )
            self.assertEqual(store.saved["catalog_sequence"], 2)
            self.assertEqual(store.saved["publisher_key_id"], BUNDLE_KEY_ID)
            self.assertEqual(store.saved["license_identifier"], source.accepted_licenses[0])


if __name__ == "__main__":
    unittest.main()
