from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import socket
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.advisory_bundle import BundleVerificationError, preview_bundle, verify_bundle
from app.advisory_feed_registry import (
    FeedRegistryDocument,
    PublisherKey,
    PublisherKeyringDocument,
    RegistryError,
    ReviewedFeedRegistry,
    load_reviewed_feed_registry,
)
from app.advisory_transport import (
    AdvisoryDownloader,
    DownloadSecurityError,
    PrivateStagingArea,
    StagingSecurityError,
    TransportResponse,
    read_single_link_file,
    resolve_public_addresses,
    validate_download_url,
)


NOW = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)
FEED_ROOT = Path(__file__).resolve().parents[1] / "advisory_feeds"
FIXTURE_ROOT = FEED_ROOT / "fixtures" / "openassetwatch-synthetic-signed"
PUBLIC_DNS = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]


def _fixture() -> tuple[bytes, bytes, bytes]:
    return (
        (FIXTURE_ROOT / "manifest.json").read_bytes(),
        (FIXTURE_ROOT / "manifest.ed25519").read_bytes(),
        (FIXTURE_ROOT / "catalog.json").read_bytes(),
    )


def _test_registry(
    private_key: Ed25519PrivateKey,
    *,
    key_status: str = "active",
    key_id: str = "test-publisher-key-1",
    enabled: bool = True,
    not_after: datetime | None = NOW + timedelta(days=30),
) -> ReviewedFeedRegistry:
    production = load_reviewed_feed_registry()
    source = production.source("openassetwatch-synthetic-signed").model_copy(
        update={"trusted_publisher_key_ids": [key_id], "enabled": enabled}
    )
    public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key = PublisherKey(
        key_id=key_id,
        publisher_id="test-publisher",
        publisher_name="Ephemeral Unit Test Publisher",
        algorithm="ed25519",
        public_key_base64=base64.b64encode(public).decode("ascii"),
        status=key_status,
        not_before=NOW - timedelta(days=30),
        not_after=not_after,
    )
    return ReviewedFeedRegistry(
        FeedRegistryDocument(
            schema_version="oaw.advisory-feed-registry.v1",
            registry_version="test",
            sources=[source],
        ),
        PublisherKeyringDocument(
            schema_version="oaw.advisory-publisher-keyring.v1",
            keyring_version="test",
            keys=[key],
        ),
    )


def _signed_bundle(
    *,
    private_key: Ed25519PrivateKey | None = None,
    manifest_updates: dict | None = None,
    payload: bytes | None = None,
    compression: str = "none",
    registry: ReviewedFeedRegistry | None = None,
) -> tuple[bytes, bytes, bytes, ReviewedFeedRegistry]:
    key = private_key or Ed25519PrivateKey.generate()
    current_registry = registry or _test_registry(key)
    source = current_registry.source("openassetwatch-synthetic-signed")
    _, _, default_payload = _fixture()
    clear_payload = payload or default_payload
    wire_payload = gzip.compress(clear_payload, mtime=0) if compression == "gzip" else clear_payload
    catalog = json.loads(clear_payload)
    aliases = sum(len(item.get("aliases", [])) for item in catalog["advisories"])
    references = sum(len(item.get("references", [])) for item in catalog["advisories"])
    manifest = {
        "schema_id": "oaw.advisory-bundle.manifest.v1",
        "schema_version": 1,
        "source_id": source.source_id,
        "publisher_key_id": source.trusted_publisher_key_ids[0],
        "catalog_version": catalog["catalog_version"],
        "catalog_sequence": 1,
        "created_at": (NOW - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
        "payload_name": source.expected_payload_name,
        "payload_media_type": (
            "application/vnd.openassetwatch.advisory-catalog+gzip"
            if compression == "gzip"
            else "application/vnd.openassetwatch.advisory-catalog+json"
        ),
        "payload_compression": compression,
        "payload_sha256": hashlib.sha256(wire_payload).hexdigest(),
        "compressed_bytes": len(wire_payload),
        "uncompressed_bytes": len(clear_payload),
        "advisory_count": len(catalog["advisories"]),
        "alias_count": aliases,
        "reference_count": references,
        "license_identifier": source.accepted_licenses[0],
        "attribution": source.required_attribution,
        "upstream_provenance": {
            "source_name": catalog["source"]["name"],
            "source_version": catalog["source"]["version"],
            "dataset_id": "unit-test-dataset",
            "retrieved_at": (NOW - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        },
        "adapter_version": source.adapter_version,
        "minimum_supported_catalog_version": 1,
    }
    manifest.update(manifest_updates or {})
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = base64.b64encode(key.sign(manifest_bytes)) + b"\n"
    return manifest_bytes, signature, wire_payload, current_registry


class AdvisoryBundleSecurityTests(unittest.TestCase):
    def test_committed_synthetic_bundle_verifies_and_previews(self) -> None:
        manifest, signature, payload = _fixture()
        registry = load_reviewed_feed_registry()
        source = registry.source("openassetwatch-synthetic-signed")
        bundle = verify_bundle(
            manifest_bytes=manifest,
            signature_bytes=signature,
            payload_bytes=payload,
            source=source,
            registry=registry,
            now=NOW,
        )
        preview = preview_bundle(bundle, previous_catalog=None, now=NOW)
        self.assertEqual(bundle.manifest.catalog_sequence, 1)
        self.assertEqual(preview.signature_status, "verified")
        self.assertEqual(preview.added_advisories, 1)

    def test_exact_manifest_bytes_are_signed(self) -> None:
        manifest, signature, payload, registry = _signed_bundle()
        source = registry.source("openassetwatch-synthetic-signed")
        verify_bundle(
            manifest_bytes=manifest,
            signature_bytes=signature,
            payload_bytes=payload,
            source=source,
            registry=registry,
            now=NOW,
        )
        reformatted = json.dumps(json.loads(manifest), indent=2).encode("utf-8")
        with self.assertRaisesRegex(BundleVerificationError, "signature"):
            verify_bundle(
                manifest_bytes=reformatted,
                signature_bytes=signature,
                payload_bytes=payload,
                source=source,
                registry=registry,
                now=NOW,
            )

    def test_signature_key_and_manifest_policy_rejections(self) -> None:
        key = Ed25519PrivateKey.generate()
        cases = [
            ("invalid-signature", {}, None, b"A" * 88 + b"\n", "signature"),
            ("malformed-signature", {}, None, b"not-base64\n", "signature"),
            ("expired-manifest", {"expires_at": (NOW - timedelta(seconds=1)).isoformat()}, None, None, "expired"),
            ("future-manifest", {"created_at": (NOW + timedelta(hours=1)).isoformat()}, None, None, "future"),
            (
                "future-provenance",
                {
                    "upstream_provenance": {
                        "source_name": "OpenAssetWatch Synthetic Advisory Laboratory",
                        "source_version": "fixture-2026.1",
                        "dataset_id": "unit-test-dataset",
                        "retrieved_at": (NOW + timedelta(hours=1)).isoformat(),
                    }
                },
                None,
                None,
                "retrieval time",
            ),
            ("source-mismatch", {"source_id": "different-reviewed-source"}, None, None, "source"),
            ("license-mismatch", {"license_identifier": "Proprietary"}, None, None, "license"),
            ("attribution-missing", {"attribution": ""}, None, None, "schema"),
        ]
        for name, updates, custom_registry, replacement_signature, message in cases:
            with self.subTest(name=name):
                manifest, signature, payload, registry = _signed_bundle(
                    private_key=key,
                    manifest_updates=updates,
                    registry=custom_registry,
                )
                if replacement_signature is not None:
                    signature = replacement_signature
                with self.assertRaisesRegex(BundleVerificationError, message):
                    verify_bundle(
                        manifest_bytes=manifest,
                        signature_bytes=signature,
                        payload_bytes=payload,
                        source=registry.source("openassetwatch-synthetic-signed"),
                        registry=registry,
                        now=NOW,
                    )

        for status, message in (("revoked", "revoked"), ("retired", "retired")):
            with self.subTest(key_status=status):
                registry = _test_registry(key, key_status=status)
                manifest, signature, payload, _ = _signed_bundle(private_key=key, registry=registry)
                with self.assertRaisesRegex(BundleVerificationError, message):
                    verify_bundle(
                        manifest_bytes=manifest,
                        signature_bytes=signature,
                        payload_bytes=payload,
                        source=registry.source("openassetwatch-synthetic-signed"),
                        registry=registry,
                        now=NOW,
                    )

        expired_registry = _test_registry(key, not_after=NOW - timedelta(seconds=1))
        manifest, signature, payload, _ = _signed_bundle(private_key=key, registry=expired_registry)
        with self.assertRaisesRegex(BundleVerificationError, "expired"):
            verify_bundle(
                manifest_bytes=manifest,
                signature_bytes=signature,
                payload_bytes=payload,
                source=expired_registry.source("openassetwatch-synthetic-signed"),
                registry=expired_registry,
                now=NOW,
            )

    def test_unknown_key_and_payload_invariants_are_rejected(self) -> None:
        key = Ed25519PrivateKey.generate()
        registry = _test_registry(key)
        for name, updates, message in (
            ("unknown-key", {"publisher_key_id": "unknown-publisher-key"}, "not trusted"),
            ("digest", {"payload_sha256": "0" * 64}, "digest"),
            ("compressed-size", {"compressed_bytes": 1, "uncompressed_bytes": 1}, "byte count"),
            ("advisory-count", {"advisory_count": 2}, "count"),
        ):
            with self.subTest(name=name):
                manifest, signature, payload, _ = _signed_bundle(
                    private_key=key,
                    manifest_updates=updates,
                    registry=registry,
                )
                with self.assertRaisesRegex(BundleVerificationError, message):
                    verify_bundle(
                        manifest_bytes=manifest,
                        signature_bytes=signature,
                        payload_bytes=payload,
                        source=registry.source("openassetwatch-synthetic-signed"),
                        registry=registry,
                        now=NOW,
                    )

        manifest, signature, payload, _ = _signed_bundle(
            private_key=key,
            manifest_updates={"uncompressed_bytes": 1},
            compression="gzip",
            registry=registry,
        )
        with self.assertRaisesRegex(BundleVerificationError, "uncompressed byte count"):
            verify_bundle(
                manifest_bytes=manifest,
                signature_bytes=signature,
                payload_bytes=payload,
                source=registry.source("openassetwatch-synthetic-signed"),
                registry=registry,
                now=NOW,
            )

    def test_gzip_bomb_ratio_trailing_and_concatenation_are_rejected(self) -> None:
        key = Ed25519PrivateKey.generate()
        registry = _test_registry(key)
        source = registry.source("openassetwatch-synthetic-signed")
        _, _, clear = _fixture()
        highly_compressible = clear + b" " * 100_000
        manifest, signature, payload, _ = _signed_bundle(
            private_key=key,
            payload=highly_compressible,
            compression="gzip",
            registry=registry,
        )
        with self.assertRaises(BundleVerificationError):
            verify_bundle(
                manifest_bytes=manifest,
                signature_bytes=signature,
                payload_bytes=payload,
                source=source,
                registry=registry,
                now=NOW,
            )

        for suffix in (b"trailing", gzip.compress(b"second", mtime=0)):
            wire = gzip.compress(clear, mtime=0) + suffix
            manifest, signature, _, _ = _signed_bundle(
                private_key=key,
                payload=clear,
                compression="gzip",
                registry=registry,
                manifest_updates={
                    "payload_sha256": hashlib.sha256(wire).hexdigest(),
                    "compressed_bytes": len(wire),
                },
            )
            with self.subTest(suffix=suffix[:8]):
                with self.assertRaisesRegex(BundleVerificationError, "trailing"):
                    verify_bundle(
                        manifest_bytes=manifest,
                        signature_bytes=signature,
                        payload_bytes=wire,
                        source=source,
                        registry=registry,
                        now=NOW,
                    )

    def test_registry_rejects_unknown_and_disabled_sources(self) -> None:
        registry = load_reviewed_feed_registry()
        with self.assertRaisesRegex(RegistryError, "not configured"):
            registry.source("missing-source")
        key = Ed25519PrivateKey.generate()
        disabled = _test_registry(key, enabled=False)
        with self.assertRaisesRegex(RegistryError, "disabled"):
            disabled.source("openassetwatch-synthetic-signed")

        document = registry.source_document.model_dump(mode="json")
        document["sources"][0]["endpoint"]["manifest_path"] = "/safe/%2e%2e/manifest.json"
        with self.assertRaises(ValueError):
            FeedRegistryDocument.model_validate(document)

    def test_no_private_signing_key_or_unsigned_fallback_is_committed(self) -> None:
        tracked_feed_text = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in FEED_ROOT.rglob("*")
            if path.is_file()
        )
        self.assertNotIn("PRIVATE KEY", tracked_feed_text)
        self.assertNotIn("private_key", tracked_feed_text)
        cli = (Path(__file__).resolve().parents[2] / "scripts" / "advisory_feed_sync.py").read_text(encoding="utf-8")
        self.assertNotIn("skip-signature", cli)
        self.assertNotIn("unsigned", cli.casefold())


class _FakeTransport:
    def __init__(self, response: TransportResponse) -> None:
        self.response = response
        self.calls: list[dict] = []

    def get(self, **kwargs):
        self.calls.append(kwargs)
        return self.response


class AdvisoryTransportSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = load_reviewed_feed_registry().source("openassetwatch-synthetic-signed")

    def test_url_policy_rejects_scheme_credentials_host_path_query_and_port(self) -> None:
        good = "https://advisories.openassetwatch.invalid/v1/synthetic/manifest.json"
        self.assertEqual(validate_download_url(self.source, "manifest", good)[0], self.source.endpoint.host)
        cases = (
            "http://advisories.openassetwatch.invalid/v1/synthetic/manifest.json",
            "https://user:pass@advisories.openassetwatch.invalid/v1/synthetic/manifest.json",
            "https://other.invalid/v1/synthetic/manifest.json",
            "https://advisories.openassetwatch.invalid/wrong",
            "https://advisories.openassetwatch.invalid:444/v1/synthetic/manifest.json",
            "https://advisories.openassetwatch.invalid/v1/synthetic/manifest.json?next=1",
        )
        for value in cases:
            with self.subTest(value=value), self.assertRaises(DownloadSecurityError):
                validate_download_url(self.source, "manifest", value)

    def test_prohibited_and_mixed_dns_results_are_rejected(self) -> None:
        prohibited = (
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "224.0.0.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
        )
        for address in prohibited:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            answers = [(family, socket.SOCK_STREAM, 6, "", (address, 443))]
            with self.subTest(address=address), self.assertRaisesRegex(DownloadSecurityError, "prohibited"):
                resolve_public_addresses("feed.invalid", resolver=lambda *_args, **_kwargs: answers)
        mixed = PUBLIC_DNS + [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with self.assertRaisesRegex(DownloadSecurityError, "prohibited"):
            resolve_public_addresses("feed.invalid", resolver=lambda *_args, **_kwargs: mixed)

    def test_downloader_rejects_redirect_peer_change_headers_type_size_and_timeout(self) -> None:
        cases = [
            ("redirect", 302, (("Content-Type", "application/json"),), [b"x"], "93.184.216.34", "redirect"),
            ("peer", 200, (("Content-Type", "application/json"),), [b"x"], "93.184.216.35", "peer"),
            ("type", 200, (("Content-Type", "text/html"),), [b"x"], "93.184.216.34", "content type"),
            ("duplicate", 200, (("Content-Type", "application/json"), ("Content-Type", "application/json")), [b"x"], "93.184.216.34", "ambiguous"),
            ("size", 200, (("Content-Type", "application/json"),), [b"x" * 70_000], "93.184.216.34", "byte limit"),
        ]
        for name, status, headers, chunks, peer, message in cases:
            closed = []
            response = TransportResponse(status, headers, chunks, peer, lambda: closed.append(True))
            downloader = AdvisoryDownloader(
                transport=_FakeTransport(response),
                resolver=lambda *_args, **_kwargs: PUBLIC_DNS,
            )
            with self.subTest(name=name), self.assertRaisesRegex(DownloadSecurityError, message):
                downloader.fetch(self.source, "manifest")
            self.assertTrue(closed)

        ticks = iter((0.0, 31.0))
        response = TransportResponse(200, (("Content-Type", "application/json"),), [b"x"], "93.184.216.34", lambda: None)
        downloader = AdvisoryDownloader(
            transport=_FakeTransport(response),
            resolver=lambda *_args, **_kwargs: PUBLIC_DNS,
            clock=lambda: next(ticks),
        )
        with self.assertRaisesRegex(DownloadSecurityError, "timeout"):
            downloader.fetch(self.source, "manifest")

    def test_proxy_environment_is_not_inherited(self) -> None:
        response = TransportResponse(
            200,
            (("Content-Type", "application/json"), ("Content-Length", "2")),
            [b"{}"],
            "93.184.216.34",
            lambda: None,
        )
        transport = _FakeTransport(response)
        old_proxy = os.environ.get("HTTPS_PROXY")
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:9"
        try:
            result = AdvisoryDownloader(
                transport=transport,
                resolver=lambda *_args, **_kwargs: PUBLIC_DNS,
            ).fetch(self.source, "manifest")
        finally:
            if old_proxy is None:
                os.environ.pop("HTTPS_PROXY", None)
            else:
                os.environ["HTTPS_PROXY"] = old_proxy
        self.assertEqual(result.body, b"{}")
        self.assertNotIn("proxy", transport.calls[0])

    def test_error_summaries_do_not_echo_response_bodies_or_credentials(self) -> None:
        secret = "Bearer customer-secret-value"
        response = TransportResponse(
            500,
            (("Content-Type", "text/plain"), ("Authorization", secret)),
            [b"private upstream response body"],
            "93.184.216.34",
            lambda: None,
        )
        downloader = AdvisoryDownloader(
            transport=_FakeTransport(response),
            resolver=lambda *_args, **_kwargs: PUBLIC_DNS,
        )
        with self.assertRaises(DownloadSecurityError) as raised:
            downloader.fetch(self.source, "manifest")
        self.assertNotIn(secret, str(raised.exception))
        self.assertNotIn("private upstream response body", str(raised.exception))

    def test_private_staging_rejects_links_and_cleans_bounded_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "private"
            staging = PrivateStagingArea(root)
            run = staging.create_run_directory("afrun_" + "a" * 32)
            artifact = staging.write_artifact(run, "manifest.json", b"{}")
            self.assertEqual(read_single_link_file(artifact.absolute(), maximum_bytes=16), b"{}")
            linked = run / "linked"
            os.link(artifact, linked)
            with self.assertRaisesRegex(StagingSecurityError, "single-link"):
                read_single_link_file(artifact.absolute(), maximum_bytes=16)
            linked.unlink()
            staging.cleanup(run)
            self.assertFalse(run.exists())

    @unittest.skipIf(os.name == "nt" or not hasattr(os, "symlink"), "POSIX symlink semantics required")
    def test_staging_root_symlink_is_rejected_before_target_permissions_change(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            victim = parent / "victim"
            victim.mkdir(mode=0o755)
            os.chmod(victim, 0o755)
            root = parent / "staging"
            os.symlink(victim, root, target_is_directory=True)

            with self.assertRaisesRegex(StagingSecurityError, "without following links"):
                PrivateStagingArea(root).ensure_root()

            self.assertTrue(root.is_symlink())
            self.assertEqual(stat.S_IMODE(victim.stat().st_mode), 0o755)


if __name__ == "__main__":
    unittest.main()
