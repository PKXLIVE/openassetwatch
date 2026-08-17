#!/usr/bin/env python3
"""Synthetic, offline signed-feed verification and preview benchmark."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import sys
import time
import tracemalloc
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
FIXTURE = BACKEND / "advisory_feeds" / "fixtures" / "openassetwatch-synthetic-signed" / "catalog.json"
sys.path.insert(0, str(BACKEND))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from app.advisory_bundle import _decompress_gzip, preview_bundle, verify_bundle, verify_manifest  # noqa: E402
from app.advisory_catalog import parse_catalog_bytes  # noqa: E402
from app.advisory_feed_registry import (  # noqa: E402
    FeedRegistryDocument,
    PublisherKey,
    PublisherKeyringDocument,
    ReviewedFeedRegistry,
    load_reviewed_feed_registry,
)
from app.advisory_sync_service import changed_record_ids  # noqa: E402


def arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--advisories", type=int, default=1000, choices=range(1, 5001), metavar="1..5000")
    return parser.parse_args(argv)


def timed(function, *args, **kwargs):
    started = time.perf_counter()
    result = function(*args, **kwargs)
    return result, (time.perf_counter() - started) * 1000.0


def build_workload(count: int):
    now = datetime.now(timezone.utc)
    source = load_reviewed_feed_registry().source("openassetwatch-synthetic-signed")
    base = json.loads(FIXTURE.read_text(encoding="utf-8"))
    prototype = base["advisories"][0]
    advisories = []
    for index in range(count):
        record = json.loads(json.dumps(prototype))
        record["id"] = f"OAW-BENCH-2099-{index:06d}"
        record["aliases"] = [f"CVE-DEMO-2099-{index:06d}"]
        record["references"] = [
            {
                "type": "advisory",
                "url": f"https://advisories.example.invalid/OAW-BENCH-2099-{index:06d}",
            }
        ]
        advisories.append(record)
    catalog_document = {
        **base,
        "catalog_version": f"synthetic-benchmark-{count}",
        "generated_at": now.isoformat(),
        "source": {**base["source"], "version": f"benchmark-{count}"},
        "advisories": advisories,
    }
    for index, advisory in enumerate(advisories):
        entropy = "".join(
            hashlib.sha256(f"synthetic-benchmark-{index}-{block}".encode("ascii")).hexdigest()
            for block in range(5)
        )
        advisory["summary"] = f"Synthetic benchmark evidence {index}: {entropy}"
    catalog_bytes = json.dumps(catalog_document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    compressed = gzip.compress(catalog_bytes, compresslevel=6, mtime=0)

    private_key = Ed25519PrivateKey.generate()
    key_id = "oaw-ephemeral-benchmark-key"
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key = PublisherKey(
        key_id=key_id,
        publisher_id="openassetwatch-ephemeral-benchmark",
        publisher_name="OpenAssetWatch Ephemeral Benchmark",
        algorithm="ed25519",
        public_key_base64=base64.b64encode(public_bytes).decode("ascii"),
        status="active",
        not_before=now - timedelta(minutes=1),
        not_after=now + timedelta(days=1),
    )
    reviewed_source = source.model_copy(update={"trusted_publisher_key_ids": [key_id]})
    registry = ReviewedFeedRegistry(
        FeedRegistryDocument(
            schema_version="oaw.advisory-feed-registry.v1",
            registry_version="benchmark",
            sources=[reviewed_source],
        ),
        PublisherKeyringDocument(
            schema_version="oaw.advisory-publisher-keyring.v1",
            keyring_version="benchmark",
            keys=[key],
        ),
    )
    manifest = {
        "schema_id": "oaw.advisory-bundle.manifest.v1",
        "schema_version": 1,
        "source_id": source.source_id,
        "publisher_key_id": key_id,
        "catalog_version": catalog_document["catalog_version"],
        "catalog_sequence": 1,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=12)).isoformat(),
        "payload_name": source.expected_payload_name,
        "payload_media_type": "application/vnd.openassetwatch.advisory-catalog+gzip",
        "payload_compression": "gzip",
        "payload_sha256": hashlib.sha256(compressed).hexdigest(),
        "compressed_bytes": len(compressed),
        "uncompressed_bytes": len(catalog_bytes),
        "advisory_count": count,
        "alias_count": count,
        "reference_count": count,
        "license_identifier": "Apache-2.0",
        "attribution": source.required_attribution,
        "upstream_provenance": {
            "source_name": catalog_document["source"]["name"],
            "source_version": catalog_document["source"]["version"],
            "dataset_id": "synthetic-offline-benchmark",
            "retrieved_at": now.isoformat(),
        },
        "adapter_version": source.adapter_version,
        "minimum_supported_catalog_version": 1,
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature_bytes = base64.b64encode(private_key.sign(manifest_bytes)) + b"\n"
    return now, reviewed_source, registry, manifest_bytes, signature_bytes, compressed


def main(argv: list[str] | None = None) -> int:
    args = arguments(argv or sys.argv[1:])
    now, source, registry, manifest, signature, payload = build_workload(args.advisories)
    tracemalloc.start()
    _, signature_ms = timed(
        verify_manifest,
        manifest_bytes=manifest,
        signature_bytes=signature,
        source=source,
        registry=registry,
        now=now,
    )
    clear, decompression_ms = timed(
        _decompress_gzip,
        payload,
        maximum_bytes=source.limits.maximum_uncompressed_bytes,
        maximum_ratio=source.limits.maximum_expansion_ratio,
    )
    _, validation_ms = timed(parse_catalog_bytes, clear)
    bundle, full_verification_ms = timed(
        verify_bundle,
        manifest_bytes=manifest,
        signature_bytes=signature,
        payload_bytes=payload,
        source=source,
        registry=registry,
        now=now,
    )
    preview, preview_ms = timed(preview_bundle, bundle, previous_catalog=None, now=now)
    changed, reevaluation_scope_ms = timed(changed_record_ids, bundle.catalog, None)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(
        json.dumps(
            {
                "workload": "synthetic-offline-no-network",
                "advisory_count": args.advisories,
                "payload_compressed_bytes": len(payload),
                "payload_uncompressed_bytes": len(clear),
                "manifest_signature_verification_ms": round(signature_ms, 3),
                "bounded_decompression_ms": round(decompression_ms, 3),
                "catalog_validation_ms": round(validation_ms, 3),
                "full_bundle_verification_ms": round(full_verification_ms, 3),
                "preview_diff_ms": round(preview_ms, 3),
                "targeted_reevaluation_scope_ms": round(reevaluation_scope_ms, 3),
                "changed_advisory_count": len(changed),
                "preview_added_advisories": preview.added_advisories,
                "peak_tracemalloc_bytes": peak,
                "atomic_import_ms": None,
                "targeted_reevaluation_ms": None,
                "database_measurement_status": "requires-live-postgresql",
                "network_throughput_claimed": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
