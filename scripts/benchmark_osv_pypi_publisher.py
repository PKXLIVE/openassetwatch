#!/usr/bin/env python3
"""Bounded synthetic benchmark for OSV PyPI normalization and bundle creation."""

from __future__ import annotations

import argparse
import json
import sys
import tracemalloc
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import perf_counter

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.osv_pypi_adapter import (  # noqa: E402
    SYNTHETIC_DEMO_POLICY,
    NormalizationReport,
    build_catalog,
    canonical_json_bytes,
    format_utc,
    normalize_osv_record,
    parse_modified_index,
    parse_osv_record_bytes,
)
from app.osv_pypi_publisher import sign_catalog_bundle  # noqa: E402


NOW = datetime(2099, 2, 1, 12, 0, tzinfo=timezone.utc)


def _record(number: int, modified: datetime) -> dict:
    record_id = f"PYSEC-2099-{number}"
    return {
        "schema_version": "1.7.3",
        "id": record_id,
        "published": "2099-01-01T00:00:00Z",
        "modified": format_utc(modified),
        "aliases": [f"CVE-2099-{number:04d}"],
        "upstream": [],
        "related": [],
        "summary": f"Synthetic benchmark advisory {number}",
        "details": "OpenAssetWatch-authored synthetic benchmark data.",
        "affected": [
            {
                "package": {
                    "ecosystem": "PyPI",
                    "name": f"oaw-benchmark-{number}",
                    "purl": f"pkg:pypi/oaw-benchmark-{number}",
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                    }
                ],
                "versions": ["1.0.0"],
                "ecosystem_specific": {"severity": "MEDIUM"},
                "database_specific": {
                    "source": (
                        "https://github.com/PKXLIVE/openassetwatch/blob/main/"
                        f"backend/tests/fixtures/osv-pypi/{record_id}.yaml"
                    )
                },
            }
        ],
        "references": [{"type": "WEB", "url": "https://github.com/PKXLIVE/openassetwatch"}],
        "credits": [],
        "database_specific": {},
    }


def benchmark(count: int) -> dict:
    if not 1 <= count <= 5_000:
        raise ValueError("count must be between 1 and 5000")
    tracemalloc.start()
    started = perf_counter()
    report = NormalizationReport()
    records = []
    index_lines = []
    for number in range(1, count + 1):
        modified = NOW + timedelta(microseconds=number)
        raw = canonical_json_bytes(_record(number, modified))
        parsed = parse_osv_record_bytes(raw, expected_id=f"PYSEC-2099-{number}")
        records.append(
            normalize_osv_record(
                parsed,
                expected_modified=modified,
                policy=SYNTHETIC_DEMO_POLICY,
                report=report,
            )
        )
        index_lines.append(f"{format_utc(modified)},PYSEC-2099-{number}\n")
    normalized_at = perf_counter()
    highest = NOW + timedelta(microseconds=count)
    first = build_catalog(records, highest_modified=highest, policy=SYNTHETIC_DEMO_POLICY)
    second = build_catalog(records, highest_modified=highest, policy=SYNTHETIC_DEMO_POLICY)
    built_at = perf_counter()
    index = parse_modified_index(
        "".join(reversed(index_lines)).encode("ascii"),
        maximum_rows=5_000,
    )
    bundle = sign_catalog_bundle(
        first,
        policy=SYNTHETIC_DEMO_POLICY,
        index=index,
        key_id="oaw-benchmark-ed25519-2099-01",
        private_key=Ed25519PrivateKey.generate(),
        sequence=1,
        created_at=highest + timedelta(seconds=1),
        validity_days=7,
    )
    signed_at = perf_counter()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "status": "synthetic-benchmark-complete",
        "synthetic_fixture": True,
        "record_count": count,
        "normalization_seconds": round(normalized_at - started, 6),
        "catalog_build_seconds": round(built_at - normalized_at, 6),
        "sign_and_verify_seconds": round(signed_at - built_at, 6),
        "total_seconds": round(signed_at - started, 6),
        "peak_memory_bytes": peak,
        "payload_bytes": len(first.payload_bytes),
        "payload_sha256": first.payload_digest,
        "deterministic_payload": first.payload_bytes == second.payload_bytes,
        "signature_verified": bundle.verified.payload_digest == first.payload_digest,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=2_000)
    args = parser.parse_args()
    print(json.dumps(benchmark(args.count), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
