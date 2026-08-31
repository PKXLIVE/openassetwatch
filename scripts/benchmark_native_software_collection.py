#!/usr/bin/env python3
"""Bounded synthetic native-software canonical-ingestion benchmark."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import tracemalloc
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import text


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))
if str(REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "scripts"))

from app import main as backend_main  # noqa: E402
from app.advisory_catalog import load_catalog  # noqa: E402
from app.advisory_store import SqlAdvisoryStore  # noqa: E402
from app.canonical_ingestion import endpoint_envelope, ingest  # noqa: E402
from demo_native_software_collection import (  # noqa: E402
    ASSET_ID,
    SITE_ID,
    _patch_runtime,
    disposable_database,
    enroll_fictional_endpoint,
    native_payload,
)


MAX_COMPONENTS = 2_000


def _synthetic_records(count: int) -> tuple[list[tuple[str, str]], int]:
    if not 1 <= count <= MAX_COMPONENTS:
        raise ValueError("component benchmark count must be between 1 and 2000")
    unique = [("fictional-native-library", "1.5.0")]
    unique.extend(
        (f"fictional-benchmark-package-{index:04d}", "1.0.0")
        for index in range(1, count)
    )
    raw = unique + unique[::10]
    seen: set[tuple[str, str]] = set()
    deduplicated: list[tuple[str, str]] = []
    for record in raw:
        key = (record[0].casefold(), "amd64")
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(record)
    return deduplicated, len(raw) - len(deduplicated)


def run_benchmark(*, database_url: str, component_count: int) -> dict[str, object]:
    tracemalloc.start()
    started = time.perf_counter()
    records, duplicate_count = _synthetic_records(component_count)
    collection_seconds = time.perf_counter() - started
    now = datetime.now(timezone.utc).replace(microsecond=0)

    started = time.perf_counter()
    payload = native_payload(
        now=now,
        batch_id="native-benchmark-complete-0001",
        status="complete",
        packages=records,
    )
    parsing_seconds = time.perf_counter() - started
    payload_bytes = len(
        json.dumps(
            payload.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )

    with disposable_database(database_url) as engine:
        runtime_patchers = _patch_runtime(engine)
        with (
            runtime_patchers[0],
            runtime_patchers[1],
            runtime_patchers[2],
            runtime_patchers[3],
        ):
            _issued, context = enroll_fictional_endpoint(engine, now=now)
            catalog, checksum = load_catalog(
                BACKEND_ROOT
                / "catalogs"
                / "synthetic-native-software-advisory-catalog.json"
            )
            SqlAdvisoryStore().import_catalog(
                catalog=catalog,
                checksum=checksum,
                imported_at=now,
            )
            started = time.perf_counter()
            acknowledgement = ingest(
                endpoint_envelope(
                    payload=payload,
                    context=context,
                    received_at=now,
                )
            )
            ingestion_seconds = time.perf_counter() - started

            started = time.perf_counter()
            backend_main._run_canonical_inventory_evaluation(
                canonical_collection_id=acknowledgement.canonical_collection_id
            )
            evaluation_seconds = time.perf_counter() - started
            with engine.connect() as connection:
                counts = {
                    "components": int(
                        connection.execute(
                            text(
                                "SELECT COUNT(*) FROM asset_components "
                                "WHERE site_id=:site_id AND asset_id=:asset_id "
                                "AND active=TRUE"
                            ),
                            {"site_id": SITE_ID, "asset_id": ASSET_ID},
                        ).scalar_one()
                    ),
                    "source_presence": int(
                        connection.execute(
                            text(
                                "SELECT COUNT(*) FROM component_source_presence "
                                "WHERE site_id=:site_id AND asset_id=:asset_id "
                                "AND active=TRUE"
                            ),
                            {"site_id": SITE_ID, "asset_id": ASSET_ID},
                        ).scalar_one()
                    ),
                    "matches": int(
                        connection.execute(
                            text(
                                "SELECT COUNT(*) FROM vulnerability_matches "
                                "WHERE site_id=:site_id AND asset_id=:asset_id"
                            ),
                            {"site_id": SITE_ID, "asset_id": ASSET_ID},
                        ).scalar_one()
                    ),
                    "findings": int(
                        connection.execute(
                            text(
                                "SELECT COUNT(*) FROM findings "
                                "WHERE site_id=:site_id AND asset_id=:asset_id"
                            ),
                            {"site_id": SITE_ID, "asset_id": ASSET_ID},
                        ).scalar_one()
                    ),
                    "risk_rows": int(
                        connection.execute(
                            text(
                                "SELECT COUNT(*) FROM asset_risk_scores "
                                "WHERE site_id=:site_id AND asset_id=:asset_id"
                            ),
                            {"site_id": SITE_ID, "asset_id": ASSET_ID},
                        ).scalar_one()
                    ),
                }

    _current_bytes, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    success = (
        counts["components"] == component_count
        and counts["source_presence"] == component_count
        and counts["matches"] >= 1
        and counts["findings"] >= 1
        and counts["risk_rows"] == 1
    )
    return {
        "schema_version": "oaw.native-software-benchmark.v1",
        "synthetic_only": True,
        "offline": True,
        "development_measurement_not_capacity_claim": True,
        "status": "passed" if success else "failed",
        "scale": {
            "components": component_count,
            "duplicate_input_records": duplicate_count,
        },
        "seconds": {
            "synthetic_collection": round(collection_seconds, 6),
            "contract_parsing_and_normalization": round(parsing_seconds, 6),
            "authenticated_canonical_ingestion": round(ingestion_seconds, 6),
            "component_vulnerability_finding_risk_evaluation": round(
                evaluation_seconds,
                6,
            ),
        },
        "submission_payload_bytes": payload_bytes,
        "peak_memory_mib": round(peak_bytes / (1024 * 1024), 3),
        "persisted": counts,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the disposable synthetic native-software benchmark."
    )
    parser.add_argument("--components", type=int, default=2_000)
    args = parser.parse_args(argv)
    database_url = os.getenv("DATABASE_URL")
    if (
        os.getenv("OPENASSETWATCH_NATIVE_SOFTWARE_BENCHMARK") != "1"
        or not database_url
    ):
        print(
            json.dumps(
                {
                    "status": "disabled",
                    "error_code": "explicit-benchmark-environment-required",
                },
                sort_keys=True,
            )
        )
        return 2
    try:
        result = run_benchmark(
            database_url=database_url,
            component_count=args.components,
        )
    except Exception as exc:  # noqa: BLE001 - keep configuration details private.
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error_code": f"benchmark-{type(exc).__name__.lower()}"[:80],
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
