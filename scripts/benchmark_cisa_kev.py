#!/usr/bin/env python3
"""Benchmark bounded synthetic CISA KEV validation and exact correlation."""

from __future__ import annotations

import argparse
import json
import sys
import tracemalloc
from pathlib import Path
from time import perf_counter


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.kev_catalog import canonical_kev_bytes, normalize_cisa_kev_catalog, parse_cisa_kev_bytes  # noqa: E402
from app.kev_correlation import correlate_current_affected_matches, exact_cve_aliases  # noqa: E402


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the offline synthetic KEV benchmark.")
    parser.add_argument("--records", type=int, default=2_000)
    parser.add_argument("--aliases", type=int, default=6_000)
    parser.add_argument("--matches", type=int, default=5_000)
    return parser


def _source(record_count: int) -> bytes:
    vulnerabilities = []
    for index in range(record_count):
        cve = f"CVE-2099-{10_000 + index}"
        vulnerabilities.append(
            {
                "cveID": cve,
                "vendorProject": f"Fictional Vendor {index % 37}",
                "product": f"Synthetic Product {index}",
                "vulnerabilityName": f"Synthetic benchmark weakness {index}",
                "dateAdded": "2099-01-01",
                "shortDescription": "Fictional bounded benchmark record; no real product or vulnerability.",
                "requiredAction": "Review the fictional benchmark component; no action is executed.",
                "dueDate": "2099-01-31",
                "knownRansomwareCampaignUse": "Known" if index % 11 == 0 else "Unknown",
                "cwes": ["CWE-9999"],
            }
        )
    return json.dumps(
        {
            "catalogVersion": "synthetic-benchmark-2099.1",
            "dateReleased": "2099-01-02T12:00:00Z",
            "count": record_count,
            "vulnerabilities": vulnerabilities,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not 1_000 <= args.records <= 10_000:
        raise SystemExit("--records must be between 1000 and 10000")
    if not 1_000 <= args.aliases <= 200_000:
        raise SystemExit("--aliases must be between 1000 and 200000")
    if not 1_000 <= args.matches <= 200_000:
        raise SystemExit("--matches must be between 1000 and 200000")

    tracemalloc.start()
    started = perf_counter()
    source_bytes = _source(args.records)
    generated_at = perf_counter()
    source_catalog = parse_cisa_kev_bytes(source_bytes)
    validated_at = perf_counter()
    catalog = normalize_cisa_kev_catalog(source_catalog)
    payload = canonical_kev_bytes(catalog)
    imported_at = perf_counter()

    advisory_aliases = [
        {
            "advisory_id": f"adv_{index:032x}",
            "alias": f"CVE-2099-{10_000 + (index % args.records)}",
        }
        for index in range(args.aliases)
    ]
    matches = [
        {
            "match_id": f"vmt_{index:032x}",
            "advisory_id": advisory_aliases[index % len(advisory_aliases)]["advisory_id"],
            "match_status": "affected",
            "aliases": [
                advisory_aliases[index % len(advisory_aliases)]["alias"],
                f"GHSA-fictional-{index:08d}",
            ],
        }
        for index in range(args.matches)
    ]
    indexed_at = perf_counter()
    correlations = correlate_current_affected_matches(matches, catalog.records)
    correlated_at = perf_counter()

    changed_cves = {f"CVE-2099-{10_000 + index}" for index in range(min(100, args.records))}
    targeted_matches = [
        match
        for match in matches
        if changed_cves.intersection(exact_cve_aliases(match["aliases"]))
    ]
    targeted = correlate_current_affected_matches(targeted_matches, catalog.records)
    targeted_at = perf_counter()

    page_size = 50
    page_projection_count = 0
    sorted_records = sorted(catalog.records, key=lambda item: (item.date_added, item.cve_id), reverse=True)
    for offset in range(0, min(len(sorted_records), 1_000), page_size):
        page_projection_count += len(
            [record.model_dump(mode="json") for record in sorted_records[offset : offset + page_size]]
        )
    paginated_at = perf_counter()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    if len(correlations) != args.matches:
        raise RuntimeError("full synthetic correlation count was not deterministic")
    if any(item.cve_id not in changed_cves for item in targeted):
        raise RuntimeError("targeted synthetic reevaluation escaped the changed CVE set")
    result = {
        "schema_version": "oaw.cisa-kev-benchmark.v1",
        "synthetic_only": True,
        "record_count": args.records,
        "advisory_alias_count": args.aliases,
        "current_affected_match_count": args.matches,
        "source_bytes": len(source_bytes),
        "normalized_payload_bytes": len(payload),
        "full_correlation_count": len(correlations),
        "targeted_changed_cve_count": len(changed_cves),
        "targeted_match_count": len(targeted_matches),
        "targeted_correlation_count": len(targeted),
        "api_projection_count": page_projection_count,
        "timing_seconds": {
            "fixture_generation": round(generated_at - started, 6),
            "schema_validation": round(validated_at - generated_at, 6),
            "catalog_import_projection": round(imported_at - validated_at, 6),
            "alias_and_match_index_generation": round(indexed_at - imported_at, 6),
            "full_exact_cve_correlation": round(correlated_at - indexed_at, 6),
            "targeted_reevaluation": round(targeted_at - correlated_at, 6),
            "api_pagination_projection": round(paginated_at - targeted_at, 6),
            "total": round(paginated_at - started, 6),
        },
        "peak_traced_memory_bytes": peak,
        "bounds": {
            "one_cve_index_per_batch": True,
            "duplicate_match_ids_rejected": True,
            "alias_values_per_match": 2,
            "page_size": page_size,
            "database_import_and_query_plan": "validated separately by isolated PostgreSQL lifecycle test",
        },
    }
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
