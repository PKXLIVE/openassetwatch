#!/usr/bin/env python3
"""Import one reviewed local advisory catalog without network access."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Validate and atomically import a bounded OpenAssetWatch advisory "
            "catalog. The importer performs no network requests."
        )
    )
    parser.add_argument(
        "--source",
        required=True,
        type=Path,
        help="Path to a reviewed oaw.advisory-catalog.v1 JSON file.",
    )
    parser.add_argument(
        "--skip-evaluation",
        action="store_true",
        help="Import without immediately running a bounded full evaluation.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    sys.path.insert(0, str(BACKEND_ROOT))

    from app.advisory_catalog import CatalogValidationError, load_catalog
    from app.advisory_store import SqlAdvisoryStore
    from app.vulnerability_service import evaluate_vulnerabilities

    try:
        catalog, checksum = load_catalog(args.source.resolve(strict=True))
        result = SqlAdvisoryStore().import_catalog(
            catalog=catalog,
            checksum=checksum,
        )
        output: dict[str, object] = {
            **result,
            "source_license": catalog.source.license,
            "provenance": catalog.source.provenance,
            "runtime_network_access": False,
        }
        if not args.skip_evaluation:
            output["evaluation"] = evaluate_vulnerabilities(
                trigger_type="offline-advisory-import",
                requested_by="local-maintainer",
            ).as_dict()
    except CatalogValidationError as exc:
        print(f"Advisory catalog rejected: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - CLI returns a bounded error type.
        print(
            f"Advisory catalog import failed safely: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(output, default=str, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
