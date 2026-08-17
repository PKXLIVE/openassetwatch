#!/usr/bin/env python3
"""Validate and atomically install a reviewed local vendor catalog."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.vendor_catalog import CatalogPathError, CatalogValidationError, replace_catalog  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate a local JSON vendor catalog and atomically install it. "
            "This command never downloads catalog data."
        )
    )
    parser.add_argument("--source", type=Path, required=True, help="local reviewed JSON catalog")
    parser.add_argument(
        "--target-directory",
        type=Path,
        required=True,
        help="existing trusted directory that will contain vendor-catalog.json",
    )
    arguments = parser.parse_args()
    try:
        installed = replace_catalog(
            source_path=arguments.source,
            target_directory=arguments.target_directory,
        )
    except (CatalogPathError, CatalogValidationError) as exc:
        print(f"catalog import rejected: {exc}", file=sys.stderr)
        return 2
    print(f"installed validated catalog: {installed.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
