#!/usr/bin/env python3
"""Preview historical collector compatibility without changing repository data."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.database import get_engine  # noqa: E402


PREVIEW_SQL = text(
    """
    SELECT
        COUNT(*) AS legacy_records,
        COUNT(m.mapping_id) AS already_mapped,
        COUNT(*) FILTER (
            WHERE m.mapping_id IS NULL
              AND (
                  s.collector_guid IS NOT NULL
                  OR s.collector_id IS NOT NULL
              )
              AND jsonb_typeof(s.payload_json) = 'object'
        ) AS safely_mappable,
        COUNT(*) FILTER (
            WHERE m.mapping_id IS NULL
              AND s.collector_guid IS NULL
              AND s.collector_id IS NULL
        ) AS ambiguous_records
    FROM collector_inventory_submissions s
    LEFT JOIN legacy_submission_mappings m
      ON m.legacy_submission_id = s.id
    """
)


def preview() -> dict[str, object]:
    with get_engine().connect() as connection:
        transaction = connection.begin()
        try:
            connection.exec_driver_sql("SET TRANSACTION READ ONLY")
            row = connection.execute(PREVIEW_SQL).mappings().one()
            transaction.commit()
        except Exception:
            transaction.rollback()
            raise
    total = int(row["legacy_records"])
    mapped = int(row["already_mapped"])
    safely_mappable = int(row["safely_mappable"])
    ambiguous = int(row["ambiguous_records"])
    return {
        "schema_version": "oaw.historical-ingestion-preview.v1",
        "legacy_records": total,
        "already_mapped": mapped,
        "safely_mappable": safely_mappable,
        "ambiguous_records": ambiguous,
        "historical_only": max(0, total - mapped - safely_mappable),
        "conflicts": 0,
        "mutation_performed": False,
    }


def main() -> int:
    try:
        report = preview()
    except (SQLAlchemyError, KeyError, TypeError, ValueError):
        print(
            json.dumps(
                {
                    "status": "error",
                    "error_code": "historical-preview-unavailable",
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
