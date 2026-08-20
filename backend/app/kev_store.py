"""Additive persistence and exact-CVE correlation for CISA KEV priority."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence
from uuid import uuid4

from sqlalchemy import bindparam, text

from .kev_catalog import CISA_KEV_SOURCE_ID, KevCatalog, KevRecord, normalize_cve


MAX_KEV_PAGE = 200
MAX_KEV_OFFSET = 100_000
MAX_KEV_CORRELATIONS = 200_000
MAX_KEV_FACTORS = 200_000
MAX_KEV_MATCH_REFRESH = 50_000
KEV_FRESH_DAYS = 8
KEV_AGING_DAYS = 14
KEV_WEIGHT = 12.0
KEV_RANSOMWARE_WEIGHT = 18.0


KEV_SCHEMA_SQL = (
    """
    CREATE TABLE IF NOT EXISTS kev_catalog_imports (
        import_id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL,
        catalog_version TEXT NOT NULL,
        catalog_date_released TIMESTAMPTZ NOT NULL,
        payload_sha256 TEXT NOT NULL,
        source_digest TEXT NOT NULL,
        catalog_sequence BIGINT,
        license_identifier TEXT NOT NULL,
        provenance_json JSONB NOT NULL,
        record_count INTEGER NOT NULL,
        active BOOLEAN NOT NULL DEFAULT FALSE,
        imported_at TIMESTAMPTZ NOT NULL,
        activated_at TIMESTAMPTZ,
        deactivated_at TIMESTAMPTZ,
        UNIQUE (source_id, catalog_version, payload_sha256)
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_kev_imports_active ON kev_catalog_imports (source_id) WHERE active = TRUE",
    "CREATE INDEX IF NOT EXISTS idx_kev_imports_released ON kev_catalog_imports (catalog_date_released DESC, import_id)",
    """
    CREATE TABLE IF NOT EXISTS kev_records (
        import_id TEXT NOT NULL REFERENCES kev_catalog_imports(import_id),
        kev_record_id TEXT NOT NULL,
        cve_id TEXT NOT NULL,
        vendor_project TEXT NOT NULL,
        product TEXT NOT NULL,
        vulnerability_name TEXT NOT NULL,
        date_added DATE NOT NULL,
        short_description TEXT NOT NULL,
        required_action TEXT NOT NULL,
        cisa_due_date DATE NOT NULL,
        ransomware_campaign_status TEXT NOT NULL,
        notes TEXT,
        cwes_json JSONB NOT NULL,
        record_digest TEXT NOT NULL,
        first_seen_at TIMESTAMPTZ NOT NULL,
        last_seen_at TIMESTAMPTZ NOT NULL,
        active BOOLEAN NOT NULL DEFAULT FALSE,
        PRIMARY KEY (import_id, kev_record_id),
        UNIQUE (import_id, cve_id),
        CHECK (ransomware_campaign_status IN ('Known', 'Unknown', 'Not supplied'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_kev_records_cve ON kev_records (cve_id, active)",
    "CREATE INDEX IF NOT EXISTS idx_kev_records_date_added ON kev_records (date_added DESC, cve_id)",
    "CREATE INDEX IF NOT EXISTS idx_kev_records_due_date ON kev_records (cisa_due_date, cve_id)",
    "CREATE INDEX IF NOT EXISTS idx_kev_records_ransomware ON kev_records (ransomware_campaign_status, active)",
    "CREATE INDEX IF NOT EXISTS idx_kev_records_import ON kev_records (import_id, active)",
    """
    CREATE TABLE IF NOT EXISTS kev_record_history (
        history_id BIGSERIAL PRIMARY KEY,
        kev_record_id TEXT NOT NULL,
        cve_id TEXT NOT NULL,
        import_id TEXT NOT NULL REFERENCES kev_catalog_imports(import_id),
        event_type TEXT NOT NULL,
        snapshot_json JSONB NOT NULL,
        recorded_at TIMESTAMPTZ NOT NULL,
        CHECK (event_type IN ('added', 'updated', 'removed', 'reactivated'))
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_kev_history_cve ON kev_record_history (cve_id, recorded_at DESC)",
    """
    CREATE TABLE IF NOT EXISTS advisory_kev_correlations (
        correlation_id TEXT PRIMARY KEY,
        import_id TEXT NOT NULL REFERENCES kev_catalog_imports(import_id),
        advisory_id TEXT NOT NULL REFERENCES advisories(advisory_id),
        kev_record_id TEXT NOT NULL,
        cve_id TEXT NOT NULL,
        exact_alias TEXT NOT NULL,
        first_seen_at TIMESTAMPTZ NOT NULL,
        last_seen_at TIMESTAMPTZ NOT NULL,
        current BOOLEAN NOT NULL DEFAULT FALSE,
        UNIQUE (import_id, advisory_id, cve_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_kev_correlations_advisory ON advisory_kev_correlations (advisory_id, current)",
    "CREATE INDEX IF NOT EXISTS idx_kev_correlations_cve ON advisory_kev_correlations (cve_id, current)",
    """
    CREATE TABLE IF NOT EXISTS vulnerability_priority_factors (
        factor_id TEXT PRIMARY KEY,
        import_id TEXT NOT NULL REFERENCES kev_catalog_imports(import_id),
        match_id TEXT NOT NULL REFERENCES vulnerability_matches(match_id),
        advisory_id TEXT NOT NULL REFERENCES advisories(advisory_id),
        kev_record_id TEXT NOT NULL,
        cve_id TEXT NOT NULL,
        priority_status TEXT NOT NULL,
        source_freshness TEXT NOT NULL,
        base_weight DOUBLE PRECISION NOT NULL,
        adjusted_weight DOUBLE PRECISION NOT NULL,
        first_seen_at TIMESTAMPTZ NOT NULL,
        last_seen_at TIMESTAMPTZ NOT NULL,
        current BOOLEAN NOT NULL DEFAULT FALSE,
        UNIQUE (import_id, match_id, cve_id),
        CHECK (priority_status IN ('known_exploited', 'known_exploited_ransomware')),
        CHECK (source_freshness IN ('fresh', 'aging', 'stale')),
        CHECK (base_weight >= 0 AND base_weight <= 25),
        CHECK (adjusted_weight >= 0 AND adjusted_weight <= 25)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_kev_factors_match ON vulnerability_priority_factors (match_id, current)",
    "CREATE INDEX IF NOT EXISTS idx_kev_factors_cve ON vulnerability_priority_factors (cve_id, current)",
    "CREATE INDEX IF NOT EXISTS idx_kev_factors_import ON vulnerability_priority_factors (import_id, current)",
    "CREATE INDEX IF NOT EXISTS idx_kev_factors_record_current ON vulnerability_priority_factors (kev_record_id, match_id) WHERE current = TRUE",
    """
    CREATE TABLE IF NOT EXISTS vulnerability_priority_factor_history (
        history_id BIGSERIAL PRIMARY KEY,
        factor_id TEXT NOT NULL,
        match_id TEXT NOT NULL,
        kev_record_id TEXT NOT NULL,
        cve_id TEXT NOT NULL,
        previous_current BOOLEAN,
        current_current BOOLEAN NOT NULL,
        snapshot_json JSONB NOT NULL,
        recorded_at TIMESTAMPTZ NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_kev_factor_history_match ON vulnerability_priority_factor_history (match_id, recorded_at DESC)",
)


def ensure_kev_schema(connection: Any) -> None:
    """Temporary compatibility seam; versioned migrations own durable DDL."""

    from .schema_migrations import ensure_schema_ready

    ensure_schema_ready(connection.engine)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, default=str)


def _json_value(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return default


def _record_digest(record: KevRecord) -> str:
    return hashlib.sha256(
        json.dumps(
            record.model_dump(mode="json"),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _identifier(prefix: str, *values: str) -> str:
    return prefix + hashlib.sha256("\x00".join(values).encode("utf-8")).hexdigest()


def catalog_freshness(released_at: datetime, *, now: datetime) -> str:
    age = max(now - released_at.astimezone(timezone.utc), timedelta())
    if age <= timedelta(days=KEV_FRESH_DAYS):
        return "fresh"
    if age <= timedelta(days=KEV_AGING_DAYS):
        return "aging"
    return "stale"


def _freshness_factor(value: str) -> float:
    return {"fresh": 1.0, "aging": 0.8, "stale": 0.45}.get(value, 0.45)


def _project_record(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["cwes"] = _json_value(item.pop("cwes_json", []), [])[:64]
    item.pop("record_digest", None)
    return item


def _active_import(connection: Any) -> Any:
    return connection.execute(
        text(
            "SELECT * FROM kev_catalog_imports WHERE source_id = :source_id AND active = TRUE"
        ),
        {"source_id": CISA_KEV_SOURCE_ID},
    ).mappings().one_or_none()


def _record_snapshot(record: KevRecord) -> dict[str, Any]:
    return record.model_dump(mode="json")


def _record_factor_deactivations(
    connection: Any,
    *,
    now: datetime,
    match_ids: Sequence[str] | None = None,
    except_factor_ids: set[str] | None = None,
) -> int:
    clauses = ["current = TRUE"]
    statement = """
        INSERT INTO vulnerability_priority_factor_history (
            factor_id, match_id, kev_record_id, cve_id,
            previous_current, current_current, snapshot_json,
            recorded_at
        )
        SELECT factor_id, match_id, kev_record_id, cve_id,
            TRUE, FALSE,
            jsonb_build_object(
                'priority_status', priority_status,
                'source_freshness', source_freshness,
                'adjusted_weight', adjusted_weight
            ),
            :now
        FROM vulnerability_priority_factors
        WHERE
    """
    params: dict[str, Any] = {"now": now}
    query = text(statement + " AND ".join(clauses))
    if match_ids is not None:
        clauses.append("match_id IN :match_ids")
        params["match_ids"] = list(match_ids)
    if except_factor_ids:
        clauses.append("factor_id NOT IN :factor_ids")
        params["factor_ids"] = sorted(except_factor_ids)
    query = text(statement + " AND ".join(clauses))
    if match_ids is not None:
        query = query.bindparams(bindparam("match_ids", expanding=True))
    if except_factor_ids:
        query = query.bindparams(bindparam("factor_ids", expanding=True))
    result = connection.execute(query, params)
    return int(result.rowcount or 0)


def refresh_match_priority_factors(
    connection: Any,
    *,
    match_ids: Sequence[str],
    now: datetime,
) -> dict[str, Any]:
    """Refresh KEV factors for authoritative match rows inside their transaction."""

    bounded_ids = sorted({str(value) for value in match_ids if value})
    if not bounded_ids:
        return {"refreshed_match_count": 0, "current_factor_count": 0, "affected_site_ids": []}
    if len(bounded_ids) > MAX_KEV_MATCH_REFRESH:
        raise ValueError("KEV match refresh exceeds the reviewed limit")
    ensure_kev_schema(connection)
    active = _active_import(connection)
    desired_rows: list[Any] = []
    freshness = "unavailable"
    if active is not None:
        freshness = catalog_freshness(active["catalog_date_released"], now=now)
        query = text(
            """
            SELECT DISTINCT vm.match_id, vm.advisory_id, vm.site_id,
                akc.kev_record_id, akc.cve_id,
                kr.ransomware_campaign_status
            FROM vulnerability_matches vm
            JOIN advisory_kev_correlations akc
              ON akc.advisory_id = vm.advisory_id
             AND akc.import_id = :import_id
             AND akc.current = TRUE
            JOIN kev_records kr
              ON kr.import_id = akc.import_id
             AND kr.kev_record_id = akc.kev_record_id
             AND kr.active = TRUE
            WHERE vm.match_id IN :match_ids
              AND vm.match_status = 'affected'
            ORDER BY vm.match_id, akc.cve_id
            LIMIT :limit
            """
        ).bindparams(bindparam("match_ids", expanding=True))
        desired_rows = connection.execute(
            query,
            {
                "match_ids": bounded_ids,
                "import_id": active["import_id"],
                "limit": MAX_KEV_FACTORS + 1,
            },
        ).mappings().all()
        if len(desired_rows) > MAX_KEV_FACTORS:
            raise ValueError("KEV priority-factor refresh limit exceeded")

    desired_ids = {
        _identifier("kevfac_", str(active["import_id"]), str(row["match_id"]), str(row["cve_id"]))
        for row in desired_rows
    } if active is not None else set()
    deactivated = _record_factor_deactivations(
        connection,
        now=now,
        match_ids=bounded_ids,
        except_factor_ids=desired_ids,
    )
    deactivate_query = text(
        """
        UPDATE vulnerability_priority_factors
        SET current = FALSE, last_seen_at = :now
        WHERE current = TRUE AND match_id IN :match_ids
        """
        + (" AND factor_id NOT IN :factor_ids" if desired_ids else "")
    ).bindparams(bindparam("match_ids", expanding=True))
    params: dict[str, Any] = {"now": now, "match_ids": bounded_ids}
    if desired_ids:
        deactivate_query = deactivate_query.bindparams(bindparam("factor_ids", expanding=True))
        params["factor_ids"] = sorted(desired_ids)
    connection.execute(deactivate_query, params)

    activated = 0
    sites: set[str] = set()
    for row in desired_rows:
        factor_id = _identifier(
            "kevfac_", str(active["import_id"]), str(row["match_id"]), str(row["cve_id"])
        )
        sites.add(str(row["site_id"]))
        ransomware = row["ransomware_campaign_status"] == "Known"
        priority_status = "known_exploited_ransomware" if ransomware else "known_exploited"
        base_weight = KEV_RANSOMWARE_WEIGHT if ransomware else KEV_WEIGHT
        adjusted_weight = round(base_weight * _freshness_factor(freshness), 4)
        previous_current = connection.execute(
            text("SELECT current FROM vulnerability_priority_factors WHERE factor_id = :factor_id"),
            {"factor_id": factor_id},
        ).scalar_one_or_none()
        connection.execute(
            text(
                """
                INSERT INTO vulnerability_priority_factors (
                    factor_id, import_id, match_id, advisory_id,
                    kev_record_id, cve_id, priority_status,
                    source_freshness, base_weight, adjusted_weight,
                    first_seen_at, last_seen_at, current
                ) VALUES (
                    :factor_id, :import_id, :match_id, :advisory_id,
                    :kev_record_id, :cve_id, :priority_status,
                    :source_freshness, :base_weight, :adjusted_weight,
                    :now, :now, TRUE
                )
                ON CONFLICT (import_id, match_id, cve_id) DO UPDATE SET
                    priority_status = EXCLUDED.priority_status,
                    source_freshness = EXCLUDED.source_freshness,
                    base_weight = EXCLUDED.base_weight,
                    adjusted_weight = EXCLUDED.adjusted_weight,
                    last_seen_at = EXCLUDED.last_seen_at,
                    current = TRUE
                """
            ),
            {
                **dict(row),
                "factor_id": factor_id,
                "import_id": active["import_id"],
                "priority_status": priority_status,
                "source_freshness": freshness,
                "base_weight": base_weight,
                "adjusted_weight": adjusted_weight,
                "now": now,
            },
        )
        if previous_current is not True:
            activated += 1
            connection.execute(
                text(
                    """
                    INSERT INTO vulnerability_priority_factor_history (
                        factor_id, match_id, kev_record_id, cve_id,
                        previous_current, current_current, snapshot_json,
                        recorded_at
                    ) VALUES (
                        :factor_id, :match_id, :kev_record_id, :cve_id,
                        :previous_current, TRUE, CAST(:snapshot AS JSONB), :now
                    )
                    """
                ),
                {
                    "factor_id": factor_id,
                    "match_id": row["match_id"],
                    "kev_record_id": row["kev_record_id"],
                    "cve_id": row["cve_id"],
                    "previous_current": previous_current,
                    "snapshot": _json(
                        {
                            "priority_status": priority_status,
                            "freshness": freshness,
                            "adjusted_weight": adjusted_weight,
                        }
                    ),
                    "now": now,
                },
            )
    return {
        "refreshed_match_count": len(bounded_ids),
        "current_factor_count": len(desired_rows),
        "activated_factor_count": activated,
        "deactivated_factor_count": deactivated,
        "affected_site_ids": sorted(sites),
    }


def import_kev_catalog(
    connection: Any,
    *,
    catalog: KevCatalog,
    checksum: str,
    imported_at: datetime,
    reactivate_existing: bool = True,
    catalog_sequence: int | None = None,
    source_digest: str | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Activate one normalized KEV catalog inside the shared feed transaction."""

    ensure_kev_schema(connection)
    # Match reconciliation and catalog activation both derive current KEV
    # factors. Share the match lock so neither can persist a stale snapshot
    # after the other workflow commits.
    connection.execute(
        text(
            """
            SELECT pg_advisory_xact_lock(
                hashtext('openassetwatch-vulnerability-matches')::bigint
            )
            """
        )
    )
    now = imported_at.astimezone(timezone.utc)
    previous_import = _active_import(connection)
    previous_records = {}
    if previous_import is not None:
        previous_records = {
            str(row["cve_id"]): dict(row)
            for row in connection.execute(
                text("SELECT * FROM kev_records WHERE import_id = :import_id"),
                {"import_id": previous_import["import_id"]},
            ).mappings().all()
        }

    existing = connection.execute(
        text(
            """
            SELECT import_id FROM kev_catalog_imports
            WHERE source_id = :source_id
              AND catalog_version = :catalog_version
              AND payload_sha256 = :payload_sha256
            """
        ),
        {
            "source_id": catalog.source.source_id,
            "catalog_version": catalog.catalog_version,
            "payload_sha256": checksum,
        },
    ).scalar_one_or_none()
    reactivated = existing is not None
    if reactivated and not reactivate_existing:
        raise ValueError("KEV catalog already exists")
    import_id = str(existing) if existing else "kevimp_" + uuid4().hex

    connection.execute(
        text(
            "UPDATE kev_catalog_imports SET active = FALSE, deactivated_at = :now "
            "WHERE source_id = :source_id AND active = TRUE"
        ),
        {"now": now, "source_id": CISA_KEV_SOURCE_ID},
    )
    connection.execute(text("UPDATE kev_records SET active = FALSE WHERE active = TRUE"))
    connection.execute(text("UPDATE advisory_kev_correlations SET current = FALSE WHERE current = TRUE"))
    _record_factor_deactivations(connection, now=now)
    connection.execute(
        text(
            "UPDATE vulnerability_priority_factors "
            "SET current = FALSE, last_seen_at = :now WHERE current = TRUE"
        ),
        {"now": now},
    )

    if not reactivated:
        connection.execute(
            text(
                """
                INSERT INTO kev_catalog_imports (
                    import_id, source_id, catalog_version,
                    catalog_date_released, payload_sha256, source_digest,
                    catalog_sequence, license_identifier, provenance_json,
                    record_count, active, imported_at, activated_at
                ) VALUES (
                    :import_id, :source_id, :catalog_version,
                    :catalog_date_released, :payload_sha256, :source_digest,
                    :catalog_sequence, :license_identifier,
                    CAST(:provenance_json AS JSONB), :record_count, TRUE,
                    :imported_at, :activated_at
                )
                """
            ),
            {
                "import_id": import_id,
                "source_id": catalog.source.source_id,
                "catalog_version": catalog.catalog_version,
                "catalog_date_released": catalog.catalog_date_released,
                "payload_sha256": checksum,
                "source_digest": source_digest or checksum,
                "catalog_sequence": catalog_sequence,
                "license_identifier": catalog.source.license_identifier,
                "provenance_json": _json(provenance or catalog.source.model_dump(mode="json")),
                "record_count": len(catalog.records),
                "imported_at": now,
                "activated_at": now,
            },
        )
        for record in catalog.records:
            previous = previous_records.get(record.cve_id)
            first_seen = previous["first_seen_at"] if previous else now
            digest = _record_digest(record)
            connection.execute(
                text(
                    """
                    INSERT INTO kev_records (
                        import_id, kev_record_id, cve_id, vendor_project,
                        product, vulnerability_name, date_added,
                        short_description, required_action, cisa_due_date,
                        ransomware_campaign_status, notes, cwes_json,
                        record_digest, first_seen_at, last_seen_at, active
                    ) VALUES (
                        :import_id, :kev_record_id, :cve_id, :vendor_project,
                        :product, :vulnerability_name, :date_added,
                        :short_description, :required_action, :cisa_due_date,
                        :ransomware_campaign_status, :notes,
                        CAST(:cwes_json AS JSONB), :record_digest,
                        :first_seen_at, :last_seen_at, TRUE
                    )
                    """
                ),
                {
                    **record.model_dump(mode="python", exclude={"cwes"}),
                    "import_id": import_id,
                    "cwes_json": _json(record.cwes),
                    "record_digest": digest,
                    "first_seen_at": first_seen,
                    "last_seen_at": now,
                },
            )
            event = "added" if previous is None else (
                "updated" if previous.get("record_digest") != digest else None
            )
            if event:
                connection.execute(
                    text(
                        """
                        INSERT INTO kev_record_history (
                            kev_record_id, cve_id, import_id, event_type,
                            snapshot_json, recorded_at
                        ) VALUES (
                            :kev_record_id, :cve_id, :import_id, :event_type,
                            CAST(:snapshot AS JSONB), :recorded_at
                        )
                        """
                    ),
                    {
                        "kev_record_id": record.kev_record_id,
                        "cve_id": record.cve_id,
                        "import_id": import_id,
                        "event_type": event,
                        "snapshot": _json(_record_snapshot(record)),
                        "recorded_at": now,
                    },
                )
        current_cves = {record.cve_id for record in catalog.records}
        for cve_id in sorted(set(previous_records) - current_cves):
            previous = previous_records[cve_id]
            connection.execute(
                text(
                    """
                    INSERT INTO kev_record_history (
                        kev_record_id, cve_id, import_id, event_type,
                        snapshot_json, recorded_at
                    ) VALUES (
                        :kev_record_id, :cve_id, :import_id, 'removed',
                        CAST(:snapshot AS JSONB), :recorded_at
                    )
                    """
                ),
                {
                    "kev_record_id": previous["kev_record_id"],
                    "cve_id": cve_id,
                    "import_id": import_id,
                    "snapshot": _json(_project_record(previous)),
                    "recorded_at": now,
                },
            )
    else:
        connection.execute(
            text(
                """
                UPDATE kev_catalog_imports
                SET active = TRUE, activated_at = :now,
                    deactivated_at = NULL, catalog_sequence = COALESCE(:sequence, catalog_sequence)
                WHERE import_id = :import_id
                """
            ),
            {"now": now, "sequence": catalog_sequence, "import_id": import_id},
        )
        connection.execute(
            text("UPDATE kev_records SET active = TRUE, last_seen_at = :now WHERE import_id = :import_id"),
            {"now": now, "import_id": import_id},
        )
        for record in catalog.records:
            connection.execute(
                text(
                    """
                    INSERT INTO kev_record_history (
                        kev_record_id, cve_id, import_id, event_type,
                        snapshot_json, recorded_at
                    ) VALUES (
                        :kev_record_id, :cve_id, :import_id, 'reactivated',
                        CAST(:snapshot AS JSONB), :recorded_at
                    )
                    """
                ),
                {
                    "kev_record_id": record.kev_record_id,
                    "cve_id": record.cve_id,
                    "import_id": import_id,
                    "snapshot": _json(_record_snapshot(record)),
                    "recorded_at": now,
                },
            )

    correlation_rows = connection.execute(
        text(
            """
            SELECT DISTINCT a.advisory_id, aa.alias AS exact_alias,
                kr.kev_record_id, kr.cve_id
            FROM kev_records kr
            JOIN advisory_aliases aa ON UPPER(aa.alias) = kr.cve_id
            JOIN advisories a ON a.advisory_id = aa.advisory_id
            WHERE kr.import_id = :import_id
              AND kr.active = TRUE
              AND a.current = TRUE
            ORDER BY a.advisory_id, kr.cve_id
            LIMIT :limit
            """
        ),
        {"import_id": import_id, "limit": MAX_KEV_CORRELATIONS + 1},
    ).mappings().all()
    if len(correlation_rows) > MAX_KEV_CORRELATIONS:
        raise ValueError("KEV exact-alias correlation limit exceeded")
    for row in correlation_rows:
        correlation_id = _identifier(
            "kevcorr_", import_id, str(row["advisory_id"]), str(row["cve_id"])
        )
        connection.execute(
            text(
                """
                INSERT INTO advisory_kev_correlations (
                    correlation_id, import_id, advisory_id, kev_record_id,
                    cve_id, exact_alias, first_seen_at, last_seen_at, current
                ) VALUES (
                    :correlation_id, :import_id, :advisory_id,
                    :kev_record_id, :cve_id, :exact_alias, :now, :now, TRUE
                )
                ON CONFLICT (import_id, advisory_id, cve_id) DO UPDATE SET
                    exact_alias = EXCLUDED.exact_alias,
                    last_seen_at = EXCLUDED.last_seen_at,
                    current = TRUE
                """
            ),
            {**dict(row), "correlation_id": correlation_id, "import_id": import_id, "now": now},
        )

    freshness = catalog_freshness(catalog.catalog_date_released, now=now)
    factor_rows = connection.execute(
        text(
            """
            SELECT DISTINCT vm.match_id, vm.advisory_id, vm.site_id,
                akc.kev_record_id, akc.cve_id,
                kr.ransomware_campaign_status
            FROM advisory_kev_correlations akc
            JOIN vulnerability_matches vm ON vm.advisory_id = akc.advisory_id
            JOIN kev_records kr
              ON kr.import_id = akc.import_id
             AND kr.kev_record_id = akc.kev_record_id
            WHERE akc.import_id = :import_id
              AND akc.current = TRUE
              AND vm.match_status = 'affected'
            ORDER BY vm.match_id, akc.cve_id
            LIMIT :limit
            """
        ),
        {"import_id": import_id, "limit": MAX_KEV_FACTORS + 1},
    ).mappings().all()
    if len(factor_rows) > MAX_KEV_FACTORS:
        raise ValueError("KEV priority-factor limit exceeded")
    active_factor_ids: set[str] = set()
    for row in factor_rows:
        factor_id = _identifier("kevfac_", import_id, str(row["match_id"]), str(row["cve_id"]))
        active_factor_ids.add(factor_id)
        ransomware = row["ransomware_campaign_status"] == "Known"
        status = "known_exploited_ransomware" if ransomware else "known_exploited"
        base = KEV_RANSOMWARE_WEIGHT if ransomware else KEV_WEIGHT
        adjusted = round(base * _freshness_factor(freshness), 4)
        previous_current = connection.execute(
            text("SELECT current FROM vulnerability_priority_factors WHERE factor_id = :factor_id"),
            {"factor_id": factor_id},
        ).scalar_one_or_none()
        connection.execute(
            text(
                """
                INSERT INTO vulnerability_priority_factors (
                    factor_id, import_id, match_id, advisory_id,
                    kev_record_id, cve_id, priority_status,
                    source_freshness, base_weight, adjusted_weight,
                    first_seen_at, last_seen_at, current
                ) VALUES (
                    :factor_id, :import_id, :match_id, :advisory_id,
                    :kev_record_id, :cve_id, :priority_status,
                    :source_freshness, :base_weight, :adjusted_weight,
                    :now, :now, TRUE
                )
                ON CONFLICT (import_id, match_id, cve_id) DO UPDATE SET
                    priority_status = EXCLUDED.priority_status,
                    source_freshness = EXCLUDED.source_freshness,
                    base_weight = EXCLUDED.base_weight,
                    adjusted_weight = EXCLUDED.adjusted_weight,
                    last_seen_at = EXCLUDED.last_seen_at,
                    current = TRUE
                """
            ),
            {
                **dict(row),
                "factor_id": factor_id,
                "import_id": import_id,
                "priority_status": status,
                "source_freshness": freshness,
                "base_weight": base,
                "adjusted_weight": adjusted,
                "now": now,
            },
        )
        if previous_current is not True:
            connection.execute(
                text(
                    """
                    INSERT INTO vulnerability_priority_factor_history (
                        factor_id, match_id, kev_record_id, cve_id,
                        previous_current, current_current, snapshot_json,
                        recorded_at
                    ) VALUES (
                        :factor_id, :match_id, :kev_record_id, :cve_id,
                        :previous_current, TRUE, CAST(:snapshot AS JSONB), :now
                    )
                    """
                ),
                {
                    "factor_id": factor_id,
                    "match_id": row["match_id"],
                    "kev_record_id": row["kev_record_id"],
                    "cve_id": row["cve_id"],
                    "previous_current": previous_current,
                    "snapshot": _json({"priority_status": status, "freshness": freshness, "adjusted_weight": adjusted}),
                    "now": now,
                },
            )

    previous_cves = set(previous_records)
    current_cves = {record.cve_id for record in catalog.records}
    changed = sorted(
        previous_cves ^ current_cves
        | {
            record.cve_id
            for record in catalog.records
            if record.cve_id in previous_records
            and previous_records[record.cve_id].get("record_digest") != _record_digest(record)
        }
    )
    affected_site_values: set[str] = set()
    if changed:
        site_query = text(
            """
            SELECT DISTINCT vm.site_id
            FROM vulnerability_priority_factors vpf
            JOIN vulnerability_matches vm ON vm.match_id = vpf.match_id
            WHERE vpf.cve_id IN :changed_cves
            ORDER BY vm.site_id
            LIMIT :limit
            """
        ).bindparams(bindparam("changed_cves", expanding=True))
        affected_site_values.update(
            str(value)
            for value in connection.execute(
                site_query,
                {"changed_cves": changed, "limit": 10_001},
            ).scalars().all()
        )
    previous_freshness = (
        catalog_freshness(previous_import["catalog_date_released"], now=now)
        if previous_import is not None
        else None
    )
    if previous_freshness is not None and previous_freshness != freshness:
        affected_site_values.update(
            str(value)
            for value in connection.execute(
                text(
                    """
                    SELECT DISTINCT vm.site_id
                    FROM vulnerability_priority_factors vpf
                    JOIN vulnerability_matches vm ON vm.match_id = vpf.match_id
                    WHERE vpf.import_id = :import_id
                      AND vpf.current = TRUE
                    ORDER BY vm.site_id
                    LIMIT :limit
                    """
                ),
                {"import_id": import_id, "limit": 10_001},
            ).scalars().all()
        )
    affected_sites = sorted(affected_site_values)
    if len(affected_sites) > 10_000:
        raise ValueError("KEV targeted site reevaluation limit exceeded")
    return {
        "import_id": import_id,
        "source_id": catalog.source.source_id,
        "catalog_version": catalog.catalog_version,
        "record_count": len(catalog.records),
        "correlation_count": len(correlation_rows),
        "priority_factor_count": len(factor_rows),
        "changed_cves": changed[:100],
        "changed_cve_count": len(changed),
        "changed_cves_truncated": len(changed) > 100,
        "affected_site_ids": affected_sites,
        "source_freshness": freshness,
        "reactivated": reactivated,
    }


class SqlKevStore:
    def __init__(self) -> None:
        self._schema_ready = False

    def _engine(self):
        from .database import get_engine

        return get_engine()

    def ensure_schema(self) -> None:
        if self._schema_ready:
            return
        from .schema_migrations import ensure_schema_ready

        ensure_schema_ready(self._engine())
        self._schema_ready = True

    def status(self, *, now: datetime | None = None) -> dict[str, Any]:
        self.ensure_schema()
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        with self._engine().begin() as connection:
            active = _active_import(connection)
            history_count = int(connection.execute(text("SELECT COUNT(*) FROM kev_catalog_imports")).scalar_one())
            factor_count = int(connection.execute(text("SELECT COUNT(*) FROM vulnerability_priority_factors WHERE current = TRUE")).scalar_one())
            match_count = int(connection.execute(text("SELECT COUNT(DISTINCT match_id) FROM vulnerability_priority_factors WHERE current = TRUE")).scalar_one())
        if active is None:
            return {
                "status": "KEV data unavailable",
                "source_id": CISA_KEV_SOURCE_ID,
                "freshness": "unavailable",
                "active_catalog": None,
                "history_count": history_count,
                "current_factor_count": 0,
                "current_match_count": 0,
            }
        item = dict(active)
        item["provenance"] = _json_value(item.pop("provenance_json", {}), {})
        freshness = catalog_freshness(item["catalog_date_released"], now=current)
        return {
            "status": "KEV catalog stale" if freshness == "stale" else "available",
            "source_id": CISA_KEV_SOURCE_ID,
            "freshness": freshness,
            "active_catalog": item,
            "history_count": history_count,
            "current_factor_count": factor_count,
            "current_match_count": match_count,
        }

    def list_records(
        self,
        *,
        cve_id: str | None = None,
        vendor_project: str | None = None,
        ransomware_status: str | None = None,
        date_added_from: Any = None,
        due_date_to: Any = None,
        site_id: str | None = None,
        asset_id: str | None = None,
        currently_affected: bool | None = None,
        priority: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        self.ensure_schema()
        if not 1 <= limit <= MAX_KEV_PAGE or not 0 <= offset <= MAX_KEV_OFFSET:
            raise ValueError("KEV pagination is outside reviewed bounds")
        normalized_cve = normalize_cve(cve_id) if cve_id else None
        if ransomware_status not in {None, "Known", "Unknown", "Not supplied"}:
            raise ValueError("ransomware status filter is invalid")
        if priority not in {None, "known_exploited", "known_exploited_ransomware"}:
            raise ValueError("KEV priority filter is invalid")
        where = [
            "kr.active = TRUE",
            "(:cve_id IS NULL OR kr.cve_id = :cve_id)",
            "(:vendor_project IS NULL OR LOWER(kr.vendor_project) = LOWER(:vendor_project))",
            "(:ransomware_status IS NULL OR kr.ransomware_campaign_status = :ransomware_status)",
            "(:date_added_from IS NULL OR kr.date_added >= :date_added_from)",
            "(:due_date_to IS NULL OR kr.cisa_due_date <= :due_date_to)",
            "((:site_id IS NULL AND :asset_id IS NULL) OR EXISTS (SELECT 1 FROM vulnerability_priority_factors vpf JOIN vulnerability_matches vm ON vm.match_id = vpf.match_id WHERE vpf.kev_record_id = kr.kev_record_id AND vpf.current = TRUE AND (:site_id IS NULL OR vm.site_id = :site_id) AND (:asset_id IS NULL OR vm.asset_id = :asset_id)))",
            "(:currently_affected IS NULL OR EXISTS (SELECT 1 FROM vulnerability_priority_factors vpf WHERE vpf.kev_record_id = kr.kev_record_id AND vpf.current = TRUE) = :currently_affected)",
            "(:priority IS NULL OR EXISTS (SELECT 1 FROM vulnerability_priority_factors vpf WHERE vpf.kev_record_id = kr.kev_record_id AND vpf.current = TRUE AND vpf.priority_status = :priority))",
        ]
        params = {
            "cve_id": normalized_cve,
            "vendor_project": vendor_project,
            "ransomware_status": ransomware_status,
            "date_added_from": date_added_from,
            "due_date_to": due_date_to,
            "site_id": site_id,
            "asset_id": asset_id,
            "currently_affected": currently_affected,
            "priority": priority,
            "limit": limit,
            "offset": offset,
        }
        base = " FROM kev_records kr WHERE " + " AND ".join(where)
        with self._engine().begin() as connection:
            rows = connection.execute(
                text(
                    "SELECT kr.*, (SELECT COUNT(*) FROM vulnerability_priority_factors vpf WHERE vpf.kev_record_id = kr.kev_record_id AND vpf.current = TRUE) AS current_match_count"
                    + base
                    + " ORDER BY kr.date_added DESC, kr.cve_id LIMIT :limit OFFSET :offset"
                ),
                params,
            ).mappings().all()
            total = int(connection.execute(text("SELECT COUNT(*)" + base), params).scalar_one())
        return {
            "items": [_project_record(row) for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
            "truncated": offset + len(rows) < total,
        }

    def get_record(self, cve_id: str) -> dict[str, Any] | None:
        result = self.list_records(cve_id=cve_id, limit=1)
        return result["items"][0] if result["items"] else None

    def asset_records(self, *, asset_id: str, site_id: str | None = None, limit: int = 200) -> dict[str, Any]:
        result = self.list_records(asset_id=asset_id, site_id=site_id, currently_affected=True, limit=limit)
        return result

    def summary(self, *, site_id: str | None = None, now: datetime | None = None) -> dict[str, Any]:
        status = self.status(now=now)
        self.ensure_schema()
        with self._engine().begin() as connection:
            params = {"site_id": site_id}
            row = connection.execute(
                text(
                    """
                    SELECT COUNT(DISTINCT vpf.kev_record_id) AS records,
                        COUNT(DISTINCT vpf.match_id) AS matches,
                        COUNT(DISTINCT vm.asset_id) AS assets,
                        COUNT(DISTINCT vm.site_id) AS sites,
                        COUNT(DISTINCT CASE WHEN vpf.priority_status = 'known_exploited_ransomware' THEN vpf.match_id END) AS ransomware_matches
                    FROM vulnerability_priority_factors vpf
                    JOIN vulnerability_matches vm ON vm.match_id = vpf.match_id
                    WHERE vpf.current = TRUE
                      AND (:site_id IS NULL OR vm.site_id = :site_id)
                    """
                ),
                params,
            ).mappings().one()
        return {**status, "current": dict(row), "site_filter": site_id}

    def enrich_matches(self, matches: Sequence[dict[str, Any]], *, now: datetime | None = None) -> list[dict[str, Any]]:
        values = [dict(item) for item in matches]
        if not values:
            return values
        self.ensure_schema()
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        match_ids = sorted({str(item.get("match_id")) for item in values if item.get("match_id")})
        with self._engine().begin() as connection:
            active = _active_import(connection)
            rows = []
            if match_ids:
                query = text(
                    """
                    SELECT vpf.*, kr.vendor_project, kr.product,
                        kr.vulnerability_name, kr.date_added,
                        kr.short_description, kr.required_action,
                        kr.cisa_due_date, kr.ransomware_campaign_status,
                        kci.catalog_version, kci.catalog_date_released,
                        kci.source_id, kci.license_identifier,
                        kci.payload_sha256, kci.provenance_json
                    FROM vulnerability_priority_factors vpf
                    JOIN kev_records kr
                      ON kr.import_id = vpf.import_id
                     AND kr.kev_record_id = vpf.kev_record_id
                    JOIN kev_catalog_imports kci ON kci.import_id = vpf.import_id
                    WHERE vpf.current = TRUE AND vpf.match_id IN :match_ids
                    ORDER BY vpf.match_id, vpf.cve_id
                    """
                ).bindparams(bindparam("match_ids", expanding=True))
                rows = connection.execute(query, {"match_ids": match_ids}).mappings().all()
        by_match: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            item = dict(row)
            item["provenance"] = _json_value(item.pop("provenance_json", {}), {})
            by_match.setdefault(str(item["match_id"]), []).append(item)
        active_freshness = (
            catalog_freshness(active["catalog_date_released"], now=current)
            if active is not None
            else "unavailable"
        )
        for item in values:
            factors = by_match.get(str(item.get("match_id")), [])
            aliases = item.get("aliases") if isinstance(item.get("aliases"), list) else []
            cve_aliases = []
            for alias in aliases:
                if not isinstance(alias, str):
                    continue
                try:
                    cve_aliases.append(normalize_cve(alias))
                except ValueError:
                    continue
            if item.get("match_status") != "affected":
                state = "not-currently-affected"
            elif factors:
                state = (
                    "known_exploited_ransomware"
                    if any(value["priority_status"] == "known_exploited_ransomware" for value in factors)
                    else "known_exploited"
                )
            elif active is None:
                state = "KEV data unavailable"
            elif not cve_aliases:
                state = "alias missing"
            else:
                state = "not_in_active_kev"
            item["kev"] = {
                "status": state,
                "source_id": CISA_KEV_SOURCE_ID,
                "freshness": active_freshness,
                "catalog_version": str(active["catalog_version"]) if active is not None else None,
                "exact_cve_aliases": sorted(set(cve_aliases)),
                "records": factors,
                "local_compromise_established": False,
                "required_action_execution": "disabled",
            }
        return values

    def rebuild_active(self, *, now: datetime | None = None) -> dict[str, Any]:
        self.ensure_schema()
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        with self._engine().begin() as connection:
            active = _active_import(connection)
            if active is None:
                raise ValueError("KEV data unavailable")
            rows = connection.execute(
                text("SELECT * FROM kev_records WHERE import_id = :import_id ORDER BY cve_id"),
                {"import_id": active["import_id"]},
            ).mappings().all()
            records = [
                KevRecord.model_validate(
                    {
                        "kev_record_id": row["kev_record_id"],
                        "cve_id": row["cve_id"],
                        "vendor_project": row["vendor_project"],
                        "product": row["product"],
                        "vulnerability_name": row["vulnerability_name"],
                        "date_added": row["date_added"],
                        "short_description": row["short_description"],
                        "required_action": row["required_action"],
                        "cisa_due_date": row["cisa_due_date"],
                        "ransomware_campaign_status": row["ransomware_campaign_status"],
                        "notes": row["notes"],
                        "cwes": _json_value(row["cwes_json"], []),
                    }
                )
                for row in rows
            ]
            from .kev_catalog import KevCatalogSource

            catalog = KevCatalog(
                schema_version="oaw.kev-catalog.v1",
                source=KevCatalogSource.model_validate(
                    _json_value(active["provenance_json"], {}).get("source", {})
                    or {
                        "source_id": CISA_KEV_SOURCE_ID,
                        "name": "CISA Known Exploited Vulnerabilities",
                        "official_mirror_url": "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
                        "canonical_documentation_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                        "license_identifier": "CC0-1.0",
                        "provenance": "CISA KEV official source; normalized by OpenAssetWatch.",
                    }
                ),
                catalog_version=active["catalog_version"],
                catalog_date_released=active["catalog_date_released"],
                records=records,
            )
            result = import_kev_catalog(
                connection,
                catalog=catalog,
                checksum=active["payload_sha256"],
                imported_at=current,
                reactivate_existing=True,
                catalog_sequence=active["catalog_sequence"],
                source_digest=active["source_digest"],
                provenance=_json_value(active["provenance_json"], {}),
            )
            all_sites = [
                str(value)
                for value in connection.execute(
                    text(
                        """
                        SELECT DISTINCT vm.site_id
                        FROM vulnerability_priority_factors vpf
                        JOIN vulnerability_matches vm ON vm.match_id = vpf.match_id
                        WHERE vpf.current = TRUE
                        ORDER BY vm.site_id
                        LIMIT 10001
                        """
                    )
                ).scalars().all()
            ]
            if len(all_sites) > 10_000:
                raise ValueError("KEV full rebuild site limit exceeded")
            return {**result, "affected_site_ids": all_sites, "full_rebuild": True}
