"""Versioned local advisory catalog persistence."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Sequence
from uuid import uuid4

from sqlalchemy import bindparam, text

from .advisory_catalog import AdvisoryCatalog
from .component_intelligence import normalized_token, purl_identity


ADVISORY_SCHEMA_SQL = (
    """
    CREATE TABLE IF NOT EXISTS advisory_catalog_imports (
        import_id TEXT PRIMARY KEY,
        catalog_version TEXT NOT NULL,
        source TEXT NOT NULL,
        source_version TEXT NOT NULL,
        source_license TEXT NOT NULL,
        provenance TEXT NOT NULL,
        checksum TEXT NOT NULL,
        generated_at TIMESTAMPTZ NOT NULL,
        imported_at TIMESTAMPTZ NOT NULL,
        advisory_count INTEGER NOT NULL,
        status TEXT NOT NULL,
        CHECK (status IN ('completed', 'failed')),
        UNIQUE (source, catalog_version, checksum)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS advisories (
        advisory_id TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        source_record_id TEXT NOT NULL,
        source_version TEXT NOT NULL,
        title TEXT NOT NULL,
        summary TEXT NOT NULL,
        severity TEXT NOT NULL,
        cvss DOUBLE PRECISION,
        known_exploited BOOLEAN NOT NULL DEFAULT FALSE,
        published_at TIMESTAMPTZ NOT NULL,
        modified_at TIMESTAMPTZ NOT NULL,
        withdrawn_at TIMESTAMPTZ,
        current BOOLEAN NOT NULL DEFAULT TRUE,
        catalog_import_id TEXT NOT NULL
            REFERENCES advisory_catalog_imports(import_id),
        checksum TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (source, source_record_id),
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
        CHECK (cvss IS NULL OR (cvss >= 0.0 AND cvss <= 10.0))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS advisory_aliases (
        advisory_id TEXT NOT NULL
            REFERENCES advisories(advisory_id) ON DELETE CASCADE,
        alias TEXT NOT NULL,
        PRIMARY KEY (advisory_id, alias)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS advisory_affected_components (
        affected_id TEXT PRIMARY KEY,
        advisory_id TEXT NOT NULL
            REFERENCES advisories(advisory_id) ON DELETE CASCADE,
        ecosystem TEXT NOT NULL,
        namespace TEXT,
        vendor TEXT,
        name TEXT NOT NULL,
        normalized_name TEXT NOT NULL,
        canonical_identifier TEXT,
        exact_versions_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        fixed_versions_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        architectures_json JSONB NOT NULL DEFAULT '[]'::jsonb,
        platforms_json JSONB NOT NULL DEFAULT '[]'::jsonb
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS advisory_version_ranges (
        range_id TEXT PRIMARY KEY,
        affected_id TEXT NOT NULL
            REFERENCES advisory_affected_components(affected_id) ON DELETE CASCADE,
        ordinal INTEGER NOT NULL,
        introduced TEXT,
        introduced_inclusive BOOLEAN NOT NULL DEFAULT TRUE,
        fixed TEXT,
        fixed_inclusive BOOLEAN NOT NULL DEFAULT FALSE,
        last_affected TEXT,
        last_affected_inclusive BOOLEAN NOT NULL DEFAULT TRUE,
        UNIQUE (affected_id, ordinal)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS advisory_references (
        advisory_id TEXT NOT NULL
            REFERENCES advisories(advisory_id) ON DELETE CASCADE,
        ordinal INTEGER NOT NULL,
        reference_type TEXT NOT NULL,
        reference_url TEXT NOT NULL,
        PRIMARY KEY (advisory_id, ordinal)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_advisories_current_severity ON advisories (current, withdrawn_at, severity, modified_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_advisories_known_exploited ON advisories (known_exploited, current) WHERE known_exploited = TRUE",
    "CREATE INDEX IF NOT EXISTS idx_advisory_aliases_alias ON advisory_aliases (alias)",
    "CREATE INDEX IF NOT EXISTS idx_advisory_affected_identity ON advisory_affected_components (ecosystem, canonical_identifier) WHERE canonical_identifier IS NOT NULL",
    "CREATE INDEX IF NOT EXISTS idx_advisory_affected_name ON advisory_affected_components (ecosystem, normalized_name, vendor)",
    "CREATE INDEX IF NOT EXISTS idx_advisory_ranges_affected ON advisory_version_ranges (affected_id, ordinal)",
    "CREATE INDEX IF NOT EXISTS idx_catalog_imports_imported ON advisory_catalog_imports (imported_at DESC)",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_catalog_imports_source_version_checksum_ci ON advisory_catalog_imports (LOWER(source), catalog_version, checksum)",
)
MAX_ADVISORY_MATCH_ROWS = 200_001


def ensure_advisory_schema(connection: Any) -> None:
    for statement in ADVISORY_SCHEMA_SQL:
        connection.execute(text(statement))


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


def advisory_id_for(*, source: str, source_record_id: str) -> str:
    canonical = "\x00".join((source.casefold(), source_record_id.casefold()))
    return "adv_" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def affected_id_for(
    *,
    advisory_id: str,
    ecosystem: str,
    identity: str,
    ordinal: int,
) -> str:
    canonical = "\x00".join((advisory_id, ecosystem, identity, str(ordinal)))
    return "aff_" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def _record_checksum(record: Any) -> str:
    data = json.dumps(
        record.model_dump(mode="json"),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def import_catalog(
    connection: Any,
    *,
    catalog: AdvisoryCatalog,
    checksum: str,
    imported_at: datetime | None = None,
    reactivate_existing: bool = False,
) -> dict[str, Any]:
    """Atomically replace one source's reviewed catalog snapshot."""

    imported = (imported_at or datetime.now(timezone.utc)).astimezone(
        timezone.utc
    )
    import_id = "aimp_" + uuid4().hex
    source = catalog.source.name
    connection.execute(
        text(
            """
            SELECT pg_advisory_xact_lock(
                hashtext('openassetwatch-advisory-catalog')::bigint
            )
            """
        )
    )
    existing = connection.execute(
        text(
            """
            SELECT import_id
            FROM advisory_catalog_imports
            WHERE LOWER(source) = LOWER(:source)
              AND catalog_version = :catalog_version
              AND checksum = :checksum
              AND status = 'completed'
            """
        ),
        {
            "source": source,
            "catalog_version": catalog.catalog_version,
            "checksum": checksum,
        },
    ).scalar_one_or_none()
    if existing and not reactivate_existing:
        return {
            "import_id": existing,
            "catalog_version": catalog.catalog_version,
            "source": source,
            "checksum": checksum,
            "advisory_count": len(catalog.advisories),
            "duplicate": True,
            "reactivated": False,
            "imported_at": imported,
        }
    if existing:
        import_id = str(existing)
    else:
        connection.execute(
            text(
                """
                INSERT INTO advisory_catalog_imports (
                    import_id, catalog_version, source, source_version,
                    source_license, provenance, checksum, generated_at,
                    imported_at, advisory_count, status
                )
                VALUES (
                    :import_id, :catalog_version, :source, :source_version,
                    :source_license, :provenance, :checksum, :generated_at,
                    :imported_at, :advisory_count, 'completed'
                )
                """
            ),
            {
                "import_id": import_id,
                "catalog_version": catalog.catalog_version,
                "source": source,
                "source_version": catalog.source.version,
                "source_license": catalog.source.license,
                "provenance": catalog.source.provenance,
                "checksum": checksum,
                "generated_at": catalog.generated_at,
                "imported_at": imported,
                "advisory_count": len(catalog.advisories),
            },
        )
    imported_advisory_ids: list[str] = []
    for record in catalog.advisories:
        advisory_id = advisory_id_for(
            source=source,
            source_record_id=record.id,
        )
        imported_advisory_ids.append(advisory_id)
        connection.execute(
            text(
                """
                INSERT INTO advisories (
                    advisory_id, source, source_record_id, source_version,
                    title, summary, severity, cvss, known_exploited,
                    published_at, modified_at, withdrawn_at, current,
                    catalog_import_id, checksum
                )
                VALUES (
                    :advisory_id, :source, :source_record_id, :source_version,
                    :title, :summary, :severity, :cvss, :known_exploited,
                    :published_at, :modified_at, :withdrawn_at, TRUE,
                    :catalog_import_id, :checksum
                )
                ON CONFLICT (advisory_id) DO UPDATE SET
                    source_version = EXCLUDED.source_version,
                    title = EXCLUDED.title,
                    summary = EXCLUDED.summary,
                    severity = EXCLUDED.severity,
                    cvss = EXCLUDED.cvss,
                    known_exploited = EXCLUDED.known_exploited,
                    published_at = EXCLUDED.published_at,
                    modified_at = EXCLUDED.modified_at,
                    withdrawn_at = EXCLUDED.withdrawn_at,
                    current = TRUE,
                    catalog_import_id = EXCLUDED.catalog_import_id,
                    checksum = EXCLUDED.checksum,
                    updated_at = NOW()
                """
            ),
            {
                "advisory_id": advisory_id,
                "source": source,
                "source_record_id": record.id,
                "source_version": catalog.source.version,
                "title": record.title,
                "summary": record.summary,
                "severity": record.severity,
                "cvss": record.cvss,
                "known_exploited": record.known_exploited,
                "published_at": record.published_at,
                "modified_at": record.modified_at,
                "withdrawn_at": record.withdrawn_at,
                "catalog_import_id": import_id,
                "checksum": _record_checksum(record),
            },
        )
        for table in (
            "advisory_aliases",
            "advisory_references",
        ):
            connection.execute(
                text(f"DELETE FROM {table} WHERE advisory_id = :advisory_id"),
                {"advisory_id": advisory_id},
            )
        connection.execute(
            text(
                """
                DELETE FROM advisory_affected_components
                WHERE advisory_id = :advisory_id
                """
            ),
            {"advisory_id": advisory_id},
        )
        for alias in record.aliases:
            connection.execute(
                text(
                    """
                    INSERT INTO advisory_aliases (advisory_id, alias)
                    VALUES (:advisory_id, :alias)
                    """
                ),
                {"advisory_id": advisory_id, "alias": alias},
            )
        for reference_ordinal, reference in enumerate(record.references):
            connection.execute(
                text(
                    """
                    INSERT INTO advisory_references (
                        advisory_id, ordinal, reference_type, reference_url
                    )
                    VALUES (
                        :advisory_id, :ordinal, :reference_type, :reference_url
                    )
                    """
                ),
                {
                    "advisory_id": advisory_id,
                    "ordinal": reference_ordinal,
                    "reference_type": reference.type,
                    "reference_url": reference.url,
                },
            )
        for affected_ordinal, affected in enumerate(record.affected):
            canonical_identifier = (
                purl_identity(affected.identifier)
                if affected.identifier
                else None
            )
            normalized_name = normalized_token(affected.name)
            identity = canonical_identifier or "\x1f".join(
                (
                    affected.vendor or "",
                    affected.namespace or "",
                    normalized_name,
                )
            )
            affected_id = affected_id_for(
                advisory_id=advisory_id,
                ecosystem=affected.ecosystem,
                identity=identity,
                ordinal=affected_ordinal,
            )
            connection.execute(
                text(
                    """
                    INSERT INTO advisory_affected_components (
                        affected_id, advisory_id, ecosystem, namespace, vendor,
                        name, normalized_name, canonical_identifier,
                        exact_versions_json, fixed_versions_json,
                        architectures_json, platforms_json
                    )
                    VALUES (
                        :affected_id, :advisory_id, :ecosystem, :namespace,
                        :vendor, :name, :normalized_name, :canonical_identifier,
                        CAST(:exact_versions_json AS JSONB),
                        CAST(:fixed_versions_json AS JSONB),
                        CAST(:architectures_json AS JSONB),
                        CAST(:platforms_json AS JSONB)
                    )
                    """
                ),
                {
                    "affected_id": affected_id,
                    "advisory_id": advisory_id,
                    "ecosystem": affected.ecosystem,
                    "namespace": affected.namespace,
                    "vendor": affected.vendor,
                    "name": affected.name,
                    "normalized_name": normalized_name,
                    "canonical_identifier": canonical_identifier,
                    "exact_versions_json": _json(affected.exact_versions),
                    "fixed_versions_json": _json(affected.fixed_versions),
                    "architectures_json": _json(affected.architectures),
                    "platforms_json": _json(affected.platforms),
                },
            )
            for range_ordinal, version_range in enumerate(affected.ranges):
                range_id = "rng_" + hashlib.sha256(
                    f"{affected_id}\x00{range_ordinal}".encode("utf-8")
                ).hexdigest()[:32]
                connection.execute(
                    text(
                        """
                        INSERT INTO advisory_version_ranges (
                            range_id, affected_id, ordinal, introduced,
                            introduced_inclusive, fixed, fixed_inclusive,
                            last_affected, last_affected_inclusive
                        )
                        VALUES (
                            :range_id, :affected_id, :ordinal, :introduced,
                            :introduced_inclusive, :fixed, :fixed_inclusive,
                            :last_affected, :last_affected_inclusive
                        )
                        """
                    ),
                    {
                        "range_id": range_id,
                        "affected_id": affected_id,
                        "ordinal": range_ordinal,
                        **version_range.model_dump(),
                    },
                )
    stale_statement = text(
        """
        UPDATE advisories
        SET current = FALSE, updated_at = NOW()
        WHERE LOWER(source) = LOWER(:source)
          AND current = TRUE
        """
        + (
            "\n          AND advisory_id NOT IN :advisory_ids"
            if imported_advisory_ids
            else ""
        )
    )
    params: dict[str, Any] = {"source": source}
    if imported_advisory_ids:
        stale_statement = stale_statement.bindparams(
            bindparam("advisory_ids", expanding=True)
        )
        params["advisory_ids"] = imported_advisory_ids
    connection.execute(stale_statement, params)
    return {
        "import_id": import_id,
        "catalog_version": catalog.catalog_version,
        "source": source,
        "checksum": checksum,
        "advisory_count": len(catalog.advisories),
        "duplicate": existing is not None,
        "reactivated": existing is not None,
        "imported_at": imported,
    }


class SqlAdvisoryStore:
    def __init__(self) -> None:
        self._schema_ready = False

    def _engine(self):
        from .database import get_engine

        return get_engine()

    def ensure_schema(self) -> None:
        if self._schema_ready:
            return
        with self._engine().begin() as connection:
            ensure_advisory_schema(connection)
        self._schema_ready = True

    def import_catalog(
        self,
        *,
        catalog: AdvisoryCatalog,
        checksum: str,
        imported_at: datetime | None = None,
    ) -> dict[str, Any]:
        self.ensure_schema()
        with self._engine().begin() as connection:
            return import_catalog(
                connection,
                catalog=catalog,
                checksum=checksum,
                imported_at=imported_at,
            )

    def catalog_status(self) -> dict[str, Any]:
        self.ensure_schema()
        with self._engine().begin() as connection:
            row = connection.execute(
                text(
                    """
                    SELECT
                        import_id, catalog_version, source, source_version,
                        source_license, provenance, checksum, generated_at,
                        imported_at, advisory_count, status
                    FROM advisory_catalog_imports
                    WHERE status = 'completed'
                    ORDER BY imported_at DESC
                    LIMIT 1
                    """
                )
            ).mappings().one_or_none()
            counts = connection.execute(
                text(
                    """
                    SELECT
                        COUNT(*) FILTER (WHERE current = TRUE) AS current_count,
                        COUNT(*) FILTER (
                            WHERE current = TRUE AND withdrawn_at IS NOT NULL
                        ) AS withdrawn_count,
                        COUNT(*) FILTER (
                            WHERE current = TRUE AND known_exploited = TRUE
                        ) AS known_exploited_count
                    FROM advisories
                    """
                )
            ).mappings().one()
        return {
            "catalog": dict(row) if row else None,
            "current_advisory_count": int(counts["current_count"] or 0),
            "withdrawn_advisory_count": int(counts["withdrawn_count"] or 0),
            "known_exploited_advisory_count": int(
                counts["known_exploited_count"] or 0
            ),
            "runtime_network_access": False,
        }

    def list_advisories_for_matching(
        self,
        *,
        advisory_id: str | None = None,
        advisory_ids: Sequence[str] | None = None,
        ecosystems: Sequence[str] | None = None,
        limit: int = 20_000,
    ) -> list[dict[str, Any]]:
        self.ensure_schema()
        if not 1 <= limit <= MAX_ADVISORY_MATCH_ROWS:
            raise ValueError(
                "advisory matching row limit must be between 1 and 200001"
            )
        safe_limit = limit
        advisory_id_values = sorted(set(advisory_ids or ()))
        if advisory_id and advisory_id_values:
            raise ValueError("advisory_id and advisory_ids are mutually exclusive")
        if len(advisory_id_values) > 20_000:
            raise ValueError("advisory ID filter limit exceeded")
        ecosystem_values = sorted(set(ecosystems or ()))
        ecosystem_filter = (
            "\n              AND aac.ecosystem IN :ecosystems"
            if ecosystem_values
            else ""
        )
        advisory_ids_filter = (
            "\n              AND a.advisory_id IN :advisory_ids"
            if advisory_id_values
            else ""
        )
        statement = text(
            """
            SELECT
                a.*, aac.affected_id, aac.ecosystem, aac.namespace,
                aac.vendor, aac.name, aac.normalized_name,
                aac.canonical_identifier, aac.exact_versions_json,
                aac.fixed_versions_json, aac.architectures_json,
                aac.platforms_json,
                COALESCE(
                    (
                        SELECT jsonb_agg(
                            jsonb_build_object(
                                'range_id', avr.range_id,
                                'introduced', avr.introduced,
                                'introduced_inclusive', avr.introduced_inclusive,
                                'fixed', avr.fixed,
                                'fixed_inclusive', avr.fixed_inclusive,
                                'last_affected', avr.last_affected,
                                'last_affected_inclusive',
                                    avr.last_affected_inclusive
                            )
                            ORDER BY avr.ordinal
                        )
                        FROM advisory_version_ranges avr
                        WHERE avr.affected_id = aac.affected_id
                    ),
                    '[]'::jsonb
                ) AS ranges_json,
                COALESCE(
                    (
                        SELECT jsonb_agg(aa.alias ORDER BY aa.alias)
                        FROM advisory_aliases aa
                        WHERE aa.advisory_id = a.advisory_id
                    ),
                    '[]'::jsonb
                ) AS aliases_json
            FROM advisories a
            JOIN advisory_affected_components aac
              ON aac.advisory_id = a.advisory_id
            WHERE (:advisory_id IS NULL OR a.advisory_id = :advisory_id)
            """
            + advisory_ids_filter
            + ecosystem_filter
            + """
            ORDER BY a.advisory_id, aac.affected_id
            LIMIT :limit
            """
        )
        params: dict[str, Any] = {
            "advisory_id": advisory_id,
            "limit": safe_limit,
        }
        if ecosystem_values:
            statement = statement.bindparams(
                bindparam("ecosystems", expanding=True)
            )
            params["ecosystems"] = ecosystem_values
        if advisory_id_values:
            statement = statement.bindparams(
                bindparam("advisory_ids", expanding=True)
            )
            params["advisory_ids"] = advisory_id_values
        with self._engine().begin() as connection:
            rows = connection.execute(statement, params).mappings().all()
        items = []
        for row in rows:
            item = dict(row)
            for source, target in (
                ("exact_versions_json", "exact_versions"),
                ("fixed_versions_json", "fixed_versions"),
                ("architectures_json", "architectures"),
                ("platforms_json", "platforms"),
                ("ranges_json", "ranges"),
                ("aliases_json", "aliases"),
            ):
                item[target] = _json_value(item.pop(source), [])
            items.append(item)
        return items
