"""Versioned, checksummed PostgreSQL schema migrations for OpenAssetWatch."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import threading
import time
import weakref
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Sequence

from sqlalchemy import text
from sqlalchemy.engine import Connection, Engine


MIGRATION_DIRECTORY = Path(__file__).resolve().with_name("migration_sql")
MIGRATION_FILENAME = re.compile(
    r"^(?P<version>[0-9]{4})_(?P<name>[a-z0-9][a-z0-9_]*)\.sql$"
)
MAX_MIGRATION_BYTES = 2 << 20
MIGRATION_LOCK_ID = int.from_bytes(
    hashlib.sha256(b"openassetwatch:schema-migrations:v1").digest()[:8],
    byteorder="big",
    signed=True,
)
MIGRATION_LOCK_TIMEOUT_SECONDS = 30.0
APPLICATION_VERSION = "0.1.0"
MINIMUM_APPLICATION_VERSION = "0.1.0"
MIGRATION_STATE_TABLE = "oaw_schema_migrations"
MIGRATION_STATE_SQL = """
CREATE TABLE IF NOT EXISTS public.oaw_schema_migrations (
    version INTEGER PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    checksum CHAR(64) NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    execution_duration_ms INTEGER NOT NULL,
    application_version VARCHAR(64) NOT NULL,
    minimum_application_version VARCHAR(64) NOT NULL,
    CHECK (version > 0),
    CHECK (execution_duration_ms >= 0 AND execution_duration_ms <= 86400000),
    CHECK (checksum ~ '^[0-9a-f]{64}$')
)
"""
_CREATE_TABLE_PATTERN = re.compile(
    r"CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\s+(?:public\.)?"
    r"(?P<table>[a-z][a-z0-9_]*)\s*\((?P<body>.*?)^\);",
    re.IGNORECASE | re.MULTILINE | re.DOTALL,
)
_ALTER_COLUMN_PATTERN = re.compile(
    r"ALTER\s+TABLE\s+(?:public\.)?(?P<table>[a-z][a-z0-9_]*)\s+"
    r"ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\s+"
    r"(?P<column>[a-z][a-z0-9_]*)\s+(?P<definition>[^;]+)",
    re.IGNORECASE,
)
_INDEX_PATTERN = re.compile(
    r"CREATE\s+(?P<unique>UNIQUE\s+)?INDEX\s+IF\s+NOT\s+EXISTS\s+"
    r"(?P<index>[a-z][a-z0-9_]*)\s+ON\s+(?:public\.)?"
    r"(?P<table>[a-z][a-z0-9_]*)",
    re.IGNORECASE,
)
_COLUMN_PATTERN = re.compile(
    r"^(?P<column>[a-z][a-z0-9_]*)\s+"
    r"(?P<type>DOUBLE\s+PRECISION|TIMESTAMPTZ|BIGSERIAL|BIGINT|INTEGER|"
    r"BOOLEAN|JSONB|TEXT|DATE|BYTEA|VARCHAR\([0-9]+\)|CHAR\([0-9]+\))"
    r"(?P<remainder>(?:\s+.*)?)$",
    re.IGNORECASE | re.DOTALL,
)
_CONSTRAINT_PREFIXES = (
    "CHECK ",
    "CONSTRAINT ",
    "FOREIGN KEY ",
    "PRIMARY KEY ",
    "UNIQUE ",
)
_TYPE_NAMES = {
    "BIGSERIAL": ("bigint", None),
    "BIGINT": ("bigint", None),
    "INTEGER": ("integer", None),
    "TEXT": ("text", None),
    "JSONB": ("jsonb", None),
    "TIMESTAMPTZ": ("timestamp with time zone", None),
    "DOUBLE PRECISION": ("double precision", None),
    "BOOLEAN": ("boolean", None),
    "DATE": ("date", None),
    "BYTEA": ("bytea", None),
}


class SchemaMigrationError(RuntimeError):
    """Bounded migration failure safe for logs, health, and operator output."""

    def __init__(self, code: str, summary: str) -> None:
        self.code = re.sub(r"[^a-z0-9-]", "-", code.lower())[:80]
        self.summary = " ".join(summary.split())[:240]
        super().__init__(self.summary)


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    checksum: str
    sql: str

    @property
    def identifier(self) -> str:
        return f"{self.version:04d}_{self.name}"


@dataclass(frozen=True)
class ExpectedColumn:
    data_type: str
    nullable: bool
    maximum_length: int | None = None
    default: str | None = None


@dataclass(frozen=True)
class SchemaContract:
    columns: dict[str, dict[str, ExpectedColumn]]
    primary_keys: dict[str, tuple[str, ...]]
    unique_constraints: dict[str, frozenset[tuple[str, ...]]]
    foreign_keys: dict[
        str,
        frozenset[tuple[tuple[str, ...], str, tuple[str, ...], str]],
    ]
    check_constraints: dict[str, frozenset[str]]
    indexes: dict[str, tuple[str, bool, tuple[str, ...], str | None]]
    safely_addable_columns: frozenset[tuple[str, str]]


@dataclass(frozen=True)
class SchemaStatus:
    state: str
    current_version: int
    latest_available_version: int
    pending_migration_count: int
    compatibility_state: str
    checksum_integrity: str
    last_migration_time: datetime | None = None
    failure_code: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


_ready_lock = threading.Lock()
_ready_engines: weakref.WeakKeyDictionary[Engine, SchemaStatus] = (
    weakref.WeakKeyDictionary()
)
_runtime_lock = threading.Lock()
_runtime_readiness: dict[str, Any] = {
    "state": "not-started",
    "current_version": 0,
    "latest_available_version": 0,
    "failure_code": None,
}


def _bounded_application_version() -> str:
    value = os.getenv("OPENASSETWATCH_CONTROL_TOWER_VERSION", APPLICATION_VERSION)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}", value):
        return APPLICATION_VERSION
    return value


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _unsafe_posix_write_permissions(path: Path, mode: int) -> bool:
    if os.name != "posix" or not mode & 0o022:
        return False
    try:
        flags = os.statvfs(path).f_flag
    except OSError:
        return True
    return not bool(flags & getattr(os, "ST_RDONLY", 1))


def _safe_read_migration(path: Path, directory: Path) -> bytes:
    try:
        directory_before = directory.lstat()
        if directory.is_symlink() or not stat.S_ISDIR(directory_before.st_mode):
            raise SchemaMigrationError(
                "migration-root-invalid", "Migration root is not a regular directory."
            )
        if _unsafe_posix_write_permissions(directory, directory_before.st_mode):
            raise SchemaMigrationError(
                "migration-root-permissions",
                "Migration root must not be group-writable or world-writable.",
            )
        candidate = path.absolute()
        if candidate.parent != directory.absolute():
            raise SchemaMigrationError(
                "migration-path-invalid", "Migration file escaped the fixed migration root."
            )
        before = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise SchemaMigrationError(
                "migration-file-invalid",
                "Migration file must be regular, single-linked, and non-replaced.",
            )
        if _unsafe_posix_write_permissions(path, before.st_mode):
            raise SchemaMigrationError(
                "migration-file-permissions",
                "Migration file must not be group-writable or world-writable.",
            )
        flags = os.O_RDONLY
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or not _same_file_identity(before, opened)
            ):
                raise SchemaMigrationError(
                    "migration-file-replaced",
                    "Migration file changed identity while being opened.",
                )
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, 64 << 10)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_MIGRATION_BYTES:
                    raise SchemaMigrationError(
                        "migration-file-too-large", "Migration exceeds the reviewed size limit."
                    )
                chunks.append(chunk)
        finally:
            os.close(descriptor)
        after = path.lstat()
        directory_after = directory.lstat()
        if (
            not _same_file_identity(before, after)
            or not _same_file_identity(directory_before, directory_after)
        ):
            raise SchemaMigrationError(
                "migration-file-replaced",
                "Migration path changed while its bytes were read.",
            )
        return b"".join(chunks)
    except SchemaMigrationError:
        raise
    except (OSError, ValueError) as exc:
        raise SchemaMigrationError(
            "migration-file-unavailable",
            f"Migration file could not be read safely ({type(exc).__name__}).",
        ) from None


def discover_migrations(directory: Path = MIGRATION_DIRECTORY) -> tuple[Migration, ...]:
    """Discover immutable migrations from a fixed or explicitly test-owned root."""

    try:
        entries = list(directory.iterdir())
    except OSError as exc:
        raise SchemaMigrationError(
            "migration-root-unavailable",
            f"Migration root could not be inspected ({type(exc).__name__}).",
        ) from None
    migrations: list[Migration] = []
    versions: set[int] = set()
    for path in entries:
        match = MIGRATION_FILENAME.fullmatch(path.name)
        if match is None:
            raise SchemaMigrationError(
                "migration-filename-invalid",
                "Migration root contains an unrecognized entry.",
            )
        version = int(match.group("version"))
        if version <= 0 or version in versions:
            raise SchemaMigrationError(
                "migration-version-duplicate", "Migration versions must be unique and positive."
            )
        payload = _safe_read_migration(path, directory)
        if not payload or b"\x00" in payload:
            raise SchemaMigrationError(
                "migration-content-invalid", "Migration bytes are empty or malformed."
            )
        try:
            sql = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise SchemaMigrationError(
                "migration-content-invalid", "Migration must be strict UTF-8 text."
            ) from None
        if re.search(r"(?m)^\s*\\", sql):
            raise SchemaMigrationError(
                "migration-content-invalid",
                "Migration SQL cannot contain client-side include commands.",
            )
        versions.add(version)
        migrations.append(
            Migration(
                version=version,
                name=match.group("name"),
                checksum=hashlib.sha256(payload).hexdigest(),
                sql=sql,
            )
        )
    migrations.sort(key=lambda item: item.version)
    if not migrations:
        raise SchemaMigrationError(
            "migration-set-empty", "No reviewed schema migrations are available."
        )
    expected_versions = list(range(1, migrations[-1].version + 1))
    actual_versions = [item.version for item in migrations]
    if actual_versions != expected_versions:
        raise SchemaMigrationError(
            "migration-version-gap", "Migration versions must be contiguous from 0001."
        )
    return tuple(migrations)


def _split_sql_items(body: str) -> list[str]:
    items: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    index = 0
    while index < len(body):
        char = body[index]
        if quote:
            if char == quote:
                if index + 1 < len(body) and body[index + 1] == quote:
                    index += 1
                else:
                    quote = None
        elif char in {"'", '"'}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            items.append(body[start:index].strip())
            start = index + 1
        index += 1
    tail = body[start:].strip()
    if tail:
        items.append(tail)
    return items


def _normalize_sql_fragment(value: str) -> str:
    normalized = " ".join(value.strip().split()).lower()
    normalized = re.sub(r"\s*,\s*", ",", normalized)
    normalized = re.sub(r"\(\s+", "(", normalized)
    normalized = re.sub(r"\s+\)", ")", normalized)
    normalized = re.sub(
        r"::(?:text|character\s+varying|double\s+precision|numeric|integer|bigint|boolean|date)\b(?:\[\])?",
        "",
        normalized,
    )
    normalized = re.sub(
        r"\b(lower|length|nextval|any|in)\s+\(", r"\1(", normalized
    )
    normalized = re.sub(
        r"\b([a-z][a-z0-9_]*)\s*=\s*any\(array\[([^\]]+)\]\)",
        r"\1 in(\2)",
        normalized,
    )
    normalized = re.sub(
        r"\b([a-z][a-z0-9_]*)\s+in\(([^,()]+)\)",
        r"\1=\2",
        normalized,
    )
    normalized = re.sub(
        r"\b([a-z][a-z0-9_]*)\s+between\s+([^\s()]+)\s+and\s+([^\s()]+)",
        r"\1>=\2 and \1<=\3",
        normalized,
    )
    normalized = re.sub(r"\s*(>=|<=|<>|=|>|<|~)\s*", r"\1", normalized)
    while normalized.startswith("(") and normalized.endswith(")"):
        depth = 0
        wraps_entire_value = True
        quote: str | None = None
        for index, char in enumerate(normalized):
            if quote:
                if char == quote:
                    quote = None
                continue
            if char in {"'", '"'}:
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0 and index != len(normalized) - 1:
                    wraps_entire_value = False
                    break
        if not wraps_entire_value:
            break
        normalized = normalized[1:-1].strip()
    previous = None
    while previous != normalized:
        previous = normalized
        normalized = re.sub(
            r"\(([^()]+(?:\s+and\s+[^()]+)+)\)",
            lambda match: (
                match.group(0)
                if " or " in match.group(1)
                else match.group(1)
            ),
            normalized,
        )
    return normalized


def _expected_default(raw_type: str, remainder: str) -> str | None:
    if raw_type == "BIGSERIAL":
        return "serial-sequence"
    match = re.search(
        r"\bDEFAULT\s+(.+?)(?=\s+(?:NOT\s+NULL|NULL|REFERENCES|CHECK|UNIQUE|PRIMARY\s+KEY)\b|$)",
        remainder,
        re.IGNORECASE | re.DOTALL,
    )
    if match is None:
        return None
    return _normalize_sql_fragment(match.group(1))


def _actual_default(value: object) -> str | None:
    if value is None:
        return None
    return _normalize_sql_fragment(str(value))


def _expected_column(definition: str) -> tuple[str, ExpectedColumn] | None:
    match = _COLUMN_PATTERN.match(" ".join(definition.split()))
    if match is None:
        return None
    raw_type = match.group("type").upper()
    maximum_length: int | None = None
    if raw_type.startswith("VARCHAR("):
        data_type = "character varying"
        maximum_length = int(raw_type[8:-1])
    elif raw_type.startswith("CHAR("):
        data_type = "character"
        maximum_length = int(raw_type[5:-1])
    else:
        data_type, maximum_length = _TYPE_NAMES[raw_type]
    remainder = match.group("remainder").upper()
    nullable = "NOT NULL" not in remainder and "PRIMARY KEY" not in remainder
    return match.group("column").lower(), ExpectedColumn(
        data_type=data_type,
        nullable=nullable,
        maximum_length=maximum_length,
        default=_expected_default(raw_type, match.group("remainder")),
    )


def _column_list(value: str) -> tuple[str, ...]:
    return tuple(
        part.strip().split()[0].lower()
        for part in value.split(",")
        if part.strip()
    )


def _expected_foreign_key(
    definition: str,
    *,
    column_name: str | None = None,
) -> tuple[tuple[str, ...], str, tuple[str, ...], str] | None:
    if column_name is None:
        match = re.fullmatch(
            r"FOREIGN\s+KEY\s*\((?P<local>[^)]+)\)\s+"
            r"REFERENCES\s+(?:public\.)?(?P<table>[a-z][a-z0-9_]*)\s*"
            r"\((?P<remote>[^)]+)\)"
            r"(?:\s+ON\s+DELETE\s+(?P<delete>CASCADE|SET\s+NULL|RESTRICT|NO\s+ACTION))?",
            definition,
            re.IGNORECASE | re.DOTALL,
        )
        if match is None:
            return None
        local_columns = _column_list(match.group("local"))
    else:
        match = re.search(
            r"\bREFERENCES\s+(?:public\.)?(?P<table>[a-z][a-z0-9_]*)\s*"
            r"\((?P<remote>[^)]+)\)"
            r"(?:\s+ON\s+DELETE\s+(?P<delete>CASCADE|SET\s+NULL|RESTRICT|NO\s+ACTION))?",
            definition,
            re.IGNORECASE | re.DOTALL,
        )
        if match is None:
            return None
        local_columns = (column_name,)
    return (
        local_columns,
        match.group("table").lower(),
        _column_list(match.group("remote")),
        " ".join((match.group("delete") or "NO ACTION").lower().split()),
    )


def _expected_indexes(
    sql: str,
) -> dict[str, tuple[str, bool, tuple[str, ...], str | None]]:
    indexes: dict[str, tuple[str, bool, tuple[str, ...], str | None]] = {}
    for match in _INDEX_PATTERN.finditer(sql):
        opening = sql.find("(", match.end())
        if opening < 0:
            raise SchemaMigrationError(
                "migration-contract-invalid", "Migration index has no key definition."
            )
        depth = 0
        quote: str | None = None
        closing = -1
        cursor = opening
        while cursor < len(sql):
            char = sql[cursor]
            if quote:
                if char == quote:
                    if cursor + 1 < len(sql) and sql[cursor + 1] == quote:
                        cursor += 1
                    else:
                        quote = None
            elif char in {"'", '"'}:
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    closing = cursor
                    break
            cursor += 1
        statement_end = sql.find(";", closing + 1) if closing >= 0 else -1
        if closing < 0 or statement_end < 0:
            raise SchemaMigrationError(
                "migration-contract-invalid", "Migration index definition is malformed."
            )
        keys = tuple(
            _normalize_sql_fragment(item)
            for item in _split_sql_items(sql[opening + 1 : closing])
        )
        if not keys or any(not item for item in keys):
            raise SchemaMigrationError(
                "migration-contract-invalid", "Migration index has invalid keys."
            )
        remainder = sql[closing + 1 : statement_end].strip()
        predicate: str | None = None
        if remainder:
            predicate_match = re.fullmatch(
                r"WHERE\s+(.+)", remainder, re.IGNORECASE | re.DOTALL
            )
            if predicate_match is None:
                raise SchemaMigrationError(
                    "migration-contract-invalid",
                    "Migration index contains unsupported options.",
                )
            predicate = _normalize_sql_fragment(predicate_match.group(1))
        index_name = match.group("index").lower()
        if index_name in indexes:
            raise SchemaMigrationError(
                "migration-contract-invalid", "Migration index names must be unique."
            )
        indexes[index_name] = (
            match.group("table").lower(),
            bool(match.group("unique")),
            keys,
            predicate,
        )
    return indexes


def schema_contract(migrations: Sequence[Migration]) -> SchemaContract:
    sql = "\n".join(item.sql for item in migrations)
    columns: dict[str, dict[str, ExpectedColumn]] = {}
    primary_keys: dict[str, tuple[str, ...]] = {}
    unique_constraints: dict[str, set[tuple[str, ...]]] = {}
    foreign_keys: dict[
        str,
        set[tuple[tuple[str, ...], str, tuple[str, ...], str]],
    ] = {}
    check_constraints: dict[str, set[str]] = {}
    for match in _CREATE_TABLE_PATTERN.finditer(sql):
        table_name = match.group("table").lower()
        table_columns = columns.setdefault(table_name, {})
        unique_sets = unique_constraints.setdefault(table_name, set())
        foreign_key_set = foreign_keys.setdefault(table_name, set())
        check_set = check_constraints.setdefault(table_name, set())
        for item in _split_sql_items(match.group("body")):
            normalized = " ".join(item.split())
            upper = normalized.upper()
            if upper.startswith("PRIMARY KEY "):
                values = re.search(r"\(([^)]+)\)", normalized)
                if values:
                    primary_keys[table_name] = _column_list(values.group(1))
                continue
            if upper.startswith("UNIQUE "):
                values = re.search(r"\(([^)]+)\)", normalized)
                if values:
                    unique_sets.add(_column_list(values.group(1)))
                continue
            if upper.startswith("FOREIGN KEY "):
                expected_foreign_key = _expected_foreign_key(normalized)
                if expected_foreign_key is None:
                    raise SchemaMigrationError(
                        "migration-contract-invalid",
                        "Migration contains an unsupported foreign key.",
                    )
                foreign_key_set.add(expected_foreign_key)
                continue
            if upper.startswith("CHECK "):
                expression = normalized[5:].strip()
                if not expression.startswith("(") or not expression.endswith(")"):
                    raise SchemaMigrationError(
                        "migration-contract-invalid",
                        "Migration contains an unsupported check constraint.",
                    )
                check_set.add(_normalize_sql_fragment(expression))
                continue
            if upper.startswith(_CONSTRAINT_PREFIXES):
                continue
            expected = _expected_column(normalized)
            if expected is None:
                raise SchemaMigrationError(
                    "migration-contract-invalid",
                    "Migration contains an unsupported column definition.",
                )
            column_name, column = expected
            table_columns[column_name] = column
            if "PRIMARY KEY" in upper:
                primary_keys[table_name] = (column_name,)
            if re.search(r"\bUNIQUE\b", upper):
                unique_sets.add((column_name,))
            expected_foreign_key = _expected_foreign_key(
                normalized, column_name=column_name
            )
            if expected_foreign_key is not None:
                foreign_key_set.add(expected_foreign_key)
    addable: set[tuple[str, str]] = set()
    for match in _ALTER_COLUMN_PATTERN.finditer(sql):
        table_name = match.group("table").lower()
        column_name = match.group("column").lower()
        expected = _expected_column(
            f"{column_name} {match.group('definition').strip()}"
        )
        if expected is None or table_name not in columns:
            raise SchemaMigrationError(
                "migration-contract-invalid",
                "Migration contains an unsupported additive column definition.",
            )
        current = columns[table_name].get(column_name)
        if current is None:
            columns[table_name][column_name] = expected[1]
        elif (
            current.data_type,
            current.nullable,
            current.maximum_length,
        ) != (
            expected[1].data_type,
            expected[1].nullable,
            expected[1].maximum_length,
        ):
            raise SchemaMigrationError(
                "migration-contract-invalid",
                "Additive column definition conflicts with the final schema.",
            )
        addable.add((table_name, column_name))
    indexes = _expected_indexes(sql)
    return SchemaContract(
        columns=columns,
        primary_keys=primary_keys,
        unique_constraints={
            table: frozenset(values) for table, values in unique_constraints.items()
        },
        foreign_keys={
            table: frozenset(values) for table, values in foreign_keys.items()
        },
        check_constraints={
            table: frozenset(values) for table, values in check_constraints.items()
        },
        indexes=indexes,
        safely_addable_columns=frozenset(addable),
    )


def _set_search_path(connection: Connection) -> None:
    # Omitting pg_catalog keeps PostgreSQL's implicit catalog lookup ahead of
    # public, while pg_temp is explicitly placed after public for safe object
    # creation and resolution during reviewed migrations.
    connection.exec_driver_sql("SET LOCAL search_path TO public, pg_temp")


def _actual_columns(
    connection: Connection,
) -> dict[str, dict[str, tuple[str, bool, int | None, str | None]]]:
    rows = connection.execute(
        text(
            """
            SELECT table_name, column_name, data_type, is_nullable,
                   character_maximum_length, column_default
            FROM information_schema.columns
            WHERE table_schema = 'public'
            """
        )
    ).mappings()
    result: dict[str, dict[str, tuple[str, bool, int | None, str | None]]] = {}
    for row in rows:
        result.setdefault(str(row["table_name"]), {})[str(row["column_name"])] = (
            str(row["data_type"]),
            str(row["is_nullable"]) == "YES",
            int(row["character_maximum_length"])
            if row["character_maximum_length"] is not None
            else None,
            _actual_default(row["column_default"]),
        )
    return result


def _actual_key_constraints(
    connection: Connection, constraint_type: str
) -> dict[str, set[tuple[str, ...]]]:
    rows = connection.execute(
        text(
            """
            SELECT tc.table_name, tc.constraint_name, kcu.column_name,
                   kcu.ordinal_position
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
              ON tc.constraint_schema = kcu.constraint_schema
             AND tc.constraint_name = kcu.constraint_name
             AND tc.table_name = kcu.table_name
            WHERE tc.table_schema = 'public'
              AND tc.constraint_type = :constraint_type
            ORDER BY tc.table_name, tc.constraint_name, kcu.ordinal_position
            """
        ),
        {"constraint_type": constraint_type},
    ).mappings()
    grouped: dict[tuple[str, str], list[str]] = {}
    for row in rows:
        grouped.setdefault(
            (str(row["table_name"]), str(row["constraint_name"])), []
        ).append(str(row["column_name"]))
    result: dict[str, set[tuple[str, ...]]] = {}
    for (table_name, _constraint_name), values in grouped.items():
        result.setdefault(table_name, set()).add(tuple(values))
    return result


def _actual_foreign_keys(
    connection: Connection,
) -> dict[str, set[tuple[tuple[str, ...], str, tuple[str, ...], str]]]:
    rows = connection.execute(
        text(
            """
            SELECT local_table.relname AS table_name,
                   remote_table.relname AS remote_table_name,
                   remote_namespace.nspname AS remote_schema_name,
                   constraint_metadata.confdeltype AS delete_action,
                   ARRAY(
                       SELECT local_attribute.attname
                       FROM unnest(constraint_metadata.conkey)
                            WITH ORDINALITY AS local_key(attnum, ordinal)
                       JOIN pg_catalog.pg_attribute local_attribute
                         ON local_attribute.attrelid = constraint_metadata.conrelid
                        AND local_attribute.attnum = local_key.attnum
                       ORDER BY local_key.ordinal
                   ) AS local_columns,
                   ARRAY(
                       SELECT remote_attribute.attname
                       FROM unnest(constraint_metadata.confkey)
                            WITH ORDINALITY AS remote_key(attnum, ordinal)
                       JOIN pg_catalog.pg_attribute remote_attribute
                         ON remote_attribute.attrelid = constraint_metadata.confrelid
                        AND remote_attribute.attnum = remote_key.attnum
                       ORDER BY remote_key.ordinal
                   ) AS remote_columns
            FROM pg_catalog.pg_constraint constraint_metadata
            JOIN pg_catalog.pg_class local_table
              ON local_table.oid = constraint_metadata.conrelid
            JOIN pg_catalog.pg_class remote_table
              ON remote_table.oid = constraint_metadata.confrelid
            JOIN pg_catalog.pg_namespace remote_namespace
              ON remote_namespace.oid = remote_table.relnamespace
            JOIN pg_catalog.pg_namespace namespace
              ON namespace.oid = local_table.relnamespace
            WHERE namespace.nspname = 'public'
              AND constraint_metadata.contype = 'f'
              AND constraint_metadata.convalidated = TRUE
            """
        )
    ).mappings()
    delete_actions = {
        "a": "no action",
        "c": "cascade",
        "n": "set null",
        "r": "restrict",
        "d": "set default",
    }
    result: dict[
        str,
        set[tuple[tuple[str, ...], str, tuple[str, ...], str]],
    ] = {}
    for row in rows:
        result.setdefault(str(row["table_name"]), set()).add(
            (
                tuple(str(item) for item in row["local_columns"]),
                str(row["remote_table_name"])
                if str(row["remote_schema_name"]) == "public"
                else f"{row['remote_schema_name']}.{row['remote_table_name']}",
                tuple(str(item) for item in row["remote_columns"]),
                delete_actions.get(str(row["delete_action"]), "unknown"),
            )
        )
    return result


def _actual_check_constraints(connection: Connection) -> dict[str, set[str]]:
    rows = connection.execute(
        text(
            """
            SELECT table_relation.relname AS table_name,
                   pg_get_constraintdef(constraint_metadata.oid, TRUE) AS definition
            FROM pg_catalog.pg_constraint constraint_metadata
            JOIN pg_catalog.pg_class table_relation
              ON table_relation.oid = constraint_metadata.conrelid
            JOIN pg_catalog.pg_namespace namespace
              ON namespace.oid = table_relation.relnamespace
            WHERE namespace.nspname = 'public'
              AND constraint_metadata.contype = 'c'
              AND constraint_metadata.convalidated = TRUE
            """
        )
    ).mappings()
    result: dict[str, set[str]] = {}
    for row in rows:
        definition = " ".join(str(row["definition"]).split())
        match = re.fullmatch(r"CHECK\s*\((.*)\)", definition, re.IGNORECASE)
        if match is None:
            continue
        result.setdefault(str(row["table_name"]), set()).add(
            _normalize_sql_fragment(match.group(1))
        )
    return result


def _serial_default_uses_public_sequence(
    connection: Connection, table_name: str, column_name: str
) -> bool:
    return bool(
        connection.execute(
            text(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_catalog.pg_attrdef default_metadata
                    JOIN pg_catalog.pg_class table_relation
                      ON table_relation.oid = default_metadata.adrelid
                    JOIN pg_catalog.pg_namespace table_namespace
                      ON table_namespace.oid = table_relation.relnamespace
                    JOIN pg_catalog.pg_attribute column_metadata
                      ON column_metadata.attrelid = table_relation.oid
                     AND column_metadata.attnum = default_metadata.adnum
                    JOIN pg_catalog.pg_depend default_dependency
                      ON default_dependency.classid = 'pg_attrdef'::regclass
                     AND default_dependency.objid = default_metadata.oid
                     AND default_dependency.refclassid = 'pg_class'::regclass
                    JOIN pg_catalog.pg_class sequence_relation
                      ON sequence_relation.oid = default_dependency.refobjid
                     AND sequence_relation.relkind = 'S'
                    JOIN pg_catalog.pg_namespace sequence_namespace
                      ON sequence_namespace.oid = sequence_relation.relnamespace
                    JOIN pg_catalog.pg_depend ownership_dependency
                      ON ownership_dependency.classid = 'pg_class'::regclass
                     AND ownership_dependency.objid = sequence_relation.oid
                     AND ownership_dependency.refclassid = 'pg_class'::regclass
                     AND ownership_dependency.refobjid = table_relation.oid
                     AND ownership_dependency.refobjsubid = column_metadata.attnum
                     AND ownership_dependency.deptype IN ('a', 'i')
                    WHERE table_namespace.nspname = 'public'
                      AND table_relation.relname = :table_name
                      AND column_metadata.attname = :column_name
                      AND sequence_namespace.nspname = 'public'
                      AND pg_catalog.pg_get_expr(
                            default_metadata.adbin,
                            default_metadata.adrelid
                          ) = pg_catalog.format(
                            'nextval(%L::regclass)',
                            sequence_relation.oid::regclass::text
                          )
                )
                """
            ),
            {"table_name": table_name, "column_name": column_name},
        ).scalar_one()
    )


def _actual_indexes(
    connection: Connection,
) -> dict[str, tuple[str, bool, tuple[str, ...], str | None]]:
    rows = connection.execute(
        text(
            """
            SELECT index_relation.relname AS index_name,
                   table_relation.relname AS table_name,
                   index_metadata.indisunique AS is_unique,
                   ARRAY(
                       SELECT pg_get_indexdef(
                           index_metadata.indexrelid, key_ordinal, TRUE
                       ) || CASE
                           WHEN (
                               index_metadata.indoption[key_ordinal - 1] & 1
                           ) = 1 THEN ' DESC'
                           ELSE ''
                       END
                       FROM generate_series(
                           1, index_metadata.indnkeyatts
                       ) AS key_ordinal
                       ORDER BY key_ordinal
                   ) AS key_definitions,
                   pg_get_expr(
                       index_metadata.indpred,
                       index_metadata.indrelid,
                       TRUE
                   ) AS predicate
            FROM pg_catalog.pg_index index_metadata
            JOIN pg_catalog.pg_class index_relation
              ON index_relation.oid = index_metadata.indexrelid
            JOIN pg_catalog.pg_class table_relation
              ON table_relation.oid = index_metadata.indrelid
            JOIN pg_catalog.pg_namespace namespace
              ON namespace.oid = table_relation.relnamespace
            WHERE namespace.nspname = 'public'
              AND index_metadata.indisvalid = TRUE
              AND index_metadata.indisready = TRUE
              AND index_metadata.indislive = TRUE
            """
        )
    ).mappings()
    return {
        str(row["index_name"]): (
            str(row["table_name"]),
            bool(row["is_unique"]),
            tuple(
                _normalize_sql_fragment(str(item))
                for item in row["key_definitions"]
            ),
            _normalize_sql_fragment(str(row["predicate"]))
            if row["predicate"] is not None
            else None,
        )
        for row in rows
    }


def verify_schema_compatibility(
    connection: Connection,
    contract: SchemaContract,
    *,
    allow_missing_objects: bool,
) -> None:
    columns = _actual_columns(connection)
    primary_keys = _actual_key_constraints(connection, "PRIMARY KEY")
    unique_constraints = _actual_key_constraints(connection, "UNIQUE")
    foreign_keys = _actual_foreign_keys(connection)
    check_constraints = _actual_check_constraints(connection)
    indexes = _actual_indexes(connection)
    for table_name, expected_columns in contract.columns.items():
        actual_columns = columns.get(table_name)
        if actual_columns is None:
            if allow_missing_objects:
                continue
            raise SchemaMigrationError(
                "schema-object-missing", "Required schema table is missing."
            )
        for column_name, expected in expected_columns.items():
            actual = actual_columns.get(column_name)
            if actual is None:
                if allow_missing_objects and (
                    table_name,
                    column_name,
                ) in contract.safely_addable_columns:
                    continue
                raise SchemaMigrationError(
                    "schema-column-missing", "Required schema column is missing."
                )
            expected_definition = (
                expected.data_type,
                expected.nullable,
                expected.maximum_length,
                expected.default,
            )
            comparable_actual = actual
            if expected.default == "serial-sequence":
                serial_default = actual[3]
                if (
                    serial_default is not None
                    and serial_default.startswith("nextval(")
                    and _serial_default_uses_public_sequence(
                        connection, table_name, column_name
                    )
                ):
                    comparable_actual = (*actual[:3], "serial-sequence")
            if comparable_actual != expected_definition:
                raise SchemaMigrationError(
                    "schema-column-incompatible",
                    "Existing schema column has an incompatible definition.",
                )
        expected_primary_key = contract.primary_keys.get(table_name)
        if expected_primary_key and expected_primary_key not in primary_keys.get(
            table_name, set()
        ):
            raise SchemaMigrationError(
                "schema-primary-key-incompatible",
                "Existing schema primary key is missing or incompatible.",
            )
        expected_unique = contract.unique_constraints.get(table_name, frozenset())
        if not expected_unique.issubset(unique_constraints.get(table_name, set())):
            raise SchemaMigrationError(
                "schema-unique-constraint-incompatible",
                "Existing schema uniqueness contract is missing or incompatible.",
            )
        expected_foreign_keys = contract.foreign_keys.get(table_name, frozenset())
        required_foreign_keys = expected_foreign_keys
        if allow_missing_objects:
            required_foreign_keys = frozenset(
                foreign_key
                for foreign_key in expected_foreign_keys
                if not any(
                    column_name not in actual_columns
                    and (table_name, column_name)
                    in contract.safely_addable_columns
                    for column_name in foreign_key[0]
                )
            )
        if not required_foreign_keys.issubset(foreign_keys.get(table_name, set())):
            raise SchemaMigrationError(
                "schema-foreign-key-incompatible",
                "Existing schema foreign-key contract is missing or incompatible.",
            )
        expected_checks = contract.check_constraints.get(table_name, frozenset())
        if not expected_checks.issubset(check_constraints.get(table_name, set())):
            raise SchemaMigrationError(
                "schema-check-incompatible",
                "Existing schema check contract is missing or incompatible.",
            )
    for index_name, expected in contract.indexes.items():
        actual = indexes.get(index_name)
        if actual is None:
            if allow_missing_objects:
                continue
            raise SchemaMigrationError(
                "schema-index-missing", "Required schema index is missing."
            )
        if actual != expected:
            raise SchemaMigrationError(
                "schema-index-incompatible",
                "Existing schema index name has an incompatible definition.",
            )


def _state_table_exists(connection: Connection) -> bool:
    return (
        connection.execute(
            text("SELECT to_regclass('public.oaw_schema_migrations') IS NOT NULL")
        ).scalar_one()
        is True
    )


def _load_applied(connection: Connection) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            text(
                """
                SELECT version, name, checksum, applied_at,
                       execution_duration_ms, application_version,
                       minimum_application_version
                FROM public.oaw_schema_migrations
                ORDER BY version ASC
                """
            )
        ).mappings()
    ]


def _validate_applied_history(
    applied: Sequence[dict[str, Any]], migrations: Sequence[Migration]
) -> None:
    available = {item.version: item for item in migrations}
    applied_versions = [int(row["version"]) for row in applied]
    if applied_versions and applied_versions != list(
        range(1, applied_versions[-1] + 1)
    ):
        raise SchemaMigrationError(
            "applied-version-gap", "Applied migration history is not contiguous."
        )
    for row in applied:
        version = int(row["version"])
        migration = available.get(version)
        if migration is None:
            raise SchemaMigrationError(
                "unknown-applied-version",
                "Database contains an unknown applied migration version.",
            )
        if str(row["name"]) != migration.name:
            raise SchemaMigrationError(
                "applied-name-mismatch", "Applied migration name is immutable."
            )
        if str(row["checksum"]) != migration.checksum:
            raise SchemaMigrationError(
                "migration-checksum-mismatch",
                "Applied migration checksum does not match reviewed bytes.",
            )


def _status_from_applied(
    applied: Sequence[dict[str, Any]], migrations: Sequence[Migration]
) -> SchemaStatus:
    current = int(applied[-1]["version"]) if applied else 0
    latest = migrations[-1].version
    pending = max(0, latest - current)
    return SchemaStatus(
        state="ready" if pending == 0 else "migration-required",
        current_version=current,
        latest_available_version=latest,
        pending_migration_count=pending,
        compatibility_state="compatible" if pending == 0 else "migration-required",
        checksum_integrity="verified",
        last_migration_time=applied[-1]["applied_at"] if applied else None,
    )


def verify_database_schema(
    engine: Engine, migrations: Sequence[Migration] | None = None
) -> SchemaStatus:
    available = tuple(migrations or discover_migrations())
    contract = schema_contract(available)
    with engine.connect() as connection:
        with connection.begin():
            _set_search_path(connection)
            if not _state_table_exists(connection):
                return SchemaStatus(
                    state="uninitialized",
                    current_version=0,
                    latest_available_version=available[-1].version,
                    pending_migration_count=len(available),
                    compatibility_state="migration-required",
                    checksum_integrity="not-recorded",
                )
            applied = _load_applied(connection)
            _validate_applied_history(applied, available)
            if applied:
                applied_contract = schema_contract(available[: int(applied[-1]["version"])])
                verify_schema_compatibility(
                    connection, applied_contract, allow_missing_objects=False
                )
            return _status_from_applied(applied, available)


def database_schema_status(engine: Engine) -> SchemaStatus:
    try:
        return verify_database_schema(engine)
    except SchemaMigrationError as exc:
        return SchemaStatus(
            state="failed",
            current_version=0,
            latest_available_version=0,
            pending_migration_count=0,
            compatibility_state="incompatible",
            checksum_integrity="failed",
            failure_code=exc.code,
        )
    except Exception as exc:  # bounded operator surface; no raw DB text escapes.
        return SchemaStatus(
            state="failed",
            current_version=0,
            latest_available_version=0,
            pending_migration_count=0,
            compatibility_state="unavailable",
            checksum_integrity="unknown",
            failure_code=f"database-{type(exc).__name__.lower()}"[:80],
        )


def _acquire_lock(connection: Connection, *, timeout_seconds: float) -> None:
    deadline = time.monotonic() + max(0.0, min(timeout_seconds, 300.0))
    while True:
        acquired = bool(
            connection.execute(
                text("SELECT pg_try_advisory_lock(:lock_id)"),
                {"lock_id": MIGRATION_LOCK_ID},
            ).scalar_one()
        )
        connection.commit()
        if acquired:
            return
        if time.monotonic() >= deadline:
            raise SchemaMigrationError(
                "migration-lock-timeout",
                "Database migration lock was not available within the bounded wait.",
            )
        time.sleep(0.1)


def _release_lock(connection: Connection) -> None:
    if connection.in_transaction():
        connection.rollback()
    released = bool(
        connection.execute(
            text("SELECT pg_advisory_unlock(:lock_id)"),
            {"lock_id": MIGRATION_LOCK_ID},
        ).scalar_one()
    )
    connection.commit()
    if not released:
        raise SchemaMigrationError(
            "migration-lock-release-failed", "Database migration lock was not held."
        )


def migrate_database_schema(
    engine: Engine,
    *,
    migrations: Sequence[Migration] | None = None,
    lock_timeout_seconds: float = MIGRATION_LOCK_TIMEOUT_SECONDS,
) -> SchemaStatus:
    available = tuple(migrations or discover_migrations())
    full_contract = schema_contract(available)
    with engine.connect() as connection:
        acquired = False
        primary_error: Exception | None = None
        try:
            _acquire_lock(connection, timeout_seconds=lock_timeout_seconds)
            acquired = True
            with connection.begin():
                _set_search_path(connection)
                connection.execute(text(MIGRATION_STATE_SQL))
                state_contract = schema_contract(
                    (
                        Migration(
                            version=1,
                            name="migration_state",
                            checksum="0" * 64,
                            sql=MIGRATION_STATE_SQL.rstrip() + ";\n",
                        ),
                    )
                )
                verify_schema_compatibility(
                    connection, state_contract, allow_missing_objects=False
                )
                applied = _load_applied(connection)
                _validate_applied_history(applied, available)
                verify_schema_compatibility(
                    connection, full_contract, allow_missing_objects=True
                )
            applied_versions = {int(row["version"]) for row in applied}
            for migration in available:
                if migration.version in applied_versions:
                    continue
                started = time.monotonic()
                try:
                    with connection.begin():
                        _set_search_path(connection)
                        connection.exec_driver_sql(migration.sql)
                        applied_contract = schema_contract(
                            tuple(
                                item
                                for item in available
                                if item.version <= migration.version
                            )
                        )
                        verify_schema_compatibility(
                            connection,
                            applied_contract,
                            allow_missing_objects=False,
                        )
                        duration_ms = min(
                            86_400_000,
                            max(0, int((time.monotonic() - started) * 1000)),
                        )
                        connection.execute(
                            text(
                                """
                                INSERT INTO public.oaw_schema_migrations (
                                    version, name, checksum,
                                    execution_duration_ms, application_version,
                                    minimum_application_version
                                ) VALUES (
                                    :version, :name, :checksum,
                                    :execution_duration_ms, :application_version,
                                    :minimum_application_version
                                )
                                """
                            ),
                            {
                                "version": migration.version,
                                "name": migration.name,
                                "checksum": migration.checksum,
                                "execution_duration_ms": duration_ms,
                                "application_version": _bounded_application_version(),
                                "minimum_application_version": MINIMUM_APPLICATION_VERSION,
                            },
                        )
                except SchemaMigrationError:
                    raise
                except Exception as exc:
                    raise SchemaMigrationError(
                        "migration-application-failed",
                        f"Migration {migration.identifier} rolled back ({type(exc).__name__}).",
                    ) from None
            with connection.begin():
                _set_search_path(connection)
                applied = _load_applied(connection)
                _validate_applied_history(applied, available)
                verify_schema_compatibility(
                    connection, full_contract, allow_missing_objects=False
                )
                return _status_from_applied(applied, available)
        except Exception as exc:
            primary_error = exc
            raise
        finally:
            if acquired:
                try:
                    _release_lock(connection)
                except SchemaMigrationError:
                    if primary_error is None:
                        raise


def ensure_schema_ready(engine: Engine) -> SchemaStatus:
    with _ready_lock:
        ready = _ready_engines.get(engine)
        if ready is not None:
            return ready
        try:
            ready = migrate_database_schema(engine)
        except SchemaMigrationError as exc:
            set_runtime_migration_failure(exc.code)
            raise
        except Exception as exc:
            code = f"database-{type(exc).__name__.lower()}"[:80]
            set_runtime_migration_failure(code)
            raise SchemaMigrationError(
                code, "Database schema migration failed safely."
            ) from None
        _ready_engines[engine] = ready
        set_runtime_migration_ready(ready)
        return ready


def set_runtime_migration_ready(status: SchemaStatus) -> None:
    with _runtime_lock:
        _runtime_readiness.update(
            {
                "state": "ready",
                "current_version": status.current_version,
                "latest_available_version": status.latest_available_version,
                "failure_code": None,
            }
        )


def set_runtime_migration_failure(code: str) -> None:
    with _runtime_lock:
        _runtime_readiness.update(
            {
                "state": "failed",
                "current_version": 0,
                "latest_available_version": 0,
                "failure_code": re.sub(r"[^a-z0-9-]", "-", code.lower())[:80],
            }
        )


def runtime_schema_readiness() -> dict[str, Any]:
    with _runtime_lock:
        return dict(_runtime_readiness)


def reset_schema_runtime_for_tests() -> None:
    with _ready_lock:
        _ready_engines.clear()
    with _runtime_lock:
        _runtime_readiness.update(
            {
                "state": "not-started",
                "current_version": 0,
                "latest_available_version": 0,
                "failure_code": None,
            }
        )


def format_schema_status(status: SchemaStatus) -> dict[str, Any]:
    payload = status.as_dict()
    if isinstance(payload.get("last_migration_time"), datetime):
        payload["last_migration_time"] = payload["last_migration_time"].isoformat()
    return payload


def iter_migration_identifiers(
    migrations: Iterable[Migration] | None = None,
) -> tuple[str, ...]:
    return tuple(item.identifier for item in (migrations or discover_migrations()))


def operator_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inspect or apply reviewed OpenAssetWatch schema migrations."
    )
    parser.add_argument(
        "operation",
        choices=("status", "verify", "migrate"),
        help="status is non-throwing; verify fails closed; migrate applies forward migrations",
    )
    args = parser.parse_args(argv)
    from .database import get_engine

    try:
        engine = get_engine()
        if args.operation == "status":
            status = database_schema_status(engine)
        elif args.operation == "verify":
            status = verify_database_schema(engine)
        else:
            status = migrate_database_schema(engine)
    except SchemaMigrationError as exc:
        payload: dict[str, Any] = {
            "status": "failed",
            "failure_code": exc.code,
            "message": exc.summary,
        }
        exit_code = 2
    except Exception as exc:  # never expose database URLs or raw driver errors.
        payload = {
            "status": "failed",
            "failure_code": f"database-{type(exc).__name__.lower()}"[:80],
            "message": "Database schema operation failed safely.",
        }
        exit_code = 2
    else:
        payload = format_schema_status(status)
        exit_code = 0 if status.state == "ready" else 2
    print(json.dumps(payload, indent=2, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(operator_main())
