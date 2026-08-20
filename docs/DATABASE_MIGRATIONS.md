# Database Schema Migrations

OpenAssetWatch owns its PostgreSQL schema through a small, project-native,
forward-only migration runner. This is the versioned baseline for future
schema changes; it is not a claim that upgrades from releases predating this
baseline have been tested.

## Authority and packaged files

The durable schema authority is the ordered SQL history in
`backend/app/migration_sql/`. Each filename is
`NNNN_lowercase_migration_name.sql`, beginning with
`0001_current_schema_baseline.sql`. Versions must be unique, positive, and
contiguous. Migration bytes are strict UTF-8, have a two-MiB size bound, and
cannot contain client-side `psql` commands.

The migration directory is fixed beside the packaged backend module. Neither
an API, environment value, feed, AI response, nor CLI argument can select
another directory or supply SQL. The backend image copies this directory into
the image. No migration code or metadata is downloaded at runtime.

`database/schema.sql` is a non-executable reference manifest containing the
canonical baseline path and exact checksum. It exits with an error if invoked
through `psql`; raw `psql` execution would bypass locking, transactions, and
registry state. It is not a second schema authority, and Docker Compose does
not mount it as a PostgreSQL initialization script. A regression test verifies
the reference path, checksum, and fail-closed guard.

## Registry, checksums, and compatibility

The runner computes SHA-256 over each migration's exact bytes. An applied row
in `oaw_schema_migrations` records:

- integer version and bounded name
- 64-character SHA-256 checksum
- database-assigned application time
- bounded execution duration in milliseconds
- bounded application version and minimum application version

State inserts are parameterized. The registry never stores SQL, database URLs,
passwords, repository paths, or raw exception text. Changing an applied
migration's bytes or name fails closed. Gaps, duplicate versions, malformed
filenames, and unknown applied versions also fail closed.

Before adopting or verifying a schema, the runner checks expected column types,
nullability, bounded character lengths, primary keys, unique constraints, and
index identity. Index checks include the owning table, uniqueness, ordered key
expressions, descending order, and partial-index predicates. A conflicting
existing definition is rejected; table presence alone is not treated as proof
of compatibility.

On POSIX systems, writable migration directories and files must not be group-
or world-writable. Docker Desktop can emulate host bind-mount mode bits as
`0777`; those bits are accepted only when the filesystem itself reports a
read-only mount. Compose therefore mounts `/app` read-only. Files must be
regular, single-linked files. Symlinks, hard-link
aliases, non-regular files, path escape, oversized files, identity replacement
during open/read, and migration-root replacement are rejected. These checks
protect host-mounted development trees as well as packaged images. Migration
files remain trusted, reviewed code.

## Locking and transactions

Migration coordination uses the stable PostgreSQL advisory-lock identity
derived from SHA-256 of `openassetwatch:schema-migrations:v1`. Acquisition uses
`pg_try_advisory_lock` with a bounded 30-second default wait and a hard
five-minute programmatic ceiling. Lock release runs after success or failure.

Every migration is applied in its own database transaction with a fixed local
`search_path` of `public, pg_temp`; PostgreSQL therefore resolves its implicit
`pg_catalog` ahead of `public` while new unqualified objects still target
`public`. Compatibility is verified before and
after application, and the registry row is inserted only after the migration
SQL and post-checks succeed in that same transaction. A failing migration is
rolled back and is not marked applied. The baseline contains no PostgreSQL DDL
that must run outside a transaction.

## Fresh and existing databases

For a fresh database, migration 0001 creates the complete current schema and
records itself only after verification. Repeated execution is idempotent.

For an existing database created by the former startup and store-owned DDL,
the runner first inspects the schema. It permits objects that are genuinely
missing and the five reviewed additive compatibility columns declared by the
baseline. `CREATE ... IF NOT EXISTS` and those bounded `ADD COLUMN IF NOT
EXISTS` statements then fill only safe gaps. Existing rows are not rewritten,
tables are not dropped, and conflicting types, constraints, or indexes block
adoption. The baseline is recorded only after the full resulting contract
passes.

Back up persistent databases and test restore before any production upgrade.
OpenAssetWatch does not automatically downgrade a schema. Recovery is
forward-only: preserve the failed database, restore the last verified backup
when necessary, correct the reviewed migration or environment before release,
and run `verify` again. Never edit an applied migration to repair production;
add a new reviewed forward migration.

## Startup, readiness, and status

FastAPI lifespan startup calls the migration runner before requests can be
served. A successful engine is cached, so normal store, dashboard, ingestion,
and AI requests do not execute migration SQL. A migration or compatibility
failure aborts startup with a bounded failure code.

`GET /health` remains a process liveness response. Docker health checks use
`GET /ready`, which reports only bounded schema state: current and latest
versions plus a failure code when applicable. It returns HTTP 503 unless the
startup migration state is ready. It exposes no SQL, database errors,
credentials, or paths.

Run the operator interface inside the Linux backend environment:

```powershell
docker compose exec backend python -m app.schema_migrations status
docker compose exec backend python -m app.schema_migrations verify
docker compose exec backend python -m app.schema_migrations migrate
```

The repository wrapper provides the same three operations when a maintainer
already has the backend dependencies and `DATABASE_URL` configured:

```powershell
python scripts/manage_database_schema.py status
python scripts/manage_database_schema.py verify
python scripts/manage_database_schema.py migrate
```

The CLI does not support arbitrary SQL or directories, force-marking,
checksum bypass, gap bypass, downgrade, or reset.

## Temporary legacy compatibility bridge

The former DDL constants remain temporarily so their historical shape can be
reviewed, but their production `ensure_*_schema` entry points now delegate to
the central migration runner. They no longer execute their local DDL. The
frozen fingerprints in `database/legacy-ddl-compatibility.json` and the schema
tests fail if ordinary application modules gain or silently change persistent
DDL.

| Legacy location | Objects formerly owned | Current behavior |
| --- | --- | --- |
| `backend/app/database.py` | hub, collector, sensor identity, inventory, AI audit tables | delegates to migration readiness |
| `backend/app/classification_store.py` | classification evidence, results, history, conflicts | delegates to migration readiness |
| `backend/app/component_store.py` | components, component history and evidence | delegates to migration readiness |
| `backend/app/advisory_store.py` | advisory catalog and normalized advisory records | delegates to migration readiness |
| `backend/app/advisory_sync_store.py` | trusted-feed runs, catalogs, and activation history | delegates to migration readiness |
| `backend/app/vulnerability_store.py` | deterministic matches, history, and runs | delegates to migration readiness |
| `backend/app/finding_store.py` | findings, evidence, risk, and evaluation history | delegates to migration readiness |
| `backend/app/kev_store.py` | KEV imports, records, correlations, and factors | delegates to migration readiness |

Remove these frozen constants in a later, separately reviewed cleanup only
after supported upgrade paths no longer need the compatibility comparison.
Runtime data initialization that is not schema DDL remains unchanged.

## Adding a future migration

1. Never modify or rename an applied file.
2. Add the next contiguous, zero-padded SQL file under
   `backend/app/migration_sql/` with a stable lowercase name.
3. Prefer additive expand-and-contract changes. Keep data backfills separate
   from schema DDL and define their checkpoints and recovery behavior.
4. Use schema-qualified objects or the fixed `public` contract. Do not use
   dynamic object names, network access, client-side includes, nontransactional
   DDL, or unbounded data rewrites.
5. Update the compatibility parser only through focused review when a new SQL
   form is genuinely required.
6. Add unit, fresh-database, existing-upgrade, rollback, concurrency,
   idempotency, and snapshot/contract tests appropriate to the change.
7. Review backup, restore, rolling-version compatibility, tenant scope, least
   privilege, and air-gapped packaging before release.

Run focused tests through the locked Linux backend image:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace/backend backend `
  python -m unittest -v tests.test_schema_migrations
```

The destructive PostgreSQL cases are gated and create only random databases
whose names match `openassetwatch_schema_test_<16-hex>`; they refuse to drop
anything else:

```powershell
docker compose run --rm --volume "${PWD}:/workspace" `
  --workdir /workspace/backend `
  --env OPENASSETWATCH_SCHEMA_POSTGRES_TEST=1 backend `
  python -m unittest -v tests.test_schema_migrations_postgres
```

## Baseline limitations

- Version 0001 is the starting point; no older release-to-release history is
  represented.
- There is no automatic downgrade or destructive reset.
- Large online backfills, backup confirmation, restore automation, rolling
  mixed-version compatibility, migration heartbeats, and dedicated least-
  privilege migration credentials remain future hardening.
- Advisory-lock acquisition is bounded, but this baseline does not yet impose
  a PostgreSQL statement timeout on reviewed DDL; operators must schedule
  upgrades to avoid unbounded waits on application-held table locks.
- The baseline does not add endpoint identity, tenant ownership, RBAC, job
  scheduling, EPSS, feeds, dashboard redesign, or AI/multi-agent behavior.

The broader target architecture and release policy remain documented in
`docs/architecture/database-schema-migration-governance.md`.
