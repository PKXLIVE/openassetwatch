# Development Validation

This page records the validation requirements that apply across
OpenAssetWatch development. Setup and the base commands are in
[LOCAL_DEV_SETUP.md](LOCAL_DEV_SETUP.md); each component README adds its own
commands. Report only checks that actually ran, with their results.

## Backend unit suite

Backend CI runs the suite on Python 3.12 with the hash-locked
`backend/requirements.txt`:

```text
python -m unittest discover -s backend/tests -t backend
```

Locally, run the same command in the locked backend image with the repository
mounted, as [LOCAL_DEV_SETUP.md](LOCAL_DEV_SETUP.md) shows. Without the gate variables
below, the PostgreSQL suites skip.

## Gated PostgreSQL suites

Each suite runs only when its variable is `1`. Except for KEV and mirror,
each suite reads `DATABASE_URL` and creates and drops its own randomly named
database under a fixed test prefix, refusing to drop anything else.

| Variable | Test modules |
| --- | --- |
| `OPENASSETWATCH_SCHEMA_POSTGRES_TEST` | `test_schema_migrations_postgres` |
| `OPENASSETWATCH_CANONICAL_INGESTION_POSTGRES_TEST` | `test_canonical_ingestion_postgres` |
| `OPENASSETWATCH_DECISION_POSTGRES_TEST` | `test_decision_postgres` |
| `OPENASSETWATCH_ENDPOINT_AGENT_POSTGRES_TEST` | `test_endpoint_agent_postgres` |
| `OPENASSETWATCH_FINDING_WORK_POSTGRES_TEST` | `test_finding_work_postgres` |
| `OPENASSETWATCH_IMPORTANCE_POSTGRES_TEST` | `test_asset_importance_postgres` |
| `OPENASSETWATCH_TEMPORAL_POSTGRES_TEST` | `test_temporal_postgres`, `test_temporal_deviation_postgres` |
| `OPENASSETWATCH_VERIFICATION_POSTGRES_TEST` | `test_verification_postgres` |
| `OPENASSETWATCH_KEV_POSTGRES_TEST` | `test_kev_postgres` |
| `OPENASSETWATCH_MIRROR_POSTGRES_TEST` | `test_advisory_mirror_postgres` |

The KEV and mirror suites work differently:

- **Separate database.** Each needs an existing, empty database named by
  `OPENASSETWATCH_KEV_POSTGRES_DATABASE` or
  `OPENASSETWATCH_MIRROR_POSTGRES_DATABASE`.
- **Separate process.** Each rewrites `DATABASE_URL` when imported with its
  gate set, so it runs in its own test process, not in the same run as the
  other gated suites.

Rules for every gated suite:

- Run against the Compose PostgreSQL service or an equivalent disposable
  PostgreSQL instance on a private network.
- Never point a gated suite at a production, customer or shared database.
- Remove only databases or instances the run itself created. Never remove
  the Compose `postgres_data` volume or other existing data.

## Known baseline failures

With every gate enabled, these four tests fail on `main`. The failures are
pre-existing technical debt, tracked separately. Report them by name; do not
count them as regressions, and do not change them in unrelated work.

- `tests.test_temporal_postgres.TemporalPostgresTests.test_all_registered_queries_are_site_scoped_and_quality_aware`
- `tests.test_temporal_postgres.TemporalPostgresTests.test_as_of_projection_excludes_evidence_received_at_or_after_cutoff`
- `tests.test_temporal_postgres.TemporalPostgresTests.test_projection_is_stable_across_fresh_service_instances`
- `tests.test_endpoint_agent_postgres.EndpointAgentPostgresTests.test_full_identity_replay_rotation_and_persistence_lifecycle`

The three temporal tests assert a stale schema version. Any other failure is
new until shown otherwise.

## Decision ruleset compatibility

`V1CompatibilityTests` in `backend/tests/test_asset_importance.py` pins
ruleset `oaw.decision.rules.v1`.

- It checks that all 84,480 decisions are bit-identical to a recorded SHA-256
  digest (`V1_UNIVERSE_DIGEST`).
- It is not gated, so Backend CI runs it on every pull request.
- A change that alters any v1 decision fails it.
- Changed decisions need a new, approved ruleset version.

## Failure classification

Classify every failed check before acting on it:

| Class | Meaning | Action |
| --- | --- | --- |
| Introduced | Caused by the change | Fix it, then rerun |
| Pre-existing | Fails on `main` too | Name it and leave it alone |
| Environmental | Missing tool, service or platform | Name what is missing |
| Expected safety guard | A guard correctly refused | Keep the guard |
| Unknown | Cause not established | Investigate before claiming results |

A test or gate is never weakened to make a run pass.

## Continuous integration

These workflows in `.github/workflows` stay enabled and unweakened. A result
counts only once its run has been observed.

| Workflow | Runs on |
| --- | --- |
| Backend CI, Collector CI, Agent CI | Pull requests and `main` |
| CodeQL | Pull requests to `main`, pushes to `main`, weekly |
| Developer Certificate of Origin | Pull requests to `main` |
| Dependency Review | Pull requests |
| Secret Scan | Pull requests and `main` |
| License metadata | Pull requests and `main` |
| SBOM | Pull requests and `main` |
| OpenSSF Scorecard | `main`, branch protection changes, weekly |
| Repo Impersonation Scan | Daily |
| Advisory Mirror Publication | Pull requests touching its paths, weekly, manual |
| Agent release publication | Pull requests touching its paths, `v*` tags, manual |
| Agent macOS signed release | `agent-macos-v*` tags, manual |
