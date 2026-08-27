# OpenAssetWatch Backend

The backend is the first OpenAssetWatch Control Tower API. It is a FastAPI
service backed by PostgreSQL through SQLAlchemy.

## What It Provides

- health and version endpoint
- site/project records
- endpoint-agent and future network-sensor enrollment records
- agent check-in ingestion
- Go agent local inventory ingestion
- raw inventory evidence persistence
- Control Tower asset normalization with source-aware classification evidence
- versioned deterministic asset classification, history, and conflicts
- server-derived direct-evidence trust, server-assigned identity for legacy
  unauthenticated input, future-skew rejection, and source-fair bounded
  evidence selection
- local-only fictional vendor catalog with safe reviewed replacement
- normalized software, package, operating-system, and reviewed firmware
  inventory with material history
- strict versioned offline advisory catalogs with licensing, provenance, and
  checksums
- reviewed signed-feed synchronization with Ed25519 verification, bounded
  private staging, explicit approval, atomic activation, and rollback
- ecosystem-aware deterministic vulnerability matches and match history
- idempotent outbound observation batches with site/sensor provenance
- one canonical inventory write service for endpoint, passive-sensor, Python
  collector, and transitional local-inventory routes
- persisted source trust precedence, canonical acknowledgements, compatibility
  mappings, and retryable downstream evaluation state
- one-time passive-sensor enrollment and bound, rotatable credentials
- site and sensor health/freshness summaries
- versioned deterministic finding rules with persisted lifecycle and evidence
- explainable deterministic asset and site risk scores
- deterministic and optional external AI Advisor providers
- bounded read-only AI evidence tools and audit metadata
- focused AI Advisor dashboard view
- governed deterministic temporal metric registry and bounded daily UTC signal
  projection
- read-only Environment Trends dashboard with explicit missingness and
  incomplete/stale source states
- release/artifact metadata placeholder
- static dashboard mount at `/ui`
- legacy Python collector ingestion and policy endpoints

## Local Run

From the repository root:

```powershell
docker compose up -d --build --remove-orphans
```

Wait for healthy services:

```powershell
docker compose ps
```

Then check backend health:

```powershell
curl.exe http://localhost:8000/health
```

Open the dashboard:

```text
http://localhost:8080
```

View backend logs:

```powershell
docker compose logs -f backend
```

Stop the stack:

```powershell
docker compose down
```

Reset local development data:

```powershell
docker compose down -v --remove-orphans
```

The backend image installs Python dependencies at build time through
`backend/Dockerfile`; the source tree remains bind-mounted into `/app` for
local development reloads. The image uses pip hash-checking mode against the
fully resolved `backend/requirements.txt` lock.

## Dependency Inputs And Lock

`backend/requirements.in` is the readable direct-dependency manifest and the
file maintainers should edit. `backend/requirements.txt` is generated with
Python 3.12 on Linux by `pip-tools==7.5.3`; it pins the complete runtime graph
and includes package hashes. Dependabot's `/backend` pip configuration uses the
standard pip-compile input/lock pair and increases the source constraint when
an accepted release requires it.

From the repository root, regenerate the lock in the same Python environment
as the backend image:

```powershell
$CompileCommand = "python -m piptools compile --generate-hashes --strip-extras --newline=lf --output-file backend/requirements.txt backend/requirements.in"
docker run --rm --volume "${PWD}:/workspace" --workdir /workspace `
  --env "CUSTOM_COMPILE_COMMAND=$CompileCommand" python:3.12-slim `
  sh -c 'python -m pip install --disable-pip-version-check --no-cache-dir pip-tools==7.5.3 && python -m piptools compile --generate-hashes --strip-extras --newline=lf --output-file backend/requirements.txt backend/requirements.in'
```

For an intentional targeted update, append a reviewed option such as
`--upgrade-package cryptography`; do not use an unscoped `--upgrade` for routine
lock regeneration.

Review both files together. The lock targets Linux, so verify it in the same
container environment rather than installing it into a Windows virtual
environment:

```powershell
docker build --tag openassetwatch-backend-lock-check backend
docker run --rm openassetwatch-backend-lock-check python -m pip check
docker run --rm --entrypoint sh openassetwatch-backend-lock-check `
  -c 'python -m pip install --disable-pip-version-check --no-cache-dir pip-audit==2.10.1 && python -m pip_audit --require-hashes --disable-pip -r /tmp/openassetwatch-requirements.txt'
```

## Database

The default local deployment uses PostgreSQL. Versioned, immutable migration
files under `backend/app/migration_sql/` are the durable schema authority.
Backend lifespan startup applies and verifies them under a bounded PostgreSQL
advisory lock before serving requests. Docker health checks use `/ready`, while
`/health` remains process liveness.

Inspect or apply the current migration state inside the backend container:

```powershell
docker compose exec backend python -m app.schema_migrations status
docker compose exec backend python -m app.schema_migrations verify
docker compose exec backend python -m app.schema_migrations migrate
```

`database/schema.sql` is a non-executable reference manifest for migration
0001, not a second initialization path; invoking it with `psql` exits with an
error before applying DDL. See `docs/DATABASE_MIGRATIONS.md` for checksums,
existing-database adoption, transactions, failure recovery, future migration
review, downgrade policy, and live PostgreSQL tests.

Compose mounts backend source read-only at `/app`. Local reload still observes
source changes, while migration bytes cannot be modified from the container.

Control Tower tables include:

- `sites`
- `agent_enrollments`
- `sensor_enrollments`
- `sensor_credentials`
- `sensor_identity_audit_events`
- `agent_checkins`
- `local_inventory_collections`
- `control_tower_assets`
- `ai_advisor_runs`
- `finding_evaluation_runs`
- `findings`
- `finding_evidence`
- `asset_risk_scores`
- `site_risk_scores`
- `risk_factors`
- `kev_catalog_imports`
- `kev_records`
- `kev_record_history`
- `advisory_kev_correlations`
- `vulnerability_priority_factors`
- `vulnerability_priority_factor_history`
- `classification_evidence`
- `classification_runs`
- `asset_classifications`
- `asset_classification_history`
- `asset_classification_evidence`
- `classification_conflicts`
- `asset_components`
- `asset_component_history`
- `component_evidence`
- `advisory_catalog_imports`
- `advisories`
- `advisory_aliases`
- `advisory_references`
- `advisory_affected_components`
- `advisory_version_ranges`
- `vulnerability_evaluation_runs`
- `vulnerability_matches`
- `vulnerability_match_history`
- `advisory_feed_runs`
- `advisory_feed_catalogs`
- `advisory_catalog_activations`

## Tests

Run backend tests through the Linux/Python 3.12 backend image so the hashed
lock, platform-specific dependencies, and test runtime match Docker:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace:ro" `
  --workdir /workspace/backend -e OPENASSETWATCH_AI_PROVIDER=demo backend `
  python -m unittest discover -s tests -v
```

The unit tests mock the database boundary for endpoint behavior and test local
normalization/schema helpers without requiring a live PostgreSQL instance.
Migration integration tests are separately gated because they create and drop
strictly named disposable PostgreSQL databases; see `docs/DATABASE_MIGRATIONS.md`.
The transitional local-inventory route is deprecated compatibility ingestion
and does not grant direct evidence authority from a client-declared agent or
source type. Authenticated endpoint and passive-sensor context is passed
separately by the server. Development-shared sensor and Python collector input
can contribute bounded lower-trust evidence but cannot replace authenticated
asset authority. Only new committed canonical collections queue targeted
deterministic evaluation; replay and rejected input do not. See
`docs/CANONICAL_INGESTION_COMPATIBILITY.md` for the persisted trust order,
idempotency, status endpoint, preview utility, PostgreSQL lifecycle, and current
retry limitations.
Static showcase and seed tests use only the standard library:

```powershell
python scripts/test_control_tower_dashboard.py
python scripts/test_control_tower_demo_seed.py
python scripts/test_vulnerability_intelligence_demo.py
python scripts/test_vulnerability_intelligence_performance.py
```

Run the signed-feed security, lifecycle, API, UI, and AI tests:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace/backend backend `
  python -m unittest -v tests.test_advisory_feed_security `
    tests.test_advisory_sync_lifecycle tests.test_advisory_feed_ai_ui
```

Run the licensed OSV PyPI publisher's strict normalization, network, cursor,
signing, output, offline lifecycle, and AI-evidence tests:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace/backend backend `
  python -m unittest -v tests.test_osv_pypi_publisher tests.test_osv_pypi_demo
```

The publisher is a separate one-shot administrative process; it is never
started with the backend. See `docs/OSV_PYPI_PUBLISHER.md` for its reviewed
source boundary, signing and registry workflow, recovery behavior, live smoke,
offline demonstration, and synthetic benchmark.

Run the signed advisory-mirror schema, builder, transport integration,
workflow-policy, offline lifecycle, and AI-evidence tests:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace/backend backend `
  python -m unittest -v tests.test_advisory_mirror `
    tests.test_advisory_mirror_demo tests.test_advisory_mirror_workflow
```

The mirror is a static distribution boundary, not a backend scheduler or write
API. See `docs/ADVISORY_MIRROR.md` for index v1, local commands, publication
gates, retention, key rotation, recovery, hosting, licensing, and privacy.

Run the offline CISA KEV source/schema, publisher, exact-CVE correlation,
findings/risk, authenticated API, UI, and AI boundary tests:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace/backend backend `
  python -m unittest -v tests.test_kev_catalog `
    tests.test_kev_correlation_risk tests.test_kev_api_ai_ui
```

Run the synthetic activation/update/rollback demonstration and scale
benchmark through the same locked backend image:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace backend python scripts/demo_cisa_kev.py
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace backend python scripts/benchmark_cisa_kev.py
```

The KEV publisher is a separate one-shot process and is never started with the
backend. KEV only prioritizes deterministic current affected matches; it does
not determine vulnerable versions or prove local exploitation. See
`docs/CISA_KEV.md` for source/license, signing, activation, rollback, risk,
ransomware/due-date semantics, PostgreSQL validation, and limitations.

Run the deterministic classification, conflict, reclassification, and AI
evidence showcase through the backend image:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace backend `
  python scripts/demo_asset_classification.py
```

Run the offline deterministic component/advisory showcase and representative
bounded benchmark through the same image:

```powershell
docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace backend `
  python scripts/demo_vulnerability_intelligence.py

docker compose run --rm --no-deps --volume "${PWD}:/workspace" `
  --workdir /workspace backend `
  python scripts/benchmark_vulnerability_intelligence.py `
    --assets 10000 --components-per-asset 10 --advisories 2000
```

See `docs/architecture/hub-spoke-ai-showcase.md` for provider configuration,
the observation batch contract, trust boundaries, local Ollama activation, and
deterministic-mode restoration steps.
See `docs/SENSOR_ENROLLMENT.md` for the one-time sensor enrollment API,
credential storage, rotation/revocation, and development shared-token boundary.
See `docs/DETERMINISTIC_FINDINGS_AND_RISK.md` for the rule registry, finding
lifecycle, score formula, API, configuration, AI authority boundary, and safe
rule-extension process.
See `docs/ASSET_CLASSIFICATION_AND_EVIDENCE_FUSION.md` for classifier
precedence, confidence, provenance, conflicts, managed capability, catalog
handling, APIs, demo, and safe extension steps.
See `docs/SOFTWARE_AND_VULNERABILITY_INTELLIGENCE.md` for component identity,
version comparison, firmware trust, the reviewed offline catalog, matching,
findings/risk, API, AI, dashboard, demo, benchmark, and adapter boundaries.
See `docs/TRUSTED_ADVISORY_FEEDS.md` for reviewed sources, signed bundle/key
formats, download and staging controls, approval, activation, rollback, CLI,
admin API, Settings UI, AI evidence, offline behavior, and source onboarding.
See `docs/ADVISORY_MIRROR.md` for vendor-neutral static distribution of the
same complete signed bundles through a separately signed discovery index.
See `docs/TEMPORAL_SIGNAL_FOUNDATION.md` for the Phase 1 signal contract,
governed registry, supported and deferred metrics, UTC bucketing, read-only API,
missingness/backfill behavior, security boundaries, and Environment Trends UI.

## Safety Boundaries

The backend does not perform active scanning, credential collection, remote
command execution, package installation, self-update, or release download
execution. Ingestion treats client-submitted data as passive observations, not
privileged truth. Classification and finding evaluation run only reviewed
static rules and cannot be extended through an API or model response. The
backend performs no runtime vendor lookup, SSDP URL fetch, or active
fingerprinting. Vulnerability evaluation performs no active scan, exploit
test, runtime advisory lookup, package installation, or automatic patching.
