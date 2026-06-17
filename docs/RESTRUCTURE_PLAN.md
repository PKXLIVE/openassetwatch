# Restructure Plan

## Purpose

This pass starts moving OpenAssetWatch toward a defensive, passive-first,
evidence-based asset intelligence foundation. The source/reference project
reviewed earlier is not the target architecture. It is reference material only.
`docs/PRODUCT_ARCHITECTURE.md` captures the product-level hybrid runtime,
deployment, licensing, and inspiration boundaries for future work.

## Kept

- Existing FastAPI backend MVP for health, collector check-in, inventory
  ingestion, policy assignment, asset listing, and collector listing.
- Existing Python collector as transitional defensive MVP code for local device
  inventory, conservative ARP/neighbor cache discovery, software evidence, and
  scheduler/check-in behavior.
- Existing architecture and setup docs that already describe defensive,
  passive-first principles.
- Existing root Docker Compose local development stack.
- Hybrid product direction: Go for portable local runtime components and Python
  for AI Advisor, enrichment, scoring, reporting, export experiments,
  evaluation, and LLM workflows.

## Discarded From Active Defaults

- Scanner-launcher vocabulary in active collector policy defaults.
- `nmap_light` and Python `passive_sensor` module toggles from the default
  backend collector policy.
- Active capability discovery references to Nmap, arp-scan, tcpdump, and Zeek
  in the Python collector capability payload.

## Quarantined

No active legacy/source project tool YAMLs were found in this repository during
this pass. `configs/quarantine/` and `docs/legacy-source-review/` were added so
future unsafe or source-project-derived material has a clear non-production
location.

Quarantined material must not be loaded by OpenAssetWatch production code.

## Rewritten Safely

- Collector capability reporting now describes passive inventory sources
  instead of future scanner/fingerprinting tool buckets.
- Collector policy validation rejects unsafe or out-of-scope module names such
  as scanner, shell, exploit, payload, brute force, and credential terms.
- Safe config examples were added for advisor evidence review, approved
  diagnostics, external exposure connectors, and roles.
- Go foundation packages and commands were added for agent, sensor, collector,
  config loading, output, API path constants, auth references, audit, storage,
  updater, installer service specs, models, schema, and version.
- Installer scaffolding was added for Linux, macOS, Windows, and Docker.
- Product architecture documentation now records supported deployment models,
  future licensing/entitlement work, and AiSOC inspiration boundaries without
  implementing license enforcement or copying another product wholesale.

## Validation Status

- System Go is installed at `C:\Program Files\Go\bin\go.exe`. The current
  Codex PowerShell process did not resolve `go` through PATH, so validation used
  the system install by absolute path.
- Go version used: `go1.26.4 windows/amd64`.
- `gofmt -w cmd internal pkg` passed using the system Go install.
- `go test ./...` initially could not create the default build cache under
  `C:\Users\stono\AppData\Local\go-build` due an access denied error. It passed
  after setting `GOCACHE` and `GOMODCACHE` to temp directories.
- System `python` and `pip` are still not available on PATH in this environment.
- A project-local `.venv/` was created using the bundled Codex Python runtime.
- Python version used for tests: `Python 3.12.13`.
- Pip used for tests: `.venv\Scripts\python.exe -m pip`.
- Backend dependencies were installed into `.venv/` from
  `backend/requirements.txt`.
- `python -m unittest discover -s collector\tests -t collector` passed: 80
  tests OK.
- `python -m unittest discover -s backend\tests -t backend` passed: 37 tests
  OK.
- Backend startup import check passed with `PYTHONPATH=backend`.
- A repository scan for forbidden active config fields under `configs/` found
  no matches.
- A repository scan for scanner/offensive terms found remaining active-code
  references only in the collector unsafe-policy denylist.
- First Go local-inventory migration validation passed after adding passive
  platform, host, interface, default-gateway, and neighbor-cache collection
  packages under `internal/collector/`, including per-observation `source` and
  `collected_at` fields for JSON/API/export readiness.
- `gofmt -w cmd internal pkg` passed for the Go local-inventory migration.
- `go test ./...` passed for the Go local-inventory migration using the
  documented temporary `GOCACHE` and `GOMODCACHE` workaround.

## Next Required Local Validation

- Ensure `C:\Program Files\Go\bin` is available on PATH for new shells, or use
  the absolute system Go path.
- Ensure the Go build cache path is writable, or set `GOCACHE` to a writable
  local/temp directory.
- Install Python/pip persistently or create a project virtual environment.
- For this workspace, `.venv/` is the recommended local Python environment and
  is ignored by Git.
- Run `gofmt -w cmd internal pkg`.
- Run `go test ./...`.
- Install backend test dependencies from `backend/requirements.txt`.
- Run collector tests with `python -m unittest discover -s collector\tests -t collector`.
- Run backend tests with `python -m unittest discover -s backend\tests -t backend`.

## Next Steps

- Expand Go tests around config validation, schema policy, and inventory output.
- Continue migrating Python collector scheduler/check-in/backend upload behavior
  into Go after the local inventory package boundaries settle.
- Add licensing and entitlement design as a future control-plane workstream; do
  not implement license enforcement in this foundation pass.
- Define production schema files for assets, evidence, findings, connectors,
  and approved diagnostics.
- Continue tightening loader-level enforcement for future config types.
- Keep Skills out of this phase; handle them separately later.
