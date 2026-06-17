# Restructure Plan

## Purpose

This pass starts moving OpenAssetWatch toward a defensive, passive-first,
evidence-based asset intelligence foundation. The source/reference project
reviewed earlier is not the target architecture. It is reference material only.

## Kept

- Existing FastAPI backend MVP for health, collector check-in, inventory
  ingestion, policy assignment, asset listing, and collector listing.
- Existing Python collector as transitional defensive MVP code for local device
  inventory, conservative ARP/neighbor cache discovery, software evidence, and
  scheduler/check-in behavior.
- Existing architecture and setup docs that already describe defensive,
  passive-first principles.
- Existing root Docker Compose local development stack.

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

## Validation Status

- `gofmt -w cmd internal pkg` was attempted but could not run because `gofmt`
  is not installed or available on PATH in this environment.
- `go version` was attempted and failed because the Go toolchain is not
  installed or available on PATH in this environment.
- `go test ./...` could not be run for the same reason.
- `python -m unittest discover -s collector\tests -t collector` using the
  bundled Codex Python runtime passed: 80 tests OK.
- `python -m unittest discover -s backend\tests -t backend` using the bundled
  Codex Python runtime failed before running backend tests because `fastapi` is
  not installed in that runtime.
- A repository scan for forbidden active config fields under `configs/` found
  no matches.
- A repository scan for scanner/offensive terms found remaining active-code
  references only in the collector unsafe-policy denylist.

## Next Required Local Validation

- Install Go.
- Run `gofmt -w cmd internal pkg`.
- Run `go test ./...`.
- Install backend test dependencies.
- Run backend tests with `python -m unittest discover -s backend\tests -t backend`.

## Next Steps

- Expand Go tests around config validation, schema policy, and inventory output.
- Move local platform and neighbor discovery from the Python collector into Go.
- Define production schema files for assets, evidence, findings, connectors,
  and approved diagnostics.
- Continue tightening loader-level enforcement for future config types.
- Keep Skills out of this phase; handle them separately later.
