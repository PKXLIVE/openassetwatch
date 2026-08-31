---
name: oaw-validation
description: Select, run, interpret, and report OpenAssetWatch validation for implementation work. Use when code, configuration, packaging, migrations, workflows, or behavior changed and Codex must prove the change is ready for review. Do not claim unavailable CI, hardware, production, or external-service validation.
---

# OpenAssetWatch Validation

Treat validation as evidence, not ceremony. Run the smallest checks that can catch likely regressions while iterating, then run the broader applicable gates before declaring the task ready.

## 1. Determine the affected validation domains

Inspect the final diff and map changes to one or more domains:

- Go agent/sensor/collector/shared packages;
- Python collector;
- backend/API/data model;
- PostgreSQL schema/migrations;
- Docker/Compose/deployment;
- packaging/release workflows;
- frontend/UI if present in the changed scope;
- documentation/policy only;
- security, dependency, provenance, or licensing controls.

Read `docs/LOCAL_DEV_SETUP.md` and component-specific README/docs before inventing commands.

## 2. Go validation

When Go behavior is affected:

1. Format changed Go files with `gofmt`.
2. Run targeted package tests during iteration when useful.
3. Run `go test ./...` before completion when the environment supports it.
4. In Windows Codex environments, use writable temp/workspace `GOCACHE` and `GOMODCACHE` paths when the default cache is denied, exactly as documented in `docs/LOCAL_DEV_SETUP.md`.

A formatting-only run is not sufficient evidence for behavioral changes.

## 3. Python collector validation

When collector Python is affected, use the project-local environment and unittest discovery command documented in `docs/LOCAL_DEV_SETUP.md`.

If the required interpreter/environment is unavailable, do not silently switch to an incompatible dependency set. Report the unavailable validation and continue with other safe checks.

## 4. Backend validation

When backend behavior or dependencies are affected:

- build/use the locked backend Docker image as documented;
- run `python -m pip check` in the image when dependency integrity matters;
- run the repository-mounted backend unittest suite for behavioral changes;
- run the backend startup/import check when initialization, configuration, or dependencies changed.

Do not install the Linux backend lock directly into the Windows virtual environment contrary to `docs/LOCAL_DEV_SETUP.md`.

## 5. Database migration validation

When schema/migration behavior changes:

- use the local Compose PostgreSQL service;
- verify health/readiness and migration status/checksum as documented;
- run the destructive lifecycle suite only under the guarded `openassetwatch_schema_test_` test-database mechanism;
- never point destructive migration validation at production, customer, or shared databases.

If the guard refuses to run, treat that as a safety success and diagnose the test setup rather than bypassing it.

## 6. Workflow, release, and packaging validation

For GitHub Actions, installer, packaging, or release changes:

- validate syntax/configuration locally when an approved tool exists;
- inspect changed workflow permissions, triggers, secret use, artifact handling, and release scope;
- run non-destructive local build/package checks that are available;
- rely on GitHub Actions for platform-specific runner evidence when local execution cannot reproduce it;
- never claim a workflow is passing until the relevant run has completed successfully.

Do not weaken CodeQL, dependency review, gitleaks/secret scanning, DCO, SBOM, scorecard, or other established gates simply to obtain a green result.

## 7. Failure classification loop

For every failed check, classify it as:

- **introduced regression** — caused by the proposed change; fix before completion;
- **pre-existing failure** — reproduce against the appropriate baseline when practical and document evidence;
- **environmental limitation** — tool/runtime/hardware/network/service unavailable; record exact limitation;
- **expected safety guard** — a guard correctly blocked an unsafe operation; do not bypass it;
- **unknown** — investigate further rather than guessing.

Repeat `fix -> rerun` until introduced failures are resolved or a legitimate escalation condition in `AGENTS.md` is reached.

## 8. Final validation report

Report only checks actually observed. Use this structure in the PR/handoff:

- **Passed:** commands/checks and what they proved.
- **Not run:** required or useful checks that could not be run, with reason.
- **Pre-existing/environmental:** failures shown not to be caused by this change, with evidence where available.
- **CI still required:** platform/security/release gates awaiting GitHub execution.

Never convert "not run" into "passed" and never treat documentation intent as execution evidence.
