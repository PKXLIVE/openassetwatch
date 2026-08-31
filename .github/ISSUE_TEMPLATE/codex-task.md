---
name: Codex implementation task
about: Define a bounded OpenAssetWatch task with explicit outcome, constraints, and verification for autonomous execution.
title: ""
labels: ""
assignees: ""
---

## Outcome

<!-- Describe the observable result that should exist when this task is complete. -->

## Why / context

<!-- Explain the problem or user/operator need. Link authoritative docs/ADRs when relevant. -->

## In scope

- [ ]

## Out of scope

- [ ]

## Architecture / product invariants

<!-- Note task-specific constraints. Root AGENTS.md and applicable architecture skills still apply. -->

- [ ] Preserve existing OpenAssetWatch authority and safety boundaries.

## Acceptance criteria

- [ ]
- [ ] Relevant tests are added/updated when behavior changes.
- [ ] Documentation is updated when behavior/configuration/setup changes.

## Required validation

<!-- Identify known commands/gates when possible. Codex must still select additional risk-appropriate checks. -->

- [ ] Applicable local validation from `docs/LOCAL_DEV_SETUP.md`.
- [ ] Relevant GitHub CI/security gates.

## Dependencies / prerequisites

<!-- Credentials, hardware, external services, preceding issues/PRs, migrations, etc. -->

None known.

## Human-only gates

<!-- Identify actions Codex must not take autonomously for this task. -->

- Final merge to `main` remains human-gated.
- Human DCO/legal identity attestations must not be fabricated by automation.

## Stop conditions specific to this task

<!-- Add any task-specific point where Codex must stop rather than guess. -->

None beyond root `AGENTS.md` unless listed here.
