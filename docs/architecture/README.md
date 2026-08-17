# OpenAssetWatch Architecture Expansion Index

This directory contains OpenAssetWatch-owned architecture designs and supporting
implementation roadmaps. Canonical implemented behavior remains controlled by
source code and the subsystem documents linked from `docs/architecture/overview.md`.

## Native Agent And Temporal Expansion

- `agent-investigation-control-loop.md` — deterministic triage, isolated
  specialist investigation, correlation, verification, human review, recovery,
  and Agent Run Ledger design.
- `skill-pack-contract.md` — first-party versioned instruction/schema packages
  that remain subordinate to product scope, policy, tools, and authority.
- `capability-provider-contract.md` — provider-neutral capability definitions and
  replaceable implementation boundary.
- `agent-evaluation-and-release-gates.md` — evaluation fixtures, hard safety
  blockers, repeated-run testing, and public-claim discipline.
- `temporal-intelligence-roadmap.md` — historical signal projection,
  deterministic expected ranges, deviation candidates, and optional later
  forecasting.
- `native-agent-expansion-implementation-plan.md` — incremental work packages
  and sequencing constraints for future implementation.
- `decisions/0003-native-agent-investigation-and-temporal-intelligence.md` — accepted
  cross-subsystem decision and non-negotiable invariants.

These documents define additive future capabilities. They do not replace the
current asset, evidence, finding, risk, collector, passive-sensor, AI Advisor,
or deployment architecture, and they do not claim implementation status.
