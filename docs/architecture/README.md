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

## Asset Intelligence Stack Gap Expansion

- `asset-intelligence-stack-gap-additions.md` — accepted missing architecture
  for asset presence sessions, canonical field authority and change history,
  relationship evidence and edge history, dependency-aware alert compression,
  quota-aware connector credentials, transformation provenance, adaptive host
  pressure controls, governed passive fingerprint rules, worker compatibility,
  partitioned platform work, and safe fielded asset/relationship queries. The
  document also records implementation sequencing, release blockers, and the
  active/offensive or duplicative features that must not be added.
- `decision-integrity-and-evidence-snapshot-gaps.md` — accepted cross-cutting
  requirements for exact-state-bound approval receipts, incomplete-analysis
  gates, suppression/accepted-risk governance, candidate entity promotion and
  bounded reconsideration, consistent evidence snapshots, and explicit
  separation between operational activity and evidentiary lineage.

## Native Design Review Boundary

- `NO_EXTERNAL_REFERENCE_POLICY.md` — requires canonical architecture to use
  OpenAssetWatch-native terminology and independently defined contracts while
  leaving normal licensing/provenance obligations intact for any actual
  third-party material.
- `decisions/0004-native-design-provenance-boundary.md` — accepted review rule
  for native architecture expansions.

These documents define additive future capabilities and review constraints. They
do not replace the current asset, evidence, finding, risk, collector,
passive-sensor, AI Advisor, or deployment architecture, and they do not claim
implementation status.
