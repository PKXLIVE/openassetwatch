# Architecture Guide

OpenAssetWatch is an asset-first, passive-first, evidence-first defensive
platform. Start with `docs/PRODUCT_ARCHITECTURE.md` for the product/runtime
boundary, then use these canonical documents for implemented subsystems:

- `docs/architecture/mvp-architecture.md` - MVP component and deployment view
- `docs/architecture/hub-spoke-ai-showcase.md` - normalized spoke/hub contract
  and provider-neutral AI showcase
- `docs/PASSIVE_SENSOR_MVP.md` - passive network sensor and privacy boundary
- `docs/SENSOR_ENROLLMENT.md` - sensor identity, enrollment, rotation, and
  revocation
- `docs/ASSET_CLASSIFICATION_AND_EVIDENCE_FUSION.md` - deterministic asset
  classification, source-aware provenance, conflicts, and local enrichment
- `docs/SOFTWARE_AND_VULNERABILITY_INTELLIGENCE.md` - reviewed offline advisory
  catalog, components, version comparison, matching, and vulnerability history
- `docs/OSV_PYPI_PUBLISHER.md` - isolated licensed PyPI/PYSEC retrieval,
  normalization, signed publishing, cursor, and operator controls
- `docs/ADVISORY_MIRROR.md` - vendor-neutral static hosting, signed discovery
  index, retained immutable bundles, hub consumption, and publication gates
- `docs/CISA_KEV.md` - official-source KEV normalization, signed enrichment,
  exact-CVE prioritization, findings/risk behavior, UI, and advisory-only AI
- `docs/DETERMINISTIC_FINDINGS_AND_RISK.md` - authoritative findings,
  lifecycle, and the explainable Operational Attention Score
- `docs/architecture/ai-advisor.md` and
  `docs/architecture/ai-agent-architecture.md` - advisory-only AI behavior and
  bounded-agent direction

The additive external-intelligence design expansion is documented separately at:

- `docs/architecture/external-intelligence-enrichment-roadmap.md` - optional
  Certificate Transparency, passive-DNS, external-observation, relationship,
  redaction, and provider-adapter direction that extends existing evidence
  workflows without replacing current collectors or architecture
- `docs/EXTERNAL_INTELLIGENCE_SOURCE_REVIEW.md` - preliminary source-specific
  constraints and review-gated dispositions for Exploratores, crt.sh,
  urlscan.io, LeakIX, ThreatCrowd, ONYPHE, and Netlas

The implemented authority order is:

```text
authenticated normalized evidence
  -> deterministic classification and matching
  -> deterministic findings and attention scoring
  -> bounded investigation and AI explanation
  -> human review
```

AI output is never an authoritative identity, classification, vulnerability
match, finding, score, decision, or action. External intelligence is likewise
non-authoritative until it is corroborated and verified through existing
OpenAssetWatch evidence and review boundaries.

## Accepted Native Expansion Designs

The following documents define accepted future OpenAssetWatch capabilities.
They extend the implemented architecture but are not implementation claims:

- `docs/architecture/agent-investigation-control-loop.md` - deterministic
  triage, isolated specialist tasks, correlation, independent verification,
  human review, recovery, and Agent Run Ledger behavior.
- `docs/architecture/skill-pack-contract.md` - versioned first-party Skill Pack
  instructions/schemas that cannot grant tools, scope, or authority.
- `docs/architecture/capability-provider-contract.md` - stable
  OpenAssetWatch-owned capability contracts with replaceable provider
  implementations.
- `docs/architecture/agent-evaluation-and-release-gates.md` - the broad agent
  evaluation and release standard for evidence, scope, authority, tools,
  verification, privacy, cancellation, Skill Packs, and hard release blockers.
- `docs/architecture/ai-adversarial-input-and-injection-evaluation.md` - a
  specialized extension of the agent evaluation standard covering
  multidimensional adversarial-input coverage, multi-turn policy revalidation,
  tool-metadata and argument-provenance tests, structured-output semantic
  validation, propagation resistance, resource-abuse evaluation, local-model
  integrity qualification, and explicit unknown coverage states.
- `docs/architecture/temporal-intelligence-roadmap.md` - historical signal
  projections, transparent expected ranges, deterministic deviation handling,
  and optional future forecasting providers.
- `docs/architecture/defensive-content-and-model-robustness.md` - structural
  versus heuristic AI safety controls, monotonic context taint, transformed
  secret egress protection, sensitive-content inspection, current security
  intelligence, parser robustness, adversarial model evaluation, and ML score
  provenance.
- `docs/architecture/decisions/0003-native-agent-investigation-and-temporal-intelligence.md`
  - accepted cross-subsystem authority and sequencing decisions.
- `docs/architecture/decisions/0005-defensive-content-and-model-robustness.md`
  - accepted defensive content, intelligence, parser, and model robustness
  boundaries and implementation sequence.
- `docs/architecture/decisions/0006-adversarial-input-evaluation.md` - accepted
  OpenAssetWatch-native adversarial coverage, propagation, tool/output,
  resource-abuse, and local model-integrity evaluation requirements.

These designs preserve deterministic product authority, passive-first behavior,
local-first operation, and human review.

## Independent Research and Accepted Direction

The July 2026 independent security and asset-intelligence research is indexed at
`docs/research/2026-07-independent-security-research/README.md`.

That research was performed without access to the OpenAssetWatch repository so
it would not be influenced by existing architecture decisions. It covers the
external product landscape, asset identity and confidence, IoT/OT/firmware
intelligence, explainable risk, guided remediation, evidence-first agents,
adaptive drilldown dashboards, evaluation, release gates, source licensing,
and unresolved questions.

The repository-grounded integration assessment is maintained at:

- `docs/RESEARCH_INTEGRATION_AND_ARCHITECTURE_GAP_MATRIX.md`

The accepted research-aligned expansion direction and project-owner decisions
are recorded under:

- `docs/architecture/decisions/README.md`
- `docs/architecture/decisions/0001-research-aligned-expansion.md`
- `docs/architecture/decisions/0002-additive-external-intelligence-enrichment.md`
- `docs/architecture/decisions/0005-defensive-content-and-model-robustness.md`
- `docs/architecture/decisions/0006-adversarial-input-evaluation.md`

Third-party advisory, fingerprint, and external-intelligence source decisions
are governed by:

- `docs/SOURCE_LICENSING_REGISTRY.md`

Research documents remain external evidence inputs, not implementation claims.
The gap matrix records current coverage and prerequisites, while the ADRs record
which directions are approved. Canonical subsystem documents and source code
continue to control current behavior.
