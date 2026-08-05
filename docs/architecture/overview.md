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
- `docs/DETERMINISTIC_FINDINGS_AND_RISK.md` - authoritative findings,
  lifecycle, and the explainable Operational Attention Score
- `docs/architecture/ai-advisor.md` and
  `docs/architecture/ai-agent-architecture.md` - advisory-only AI behavior and
  future bounded-agent direction

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
  -> bounded read-only AI explanation
  -> human review
```

AI output is never an authoritative identity, classification, vulnerability
match, finding, score, decision, or action. External intelligence is likewise
non-authoritative until it is corroborated and verified through existing
OpenAssetWatch evidence and review boundaries.

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

Third-party advisory, fingerprint, and external-intelligence source decisions
are governed by:

- `docs/SOURCE_LICENSING_REGISTRY.md`

Research documents remain external evidence inputs, not implementation claims.
The gap matrix records current coverage and prerequisites, while the ADRs record
which directions are approved. Canonical subsystem documents and source code
continue to control current behavior.
