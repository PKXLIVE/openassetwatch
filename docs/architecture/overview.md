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
- `docs/DETERMINISTIC_FINDINGS_AND_RISK.md` - authoritative findings,
  lifecycle, and explainable risk
- `docs/architecture/ai-advisor.md` and
  `docs/architecture/ai-agent-architecture.md` - advisory-only AI direction

The implemented authority order is:

```text
authenticated normalized evidence
  -> deterministic classification
  -> deterministic findings and risk
  -> bounded read-only AI explanation
  -> human review
```

AI output is never an authoritative identity, classification, finding, or risk
input.
