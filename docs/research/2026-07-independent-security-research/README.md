# Independent Security and Asset-Intelligence Research — July 2026

## Status

This directory preserves the independent public-source research gathered in July 2026 before it is reconciled against OpenAssetWatch's implemented architecture.

These documents are **research inputs, not implementation commitments**. They must not be treated as proof that a capability already exists in OpenAssetWatch. A later research-integration matrix will classify each finding as already covered, partially covered, missing, conflicting, deferred, or rejected.

## Research boundary

The research was intentionally performed without access to the OpenAssetWatch repository so it would not be shaped by existing project decisions. The studies used public sources, standards, government guidance, peer-reviewed research, official project documentation, public repositories, public advisories, vendor material clearly labeled as such, and public operator evidence.

The research did not produce code, configurations, active scanning, exploit testing, or product-specific implementations.

## Audited source set

The research program covered:

1. AI security and asset-intelligence landscape.
2. Armis Centrix, CAASM, cyber-exposure, and OT/IoT product capabilities.
3. Explainable cyber-asset risk prioritization.
4. AI-generated security drilldown dashboards.
5. Cyber-asset identity resolution and confidence scoring.
6. Open IoT, OT, firmware, and appliance intelligence.
7. Evidence-first multi-agent security operations.
8. Evidence-based guided remediation.
9. Product evaluation, benchmark credibility, and release gates.

Where a second-pass adversarial audit exists, the audit supersedes conflicting wording in the first-pass report. In particular:

- The second-pass AI-security landscape report supersedes its first pass.
- The IoT/OT/firmware audit controls factual corrections, source grading, licensing caveats, and GRASSMARLIN history.
- The remediation audit controls BOD 26-04 naming and interpretation, NIST OT-scanning citations, FDA guidance currency, and corrected research figures.

## Common conclusions

The independent studies converge on the following principles:

- Deterministic collection, validation, normalization, matching, authorization, and policy enforcement must remain authoritative.
- AI should operate downstream from validated evidence and should explain, summarize, prioritize, and propose—not create authoritative facts or perform autonomous remediation.
- Missing evidence is uncertainty, not proof of safety or absence.
- Asset identity requires multi-signal evidence fusion, time-aware confidence, reversible merges and splits, and downstream finding re-evaluation after correction.
- Passive observation is the safe baseline for IoT and OT. Active interrogation requires deterministic policy gates, explicit approval, vendor/model validation, and safety review.
- CVSS severity, EPSS probability, KEV exploitation history, exposure, asset importance, urgency, confidence, and remediation value must remain separate.
- Risk prioritization should use transparent decision logic such as SSVC-style action bands, not an opaque AI-generated scalar.
- A patch does not prove attacker eviction, trust restoration, or successful remediation. Closure requires independent verification.
- Generated dashboards are feasible when AI selects and arranges approved metrics and panels through a semantic layer. Free-form SQL, invented joins, and executable visualization code are outside the safe unattended boundary.
- Synthetic and benchmark results must never be presented as production performance.
- Cross-tenant leakage, unsafe remediation, unauthorized dashboard access, unvalidated active OT behavior, and direct AI writes to authoritative facts are release-blocking failures.

## Documentation map

- [`LANDSCAPE_AND_PRODUCT_BENCHMARK.md`](LANDSCAPE_AND_PRODUCT_BENCHMARK.md) — what is working, what is not, Armis-like outcomes, reproducible capabilities, proprietary-scale limits, and product opportunities.
- [`ASSET_IDENTITY_AND_CONFIDENCE.md`](ASSET_IDENTITY_AND_CONFIDENCE.md) — signal hierarchy, identity fusion, calibration, time decay, merge/split governance, privacy, and evaluation.
- [`IOT_OT_FIRMWARE_INTELLIGENCE.md`](IOT_OT_FIRMWARE_INTELLIGENCE.md) — passive protocol evidence, safe-active boundaries, firmware and product normalization, advisory sources, fingerprint projects, licensing, and community corpus governance.
- [`EXPLAINABLE_RISK_AND_REMEDIATION.md`](EXPLAINABLE_RISK_AND_REMEDIATION.md) — separate risk constructs, SSVC-style decision logic, remediation guidance, compromise-aware workflows, VEX, verification, and human approval.
- [`EVIDENCE_FIRST_AGENT_OPERATING_MODEL.md`](EVIDENCE_FIRST_AGENT_OPERATING_MODEL.md) — deterministic coordinator, bounded specialist roles, typed handoffs, fact lifecycle, permission model, disagreement handling, security threats, and audit.
- [`ADAPTIVE_DRILLDOWN_DASHBOARDS.md`](ADAPTIVE_DRILLDOWN_DASHBOARDS.md) — safe AI-generated analytical workspaces, semantic-layer requirements, dashboard-plan constraints, validation, provenance, UX, and phased delivery.
- [`EVALUATION_AND_RELEASE_GATES.md`](EVALUATION_AND_RELEASE_GATES.md) — substrate-versus-AI evaluation, datasets, calibration, red-team testing, usability, public reporting, anti-gaming controls, and release blockers.
- [`SOURCE_LICENSING_AND_OPEN_QUESTIONS.md`](SOURCE_LICENSING_AND_OPEN_QUESTIONS.md) — source licensing, redistribution concerns, uncertain claims, re-verification targets, and unresolved industry problems.

## Durable research identifiers

The source studies assigned identifiers that should be preserved through future architecture decisions:

- `EXT-RES-*` — broad landscape findings.
- `ID-RES-*` — asset identity and confidence findings.
- `IOT-RES-*`, `OT-RES-*`, `FW-RES-*`, `PASV-RES-*`, `ADV-RES-*`, `LIC-RES-*`, `GOV-RES-*` — IoT, OT, firmware, passive discovery, advisory, licensing, and governance findings.
- `AGENT-RES-*`, `AGENT-SEC-*`, `AGENT-GOV-*`, `AGENT-EVAL-*` — agent architecture, security, governance, and evaluation findings.
- `REM-RES-*`, `REM-SAFE-*`, `REM-OT-*`, `REM-VEX-*`, `REM-VERIFY-*`, `REM-COMMS-*` — remediation findings.
- `EVAL-RES-*`, `EVAL-DATA-*`, `EVAL-CAL-*`, `EVAL-SEC-*`, `EVAL-GATE-*`, `EVAL-REPORT-*` — evaluation and release-gate findings.

## Use in future planning

Before any research item becomes a Codex task, it should pass through the future Research Integration and Architecture Gap Matrix and receive:

- current repository coverage;
- accepted, modified, deferred, or rejected status;
- affected architecture documents;
- security and privacy requirements;
- dependencies;
- measurable acceptance criteria;
- evaluation requirements; and
- project-owner decisions.
