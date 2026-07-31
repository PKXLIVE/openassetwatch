# Independent Security and Asset-Intelligence Research — July 2026

## Status

This directory preserves the independent public-source research gathered in
July 2026. The research was subsequently reconciled against the OpenAssetWatch
repository snapshot at commit
`76321ce56301c7846e060fe67793a108c6c3cde6`.

These documents remain **research inputs, not implementation claims**.
Repository coverage, gaps, conflicts, and prerequisites are maintained in:

- `docs/RESEARCH_INTEGRATION_AND_ARCHITECTURE_GAP_MATRIX.md`

The accepted research-aligned product direction and project-owner decisions are
recorded in:

- `docs/architecture/decisions/0001-research-aligned-expansion.md`

Third-party source approval is governed by:

- `docs/SOURCE_LICENSING_REGISTRY.md`

## Research boundary

The research was intentionally performed without access to the OpenAssetWatch
repository so it would not be shaped by existing project decisions. The
studies used public sources, standards, government guidance, peer-reviewed
research, official project documentation, public repositories, public
advisories, vendor material clearly labeled as such, and public operator
evidence.

The research did not produce code, configurations, active scanning, exploit
testing, or product-specific implementations.

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

Where a second-pass adversarial audit exists, the audit supersedes conflicting
wording in the first-pass report. In particular:

- The second-pass AI-security landscape report supersedes its first pass.
- The IoT/OT/firmware audit controls factual corrections, source grading,
  licensing caveats, and GRASSMARLIN history.
- The remediation audit controls BOD 26-04 naming and interpretation, NIST
  OT-scanning citations, FDA guidance currency, and corrected research figures.

## Common conclusions

The independent studies converge on the following principles:

- Deterministic collection, validation, normalization, matching,
  authorization, and policy enforcement must remain authoritative.
- AI should operate downstream from validated evidence and should explain,
  summarize, prioritize, and propose—not create authoritative facts or perform
  autonomous remediation.
- Missing evidence is uncertainty, not proof of safety or absence.
- Asset identity requires multi-signal evidence fusion, time-aware confidence,
  reversible merges and splits, and downstream finding re-evaluation after
  correction.
- Passive observation is the safe baseline for IoT and OT. Active
  interrogation requires deterministic policy gates, explicit approval,
  vendor/model validation, and safety review.
- CVSS severity, EPSS probability, KEV exploitation history, exposure, asset
  importance, urgency, confidence, and remediation value must remain separate.
- Risk prioritization should use transparent decision logic such as SSVC-style
  action bands, not an opaque AI-generated scalar.
- A patch does not prove attacker eviction, trust restoration, or successful
  remediation. Closure requires independent verification.
- Generated dashboards are feasible when AI selects and arranges approved
  metrics and panels through a semantic layer. Free-form SQL, invented joins,
  and executable visualization code are outside the safe unattended boundary.
- Synthetic and benchmark results must never be presented as production
  performance.
- Cross-tenant leakage, unsafe remediation, unauthorized dashboard access,
  unvalidated active OT behavior, and direct AI writes to authoritative facts
  are release-blocking failures.

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

The source studies assigned identifiers that are preserved through the
integration matrix and future architecture decisions:

- `EXT-RES-*` — broad landscape findings.
- `ID-RES-*` — asset identity and confidence findings.
- `IOT-RES-*`, `OT-RES-*`, `FW-RES-*`, `PASV-RES-*`, `ADV-RES-*`,
  `LIC-RES-*`, `GOV-RES-*` — IoT, OT, firmware, passive discovery,
  advisory, licensing, and governance findings.
- `AGENT-RES-*`, `AGENT-SEC-*`, `AGENT-GOV-*`, `AGENT-EVAL-*` — agent
  architecture, security, governance, and evaluation findings.
- `REM-RES-*`, `REM-SAFE-*`, `REM-OT-*`, `REM-VEX-*`, `REM-VERIFY-*`,
  `REM-COMMS-*` — remediation findings.
- `EVAL-RES-*`, `EVAL-DATA-*`, `EVAL-CAL-*`, `EVAL-SEC-*`,
  `EVAL-GATE-*`, `EVAL-REPORT-*` — evaluation and release-gate findings.

The integration assessment found intentionally absent or retired numbers in
some sequences. They are listed in the matrix and must not be assigned invented
meanings.

## Use in planning

Before an approved direction becomes a Codex task, its matrix row and ADR gate
must identify:

- current repository coverage;
- affected architecture and subsystem documents;
- security and privacy requirements;
- source licensing status;
- dependencies and owner decisions;
- measurable acceptance criteria;
- evaluation and release blockers; and
- whether the task is ready for detailed design, ready for implementation,
  decision-blocked, research-blocked, or prohibited.
