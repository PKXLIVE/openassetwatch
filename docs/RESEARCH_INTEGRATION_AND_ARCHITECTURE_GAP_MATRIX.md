# Research Integration and Architecture Gap Matrix

- **Assessment date:** 2026-07-31
- **Repository snapshot assessed:** `76321ce56301c7846e060fe67793a108c6c3cde6`
- **Research source:** `docs/research/2026-07-independent-security-research/`
- **Architecture decision:** `docs/architecture/decisions/0001-research-aligned-expansion.md`

## Purpose

This document maps the July 2026 independent research to the actual
OpenAssetWatch repository. It separates implemented capability, partial
coverage, documented design, missing capability, research-only opportunity, and
explicitly rejected behavior.

Research findings do not become implementation claims merely because they are
listed here. Canonical subsystem documents and source code remain authoritative
for current behavior.

## Assessment rules

- Audited research corrections supersede conflicting first-pass statements.
- Documentation is not proof of implementation.
- Tests are evidence of intended behavior, not proof of production operation.
- Demo behavior is not production readiness.
- Duplicate embedded repository blocks are counted once by path and commit.
- Missing data means unknown, not safe.
- Vendor claims remain vendor claims until independently verified.
- A proposed source remains unusable until `docs/SOURCE_LICENSING_REGISTRY.md`
  records an approved decision.

## Coverage vocabulary

| Status | Meaning |
| --- | --- |
| `implemented` | Connected implementation exists in the assessed snapshot. |
| `implemented-with-limitations` | A working substrate exists but does not meet the complete research recommendation. |
| `partial` | Some required elements exist. |
| `designed` | Documented direction exists without a complete runtime. |
| `missing` | No applicable implementation was located. |
| `duplicate-direction` | Research reinforces an existing architecture choice. |
| `deferred` | Deliberately postponed or avoided by current design. |
| `rejected` | Incompatible with product safety, privacy, licensing, or scope. |
| `research-required` | Evidence, licensing, calibration, or governance is insufficient for design approval. |
| `not-applicable` | A general research claim does not map to a current product capability. |

## Current capability baseline

### Strong existing foundations

- authenticated normalized observations and source-aware provenance;
- deterministic asset classification and conflict preservation;
- deterministic findings, lifecycle, acknowledgement, suppression, and reopen;
- deterministic software/firmware normalization, version comparison, and
  reviewed offline vulnerability matching;
- passive Linux sensing with no scan, probe, packet injection, or discovered-URL
  fetch path;
- sensor enrollment, check-in, credential rotation, and revocation;
- bounded read-only AI Advisor with evidence-ID validation;
- local/offline runtime and labeled synthetic demonstrations;
- security, dependency, secret, SBOM, license, and scorecard CI controls.

### Largest gaps

- calibrated identity resolution and reversible merge/split;
- bitemporal identity history;
- live or scheduled reviewed source adapters for KEV, OSV, GHSA, CSAF, EPSS,
  lifecycle, and vendor advisories;
- separate urgency, action-band, and remediation-value presentation;
- VEX and formal risk-acceptance governance;
- multi-agent runtime, typed handoffs, per-agent identity, and approval tiers;
- structured guided-remediation and executed-change verification;
- semantic metrics, approved panel catalog, and adaptive dashboards;
- calibration, time-split, repeated-run, and adaptive-injection evaluation;
- hosted tenant isolation, user identity, and RBAC.

## Corrected repository contradictions

| ID | Conflict | Required treatment |
| --- | --- | --- |
| `DOC-CORR-01` | `docs/DETERMINISTIC_FINDINGS_AND_RISK.md` described `oaw.findings.v2` and deferred vulnerability rules while code and vulnerability documentation used `oaw.findings.v3` with three vulnerability rules. | Correct documentation to v3 and list the implemented vulnerability rules. |
| `DOC-CORR-02` | The AI showcase limitation list said no real passive sensor existed although the passive sensor MVP was implemented separately. | Clarify that the showcase itself does not capture packets and consumes the separately implemented sensor. |
| `DOC-CORR-03` | Findings documentation said severity and confidence remain separate “throughout scoring,” while `oaw.risk.v1` combines severity weight, confidence, and freshness into one scalar. | Describe the scalar honestly as an operational attention score while keeping its factors visible. |

## Research traceability matrix

### Asset identity and evidence fusion

| Research ID | Finding | Coverage | Disposition | Gate or affected area |
| --- | --- | --- | --- | --- |
| `ID-RES-001` | Identity requires multiple independent signals. | `partial` | Expand current classification evidence into an identity-resolution model. | DR-04, DR-05; `backend/app/classification.py`; asset/evidence schemas. |
| `ID-RES-002` | Fellegi-Sunter or Bayesian linkage is a principled probabilistic core. | `missing` | Defer implementation; retain as target method for later calibrated identity work. | Labeled corpus and calibration required. |
| `ID-RES-003` | Blocking/indexing is needed before scalable pairwise matching. | `missing` | Add only when an entity-resolution engine is designed. | Depends on DR-04 and identity scale requirements. |
| `ID-RES-004` | Confidence must be calibrated. | `missing` | Adopt as release requirement before probabilistic auto-merge. | Reliability diagrams, Brier score, ECE, held-out labels. |
| `ID-RES-005` | Hardware and cryptographic anchors are strongest but sparse. | `partial` | Expand evidence hierarchy; do not assume coverage. | Asset identity architecture; certificate and attestation privacy. |
| `ID-RES-006` | TPM identity creates privacy obligations. | `missing` | Document before any TPM-backed feature. | DR-04/05; privacy design; no direct EK exposure. |
| `ID-RES-007` | MAC randomization defeats cross-network MAC identity. | `partial` | Add explicit randomized-MAC and BYOD policy. | Privacy review; no persistent cross-network BYOD tracking. |
| `ID-RES-008` | Cloned image identifiers must not establish identity. | `missing` | Add disqualifying and clone-divergence rules to future identity design. | DR-04; first-observation ambiguity research. |
| `ID-RES-009` | Identity requires bitemporal, auditable history. | `partial` | Expand append-only histories to valid and transaction time. | DR-05; schema migration design. |
| `ID-RES-010` | Missing evidence is ignorance, not disagreement. | `implemented-with-limitations` | Retain lifecycle behavior; add explicit uncertainty surfacing in scoring/UI. | DR-01/03; current low-confidence score tension. |
| `ID-RES-011` | Identity corrections must re-evaluate dependent findings. | `partial` | Make mandatory for merge/split and correction workflows. | DR-04/05; vulnerability and risk queues. |
| `ID-RES-012` | Transitive over-merge is a primary failure mode. | `deferred` | Preserve current abstention; add weak-edge closure guards before auto-merge. | Probabilistic identity remains blocked. |
| `ID-RES-013` | Naive evidence combination fails under high conflict. | `partial` | Preserve contradictions and avoid confidence inflation. | Identity evaluation and adversarial tests. |
| `ID-RES-014` | IoT fingerprints classify type better than instance identity. | `duplicate-direction` | Retain inference-only posture. | Firmware and passive evidence must not confirm vulnerabilities alone. |
| `ID-RES-015` | Vendor dedup claims are not proof of accuracy. | `not-applicable` | Use as claims discipline for comparisons. | Public benchmark and product language. |
| `ID-RES-019` | Passive fingerprints are supporting inference, not identity proof. | `implemented` | Retain. | Passive and firmware evidence tiers. |
| `ID-RES-020` | Recommended identity architecture is deterministic plus probabilistic plus graph plus human review. | `partial` | Adopt phased target; begin with reversible human-reviewed merge/split. | DR-04/05 and calibration gate. |

### Passive, IoT, OT, firmware, and fingerprint intelligence

| Research ID | Finding | Coverage | Disposition | Gate or affected area |
| --- | --- | --- | --- | --- |
| `PASV-RES-001` | Passive-first is the authoritative OT baseline. | `implemented` | Retain as non-negotiable. | `docs/PASSIVE_SENSOR_MVP.md`; sensor capture boundary. |
| `OT-RES-001` | Active OT querying requires strict validation and approval. | `designed` | Keep passive-only until DR-08 controls exist. | Deterministic policy gate, explicit approval, model/firmware validation. |
| `FW-RES-001` | Firmware identity is provenance-tagged and multi-hypothesis. | `partial` | Add explicit alternative hypotheses and OEM/variant relationships later. | Firmware schema and UI; source corpus research. |
| `IOT-RES-001` | Lab device-type accuracy is not production instance accuracy. | `duplicate-direction` | Retain claim discipline and explicit unknown handling. | Evaluation and public documentation. |
| `GOV-RES-001` | An open, signed fingerprint corpus is a high-value opportunity. | `research-required` | Research governance before accepting data. | DR-09; poisoning, privacy, moderation, retraction, license. |
| `LIC-RES-001` | Licensing is a primary fingerprint/advisory integration risk. | `partial` | Enforce the Source Licensing Registry. | DR-05a; adapter and corpus merge gate. |
| `ADV-RES-001` | Reduced NVD enrichment weakens hardware and firmware correlation. | `duplicate-direction` | Retain NVD-independent local catalog; expand reviewed sources. | DR-06 and feed-freshness controls. |

### Agent architecture and AI security

| Research ID | Finding | Coverage | Disposition | Gate or affected area |
| --- | --- | --- | --- | --- |
| `AGENT-RES-001` | The coordinator should be a deterministic control plane. | `implemented-with-limitations` | Retain for the current advisor and require it for multi-agent work. | DR-10; typed contracts and authorization. |
| `AGENT-RES-002` | Evidence states need an append-only fact lifecycle. | `partial` | Design a unified evidence/fact lifecycle without replacing authoritative relational records. | DR-05, DR-10/11; new architecture doc. |
| `AGENT-SEC-001` | External content is data, never instructions. | `implemented` | Retain and expand adversarial testing. | Provider prompts, gateway, parsers, feeds, dashboard labels. |
| `AGENT-SEC-002` | Models may not write validated facts, decisions, or actions. | `implemented` | Codify as a release invariant. | DR-11, DR-16. |
| `AGENT-SEC-003` | Agents need short-lived scoped identities. | `missing` | Require before a multi-agent or side-effecting runtime. | DR-10/12; workload identity and authorization design. |
| `AGENT-GOV-001` | Human approval must be tiered by consequence. | `designed` | Define tiers before any action feature. | DR-12; remediation and OT actions. |
| `AGENT-GOV-002` | Disagreement should be preserved; consensus is not verification. | `partial` | Preserve deterministic conflicts; add multi-agent disagreement contracts later. | DR-10/11; verifier role. |
| `AGENT-EVAL-001` | Evaluate reliability, evidence integrity, permission compliance, and false closure. | `partial` | Expand the existing advisor evaluation program. | DR-16; repeated runs and evidence metrics. |

### Guided remediation, verification, and communication

| Research ID | Finding | Coverage | Disposition | Gate or affected area |
| --- | --- | --- | --- | --- |
| `REM-RES-001` | Severity, urgency, confidence, and remediation value must stay distinct. | `partial` | Retain score engine but add separate dimensions and action bands. | DR-01/02/03; risk UI and API versioning. |
| `REM-SAFE-001` | Recommendation is not execution. | `implemented` | Retain as non-negotiable. | No write-capable advisor tools. |
| `REM-SAFE-002` | Missing identity or version blocks unsafe specificity. | `implemented` | Retain. | Vulnerability matching and remediation guidance. |
| `REM-SAFE-003` | Patching is not attacker eviction or trust restoration. | `missing` | Add incident-response escalation and compromise-aware guidance. | Guided remediation architecture. |
| `REM-OT-001` | OT remediation is passive-first and safety-governed. | `implemented` for current read-only scope | Retain and extend only after approval tiers exist. | DR-08/12. |
| `REM-VEX-001` | VEX is an assertion requiring scope, evidence, provenance, and revalidation. | `missing` | Add alongside suppression and formal risk acceptance. | DR-07; source and signature policy. |
| `REM-VERIFY-001` | Closure requires independent verification. | `partial` | Extend affirmative-evidence lifecycle rules into executed-change verification. | Verification tiers and remediation records. |
| `REM-COMMS-001` | Tailor explanations without changing the evidence. | `partial` | Add audience profiles after the structured recommendation model. | Home/SMB, technical, executive, and OT views. |

### Evaluation and release gates

| Research ID | Finding | Coverage | Disposition | Gate or affected area |
| --- | --- | --- | --- | --- |
| `EVAL-RES-001` | Deterministic substrate and AI correctness must be evaluated separately. | `partial` | Formalize report separation. | Evaluation standard and CI reports. |
| `EVAL-RES-002` | Benchmark performance is not production performance. | `implemented` | Retain. | Synthetic and pure-engine labels. |
| `EVAL-DATA-001` | Probabilistic models require time-split held-out validation. | `missing` | Require before probabilistic identity or learned risk features. | DR-04; labeled corpus. |
| `EVAL-DATA-002` | Synthetic data must be clearly labeled. | `implemented` | Retain. | Demo, tests, benchmarks, public claims. |
| `EVAL-CAL-001` | Use reliability diagrams, Brier score, and ECE. | `missing` | Require for calibrated confidence. | Identity and any probabilistic output. |
| `EVAL-SEC-001` | Security testing must repeat and adapt attacks while measuring utility. | `partial` | Expand static adversarial cases into campaigns. | Prompt injection, tool abuse, memory, source poisoning. |
| `EVAL-GATE-001` | Safety invariants should block releases. | `partial` | Encode named hard blockers from DR-16. | CI and capability-specific release criteria. |
| `EVAL-REPORT-001` | Public claims require reproducibility and visible failures. | `missing` | Add a benchmark reporting standard before public accuracy claims. | Dataset, hardware, model, prompt, runs, variance, failures. |
| `EVAL-REPORT-002` | Evaluation programs need anti-gaming controls. | `missing` | Add hidden/held-out cases, failure examples, and metric review. | Evaluation governance. |

### External landscape findings

| Research ID | Finding | Coverage | Disposition | Gate or affected area |
| --- | --- | --- | --- | --- |
| `EXT-RES-001` | Universal timely NVD enrichment is no longer reliable. | `duplicate-direction` | Retain reviewed multi-source direction. | DR-06. |
| `EXT-RES-003` | KEV is high signal but has limited coverage. | `partial` | Add as one field/source, never the whole risk model. | DR-06; licensing gate. |
| `EXT-RES-004` | EPSS is probability, not risk. | `missing` | Add only as a separate field. | DR-03/06; source license. |
| `EXT-RES-005` | OSV and GHSA are strong open-source inputs. | `missing` | Prioritize reviewed adapters after KEV. | DR-05a/06. |
| `EXT-RES-009` | Prompt-injection robustness degrades under repeated attempts. | `partial` | Expand testing. | EVAL-SEC-001; DR-16. |
| `EXT-RES-010` | Vector and memory stores must not become the system of record. | `implemented` by absence/design | Retain authoritative relational records. | Future retrieval may remain advisory. |
| `EXT-RES-014` | Unverified AI vulnerability reports create maintainer burden. | `not-applicable` | Use as governance principle for community submissions. | Evidence threshold and human validation. |
| `EXT-RES-015` | Hybrid discovery is commercially established. | `partial` | Preserve endpoint plus passive discovery; safe-active remains gated. | DR-08. |
| `EXT-RES-019` | Credible AI triage is human-supervised and evidence-showing. | `implemented` | Retain. | AI Advisor authority boundary. |
| `EXT-RES-021` | No open system clearly provides the full end-to-end capability. | `not-applicable` opportunity | Use as differentiation context, not an implementation claim. | Product strategy. |
| `EXT-RES-022` | Indirect prompt injection is a recurring production attack. | `implemented-with-limitations` | Retain controls and expand repeated testing. | DR-16. |
| `EXT-RES-023` | An AI-credited CVE does not prove autonomous security capability. | `not-applicable` | Retain claims discipline. | Public communications and benchmarks. |

### Adaptive drilldown dashboards

The dashboard research did not assign durable identifiers. These local IDs are
used for traceability.

| Local ID | Finding | Coverage | Disposition | Gate or affected area |
| --- | --- | --- | --- | --- |
| `DASH-U-01` | Fixed and parameterized templates are the mature safe baseline. | `implemented-with-limitations` | Expand deterministic drilldowns first. | DR-13. |
| `DASH-U-02` | A semantic metrics layer is a prerequisite. | `missing` | Design before AI composition. | DR-15. |
| `DASH-U-03` | AI should select only from an approved panel catalog. | `missing` | Adopt in crawl phase. | DR-13. |
| `DASH-U-04` | Dashboard plans must be schema-constrained and deterministically validated. | `missing` | Require before any AI-generated workspace. | DR-13/15/16. |
| `DASH-U-05` | Generated dashboards should be temporary by default. | `missing` | Adopt with audited explicit save. | DR-14. |
| `DASH-U-06` | Free-form SQL, invented joins/fields, and unbounded queries are prohibited. | `rejected` pattern upheld | Encode as hard invariants. | DR-15/16. |
| `DASH-U-07` | Each panel needs provenance and freshness. | `partial` | Extend record-level evidence into panel metadata. | Semantic layer and renderer. |
| `DASH-U-08` | Deterministic fallback templates are required. | `implemented` de facto | Retain fixed views as fallback. | DR-13. |

## Missing or retired research numbers

The source documents contain no definitions for these numbers:

- `EXT-RES-002`, `EXT-RES-006`, `EXT-RES-007`, `EXT-RES-008`,
  `EXT-RES-011`, `EXT-RES-012`, `EXT-RES-013`, `EXT-RES-016`,
  `EXT-RES-017`, `EXT-RES-018`, `EXT-RES-020`;
- `ID-RES-016`, `ID-RES-017`, `ID-RES-018`.

They are treated as intentionally absent or retired until a maintainer records a
replacement. Do not invent meanings for them.

## Workstream readiness

| Workstream | Status | Immediate next step |
| --- | --- | --- |
| Research governance and licensing | Ready for detailed design | Maintain source decisions and provenance requirements. |
| Documentation correction | Ready for Codex/maintainer edit | Correct `DOC-CORR-01` through `DOC-CORR-03`. |
| Explainable attention and action bands | Approved direction; detailed design required | Define score compatibility, uncertainty, dimensions, and action-band contract. |
| Multi-source vulnerability intelligence | Approved direction; source-gated | Complete source decisions, then design KEV adapter and freshness monitoring. |
| Asset identity and merge/split | Approved direction; design and data-gated | Specify bitemporal history and reversible manual workflow. |
| Probabilistic identity | Research blocked | Build labeled corpus and calibration thresholds. |
| VEX and risk acceptance | Approved direction; detailed design required | Define statuses, evidence, issuer, scope, expiry, and conflicts. |
| Multi-agent runtime | Approved direction; design-gated | Define typed contracts, deterministic coordinator, identities, and approval tiers. |
| Guided remediation and verification | Approved direction; detailed design required | Define recommendation schema, rollback, stop, escalation, and verification tiers. |
| Adaptive dashboards | Approved crawl phase; prerequisite-gated | Define semantic layer and approved panel catalog. |
| Evaluation and release gates | Ready for detailed design | Encode existing invariants and design repeated/adaptive tests. |
| Hosted multi-tenant operation | Deferred | Complete tenant identity, RBAC, privacy, retention, and operational architecture first. |

## Explicitly rejected capabilities

- autonomous high-consequence remediation;
- LLM-only vulnerability applicability or asset identity decisions;
- direct model writes to authoritative facts, decisions, or actions;
- free-form AI SQL, query languages, joins, scripts, or dashboard code;
- prompt-only security controls;
- same-model consensus treated as verification;
- active production OT interrogation without validation and approval;
- vector-only authoritative state;
- bundling proprietary or restrictively licensed intelligence without an
  approved source decision;
- public claims that present synthetic or pure-engine results as production
  performance.

## Maintenance

Update this matrix when:

- an architecture decision changes;
- a capability is implemented, removed, or materially revised;
- a research claim is corrected or superseded;
- a source license or availability changes;
- a release gate is added;
- a missing research identifier is intentionally defined or retired.