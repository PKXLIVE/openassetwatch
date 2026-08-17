# ADR-0001: Research-Aligned Architecture Expansion

- **Status:** Accepted
- **Date:** 2026-07-31
- **Decision owner:** Project owner and OpenAssetWatch maintainers
- **Research baseline:** `docs/research/2026-07-independent-security-research/`
- **Integration assessment:** `docs/RESEARCH_INTEGRATION_AND_ARCHITECTURE_GAP_MATRIX.md`

## Context

Independent public-source research was completed without access to the
OpenAssetWatch repository and was then compared with the repository snapshot at
commit `76321ce56301c7846e060fe67793a108c6c3cde6`. The second-pass adversarial
audit found that the existing deterministic foundation is materially stronger
than the first-pass assessment suggested and should be extended rather than
replaced.

The implemented authority order remains:

```text
authenticated normalized evidence
  -> deterministic classification
  -> deterministic findings and attention scoring
  -> bounded read-only AI explanation
  -> human review
```

The research supports a broader product direction resembling enterprise asset
intelligence and exposure-management outcomes while preserving local-first,
passive-first, evidence-first, and human-supervised operation.

## Decision

OpenAssetWatch adopts **Research-Aligned Expansion** as its target architecture
direction.

This decision preserves the current deterministic substrate and adds new
capabilities in phases. It does not approve immediate implementation of every
research recommendation. Each workstream must satisfy its listed design,
licensing, evaluation, privacy, and safety gates before it becomes coding work.

### Non-negotiable invariants

1. AI output is never an authoritative asset identity, fact, finding, score,
   decision, suppression, or remediation action.
2. External text, feeds, hostnames, banners, logs, advisories, and tool metadata
   are untrusted data, never executable instructions.
3. OpenAssetWatch remains passive-first. Active IoT or OT interrogation is not
   permitted without deterministic policy gates, explicit approval, and
   device-specific validation.
4. Product-specific remediation guidance requires sufficiently confirmed
   product identity and version evidence.
5. Autonomous irreversible, safety-impacting, or physical-world remediation is
   prohibited.
6. Generated dashboards may use only approved metrics, dimensions, joins, and
   visual components. Free-form SQL, arbitrary code, and model-invented fields
   are prohibited.
7. Third-party advisory and fingerprint sources may not be bundled, cached, or
   redistributed until the Source Licensing Registry records an approved
   decision.
8. Synthetic, demo, and pure-engine benchmark results must remain clearly
   separated from production or live-model performance claims.

## Accepted project-owner decisions

### DR-01 — Meaning of the current 0–100 score

Retain the versioned deterministic engine. Define the scalar as an
**Operational Attention Score**, not a complete scientific measure of cyber
risk. Existing API and database names may remain temporarily for compatibility,
but future documentation and UI must explain the meaning accurately. Surface an
explicit uncertainty indicator so low or missing confidence cannot be mistaken
for safety.

### DR-02 — SSVC-style action bands

Adopt a transparent decision layer with user-facing bands such as:

- Monitor
- Plan
- Prioritize
- Act Now

The bands are separate from the Operational Attention Score and must be derived
from reviewed deterministic decision points, not model judgment.

### DR-03 — Separate decision dimensions

Present severity, known exploitation, exploit probability, exposure, asset
importance, confidence, urgency, and remediation value as distinct fields when
the required evidence exists. Do not fold future EPSS, KEV, SSVC, or
remediation-value inputs into the existing scalar.

### DR-04 — Asset merge, split, and probabilistic identity

Introduce reversible, human-reviewed merge and split before any automatic
probabilistic merge. Preserve all source records and history. Probabilistic
automation remains blocked until a labeled evaluation corpus demonstrates an
acceptable false-merge rate and calibrated confidence.

### DR-05 — Bitemporal evidence history

Adopt valid-time and transaction-time semantics for identity and classification
changes. Corrections must remain auditable and must trigger re-evaluation of
dependent vulnerability matches, findings, and scores.

### DR-05a — Source Licensing Registry gate

Require `docs/SOURCE_LICENSING_REGISTRY.md` to contain an approved source
decision before a third-party feed or fingerprint corpus is imported, bundled,
cached, redistributed, or used in a commercial offering.

### DR-06 — Vulnerability-source strategy

Use reviewed offline adapters and retain the local catalog as the runtime
boundary. Initial source priority is:

1. CISA KEV
2. OSV
3. GitHub Advisory Database
4. Vendor CSAF and PSIRT advisories
5. EUVD after its bulk-use and redistribution terms are re-verified

EPSS may be added as a separate probability field. No source becomes a sole
oracle, and missing enrichment remains unknown rather than safe.

### DR-07 — VEX, suppression, and risk acceptance

Add VEX as a separate applicability assertion workflow. VEX does not replace
finding suppression. A `not_affected` assertion must be scoped, justified,
provenance-traceable, reviewed, expiring or revalidated, and reversible when
new evidence conflicts with it. Formal risk acceptance requires a named
approver and expiration.

### DR-08 — IoT and OT active-query boundary

Keep passive-only behavior as the default. Any future safe-active capability
requires deterministic allowlists, explicit approval, bounded rate/session
controls, vendor and model validation, isolated testing, complete auditing, and
an immediate stop path. Identification must never issue write or control
operations.

### DR-09 — Open fingerprint corpus

Treat a signed, provenance-tracked, openly licensed fingerprint corpus as a
research program, not an implementation commitment. Governance, poisoning
resistance, privacy, moderation, licensing, correction, and retraction must be
designed first.

### DR-10 — Multi-agent coordinator authority

Any future multi-agent runtime uses a deterministic coordinator/control plane
for scope, evidence packaging, tool authorization, budgets, typed contracts,
fact-state transitions, conflict detection, and audit. Models may propose
analysis only within bounded specialist roles.

### DR-11 — Agent fact-write permissions

No model-backed agent may directly write validated facts, final decisions, or
actions. Agents may propose observations, hypotheses, findings, and
recommendations. Promotion requires a deterministic validator or an authorized
human decision.

### DR-12 — Human-approval tiers

Define consequence-based approval tiers before adding any action capability.
Read-only analysis may run within deterministic scope. Consequential,
irreversible, credential, isolation, OT, safety, or physical-world actions
require human approval, with OT and safety-impacting actions always requiring
qualified review.

### DR-13 — Adaptive-dashboard scope

Begin only with the crawl phase:

1. deterministic parameterized drilldowns;
2. an approved panel catalog;
3. AI selection and arrangement of approved panels.

Metric composition and declarative visualization generation require the
semantic layer, validator, query governor, authorization model, and evaluation
gates first.

### DR-14 — Temporary versus saved dashboards

Generated investigation workspaces are temporary by default. Saving requires
an explicit user action and an auditable record. AI may not silently replace or
modify primary dashboards.

### DR-15 — Semantic metrics ownership

The platform owns and versions the semantic metrics layer. Measures,
dimensions, allowed joins, sensitivity, freshness rules, cardinality limits,
and query costs are deterministic metadata. The model cannot invent them.

### DR-16 — Named release blockers

Treat these as hard release blockers for the relevant capability:

- cross-tenant data leakage;
- autonomous or unsafe remediation;
- direct AI writes to authoritative facts;
- unvalidated active OT behavior;
- unauthorized dashboard or field access.

Additional capability-specific blockers must be recorded in the future
Evaluation and Release-Gate Standard.

### DR-17 — Local-first versus hosted priority

Local-first and self-hosted operation remain the primary product posture.
Hosted and multi-tenant operation are optional, later work and require tenant
isolation, user identity, RBAC, retention, privacy, provider governance, and
operational maturity before release.

## Sequencing

### Phase 0 — Documentation and governance

- correct stale architecture documentation;
- maintain the research integration matrix;
- establish the Source Licensing Registry;
- define the Evaluation and Release-Gate Standard;
- document score meaning and uncertainty.

### Phase 1 — Deterministic intelligence expansion

- reviewed KEV adapter design and source-freshness controls;
- separate urgency and confidence presentation;
- SSVC-style deterministic action bands;
- VEX and risk-acceptance data model;
- bitemporal evidence design.

### Phase 2 — Identity and guided remediation

- reversible manual merge and split;
- mandatory downstream re-evaluation;
- structured recommendations, alternatives, rollback, stop conditions, and
  verification evidence;
- incident-response escalation when exploitation may already have occurred.

### Phase 3 — Agent and adaptive-workspace expansion

- typed specialist-agent contracts under the deterministic coordinator;
- per-agent scoped identities and approval tiers;
- semantic metrics layer and approved dashboard-panel catalog;
- temporary AI-composed investigation workspaces.

### Phase 4 — Advanced and research-blocked work

- calibrated probabilistic identity resolution;
- governed community fingerprint corpus;
- any safe-active IoT/OT capability;
- optional hosted multi-tenant operation.

## Consequences

### Positive

- Preserves proven deterministic and local-first strengths.
- Adds enterprise-grade outcomes without copying a proprietary implementation.
- Makes risk and remediation decisions more transparent.
- Creates a safe path toward agentic analysis and adaptive dashboards.
- Prevents licensing and benchmark claims from becoming afterthoughts.

### Costs and risks

- Adds schema, history, governance, evaluation, and UX complexity.
- Requires careful compatibility handling around the current risk API.
- Delays probabilistic identity and autonomous-looking features until evidence
  and safety gates exist.
- Requires ongoing source-license and standards maintenance.

## Rejected alternatives

- Replacing the deterministic foundation with an LLM-first architecture.
- Treating a vector database as the authoritative system of record.
- Unrestricted AI-generated SQL, queries, joins, scripts, or dashboard code.
- Autonomous high-consequence remediation.
- Active production OT probing without device-specific validation and approval.
- Bundling proprietary or restrictively licensed intelligence without an
  approved source decision.

## Implementation status

This ADR records architecture direction. It does not claim that the new
capabilities are implemented. Implementation status remains governed by the
canonical subsystem documents and the research integration matrix.