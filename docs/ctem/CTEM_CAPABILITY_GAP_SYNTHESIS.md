# CTEM Capability Gap Synthesis

**Status: Research synthesis.** This is not canonical architecture, an
architecture decision, or an implementation claim. Every capability here must
receive its own OpenAssetWatch design under ADR-0004 before implementation.

- **Reviewed:** 2026-11-24.
- **Repository baseline:** `origin/main` at `0eae54d`, refreshed at `980d7c3`
  when `CTEM-GAP-01` was implemented. Current coverage comes
  from [CTEM_REPOSITORY_KNOWLEDGE_MAP.md](CTEM_REPOSITORY_KNOWLEDGE_MAP.md).

This document evaluates continuous threat exposure management (CTEM)
capabilities against OpenAssetWatch. CTEM here means the general five-stage
loop: scoping, discovery, prioritization, validation, and mobilization. The
capabilities were identified by studying public exposure-management
architectures, standards, and research, and by reconciling them with
OpenAssetWatch's implementation and accepted design. Each is described as an
OpenAssetWatch capability or candidate gap. Nothing was copied from any
external source.

## Architectural position

Research identified several patterns that are common in exposure-management
systems but that conflict with OpenAssetWatch's direction. OpenAssetWatch keeps
its own model:

| Pattern seen in research | OpenAssetWatch position |
| --- | --- |
| Discovery and validation driven by active scanning, reconnaissance, and re-running detection checks | OpenAssetWatch stays passive-first (ADR-0001 invariant 3). Active validation remains an optional, bounded future capability under DR-08, never a default. |
| One finding status that mixes evidence state with work progress, such as "in progress" or "fix applied" | Evidence status (deterministic), work status (manual, implemented in #190), and governance overlays stay separate. |
| Asset risk as a single product of likelihood, exposure, criticality, and a control "reduction factor" | Decision dimensions stay separate (DR-03). The Operational Attention Score is one aid, not the decision. |
| Exposure as an editable asset attribute with an assumed default | Exposure is derived from dated evidence. Missing evidence is `unknown`. |
| Closing work in an external ticketing system triggers verification or closure | Ticket state may update work status only. A finding resolves only on fresh affirmative evidence. |
| Multi-tenant identity and access control built in from the start | Local-first; hosted multi-tenancy deferred (DR-17). |
| Advisory AI triage that never writes findings | Same boundary, already implemented in the read-only AI Advisor. |

## Capability classification

Classifications: **ALREADY PRESENT**, **PARTIALLY PRESENT**, **USEFUL GAP**,
**FUTURE INTEGRATION CANDIDATE**, and **NOT APPROPRIATE FOR OPENASSETWATCH**.

| CTEM stage | Capability | Classification | OpenAssetWatch position |
| --- | --- | --- | --- |
| Scoping | Site as the operational scope boundary | ALREADY PRESENT | `site_id` on all evidence, findings, and risk |
| Scoping | Verified external scope (owned domains, addresses) | USEFUL GAP | Designed (ADR-0002 AD-02); see [`CTEM-GAP-03`](#ctem-gap-03-evidence-derived-exposure-state-and-verified-scope) |
| Scoping | Rule-based asset groups and saved selections | USEFUL GAP | [`CTEM-GAP-11`](#ctem-gap-11-rule-based-asset-groups) |
| Scoping | Scoped review cycle with exclusions and success criteria | USEFUL GAP (low priority) | [`CTEM-GAP-14`](#ctem-gap-14-scoped-review-cycle) |
| Scoping | Asset importance and business-service context | PARTIALLY PRESENT | Asset-level audited importance implemented; business services deferred ([`CTEM-GAP-02`](#ctem-gap-02-asset-importance-and-business-service-context)) |
| Discovery | Typed asset inventory with source provenance | ALREADY PRESENT | Canonical ingestion, classification, evidence fusion |
| Discovery | Endpoint software inventory and version history | ALREADY PRESENT | Native software collection, component store |
| Discovery | Passive network discovery | ALREADY PRESENT | Passive sensor |
| Discovery | Identity resolution with reversible merge and split | PARTIALLY PRESENT | Conflicts become findings; merge and split designed (DR-04) |
| Discovery | Field-level source authority and asset change history | PARTIALLY PRESENT | Canonical asset authority exists; field ledger designed (PR #175, merged) |
| Discovery | Asset presence and freshness | PARTIALLY PRESENT | Staleness rules exist; presence ledger designed (PR #175, merged) |
| Discovery | Technology fingerprinting by active probes | NOT APPROPRIATE | Agent and passive evidence only |
| Discovery | Active external discovery (subdomain enumeration, port and web crawling) | NOT APPROPRIATE | Violates passive-first and the ADR-0002 no-probing invariant |
| Discovery | Certificate Transparency monitoring | PARTIALLY PRESENT | Designed as the first external capability (ADR-0002 AD-07) |
| Discovery | Cloud and container inventory | FUTURE INTEGRATION CANDIDATE | [`CTEM-INT-03`](#ctem-int-03-read-only-cloud-and-container-inventory) |
| Discovery | Application and web endpoint inventory | USEFUL GAP (later) | No prior work; needs a passive or agent evidence source |
| Discovery | Identity exposure (privileged and unused accounts) | USEFUL GAP (later) | Identity and privileged-account roadmaps exist |
| Discovery | Import of results from scanners the customer already runs | FUTURE INTEGRATION CANDIDATE | [`CTEM-INT-01`](#ctem-int-01-read-only-scanner-result-import) |
| Discovery | Scan orchestration (workflows, zones, windows, intensity) | NOT APPROPRIATE | A raw scanner platform is a product non-goal |
| Prioritization | Deterministic findings with evidence and deduplication | ALREADY PRESENT | Ten rules, dedupe keys, finding evidence |
| Prioritization | Vulnerability matching against a signed offline catalog | ALREADY PRESENT | Signed advisory bundles, offline mirror |
| Prioritization | Known-exploited status | ALREADY PRESENT | KEV prioritization |
| Prioritization | Exploit-likelihood context | USEFUL GAP | [`CTEM-GAP-08`](#ctem-gap-08-exploit-likelihood-context) |
| Prioritization | Action bands with reason codes, explanations, recompute on input change | ALREADY PRESENT (v1) | [`CTEM-GAP-01`](#ctem-gap-01-deterministic-decision-layer), implemented |
| Prioritization | Evidence-derived exposure state | USEFUL GAP | [`CTEM-GAP-03`](#ctem-gap-03-evidence-derived-exposure-state-and-verified-scope) |
| Prioritization | Scoped compensating-control assessment | USEFUL GAP | [`CTEM-GAP-07`](#ctem-gap-07-scoped-compensating-control-assessment) |
| Prioritization | Relationship and path hints | USEFUL GAP (deferred) | [`CTEM-GAP-13`](#ctem-gap-13-freshness-gated-relationship-and-path-hints) |
| Prioritization | Single multiplied risk score; external-posture letter grade | NOT APPROPRIATE | Hides separate dimensions (DR-03) |
| Prioritization | Temporal baselines and deviations | ALREADY PRESENT | Context only, never authority |
| Validation | Resolution only on fresh affirmative evidence | ALREADY PRESENT | Deterministic reconciliation |
| Validation | Per-finding verification guidance and recorded proof | ALREADY PRESENT | [`CTEM-GAP-06`](#ctem-gap-06-remediation-verification-records), implemented |
| Validation | Coverage-aware closure (partial or failed collection never clears a finding) | PARTIALLY PRESENT | Freshness gating exists; coverage states designed (PR #175) and proposed (PR #189); both on `main` |
| Validation | Active retest by re-running detection checks | NOT APPROPRIATE (default) | `CTEM-GAP-06` verifies passively |
| Validation | Attack simulation and penetration-test management | NOT APPROPRIATE | Offensive testing is out of scope |
| Mobilization | Manual work tracking with unverified owner labels | ALREADY PRESENT | Implemented in #190 |
| Mobilization | Grouping findings by a shared treatment | USEFUL GAP | [`CTEM-GAP-05`](#ctem-gap-05-grouping-findings-by-a-shared-treatment) |
| Mobilization | Target dates derived from priority | USEFUL GAP (deferred) | [`CTEM-GAP-12`](#ctem-gap-12-target-dates-derived-from-action-bands) |
| Mobilization | Exception governance: accepted risk, false positives, applicability statements | USEFUL GAP | [`CTEM-GAP-04`](#ctem-gap-04-exception-governance) |
| Mobilization | Verified ownership from directory or asset-management sources | PARTIALLY PRESENT | Designed in the identity and ITSM roadmaps |
| Mobilization | Personal work queue | PARTIALLY PRESENT | Work items filter by owner label; a queue view is a small follow-up |
| Mobilization | Outbound projection to external ticketing systems | FUTURE INTEGRATION CANDIDATE | [`CTEM-INT-02`](#ctem-int-02-outbound-ticket-projection) |
| Mobilization | Event automation and notifications | FUTURE INTEGRATION CANDIDATE (later) | Requires approval tiers (DR-12) |
| Mobilization | Multi-team remediation campaign management | NOT APPROPRIATE (now) | Revisit after `CTEM-GAP-05` |
| Cross-cutting | Outcome metrics with explicit units and "not measured" | ALREADY PRESENT | [`CTEM-GAP-09`](#ctem-gap-09-outcome-metrics), implemented |
| Cross-cutting | Tamper-evident governance history | USEFUL GAP | [`CTEM-GAP-10`](#ctem-gap-10-tamper-evident-governance-history) |
| Cross-cutting | Detection and indicator context | FUTURE INTEGRATION CANDIDATE | [`CTEM-INT-04`](#ctem-int-04-read-only-detection-and-indicator-context) |
| Cross-cutting | Exchange with other exposure-management systems | FUTURE INTEGRATION CANDIDATE | [`CTEM-INT-05`](#ctem-int-05-optional-exchange-with-external-exposure-systems) |
| Cross-cutting | Read-only AI triage that never writes | ALREADY PRESENT | Read-only AI Advisor |
| Cross-cutting | Model Context Protocol server with authorization | PARTIALLY PRESENT | `cmd/oaw-mcp-stdio` is a stub; direction documented |
| Cross-cutting | Versioned rule and content packs | PARTIALLY PRESENT | Skill Pack contract designed; fingerprint rule packs designed (PR #175, merged) |
| Cross-cutting | Signed releases, SBOM, build provenance | ALREADY PRESENT | Release trust controls |
| Cross-cutting | Multi-tenancy, row-level isolation, enterprise sign-on | NOT APPROPRIATE (now) | Deferred by DR-17 |
| Cross-cutting | Leaked-credential monitoring | NOT APPROPRIATE | Conflicts with ADR-0002 minimal retention |
| Cross-cutting | Source-code, dependency, and secret scanning; CI gates | NOT APPROPRIATE | Application-security scope, not asset-first |
| Cross-cutting | Bug-bounty program management | NOT APPROPRIATE | Outside product scope |

## Useful gaps

Ordered by recommended sequence. Each entry notes the kind of source behind the
recommendation: **REPOSITORY IMPLEMENTATION**, **REPOSITORY DESIGN /
RESEARCH**, **EXTERNAL RESEARCH** (generalized; sources are not recorded), and
**NEW ARCHITECTURAL INFERENCE**.

### CTEM-GAP-01: Deterministic decision layer

- **Status:** IMPLEMENTED (v1). See [CTEM_DECISION_LAYER.md](CTEM_DECISION_LAYER.md).
  v1 cannot produce Act Now until exposure or asset importance exists; the
  refreshed order is in [CTEM_IMPLEMENTATION_ROADMAP.md](CTEM_IMPLEMENTATION_ROADMAP.md).
- **Provenance:** REPOSITORY DESIGN / RESEARCH (ADR-0001 DR-01 to DR-03;
  `EXPLAINABLE_RISK_DECISION_MODEL.md`), corroborated by EXTERNAL RESEARCH.
  Research found a recurring failure: a well-computed priority that operators
  cannot sort by, filter on, or read the reasons for.
- **Outcome:** each finding carries a deterministic action band (Monitor,
  Plan, Prioritize, Act Now) with reason codes and an explanation. The band is
  recomputed when an input changes (a known-exploited listing, a new asset
  importance, a changed exposure state). Lists sort by band by default.
- **Existing equivalent:** the Operational Attention Score exists. The
  `oaw.decision.v1` record is designed but not implemented.
- **Build or integrate:** build. This is core authority and must stay native.
- **Evidence:** severity, known-exploited status, confidence, and freshness
  (all present); exposure, importance, and exploit likelihood when available,
  otherwise `unknown`.
- **Fit:** extends `risk.py` and the finding store without changing the
  existing score. Bands are a separate field (DR-02).
- **Security:** deterministic and versioned; AI may explain but never set a
  band. Reason codes cite evidence IDs.
- **Local-first:** fully local.
- **Passive-first:** consumes existing evidence only.
- **Complexity:** medium. The decision model already specifies the contract,
  persistence, recomputation, API, and tests.

### CTEM-GAP-02: Asset importance and business-service context

- **Provenance:** REPOSITORY DESIGN / RESEARCH (decision model: asset
  importance; `itsm-cmdb-enrichment-roadmap.md`) and EXTERNAL RESEARCH
  (importance raised by business context; governance over lowering it).
- **Outcome:** an audited importance value per asset (`critical`, `high`,
  `standard`, `low`, `unknown`). Assets can optionally be grouped into business
  services that may raise, but never lower, an asset's effective importance.
  Lowering importance on an asset with open findings should require a second
  person.
- **Existing equivalent:** asset-level audited importance is implemented
  ([CTEM_ASSET_IMPORTANCE.md](CTEM_ASSET_IMPORTANCE.md)). Lowering is recorded
  as security-sensitive, but second-person review is not enforceable until
  per-user identity exists. Business services are not implemented.
- **Build or integrate:** build the native assignment. Imported
  asset-management data may later supply suggestions.
- **Evidence:** operator assignment (authoritative); imported values and
  role-based defaults (suggestions until reviewed).
- **Fit:** an input to `CTEM-GAP-01`.
- **Security:** downgrading importance can hide risk, so it needs separation
  of duties and an audit trail.
- **Local-first:** local.
- **Passive-first:** no collection impact.
- **Complexity:** low to medium. Propagation through dependency edges waits
  for the relationship ledger (PR #175).

### CTEM-GAP-03: Evidence-derived exposure state and verified scope

- **Provenance:** REPOSITORY DESIGN / RESEARCH (decision model: exposure
  state; ADR-0002 AD-02; PR #189) and EXTERNAL RESEARCH. Research showed that
  exposure set as an editable asset attribute with an assumed default can be
  wrong without anyone noticing.
- **Outcome:** each finding explains its exposure state (`internet-reachable`,
  `internally-reachable`, `segmented`, `unknown`, and so on) from dated
  evidence. Recurring external enrichment runs only against registered,
  verified scope.
- **Existing equivalent:** the vocabulary is designed; all findings are
  currently `unknown`.
- **Build or integrate:** build the derivation and the scope registry.
  Certificate Transparency evidence comes first (ADR-0002 AD-07).
- **Evidence:** passive service observations, configuration evidence, and
  reviewed external observations. A listening port alone never proves Internet
  exposure.
- **Fit:** feeds `CTEM-GAP-01` and keeps the ADR-0002 observation lifecycle.
- **Security:** scope verification prevents enriching assets the operator does
  not own. `not-reachable` cannot be asserted without evidence.
- **Local-first:** derivation is local; external enrichment stays optional.
- **Passive-first:** read-only public records only.
- **Complexity:** medium to high.

### CTEM-GAP-04: Exception governance

- **Provenance:** REPOSITORY DESIGN / RESEARCH (ADR-0001 DR-07; PR #175
  exception ledger; decision model: risk acceptance) and EXTERNAL RESEARCH
  (requester and approver separation, a preview of affected findings before
  approval, a maximum expiry).
- **Outcome:** accepted risk, false-positive assertions, and applicability
  (VEX) statements become separate, scoped, expiring records. Each has a
  requester, a different approver, a preview of the findings it affects, and
  re-evaluation at expiry. Suppression keeps its current meaning.
- **Existing equivalent:** single-finding suppression with optional expiry.
- **Build or integrate:** build; this is governance authority.
- **Evidence:** a justification code, scope, and evidence IDs; for
  applicability statements, issuer, signature, and status.
- **Fit:** an overlay that never rewrites evidence. Follows the append-only
  event pattern of `finding_work_events`.
- **Security:** high. Exceptions are the main way to hide real risk. Genuine
  two-person approval **depends on per-user identity**, which OpenAssetWatch
  does not have yet (DR-17). Until then, approvers can only be recorded as
  unverified labels.
- **Local-first:** local.
- **Passive-first:** no impact.
- **Complexity:** medium; real separation of duties is blocked on identity.

### CTEM-GAP-05: Grouping findings by a shared treatment

- **Provenance:** EXTERNAL RESEARCH, built on REPOSITORY IMPLEMENTATION
  (vulnerability matching already knows fixed-version availability; work items
  exist).
- **Outcome:** OpenAssetWatch should support grouping related findings by a
  shared treatment that can reduce multiple exposures. For example, "upgrade
  component C on asset A to version V or later" could close several
  vulnerability findings at once. The group shows how many findings and how
  much attention score the treatment covers, and can carry one work item.
- **Existing equivalent:** per-finding work items only.
- **Build or integrate:** build.
- **Evidence:** component identity, installed version, and fixed version from
  reviewed advisories. Groups are computed, never asserted.
- **Fit:** a computed view over findings plus an optional group-level work
  item. Each member finding still resolves only on its own evidence.
- **Security:** marking a group done must not resolve members.
- **Local-first:** local.
- **Passive-first:** no impact.
- **Complexity:** low to medium.

### CTEM-GAP-06: Remediation verification records

- **Provenance:** REPOSITORY DESIGN / RESEARCH (PR #189: remediation
  verification; REM-VERIFY-001 in the gap matrix) and EXTERNAL RESEARCH
  (explicit, server-decided verification guidance per finding).
- **Outcome:** each finding or exposure states how it can be verified (for
  example, a later agent inventory showing a version at or above V, or a
  passive observation no longer showing a service). It also shows the
  comparable before-and-after evidence once available. Completed work with no
  verification is visibly unverified.
- **Existing equivalent:** implemented
  ([CTEM_REMEDIATION_VERIFICATION.md](CTEM_REMEDIATION_VERIFICATION.md)):
  per-rule guidance, baselines captured when work is marked done, a
  deterministic verification state, a "done but unverified" view, and
  append-only transition history. Resolution still comes only from the
  deterministic finding lifecycle.
- **Build or integrate:** build.
- **Evidence:** the evidence source that produced the finding, at a later
  time, from a healthy, complete collection.
- **Fit:** a read model joining work status with evidence status. No new
  state machine.
- **Security:** "not observed" from a failed or partial collection is never
  proof (PR #189: freshness and incomplete collection).
- **Local-first:** local.
- **Passive-first:** yes. Verification waits for the next agent or sensor
  evidence instead of an active retest.
- **Complexity:** medium.

### CTEM-GAP-07: Scoped compensating-control assessment

- **Provenance:** REPOSITORY DESIGN / RESEARCH (PR #189: mitigating controls)
  and EXTERNAL RESEARCH. Research showed a failure pattern to avoid: a control
  record with a numeric reduction factor that lowers an asset-wide score.
- **Outcome:** an assessment ties one control to one vulnerability, subject,
  and path. It records mechanism, enforcement mode, scope, evidence time,
  expiry, and invalidating conditions, and keeps "present", "inferred
  mitigation", and "observed prevention" distinct.
- **Existing equivalent:** none.
- **Build or integrate:** build the assessment. Control evidence may arrive
  later through connectors.
- **Evidence:** control configuration, policy version, relevant telemetry. An
  asset-level "control installed" signal is insufficient.
- **Fit:** a separate decision dimension for `CTEM-GAP-01`, never a score
  multiplier (DR-03).
- **Security:** a mis-scoped control hides exposure; expiry and revalidation
  are required.
- **Local-first:** local.
- **Passive-first:** yes; no empirical testing.
- **Complexity:** high. Sequence after `CTEM-GAP-01` and `CTEM-GAP-03`.

### CTEM-GAP-08: Exploit-likelihood context

- **Provenance:** REPOSITORY DESIGN / RESEARCH (ADR-0001 DR-03, DR-06; July
  research `EXT-RES-004`) and EXTERNAL RESEARCH (exploit likelihood used as one
  input among several).
- **Outcome:** an exploit-probability field on vulnerability matches (EPSS),
  with the date it was observed, shown separately from severity and
  known-exploited status.
- **Existing equivalent:** none.
- **Build or integrate:** a reviewed offline adapter, like the known-exploited
  adapter.
- **Evidence:** the published dataset, after a Source Licensing Registry
  decision.
- **Fit:** a separate field and an input to `CTEM-GAP-01`. Never folded into
  the attention score.
- **Security:** integrity through the signed advisory pipeline.
- **Local-first:** offline bundle.
- **Passive-first:** no impact.
- **Complexity:** low, once the source is approved.

### CTEM-GAP-09: Outcome metrics

- **Provenance:** REPOSITORY DESIGN / RESEARCH (DR-15 semantic metrics; PR
  #189 explicit count units) and EXTERNAL RESEARCH (metrics that report "not
  measured" rather than zero). REPOSITORY IMPLEMENTATION makes this newly
  possible: since #190, work events give dated status changes.
- **Outcome:** time from first detection to verified resolution, backlog age
  by action band, the share of done work that was verified, and collection
  coverage. Each metric states its unit and population, and shows "not
  measured" instead of 0.
- **Existing equivalent:** fixed dashboard counts only.
- **Build or integrate:** build, as deterministic metric definitions.
- **Evidence:** finding lifecycle timestamps, work events, verification
  records.
- **Fit:** the first entries of the platform-owned semantic metrics layer.
- **Security:** inherits site scope; no free-form queries.
- **Local-first:** local.
- **Passive-first:** no impact.
- **Complexity:** low to medium.

### CTEM-GAP-10: Tamper-evident governance history

- **Provenance:** EXTERNAL RESEARCH (hash-chained audit with a verification
  check) and REPOSITORY DESIGN / RESEARCH (PR #189 audit boundaries; PR #175
  lineage separation). Applying it to work and exception events is NEW
  ARCHITECTURAL INFERENCE.
- **Outcome:** each append-only governance event (work, exception, decision)
  carries a hash of its predecessor, and a verification read reports the first
  break.
- **Existing equivalent:** `finding_work_events` is append-only by database
  trigger, but not chained.
- **Build or integrate:** build.
- **Evidence:** the events themselves.
- **Fit:** an additive column and verifier that extend the work-tracking
  trigger pattern.
- **Security:** detects tampering after the fact; it cannot stop a database
  owner from rewriting history. Anchoring (signed checkpoints or an external
  copy) needs design.
- **Local-first:** local.
- **Passive-first:** no impact.
- **Complexity:** low for the chain, medium for anchoring.

### CTEM-GAP-11: Rule-based asset groups

- **Provenance:** EXTERNAL RESEARCH and NEW ARCHITECTURAL INFERENCE.
- **Outcome:** saved, named selections of assets defined by deterministic
  rules over approved fields (category, site, component, importance) or by
  explicit lists. They can filter lists, metrics, and review cycles.
- **Existing equivalent:** sites only.
- **Build or integrate:** build. Rules use the safe query grammar designed in
  PR #175 (merged), never free-form queries.
- **Evidence:** asset fields already stored.
- **Fit:** a read-side construct; groups never grant authority or change
  findings.
- **Security:** bounded evaluation that respects site scope.
- **Local-first:** local.
- **Passive-first:** no impact.
- **Complexity:** low to medium.

### CTEM-GAP-12: Target dates derived from action bands

- **Provenance:** EXTERNAL RESEARCH (deadlines derived from priority, tightened
  for known-exploited issues) and REPOSITORY DESIGN / RESEARCH (PR #189 target
  date; case `sla_due_at`).
- **Outcome:** an optional target date on a work item, derived
  deterministically from the action band and tightened for known-exploited
  findings. It can be shortened, never silently extended.
- **Existing equivalent:** none; work tracking v1 deliberately excluded dates.
- **Build or integrate:** build after `CTEM-GAP-01`.
- **Evidence:** action band and known-exploited status.
- **Fit:** extends work items with no effect on findings or risk.
- **Security:** extending a date is audited like an exception.
- **Local-first:** local.
- **Passive-first:** no impact.
- **Complexity:** low, once action bands exist. Notifications are separate
  (DR-12).

### CTEM-GAP-13: Freshness-gated relationship and path hints

- **Provenance:** REPOSITORY DESIGN / RESEARCH (July research: freshness-gated
  path hints; PR #175 relationship ledger; ADR-0002 AD-05) and EXTERNAL
  RESEARCH (path graphs with choke points).
- **Outcome:** an explanation of how an exposed asset might reach an important
  one, built only from dated, scoped relationships and labelled as a hint.
- **Existing equivalent:** none.
- **Build or integrate:** build later; the relationship ledger comes first.
- **Evidence:** relationship records with source, time, and confidence. Stale
  edges are excluded, never assumed.
- **Fit:** a projection, never authority.
- **Security:** stale graphs create false paths and hide real ones. Hints must
  not change bands without a reviewed rule.
- **Local-first:** local.
- **Passive-first:** yes.
- **Complexity:** high; research-gated.

### CTEM-GAP-14: Scoped review cycle

- **Provenance:** EXTERNAL RESEARCH and NEW ARCHITECTURAL INFERENCE.
- **Outcome:** an optional, dated review record that names an asset group, its
  exclusions with reasons, measurable goals drawn from `CTEM-GAP-09`, and the
  result at close.
- **Existing equivalent:** none.
- **Build or integrate:** build, lightweight. For home and SMB users this may
  be a report rather than a workflow.
- **Evidence:** metric snapshots.
- **Fit:** composes `CTEM-GAP-09` and `CTEM-GAP-11` with no new authority.
- **Security:** low risk.
- **Local-first:** local.
- **Passive-first:** no impact.
- **Complexity:** low, but valuable only after `CTEM-GAP-09` and
  `CTEM-GAP-11`.

## Future integration candidates

Each must use the capability/provider contract, treat incoming data as
untrusted, provenance-tagged evidence, fail without breaking core behavior, and
pass a Source Licensing Registry decision.

### CTEM-INT-01: Read-only scanner result import

- **Provenance:** REPOSITORY DESIGN / RESEARCH
  (`vulnerability-scanner-enrichment-roadmap.md`) and EXTERNAL RESEARCH.
- Import results that the customer's existing scanners already produced, in
  standard interchange formats, as candidate evidence. OpenAssetWatch never
  launches a scan. Imported assertions stay candidates until deterministic
  matching agrees (ADR-0002 AD-06).

### CTEM-INT-02: Outbound ticket projection

- **Provenance:** REPOSITORY DESIGN / RESEARCH
  (`connector-playbook-projection-architecture.md`) and EXTERNAL RESEARCH.
- Project a work item to an external ticketing system and store the reference
  in `finding_work_references`. Inbound ticket state may update **work status**
  only, never finding status. Verification waits for the next evidence
  (`CTEM-GAP-06`).

### CTEM-INT-03: Read-only cloud and container inventory

- **Provenance:** REPOSITORY DESIGN / RESEARCH
  (`smb-asset-intelligence-product-direction.md`; spokes in
  `PRODUCT_ARCHITECTURE.md`) and EXTERNAL RESEARCH.
- Read-only inventory connectors for cloud providers and container
  orchestrators, run as spokes with customer-held credentials and no write
  scopes.

### CTEM-INT-04: Read-only detection and indicator context

- **Provenance:** REPOSITORY DESIGN / RESEARCH
  (`security-operations-detection-case-intelligence.md`) and EXTERNAL
  RESEARCH.
- Detection events and indicators may create investigation candidates or
  prompts to review a resolved finding. They never directly reopen or create
  authoritative findings without a deterministic rule.

### CTEM-INT-05: Optional exchange with external exposure systems

- **Provenance:** NEW ARCHITECTURAL INFERENCE.
- Organizations that also run another exposure-management system could export
  OpenAssetWatch assets and findings over an API, or import that system's
  findings as candidates through `CTEM-INT-01`. The exchange stays optional and
  needs provider and licensing review.

## Not appropriate for OpenAssetWatch

| Capability | Reason |
| --- | --- |
| Scan orchestration, scanner-running sensors, active external discovery | Violates passive-first (ADR-0001 invariant 3) and the raw-scanner non-goal |
| Active retest by re-running detection checks | Active probing; `CTEM-GAP-06` verifies passively |
| Attack simulation; penetration-test management | Offensive testing is out of scope |
| Leaked-credential monitoring | Conflicts with ADR-0002 minimal retention |
| Source-code, dependency, and secret scanning; CI gates | Application-security tooling, not asset-first |
| Bug-bounty program management | Outside product scope |
| A finding status that mixes evidence and work | Deliberately separated (#190) |
| A multiplied risk score with a control reduction factor; a letter grade | Hides separate dimensions (DR-03) |
| Multi-tenancy, row-level isolation, enterprise sign-on now | Deferred by DR-17 |

## Recommended sequence

This was the order before the decision layer was implemented. It is
superseded by [CTEM_IMPLEMENTATION_ROADMAP.md](CTEM_IMPLEMENTATION_ROADMAP.md).

1. `CTEM-GAP-01` decision layer, with `CTEM-GAP-08` once its source is
   approved.
2. `CTEM-GAP-02` asset importance and `CTEM-GAP-05` treatment grouping.
3. `CTEM-GAP-06` verification records and `CTEM-GAP-09` outcome metrics.
4. `CTEM-GAP-03` scope registry and Certificate Transparency evidence.
5. `CTEM-GAP-04` exception governance once per-user identity exists;
   `CTEM-GAP-10` can land earlier.
6. `CTEM-GAP-11`, `CTEM-GAP-12`, then `CTEM-GAP-14`.
7. `CTEM-GAP-07` and `CTEM-GAP-13`, which are research-gated.

Each step needs its own OpenAssetWatch design before implementation, and every
adopted capability must remain additive to the existing evidence, finding,
risk, and AI boundaries.

## Limits

- External research was generalized. Its sources are deliberately not
  recorded in the repository.
- Capabilities observed in external systems were not verified by running
  them; they are treated as ideas, not as evidence of effectiveness.
