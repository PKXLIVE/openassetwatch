# Security Operations, Detection, and Case Intelligence Architecture

## Purpose

This document defines a future, provider-neutral architecture for turning OpenAssetWatch observations into normalized alerts, correlated cases, replayable investigations, governed detection content, and evidence-backed response recommendations.

The design fills long-term security-operations gaps without changing the current implementation scope. OpenAssetWatch remains passive-first, advisory-first, evidence-first, and read-only by default. This document does not authorize autonomous containment, exploitation, command execution, or unrestricted active scanning.

The concepts in this document are independently expressed OpenAssetWatch requirements. They do not reproduce a third-party product architecture, diagram, workflow, naming system, or implementation.

## Decision Summary

OpenAssetWatch should eventually support a controlled security-operations layer built around these principles:

1. Normalize heterogeneous observations before correlation.
2. Preserve raw source data separately from canonical records.
3. Correlate repeated or related alerts into smaller, explainable cases.
4. Keep an append-only investigation ledger that can be replayed.
5. Separate analyst assessments from AI-generated assessments.
6. Make deterministic findings and evidence the source of truth.
7. Treat AI as an optional explanation and prioritization layer.
8. Manage detections through proposal, evaluation, approval, promotion, and rollback.
9. Validate tuning changes against reproducible datasets before promotion.
10. Keep external tickets, notifications, and dashboards as projections of canonical state.
11. Preserve safe operation when AI, an integration, or an enrichment source is unavailable.
12. Require explicit approval and verification before any future action-capable workflow.

---

## 1. Position in the OpenAssetWatch Architecture

```text
Collectors, Sensors, Imports, and Enrichment Sources
                        |
                        v
               Ingestion and Validation
                        |
                        v
               Canonical Event Envelope
                        |
                        +------------------------------+
                        |                              |
                        v                              v
              Observable Extraction          Raw Source Archive
                        |
                        v
              Normalization and Deduplication
                        |
                        v
              Correlation and Case Building
                        |
                        v
             Finding Intelligence Pipeline
                        |
                        +------------------------------+
                        |                              |
                        v                              v
             Investigation Workspace          Exposure Path Analysis
                        |                              |
                        +---------------+--------------+
                                        |
                                        v
                         Reports and Recommendations
                                        |
                         +--------------+--------------+
                         |                             |
                         v                             v
                Internal Control Tower        External Projections

Cross-cutting controls:
- tenant isolation
- authorization
- evidence provenance
- data classification
- audit and monitoring
- retention and deletion
- AI policy and routing
- integration trust review
- safe output publishing
```

The security-operations layer should consume normalized OpenAssetWatch evidence. It should not replace collectors, passive discovery, evidence storage, deterministic risk rules, or the AI Tool Gateway.

---

## 2. Canonical Data Model

### 2.1 Source Event Envelope

Every imported event should first be wrapped in a source-neutral envelope.

Suggested fields:

- `event_id`
- `tenant_id`
- `source_id`
- `source_type`
- `source_event_id`
- `source_sequence`
- `received_at`
- `observed_at`
- `event_type`
- `schema_version`
- `content_hash`
- `idempotency_key`
- `data_classification`
- `payload_reference`
- `normalization_status`
- `validation_errors`

Example:

```json
{
  "event_id": "evt-01J...",
  "tenant_id": "tenant-home-lab",
  "source_id": "collector-01",
  "source_type": "collector",
  "source_event_id": "submission-8841",
  "source_sequence": 8841,
  "received_at": "2026-07-24T18:02:01Z",
  "observed_at": "2026-07-24T18:01:42Z",
  "event_type": "network_observation",
  "schema_version": "1.0",
  "content_hash": "sha256:...",
  "idempotency_key": "collector-01:submission-8841",
  "data_classification": "internal",
  "payload_reference": "raw-events/evt-01J...",
  "normalization_status": "pending",
  "validation_errors": []
}
```

### 2.2 Canonical Alert

A canonical alert represents a condition requiring review. It may originate from a deterministic rule, imported scanner result, policy violation, collector health condition, or approved enrichment source.

Suggested fields:

- `alert_id`
- `tenant_id`
- `title`
- `summary`
- `category`
- `severity`
- `confidence`
- `status`
- `source_type`
- `source_record_ids`
- `rule_id`
- `rule_version`
- `asset_ids`
- `observable_ids`
- `evidence_refs`
- `first_seen`
- `last_seen`
- `occurrence_count`
- `deduplication_key`
- `correlation_key`
- `data_classification`
- `raw_extension_reference`

Source-specific fields that do not map cleanly into the canonical schema should remain in a separate extension object or raw source record. They should not be forced into misleading canonical fields.

### 2.3 Observable

An observable is a normalized entity extracted from evidence.

Suggested types:

- asset identifier
- hostname
- domain
- IP address
- hardware address
- URL
- service
- port and protocol
- process or software name
- package and version
- account or identity reference
- certificate fingerprint
- file hash
- cloud resource identifier
- network segment
- security control
- vulnerability identifier

Suggested fields:

- `observable_id`
- `tenant_id`
- `type`
- `normalized_value`
- `display_value`
- `role`
- `first_seen`
- `last_seen`
- `source_refs`
- `asset_refs`
- `confidence`
- `sensitivity`
- `normalization_version`

The `role` field should describe how the observable participates in the alert, for example `source`, `destination`, `affected`, `owner`, `control`, `dependency`, or `external_exposure`.

### 2.4 Case

A case groups related alerts, assets, evidence, and investigation activity.

Suggested fields:

- `case_id`
- `tenant_id`
- `case_key`
- `title`
- `summary`
- `status`
- `verdict`
- `severity`
- `priority`
- `confidence`
- `owner_id`
- `team_id`
- `queue_id`
- `sla_due_at`
- `snoozed_until`
- `first_seen`
- `last_seen`
- `created_at`
- `updated_at`
- `alert_ids`
- `asset_ids`
- `observable_ids`
- `finding_ids`
- `exposure_path_ids`
- `evidence_refs`
- `analyst_assessment`
- `ai_assessment`
- `resolution_summary`
- `external_projection_refs`

Suggested statuses:

- `new`
- `triage`
- `investigating`
- `waiting_for_evidence`
- `waiting_for_approval`
- `snoozed`
- `resolved`
- `closed`

Suggested verdicts:

- `confirmed_risk`
- `expected_activity`
- `false_positive`
- `insufficient_data`
- `duplicate`
- `externally_managed`
- `accepted_risk`
- `not_applicable`

A closed case should not require a model-generated verdict. Analyst assessment and deterministic evidence remain authoritative.

---

## 3. Ingestion and Source Adapters

### 3.1 Adapter Contract

Each adapter should declare:

- adapter identifier and version
- supported source types
- authentication method
- supported event schemas
- polling or push behavior
- ordering guarantees
- replay support
- pagination behavior
- rate limits
- health-check method
- data classifications handled
- tenant-scoping behavior
- supported write-back actions
- required approvals

Adapters should be capability-driven rather than hard-coded into investigation workflows.

### 3.2 Ingestion Requirements

The ingestion layer should provide:

- schema validation
- idempotency
- duplicate suppression
- source ordering where available
- retry with bounded backoff
- dead-letter handling
- replay from a checkpoint
- maximum payload size
- decompression limits
- rate limiting
- tenant validation
- content hashing
- safe raw-record retention
- source health and lag metrics

### 3.3 Webhook Security

Inbound webhooks should use:

- per-integration credentials
- message authentication or signatures where supported
- timestamp and replay-window checks
- idempotency keys
- request-size limits
- source IP restrictions where practical
- rate limits
- tenant-bound routing
- redacted audit records

Public webhook tokens must not grant broader API access.

### 3.4 Source-of-Truth Rule

OpenAssetWatch should remain authoritative for its own cases, findings, evidence, and investigation state.

External ticket, chat, or notification systems should be treated as projections:

```text
Canonical OpenAssetWatch State
             |
             v
        Outbox Event
             |
             v
   External Projection Adapter
             |
             v
 Ticket, Message, or Notification
```

Outbound delivery failure must not roll back the canonical OpenAssetWatch write. Inbound status updates should be authenticated, idempotent, and restricted to explicitly allowed fields.

---

## 4. Normalization, Deduplication, and Correlation

### 4.1 Normalization

Normalization should be deterministic and versioned. It may include:

- timestamp normalization
- hostname and domain canonicalization
- IP and network normalization
- software and package name normalization
- vulnerability identifier mapping
- severity normalization
- asset resolution
- identity resolution
- observable extraction
- data classification
- source confidence mapping

### 4.2 Deduplication

Deduplication should prevent repeated source events from inflating risk.

Possible inputs include:

- source event identifier
- content hash
- tenant
- asset
- rule
- normalized condition
- time window
- observable set
- source-specific repeat count

Deduplication must preserve occurrence counts, first seen, last seen, and source provenance.

### 4.3 Correlation

Correlation should group related alerts without hiding evidence.

Potential correlation signals:

- common asset or identity
- common vulnerability or exposed service
- shared network segment
- overlapping observables
- temporal proximity
- repeated communication pattern
- shared root cause
- shared external exposure
- same missing security control
- same software package or version
- existing exposure path

The primary correlation path should be deterministic and explainable. AI may propose additional relationships, but proposed relationships must be labeled as inferred and cannot silently merge canonical records.

### 4.4 Correlation Result

```json
{
  "correlation_id": "corr-123",
  "tenant_id": "tenant-1",
  "member_alert_ids": ["alert-1", "alert-2"],
  "correlation_type": "shared_asset_and_condition",
  "confidence": 0.93,
  "deterministic": true,
  "rule_version": "2.1",
  "evidence_refs": ["evidence-7", "evidence-9"],
  "explanation": "Both alerts identify the same service and software version on the same asset within the configured correlation window."
}
```

### 4.5 Alert Flood Reduction

The correlation layer should reduce noise while preserving visibility:

- repeated alerts become one case with an occurrence trend
- mutually corroborating sources increase confidence rather than count
- conflicting sources create an explicit conflict record
- stale alerts are not silently mixed with current evidence
- deduplication does not delete the original source record
- case reopening follows deterministic rules

---

## 5. Finding Intelligence Pipeline

The canonical processing sequence should be:

```text
Normalized Alert or Observation
            |
            v
    Deterministic Rule Evaluation
            |
            v
       Canonical Finding
            |
            v
      Ownership Resolution
            |
            v
      Confidence Calculation
            |
            v
       Evidence Selection
            |
            v
        Finding Fusion
            |
            v
    Exposure Path Correlation
            |
            v
 AI Explanation and Prioritization
```

AI should not be responsible for the authoritative detection, deduplication, ownership, confidence baseline, or canonical finding state.

### 5.1 Ownership Resolution

Ownership may be derived from:

- collector enrollment
- manually assigned owner
- identity enrichment
- network segment ownership
- business service mapping
- management-tool metadata
- asset tags
- source system ownership

Conflicting ownership should be represented explicitly rather than overwritten.

### 5.2 Confidence

Confidence should consider:

- direct versus inferred evidence
- source reliability
- source diversity
- freshness
- deterministic rule quality
- corroboration
- contradiction
- asset identity confidence
- reachability confidence

Model confidence must never replace evidence confidence.

### 5.3 Evidence Selection

The evidence selector should choose the smallest sufficient evidence set for review, reporting, and AI context assembly. It should preserve references to the full source record while avoiding oversized context or unnecessary sensitive data.

### 5.4 Finding Fusion

Finding fusion should:

- combine duplicate findings from multiple sources
- retain every source reference
- prevent duplicated risk scoring
- record agreement and conflict
- select a canonical condition
- preserve source-specific status and timestamps
- recalculate confidence as sources change

---

## 6. Case Building and Lifecycle

### 6.1 Case Creation

A case may be created when:

- a deterministic correlation policy is satisfied
- a high-priority standalone finding requires review
- an analyst manually groups alerts
- a scheduled hunt produces a reviewable result
- an exposure path exceeds a configured threshold
- a collector or site health condition requires operational follow-up

### 6.2 Stable Identifiers

Cases should receive stable, human-readable identifiers in addition to internal IDs. Identifiers must not expose tenant secrets or sequential volume across tenants.

### 6.3 Assignment and Claiming

Queues should support:

- mine
- unassigned
- team
- all accessible
- snoozed
- waiting for evidence
- waiting for approval

Claim operations must be atomic. Two analysts should not silently claim the same case. A compare-and-set update should verify that the case remains unassigned before ownership changes.

### 6.4 SLA Timers

SLA timers should be based on server time and stored due dates, not browser timers. Suggested milestones include:

- time to acknowledge
- time to initial assessment
- time waiting for external evidence
- time to resolution
- time in a snoozed state

SLA policies should be versioned and tenant-scoped.

### 6.5 Next Action

Each queue row should expose one clear next action, such as:

- claim
- review evidence
- request more evidence
- approve or reject a proposal
- resolve
- reopen

The interface should avoid presenting several equally prominent actions that encourage inconsistent triage.

---

## 7. Investigation Ledger and Replay

### 7.1 Purpose

Important investigations need a replayable record of what evidence was available, which deterministic transformations occurred, which tools were called, and which decisions were made.

The ledger must not store private chain-of-thought. It should store structured decision records and concise reasoning summaries suitable for audit.

### 7.2 Append-Only Events

Suggested event types:

- case created
- alert linked
- alert unlinked
- evidence added
- evidence invalidated
- ownership changed
- assignment changed
- analyst note added
- deterministic rule evaluated
- AI analysis requested
- AI analysis completed
- tool requested
- tool approved or denied
- tool completed or failed
- exposure path created or updated
- finding fused
- verdict changed
- severity changed
- external projection created
- report generated
- case resolved
- case reopened

### 7.3 Ledger Event Contract

```json
{
  "ledger_event_id": "led-01J...",
  "case_id": "CASE-2026-0042",
  "tenant_id": "tenant-1",
  "event_type": "ai_analysis_completed",
  "actor_type": "agent",
  "actor_id": "risk-advisor",
  "occurred_at": "2026-07-24T19:00:00Z",
  "parent_event_id": "led-01H...",
  "input_refs": ["finding-17", "evidence-44"],
  "output_refs": ["analysis-22"],
  "policy_version": "ai-policy-3",
  "model_ref": "approved-model-profile-2",
  "reasoning_summary": "The recommendation is based on confirmed external exposure, a matching vulnerable software version, and absence of a compensating control.",
  "content_hash": "sha256:..."
}
```

### 7.4 Replay View

A replay view should distinguish:

- observed facts
- imported enrichment
- deterministic derivations
- inferred relationships
- AI recommendations
- analyst decisions
- approval decisions
- published outputs

The replay should answer what changed and why without reconstructing hidden model deliberation.

### 7.5 Branching

An analyst may explore an alternate hypothesis without overwriting the primary case narrative. Branch records should include:

- branch identifier
- parent ledger event
- hypothesis
- evidence scope
- status
- conclusion
- merge or discard decision

---

## 8. Investigation Workspace

A future investigation workspace should include:

### Primary Pane

- case summary
- current status, verdict, severity, and priority
- assigned owner and SLA
- selected evidence
- related assets and identities
- findings and exposure paths
- investigation timeline
- analyst notes
- report preview

### Investigation Rail

- concise deterministic narrative
- related entities and pivots
- recent event mini-timeline
- evidence conflicts
- recommended next action
- recommendation rationale
- expected benefit
- operational risk
- approval requirement

### Deterministic Narrative

A baseline narrative should be generated from structured records without requiring AI. For example:

```text
An externally reachable management service was observed on asset A. A matching software version is associated with finding F. No approved compensating control is currently recorded. The asset is connected to segment S, which also contains two unmanaged devices. Reachability between the management service and those devices is inferred and has not been actively validated.
```

### Optional Deep Explanation

AI may provide a deeper explanation only after receiving:

- a typed task
- tenant-scoped evidence
- trust labels
- evidence classifications
- output schema
- token and time limits
- allowed destination

Every material statement should cite evidence or be labeled as an inference, recommendation, or unknown.

---

## 9. Analyst and AI Assessment Separation

Case records should keep analyst and AI fields separate.

### Analyst Assessment

Suggested fields:

- analyst verdict
- analyst severity
- analyst confidence
- analyst summary
- resolution code
- accepted assumptions
- follow-up owner
- review timestamp

### AI Assessment

Suggested fields:

- advisory verdict
- advisory severity
- advisory confidence
- evidence references
- reasoning summary
- recommendation
- uncertainty list
- model profile and version
- policy version
- created timestamp
- validation status

AI values must not overwrite analyst fields. The interface should make the source of each assessment obvious.

---

## 10. Typed Investigation Report

Suggested report contract:

- report identifier
- case identifier
- report type
- title
- executive digest
- verdict
- severity
- priority
- confidence
- business impact
- technical impact
- affected assets
- affected identities
- supporting findings
- selected evidence
- exposure or attack chain
- timeline
- observables and indicators
- control gaps
- recommended actions
- validation steps
- unknowns and assumptions
- framework mappings
- analyst approval
- generation metadata

Report types may include:

- executive summary
- technical investigation report
- remediation plan
- shift handoff
- evidence package
- compliance-oriented summary

The report generator should have a deterministic template fallback when AI is unavailable.

---

## 11. Case-Derived Operational Knowledge

### 11.1 Scope Boundary

OpenAssetWatch should not build a broad new memory architecture as part of the current roadmap. A future case-derived knowledge feature may be added later as a small, explicit service.

### 11.2 Eligible Source

A case may produce a knowledge record only when:

- the case is closed
- an analyst verdict exists
- evidence references remain valid
- the record contains no secrets
- tenant policy allows retention
- the content is bounded and inspectable

### 11.3 Suggested Knowledge Record

- `knowledge_id`
- `tenant_id`
- `source_case_id`
- `source_type`
- `title`
- `summary`
- `keywords`
- `observable_types`
- `verdict`
- `evidence_refs`
- `created_at`
- `expires_at`
- `reviewed_by`
- `trust_state`

Suggested source types:

- `manual`
- `case_derived`

A case should create at most one default knowledge record unless a human explicitly approves additional records.

### 11.4 Non-Authority Rule

Case-derived knowledge is context, not current truth. Important claims must be revalidated against current evidence before use in a high-impact recommendation.

---

## 12. Detection-as-Code Lifecycle

### 12.1 Detection Object

A detection should be a versioned, reviewable object containing:

- detection identifier
- name and description
- category
- author and owner
- version
- status
- supported data sources
- required fields
- query or rule definition
- severity and confidence defaults
- suppression logic
- test fixtures
- expected matches
- expected non-matches
- evaluation results
- deployment targets
- rollback version
- change history

### 12.2 Lifecycle

```text
Draft Proposal
      |
      v
Static Validation
      |
      v
Fixture and Dataset Evaluation
      |
      v
Peer or Owner Review
      |
      v
Approved Candidate
      |
      v
Limited Promotion
      |
      v
Operational Monitoring
      |
      +---- success ----> General Promotion
      |
      `---- regression -> Rollback
```

Suggested statuses:

- draft
- proposed
- validating
- needs_changes
- approved
- canary
- active
- deprecated
- rolled_back
- rejected

### 12.3 Generated Detections

AI-generated detection content must remain a draft. It must be:

- schema validated
- field validated
- tested against positive and negative fixtures
- evaluated on historical or synthetic data
- reviewed by an authorized human
- versioned
- rollbackable
- attributable to its generation task

### 12.4 Platform and Tenant Detections

Platform-maintained detections should be visible but immutable to normal tenants. Tenant-defined detections may be edited only by authorized roles and must follow the same validation lifecycle.

---

## 13. Detection Tuning Workbench

### 13.1 Purpose

The tuning workbench should help reduce noise without hiding risk.

### 13.2 Suggestion Lanes

Deterministic tuning suggestions may be generated from:

- false-positive rate
- analyst verdict history
- alert volume
- repeated suppressions
- low confidence
- data-field absence
- stale rule execution
- data-source drift
- duplicate conditions
- unused or unreachable rule branches

### 13.3 Safe Mechanical Changes

Examples include:

- add a narrow exclusion supported by analyst verdicts
- require a missing corroborating field
- narrow a time window
- reduce duplicate notifications
- change routing or priority rather than disabling detection
- deprecate a rule after replacement validation

Each proposal should have one primary mechanical action and a clear reason.

### 13.4 Before-and-After Record

Every tuning proposal should retain:

- previous rule version
- proposed rule version
- affected data sources
- expected volume change
- known false-positive examples
- known true-positive examples
- evaluation metrics
- reviewer
- approval
- promotion time
- rollback target

### 13.5 Drift Monitoring

Detection drift metrics may include:

- hit-rate change
- field availability change
- confidence distribution change
- data-source lag
- false-positive rate change
- verdict distribution change
- rule execution failures
- sudden zero-result condition

---

## 14. Hunt-as-Code

A hunt should be a versioned, hypothesis-driven definition rather than a free-form prompt.

Suggested fields:

- hunt identifier
- hypothesis
- required evidence sources
- query or analytical steps
- schedule
- lookback period
- tenant scope
- expected output schema
- escalation threshold
- owner
- version
- test fixtures
- status

Hunts may produce candidate findings or cases. They should not directly execute remediation.

---

## 15. Evaluation Harness

### 15.1 Evaluation Layers

OpenAssetWatch should maintain two clearly separated evaluation layers.

#### Deterministic Substrate Evaluation

Tests:

- normalization
- deduplication
- correlation
- finding fusion
- evidence selection
- policy decisions
- schema validation
- tenant isolation
- permission paths
- detection fixtures

These tests should run without a live model.

#### Live AI Evaluation

Tests:

- evidence citation quality
- unsupported claims
- recommendation usefulness
- uncertainty disclosure
- structured output compliance
- prompt-injection resistance
- sensitive-data handling
- latency
- token use
- estimated or actual cost

Live model results must not be presented as deterministic guarantees.

### 15.2 Dataset Structure

A reusable evaluation case should include:

- case identifier
- scenario description
- synthetic or sanitized evidence
- expected deterministic findings
- expected non-findings
- expected correlation groups
- expected case priority
- expected required evidence
- allowed recommendation categories
- prohibited claims
- tenant boundary

### 15.3 Metrics

Possible metrics include:

- precision
- recall
- false-positive rate
- false-negative rate
- citation validity
- schema pass rate
- unsupported-claim rate
- case-grouping accuracy
- analyst agreement
- latency
- token consumption
- cost per validated result

Metrics should be reported per scenario and as macro averages so high-volume cases do not hide weak categories.

### 15.4 Provenance

Evaluation reports should record:

- dataset version and hash
- software commit
- detection versions
- policy versions
- model profile and digest
- runtime profile
- date
- environment class
- measured, estimated, or synthetic label

Historical scorecards should be append-oriented so regressions remain visible.

### 15.5 CI Gates

CI may fail when:

- deterministic tests regress
- a new high-severity agent security issue appears
- a detection loses required precision or recall
- tenant-isolation fixtures fail
- output schemas change without migration
- protected control artifacts drift
- baseline comparison reveals a new prohibited permission path

Live model evaluation may run on a schedule or protected release workflow rather than every pull request.

---

## 16. Analyst Feedback and Model Governance

### 16.1 Feedback Record

Feedback should record:

- case or finding reference
- analyst identity
- original output
- corrected label or text
- reason
- confidence
- timestamp
- evidence references
- whether the correction is eligible for training or evaluation

### 16.2 Poisoning Protections

Feedback must not automatically update a production model or knowledge base.

Required controls include:

- authenticated analyst identity
- role checks
- minimum sample counts
- label consistency checks
- quarantine period
- tenant separation
- outlier and adversarial review
- source provenance
- duplicate suppression
- manual promotion approval

### 16.3 Champion and Challenger

A future model-update process should:

1. preserve the active model and metadata
2. train or configure a challenger
3. evaluate both on the same versioned dataset
4. require minimum improvement and no unacceptable regression
5. review fairness, poisoning, and tenant-isolation tests
6. promote only with approval
7. retain rollback capability
8. monitor post-promotion drift

A model may be hot-reloaded only after the same promotion controls are satisfied.

---

## 17. Advisory Response Planning

### 17.1 Current Boundary

OpenAssetWatch currently remains advisory. The platform may generate recommended actions and validation steps, but it should not automatically execute containment or remediation.

### 17.2 Future Response Plan Object

A future response plan may include:

- plan identifier
- case identifier
- proposed action
- target scope
- confidence
- expected impact
- safety score
- blast-radius estimate
- critical-asset flag
- rationale
- evidence refs
- approval tier
- dry-run result
- rollback plan
- verification plan
- status

### 17.3 Suggested State Machine

```text
triggered
   |
   v
planning
   |
   v
awaiting_approval
   |
   v
approved
   |
   v
executing
   |
   v
verifying
   |
   +---- success ----> completed
   |
   +---- unsafe -----> rolled_back
   |
   `---- error ------> failed
```

### 17.4 Safety Invariants

- critical assets require human approval
- high blast radius requires human approval
- uncertain target identity blocks execution
- missing rollback blocks high-impact execution
- an AI recommendation cannot approve itself
- generation and publication identities remain separate
- verification must use fresh evidence
- failure must not be represented as success

These are future requirements only. Current implementations should stop at recommendation generation.

---

## 18. What-If Simulation

OpenAssetWatch may later support simulation of control changes or exposure paths.

Examples:

- remove public exposure
- add a network segmentation control
- patch a service
- add endpoint coverage
- disable an unused identity
- change collector deployment coverage

Simulation results must be labeled:

- synthetic
- directional
- based on stated assumptions
- not proof of exploitability
- not a production breach probability

The simulation engine should not perform adversary emulation or execute offensive actions.

---

## 19. Connector and Extension Architecture

### 19.1 Self-Describing Connectors

Connectors should expose:

- configuration schema
- credential schema
- capability list
- supported operations
- read and write classification
- approval requirements
- test method
- health method
- data classifications
- version and digest

### 19.2 Credential Handling

Credentials should be:

- encrypted at rest
- hidden from normal API responses
- scoped per connector
- rotated
- audited
- injected only at execution time
- inaccessible to models

Where practical, connector services should receive a narrow credential reference or proxy rather than the reusable secret.

### 19.3 Safe Connection Tests

A connection test should:

- avoid saving invalid credentials
- avoid making destructive calls
- use a narrow endpoint
- apply a short timeout
- redact errors
- record test status without secrets

### 19.4 Extension Management Console

A future management console should support:

- read definitions
- validate definitions
- show per-section errors
- show integration health
- enable or disable approved versions
- display trust state
- display last review

It should not execute arbitrary extension code from the management screen.

One broken definition must not prevent healthy definitions from loading.

### 19.5 Development and Production Separation

Development examples, test connectors, and sample playbooks should remain separate from production distributions. A production package should include an empty extension template rather than automatically enabling demonstration integrations.

Optional extensions should fail with explicit messages. Silent fallback to an unrelated provider or tool is prohibited.

---

## 20. Data Privacy and Egress Control

### 20.1 Operation Modes

Suggested modes:

- local air-gapped
- local with approved enrichment
- self-hosted distributed
- managed control plane with tenant policy

### 20.2 Egress Matrix

Each operation should declare:

- data classes read
- external destinations
- fields transmitted
- pseudonymization applied
- retention expectation
- approval requirement
- fallback behavior

### 20.3 Pseudonymization

For approved external processing, OpenAssetWatch should use request-scoped aliases where practical. Re-association should occur locally.

```text
Internal Asset Identifier
          |
          v
 Request-Scoped Alias Map
          |
          v
 Approved External Processing
          |
          v
      Returned Alias
          |
          v
    Local Rehydration
```

### 20.4 Air-Gapped Verification

CI or release testing should demonstrate that local and deterministic operation succeeds when outbound network access is blocked.

### 20.5 Prompt and Context Sanitization

Controls should include:

- explicit trust labels
- untrusted-content wrappers
- delimiter normalization
- maximum length and nesting
- bounded lists
- suspicious instruction detection
- separation of instructions and evidence
- typed output validation
- destination-aware redaction

Sanitization is a defense-in-depth control. It does not replace authorization, permission-path analysis, or tool policy.

---

## 21. Service and Tenant Isolation

### 21.1 Suggested Service Boundaries

Logical services may include:

- ingestion
- normalization
- correlation
- case management
- finding intelligence
- detection registry
- evaluation workers
- AI orchestration
- tool gateway
- projection outbox
- audit and monitoring

These may begin in one deployable application, but interfaces and permissions should remain explicit.

### 21.2 Data Access

Every query and mutation should enforce tenant scope. Database-level tenant policies may be added where supported, but application-layer tests remain required.

### 21.3 Network Segmentation

Frontend, backend, AI runtime, data store, and integration workers should not all share unrestricted network access. Service-to-service traffic should be authenticated and minimized.

### 21.4 Audit

Audit records should be append-oriented and protected from normal application edits. Sensitive values must be redacted.

---

## 22. Observability

Every major service should expose:

- health
- readiness
- request metrics
- queue depth
- processing latency
- failure rate
- retry rate
- stale-job count
- data lag
- tenant-safe traces
- structured logs

Security-operations metrics may include:

- alerts ingested
- alerts deduplicated
- cases created
- correlation ratio
- cases by status and verdict
- SLA breaches
- time to acknowledge
- time to resolution
- AI analyses requested and rejected
- detection hit rate
- tuning proposals
- evaluation regressions
- connector failures
- projection backlog

Prompt text, secrets, and unrestricted raw evidence should not appear in general logs.

---

## 23. Shift Handoff and Operational Views

A future handoff view may include:

- active cases
- unassigned high-priority cases
- cases approaching SLA
- cases waiting for evidence
- pending approvals
- connector or collector degradation
- recent detection changes
- evaluation regressions
- unresolved exposure paths
- notes from the prior shift

Handoff records should be time-bound, evidence-linked, and inspectable. They should not become a separate source of truth.

---

## 24. Failure and Degradation Behavior

Required behavior:

- collector ingestion continues when AI is unavailable
- normalization and deterministic findings continue without AI
- case creation continues without external projections
- projection failures remain in an outbox for retry
- one failed connector does not block unrelated connectors
- correlation falls back safely if optional enrichment is unavailable
- reports have deterministic fallback templates
- model failure does not silently change data-sharing policy
- partial results are labeled
- stale jobs are reconciled
- duplicate execution is suppressed
- disabled integrations remain removable without migration of canonical state

Example failure record:

```json
{
  "operation": "external_projection",
  "status": "deferred",
  "reason": "connector_circuit_open",
  "canonical_write_completed": true,
  "retry_after_seconds": 120,
  "user_action_required": false
}
```

---

## 25. Proposed Implementation Roadmap

### Phase A: Contracts and Storage

- define canonical source event
- define alert, observable, case, and ledger schemas
- define analyst and AI assessment separation
- define report schema
- define connector capability schema
- define detection and evaluation schemas

### Phase B: Deterministic Ingestion and Cases

- add idempotent ingestion
- add raw source archive
- add normalization and observable extraction
- add deduplication
- add basic deterministic correlation
- add case creation and assignment
- add append-only ledger

### Phase C: Investigation Workspace

- add queue filters
- add atomic claiming
- add server-based SLA timers
- add evidence timeline
- add deterministic narrative
- add typed report generation
- add shift handoff view

### Phase D: Detection Lifecycle

- add detection registry
- add static validation
- add fixture evaluation
- add proposal and approval workflow
- add canary promotion
- add rollback
- add tuning workbench and drift metrics

### Phase E: Evaluation and Feedback

- add deterministic evaluation suite
- add synthetic case datasets
- add live AI evaluation harness
- add versioned scorecards
- add analyst feedback quarantine
- add champion-and-challenger governance

### Phase F: External Projections and Extensions

- add projection outbox
- add authenticated inbound updates
- add connector registry
- add credential vault or proxy
- add extension validation console
- add connector health and circuit breakers

### Phase G: Advisory Response Planning

- add response-plan schema
- add approval state machine
- add dry-run representation
- add verification and rollback contracts
- keep execution disabled until separately designed, reviewed, and approved

---

## 26. Acceptance Criteria

The first production-capable security-operations layer should not be considered complete until:

- every source record is tenant-scoped and attributable
- duplicate ingestion is idempotent
- raw source data remains separable from canonical fields
- correlation is explainable and replayable
- original alerts remain accessible after case grouping
- analyst assessments cannot be overwritten by AI
- every material AI statement references evidence or declares uncertainty
- case assignment is atomic
- SLA calculations use server time
- ledger events are append-oriented and auditable
- detection changes require evaluation and approval
- generated detection content cannot publish itself
- evaluation reports include dataset and software provenance
- external projection failure cannot roll back canonical state
- air-gapped deterministic operation remains functional
- tenant isolation is covered by automated tests
- all action-capable future workflows require independent approval, verification, and rollback

---

## 27. Explicit Non-Goals

This architecture does not authorize:

- autonomous containment
- automatic network or endpoint changes
- exploit generation
- payload generation
- credential collection
- password cracking
- remote shell management
- command-and-control features
- prohibited: arbitrary command execution
- prohibited: unrestricted active scanning
- adversary emulation against operational assets
- self-approving AI actions
- model-generated findings without evidence
- silent external data sharing
- replacement of deterministic findings with model opinion

---

## 28. Relationship to Other Architecture Documents

- `docs/architecture/ai-agent-architecture.md` defines the foundational AI Advisor, evidence, agents, Tool Gateway, audit, and handoff direction.
- `docs/architecture/ai-model-routing.md` defines deterministic, local, external, human-review, and insufficient-evidence routes.
- `docs/architecture/ai-governance-security.md` defines policy enforcement and isolated agent execution.
- `docs/architecture/ai-observability-operations.md` defines AI operations telemetry.
- `docs/architecture/local-agentic-ai-design.md` defines workload scheduling and specialist-agent execution.
- `docs/architecture/defensive-ai-security-gap-backlog.md` preserves future defensive-intelligence gaps and implementation sequencing.
- `docs/architecture/ai-agent-permission-output-security.md` defines permission paths, trust-labeled context, safe output publishing, and protected control artifacts.

## Final Position

OpenAssetWatch should evolve from asset visibility into security decision support through deterministic normalization, explainable correlation, evidence-backed cases, replayable investigations, and governed detection content.

AI may improve explanation, prioritization, reporting, and analyst efficiency, but it must remain subordinate to evidence, policy, tenant boundaries, and human judgment. The platform should continue to provide useful collection, findings, cases, and reports when no AI service is configured.
