# Security Investigation and Case Operations Architecture

## Purpose

This document defines a future, provider-neutral architecture for turning OpenAssetWatch observations, findings, enrichment, and relationship data into structured investigations that analysts and operators can review, assign, replay, and close.

The design fills operational gaps between asset visibility and actionable defensive work. It does not turn OpenAssetWatch into a full event-management platform, a penetration-testing platform, or an autonomous response system.

The architecture remains:

- passive-first
- evidence-first
- deterministic where possible
- advisory-first
- read-only by default
- tenant-scoped
- auditable
- useful without any AI model

## Design Boundaries

OpenAssetWatch may eventually support investigation workflows around:

- newly discovered or changed assets
- unmanaged or unknown devices
- missing security controls
- vulnerable or outdated software
- suspicious exposure relationships
- collector and sensor health
- repeated or correlated findings
- external exposure candidates
- evidence-backed exposure paths

The investigation layer must not:

- invent events or findings
- treat AI output as authoritative evidence
- silently alter asset, collector, network, or endpoint state
- perform exploitation
- collect credentials
- execute arbitrary commands
- cross tenant boundaries
- replace deterministic collection or scoring

## End-to-End Flow

```text
Collectors, Sensors, and Approved Integrations
                    |
                    v
          Raw Source Records
                    |
                    v
       Normalization and Deduplication
                    |
                    v
      Evidence, Observations, and Findings
                    |
                    v
       Correlation and Case Formation
                    |
                    v
       Investigation Work Queue
                    |
                    v
 Deterministic Investigation Summary and Pivots
                    |
          +---------+----------+
          |                    |
          v                    v
  Analyst Investigation   Optional AI Explanation
          |                    |
          +---------+----------+
                    |
                    v
        Playbooks and Recommendations
                    |
                    v
      Analyst Decision and Case Closure
                    |
                    v
  Optional Reviewed Operational Lesson
```

The normal read path should remain deterministic. AI may provide an optional deeper explanation after the evidence and case context have already been assembled.

---

## 1. Canonical Investigation Domain Model

The investigation layer should use typed records instead of relying on free-form reports.

### 1.1 Security Signal

A security signal represents one normalized observation or alert-like record received from a collector, rule, enrichment source, or approved integration.

Suggested fields:

- `signal_id`
- `tenant_id`
- `source_type`
- `source_instance_id`
- `source_record_id`
- `source_url`, when safe and useful
- `title`
- `description`
- `first_seen_at`
- `last_seen_at`
- `received_at`
- `source_severity`
- `source_confidence`
- `source_disposition`
- `analytic_type`
- `analytic_id`
- `analytic_version`
- `normalized_category`
- `normalized_tactic`
- `normalized_technique`
- `correlation_uid`
- `artifact_refs`
- `evidence_refs`
- `raw_record_ref`
- `unmapped_fields`
- `normalization_version`

The normalized record should preserve source-defined values rather than overwriting them with later system or analyst assessments.

### 1.2 Finding

A finding is a canonical OpenAssetWatch security or posture condition derived from evidence.

Findings remain separate from security signals because one finding may be supported by many signals, and one signal may support several findings.

Suggested fields:

- `finding_id`
- `finding_type`
- `title`
- `summary`
- `severity`
- `confidence`
- `status`
- `affected_assets`
- `evidence_refs`
- `source_finding_refs`
- `rule_id`
- `rule_version`
- `first_seen_at`
- `last_seen_at`
- `validated_at`
- `validation_state`
- `statement_classification`
- `recommended_action`

### 1.3 Case

A case is the operational container for related signals, findings, assets, artifacts, analyst activity, AI analysis, playbook runs, approvals, and closure decisions.

Suggested fields:

- `case_id`
- `tenant_id`
- `title`
- `description`
- `category`
- `status`
- `assignee_id`
- `created_at`
- `updated_at`
- `acknowledged_at`
- `closed_at`
- `correlation_uid`
- `primary_asset_id`
- `signal_ids`
- `finding_ids`
- `artifact_ids`
- `evidence_refs`
- `tags`
- `sla_policy_id`
- `sla_due_at`
- `snoozed_until`
- `closure_summary`
- `external_projection_refs`

The case should maintain separate assessments for each decision source.

### 1.4 Separate Assessment Channels

OpenAssetWatch should never collapse source, deterministic, AI, and human assessments into one ambiguous field.

```text
Source assessment
  = what an upstream source reported

Deterministic assessment
  = what OpenAssetWatch rules calculated

AI assessment
  = advisory interpretation over approved evidence

Analyst assessment
  = the human-reviewed operational decision
```

Suggested assessment groups:

```json
{
  "source_assessment": {
    "severity": "high",
    "confidence": "unknown",
    "disposition": "detected"
  },
  "deterministic_assessment": {
    "severity": "medium",
    "confidence": 0.88,
    "impact": "medium",
    "priority": "high",
    "rule_refs": ["rule-17"]
  },
  "ai_assessment": {
    "verdict": "suspicious",
    "severity": "medium",
    "impact": "medium",
    "priority": "high",
    "confidence": 0.72,
    "analysis_record_id": "analysis-42"
  },
  "analyst_assessment": {
    "verdict": "security_risk",
    "severity": "high",
    "impact": "high",
    "priority": "critical",
    "confidence": "high",
    "decided_by": "user-9",
    "decided_at": "2026-07-24T18:00:00Z"
  }
}
```

AI fields must not overwrite source, deterministic, or analyst fields. A later analyst correction should remain visible as a correction rather than rewriting history.

### 1.5 Case Status

Suggested case states:

- `new`
- `queued`
- `assigned`
- `in_progress`
- `waiting_for_evidence`
- `waiting_for_approval`
- `on_hold`
- `resolved`
- `closed`
- `reopened`

Suggested verdicts:

- `unknown`
- `true_positive`
- `false_positive`
- `suspicious`
- `benign`
- `security_risk`
- `insufficient_data`
- `duplicate`
- `managed_externally`
- `accepted_risk`
- `not_applicable`

State transitions should be enforced by code and recorded in the case timeline.

---

## 2. Artifact and Observable Model

### Purpose

Investigations need a consistent way to represent the entities extracted from signals and evidence.

An artifact is a typed value with an operational role in an event or case.

### Suggested Artifact Types

- asset identifier
- hostname
- IP address
- hardware address
- subnet
- port
- protocol
- URL
- domain
- email address
- user or account identifier
- role or group
- process name
- process identifier
- process command line
- file name
- file path
- file hash
- software package
- service
- cloud resource
- container or workload
- vulnerability identifier
- weakness identifier
- certificate fingerprint
- threat indicator
- policy identifier
- collector identifier
- sensor identifier

### Suggested Artifact Roles

- `source`
- `destination`
- `actor`
- `target`
- `affected`
- `owner`
- `requester`
- `responder`
- `related`
- `observed`

### Artifact Record

```json
{
  "artifact_id": "artifact-123",
  "tenant_id": "tenant-1",
  "type": "hostname",
  "role": "affected",
  "value": "workstation-01",
  "normalized_value": "workstation-01",
  "value_hash": "sha256:...",
  "sensitivity": "internal",
  "confidence": 0.95,
  "first_seen_at": "2026-07-24T10:00:00Z",
  "last_seen_at": "2026-07-24T10:04:00Z",
  "source_refs": ["signal-91"],
  "linked_asset_id": "asset-77"
}
```

Sensitive artifact values should be redacted or aliased before external processing. The artifact identifier and value hash allow correlation without exposing the raw value unnecessarily.

---

## 3. Correlation and Case Formation

### 3.1 Correlation Goals

Correlation should reduce repeated signals into understandable work without hiding source evidence.

It should support:

- duplicate suppression
- time-window grouping
- entity-based grouping
- finding-based grouping
- campaign or sequence grouping
- asset-centered investigations
- exposure-path investigations
- reopening when new related evidence arrives

### 3.2 Deterministic Correlation Identifier

A deterministic correlation identifier can be generated from:

- tenant identifier
- correlation rule identifier and version
- time bucket
- sorted normalized entity keys
- optional asset or finding identifiers

Example:

```text
correlation_uid = hash(
  tenant_id
  + correlation_rule_id
  + time_bucket
  + sorted(entity_keys)
)
```

The input fields used to produce the identifier must be retained in `correlation_basis` so the grouping can be explained later.

### 3.3 Idempotency

Repeated delivery of the same source record must not create duplicate signals, cases, or playbook jobs.

Recommended idempotency keys:

- source instance + source record identifier
- normalized content hash when no source identifier exists
- case correlation identifier
- playbook run request identifier
- analysis request identifier

### 3.4 Case Formation Rules

A case builder should:

1. validate tenant scope
2. normalize correlation keys
3. check for a matching open case
4. lock the matching case or correlation key
5. attach the new signal and artifacts
6. update first-seen and last-seen ranges
7. recalculate deterministic assessment
8. append a timeline event
9. enqueue optional analysis only when policy permits

Concurrency controls should ensure two workers cannot create separate cases for the same correlation key at the same time.

### 3.5 Preserve Source Records

Correlation must not discard source records. A case should provide a compact view while retaining links to every supporting signal and evidence record.

### 3.6 Correlation Confidence

Each case should state why records were grouped.

Suggested fields:

- `correlation_method`
- `correlation_rule_id`
- `correlation_rule_version`
- `correlation_confidence`
- `correlation_basis`
- `conflicting_evidence`
- `alternative_case_candidates`

---

## 4. Investigation Work Queue

### Purpose

The queue should answer one operational question:

> What should I investigate next?

It should not attempt to show every low-priority record at once.

### 4.1 Suggested Queue Buckets

- **Mine** — open cases assigned to the current user
- **Unassigned** — unowned cases above a configured priority threshold
- **Team** — all cases visible to the current team
- **Waiting** — cases waiting for evidence or approval
- **Snoozed** — temporarily deferred cases

### 4.2 Queue Ordering

Suggested ordering:

1. breached service target
2. assigned-to-current-user
3. critical priority
4. high priority
5. closest service target
6. oldest acknowledged time
7. oldest first-seen time

Operational service targets should not alter security severity. They are separate dimensions.

### 4.3 Server-Anchored Service Targets

The server should calculate:

- `sla_due_at`
- `sla_remaining_seconds`
- `sla_breached`
- `generated_at`

The user interface may animate the countdown locally, but it must re-anchor to the server timestamp so different analysts see consistent values.

### 4.4 Atomic Claim

Claiming a case must be race-safe.

Conceptual operation:

```text
Update the case assignee only when it is currently unassigned.
Return the winner or a conflict containing the actual owner.
```

Reclaiming a case already owned by the caller should be idempotent.

### 4.5 Queue Actions

Initial queue actions may include:

- open
- claim
- release
- acknowledge
- snooze
- assign
- escalate
- mark duplicate

Actions should use narrow API contracts and write timeline and audit records.

### 4.6 Snooze

Snooze should:

- use bounded preset or policy-approved durations
- require a reason for long deferrals
- retain the original service target
- reappear automatically when the snooze expires
- remain visible in audit and shift handoff views

Long-term noise handling should occur through finding or detector tuning rather than indefinite per-case snoozing.

### 4.7 Shift Handoff

A shift handoff record should include:

- active assigned cases
- unassigned critical and high cases
- service-target breaches and near-breaches
- investigations currently running
- pending approvals
- cases waiting for evidence
- recently failed playbook or analysis jobs
- unresolved unknowns
- recommended next step
- current owner and incoming owner
- handoff author and timestamp

Handoff should be generated deterministically from current case state, with an optional AI-written summary layered on top.

---

## 5. Deterministic Investigation View

### Purpose

The primary investigation panel should be fast, consistent, and useful without a model call.

### 5.1 Suggested Sections

1. **Correlation narrative** — why the case or alert was promoted
2. **Related entities** — pivotable assets, users, network indicators, findings, and cases
3. **Mini-timeline** — the most recent important events
4. **Recommended next steps** — structured advisory actions with rationale and risk
5. **Unknowns** — missing evidence and unresolved questions

### 5.2 Deterministic Narrative

The narrative should be generated from the same normalized inputs used during correlation.

It should answer:

- which signals or findings contributed
- which entities matched
- which time window was used
- what risk factors increased priority
- which uncertainty reduced confidence
- what evidence would improve the assessment

The narrative should be produced once, versioned, and cached. Opening the case should not require a new model call.

### 5.3 Related Entity Pivots

Each related entity should provide:

- type
- display label
- normalized value or alias
- relationship to the case
- confidence
- pivot destination
- allowed actions

A pivot should take the user directly to an asset, relationship graph, evidence record, finding, or related case.

### 5.4 Mini-Timeline

The mini-timeline may merge:

- case status transitions
- analyst comments
- evidence attachments
- playbook checkpoints
- analysis jobs
- approval requests and decisions
- policy denials
- audit events relevant to the case

Events should be deduplicated, sorted, and bounded. The full timeline remains available on the case page.

### 5.5 Recommended Actions

A recommendation should include:

- action title
- priority
- rationale
- expected benefit
- operational risk
- evidence references
- prerequisites
- approval requirement
- verification method

The investigation view should not execute the action. Execution, if ever supported, belongs to a separate controlled workflow.

### 5.6 Optional Deep Explanation

A model-assisted explanation may be requested explicitly.

It must:

- use the same tenant-scoped evidence envelope
- cite evidence references
- distinguish fact, inference, and recommendation
- preserve the deterministic narrative
- record route, model, policy, and validation metadata
- never alter case state without a separate approved operation

---

## 6. Investigation Ledger and Replay

### Purpose

Important investigations need an append-only record showing what the system and users did, without storing private model chain-of-thought.

### 6.1 Ledger Event Types

- case created
- signal attached
- finding attached
- correlation recalculated
- evidence retrieved
- context assembled
- model request started
- model response validated
- tool requested
- tool allowed or denied
- tool result received
- analyst comment
- assignment changed
- status changed
- approval requested
- approval approved, edited, denied, or expired
- playbook started, checkpointed, completed, failed, or cancelled
- recommendation generated
- external projection attempted
- case closed or reopened

### 6.2 Ledger Record

Suggested fields:

- `ledger_event_id`
- `tenant_id`
- `case_id`
- `sequence_number`
- `event_type`
- `actor_type`
- `actor_id`
- `agent_id`
- `task_id`
- `execution_id`
- `policy_version`
- `model_id`
- `model_version`
- `prompt_hash`
- `input_artifact_hash`
- `evidence_refs`
- `tool_id`
- `tool_arguments_redacted`
- `decision_summary`
- `output_ref`
- `status`
- `created_at`
- `previous_event_hash`
- `event_hash`

Hash chaining is optional but useful for detecting unexpected ledger modification.

### 6.3 Reasoning Summary, Not Private Chain-of-Thought

The ledger may store a concise decision summary describing:

- what evidence was considered
- what deterministic checks passed or failed
- why a route or recommendation was selected
- what uncertainty remains

It should not store private hidden reasoning, unrestricted prompts, secrets, or sensitive raw evidence by default.

### 6.4 Replay

A replay should reconstruct:

- the evidence available at each step
- the rules and policies in effect
- model and agent versions
- tool requests and results
- human decisions
- final outcome

Replay should never re-execute actions automatically. It is an inspection capability.

### 6.5 Immutability and Retention

Ledger events should be append-only. Corrections should add new events rather than update historical ones.

Retention should be configurable by deployment and data type. Sensitive debug payloads should have shorter retention than operational metadata.

---

## 7. Structured Investigation Report

An investigation report should use a versioned schema.

Suggested fields:

```json
{
  "report_schema": "investigation_report.v1",
  "profile_version": "profile-3",
  "case_id": "case-123",
  "verdict": "suspicious",
  "severity": "high",
  "impact": "medium",
  "priority": "high",
  "confidence": 0.78,
  "digest": "Several correlated observations indicate an unmanaged exposed service.",
  "affected_assets": [],
  "evidence_findings": [],
  "exposure_path": [],
  "timeline": [],
  "artifacts": [],
  "recommended_actions": [],
  "unknowns": [],
  "evidence_refs": [],
  "generated_at": "2026-07-24T18:00:00Z"
}
```

### Required Report Principles

- `unknowns` is mandatory, even when empty
- every conclusion references evidence
- the report states the profile and schema version
- missing evidence lowers confidence
- source facts and AI interpretation remain separate
- the report is valid even when no model is configured

---

## 8. Playbook Runtime

### Purpose

Playbooks should provide repeatable investigation and reporting workflows without giving a model unrestricted control.

### 8.1 Playbook Categories

Initial future categories may include:

- assemble case summary
- retrieve current asset context
- collect approved enrichment
- review stale evidence
- generate an investigation report
- prepare a remediation plan
- extract reviewed operational lessons
- create a sanitized external ticket projection

### 8.2 Playbook Definition

Suggested fields:

- `playbook_id`
- `namespace`
- `name`
- `description`
- `version`
- `source`
- `digest`
- `tags`
- `input_schema`
- `output_schema`
- `required_permissions`
- `required_tools`
- `read_only`
- `requires_approval`
- `supports_dry_run`
- `max_runtime_seconds`
- `max_tool_calls`
- `owner`
- `review_state`

### 8.3 Playbook Run

Suggested run fields:

- `run_id`
- `playbook_id`
- `playbook_version`
- `case_id`
- `requested_by`
- `trigger`
- `user_input`
- `status`
- `scheduled_at`
- `started_at`
- `completed_at`
- `execution_id`
- `result_ref`
- `remark`
- `error_summary`
- `approval_id`

Suggested states:

- pending
- running
- waiting_for_approval
- succeeded
- partially_succeeded
- failed
- cancelled
- timed_out

### 8.4 Duplicate Suppression and Locking

The runtime should prevent duplicate analysis jobs for the same case and playbook scope.

Recommended pattern:

1. acquire a case or idempotency lock
2. check for a pending or running equivalent job
3. return the existing job when appropriate
4. create a new job only when no equivalent exists
5. enforce state transitions transactionally

### 8.5 Fail Clearly

Missing prompts, schemas, tools, or permissions should produce an explicit failure. The runtime should not silently substitute empty prompts or broader capabilities.

### 8.6 Read-Only First

Initial playbooks should use read-only tools. Any future action-capable playbook must follow the approval, blast-radius, publisher, verification, and rollback requirements in the response-governance architecture.

---

## 9. Optional Reviewed Operational Lessons

### Scope Control

OpenAssetWatch should not build a new general memory architecture during the current core-platform work.

A narrow future capability may extract one reusable operational lesson from a closed or analyst-validated case.

This is optional and should not be implemented until the case and evidence models are stable.

### Required Conditions

- the case has an analyst verdict
- the lesson cites the source case
- a human reviews or approves publication
- the lesson has an owner
- the lesson has an expiration or review date
- the lesson contains no secrets or sensitive raw evidence
- the lesson cannot override current evidence or policy
- the lesson can be corrected, withdrawn, exported, and deleted

### Suggested Record

```json
{
  "lesson_id": "lesson-19",
  "source_case_id": "case-123",
  "title": "Validate unmanaged device ownership before segmentation changes",
  "body": "A device with only passive network evidence should remain unverified until ownership or management evidence is confirmed.",
  "tags": ["asset-validation", "segmentation"],
  "approved_by": "user-7",
  "approved_at": "2026-07-25T10:00:00Z",
  "expires_at": "2027-01-25T10:00:00Z",
  "status": "approved"
}
```

### Bounded Retrieval

Future retrieval should limit:

- search keywords
- number of records
- record age
- data sensitivity
- tenant scope

Expired records must not be returned. A deterministic keyword fallback should remain available when an AI keyword extractor fails.

---

## 10. Source of Truth and External Projections

OpenAssetWatch should remain authoritative for case state.

External ticketing, messaging, reporting, or collaboration systems should receive projections rather than becoming competing case databases.

### Outbound Projection

1. persist the OpenAssetWatch case change
2. enqueue a projection task
3. write to approved external destinations
4. record external identifier and URL
5. retry failures independently
6. never roll back the canonical case because a projection failed

### Inbound Synchronization

Inbound status changes should:

- authenticate the source
- verify message integrity
- resolve the external reference
- map the external status into a limited OpenAssetWatch state
- apply the change idempotently
- preserve source-specific metadata externally
- append timeline and audit events

The mapping may intentionally be lossy. Only the fields required for convergence should be synchronized.

---

## 11. Security and Privacy Requirements

- Every query and mutation is tenant-scoped.
- AI analysis uses approved evidence aliases when external processing is allowed.
- Raw source payloads are not copied into general logs.
- Prompt and evidence inputs are treated as untrusted data.
- Tool output is validated and bounded.
- Ledger records redact secrets and sensitive arguments.
- Assignment, closure, approval, and external projection are audited.
- External projection failures do not weaken canonical consistency.
- Case exports are access-controlled and audited.
- AI recommendations cannot directly change systems.

---

## 12. Operational Metrics

Useful investigation metrics include:

- new cases by category
- unassigned high-priority cases
- service-target breaches
- time to acknowledge
- time to assign
- time to resolve
- cases waiting for evidence
- cases waiting for approval
- reopened cases
- duplicate cases prevented
- correlation confidence distribution
- AI analysis success and validation rate
- playbook completion and failure rate
- external projection failure rate
- analyst-versus-AI assessment differences
- unknowns resolved over time

Metrics must be tenant-scoped and must not expose sensitive case content in aggregate views.

---

## 13. Implementation Roadmap

### Phase 1: Contracts

- define signal, case, artifact, timeline, and assessment schemas
- define case states and transition rules
- define deterministic correlation identifier
- define structured investigation report
- define ledger event contract

### Phase 2: Deterministic Case Operations

- create cases from approved findings and signals
- add correlation and duplicate suppression
- add assignment and atomic claim
- add server-anchored service targets
- add timeline and audit events
- add deterministic investigation narrative

### Phase 3: Investigation Workspace

- add queue buckets
- add entity pivots
- add mini-timeline
- add structured recommendations and unknowns
- add shift handoff view

### Phase 4: Read-Only Playbooks

- add playbook registry
- add transactional run state
- add duplicate-job suppression
- add case summary and report playbooks
- add cancellation and bounded execution

### Phase 5: Replay and External Projection

- add append-only investigation ledger
- add safe replay
- add external projection references
- add idempotent outbound and inbound synchronization

### Phase 6: Optional Enhancements

- add explicit AI deep explanation
- add reviewed operational lesson extraction
- add additional case correlation strategies
- add policy-controlled federated evidence queries

---

## 14. Acceptance Criteria

The first production-capable investigation layer should not be considered complete until:

- source, deterministic, AI, and analyst assessments are separate
- every case is tenant-scoped
- correlation is deterministic and explainable
- duplicate source delivery is idempotent
- case claim is race-safe
- service targets are server-anchored
- the primary investigation view works without AI
- AI analysis cannot overwrite canonical evidence or analyst decisions
- every playbook run has a typed state and result
- important steps are replayable from append-only records
- private chain-of-thought is not stored
- external systems remain projections of canonical state
- failed integrations cannot block canonical case writes
- operational lessons, if later enabled, require analyst validation and expiration

## Relationship to Other Architecture Documents

- `docs/architecture/defensive-ai-security-gap-backlog.md`
- `docs/architecture/ai-agent-permission-output-security.md`
- `docs/architecture/local-agentic-ai-design.md`
- `docs/architecture/detection-feedback-response-governance.md`
- `docs/architecture/connector-playbook-projection-architecture.md`
