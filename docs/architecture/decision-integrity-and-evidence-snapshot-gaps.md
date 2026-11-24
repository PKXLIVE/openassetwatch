# Decision Integrity and Evidence Snapshot Gap Additions

## Purpose

This document records additional OpenAssetWatch design gaps that should be
implemented through the existing policy, evidence, task, connector, finding,
case, AI/MCP, reporting, and external-intelligence boundaries.

The additions close gaps around high-impact approval integrity, incomplete
analysis, suppression and accepted-risk governance, candidate-entity promotion,
reconsideration, consistent read snapshots, and separation of operational
activity from evidentiary lineage.

They are additive to `asset-intelligence-stack-gap-additions.md` and do not
create a new scanner, orchestration engine, asset database, graph authority, or
AI decision authority.

## Architecture Status

- Architecture state: `documented_direction`
- Gap disposition: accepted for phased implementation through existing subsystems
- Runtime change in this document: none
- Authority rule: deterministic product policy and authenticated human decisions
  remain authoritative; model output is advisory

The following capabilities are implementation targets, not implementation
claims.

---

## 1. Gap Disposition Summary

| Priority | Capability | Disposition | Primary owner in the existing stack |
| --- | --- | --- | --- |
| P0 | Evidence-Bound Gate Receipt | add | policy/approval/audit boundary |
| P0 | Coverage Completeness Gate | add | evaluation + Safe Output/Action Gate |
| P1 | Suppression, Exception, and Accepted-Risk Ledger | add | finding/detection/policy governance |
| P0/P1 | Candidate Entity Promotion Review Ledger | add | canonical evidence + scope governance |
| P1 | Bounded Candidate Reconsideration | add | evidence/candidate promotion lifecycle |
| P1 | Consistent Evidence Snapshot Contract | add | Control Plane read/query boundary |
| P1/P2 | Operational Activity and Evidentiary Lineage Separation | formalize | telemetry + provenance/audit boundaries |

These capabilities are cross-cutting. They should be implemented by extending
existing subsystem contracts rather than by creating a parallel workflow
platform.

---

## 2. Evidence-Bound Gate Receipt

### Gap

OpenAssetWatch already requires human approval for high-impact actions and
records policy, scope, evidence, and task state in multiple architecture areas.
It does not yet define one reusable contract that proves an approval or pass was
issued for the exact state that was reviewed.

A human approval becomes unsafe when the underlying object, evidence, policy,
destination, or action changes after review but the old approval remains
reusable.

Examples include:

- a remediation plan changing after approval;
- a detection rule changing after review;
- a connector configuration changing after a connection test;
- an external publication payload changing after sanitization review;
- a generated report changing after release approval;
- a Skill Pack, model, or tool manifest changing after qualification;
- a dashboard plan changing after a user chooses to persist it; and
- a security exception being reused against a materially different finding.

### Required capability

Every high-impact gate should be able to issue a versioned receipt bound to the
exact reviewed input.

Suggested logical contract:

```text
gate_receipt_id
schema_version

tenant_id
site_id

gate_type
subject_type
subject_id
subject_version
subject_digest

evidence_snapshot_id
evidence_snapshot_digest
policy_version
policy_digest

evaluation_bundle_version
evaluation_bundle_digest

destination_class
action_class
coverage_state

decision
  automatic_pass
  human_approved
  denied
  expired
  invalidated

approved_by_actor_type
approved_by_actor_id
approval_reason
approved_at
expires_at

reuse_policy
  one_time
  exact_state_until_expiry

invalidated_at
invalidation_reason
created_at
```

### Exact-state binding

A receipt is valid only when all security-relevant inputs still match.

At minimum, validation should compare:

- tenant and site;
- subject identity;
- subject version/digest;
- policy version/digest;
- evidence snapshot where the decision depends on evidence;
- destination and action class;
- required evaluation version;
- approval expiration; and
- any subsystem-specific dependency digests.

A material change invalidates the prior receipt.

```text
reviewed state A
  -> receipt for digest A
  -> state changes to B
  -> digest B != digest A
  -> receipt A invalid
  -> re-evaluation/re-approval required
```

The system must never silently rebind an old approval to new content.

### Automatic pass versus human approval

An automatic pass and a human exception are separate decision classes.

An automatic pass requires every deterministic release condition to succeed.
A human approval may be allowed only where the governing policy explicitly
permits an exception.

The receipt must preserve which path was used.

A human approval must not be represented as a clean automatic pass.

### Suggested initial uses

Implement the receipt contract first for:

1. controlled remediation execution;
2. external publication or projection;
3. detection/rule promotion;
4. Skill Pack and model promotion;
5. connector activation after material configuration change;
6. security exception/accepted-risk decisions; and
7. other high-impact write actions admitted by the Policy Compiler.

Low-impact read operations do not need gate receipts.

### Release blockers

Do not ship reusable approval when:

- the approved state cannot be deterministically identified;
- the approved payload can change without invalidating the receipt;
- the approval can cross tenant/site scope;
- the approval reason or actor is missing for a human exception; or
- an agent/model can create or extend its own approval.

---

## 3. Coverage Completeness Gate

### Gap

OpenAssetWatch already records partial task results, missing evidence, degraded
providers, and evaluation failures. It needs a cross-cutting rule that prevents
incomplete analysis from being interpreted as authorization.

Examples of incomplete analysis include:

- truncated input;
- task timeout;
- output-size limit reached;
- missing pages or records;
- unavailable required evidence;
- failed connector/source;
- unsupported parser or schema;
- stale required source;
- evaluation suite not fully executed;
- model/tool failure that removed a required stage; and
- query or context limits that prevented complete review.

### Required coverage states

Every gateable evaluation should report one of:

```text
complete
partial
truncated
stale_dependency
missing_dependency
unsupported
failed
unknown
```

Subsystems may add more specific states, but they must map to this common
security meaning.

### Core invariant

> Only `complete` coverage may create an automatic pass for a high-impact action.

This means:

```text
partial result != clean result
no returned finding != no finding exists
truncated evaluation != authorized action
unavailable dependency != safe state
```

### Exceptional human override

Some operational conditions may make complete automated evaluation impossible.
If policy allows a human override, it must be explicit and exceptional.

Required behavior:

- show exactly what was not evaluated;
- preserve the incomplete coverage state;
- require a human actor and reason;
- bind the approval to the exact subject/evidence digest;
- make the resulting gate decision `human_approved`, never `automatic_pass`;
- expire the override;
- prevent reuse after state drift; and
- retain a visible audit warning.

The override path must not be callable on an agent's own initiative.

### Product integration

The Coverage Completeness Gate should be shared by:

- Safe Output/Action Gate;
- report and intelligence publication;
- controlled remediation;
- detection/model/Skill Pack release gates;
- data import validation;
- connector activation checks;
- dashboard certification where applicable; and
- future security assurance workflows.

---

## 4. Suppression, Exception, and Accepted-Risk Ledger

### Gap

OpenAssetWatch detection architecture already anticipates suppression policies,
analyst feedback, and finding dispositions. A canonical exception record is
needed so suppression never means deletion and so accepted risk cannot become an
unbounded hidden bypass.

The platform must distinguish:

```text
finding resolved
finding suppressed from notification
finding excluded from one analytical view
finding accepted as risk
finding classified as false positive
finding temporarily waived
```

Those states are not interchangeable.

### Required capability

Create a deterministic, auditable ledger for suppressions and security
exceptions.

Suggested contract:

```text
exception_id
schema_version

tenant_id
site_id

exception_type
  notification_suppression
  finding_suppression
  false_positive_disposition
  accepted_risk
  temporary_waiver
  maintenance_exception

target_type
target_id
target_version
target_digest

match_scope
reason_code
reason_text
supporting_evidence_refs

requested_by
approved_by
created_at
approved_at
expires_at

maximum_severity
policy_version
exception_version

state
  proposed
  active
  expired
  revoked
  invalidated
  superseded

revalidation_triggers
last_revalidated_at
invalidated_at
invalidation_reason
```

### Invariants

1. The underlying finding/evidence remains queryable.
2. Suppression changes presentation/routing behavior; it does not rewrite the
   evidence as safe.
3. Exception matching is deterministic and explainable.
4. Broad wildcard exceptions require stronger authorization than narrow ones.
5. High-impact exceptions require an expiration/review date.
6. A materially changed target invalidates an exact-state exception.
7. A rule-version change may require exception revalidation.
8. A finding reopening with new evidence may require exception revalidation.
9. Tenant/site scope can never be widened implicitly.
10. AI may recommend an exception but cannot approve, activate, extend, or hide
    one.

### Critical/high-severity behavior

OpenAssetWatch should not adopt a blanket rule that a locally configured ignore
always permits high-severity risk to pass silently.

Instead, policy should define severity-specific requirements. For the highest
risk classes, suppression should remain visibly exceptional and should require
explicit human approval when used to authorize a high-impact action.

### Exception health

The Control Tower should be able to show:

- active exceptions;
- exceptions nearing expiry;
- invalidated exceptions;
- broad-scope exceptions;
- repeated use of one exception;
- exceptions associated with unresolved critical/high findings; and
- exceptions whose supporting evidence or target version changed.

---

## 5. Candidate Entity Promotion Review Ledger

### Gap

External intelligence and relationship architecture already permits candidate
entities and hypotheses that must not silently create or merge authoritative
assets. OpenAssetWatch needs a canonical decision record for how a candidate
moves from observation into an accepted managed-scope/entity relationship.

Without a promotion ledger, the platform can show a candidate but cannot fully
explain who or what accepted/rejected it, which evidence was considered, which
policy version applied, or whether it should be reconsidered later.

### Candidate states

Use a lifecycle such as:

```text
observed_candidate
  -> evaluating
  -> pending_review
  -> accepted
  -> rejected
  -> expired
  -> superseded
```

The accepted state should preserve how acceptance occurred:

```text
deterministically_accepted
human_accepted
```

A model-generated recommendation must not create `accepted` state by itself.

### Suggested logical contract

```text
candidate_promotion_id
schema_version

tenant_id
site_id
candidate_entity_type
candidate_value
candidate_digest

proposed_relationship_type
proposed_parent_entity_id
proposed_scope_id

source_refs
evidence_refs
evidence_snapshot_id

deterministic_score
confidence
recommendation_state
recommendation_reason_codes

status
  observed_candidate
  evaluating
  pending_review
  deterministically_accepted
  human_accepted
  rejected
  expired
  superseded

decision_policy_version
decision_policy_digest
decision_by_actor_type
decision_by_actor_id
decision_reason
decision_at

authoritative_entity_id
created_at
updated_at
expires_at
```

### Relationship to scope governance

Candidate promotion and recurring collection scope are separate decisions.

Accepting a candidate relationship must not automatically authorize unlimited
recurring collection around that entity.

For externally observed public entities:

```text
candidate observed
  -> relationship reviewed
  -> candidate accepted as associated entity
  -> scope verification policy
  -> verified recurring scope, if separately approved
```

A candidate can therefore be useful investigative context without becoming an
owned/managed scope root.

### Associated infrastructure

The platform should preserve a state for infrastructure that is relevant to an
asset but not proven to be owned or managed by the tenant.

Examples include shared hosting, SaaS endpoints, upstream gateways, public
service dependencies, certificate-related infrastructure, and externally
observed neighbors.

Associated infrastructure must not be silently merged into the tenant's
canonical managed asset inventory.

### Human review surface

The Control Tower review should show:

- candidate value/type;
- proposed relationship;
- evidence and source independence;
- freshness;
- conflicts;
- deterministic recommendation and reason codes;
- impact of accepting the candidate;
- whether acceptance affects recurring collection scope; and
- prior decisions involving the same candidate.

### Release blockers

Do not ship candidate promotion if:

- model confidence can directly create an authoritative asset;
- one weak source can silently widen recurring scope;
- rejected candidates lose their decision history;
- associated infrastructure is automatically treated as owned;
- tenant/site context is ambiguous; or
- acceptance cannot be traced to evidence and a policy/human decision.

---

## 6. Bounded Candidate Reconsideration

### Gap

A rejected or uncertain candidate may later receive new independent evidence.
The product needs a safe way to reconsider the decision without continuously
recursing through discovery candidates or repeatedly asking analysts to review
unchanged evidence.

### Required behavior

Reconsideration must be event-driven and evidence-driven.

Eligible triggers include:

- a new independent source;
- a material relationship change;
- newly verified scope evidence;
- a new authenticated local observation;
- a policy version that materially changes the decision criteria; or
- explicit analyst request.

Do not reconsider merely because time passed when no relevant evidence changed.

### Reconsideration record

Each promotion decision should retain:

```text
reconsideration_count
last_evidence_digest
last_decision_id
last_decision_at
next_review_after
```

A reconsideration creates a new decision version instead of mutating historical
reasoning in place.

### Anti-loop controls

- bounded automatic reconsideration count;
- per-candidate cooldown;
- evidence-digest deduplication;
- no new review when evidence is unchanged;
- no recursive candidate generation by the decision process;
- no model-triggered scope expansion; and
- human review backpressure/queue limits.

This capability is deliberately different from recursive asset discovery.
OpenAssetWatch records and reevaluates evidence; it does not give a candidate or
agent permission to expand its own scope.

---

## 7. Consistent Evidence Snapshot Contract

### Gap

OpenAssetWatch has canonical mutable records, history, evidence references,
temporal projections, dashboards, reports, AI context assembly, and export
plans. It needs a reusable consistency contract so one analytical result does
not accidentally combine incompatible moments in time.

Examples:

- a report reads an asset before reclassification but findings after
  reclassification;
- a multi-panel dashboard compares counts produced from different state
  generations without saying so;
- an AI analysis cites evidence that changed midway through context assembly;
- an external projection contains a mixture of old and new canonical versions;
- a human approves a plan against evidence that changes before execution.

### Required capability

Create a lightweight snapshot/reference contract for operations that need a
stable read view.

Suggested logical metadata:

```text
evidence_snapshot_id
schema_version

tenant_id
site_scope
snapshot_purpose

requested_at
snapshot_time
consistency_watermark

canonical_schema_version
policy_version

included_entity_domains
included_entity_versions
source_high_water_marks

evidence_cutoff
freshness_summary
coverage_state
missing_or_degraded_sources

record_count
truncated
snapshot_digest
expires_at
created_at
```

The implementation does not require copying the whole database for every
snapshot. Depending on the operation, the platform may use:

- a database transaction/MVCC snapshot;
- immutable canonical record/version references;
- a materialized analytical snapshot;
- a temporal watermark; or
- a persisted evidence bundle already defined by an investigation/task.

### Snapshot consumers

Use snapshot semantics where consistency matters, including:

- investigation evidence bundles;
- AI context assembly;
- certified reports;
- controlled remediation planning/execution;
- external intelligence publication;
- long-running exports;
- rule/model evaluation fixtures; and
- dynamic dashboard panels when cross-panel consistency is required.

Interactive live dashboards may intentionally show newer data, but they must
expose panel/data freshness and should not present mixed-time comparisons as a
single atomic snapshot unless a shared watermark was used.

### Snapshot versus authority

A snapshot is a stable read reference, not a new source of truth.

Canonical relational state and immutable/history records remain authoritative.
Snapshots should be expirable and rebuildable where possible.

### Release blockers

Do not claim point-in-time consistency when:

- the relevant read set has no shared watermark/version;
- required sources were unavailable without being disclosed;
- the snapshot was truncated without a visible coverage state; or
- a later action uses a different evidence state while reusing the old gate
  receipt.

---

## 8. Operational Activity and Evidentiary Lineage Separation

### Gap

OpenAssetWatch already distinguishes audit, operational telemetry, evidence,
findings, and task state. This separation should become explicit across future
workers, candidate-promotion flows, dynamic dashboards, AI/MCP, and external
connectors so operational events do not accidentally become evidentiary facts.

### Two related but separate records

#### Operational activity

Operational activity answers:

- what is running;
- which stage/worker is active;
- progress and queue state;
- retry and timeout information;
- cache hit/miss;
- resource use;
- temporary errors; and
- user-visible progress messages.

It belongs in operational telemetry/task activity records.

#### Evidentiary lineage

Evidentiary lineage answers:

- which source produced a fact;
- which normalization/transformation created a canonical value;
- which evidence supported a relationship/finding;
- which decision promoted/rejected a candidate;
- which policy/version governed the decision; and
- which immutable records can reproduce the conclusion.

It belongs in evidence/provenance/decision records.

### Core invariant

> Logs and progress events are not automatically evidence.

A worker message such as `candidate accepted` cannot establish an authoritative
relationship unless the corresponding evidence and promotion decision records
were committed.

Likewise, deleting or rotating operational logs must not destroy evidence
lineage required to explain canonical state.

### Correlation

Both record classes should share stable correlation metadata where available:

```text
operation_id
parent_operation_id
linked_operation_ids
task_id
run_id
actor_id
tenant_id
site_id
```

This permits the Control Tower to move from a canonical fact to the operational
run that produced it without conflating the two stores.

---

## 9. Relationship to Existing OpenAssetWatch Architecture

### Canonical asset/evidence layer

Owns:

- candidate entity records;
- candidate-promotion history;
- evidence snapshots or version references;
- canonical relationship outcomes; and
- lineage links.

It does not receive model-authored authoritative conclusions.

### External intelligence enrichment

Uses candidate promotion for uncertain external entities and relationships.
Existing verified-scope rules remain mandatory for recurring external
collection.

### Connector and evidence ingress

Uses Coverage Completeness Gate for imports/connection validation where a
complete result is required, and creates transformation/evidence lineage rather
than relying on runtime logs.

### Platform Task Orchestrator

Persists waiting-for-approval state, gate receipt references, snapshot
references, coverage state, and pending candidate decisions in resumable task
state.

A task resume must not lose pending human-review state.

### Detection, finding, alert, and case governance

Uses the exception ledger for suppression/waiver/accepted-risk states while
retaining the underlying evidence/finding and historical decisions.

### AI/MCP and Agent Runtime

May:

- explain evidence snapshots;
- recommend a candidate-promotion decision;
- identify incomplete coverage;
- draft an exception justification; and
- explain why a gate failed.

May not:

- manufacture a clean coverage state;
- approve its own exception;
- create or extend a high-impact gate receipt;
- promote a candidate solely from model confidence;
- relabel associated infrastructure as owned; or
- convert operational logs into evidence.

### Safe Output/Action Gate

Validates gate receipt, snapshot/digest match, coverage state, policy version,
destination, and expiration immediately before a high-impact action.

Validation occurs at execution time, not only when approval was originally
recorded.

---

## 10. Suggested Implementation Sequence

### Phase 1 - Decision integrity foundations

Implement:

- shared digest/version helper contract;
- Evidence-Bound Gate Receipt;
- Coverage Completeness state vocabulary;
- gate validation and invalidation tests.

Initial targets should be one or two existing approval-gated workflows before
expanding the pattern platform-wide.

### Phase 2 - Exception governance

Implement:

- exception/suppression schema;
- deterministic matching;
- expiry/revocation/revalidation;
- Control Tower visibility;
- separation between finding lifecycle and notification/presentation state.

### Phase 3 - Candidate promotion lifecycle

Implement:

- candidate-promotion records;
- pending-review queue;
- deterministic acceptance/rejection where evidence rules are strong enough;
- human review;
- associated-infrastructure state;
- bounded reconsideration triggered by new evidence.

Integrate first with external-intelligence candidate relationships rather than
expanding core local discovery behavior.

### Phase 4 - Consistent read snapshots

Implement:

- snapshot metadata/reference contract;
- query/read watermark support for selected operations;
- report/AI/investigation integration;
- gate-receipt binding to evidence snapshots.

### Phase 5 - Lineage/activity hardening

Implement:

- explicit operational-event versus evidence-lineage schemas;
- shared operation correlation IDs;
- retention rules that preserve evidentiary lineage independently from verbose
  runtime logs;
- Control Tower drilldown between decisions, evidence, and producing operations.

---

## 11. Cross-Cutting Acceptance Criteria

A capability in this document is not complete until tests show that:

- changing an approved subject invalidates its exact-state receipt;
- changing required policy/evidence invalidates or re-evaluates the receipt;
- incomplete/truncated analysis cannot create an automatic pass;
- human override remains visibly distinct from clean automated validation;
- an expired/revoked exception no longer suppresses matching state;
- suppression does not delete the underlying finding/evidence;
- candidate rejection history survives later reconsideration;
- unchanged candidate evidence does not repeatedly reopen human review;
- model recommendations cannot create authoritative candidate acceptance;
- associated infrastructure is not silently merged into managed inventory;
- snapshots reveal degraded/missing sources and truncation;
- a high-impact action refuses a stale snapshot/receipt combination;
- operational logs cannot independently establish canonical evidence; and
- tenant/site boundaries survive every approval, exception, snapshot, and
  candidate-promotion path.

---

## 12. Explicitly Rejected or Already-Covered Patterns

The research that exposed these gaps also contained capabilities that should not
be added to OpenAssetWatch or are already covered by stronger existing designs.

### Reject

Do not add:

- a high-impact product gate that fails open on internal scanner/evaluator
  failure;
- reusable human approval that is not bound to exact state;
- an ignore/suppression mechanism that deletes evidence or makes critical risk
  disappear from audit/history;
- agent-initiated approval of unresolved high-impact findings;
- silent authorization when analysis is truncated or partial;
- model-only ownership or asset-promotion authority;
- recursive self-expansion of discovery scope;
- automatic promotion of associated/shared infrastructure into managed assets;
- broad live-host crawling or active discovery as a side effect of candidate
  review;
- provider-specific cloud scanning as a required OpenAssetWatch dependency;
- embedding reusable customer secrets in MCP/client configuration bundles; or
- treating operational progress logs as canonical evidence.

### Already covered; do not duplicate

Do not create new subsystems for:

- MCP local/remote transports and toolset filtering;
- scoped OAuth/service-account authentication direction;
- credential brokering and secret isolation;
- Platform Task Orchestrator leases, heartbeats, retries, and checkpoints;
- canonical asset upsert/evidence fusion;
- external-intelligence verified scope;
- deterministic findings and risk;
- Agent Run Ledger and AI audit telemetry; or
- graph/search projections as non-authoritative derived views.

Extend those existing contracts with the gaps above.

---

## 13. Target Stack View

```text
Authenticated Evidence / Approved External Observations
                         |
                         v
              Canonical Evidence Layer
                         |
             +-----------+-----------+
             |                       |
             v                       v
   Candidate Entity Queue     Canonical Asset State
             |                       |
             v                       v
 Candidate Promotion Ledger   Relationship / Finding Logic
             |                       |
      human/deterministic             |
          decision                    |
             +-----------+-----------+
                         |
                         v
             Consistent Evidence Snapshot
                         |
                         v
          Evaluation / Coverage Completeness
                         |
                         v
             Policy and Safe Action Gate
                         |
                 +-------+-------+
                 |               |
                 v               v
          automatic pass   human exception
                 |               |
                 +-------+-------+
                         |
                         v
             Evidence-Bound Gate Receipt
                         |
                         v
             Exact-State Revalidation
                         |
                         v
                Approved Action

Suppression / Accepted-Risk Ledger changes routing and presentation policy but
never deletes the underlying evidence or finding.

Operational activity is correlated with this flow, but it remains separate from
evidentiary lineage.
```

## Final Design Rule

OpenAssetWatch must be able to answer all of these questions for a high-impact
or ambiguous decision:

1. What exact state was evaluated?
2. Was the evaluation complete?
3. Which evidence and policy were used?
4. Was the result automatic or a human exception?
5. Who approved it and why?
6. Has the underlying state changed since approval?
7. Was anything suppressed, waived, or accepted as risk?
8. Why was a candidate asset/relationship accepted or rejected?
9. Can the read view be reproduced at a defined point in time?
10. Which operational run produced the records without treating its logs as the
    evidence itself?

If the platform cannot answer those questions deterministically, the decision
should not be considered fully governed.