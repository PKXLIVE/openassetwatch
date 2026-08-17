# Agent Investigation Control Loop

- **Status:** Accepted design; not yet implemented
- **Decision:** `docs/architecture/decisions/0003-native-agent-investigation-and-temporal-intelligence.md`

## Purpose

The Agent Investigation Control Loop adds deeper, multi-perspective analysis to
OpenAssetWatch without changing the authority of the current deterministic
platform.

It is designed for findings, changes, data-quality issues, and analyst questions
that benefit from more than one bounded line of inquiry. The loop does not
replace the AI Advisor. It adds OpenAssetWatch-owned control state that can
coordinate specialist analysis and return a verified, evidence-backed advisory
result to the Advisor or investigation UI.

## Authority boundary

The existing authority order remains unchanged:

```text
authenticated normalized evidence
  -> deterministic classification and matching
  -> deterministic findings and attention scoring
  -> bounded investigation and AI explanation
  -> human review
```

The investigation layer may create specialist task artifacts, hypotheses,
contradictions, evidence requests, verification results, remediation
recommendations, concise reasoning summaries, and human-reviewed investigation
annotations.

It may not directly create or modify authoritative asset identity,
classification, vulnerability applicability, deterministic findings, the
Operational Attention Score, suppressions, asset merge/split state, collector
or sensor policy, or remediation actions.

## Runtime shape

```text
finding / change / analyst question / data-quality trigger
                         |
                         v
              deterministic triage
             scope + policy + budget
                         |
            +------------+------------+
            |            |            |
            v            v            v
       specialist A specialist B specialist C
       isolated task  isolated task  isolated task
       context        context        context
            |            |            |
            +------------+------------+
                         |
                         v
              deterministic correlation
             claims + conflicts + gaps
                         |
                         v
                verification stage
                         |
              +----------+----------+
              |                     |
          supported          unsupported /
                             inconclusive
              |                     |
              v                     +----> triage / request evidence
          human review
              |
              v
   saved advisory conclusion / recommendation /
   candidate rule or workflow improvement
```

The coordinator is product code, not an LLM persona. It owns allowed state
transitions and never delegates scope, authorization, or finding authority to a
model.

## Investigation triggers

Initial trigger classes should include:

- `finding_review`
- `asset_change_review`
- `classification_conflict_review`
- `vulnerability_match_review`
- `security_coverage_review`
- `data_quality_review`
- `temporal_deviation_review`
- `advisor_question`

A trigger does not automatically justify a multi-specialist run. Deterministic
triage decides whether a single bounded explanation is sufficient or whether
parallel investigation adds value.

## Investigation control state

The system of record for a run is an OpenAssetWatch-owned control object.
Suggested fields include:

- `schema_version`
- `investigation_id`
- `trigger_type` and `trigger_id`
- `tenant_id` when applicable
- `site_id`
- `approved_scope_id`
- `objective`
- `status`
- `evidence_snapshot_at`
- `policy_version`
- finite task/step/time/provider budgets
- `required_gates`
- `next_transition`
- `stop_reason`

Model conversation history must never be the only copy of this state.

## Deterministic triage

Triage answers four questions before any specialist runs:

1. Is the request supported by current product scope?
2. What evidence is allowed for this run?
3. Which specialist roles add distinct value?
4. What verification and human-review gates are required?

Triage inputs should be structured product facts such as trigger type, evidence
classes, site, asset category, finding type, confidence, freshness, conflict
state, and available capabilities.

The first implementation should use reviewed rules rather than free-form model
routing. A model may later propose a routing suggestion, but product code must
validate the suggestion against an allowlisted route table.

## Specialist task packet

Every specialist receives a bounded task packet rather than unrestricted access
to the investigation. The packet should contain:

- stable task and investigation IDs;
- approved specialist role;
- approved Skill Pack and version;
- task objective;
- allowed evidence IDs;
- allowed tool IDs;
- exact site/asset scope;
- maximum steps and evidence records; and
- a task deadline.

A task packet never contains permission to widen its own asset IDs, site,
network targets, URLs, tools, or evidence classes.

## Initial specialist roles

### Asset Identity and Classification Investigator

Reviews conflicting identity evidence, hostname/address/platform changes,
duplicate or ambiguous asset hypotheses, weak versus strong identity anchors,
and stale evidence. It may recommend a manual merge/split review but cannot
perform one.

### Exposure and Vulnerability Investigator

Reviews observed services, software/firmware identity, vulnerability-match
prerequisites, version uncertainty, and missing or contradictory applicability
evidence. It cannot declare a vulnerability confirmed when the deterministic
matcher has not done so.

### Behavior and Change Investigator

Reviews first/last seen changes, network placement changes, service appearance
or disappearance, collector/sensor health changes, and evidence that temporally
precedes a finding. Timing alone is not causation.

### Security Coverage Investigator

Reviews EDR, MDM, vulnerability-agent, logging, and other management coverage,
including recent loss or gain of tooling evidence and unsupported conclusions
caused by stale collectors.

### Data Quality Investigator

Reviews malformed or incomplete records, stale collection, contradictory
identifiers, normalization gaps, impossible field combinations, and evidence
source health.

### IoT and OT Context Investigator

Reviews embedded or special-purpose device evidence, conservative device-type
hypotheses, safety-sensitive context, and passive evidence quality. This role
cannot initiate active interrogation.

### Remediation Planner

Consumes verified or clearly labeled unresolved hypotheses and creates a
recommended sequence, prerequisites, rollback considerations, stop conditions,
and verification steps. It does not execute remediation.

### Report Writer

Converts accepted evidence and investigation outcomes into bounded audience-
appropriate summaries while preserving the same underlying facts.

### Independent Verifier

Receives a hypothesis and the minimum evidence needed to test it. It should not
receive the original specialist's hidden reasoning. Its task is to decide
whether the stated conclusion is supported by the evidence contract.

## Context isolation

First-pass specialists should not share conclusions with one another. This
reduces anchoring and correlated error.

Allowed shared context:

- investigation objective;
- scope;
- server-issued evidence;
- product policy;
- approved Skill Pack instructions; and
- deterministic facts already authoritative before the run.

Not shared during first-pass investigation:

- another specialist's hypothesis;
- another specialist's confidence;
- another specialist's recommendation; or
- raw provider conversation state.

Later correlation, verification, and report stages may consume typed specialist
outputs because those stages are explicitly designed to compare them.

## Specialist output contract

A specialist response should contain only bounded typed fields such as:

- task status;
- observations;
- hypotheses;
- supporting evidence IDs;
- contradiction evidence IDs;
- confidence;
- verification requirement;
- missing evidence;
- recommended next step; and
- concise reasoning summary.

The schema must reject unknown evidence IDs and unsupported fields.

## Hypothesis lifecycle

Suggested states:

```text
proposed
  -> correlated
  -> verification_required
  -> supported | unsupported | inconclusive
  -> human_reviewed
  -> archived
```

Additional transitions should support `rejected`, `conflicted`,
`evidence_requested`, and `cancelled`.

`unsupported` and `inconclusive` are important outcomes. They must not be
collapsed into success or silently dropped.

## Deterministic correlation

The correlation stage is code, not a free-form synthesis prompt.

It should:

- validate all evidence IDs;
- normalize hypothesis type and affected entity IDs;
- group substantially identical claims;
- preserve conflicting claims;
- calculate source/role diversity metadata;
- detect missing required evidence classes;
- determine which hypotheses require verification; and
- produce a bounded correlation packet for the next stage.

Agent agreement is not a confidence multiplier by itself.

## Independent verification

Verification should be narrower than investigation. Allowed result values are:

- `supported`
- `unsupported`
- `inconclusive`

Every verification result should include evidence IDs, failed checks, missing
evidence, confidence, and a concise reasoning summary.

A verifier cannot promote its result into an authoritative finding. It changes
only investigation state.

## Human review

Human review occurs after verification when the investigation is being saved or
used to guide consequential work.

The reviewer should see the objective, trigger, affected assets/sites, evidence,
conflicts, specialist summaries, verification status, unresolved uncertainty,
recommended action, and rollback/stop conditions where relevant.

Approval may save an investigation annotation, remediation plan, or candidate
rule proposal. It does not bypass the deterministic subsystem that owns the
actual finding or action.

## Agent Run Ledger

The ledger is an append-only event history for the investigation control plane.
Suggested event types include:

- `investigation_started`
- `triage_completed`
- `task_dispatched`
- `task_started`
- `evidence_accessed`
- `tool_requested`
- `tool_allowed`
- `tool_denied`
- `guardrail_triggered`
- `task_completed`
- `task_failed`
- `hypothesis_proposed`
- `correlation_completed`
- `verification_started`
- `verification_completed`
- `evidence_requested`
- `human_review_recorded`
- `budget_exhausted`
- `run_cancelled`
- `run_resumed`
- `investigation_completed`

Each event should include stable IDs, timestamp, actor class, event type,
bounded entity/evidence references, relevant contract/policy version, outcome,
and sanitized metadata.

The ledger must not require private chain-of-thought, hidden prompts, complete
provider payloads, provider credentials, authorization headers, secrets, raw
packet contents, or unrelated customer data.

## Budgets and stop conditions

Every investigation is finite. The coordinator should enforce maximum
specialist tasks, parallel tasks, per-task steps, total steps, evidence
records/bytes, wall-clock time, provider/resource budget, cancellation, and
verification retries.

A run stops when the objective is verified and reviewed, required evidence is
unavailable, scope becomes invalid, policy changes invalidate the run, the user
cancels, no approved provider path remains, budget is exhausted, or repeated
verification cannot resolve the hypothesis.

Budget exhaustion is an explicit inconclusive or blocked condition, not a reason
to fabricate closure.

## Tool policy

Initial specialists should be read-only. Example tool families:

- `asset.read`
- `asset.history.read`
- `evidence.read`
- `classification.read`
- `component.read`
- `vulnerability.read`
- `finding.read`
- `risk_factors.read`
- `sensor.read`
- `collector.read`
- `changes.read`
- `temporal.read`
- `report.compose`

The coordinator supplies exact object scopes. A task cannot substitute a raw
URL, hostname, IP, CIDR, SQL expression, filesystem path, or command for an
approved object identifier.

## Failure and recovery

Investigation state should be resumable after process restart or provider
failure.

Requirements include idempotent task dispatch, immutable or superseded completed
outputs, duplicate-safe ledger writes, scope/policy revalidation on resume,
explicit stale-evidence handling, provider-version recording, cancellation
semantics, and inspectable partial runs.

## Privacy and provider boundaries

Only the minimum bounded evidence required for a task should enter provider
context. Provider-facing projections must exclude secrets, authorization data,
arbitrary filesystem content, raw packet payloads, unrelated assets/sites,
hidden product prompts, unrestricted metadata, and data outside configured
external-processing policy.

A local-only configuration must never automatically fail over to a hosted
provider.

## Target API surface

Future API design may include:

- `POST /api/v1/investigations`
- `GET /api/v1/investigations/{investigation_id}`
- `GET /api/v1/investigations/{investigation_id}/ledger`
- `GET /api/v1/investigations/{investigation_id}/tasks`
- `GET /api/v1/investigations/{investigation_id}/hypotheses`
- `POST /api/v1/investigations/{investigation_id}/cancel`
- `POST /api/v1/investigations/{investigation_id}/review`

These names are design targets, not implemented routes.

## Target UI

The first UI should emphasize evidence and state rather than agent theater.
Recommended panels are objective/status, trigger summary, evidence timeline,
parallel task status, hypotheses/conflicts, verification result, missing
evidence, recommended next step, human review, and a ledger/timeline view.

The UI must not imply that multiple agents agreeing makes a conclusion true.

## Initial implementation order

1. Define schemas and state transitions.
2. Implement deterministic triage with a small role table.
3. Implement deterministic/synthetic specialist fixtures before live models.
4. Implement append-only ledger and idempotent task state.
5. Implement deterministic correlation.
6. Implement verifier contract and state transitions.
7. Add read-only UI/API projections.
8. Add first approved Skill Packs.
9. Add provider adapters only after evaluation gates pass.
10. Add temporal-deviation investigations after the temporal baseline exists.

## Explicit non-goals

This design does not approve autonomous remediation, unrestricted agent-to-agent
conversation, recursive specialist spawning, arbitrary shell/filesystem access,
active network scanning, credential access, exploit execution, packet injection,
direct writes to findings/scores, provider-controlled permissions, provider
session state as the system of record, or model-generated scope expansion.

## Documentation-only status

This document defines the accepted design target. It does not claim that the
investigation coordinator, specialist runtime, ledger, verifier, APIs, or UI are
implemented.