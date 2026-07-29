# Detection, Feedback, and Response Governance Architecture

## Purpose

This document defines a future, provider-neutral architecture for managing OpenAssetWatch detection logic, analyst feedback, model-assisted analysis, rule quality, controlled recommendations, and post-change verification.

It fills gaps between evidence collection, deterministic findings, analyst review, continuous improvement, and safe response planning.

The design preserves these project principles:

- deterministic findings remain the source of truth
- AI is optional and advisory
- analyst decisions remain distinct from AI predictions
- rule and model changes require evidence and review
- response is recommendation-first
- high-impact actions require explicit human control
- evaluation claims must be reproducible
- feedback must not become an untrusted retraining channel

## Scope

The architecture covers:

- detector and rule lifecycle
- detection quality and tuning
- coverage and drift analysis
- reproducible evaluation
- analyst feedback integrity
- training-data eligibility
- candidate model evaluation and promotion
- AI-generated rule drafts
- response recommendation plans
- blast-radius and approval policy
- dry-run and post-change verification
- defensive what-if analysis

The architecture does not authorize:

- autonomous remediation
- offensive attack execution
- exploitation
- credential collection
- unrestricted active scanning
- automatic model promotion based on one metric
- training directly on unreviewed analyst feedback

---

## 1. Overall Lifecycle

```text
Evidence and Normalized Observations
                |
                v
      Deterministic Detection Rules
                |
                v
       Candidate Findings and Alerts
                |
                v
     Validation, Correlation, and Cases
                |
                v
          Analyst Disposition
                |
       +--------+---------+
       |                  |
       v                  v
Detection Quality     Feedback Review
and Tuning                |
       |                  v
       |         Eligible Training Records
       |                  |
       |                  v
       |          Candidate Model Build
       |                  |
       |                  v
       |       Evaluation and Promotion Gate
       |                  |
       +--------+---------+
                |
                v
      Updated Rules or Models
                |
                v
      Shadow, Canary, and Monitoring
                |
                v
        Rollback or Promotion
```

Response recommendations follow a separate governed path:

```text
Validated Case or Exposure Path
                |
                v
     Candidate Defensive Controls
                |
                v
  Impact, Safety, and Blast-Radius Scoring
                |
                v
      Approval and Dry-Run Policy
                |
                v
   Recommendation or Controlled Action
                |
                v
        Post-Change Verification
                |
                v
       Confirm, Adjust, or Roll Back
```

---

## 2. Detection Content Lifecycle

### 2.1 Detection Definition

A detection definition should include:

- `detection_id`
- `namespace`
- `name`
- `description`
- `version`
- `status`
- `owner`
- `tenant_scope`
- `source`
- `rule_language`
- `rule_body_ref`
- `input_schema`
- `required_fields`
- `key_fields`
- `severity`
- `confidence`
- `category`
- `technique_mappings`
- `data_source_requirements`
- `expected_volume`
- `suppression_policy`
- `threshold_policy`
- `test_fixture_refs`
- `created_at`
- `updated_at`
- `reviewed_at`
- `reviewed_by`
- `digest`
- `provenance`

### 2.2 Detection States

Suggested lifecycle states:

- `draft`
- `proposed`
- `validating`
- `backtesting`
- `awaiting_review`
- `approved`
- `shadow`
- `active`
- `tuning_required`
- `disabled`
- `deprecated`
- `rolled_back`
- `rejected`

### 2.3 Promotion Flow

```text
Draft
  |
  v
Schema and Syntax Validation
  |
  v
Fixture Evaluation
  |
  v
Historical Backtest
  |
  v
Coverage and Noise Review
  |
  v
Human Approval
  |
  v
Shadow Mode
  |
  v
Limited Promotion
  |
  v
Active
```

A rule should not move directly from AI generation to active enforcement.

### 2.4 Detection Proposal Record

A proposal should preserve:

- the base version
- the proposed version
- the author or generating agent
- reason for change
- expected benefit
- expected alert-volume change
- test results
- backtest results
- affected tenants or sites
- reviewer decisions
- promotion state
- rollback target

### 2.5 Platform and Tenant Definitions

Built-in detection content and tenant-specific content must remain separate.

- Platform definitions may be visible to tenants.
- Tenant users must not mutate a shared platform definition directly.
- A tenant may create an override or derivative version in its own namespace.
- Overrides must record their base rule and divergence.
- Deleting a tenant override should reveal the approved platform behavior again.

---

## 3. Deterministic Detection Quality Workbench

### Purpose

The quality workbench should identify which detections need attention without relying on a model to decide every recommendation.

### 3.1 Quality Inputs

Useful per-rule metrics include:

- total hits
- unique affected assets
- confirmed true positives
- confirmed false positives
- unknown or unreviewed results
- false-positive rate
- analyst correction rate
- confidence
- last triggered time
- last reviewed time
- average case priority
- service-target impact
- suppression count
- threshold changes
- data-source availability
- missing-field rate
- schema mismatch rate
- execution errors
- evaluation coverage

### 3.2 Suggestion Lanes

A fixed precedence ladder may produce one primary recommendation per rule.

Suggested lanes:

- `disable_candidate`
- `suppression_candidate`
- `threshold_review`
- `confidence_review`
- `missing_data_review`
- `stale_rule_review`
- `coverage_gap`
- `healthy`

The classifier should be a pure, testable function whose thresholds are versioned and shared by the implementation, tests, and documentation.

### 3.3 Example Deterministic Logic

```text
if false_positive_rate is very high and confidence is low:
    disable_candidate
else if false_positive_rate exceeds suppression threshold:
    suppression_candidate
else if false_positive_rate is elevated and hit count is sufficient:
    threshold_review
else if required fields are often missing:
    missing_data_review
else if confidence is low and hit count is sufficient:
    confidence_review
else if the rule is old and has not fired recently:
    stale_rule_review
else:
    healthy
```

Exact thresholds should be configurable and benchmarked. They should not be copied from another implementation without local evidence.

### 3.4 Bounded Projection

The workbench should cap how many rules are evaluated per request and prioritize the most operationally significant records first.

This prevents a very large imported rule library from overloading the application.

### 3.5 Tuning Actions

Initial future actions may include:

- acknowledge recommendation
- dismiss recommendation with reason
- disable tenant rule
- create suppression draft
- raise or lower threshold draft
- request confidence review
- schedule backtest
- create replacement proposal

A tuning recommendation should not silently mutate a rule.

### 3.6 Version and Audit

Every rule mutation should:

- increment the rule version
- record before and after state
- record actor, tenant, time, and reason
- retain the rollback version
- invalidate or schedule affected evaluations
- append an audit event

Dismissals should remain visible in audit views and should be reversible.

### 3.7 Automatic Tuning

An `auto_tune_eligible` flag may be used as an opt-in marker for future work. Enabling the flag must not immediately mutate the detection.

Any future automatic tuning must have:

- bounded parameter ranges
- tenant opt-in
- backtest gate
- shadow period
- rollback target
- operational budget
- audit trail
- human override

---

## 4. Coverage and Drift

### 4.1 Coverage Dimensions

OpenAssetWatch may measure coverage across:

- asset classes
- operating systems
- sites or segments
- collector capabilities
- evidence sources
- vulnerability classes
- threat-technique categories
- security controls
- business criticality
- investigation playbooks

Coverage must distinguish:

- no rule exists
- a rule exists but required telemetry is missing
- telemetry exists but the rule has never been tested
- the rule is tested but disabled
- the rule is active but stale
- the rule is active and validated

### 4.2 Coverage Snapshot

A periodic coverage snapshot should include:

- snapshot identifier
- tenant or deployment scope
- rule set version
- evidence-source inventory
- covered categories
- uncovered categories
- missing telemetry dependencies
- stale rules
- newly added gaps
- resolved gaps
- generated_at

### 4.3 Drift Categories

- detector output drift
- false-positive drift
- alert-volume drift
- feature distribution drift
- schema drift
- data-source drift
- asset-population drift
- model calibration drift
- coverage drift
- playbook completion drift

### 4.4 Drift Response

Drift should produce a review item, not an automatic model or rule replacement.

A drift finding should identify:

- what changed
- expected baseline
- current value
- statistical or deterministic method
- affected rules or models
- confidence
- data-quality concerns
- recommended validation

---

## 5. Reproducible Evaluation Harness

### Purpose

OpenAssetWatch should maintain a public or inspectable evaluation harness for deterministic substrate behavior and, separately, for live AI behavior.

### 5.1 Never Mix Evaluation Classes

The following must be reported separately:

#### Deterministic Substrate Evaluation

Measures:

- normalization
- correlation
- evidence selection
- rule matching
- report templates
- response-plan templates
- playbook mapping
- schema and coverage checks

It does not measure live model accuracy.

#### Live AI Evaluation

Measures:

- model-assisted classification
- evidence grounding
- structured-output validity
- latency
- token use
- cost
- safety denials
- tool-selection quality
- user-correction rate

It must not be presented as deterministic system performance.

### 5.2 Evaluation Corpus

A useful corpus should include:

- versioned synthetic incidents
- backing synthetic telemetry
- benign controls
- ambiguous cases
- incomplete-evidence cases
- duplicated signals
- conflicting evidence
- stale evidence
- cross-tenant negative tests
- prompt-injection fixtures
- expected case and finding outputs
- expected playbook coverage

Each synthetic incident should have at least one supporting telemetry record rather than existing only as a prose description.

### 5.3 Metrics

Deterministic metrics may include:

- normalization success
- deduplication accuracy
- correlation precision and recall
- finding schema validity
- evidence-reference completeness
- coverage mapping
- playbook completion
- report-field completeness
- false-positive reduction on a controlled noisy stream

Live AI metrics may include:

- structured-output success
- grounded-claim precision
- unsupported-claim rate
- human correction rate
- classification precision and recall
- calibration error
- latency percentiles
- tokens per task
- cost per validated result
- policy-denial correctness

### 5.4 Per-Case and Per-Template Reporting

Report both:

- per-case averages
- per-template or per-scenario macro averages

Macro reporting prevents a large number of nearly identical cases from hiding one broken scenario type.

### 5.5 Provenance

Every evaluation result should record:

- code commit
- dataset version and digest
- rule set version
- model version or digest
- prompt and policy version
- runtime profile
- execution mode
- hardware profile described generically
- test start and end time
- measured versus estimated metrics

### 5.6 Historical Results

Results should be append-oriented and queryable by software version. Replacing the latest result must not erase historical performance.

### 5.7 CI Gates

A lightweight deterministic subset should run on each relevant change.

Longer live-agent evaluations may run on a scheduled cadence or release candidate.

CI must fail closed for required gates. Permissive patterns that ignore failed tests must not be treated as release validation.

### 5.8 Honest Claims

OpenAssetWatch must not present:

- synthetic results as production measurements
- deterministic self-consistency as live model accuracy
- directional simulation as breach probability
- estimated cost as actual spend
- one dataset's performance as universal effectiveness

---

## 6. Analyst Feedback Model

### 6.1 Separate Feedback From Prediction

The original prediction, the AI recommendation, and the analyst label should all remain available.

Suggested feedback fields:

- `feedback_id`
- `tenant_id`
- `case_id`
- `finding_id`
- `signal_id`
- `prediction_id`
- `analyst_id`
- `analyst_role`
- `label_type`
- `label_value`
- `confidence`
- `reason`
- `evidence_refs`
- `created_at`
- `review_state`
- `reviewed_by`
- `reviewed_at`
- `withdrawn_at`
- `withdrawal_reason`
- `training_eligible`
- `training_exclusion_reason`

### 6.2 Feedback Types

- verdict correction
- severity correction
- impact correction
- priority correction
- confidence correction
- false-positive disposition
- missed finding
- bad correlation
- incomplete report
- unsafe recommendation
- incorrect evidence reference
- detector tuning suggestion

### 6.3 Feedback Trust Levels

Suggested trust states:

- `unreviewed`
- `single_analyst`
- `peer_reviewed`
- `supervisor_approved`
- `adjudicated`
- `withdrawn`
- `rejected`

Only feedback meeting the configured trust requirement should be eligible for model or rule improvement.

### 6.4 Poisoning and Quality Controls

The system should check for:

- unusual label volume from one identity
- abrupt label distribution changes
- repeated identical reasons
- contradictory labels on the same case
- labels without supporting evidence
- labels submitted after relevant evidence changed
- cross-tenant contamination
- automated account feedback without review
- feedback from compromised or disabled identities
- class imbalance amplification

Critical labels may require peer review or adjudication before training eligibility.

### 6.5 Retraction and Correction

Feedback must be retractable. A retraction should add a new record or state transition rather than deleting the original label silently.

---

## 7. Training-Data Eligibility

### 7.1 Evidence Quality

A training record should declare:

- full or partial feature availability
- feature-contract version
- source data types
- missing fields
- imputed fields
- inferred labels
- analyst review state
- data age
- tenant scope
- consent or policy eligibility

### 7.2 Degraded Feature Data

Records created from missing or approximate features must be tagged explicitly.

Default policy:

> Do not use degraded, synthetic, or heavily imputed production records for model promotion unless a specific experiment allows them and reports them separately.

A simple metadata-based approximation must not be treated as equivalent to a complete network-flow or host-event feature vector.

### 7.3 Feature Contract Registry

Every model should reference a versioned feature contract containing:

- ordered feature names
- types
- units
- allowed ranges
- required or optional state
- missing-value policy
- normalization method
- source mapping
- contract digest

Model loading must fail if the runtime feature contract is incompatible with the model artifact.

### 7.4 Data Splits

Evaluation should use:

- training split
- validation split
- holdout test split
- temporal holdout where relevant
- environment or tenant holdout where policy permits
- adversarial or edge-case set

Records derived from the same incident or template should not leak across splits.

---

## 8. Candidate Model Lifecycle

### 8.1 Model Registry

Suggested fields:

- `model_id`
- `model_type`
- `version`
- `artifact_digest`
- `feature_contract_version`
- `training_dataset_digest`
- `training_code_commit`
- `hyperparameters`
- `training_started_at`
- `training_completed_at`
- `evaluation_result_id`
- `status`
- `owner`
- `approved_by`
- `deployed_at`
- `rollback_model_id`
- `model_card_ref`

### 8.2 Model States

- training
- candidate
- evaluation_failed
- awaiting_review
- approved_for_shadow
- shadow
- canary
- active
- degraded
- rolled_back
- retired

### 8.3 Candidate Versus Current Model

Promotion should not rely only on accuracy improvement.

Compare at least:

- precision
- recall
- macro and weighted F1
- false-positive rate
- false-negative rate
- calibration
- class-level performance
- worst-scenario performance
- temporal holdout performance
- data-quality sensitivity
- inference latency
- memory use
- failure rate

A candidate should meet minimum floors and should not create unacceptable regression in a protected metric.

### 8.4 Promotion Decision

A promotion record should include:

- current model
- candidate model
- metrics compared
- thresholds
- regressions
- decision
- approver
- shadow or canary plan
- rollback target

### 8.5 Shadow and Canary

Before broad activation:

- run the candidate without influencing production decisions
- compare outputs against the current model
- record disagreement categories
- validate latency and resource usage
- check safety and schema behavior
- start with a bounded tenant or workload scope when canary is permitted

### 8.6 Hot Reload

A runtime reload should:

1. verify artifact digest
2. verify feature-contract compatibility
3. load the candidate beside the current model
4. run a health fixture
5. switch traffic atomically
6. retain the prior model
7. monitor early errors
8. roll back automatically on health failure

### 8.7 Model Card

The model card should state:

- intended use
- prohibited use
- training data sources
- known limitations
- supported feature contract
- evaluation sets
- class distribution
- performance by class
- calibration
- data-quality assumptions
- security tests
- deployment requirements
- rollback instructions

---

## 9. AI-Generated Detection Drafts

AI may help draft detection content, but the output must enter the same lifecycle as human-authored content.

### Required Flow

```text
Natural-Language Detection Goal
            |
            v
AI-Generated Draft
            |
            v
Schema and Syntax Validation
            |
            v
Static Safety Review
            |
            v
Fixture Tests
            |
            v
Historical Backtest
            |
            v
Coverage and Noise Evaluation
            |
            v
Human Review
            |
            v
Shadow or Rejected
```

### Required Draft Metadata

- generation task identifier
- model and prompt version
- generating actor
- source evidence or hypothesis
- target data source
- expected fields
- proposed severity and confidence
- test fixtures generated
- known assumptions
- unsupported constructs

### Rollback and Versioning

Every promoted rule must preserve the previous version. A rule draft that cannot be parsed, tested, or attributed must be rejected.

---

## 10. Response Recommendation Lifecycle

### Current Position

OpenAssetWatch should remain recommendation-first. The initial implementation should not execute response actions.

This section preserves a future-safe lifecycle in case narrowly scoped actions are added later.

### 10.1 Plan State Machine

Suggested states:

- `triggered`
- `assembling_context`
- `planning`
- `awaiting_approval`
- `approved`
- `dry_running`
- `executing`
- `verifying`
- `completed`
- `partially_completed`
- `rolled_back`
- `failed`
- `cancelled`

### 10.2 Action State Machine

- pending
- recommended
- awaiting_approval
- approved
- vetoed
- executing
- completed
- failed
- skipped
- rolled_back

### 10.3 Planned Action Contract

```json
{
  "action_id": "action-123",
  "action_type": "restrict_management_access",
  "target_refs": ["asset-77", "service-9"],
  "confidence": 0.86,
  "expected_impact": 0.63,
  "safety_score": 0.91,
  "composite_score": 0.78,
  "blast_radius": "medium",
  "approval_class": "human_required",
  "requires_approval": true,
  "rationale": "Restricting the exposed management service breaks the highest-confidence exposure path.",
  "evidence_refs": ["finding-10", "path-7"],
  "prerequisites": [],
  "verification_plan": {},
  "rollback_plan": {}
}
```

### 10.4 Blast Radius

Suggested classifications:

- `none` — observation only
- `low` — one external indicator or non-critical record
- `medium` — one internal asset or service
- `high` — critical asset, multiple assets, network segment, identity boundary, or shared service

Blast radius must be calculated deterministically from affected assets, criticality, relationships, users, and dependencies.

### 10.5 Approval Classes

OpenAssetWatch should initially support only:

- `observe`
- `recommend`
- `human_required`

Future experiments may define additional classes, but no action should become automatically executable merely because model confidence is high.

Critical assets and high-blast actions always require human approval.

### 10.6 Separate Execution Identity

The process that generates a recommendation should not automatically possess the identity needed to execute it.

A future executor should receive only:

- approved action
- approved targets
- narrow capability
- expiration
- approval record
- rollback and verification instructions

### 10.7 Dry Run

Every action-capable workflow should support dry-run behavior that shows:

- intended request
- target set
- expected changes
- dependencies
- blast radius
- policy decisions
- approval requirement
- rollback plan

A dry run must not silently invoke a real adapter.

---

## 11. Post-Change Verification

A completed action is not automatically a successful outcome.

### 11.1 Verification Record

Suggested fields:

- `verification_id`
- `plan_id`
- `action_ids`
- `started_at`
- `completed_at`
- `pre_change_evidence_refs`
- `post_change_evidence_refs`
- `monitoring_window_seconds`
- `continued_indicators`
- `new_findings`
- `expected_state_observed`
- `risk_before`
- `risk_after`
- `verification_passed`
- `verdict_reason`
- `rollback_required`

### 11.2 Verification Methods

- re-read configuration through an approved read-only tool
- observe collector or sensor evidence
- confirm an exposure-path edge is removed
- verify a service is no longer externally visible through an approved passive source
- compare pre-change and post-change findings
- monitor for continued related signals during a bounded window
- run a deterministic policy check

### 11.3 Failure Behavior

When verification fails:

- do not mark the plan successful
- identify which expected state was not observed
- stop dependent actions
- request human review
- execute rollback only when explicitly approved and supported
- preserve all evidence and adapter responses

---

## 12. Defensive What-If Analysis

### Purpose

A future simulator may compare defensive options without executing attacks or changes.

### 12.1 Inputs

- current asset and relationship graph
- exposure paths
- vulnerability and configuration findings
- asset criticality
- control coverage
- proposed control changes
- uncertainty distributions

### 12.2 Allowed Questions

- Which control breaks the most high-confidence paths?
- Which assets remain reachable after a proposed segmentation change?
- Which patch provides the largest reduction in exposure score?
- How does uncertainty affect the recommended priority?
- Which monitoring control improves visibility on the most critical paths?

### 12.3 Prohibited Behavior

The simulator must not:

- exploit systems
- generate payloads
- attempt credential use
- probe production targets without approval
- present simulated compromise as observed fact
- present directional results as real breach probability

### 12.4 Outputs

- scenario identifier
- assumptions
- changed controls
- paths before and after
- risk-score delta
- confidence interval or uncertainty range
- unresolved evidence gaps
- recommended validation
- explicit simulation label

### 12.5 Validation

Simulation quality should be compared with controlled, authorized exercises or historical evidence before it influences high-impact decisions.

---

## 13. Security Requirements

- Analyst feedback is authenticated and tenant-scoped.
- Training eligibility is policy-controlled.
- Unreviewed feedback cannot trigger production model promotion.
- Feature-contract mismatch blocks model loading.
- Candidate artifacts are signed or checksum-verified.
- Rule and model promotion requires reproducible evaluations.
- AI-generated rules remain drafts until reviewed.
- Evaluation fixtures cannot contain production secrets.
- Response recommendations cite evidence.
- High-blast actions require human approval.
- Executors use narrow, separate identities.
- Dry runs cannot reach real action adapters.
- Post-change verification is required before success is recorded.

---

## 14. Operational Metrics

### Detection Metrics

- rule hits
- false-positive rate
- true-positive rate
- confidence distribution
- missing-field rate
- detector error rate
- stale-rule count
- coverage gaps
- rule changes and rollbacks

### Feedback Metrics

- feedback volume
- review state distribution
- conflicting labels
- withdrawn labels
- training-eligible rate
- labels by source and role
- suspected poisoning events

### Model Metrics

- current and candidate performance
- disagreement rate
- calibration
- drift
- inference latency
- error rate
- rollback count
- feature-contract mismatch

### Response Metrics

- recommendations by blast radius
- approvals and denials
- dry-run count
- verification success rate
- failed or rolled-back actions
- time waiting for approval

---

## 15. Implementation Roadmap

### Phase 1: Detection Contracts

- define detection schema and states
- define proposal and version records
- define quality metrics
- define platform and tenant namespaces
- add audit events

### Phase 2: Quality Workbench

- calculate false-positive and volume metrics
- classify deterministic tuning suggestions
- add bounded projection
- add dismiss and acknowledge behavior
- add proposal generation for changes

### Phase 3: Evaluation Harness

- create versioned synthetic cases and telemetry
- separate deterministic and live-agent suites
- add per-case and per-template metrics
- store evaluation provenance and history
- add CI gates

### Phase 4: Feedback Governance

- define analyst feedback records
- add review and retraction states
- add poisoning and conflict checks
- implement training eligibility policy

### Phase 5: Model Registry and Promotion

- define feature contracts
- register candidate and active models
- implement multi-metric comparison
- add shadow, canary, rollback, and health checks

### Phase 6: Rule Draft Assistance

- generate draft rules only
- validate and backtest drafts
- add human review and promotion workflow

### Phase 7: Response Planning

- add recommendation plan schema
- add blast-radius calculation
- add approval records
- add dry-run and verification contracts
- keep execution disabled until separately approved

### Phase 8: Defensive Simulation

- build graph-based what-if analysis
- model uncertainty
- validate against controlled evidence
- label every result as simulated

---

## 16. Acceptance Criteria

The governance layer should not be considered production-capable until:

- detection content has a versioned lifecycle
- platform rules cannot be mutated from a tenant scope
- tuning recommendations are deterministic and auditable
- deterministic and live-agent evaluations are reported separately
- every evaluation records code, data, policy, and model provenance
- analyst feedback is reviewable and retractable
- unreviewed labels cannot train a production candidate
- feature-contract mismatch blocks deployment
- model promotion uses multiple protected metrics
- rollback targets are always retained
- AI-generated rules remain drafts until validation and review
- response recommendations include blast radius and verification plans
- high-impact actions require explicit human approval
- simulated outcomes are never presented as observed compromise or measured breach probability

## Relationship to Other Architecture Documents

- `docs/architecture/security-investigation-case-operations.md`
- `docs/architecture/connector-playbook-projection-architecture.md`
- `docs/architecture/defensive-ai-security-gap-backlog.md`
- `docs/architecture/ai-agent-permission-output-security.md`
- `docs/architecture/ai-observability-operations.md`
