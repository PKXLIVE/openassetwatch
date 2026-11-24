# CTEM Decision Layer

**Status: IMPLEMENTED (v1), with documented limits.** Contract
`oaw.decision.v1`, ruleset `oaw.decision.rules.v1`, migration
`0006_finding_decision_layer.sql`.

The decision layer answers one question for each deterministic finding:

> What should receive attention now, and why?

It implements the deterministic action-band part of Phase 2 of
[`EXPLAINABLE_RISK_DECISION_MODEL.md`](../EXPLAINABLE_RISK_DECISION_MODEL.md),
using only evidence the repository already records. It sits beside the
Operational Attention Score and never replaces it.

## Separate layers

These stay separate in storage, API, and meaning:

```text
evidence (authenticated observations, reviewed catalogs)
  -> finding (deterministic rule result and lifecycle)
  -> Operational Attention Score (oaw.risk.v1, a ranking signal)
  -> decision (oaw.decision.v1: action band, urgency, reason codes)
  -> human work (finding work tracking: status, owner, references)
```

- The **score** is a signal. It is shown next to each decision for context and
  never selects a band.
- The **decision** is an action-oriented classification produced by explicit,
  ordered, inspectable rules.
- **Work** is what people do about the finding. It never feeds the decision.

Future CTEM layers keep the same separation:

| Concept | Meaning | Status |
| --- | --- | --- |
| Finding | A deterministic observed or derived security condition | IMPLEMENTED |
| Exposure | The contextual state describing how that condition can affect the environment (reachability, importance, controls) | NOT IMPLEMENTED (all `unknown`) |
| Decision | The deterministic action band and reasons for a finding | IMPLEMENTED (v1) |
| Treatment | Human work addressing the condition | IMPLEMENTED (manual work tracking) |
| Verification | Evidence proving the exposure changed | NOT IMPLEMENTED (resolution on fresh evidence only) |

None of these share a status field.

## Action bands

The bands are the ones defined by the decision model. They are listed in
ascending attention order.

| Band | Label | Default urgency | Meaning |
| --- | --- | --- | --- |
| `monitor` | Monitor | `monitor` | Keep observing; current evidence justifies no change. |
| `plan` | Plan | `scheduled` | Create a reviewed remediation or evidence-gathering plan. |
| `prioritize` | Prioritize | `expedited` | Move ahead of routine work. |
| `act-now` | Act Now | `immediate` | Begin immediate human-reviewed response. |

When verification is required, urgency is `verification-required` and the band
is unchanged. A band is never an execution command.

**No v1 rule can produce Act Now.** The approved Act Now conditions need
confirmed exposure, a critical asset, compromise evidence, or safety-impact
evidence. OpenAssetWatch records none of these yet, so producing Act Now would
mean inventing facts. Act Now remains in the contract so later rulesets can use
it without a schema change.

## Ordered rules (`oaw.decision.rules.v1`)

The first matching rule selects the band. The uncertainty floor is applied
afterwards.

| Order | Rule | Condition | Band |
| --- | --- | --- | --- |
| 1 | `finding-resolved` | Finding status is resolved | none (`not-current`) |
| 2 | `vulnerability-known-exploited` | Confirmed vulnerable component with known-exploited catalog evidence | Prioritize |
| 3 | `vulnerability-critical` | Confirmed vulnerable component, critical severity | Prioritize |
| 4 | `vulnerability-confirmed` | Confirmed vulnerable component, high, medium, or low severity | Plan |
| 5 | `vulnerability-informational` | Confirmed vulnerable component, informational severity | Monitor |
| 6 | `identity-or-version-gap` | Version unknown or product identity uncertain | Plan, verification required |
| 7 | `evidence-conflict` | Classification or identity conflict | Prioritize, verification required |
| 8 | `collection-gap` | Stale collection, unclassified asset, or passive-only asset | Plan, verification required |
| 9 | `severity-default` | Other mapped rules: critical or high is Prioritize, medium or low is Plan, informational is Monitor | by severity |
| 10 | `unmapped-finding-rule` | A finding rule without a reviewed mapping | Plan, verification required |

**Uncertainty floor:** if evidence is stale or of unknown age, confidence is
low, insufficient, or conflicted, or the known-exploited catalog evidence is
stale, the decision requires verification, and a Monitor result is raised to
Plan. Missing or stale evidence never lowers a finding to Monitor. Uncertainty
never lowers a higher band.

### Uncertainty invariant

Uncertainty may prevent an unsafe low band. It must never create a security
fact. Concretely:

- stale or missing evidence never sets an exposure state, and low confidence
  never sets an exploitation status;
- unknown importance stays `unknown` and is never read as critical;
- uncertainty only ever adds the uncertainty reason codes
  (`EVIDENCE_STALE`, `EVIDENCE_FRESHNESS_UNKNOWN`, `CONFIDENCE_LOW`,
  `EXPLOITATION_SOURCE_STALE`, `UNCERTAINTY_FLOOR_APPLIED`), and never removes a
  reason;
- whenever the floor raises a band, `UNCERTAINTY_FLOOR_APPLIED` is present
  together with at least one underlying uncertainty reason;
- stale known-exploited catalog evidence is uncertainty only for a confirmed
  vulnerable component, the one place that evidence is a decision input.

**The maximum band reachable from uncertainty alone is Plan.** Uncertainty can
raise Monitor to Plan and nothing else. It cannot produce Prioritize or Act
Now. This matches the decision model: Monitor must not be used merely because
evidence is missing, and a material uncertain input keeps its provisional band
with verification required.

Two rules produce Prioritize together with verification, and neither depends on
uncertainty alone:

- `evidence-conflict` is driven by a deterministic conflict finding, an
  observed fact that strong sources disagree;
- `vulnerability-known-exploited` is driven by known-exploited catalog
  evidence. If that evidence is stale, the band stays Prioritize and
  `EXPLOITATION_SOURCE_STALE` is added; staleness neither creates nor removes
  the band.

An exhaustive unit test checks every reviewed and unmapped finding rule,
severity, catalog-evidence state, and lifecycle state against each kind of
uncertainty (330 certain cases, 1,670 comparisons).

A test asserts that every finding rule in the registry has a reviewed mapping,
so adding a finding rule without a decision mapping fails CI rather than
silently falling through.

### Confidence bands

Numeric finding confidence is a deterministic implementation weight, not a
calibrated probability. These versioned thresholds only make it readable:

| Band | Rule |
| --- | --- |
| `conflicted` | classification or identity conflict rules |
| `insufficient` | version or identity gap rules, or confidence below 0.40 |
| `low` | 0.40 up to 0.65 |
| `medium` | 0.65 up to 0.85 |
| `high` | 0.85 or more |

## Reason codes

Each reason code maps to one deterministic predicate over a canonical field, has
a fixed plain-language explanation, and is returned in catalog order. Codes are
reviewed product code; no external text can define or select one.

| Code | Canonical source | Predicate |
| --- | --- | --- |
| `FINDING_RESOLVED` | `findings.status` | status is `resolved` |
| `SUPPRESSION_ACTIVE` | `findings.status` | status is `suppressed` |
| `EXPLOITATION_KNOWN` | `finding_evidence` | vulnerable-component finding has known-exploited catalog evidence |
| `EXPLOITATION_RANSOMWARE_KNOWN` | `finding_evidence` | that evidence records ransomware campaign use |
| `EXPLOITATION_SOURCE_STALE` | `finding_evidence.freshness` | that evidence is stale or of unknown age |
| `VULNERABILITY_CONFIRMED` | `findings.rule_id` | `vulnerable-component` |
| `SECURITY_CONTROL_COVERAGE_GAP` | `findings.rule_id` | `security-coverage-gap` |
| `EVIDENCE_CONFLICTED` | `findings.rule_id` | `classification-conflict` or `identity-conflict` |
| `IDENTITY_UNCERTAIN` | `findings.rule_id` | `advisory-identity-uncertain` |
| `VERSION_UNKNOWN` | `findings.rule_id` | `component-version-unavailable` |
| `ASSET_UNMANAGED` | `findings.rule_id` | `passive-only-asset` |
| `ASSET_UNCLASSIFIED` | `findings.rule_id` | `unknown-asset` |
| `COLLECTION_STALE` | `findings.rule_id` | `asset-stale` or `sensor-stale` |
| `DECISION_RULE_UNMAPPED` | `findings.rule_id` | rule has no reviewed mapping |
| `SEVERITY_CRITICAL` to `SEVERITY_INFORMATIONAL` | `findings.severity` | exactly one, always present |
| `EXPOSURE_UNKNOWN` | exposure model (absent) | asset vulnerability finding |
| `ASSET_IMPORTANCE_UNKNOWN` | asset importance (absent) | asset vulnerability finding |
| `EVIDENCE_STALE` | `findings.evidence_freshness` | `stale` |
| `EVIDENCE_FRESHNESS_UNKNOWN` | `findings.evidence_freshness` | `unknown` |
| `CONFIDENCE_LOW` | `findings.confidence` | low or insufficient band, excluding identity and version gap rules |
| `UNCERTAINTY_FLOOR_APPLIED` | decision ruleset | uncertainty raised Monitor to Plan |

Codes considered but **not implemented**, because the repository has no
canonical per-finding source for them yet: internet exposure, unsupported or
end-of-life software or firmware, fix available, exploit probability, asset
importance values, and a combined "multiple drivers" code. Known exploitation
from a reviewed advisory's own flag (rather than catalog evidence) is also left
to a later ruleset, because that flag lives on the advisory, not the finding.

## Governance overlays

| Finding state | Decision effect |
| --- | --- |
| Acknowledged | None. Acknowledgement records review only; the decision is identical to an active finding's. |
| Suppressed | The band is still computed and shown; `prioritization_excluded` is true and `SUPPRESSION_ACTIVE` is added. Suppression does not prove the condition is gone. |
| Resolved | `decision_state` is `not-current` with no band. The transition is kept in history. |
| Reopened | A new `current` decision with cause `finding-reopened`. |

## What causes recomputation

Decisions are reconciled inside every deterministic finding evaluation, after
findings and the Operational Attention Score are settled, in the same evaluation
run. All existing evaluation triggers therefore recompute decisions, and there
is no separate or hidden recomputation path:

- administrator-requested finding evaluation;
- post-ingestion evaluation (canonical, endpoint, collector, and observation
  ingestion);
- sensor check-in evaluation;
- suppression (which already re-evaluates its site);
- advisory synchronization and known-exploited catalog refresh, which
  re-evaluate findings;
- classification and vulnerability matching re-evaluation.

The inputs whose change produces a new decision are the finding's rule,
subject type, category, severity, confidence, evidence freshness, lifecycle
class (current, suppressed, or resolved), and its evidence references, types,
and freshness. A ruleset version change is also a transition.

These never cause a decision change:

- acknowledgement;
- any finding work-tracking change (status, owner, references, notes);
- an Operational Attention Score change;
- any AI Advisor activity.

There is no decision-mutating API. Decisions change only through deterministic
finding evaluation.

## Persistence and history

Decisions are persisted as a **deterministic materialized projection plus an
append-only history of material transitions**:

- `finding_decisions` holds the current decision for each finding: schema and
  ruleset version, every output field, the input digest, the finding's
  `evaluated_at`, and the evaluation run that produced it. It is bound to the
  finding's site by a composite foreign key and cascades with the finding.
- `finding_decision_history` records only material transitions: a change of
  ruleset version, decision state, band, urgency, or reason codes. Each row
  keeps the previous and new values, the cause (`initial`, `inputs-changed`,
  `ruleset-changed`, `finding-resolved`, `finding-reopened`), the input
  digest, and the run. It is append-only by database trigger, except for the
  cascade that removes a whole finding.

**Why persist.** Every read can explain and reproduce a stored result, list and
filter queries stay indexed, and history can answer when a finding became
Prioritize, what changed, and why it moved between bands. Computing decisions
only at read time could not show history; history alone would make current
lists expensive.

**Why history records only material transitions.** Re-evaluating unchanged
inputs writes nothing at all, and a change of inputs that keeps the same
outcome updates the projection without adding history noise.

**Reuse of existing history patterns.** The repository keeps history as
per-entity tables (vulnerability matches, known-exploited records, priority
factors, classification), and temporal intelligence is a derived projection
over those tables. The decision history follows the same pattern, so later
temporal signals can project it (for example, the number of Prioritize findings
per site over time) without a parallel history system.

### Integrity

- **Reproducibility.** The input digest is SHA-256 over the exact normalized
  inputs and ruleset version. Every read recomputes the decision from current
  authoritative inputs and reports `projection_state`:
  - `current`: the stored decision is exactly what the ruleset produces now;
  - `stale`: inputs changed and no evaluation has run since;
  - `inconsistent`: inputs match but the stored outcome differs, meaning the
    projection was altered or a ruleset defect exists.
- **Limits of these controls.** The history triggers and the
  `projection_state` check protect against application writes and accidental
  SQL. They are not a control against a database role that owns the tables:
  such a role can drop the triggers, and a change that rewrites both a finding
  and its decision consistently would read as `current`. Tamper-evident
  chaining of history is a separate planned capability (`CTEM-GAP-10`).
- **Concurrency.** Reconciliation holds a transaction-scoped advisory lock and
  row locks, and an older evaluation never overwrites a newer decision.
- **Bounds.** At most 20,000 findings per reconciliation. The scope is read
  with a limit of 20,001 rows, and exceeding the cap raises before any decision
  is written, so the evaluation run fails visibly and no partial projection or
  history is recorded. The cap matches the existing finding-reconciliation cap.
- **Failure.** A decision failure fails the evaluation run like a risk failure
  does. Findings and the score reconciled earlier in the run stay committed, so
  reads then report `stale` instead of serving a silently outdated band.

### Cost

- **Evaluation:** each finding evaluation recomputes decisions for every
  finding in the evaluated site (or every finding, for an unscoped
  evaluation). That is three bounded reads (findings, their evidence, and the
  existing decisions under row lock), a pure in-memory computation per
  finding, and writes only for findings whose inputs or outcome changed.
  Unchanged inputs write nothing.
- **Reads:** a list or detail read issues a constant number of queries
  regardless of page size: the page count, the page, its evidence, the
  finding contributions, and one keyed lookup for all of the page's asset
  scores. A regression test asserts the same query count for one asset and
  for four.
- **Follow-up:** asset-scoped evaluations still recompute the whole site.
  That is correct but does more work than necessary on very large sites;
  narrowing it to the evaluated subject is a possible later optimization.

## API

All routes are read-only and follow the finding read convention (admin token
enforced when configured).

- `GET /api/v1/decisions/rules`: ruleset version, bands, ordered rules,
  reason-code catalog, confidence thresholds, and limitations.
- `GET /api/v1/decisions/findings?site_id=&action_band=&decision_state=&limit=&offset=`:
  current decisions, ordered Act Now first, then by severity.
- `GET /api/v1/decisions/findings/{finding_id}`: one decision with reason
  explanations, evidence references, `projection_state`, and Operational
  Attention Score context (`asset_score`, `formula_version`,
  `finding_contribution`, each null when not measured).
- `GET /api/v1/decisions/findings/{finding_id}/history`: material
  transitions in revision order.

The finding evaluation response gains `decision_evaluated_count` and
`decision_transition_count`.

## AI Advisor boundary

The AI Advisor is not connected to the decision layer in v1. When it is, it may
explain a persisted decision ("why is this Prioritize?") and cite its reason
codes and evidence. It may not:

- assign or change a band, urgency, or reason code;
- create a reason code or alter the ruleset;
- suppress or hide a decision;
- widen scope;
- write any decision state.

The engine has no model, network, database, or clock dependency, and a test
fails if the AI Advisor or local AI modules import the decision modules.

## Work-tracking boundary

The decision input contains no work-tracking field, the decision store reads no
work-tracking table, and a test enforces both. Marking work done never changes
an action band; only authoritative evidence does.

## Limits

- Act Now is unreachable until exposure, asset importance, compromise, or
  safety evidence exists.
- Exposure and asset importance are always `unknown` (or `not-applicable` for
  non-asset findings).
- Exploitation status is `known-exploited`, `unknown`, or `not-applicable`.
  `no-known-exploitation` is never asserted, because v1 cannot prove the
  catalog was current for that finding.
- Asset and site decision summaries are not yet provided.
- Confidence bands are readable labels over implementation weights, not
  calibrated probabilities.
- Remediation availability, value, and effort are not part of v1.

## Validation

Run tests in the locked backend image with the read-only repository mount
described in [`docs/LOCAL_DEV_SETUP.md`](../LOCAL_DEV_SETUP.md):

- unit tests: the `test_decisions` and `test_decision_api` modules under
  `backend/tests/`;
- gated database tests: the decision database module under `backend/tests/`,
  enabled by its own opt-in environment flag and run only against a
  disposable database server, following the gated-test procedure in
  [`docs/DATABASE_MIGRATIONS.md`](../DATABASE_MIGRATIONS.md). It creates random
  databases named `openassetwatch_decision_test_<16-hex>` and refuses to drop
  anything else.

Back up the database and verify the restore before applying migration 0006 to
any persistent database. An older backend refuses to start against a version 6
database.
