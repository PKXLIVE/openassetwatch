# CTEM Remediation Verification

**Status: IMPLEMENTED, with documented limits.** Capability `CTEM-GAP-06`,
contract `oaw.verification.v1`, ruleset `oaw.verification.rules.v1`, migration
`0008_finding_verification.sql`.

Verification answers, for one finding:

- What condition needs verification?
- What evidence would establish that it changed?
- Has comparable evidence arrived since remediation was reported?
- Does that evidence support the reported outcome?
- Is completed work still unverified?

## Authority

Verification is a deterministic read model over existing authorities. It adds
no remediation or finding state machine.

| Concept | Authority | Changed by verification? |
| --- | --- | --- |
| Remediation report | A finding work item marked `done` | No |
| Resolution | The deterministic finding lifecycle (fresh, affirmative, complete evidence) | No |
| Comparable "after" evidence | Finding evidence observed after the report | No |
| Collection completeness | Component source snapshots (`complete`, `partial`, `unsupported`, `failed`) | No |
| Decision band | `oaw.decision.v1` / `oaw.decision.rules.v2` | No |

Marking work done is a claim, not proof. It never resolves a finding.
Verification never resolves a finding, changes work status, or feeds the
decision layer, the Operational Attention Score, or asset importance. Absence
of an observation never establishes resolution: only the deterministic
finding lifecycle can resolve a finding, and it already refuses missing,
passive, stale, partial, or failed collection.

OpenAssetWatch stays advisory for remediation. Verification waits for the next
authorized collection. It performs no active retesting, scanning, remote
command, configuration change, or containment, and AI has no role in it.

## Verification states

| State | Meaning |
| --- | --- |
| `not-reported` | No work item for the finding is marked done. Guidance is still available. |
| `awaiting-evidence` | Work is done, and no comparable evidence has been observed since the report. |
| `insufficient-evidence` | Evidence arrived, but it cannot decide the outcome: collection after the report was partial, failed, or unsupported, or the later evidence's age is unknown. |
| `evidence-stale` | The evidence observed after the report is stale. |
| `still-present` | Fresh evidence observed after the report still matches the finding rule. |
| `conflicting-evidence` | The finding resolved, but an active identity or classification conflict on the asset prevents attributing the outcome. |
| `manual-review-required` | The finding rule has no automatic verification path (for example identity conflicts). |
| `verified` | Deterministic evaluation resolved the finding from fresh affirmative evidence. |
| `report-withdrawn` | Work was marked done and later reopened or cancelled. |

Only `verified` means the outcome is supported, and it is reachable only when
the finding lifecycle has resolved the finding, the work is still marked
done, and no identity or classification conflict is active on the asset. An
exhaustive test checks this across rules, finding states, freshness,
observation times, collection states, work states, and conflicts (10,560
cases).

If the finding was already resolved before the report, the state is still
`verified`, with reason `RESOLVED_BEFORE_REPORT` instead of
`RESOLVED_BY_FRESH_EVIDENCE`. Suppression never verifies anything; it adds
`SUPPRESSION_ACTIVE`.

"Completed but unverified" means work marked done whose state is any of
`awaiting-evidence`, `insufficient-evidence`, `evidence-stale`,
`still-present`, `conflicting-evidence`, or `manual-review-required`.

## Verification methods

Each finding rule has one reviewed method, built from the rule's existing
required evidence and resolution behavior. A test fails if a finding rule has
no method.

| Finding rule | Method | Comparable evidence | Collection check |
| --- | --- | --- | --- |
| `vulnerable-component` | `component-inventory` | A later complete inventory showing the component removed or not affected, or an advisory change to not-affected or withdrawn | Component source snapshot |
| `component-version-unavailable` | `component-inventory` | A later complete inventory with a usable version | Component source snapshot |
| `advisory-identity-uncertain` | `component-identity` | A later complete inventory or reviewed catalog that makes identity precise | Component source snapshot |
| `security-coverage-gap` | `endpoint-coverage-status` | Later endpoint-origin evidence no longer reporting the gap | Finding freshness |
| `asset-stale` | `fresh-observation` | A fresh normalized observation | Finding freshness |
| `sensor-stale` | `sensor-check-in` | A current authenticated check-in | Finding freshness |
| `unknown-asset`, `classification-conflict` | `classification` | Fresh evidence yielding a recognized, non-conflicting classification | Finding freshness |
| `passive-only-asset` | `managed-evidence` | A fresh record that is no longer passive-only | Finding freshness |
| `identity-conflict` | `manual-identity-review` | Not automatic; a person reviews merge evidence | Finding freshness |

A rule without a method is held at `manual-review-required`, never treated
as verifiable.

For vulnerable components, guidance also lists the installed and fixed
versions from the stored deterministic match. Versions are shown only when the
stored match supplies them; none are inferred.

### Collection completeness

For component methods, the newest component source snapshot for the asset
observed after the report sets `collection_completeness`:

- `complete`: a complete snapshot arrived after the report;
- `incomplete`: the newest later snapshot is partial, failed, or unsupported;
- `none-since-report`: snapshots exist for the asset, but none after the
  report;
- `not-recorded`: the asset has no snapshot records (for example legacy
  collection).

An incomplete later collection with no newer observation gives
`insufficient-evidence`. A complete later collection that deterministic
evaluation has not processed yet gives `awaiting-evidence` with reason
`EVALUATION_PENDING`. Other methods report `not-applicable`, because their
rules already gate resolution on fresh evidence.

## Before and after evidence

When work changes to `done`, the same transaction records a baseline in
`finding_verification_baselines`. Finding evidence rows are replaced on every
evaluation, so the "before" references must be copied at report time. The
baseline holds:

- the report time and work revision;
- the finding rule, status, evidence time, freshness, and reopen count;
- up to eight finding evidence references (reference, type, freshness, time);
- the newest component source snapshot at or before the report.

If baseline capture fails, the `done` transition rolls back with it. Work
marked done before migration 0008 has no baseline; its verification reports
`BASELINE_NOT_CAPTURED`.

"After" evidence is the finding's current evidence observed after the report.

## History

Each deterministic finding evaluation records material verification
transitions in `finding_verification_history`, after findings, risk, and
decisions are settled in the same run. A transition is a change of ruleset,
state, or reason codes for one remediation report. Each row keeps the previous
state, reason codes, the after-evidence references, finding status, evidence
time, collection status, and an input digest. Unchanged outcomes write
nothing. A new report (work reopened, then marked done again) starts a new
sequence.

Baselines and history are append-only by database trigger, except for the
cascade that removes a whole finding. Both are bound to the work item, finding,
and site by a composite foreign key.

Reads always recompute the current outcome. `record_state` is `current` when
the last recorded transition matches, `stale` when inputs changed since the
last evaluation, and `not-recorded` when no evaluation has run since the
report.

Limits are the same as decision history: triggers protect against
application writes and accidental SQL, not against a role that owns the
tables. Tamper-evident history is `CTEM-GAP-10`.

## API

All routes are read-only and require the configured administrative token.
They fail closed when none is configured, because they expose work items.

- `GET /api/v1/verification/rules`: states, methods, reason codes, and limits.
- `GET /api/v1/verification/unverified-work?site_id=&verification_state=&limit=&offset=`:
  work marked done whose finding is not verified, oldest report first.
- `GET /api/v1/findings/{finding_id}/verification`: guidance, current state,
  reasons, before-and-after evidence references, collection completeness, and
  the last recorded transition.
- `GET /api/v1/findings/{finding_id}/verification/history`: recorded
  transitions in report and sequence order.

No route can set a verification outcome. Responses are strict contracts that
reject unknown fields. Database errors return a generic message.

The finding evaluation response gains `verification_evaluated_count` and
`verification_transition_count`.

## Limits

- Verification covers only evidence the platform already collects and
  evaluates. It makes no exposure or reachability claim.
- Configuration-based verification is limited to the conditions existing
  rules evaluate (for example endpoint security coverage). There is no general
  configuration-change verification.
- Verification does not decide whether a reported remediation was the cause
  of a resolution; `RESOLVED_BEFORE_REPORT` marks the clear case.
- The unverified-work view computes states at read time over at most 20,000
  done work items per request.
- There is no verification target date or overdue state (`CTEM-GAP-12`) and no
  outcome metrics (`CTEM-GAP-09`).

## Validation

Run tests in the locked backend image with the repository mounted read-only,
as described in [`docs/LOCAL_DEV_SETUP.md`](../LOCAL_DEV_SETUP.md):

- unit and API tests: the `test_verification` and `test_verification_api`
  modules;
- gated database tests: the verification database module, enabled by its own
  opt-in environment flag and run only against a disposable database server,
  following [`docs/DATABASE_MIGRATIONS.md`](../DATABASE_MIGRATIONS.md). It
  creates random databases named `openassetwatch_verification_test_<16-hex>`
  and refuses to drop anything else.

Back up the database and verify the restore before applying migration 0008 to
any persistent database. An older backend refuses to start against a version 8
database.
