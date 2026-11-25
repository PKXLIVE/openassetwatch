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
| Resolution evidence | Recorded by the finding lifecycle at resolution (`finding_resolution_evidence`) | No |
| Comparable "after" evidence | For a resolved finding, its resolution evidence collected after the report; otherwise finding evidence observed after the report | No |
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
| `insufficient-evidence` | Evidence cannot decide the outcome: later collection was partial, failed, or unsupported; the evidence's age is unknown; no resolution evidence was recorded; the resolving evidence was collected before the report; or no complete collection preceded a software resolution. |
| `evidence-stale` | The evidence after the report (or the resolving evidence) is stale. |
| `still-present` | Fresh evidence observed after the report still matches the finding rule. |
| `conflicting-evidence` | The finding resolved, but an active identity or classification conflict on the asset prevents attributing the outcome. |
| `manual-review-required` | The finding rule has no automatic verification path (for example identity conflicts). |
| `verified` | Recorded technical evidence collected after the report shows the condition ended. |
| `resolved-before-report` | The finding resolved before remediation was reported. The resolution is not evidence the reported work caused it. |
| `resolved-by-advisory-change` | A reviewed advisory or applicability change resolved the finding. Nothing changed on the asset. |
| `report-withdrawn` | Work was marked done and later reopened or cancelled. |

### When an outcome is verified

A historical resolution is not proof that the reported work caused the
change. `verified` requires every one of these:

1. the finding rule has an automatic verification method;
2. no identity or classification conflict is active on the asset;
3. the finding resolved after the report;
4. the finding lifecycle recorded affirmative resolution evidence with a
   technical basis (a confirmed removal, or an installed version at the fix
   that differs from the version recorded when work was marked done), not an
   advisory or applicability basis;
5. that evidence was collected after the report and at or before the
   resolution, and is fresh or aging;
6. for software methods, the exact snapshot that observed the component (or
   confirmed its removal) is complete and falls in the same report-to-resolution
   window. A complete inventory from another collection source on the same
   asset does not count.

A resolution timestamp alone never verifies anything. An exhaustive test
states these requirements independently of the implementation and checks them
across rules, finding states, resolution times, resolution evidence (basis,
collection time, freshness), collections before and after resolution, work
states, and conflicts (11,264 cases). A second exhaustive test checks that no
unresolved finding is ever verified or closed as not attributable.

A later partial, failed, or unsupported collection does not undo a verified
outcome. The state stays `verified` and gains
`COLLECTION_DEGRADED_SINCE_VERIFICATION`. If the condition returns, the
finding reopens, the state becomes `still-present` with
`REOPENED_SINCE_REPORT`, and the earlier `verified` transition remains in
history.

Suppression never verifies anything; it adds `SUPPRESSION_ACTIVE`.

"Completed but unverified" means work marked done whose state is any of
`awaiting-evidence`, `insufficient-evidence`, `evidence-stale`,
`still-present`, `conflicting-evidence`, or `manual-review-required`.
`resolved-before-report` and `resolved-by-advisory-change` are closed but not
attributable to the reported work, and are listed separately in the rules.

## Resolution evidence

The finding lifecycle records why each resolution happened, in
`finding_resolution_evidence`, in the same transaction that resolves the
finding. It derives the evidence from the same inputs that made the finding
eligible to resolve; nothing is inferred, and nothing is recorded when no
evidence is known. Each row keeps:

- the finding and site (bound by composite foreign key);
- the resolution time (evaluation time) and evaluation run;
- the basis, the evidence reference, type, and source;
- the collection time of that evidence, distinct from the resolution time;
- freshness, and for software the installed and fixed versions;
- for software, the identity of the supporting component source snapshot.

| Basis | Meaning | Technical change? |
| --- | --- | --- |
| `component-removed` | The matcher reported `fixed` with `component-removal-confirmed-by-complete-inventory`; collection time is when the complete inventory omitted it | Yes |
| `component-version-fixed` | The matcher reported `fixed` with `at-or-after-fixed-boundary` | Only if the installed version changed since the report (see below) |
| `match-fixed-unattributed` | The matcher reported `fixed` with neither reason | No remediation claimed |
| `component-version-available` | A later inventory supplied a usable version | Yes |
| `fresh-observation`, `sensor-check-in`, `classification-recognized`, `classification-consistent`, `managed-evidence`, `healthy-coverage` | A fresh authorized observation shows the rule's condition ended | Yes |
| `applicability-not-affected` | The match became not-affected | No (applicability change) |
| `advisory-withdrawn` | The reviewed advisory was withdrawn | No (advisory change) |
| `advisory-identity-reviewed` | Identity was resolved through catalog review | No (advisory change) |

`not-affected` is treated as an applicability change, not confirmed
remediation, because it can come from an advisory revision as well as from an
upgrade. A person can confirm such cases.

A `fixed` status alone never claims an upgrade. When work is marked done, the
baseline records the installed version of each of the finding's matches
(`match_versions`). A `component-version-fixed` resolution is a confirmed
upgrade only when its installed version differs from that recorded version.
The same version means the advisory's fixed boundary was revised
(`resolved-by-advisory-change`, `FIXED_BOUNDARY_REVISED`). No recorded version
means the upgrade cannot be confirmed (`insufficient-evidence`,
`VERSION_CHANGE_UNCONFIRMED`).

Component collection checks are bound to the collection sources that report
the component, through component source presence. For an unresolved finding,
only snapshots from those sources count as collection since the report.

The table is append-only by trigger, except for the cascade that removes a
whole finding. Resolutions recorded before this capability existed have no
resolution evidence; their verification reports `RESOLUTION_EVIDENCE_UNAVAILABLE`.

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

For component methods, `collection_completeness` comes from the collection
that decides the outcome. For a resolved finding that is the newest component
source snapshot between the report and the resolution
(`collection_at_resolution`); otherwise it is the newest snapshot after the
report (`collection_since_report`):

- `complete`: that snapshot is complete;
- `incomplete`: it is partial, failed, or unsupported;
- `none-since-report`: snapshots exist for the asset, but none in that window;
- `not-recorded`: the asset has no snapshot records (for example legacy
  collection).

A software resolution without a complete collection in that window is
`insufficient-evidence`. An incomplete later collection with no newer
observation of an unresolved finding is also `insufficient-evidence`. A
complete later collection that deterministic evaluation has not processed yet
gives `awaiting-evidence` with reason `EVALUATION_PENDING`. The newest snapshot
after a resolution is reported as `collection_after_resolution` and can only
add `COLLECTION_DEGRADED_SINCE_VERIFICATION`. Other methods report
`not-applicable`, because their rules already gate resolution on fresh
evidence.

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

"After" evidence is, for a resolved finding, its recorded resolution evidence
collected after the report; for an unresolved finding, its current evidence
observed after the report. Finding evidence rows from before a resolution are
never presented as proof that the condition ended.

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
  reasons, before-and-after evidence references, the recorded resolution
  evidence (basis, technical flag, reference, source, collection time,
  freshness, versions), the collections at and after resolution, and the last
  recorded transition.
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
