# CTEM Asset Importance

**Status: IMPLEMENTED (asset-level audited assignment), with documented limits.**
Capability `CTEM-GAP-02`, migration `0007_asset_importance.sql`, decision
ruleset `oaw.decision.rules.v2`.

Asset importance answers one question for each asset:

> What is the consequence of losing or degrading this asset in this
> environment?

It is an audited operator assertion. It is not discovered evidence, not a
vulnerability severity, and not a score.

## Separate layers

```text
asset identity (site_id, asset_id)
  -> asset importance (operator assertion, audited)
  -> finding and exposure facts (deterministic evidence)
  -> Operational Attention Score (oaw.risk.v1, a ranking signal)
  -> decision (oaw.decision.v1 record, oaw.decision.rules.v2 policy)
  -> human work (finding work tracking)
```

Importance never replaces the Operational Attention Score, never changes a
finding's severity, status, or evidence, never resolves a finding, and never
changes work status. It is one separate decision input.

## Values

| Value | Meaning |
| --- | --- |
| `critical` | Losing or degrading the asset causes severe consequence in this environment. |
| `high` | Significant consequence. |
| `standard` | Ordinary consequence. |
| `low` | Limited consequence. |
| `unknown` | No operator assignment exists, or it was withdrawn. |

Only `critical`, `high`, `standard`, and `low` can be assigned. `unknown` is
the absence of an assertion. It is never stored as or read as `low`, and it
never satisfies a rule that needs `critical`.

Importance is never inferred. Asset names, hostnames, software titles,
classifications, finding severity, the Operational Attention Score, and AI
output never set or suggest a value.

## Ownership and provenance

Importance belongs to the asset, identified by `(site_id, asset_id)` as in
`control_tower_assets`. A composite foreign key binds every assignment to the
site that owns the asset, so an asset cannot be assigned under another site.

Every assignment records the site, asset, value, a required reason (up to 500
characters), the principal `api-admin-token`, an actor label marked
`unverified`, the revision, and created, reviewed, and updated times. The
source is always `operator`.

Actor labels are text supplied under the shared administrative token. They are
not authenticated identities. The API accepts no reviewer or approver
identity, because the platform cannot verify one.

## History

`asset_importance_events` is append-only. Database triggers reject `UPDATE`,
`DELETE`, and `TRUNCATE`, except for the cascade that removes a whole asset.
Each event records the revision, the previous and new values, the reason, the
actor label, and the time.

| Event type | When |
| --- | --- |
| `assigned` | First assignment, or assignment after a withdrawal |
| `changed` | A different assignable value |
| `reviewed` | The same value re-affirmed, with a new reason |
| `withdrawn` | The assignment is withdrawn; importance becomes `unknown` |

The read API also derives a `direction` (`initial`, `raised`, `lowered`,
`unchanged`, `withdrawn`, `reassigned`) from the stored values. The event
types are a fixed database check; no other event name can be stored.

Ruleset-driven re-evaluation is recorded in decision history
(`finding_decision_history`, cause `ruleset-changed`), not in importance
history, because it changes decisions, not importance.

## Withdrawal

Withdrawal makes effective importance `unknown` without destroying history:

- the current record stays, with `assignment_state = 'withdrawn'` and
  `importance = 'unknown'` (a database check ties the two together);
- a `withdrawn` event records the value being withdrawn, the withdrawal reason,
  the actor label, and the time;
- earlier events keep the prior value, actor label, reason, and time;
- the next decision evaluation sees importance as `unknown`.

A direct `DELETE` of a current record is rejected by trigger. A current record
and its events are removed only when the asset itself is removed, by cascade.

## Lowering and separation of duties

Lowering importance or withdrawing it can reduce attention on an asset, so
those events are marked `security_sensitive` in the read API, with
`independent_review` set to `recommended-not-enforced`.

**Second-person review is not enforced.** OpenAssetWatch has no
independently authenticated per-user identity yet, so a second text label
would not be independent authorization. The recorded events (previous value,
direction, reason, actor label, time) give a future reviewed workflow what it
needs once per-user identity exists. This is the same limit as exception
governance (`CTEM-GAP-04`).

## Concurrency and integrity

- **Optimistic revision.** The first assignment omits `expected_revision`;
  every later change and withdrawal must send the current revision. A stale or
  missing revision returns HTTP 409 and writes nothing. Row locks serialize
  concurrent writers, so a concurrent change cannot silently overwrite a newer
  one; concurrent first assignments record exactly one.
- **Projection and history agreement.** The current record counts only when an
  event exists at its revision with the same value, reason, principal, actor
  label, actor verification, and time, and no later event exists.
  Otherwise the read API reports `integrity_state = 'inconsistent'` and
  effective importance `unknown`, decisions treat importance as `unknown`, and
  further changes are refused. An altered record therefore cannot drive Act
  Now.
- **Limits of these controls.** As with decision history, triggers and the
  agreement check protect against application writes and accidental SQL. They
  do not protect against a database role that owns the tables, which can drop
  triggers or write a matching record and event. Tamper-evident history is
  `CTEM-GAP-10`.

## Review age

`review_state` is `current` until 180 days after the last assignment or
re-affirmation, then `review-due`; it is `not-applicable` for `unknown`.
Review age is shown to people only. It is not a decision input in
`oaw.decision.rules.v2`.

## Decision integration

The decision record contract stays `oaw.decision.v1`: no field changed shape.
The decision policy is now `oaw.decision.rules.v2`. Historical v1 decisions
keep their `oaw.decision.rules.v1` identity in history, and v1 remains exactly
reproducible (a test regenerates 84,480 v1 decisions and checks a recorded
digest).

v2 adds one rule ahead of the v1 known-exploited rule:

| Rule | Condition | Band |
| --- | --- | --- |
| `vulnerability-known-exploited-critical-asset` | Confirmed vulnerable component, known-exploited catalog evidence, operator-assigned `critical` importance, and exposure not affirmatively ruled out | Act Now |

- Exposure stays `unknown`. The rule fires because exposure is not ruled out,
  not because reachability is established. No reachability reason code is
  emitted; `EXPOSURE_UNKNOWN` remains.
- The reason codes identify both inputs: `EXPLOITATION_KNOWN` and
  `ASSET_IMPORTANCE_CRITICAL`.
- If a later exposure model establishes `not-reachable`, this rule does not
  fire and the finding falls to the Prioritize rule. `segmented` is **not**
  treated as `not-reachable`: segmentation limits reachability but does not
  rule alternate paths out, so it does not block this rule.
- **Open policy decision for `CTEM-GAP-03`:** the decision model also says
  known exploitation should be Prioritize when a reviewed segmentation control
  limits exposure. Whether that should lower a critical-asset Act Now must be
  decided with the exposure model. No current input produces any exposure
  state, so this has no effect today.
- Unknown, low, standard, or high importance cannot satisfy it.
- Importance never lowers the band other evidence justifies. Low, standard,
  and high importance change only the importance reason code. Lowering or
  withdrawing critical importance removes only the Act Now escalation that
  depended on it; for example, known exploitation still yields Prioritize.
- Retries are safe: a retried first assignment or a retried change with the
  same `expected_revision` returns HTTP 409, so it cannot add a duplicate
  transition. A failure inside a change rolls back both the record and its
  event.
- Uncertainty never creates Act Now. When the rule fires with stale or
  unknown-age evidence, the band stays Act Now with urgency
  `verification-required`, as the decision model requires for an uncertain
  critical input.

Importance reason codes apply to asset vulnerability findings:
`ASSET_IMPORTANCE_CRITICAL`, `ASSET_IMPORTANCE_HIGH`,
`ASSET_IMPORTANCE_STANDARD`, `ASSET_IMPORTANCE_LOW`, and
`ASSET_IMPORTANCE_UNKNOWN`.

The v2 input digest includes effective importance for asset findings. When
the active ruleset first runs, each existing decision records a
`ruleset-changed` transition.

## Recomputation

Each successful assignment or withdrawal runs the existing deterministic
finding evaluation, scoped to that asset (trigger `asset-importance-change`).
The decision layer then reconciles in the same run. Writes happen only for
findings whose inputs or outcome changed.

The mutation response reports `decision_reevaluation` as `completed` or
`failed`. A failure never undoes the recorded importance change; affected
decisions read as `stale` until the next evaluation.

Work-tracking changes never trigger importance or decision recomputation.

## API

Every route needs the configured administrative token and fails closed when
none is configured, including reads, because actor labels and reasons may name
people.

- `GET /api/v1/asset-importance?site_id=&importance=&limit=&offset=`: assets
  that have an importance record. Every other asset is `unknown`.
- `GET /api/v1/sites/{site_id}/assets/{asset_id}/importance`: effective
  importance, with `importance_source` (`operator-assigned` or `unassigned`),
  `assignment_state` (`assigned`, `withdrawn`, or `none`), `integrity_state`,
  and `review_state`. 404 when the asset does not exist in that site.
- `GET /api/v1/sites/{site_id}/assets/{asset_id}/importance/history`: events
  in revision order.
- `POST /api/v1/admin/sites/{site_id}/assets/{asset_id}/importance`:
  `{actor, importance, reason, expected_revision?}`.
- `POST /api/v1/admin/sites/{site_id}/assets/{asset_id}/importance/withdraw`:
  `{actor, reason, expected_revision}`.

Requests reject unknown fields (including any reviewer or approver field),
values outside the assignable set, empty or oversized reasons, and control
characters in identifiers.

Ingestion accepts any 1 to 160 character asset identifier, so an identifier
may contain `/`. The asset routes use a path converter with fixed suffixes, so
such identifiers stay addressable without ambiguity, for example
`/api/v1/sites/site-a/assets/rack/1/importance`.

## AI boundary

The AI Advisor is not connected to importance. When it is, it may explain an
importance value and its history. It may not assign, change, withdraw, or
suggest a value as authoritative. A test fails if AI, scoring, finding, or
work-tracking modules reference the importance modules.

## Deferred

These are deliberately not part of this capability:

- business-service entities and importance inherited from them;
- environment-derived importance (for example production versus test);
- propagation through relationship edges (needs the relationship ledger);
- imported importance suggestions from asset-management systems;
- automated or default importance assignment;
- enforced separation of duties for lowering (needs per-user identity);
- review age as a decision input.

## Validation

Run tests in the locked backend image with the repository mounted read-only,
as described in [`docs/LOCAL_DEV_SETUP.md`](../LOCAL_DEV_SETUP.md):

- unit and API tests: the `test_asset_importance` and
  `test_asset_importance_api` modules, plus the decision modules;
- gated database tests: the asset importance database module, enabled by its
  own opt-in environment flag and run only against a disposable database
  server, following [`docs/DATABASE_MIGRATIONS.md`](../DATABASE_MIGRATIONS.md).
  It creates random databases named `openassetwatch_importance_test_<16-hex>`
  and refuses to drop anything else.

Back up the database and verify the restore before applying migration 0007 to
any persistent database. An older backend refuses to start against a version 7
database.
