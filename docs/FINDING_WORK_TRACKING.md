# Manual Finding Work Tracking

OpenAssetWatch can record manual remediation coordination beside a
deterministic finding: a work status, an optional owner label, opaque ticket or
change reference labels, and notes. Every change is written to an append-only
event history.

Work tracking is coordination metadata only. **It never changes a finding's
status, evidence, confidence, or risk score.** Those remain owned exclusively
by the evidence-based reconciliation path described in
[DETERMINISTIC_FINDINGS_AND_RISK.md](DETERMINISTIC_FINDINGS_AND_RISK.md). Marking
work `done` does not resolve a finding; only fresh deterministic evidence that
no longer matches the rule resolves it.

Marking work `done` is a remediation report. In the same transaction,
OpenAssetWatch records the evidence present at that moment as a verification
baseline, so later evidence can be compared with it. Whether the report is
supported is a separate, deterministic verification read model; see
[CTEM_REMEDIATION_VERIFICATION.md](ctem/CTEM_REMEDIATION_VERIFICATION.md).

## Scope of v1

Included:

- one work item per finding, created explicitly by an administrator;
- work status: `open`, `in_progress`, `blocked`, `done`, `cancelled`;
- an optional owner label of kind `person` or `team`;
- up to 20 active reference labels of type `ticket`, `change`, or `other`;
- free-text notes (up to 1,000 characters);
- an append-only, revisioned event history for every change.

Not included: external URLs, ticketing or chat integrations, outbound calls,
UI, AI Advisor tools or context, SLA or due-date tracking, risk-score effects,
and risk acceptance. Work tracking is also not a feature flag; it is available
once migration `0005` is applied.

## Trust model

All work-tracking text is operator-supplied, unverified data.

- **Owner labels** are display strings. They are stored with
  `owner_verification = 'unverified'` and are not linked to any identity,
  directory, or account. A label naming a person does not prove that person
  accepted ownership.
- **Actor labels.** Each mutation requires an `actor` label. It is stored as
  supplied with `actor_verification = 'unverified'`. The authenticated
  principal is always recorded separately as the fixed value
  `api-admin-token`: the only fact the system has verified is that the shared
  admin token was presented. The API does not claim per-user authentication.
- **Reference labels** are opaque keys such as `OPS-1234`. The contract and a
  database check accept only letters, digits, space, `.`, `_`, `#`, and `-`,
  beginning with a letter or digit, so a URL, path, or scheme cannot be stored.
  The `reference_system` label (for example `jira`) is a lowercase name, not
  an integration. OpenAssetWatch never resolves or contacts a reference.
- The database enforces the `unverified` markers and the fixed principal with
  check constraints, so a direct write cannot record a verified claim.

Treat notes and labels as untrusted text when displaying them. They are not
exposed to the AI Advisor in v1.

## Lifecycle

```text
open        -> in_progress | blocked | done | cancelled
in_progress -> open | blocked | done | cancelled
blocked     -> open | in_progress | done | cancelled
done        -> open
cancelled   -> open
```

A same-status change is rejected. New work items start `open`. A work item
cannot be started for a `resolved` finding, but an existing work item stays
fully usable whatever the finding's status.

**Finding reopen.** When a resolved finding reopens because fresh evidence
matches again, its work item, owner, references, revision, and event history
are preserved unchanged. Work status is not changed automatically; an operator
decides whether to reopen the work. Each event records the finding status
observed at the time (`finding_status`) as read-only context.

## Concurrency and auditing

Every work item carries a `revision`, starting at 1. Each mutation must supply
the current `expected_revision`. The store locks the work item row, verifies
the revision, applies the change, increments the revision, and appends exactly
one event, all in one transaction. A stale revision returns `409` and writes
nothing. `(work_item_id, revision)` is unique in the event table, so concurrent
writers with the same revision serialize to a single change.

Events are append-only. A database trigger rejects `UPDATE`, `DELETE`, and
`TRUNCATE` on `finding_work_events`, including a `TRUNCATE ... CASCADE` that
reaches it from work items, findings, or sites. Because deleting a work item
would cascade to its events, a second trigger rejects a direct `DELETE` on
`finding_work_items`. The only path that removes work items and events is the
referential cascade that removes their whole finding, for example when the
finding or its site is deleted. The store has no operation that edits or
deletes events or work items.

These triggers guard against application and accidental writes. A database
role that owns the tables can still drop them, so they are not a control
against a privileged database user.

## Site consistency

A work item's `site_id` is always copied from the referenced finding row. It
is never accepted from a request. The database also enforces it: the work
item's `(finding_id, site_id)` is a foreign key to `findings(finding_id,
site_id)`, and references and events carry composite foreign keys back to the
work item's `(work_item_id, site_id)`. A direct write that binds a work item,
reference, or event to a different site is rejected.

## API

All work-tracking endpoints require a configured `OPENASSETWATCH_ADMIN_TOKEN`
and a constant-time match of `X-OpenAssetWatch-Admin-Token`. They return `503`
when the secret is not configured. Unlike general finding reads, **reads also
fail closed**, because owner, actor, and note labels may name people.

Reads:

- `GET /api/v1/finding-work-items?site_id=&work_status=&limit=&offset=`
- `GET /api/v1/findings/{finding_id}/work-item`
- `GET /api/v1/findings/{finding_id}/work-item/events?limit=&offset=`

Mutations (all `POST`, all require `actor`; all except create require
`expected_revision`):

- `/api/v1/admin/findings/{finding_id}/work-item` creates the work item
  (`201`). Optional fields: `owner_kind`, `owner_label`, `note`.
- `/api/v1/admin/findings/{finding_id}/work-item/status` takes `status` and an
  optional `note`.
- `/api/v1/admin/findings/{finding_id}/work-item/owner` takes `owner_kind` and
  `owner_label` together. Omit both to clear the owner.
- `/api/v1/admin/findings/{finding_id}/work-item/references` takes
  `reference_type`, `reference_system`, and `reference_label`.
- `/api/v1/admin/findings/{finding_id}/work-item/references/{reference_id}/remove`
- `/api/v1/admin/findings/{finding_id}/work-item/notes` takes `note`.

Request and response contracts reject unknown fields. A request cannot supply
`site_id`, a principal, a finding status, or a risk value. Errors are bounded:
`404` for a missing finding, work item, or active reference; `409` for an
existing work item, a stale revision, an invalid transition, a duplicate
reference, the reference limit, or a resolved finding at creation; `422` for
contract violations. Database errors return a generic `500`.

Example:

```sh
curl -sS -X POST \
  -H "Content-Type: application/json" \
  -H "X-OpenAssetWatch-Admin-Token: ${OPENASSETWATCH_ADMIN_TOKEN}" \
  --data '{"actor":"alex","owner_kind":"team","owner_label":"Network Ops"}' \
  http://127.0.0.1:8000/api/v1/admin/findings/fnd_<id>/work-item
```

No work-tracking endpoint triggers finding evaluation.

## Schema

Migration `backend/app/migration_sql/0005_finding_work_tracking.sql` is
additive. It adds:

- `uq_findings_id_site`, a unique index on `findings (finding_id, site_id)`
  that serves as the composite foreign-key target. `finding_id` is already the
  primary key, so existing rows always satisfy it;
- `finding_work_items`, `finding_work_references`, and `finding_work_events`
  with their indexes;
- the trigger function `oaw_finding_work_events_append_only()` and two triggers
  on `finding_work_events`;
- the trigger function `oaw_finding_work_items_cascade_only_delete()` and one
  `BEFORE DELETE` trigger on `finding_work_items`.

It changes no existing column and rewrites no existing row. Removed references
keep their row with `removed_at` and `removed_actor_label`, and the event
history keeps both the add and the removal.

**Before upgrading a persistent database to version 5, take a backup and
verify that it restores**, following
[DATABASE_MIGRATIONS.md](DATABASE_MIGRATIONS.md). Recovery is forward-only;
there is no automatic downgrade.

## Validation

Unit tests (no database):

```powershell
docker run --rm --volume "${PWD}:/workspace:ro" --workdir /workspace/backend `
  openassetwatch-backend-dev `
  python -m unittest -v tests.test_finding_work_tracking
```

The gated PostgreSQL suite creates random databases named
`openassetwatch_finding_work_test_<16-hex>` and refuses to drop anything else.
Run it only against a disposable PostgreSQL server:

```powershell
docker compose run --rm --volume "${PWD}:/workspace:ro" `
  --workdir /workspace/backend `
  --env OPENASSETWATCH_FINDING_WORK_POSTGRES_TEST=1 backend `
  python -m unittest -v tests.test_finding_work_postgres
```

It covers the full lifecycle, database-enforced site consistency and
unverified markers, append-only events, preservation across finding resolve
and reopen, unchanged finding and risk tables, stale-revision rejection, the
reference limit, and concurrent writers.

## Limits

- The schema-compatibility verifier checks tables, columns, keys, checks, and
  indexes. It does not yet check trigger presence. The gated PostgreSQL tests
  assert all three work-tracking triggers after migration.
- Upgrading to version 5 is one-way for the application: an older backend
  refuses to start against a database that has version 5 applied. Going back
  requires restoring the pre-upgrade backup, which discards work-tracking data.
- There is one shared admin principal. Per-user identity, RBAC, and tenant
  scoping are out of scope.
- Owner labels are not normalized or deduplicated across work items.
