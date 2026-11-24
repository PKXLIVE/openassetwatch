# Authenticated endpoint-agent identity and inventory

OpenAssetWatch has an additive endpoint-agent identity path for the primary Go
agent. It does not replace passive sensors, the Python collector compatibility
routes, or any deterministic classification, vulnerability, finding, or risk
engine.

## Authority flow

The hub is the identity authority:

1. An administrator with the configured admin secret creates a site-bound,
   one-time endpoint enrollment.
2. The agent exchanges that enrollment once and receives a server-generated
   `agent_id` plus one replaceable credential.
3. The hub stores only SHA-256 digests and lookup identifiers. The raw values
   are returned only when issued.
4. Authenticated check-in and inventory requests derive site, agent,
   deployment, and agent type from the credential record. Matching payload
   fields are compatibility assertions, never authority.
5. Inventory is normalized through the existing local-inventory asset,
   classification-evidence, and component path. A new authoritative asset
   model is not created.
6. Existing deterministic engines remain authoritative. AI Advisor remains
   read-only and may only explain persisted server-issued IDs.

Authentication proves which enrolled source sent a report. It does not prove
that every reported hostname, package, operating-system value, or other fact is
correct. Each fact retains its evidence method, freshness, confidence, and
deterministic evaluation semantics.

## Token formats and lifecycle

Endpoint identity uses namespaces distinct from passive-sensor identity:

- enrollment: `oaw_agent_enroll_v1.<lookup>.<secret>`
- credential: `oaw_agent_v1.<lookup>.<secret>`

Lookups and secrets are cryptographically random. Enrollment is one-time,
expires, is transactionally locked during exchange, and has bounded failed
attempt handling. Credentials bind one canonical agent to one site, one type,
and an optional reviewed deployment identifier. Rotation immediately marks
the prior credential rotated and preserves predecessor/replacement history.
Check-in and inventory persistence lock and revalidate the exact credential.
A request already holding that persistence lock finishes before an
administrator's rotation or revocation returns; after the transition returns,
the prior credential cannot commit new check-in or inventory state.

Agent and sensor token prefixes, tables, and authentication functions are
separate. Neither credential type can authenticate as the other.

## API surface

State-changing administration fails closed unless
`OPENASSETWATCH_ADMIN_TOKEN` is configured:

- `POST /api/v1/admin/agent-enrollments`
- `GET /api/v1/admin/agent-enrollments`
- `GET /api/v1/admin/agent-enrollments/{enrollment_id}`
- `POST /api/v1/admin/agent-enrollments/{enrollment_id}/revoke`
- `GET /api/v1/admin/agents`
- `POST /api/v1/admin/agents/{agent_id}/credentials/rotate`
- `POST /api/v1/admin/agents/{agent_id}/credentials/{credential_id}/revoke`
- `POST /api/v1/admin/agents/{agent_id}/revoke`
- `GET /api/v1/admin/agent-identity/audit`

Agent operations are:

- `POST /api/v1/agents/enroll`
- `POST /api/v1/agents/check-in`
- `POST /api/v1/agents/inventory`

Bound requests use `X-OpenAssetWatch-Agent-Credential`. The body middleware
limits enrollment to 8 KiB, check-in to 16 KiB, and inventory to 4 MiB,
including chunked bodies. Authentication errors are generic. Responses, audit
events, UI data, AI evidence, and logs do not include raw token material,
authorization headers, or unrestricted payloads.

## Inventory contract and replay behavior

`oaw.endpoint-inventory.v1` is strict and rejects unknown fields. It bounds
strings, timestamps, assets, interfaces, addresses, evidence, components, and
aggregate nested counts. Observations more than 30 days old or more than five
minutes in the future are rejected. Client-supplied component evidence IDs are
rejected because evidence IDs are server-issued.

The client may declare complete or partial inventory. Only a complete report
from a bound endpoint credential can close missing components for that source.
The hub injects source authentication, source authority, canonical IDs,
credential lineage, source type, and ingestion time. Payload fields cannot set
risk, findings, management state, severity, or site/agent/tenant authority.

Idempotency is persisted by the common canonical ingestion service under the
server-derived endpoint source and `inventory_batch_id`. The hub hashes the
canonical validated client body. An identical retry returns the original
canonical, storage, and compatibility collection IDs without duplicating
assets, components, vulnerability matches, findings, or risk. Reusing a batch
ID with different content returns a conflict. See
[CANONICAL_INGESTION_COMPATIBILITY.md](CANONICAL_INGESTION_COMPATIBILITY.md).

New snapshots record reevaluation as `queued`. Bounded background work targets
only the affected site and assets, then records `running`, `completed`, or
`retryable-failure`. Ingestion stays accepted if deterministic reevaluation
needs a retry; the acknowledgement never falsely reports queued work complete.
The hub serializes new batches per bound agent and admits at most 12 new batch
IDs per rolling minute. Exact identical replay is checked before that limit and
continues returning the original acknowledgement.

## Go agent lifecycle

The agent accepts enrollment material only from a protected file or standard
input, never as a command-line value:

```text
oaw-agent enroll --server-url https://hub.example.test --enrollment-token-file ENROLLMENT_FILE
oaw-agent credential-status
oaw-agent replace-credential --credential-id REPLACEMENT_ID --new-credential-file REPLACEMENT_FILE
oaw-agent clear-credential --confirm-clear
```

When the credential file exists, `check-in`, `submit`, and `run-once`
automatically use the authenticated fixed routes. Without one, the existing
compatibility routes remain available and their evidence stays untrusted.
Credentialed transport requires HTTPS except for explicit loopback development,
rejects URL credentials and redirects, disables proxy forwarding, uses fixed
hub paths, and bounds response bodies.

The credential record is separate from non-secret configuration and identity:

| Platform | Default credential record |
| --- | --- |
| Windows | `%ProgramData%\OpenAssetWatch\Agent\state\credential\credential.json` |
| Linux | `/var/lib/openassetwatch/agent/credential/credential.json` |
| macOS | `/Library/Application Support/OpenAssetWatch/Agent/state/credential/credential.json` |

The writer creates a private directory, uses a randomized exclusive temporary
file, mode `0600` where POSIX modes apply, flushes data, atomically replaces in
the same directory, rejects symlinks and non-regular files, and rejects
multiple links where the operating system exposes a reliable link count.
Failed validation leaves the current credential unchanged.

Windows standalone Go code does not claim portable DACL-owner validation. The
MSI creates a SYSTEM-owned protected credential-directory DACL for
Administrators, SYSTEM, and the service SID. Its deferred SYSTEM action checks
the known-folder path component by component, fails closed on unsafe ownership,
broad or otherwise unreviewed write-capable access, delete-child grants,
reparse points, replacement attempts, or open credential-state handles, and repairs
existing bounded direct credential files through pinned handles during
install, repair, and upgrade. Linux DEB/RPM and macOS packages create the
credential directory for the service identity with mode `0700`. Unpackaged
installations must establish equivalent ownership and access controls before
enrollment.

## Legacy compatibility

`POST /api/v1/collections/local-inventory` and check-ins without a bound
credential remain compatibility paths. Their client-declared identity never
becomes direct endpoint authority. A legacy enrollment or check-in is rejected
when its submitted agent ID collides with an active bound identity, and the
authenticated collection uses a separate internal dedupe namespace so a
lower-trust batch cannot preseed its evidence record. The explicitly configured
`OPENASSETWATCH_AGENT_TOKEN` retains local-development shared-token behavior,
but it is also lower trust and cannot call the canonical authenticated
inventory route. The passive-sensor enrollment and observation behavior is
unchanged.

The current Go inventory collector reports host, platform, interface, and
bounded machine-level native software evidence. Native source completeness is
carried through the authenticated canonical-ingestion contract so only a
server-validated complete source snapshot can withdraw prior source presence.

## Synthetic demonstration and development measurement

`scripts/demo_endpoint_agent_identity.py` creates and drops only a randomly
named `openassetwatch_agent_demo_<hex>` database. It refuses to run unless
`OPENASSETWATCH_ENDPOINT_AGENT_DEMO=1` and `DATABASE_URL` are explicitly set.
The script uses fictional inventory and the repository's synthetic advisory
catalog, performs no network feed access, never prints token material, and
reports the issued server IDs only after the complete lifecycle succeeds.

Run the default one-component acceptance flow from a disposable development
Python environment with a PostgreSQL administrator URL supplied through the
process environment:

```text
OPENASSETWATCH_ENDPOINT_AGENT_DEMO=1 python scripts/demo_endpoint_agent_identity.py
```

Set `OPENASSETWATCH_ENDPOINT_AGENT_DEMO_COMPONENTS=500` to reproduce the
bounded development workload. On 2026-08-20, one Windows Docker Desktop run
with one agent, 32 fictional interfaces, 64 fictional evidence entries, and
500 fictional components persisted all 500 components and completed targeted
classification, vulnerability, finding, and risk reevaluation in 3379.493 ms.
This is a single synthetic development measurement, not a production capacity
claim or a cross-platform benchmark.

The demonstration verifies enrollment replay rejection, site substitution
rejection, authenticated check-in, idempotent inventory retry, conflicting
batch rejection, direct evidence persistence, deterministic component/match/
finding/risk results, advisory-only AI citations, immediate old-credential
rejection after rotation, revocation, and retained secret-free audit history.

## Migration and recovery

Migration `0002_endpoint_agent_identity.sql` adds digest-only endpoint
enrollments and credentials, secret-free identity audit events, and inventory
batch replay/reevaluation state. It is discovered, checksummed, ordered, and
applied by the versioned migration runner. Service modules contain no new DDL.
Fresh databases and version-1 databases use the same runner; direct SQL
execution remains unsupported.

If a local credential is lost, revoke its server record, create a new
site-bound enrollment, and enroll again. If a rotation response was issued but
local replacement failed, preserve the existing file, revoke the unused new
credential, and repeat rotation. Never copy token values into logs, tickets,
UI fields, AI prompts, or repository files.

## Current limitations

- Credentials are bearer tokens, not mTLS, device certificates, TPM-backed
  keys, or hardware attestation.
- User/RBAC, SSO, tenancy expansion, asset merge/split, and distributed task
  execution remain future work.
- Package definitions create platform-private credential directories. Installed
  ownership/DACL and upgrade-preservation evidence is platform-specific CI;
  source validation alone is not runtime installation proof.
- AI Advisor is advisory-only. It cannot enroll, rotate, revoke, classify,
  create matches, change findings, or change risk.
