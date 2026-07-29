# Sensor Enrollment and Bound Identity

OpenAssetWatch passive sensors use a one-time enrollment token to obtain a
long-lived bearer credential bound to exactly one site, sensor ID, and sensor
type. The hub derives the authenticated identity from that credential and
rejects an observation or sensor check-in whose claimed identity differs.

This is stronger than the local-development shared collector token because one
sensor can be rotated or revoked without changing every spoke. It remains a
bearer-token design: it does not attest hardware, boot state, or possession of
a private key. Certificate-bound enrollment is future work.

## Trust and secret model

The two secret formats are structurally distinct:

```text
oaw_enroll_v1.<non-secret-lookup-id>.<256-bit-random-secret>
oaw_sensor_v1.<non-secret-lookup-id>.<256-bit-random-secret>
```

Both secrets contain 256 bits from the operating system CSPRNG. PostgreSQL
stores only the non-secret lookup ID and a SHA-256 digest of the complete
high-entropy value. Verification uses constant-time digest comparison.
Enrollment and credential list/detail responses omit lookup IDs, digests, and
raw secret values.

An enrollment token is site-bound, expires after a bounded interval, has a
fixed attempt limit, and becomes unusable in the same database transaction
that issues the credential. `SELECT ... FOR UPDATE` serializes concurrent
exchange attempts, so one token cannot issue two active credentials. A
credential is authoritative for:

- `site_id`
- `sensor_id`
- `sensor_type` (`passive-network-sensor` in this release)

The payload cannot override these bindings. Mismatches, rotated credentials,
expired credentials, and revoked credentials all receive the same bounded
HTTP 401 response.

## Lifecycle

1. Create the destination site if it does not already exist.
2. An administrator creates a short-lived enrollment.
3. The creation response shows the enrollment token once.
4. The sensor reads the token from an environment variable, protected file, or
   standard input and exchanges it over HTTPS (loopback HTTP is development
   only).
5. The hub atomically enrolls the stable sensor identity, consumes the token,
   and returns the per-sensor credential once.
6. `oaw-sensor` writes the credential to a separate private file using a
   randomized same-directory temporary file, file flush, and atomic rename.
7. Upload and sensor check-in requests continue using
   `X-OpenAssetWatch-Collector-Token`; the token prefix selects bound-sensor
   verification instead of shared development-token comparison.
8. An administrator can rotate the credential or revoke a credential, an
   unused enrollment, or the whole sensor identity.

If the exchange succeeds but the response is lost, replaying the one-time
token returns the generic failure and cannot recover the previously issued
secret. Revoke the affected sensor or create a replacement enrollment for the
same identity and enroll again. A successful replacement enrollment
transaction retires any prior active credential for that sensor.

## Administrative API

Credential-issuing administration fails closed unless
`OPENASSETWATCH_ADMIN_TOKEN` is configured. Supply it in
`X-OpenAssetWatch-Admin-Token`; never put it in a URL.

| Method and path | Result |
| --- | --- |
| `POST /api/v1/admin/sensor-enrollments` | Create a site-bound enrollment and show its raw token once. |
| `GET /api/v1/admin/sensor-enrollments` | List secret-free enrollment status. |
| `GET /api/v1/admin/sensor-enrollments/{enrollment_id}` | Inspect one secret-free enrollment. |
| `POST /api/v1/admin/sensor-enrollments/{enrollment_id}/revoke` | Revoke an unused enrollment. |
| `GET /api/v1/admin/sensors` | List credential and identity status without secret material. |
| `POST /api/v1/admin/sensors/{sensor_id}/credentials/rotate` | Retire active credentials and show the replacement once. |
| `POST /api/v1/admin/sensors/{sensor_id}/credentials/{credential_id}/revoke` | Revoke one credential. |
| `POST /api/v1/admin/sensors/{sensor_id}/revoke` | Revoke the sensor and all active credentials. |
| `GET /api/v1/admin/sensor-identity/audit` | Read bounded, secret-free identity audit events. |
| `POST /api/v1/sensors/enroll` | Exchange the one-time token. |
| `POST /api/v1/sensors/check-in` | Submit bound sensor health metadata. |

Example enrollment request body:

```json
{
  "site_id": "example-site",
  "requested_sensor_id": "sensor-example-01",
  "requested_sensor_name": "Example Passive Sensor",
  "sensor_type": "passive-network-sensor",
  "expires_in_minutes": 60
}
```

Store the returned enrollment token immediately in an approved secret channel.
It is not available from list or detail APIs.

## Sensor configuration and commands

Keep non-secret configuration, stable identity, the credential, and the spool
as separate paths:

```json
{
  "hub_url": "https://hub.example.test",
  "site_id": "example-site",
  "sensor_id": "sensor-example-01",
  "sensor_name": "Example Passive Sensor",
  "capture_mode": "live",
  "capture_interface": "enp2s0",
  "identity_path": "/var/lib/openassetwatch/sensor/identity.json",
  "credential_path": "/var/lib/openassetwatch/sensor/credential.json",
  "spool_path": "/var/lib/openassetwatch/sensor/spool",
  "credential_env": "OPENASSETWATCH_SENSOR_CREDENTIAL",
  "token_env": "OPENASSETWATCH_COLLECTOR_TOKEN",
  "batch_size": 250,
  "batch_interval_seconds": 60,
  "request_timeout_seconds": 10,
  "retry_initial_seconds": 2,
  "retry_max_seconds": 300,
  "spool_max_items": 1000,
  "spool_max_bytes": 268435456,
  "aggregation_max_devices": 2048,
  "aggregation_ttl_seconds": 1800
}
```

Preferred one-time token input:

```text
OPENASSETWATCH_SENSOR_ENROLLMENT_TOKEN=<one-time-enrollment-token>
go run ./cmd/oaw-sensor enroll --config <sensor-config-path>
```

Protected-file input:

```text
go run ./cmd/oaw-sensor enroll --config <sensor-config-path> \
  --enrollment-token-file <private-token-file>
```

Piped standard input is also available with `--enrollment-token-stdin`. There
is deliberately no command-line flag that accepts the raw token value.

Local status and credential maintenance:

```text
go run ./cmd/oaw-sensor credential-status --config <sensor-config-path>
go run ./cmd/oaw-sensor replace-credential --config <sensor-config-path>
go run ./cmd/oaw-sensor clear-credential --config <sensor-config-path> --confirm-clear
```

`replace-credential` reads the replacement from
`OPENASSETWATCH_SENSOR_CREDENTIAL` by default, or from
`--credential-file`/`--credential-stdin`. It never prints the value. Clear
removes only the local file; revoke the hub credential separately. It refuses
to claim success while an environment override is active.

For containers and managed secret injection, set
`OPENASSETWATCH_SENSOR_CREDENTIAL`. The environment value takes precedence
over the credential file. Ordinary status, health, replay, and live output
report only the authentication mode and availability.

## Local storage boundaries

On Linux and macOS, the credential root must be owned by the sensor service
identity and grant no group or other access. Credential reads reject symlinks,
non-regular files, path replacement, unsafe ownership/mode, and multiple hard
links. Writes use mode `0600`, an exclusive randomized temporary file, `fsync`,
and same-directory atomic rename.

On Windows, rooted path handling and non-symlink regular-file checks remain in
force, but the standalone Go CLI does not claim portable owner, DACL, or NTFS
link-count verification. Provision the state directory with the same explicit
Administrators, SYSTEM, and dedicated service-identity ACL model used by the
Windows agent installer. Native sensor packaging should automate and validate
that ACL before production use.

## Rotation, revocation, and evidence

Rotation creates the replacement and retires the old credential in one
transaction. The old value is rejected immediately after the transaction
commits; no grace period exists. Transfer the returned replacement through an
approved secret channel, then run `replace-credential`.

Revoking a sensor marks its hub identity revoked and rejects future uploads and
check-ins. Previously normalized observations and assets remain in PostgreSQL,
and the AI Advisor can continue citing that historical evidence. Revocation
does not delete asset history.

Audit events include enrollment creation/completion/expiration/replay,
credential use/rotation/revocation, sensor revocation, and identity mismatch.
They contain bounded identifiers and reason codes, never tokens, credential
digests, request headers, credential-file contents, or submitted secret text.

## Development compatibility and abuse controls

If `OPENASSETWATCH_COLLECTOR_TOKEN` is explicitly non-empty, a non-prefixed
value matching it remains accepted on sensor observation and check-in paths as
`development-shared` authentication. An empty variable does not enable
anonymous sensor ingestion. This mode is intended only for local demos and
cannot prevent cross-sensor substitution by holders of the shared value.

The public exchange has bounded Pydantic fields, an 8 KiB ASGI body limit
(including chunked bodies), one-hour default/five-minute minimum token expiry,
atomic one-time use, a ten-attempt token limit, generic failures, and a bounded
per-source process limiter. The attempt counter and replay protection are
PostgreSQL-backed and work across API workers. The source limiter is
deliberately process-local; a multi-instance deployment must also enforce a
shared rate limit at its reverse proxy or API gateway.

## Synthetic end-to-end demonstration

Start the local Compose backend with an explicit admin token in the process
environment, then run:

```text
python scripts/demo_sensor_enrollment.py
```

The script uses only synthetic TEST-NET evidence. It proves enrollment,
one-time replay rejection, accepted and duplicate observations, site/sensor
substitution rejection, rotation, old/new credential behavior, revocation,
historical evidence retention, deterministic AI evidence visibility, and
secret-free administrative views. Its output contains no token or credential.

## Future work

- certificate- or hardware-bound enrollment and mutual TLS
- an enterprise secret-store/installer integration for each platform
- shared multi-instance rate limiting at the gateway
- tenant-aware RBAC and scoped administrator identities
- credential activation handshakes or carefully bounded rotation overlap
- native sensor packaging that provisions Windows DACLs and service identity
