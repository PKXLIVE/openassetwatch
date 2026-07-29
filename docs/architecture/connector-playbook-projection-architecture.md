# Connector, Playbook, and External Projection Architecture

## Purpose

This document defines a future, provider-neutral architecture for bringing approved external evidence into OpenAssetWatch, running governed playbooks, validating extension definitions, and projecting canonical OpenAssetWatch state into external systems.

The design fills several integration gaps without making any external platform, protocol implementation, model provider, or workflow engine mandatory.

The architecture remains:

- source-independent
- capability-driven
- tenant-scoped
- least-privilege
- read-only by default
- resilient to integration failure
- explicit about data egress
- safe to remove or replace

## Core Rule

> OpenAssetWatch remains the source of truth. Connectors import evidence, playbooks process approved context, and external systems receive projections. None of them may silently become a competing authority for assets, findings, cases, policy, or approvals.

## High-Level Flow

```text
External Evidence Sources
          |
          +-- Polled Connector
          +-- Signed Webhook
          +-- Token-Bound Inbox
          +-- File or Batch Import
          |
          v
Connector Gateway and Validation
          |
          v
Source-Specific Parser
          |
          v
Canonical Normalized Event or Evidence Envelope
          |
          v
OpenAssetWatch Evidence, Findings, Assets, and Cases
          |
          +----------------------+----------------------+
          |                      |                      |
          v                      v                      v
Read-Only Playbook        Analyst Workflow       External Projection
          |                                             |
          v                                             v
Governed Result                                  Ticket, Message, or Report
```

---

## 1. Connector Contract

### 1.1 Connector Definition

Every connector should publish a self-describing definition.

Suggested fields:

- `connector_type_id`
- `namespace`
- `name`
- `description`
- `version`
- `category`
- `source`
- `license`
- `publisher`
- `digest`
- `supported_transports`
- `capabilities`
- `configuration_schema`
- `authentication_schema`
- `secret_fields`
- `default_poll_interval_seconds`
- `minimum_poll_interval_seconds`
- `maximum_page_size`
- `normalization_profile`
- `health_check_type`
- `data_classifications`
- `egress_requirements`
- `review_state`
- `reviewed_at`
- `expires_at`

### 1.2 Connector Capabilities

Capabilities should be explicit rather than inferred from free-form descriptions.

Possible values:

- pull alerts or findings
- pull assets
- pull vulnerabilities
- pull identities
- pull configuration posture
- pull collector or agent status
- receive webhook events
- federated search
- push case projection
- push status projection
- push report
- create ticket
- query health
- test connection

A connector receives only the permissions associated with enabled capabilities.

### 1.3 Connector Instance

A connector instance represents one configured deployment of a connector type.

Suggested fields:

- `connector_instance_id`
- `connector_type_id`
- `tenant_id`
- `name`
- `enabled`
- `configuration_encrypted_ref`
- `credential_ref`
- `poll_interval_seconds`
- `checkpoint`
- `last_poll_started_at`
- `last_poll_completed_at`
- `last_success_at`
- `last_failure_at`
- `consecutive_failures`
- `circuit_state`
- `events_received`
- `events_normalized`
- `events_rejected`
- `health_state`
- `owner`
- `created_at`
- `updated_at`

---

## 2. Canonical Evidence Ingress Envelope

All sources should be normalized into a common envelope before entering the finding, asset, or case pipeline.

```json
{
  "envelope_version": "evidence_ingress.v1",
  "tenant_id": "tenant-1",
  "source_type": "configured_connector",
  "source_instance_id": "connector-9",
  "source_record_id": "source-123",
  "idempotency_key": "sha256:...",
  "received_at": "2026-07-24T12:00:00Z",
  "observed_at": "2026-07-24T11:58:00Z",
  "record_type": "security_signal",
  "schema_profile": "normalized_security_signal.v1",
  "payload": {},
  "artifact_candidates": [],
  "source_metadata": {},
  "unmapped_fields": {},
  "raw_record_ref": "raw-records/123",
  "sensitivity": "internal",
  "integrity": {
    "transport_authenticated": true,
    "message_verified": true
  }
}
```

### Required Principles

- tenant is established before normalization
- source record identity is retained
- duplicate delivery is idempotent
- unmapped fields are preserved separately
- raw source data is stored only according to policy
- secrets are never promoted into normalized evidence
- timestamps distinguish observed, received, and processed time
- normalization errors do not silently convert invalid data into facts

---

## 3. Polled Connector Runtime

### 3.1 Scheduler

The scheduler should create one bounded job per enabled connector instance.

Responsibilities:

- reload enabled instances periodically
- honor per-instance poll cadence
- prevent overlapping polls for the same instance
- persist checkpoints
- apply timeouts and page limits
- retry transient failures
- enforce per-tenant and global concurrency
- update health records
- open a circuit after repeated failures
- resume from the last safe checkpoint

### 3.2 Poll Flow

```text
Scheduler Selects Instance
          |
          v
Load Connector Definition
          |
          v
Obtain Short-Lived Credential Access
          |
          v
Fetch Records Since Checkpoint
          |
          v
Normalize Each Record
          |
          v
Submit Bounded Batch to Ingress API
          |
          v
Persist Checkpoint and Health
```

### 3.3 Checkpoint Safety

A checkpoint should advance only after the corresponding batch is durably accepted or safely deduplicated.

If a batch partially fails, the connector should retry from the last committed checkpoint rather than skip records.

### 3.4 Health States

- healthy
- degraded
- rate_limited
- authentication_failed
- schema_error
- circuit_open
- disabled
- expired
- unknown

Health should include the last successful record time, not only whether an HTTP request succeeded.

### 3.5 Circuit Breaker

Suggested behavior:

- closed — normal calls allowed
- open — calls fail fast during cooldown
- half-open — one bounded health or poll attempt allowed

Circuit-breaker events should be visible in integration operations and should not block unrelated connectors.

---

## 4. Universal Evidence Inbox

### Purpose

Some sources cannot support polling but can send webhooks, event batches, email-derived alerts, or gateway-forwarded records.

The Universal Evidence Inbox provides a narrow, template-bound ingress path.

### 4.1 Inbox Token

Each token should be bound to:

- tenant
- parser template
- allowed content type
- maximum request size
- rate limit
- allowed source addresses, when configured
- expiration
- enabled state
- optional message-signing requirement

Tokens should be:

- displayed only once at creation
- stored as a secure hash
- independently revocable
- rotated without changing the parser definition
- audited when created, rotated, disabled, or used abnormally

### 4.2 Message Integrity

Signed senders should use a timestamped message authentication signature over the exact request body.

The receiver should verify:

- signature
- timestamp freshness
- replay identifier
- token scope
- body size
- parser template

### 4.3 Template-Bound Parsing

A token must not select an arbitrary parser at request time. Its parser is assigned during token creation.

Parser profiles may include:

- generic JSON event
- key-value event
- standard syslog event
- structured security event
- DNS observation
- ticket-status callback
- collector status event

### 4.4 Rate and Resource Limits

- requests per minute
- records per request
- raw body size
- parser depth
- maximum string length
- maximum artifact count
- maximum unmapped-field size

### 4.5 Failure Behavior

Malformed records should return structured errors and should not block valid records in a batch unless transactional mode is explicitly requested.

Rejected records should be counted and optionally stored in a quarantined error queue with bounded retention.

---

## 5. Credential Boundary

### 5.1 Separate Authorities

Credential handling should separate:

- configuration write authority
- encryption authority
- runtime decrypt or proxy authority
- connector execution identity
- connection-test identity

The component that stores connector configuration should not automatically grant broad runtime access to all services.

### 5.2 Secret References

Connectors should receive secret references or short-lived proxy access rather than reusable plaintext credentials when possible.

### 5.3 Encryption and Rotation

Encrypted connector configuration should support:

- versioned ciphertext format
- key identifier
- current and previous decryption keys during rotation
- re-encryption job
- rotation audit record
- failure recovery
- emergency revocation

### 5.4 Stateless Connection Test

The connection-test operation should:

- accept temporary values from an authenticated administrator
- create the connector in memory
- perform a narrow health check
- redact the response
- avoid persisting unsuccessful credentials
- avoid writing secrets to logs
- expire temporary values immediately

A successful test does not automatically enable the connector.

### 5.5 Credential Use Audit

Audit metadata should record:

- connector instance
- secret reference
- operation type
- destination class
- success or failure
- timestamp

It should never record the secret value.

---

## 6. Normalization and Source Preservation

### 6.1 Normalization Profile

Each connector should map source fields into versioned canonical fields.

The profile should declare:

- source schema version
- canonical schema version
- field mappings
- severity mapping
- timestamp mapping
- identifier mapping
- artifact extraction rules
- sensitive-field rules
- default values
- required fields
- fallback behavior

### 6.2 Severity Mapping

A source-specific severity ladder may be normalized into OpenAssetWatch values, but the original severity must remain available.

### 6.3 Unmapped Fields

Unmapped source fields should remain in a bounded `unmapped_fields` object so future versions can recover useful context without re-ingesting the source.

### 6.4 Raw Record References

Normalized records should reference raw records rather than embedding them repeatedly. Raw retention must be configurable and shorter than normalized record retention when appropriate.

### 6.5 Schema Drift

The connector should detect:

- missing required fields
- new unknown fields
- type changes
- timestamp format changes
- source enum changes
- payload nesting changes

Schema drift should degrade the connector and create an operational finding rather than silently discarding data.

---

## 7. Connector and Extension Registry

### Purpose

Operators need a clear inventory of every loaded connector, module, playbook, parser profile, and schema extension.

### 7.1 Registry Objects

- connector definitions
- connector instances
- parser templates
- modules
- playbooks
- schema profiles
- report exporters
- external projection adapters
- model adapters
- tool adapters

### 7.2 Trust States

- unreviewed
- validating
- approved
- approved_with_restrictions
- degraded
- expired
- quarantined
- revoked
- rejected

### 7.3 Canonical Identity

An extension should be identified by:

- namespace
- type
- identifier
- version
- digest
- publisher

Display name alone must not determine identity.

### 7.4 Collision Policy

The registry should detect:

- duplicate identifiers
- similar display names
- namespace claims
- schema identifier collisions
- tool-name collisions
- unapproved overrides

Custom content should not silently replace an official or previously approved definition.

An override must be explicit, tenant-scoped where appropriate, and auditable.

---

## 8. Extension Packaging and Production Safety

### 8.1 Canonical Custom Directory

A future self-hosted deployment may support a documented custom extension directory with subdirectories for:

- modules
- playbooks
- parser and schema definitions
- optional prompt templates
- dependency manifest

### 8.2 Development Versus Production

Development fixtures and demonstration modules must remain separate from production runtime content.

Production packages should ship:

- empty custom directories or safe templates
- no test credentials
- no test modules
- no demonstration rules enabled by default
- no sample playbooks that can alter systems

### 8.3 Container Boundary

The application image should not automatically bundle local developer custom content. Production should load explicitly mounted, reviewed extensions.

### 8.4 Dependencies

Custom dependency changes should require:

- manifest update
- security scan
- license review
- image rebuild or controlled installation
- runtime restart when necessary

Dynamic installation from untrusted sources at application startup should be prohibited.

### 8.5 Failure Isolation

One malformed extension should not prevent unrelated approved extensions from loading.

The registry should report errors per file and per object.

A missing required prompt or schema should fail the affected playbook clearly. It must not fall back to an empty or unrelated prompt.

---

## 9. Administration and Validation Console

### Purpose

Administrators need a read-only operational view of loaded definitions and their health.

### 9.1 Suggested Sections

- Connectors
- Modules
- Playbooks
- Parser and schema profiles
- Projection adapters
- Tool adapters

### 9.2 Per-Section Operations

- reload view
- refresh and validate
- filter by source or state
- inspect definition metadata
- inspect validation errors
- inspect health
- inspect recent bounded stream or queue messages when authorized

Validation should be independent per section so a failure in one class does not hide valid definitions elsewhere.

### 9.3 Read-Only by Default

The definition console should not:

- execute playbooks
- send test events to production streams
- edit files
- delete messages
- expose secret values
- run arbitrary queries

Execution belongs to the case, playbook, or connector workflow where scope and permissions are available.

### 9.4 Audit Noise

Viewing or automatically refreshing definitions should not create excessive audit records.

Manual refresh, validation, enablement, disablement, approval, revocation, or configuration changes should be audited.

### 9.5 Health Details

A module or queue-backed integration may expose:

- available
- current length
- first and last message identifiers
- consumer-group state
- oldest pending message
- last processed time
- warning

Recent message inspection must be bounded and access-controlled.

---

## 10. Playbook Catalog

### 10.1 Official and Custom Namespaces

Playbooks should be grouped by explicit namespace and source.

A custom playbook may extend an official workflow but should not silently replace it. Override behavior requires explicit configuration and review.

### 10.2 Playbook Definition

Suggested fields:

- `playbook_id`
- `namespace`
- `name`
- `description`
- `version`
- `digest`
- `source`
- `tags`
- `case_categories`
- `trigger_types`
- `input_schema`
- `output_schema`
- `required_context`
- `required_tools`
- `required_permissions`
- `read_only`
- `requires_approval`
- `supports_dry_run`
- `max_runtime_seconds`
- `max_retries`
- `owner`
- `review_state`

### 10.3 Initial Safe Playbooks

- generate case summary
- retrieve asset and finding context
- enrich approved indicators
- assemble investigation report
- review evidence freshness
- identify missing evidence
- prepare remediation plan
- create sanitized external ticket draft
- extract a reviewed operational lesson after case closure

### 10.4 Run Record

Every run should capture:

- playbook and version
- case
- user or system requester
- trigger
- input
- job identifier
- state
- timestamps
- output reference
- remark
- error summary
- approval reference
- tool execution references

### 10.5 Stable Machine Output

Playbooks and command-line clients should support versioned JSON output for automation. Human-formatted text should not be the only contract.

---

## 11. External Projection Architecture

### Purpose

OpenAssetWatch may project cases, findings, approvals, or reports to external ticketing, messaging, or collaboration systems.

OpenAssetWatch remains authoritative.

### 11.1 External Reference Record

Suggested fields:

- `external_ref_id`
- `tenant_id`
- `object_type`
- `object_id`
- `connector_instance_id`
- `external_system_class`
- `external_object_id`
- `external_url`
- `external_status`
- `last_synced_at`
- `last_sync_direction`
- `last_sync_result`
- `idempotency_key`

### 11.2 Outbound Projection

```text
Canonical OpenAssetWatch Commit
          |
          v
Projection Event
          |
          v
Capability and Policy Check
          |
          v
Sanitization and Field Mapping
          |
          v
External Write
          |
          v
External Reference Update
```

The canonical commit occurs first. External failure must not roll it back.

### 11.3 Inbound Status Convergence

Inbound callbacks should:

- verify authentication and message integrity
- resolve the external reference
- map only approved status values
- enforce tenant scope
- apply idempotently
- append timeline and audit records
- reject unsupported field writes

### 11.4 Deliberately Lossy Mapping

External-specific metadata should remain external unless OpenAssetWatch has a canonical field for it.

This avoids expanding the core schema to mirror every external system.

### 11.5 Projection Failure

Failures should:

- record diagnostic metadata
- retry with bounds
- open a circuit when necessary
- surface an operational warning
- preserve canonical state
- support manual replay

### 11.6 Messaging and Approval Projection

An external message may display an approval request, but the approval state must be committed to OpenAssetWatch through an authenticated callback.

Signed callbacks, short-lived approval identifiers, expiration, and actor authorization are required.

External messaging is a projection, not the approval database.

---

## 12. Data Egress Profiles

Every connector and projection adapter should declare what leaves the deployment.

### Suggested Profiles

#### Local Only

- no external data processing
- local connectors and stores only
- suitable for air-gapped deployments

#### Restricted External Enrichment

- approved indicators or aliases only
- destination allowlist
- redaction required
- no internal asset inventory unless explicitly allowed

#### Approved External Projection

- bounded case or report fields
- destination and purpose known
- tenant policy permits the transfer
- audit and external reference required

### Egress Record

- request identifier
- tenant
- adapter
- destination class
- data classifications
- fields removed or aliased
- purpose
- policy decision
- success or failure
- timestamp

### Network Policy

Runtime network policy should enforce the configured destination allowlist rather than relying only on application code.

An air-gap test should run core workflows with outbound network blocked and prove that local-only operation remains functional.

---

## 13. Reliability and Observability

### Connector Metrics

- poll duration
- records fetched
- records normalized
- records rejected
- checkpoint age
- source lag
- authentication failures
- schema errors
- circuit state
- rate-limit events

### Inbox Metrics

- requests accepted and rejected
- signature failures
- token failures
- replay attempts
- parser errors
- quarantined records
- rate-limit events

### Playbook Metrics

- pending and running jobs
- success and failure rate
- duration
- cancellation
- approval wait time
- tool calls
- output size

### Projection Metrics

- projection attempts
- success and failure rate
- retry count
- external callback failures
- convergence lag
- stale external references

### Health Dashboard

The integration operations view should show:

- healthy, degraded, and disabled connectors
- oldest checkpoint
- top failing parser profiles
- open circuits
- playbook queue depth
- failed projections
- expiring credentials and reviews
- schema drift findings

---

## 14. Security Requirements

- Connector instances are tenant-scoped.
- Definitions are identified by namespace, version, and digest.
- Secret fields never appear in API responses after creation.
- Invalid connection-test credentials are not persisted.
- Inbox tokens are hashed and independently revocable.
- Signed messages have replay protection.
- Connector jobs use bounded concurrency and timeouts.
- Raw records are retained only according to policy.
- Custom content is not bundled into production images by default.
- One malformed definition does not disable unrelated integrations.
- Custom overrides are explicit and audited.
- Playbooks are read-only by default.
- External systems are projections, not sources of canonical case truth.
- Outbound data is minimized, redacted, and audited.
- External failures cannot roll back canonical writes.

---

## 15. Implementation Roadmap

### Phase 1: Connector Contracts

- define connector and capability schemas
- define connector instance and health records
- define normalized ingress envelope
- define checkpoints and idempotency

### Phase 2: Safe Ingress

- implement one read-only polled connector
- implement token-bound generic inbox
- add hashing, signing, rate limits, and bounded parsing
- preserve raw references and unmapped fields

### Phase 3: Credential Boundary

- add encrypted configuration references
- add key rotation
- add stateless connection test
- add credential-use audit metadata

### Phase 4: Registry and Validation Console

- inventory definitions and instances
- add independent refresh and validation
- add file-scoped errors
- add read-only health and bounded message inspection

### Phase 5: Read-Only Playbooks

- add catalog and typed definitions
- add case-linked run records
- add queue, cancellation, and idempotency
- support stable JSON output

### Phase 6: External Projections

- add external reference records
- add asynchronous outbound projection
- add signed inbound status convergence
- add retry, circuit breaker, and manual replay

### Phase 7: Hardening

- add runtime destination allowlists
- add schema-drift detection
- add extension digest verification
- add production packaging tests
- add air-gap workflow test

---

## 16. Acceptance Criteria

The initial integration architecture should not be considered production-capable until:

- every connector has a typed definition and capability list
- tenant scope is established before normalization
- duplicate delivery is idempotent
- checkpoints advance only after durable acceptance
- credential values remain outside normal logs and responses
- connection testing does not persist failed secrets
- universal inbox tokens are hashed, scoped, rate-limited, and revocable
- message integrity and replay protection are tested
- schema drift creates visible health findings
- custom extensions are separated from production defaults
- validation errors are isolated by definition
- playbooks have typed input, output, and run states
- external projections occur after canonical writes
- external failure cannot corrupt canonical state
- outbound data flow is documented and audited
- local-only operation succeeds with network egress blocked

## Relationship to Other Architecture Documents

- `docs/architecture/security-investigation-case-operations.md`
- `docs/architecture/detection-feedback-response-governance.md`
- `docs/architecture/ai-agent-permission-output-security.md`
- `docs/architecture/defensive-ai-security-gap-backlog.md`
- `docs/architecture/experimental-external-ai-support.md`
