# Threat Intelligence Exchange Boundary

- **Status:** Accepted design; exchange runtime not yet implemented
- **Decision:** `docs/architecture/decisions/0007-threat-intelligence-exchange-boundary.md`
- **Relationship:** Specializes `connector-playbook-projection-architecture.md`, `external-intelligence-enrichment-roadmap.md`, `ai-adversarial-input-and-injection-evaluation.md`, and the Safe Output Gate in `ai-agent-permission-output-security.md`

## Purpose

OpenAssetWatch needs a safe, provider-neutral way to exchange structured cyber-threat intelligence with approved external systems without turning an external feed, exchange protocol, remote collection, or AI-generated interpretation into a competing source of truth.

This design fills the remaining exchange gap for:

- discovery of approved intelligence exchange surfaces;
- explicitly scoped intelligence collections;
- versioned object manifests and incremental synchronization;
- partial-ingestion and publication receipts;
- separate tenant, collection, object, and operation authorization;
- preservation of object provenance, freshness, versions, and withdrawal state;
- pre-model admission controls for external descriptive content;
- bounded context size and decoding behavior;
- sanitized outbound intelligence publication through a separate narrow identity; and
- clear separation between authenticated transport and trusted evidence.

No particular protocol implementation, schema library, storage engine, provider, or external platform is mandatory. Compatibility belongs behind replaceable adapters.

## Core Rules

1. OpenAssetWatch remains authoritative for OpenAssetWatch state.
2. Transport authentication proves source identity, not content truth.
3. Collection capabilities do not grant user or service authorization.
4. Inbound and outbound trust lifecycles are separate.
5. External descriptive text remains untrusted for AI purposes.
6. Protocol adapters translate transport semantics; they do not own canonical state.
7. Partial processing must be reported explicitly.
8. Schema validity does not prove semantic applicability, authorization, or truth.
9. AI agents and analytical workers do not publish directly to external intelligence collections.
10. Exchange outages must not weaken local-first operation or invalidate already accepted evidence.

## 1. High-Level Architecture

```text
Approved External Intelligence Exchange
                 |
                 v
        Protocol / Transport Adapter
                 |
                 v
       Exchange Security Boundary
                 |
      +----------+-----------+
      |          |           |
      v          v           v
Authentication Authorization Resource Limits
      |          |           |
      +----------+-----------+
                 |
                 v
      Collection / Object Validation
                 |
                 v
       Content Trust Classification
                 |
                 v
   Canonical External Intelligence Envelope
                 |
                 v
 Existing OpenAssetWatch Evidence Boundaries
                 |
      +----------+----------+-----------+
      |                     |           |
      v                     v           v
Correlation Candidates  Intelligence  Investigation Context
                           Watch
      |                     |           |
      +----------+----------+-----------+
                 |
                 v
       Deterministic / Human Verification
```

Outbound sharing is separate:

```text
Verified OpenAssetWatch Evidence
                 |
                 v
          Share Candidate
                 |
                 v
       Shareability / Scope Policy
                 |
                 v
      Sensitive Content Inspection
                 |
                 v
        Claim / Evidence Validation
                 |
                 v
       Human Approval When Required
                 |
                 v
       Narrow Exchange Publisher
                 |
                 v
     Approved External Collection
                 |
                 v
          Delivery Receipt
```

## 2. Exchange Endpoint Contract

An exchange endpoint represents one approved remote intelligence service or local exchange peer.

Suggested fields:

```text
exchange_endpoint_id
namespace
name
enabled
transport_profile
schema_profiles
base_endpoint_ref
credential_ref
server_identity_policy
allowed_tenants
allowed_collections
allowed_directions
content_types
maximum_object_bytes
maximum_batch_objects
maximum_page_size
minimum_poll_interval
request_timeout
retention_profile
trust_state
owner
reviewed_at
expires_at
last_success_at
last_failure_at
health_state
```

An endpoint definition must use reviewed configuration rather than caller-supplied arbitrary destinations. It must declare supported directions, content profiles, resource limits, identity policy, and credential references. Newly advertised capabilities never become enabled merely because a remote service announces them.

## 3. Discovery and Service Metadata

Some exchange protocols expose discovery metadata describing service partitions, collections, supported versions, or content profiles. OpenAssetWatch may consume such metadata through a bounded Exchange Discovery Profile.

Discovery is informational only. It cannot:

- create tenant mappings;
- grant read or write authority;
- enable a new collection automatically;
- change credential scope;
- expand an approved destination; or
- change the canonical OpenAssetWatch schema.

Unexpected service identity, content profile, endpoint path, or capability drift should degrade the endpoint and require review.

## 4. Intelligence Collection Contract

An Intelligence Collection is a scoped logical exchange surface. It is not a canonical OpenAssetWatch datastore and does not determine truth.

```yaml
schema: oaw.intelligence-collection.v1
collection_id: external-vulnerability-context
namespace: exchange
version: 1

tenant_scope:
  mode: single_tenant
  tenant_id: tenant-1

direction:
  inbound: true
  outbound: false

content_classes:
  - vulnerability_context
  - infrastructure_indicator

capabilities:
  supports_read: true
  supports_write: false
  supports_manifest: true
  supports_version_query: true

policy:
  inbound_trust: external_unverified
  outbound_requires_approval: true

limits:
  max_page_size: 500
  max_object_bytes: 1048576
  max_batch_objects: 1000

retention_profile: external-intelligence-default
review_state: approved_with_restrictions
```

### Collection Capability vs Authorization

Collection capability describes what the exchange surface technically supports. Authorization remains a separate chain:

```text
Authenticated Principal
        |
        v
Tenant Authorization
        |
        v
Collection Authorization
        |
        v
Object Authorization
        |
        v
Operation Authorization
```

For example, `supports_write: true` does not grant write permission to any user, agent, service, or tenant.

## 5. Canonical Intelligence Object Envelope

Every inbound object should be projected into an OpenAssetWatch-owned envelope before correlation or AI use.

```json
{
  "schema": "oaw.external-intelligence-object.v1",
  "exchange_object_id": "extintel-123",
  "tenant_id": "tenant-1",
  "exchange_endpoint_id": "exchange-1",
  "collection_id": "collection-7",
  "source_object_id": "source-object-42",
  "object_type": "indicator",
  "source_version": "2026-08-28T00:00:00Z",
  "source_created_at": "2026-08-20T00:00:00Z",
  "source_modified_at": "2026-08-28T00:00:00Z",
  "received_at": "2026-08-28T00:05:00Z",
  "content_digest": "sha256:...",
  "source_identity": "configured-source",
  "transport_authenticated": true,
  "trust_state": "external_unverified",
  "freshness_state": "current",
  "withdrawn": false,
  "content_profile": "structured-cti-v1",
  "normalized_payload": {},
  "raw_record_ref": null,
  "provenance": {},
  "ai_content_class": "untrusted_external_content"
}
```

Required properties:

- tenant scope is established before normalization;
- source identity and source object identity are retained;
- source version time is distinct from retrieval time;
- transport authentication remains separate from content trust;
- aliases do not replace server-issued OpenAssetWatch identities;
- descriptive strings remain untrusted for model-context purposes; and
- withdrawal does not erase historical evidence or audit records.

## 6. Intelligence Object Manifest

OpenAssetWatch should support lightweight manifests so incremental synchronization does not require complete payload retrieval merely to determine whether an object exists or changed.

```json
{
  "object_id": "source-object-42",
  "object_type": "indicator",
  "version": "2026-08-28T00:00:00Z",
  "modified_at": "2026-08-28T00:00:00Z",
  "content_digest": "sha256:...",
  "collection_id": "collection-7",
  "withdrawn": false
}
```

Manifest uses include incremental synchronization, duplicate suppression, version comparison, stale-object detection, selective retrieval, reconciliation, and auditing. A manifest is metadata about an external claim, not proof that the claim is correct.

## 7. Version and Withdrawal Semantics

External intelligence may be corrected, superseded, or withdrawn. OpenAssetWatch should preserve version history rather than overwrite silently.

```text
first_received
  -> current_external_version
  -> updated_external_version
  -> superseded
  -> withdrawn
  -> retained_for_history
```

Rules:

- older versions cannot overwrite newer accepted versions;
- equal IDs and equal declared versions with conflicting content are conflicts;
- withdrawal changes current external state but does not delete historical evidence;
- withdrawal does not automatically resolve an OpenAssetWatch finding;
- every material source-version transition is auditable; and
- correlation records which external version supported a candidate relationship or claim.

## 8. Incremental Synchronization and Checkpoints

```text
Load Last Committed Checkpoint
        |
        v
Retrieve Manifest / Changed Page
        |
        v
Validate Bounds and Identity
        |
        v
Retrieve Needed Objects
        |
        v
Validate / Normalize / Admit
        |
        v
Durably Commit Accepted Batch
        |
        v
Advance Checkpoint
```

Checkpoint rules:

- advance only after durable acceptance or safe deduplication;
- do not skip failed objects unless the transport supplies an explicit replay-safe cursor model;
- retain endpoint, collection, direction, source cursor/version, and last committed object metadata;
- replayed pages remain idempotent;
- source sequence rollback or unexpected cursor regression is visible; and
- endpoint failure cannot corrupt another collection's checkpoint.

## 9. Ingestion and Publication Receipts

A successful request is not equivalent to complete processing. Every batch should produce a typed receipt.

```json
{
  "exchange_run_id": "exchange-run-882",
  "direction": "inbound",
  "received": 250,
  "accepted": 230,
  "rejected": 8,
  "pending": 12,
  "duplicates": 41,
  "correlated": 73,
  "candidate_findings": 9,
  "confirmed_findings": 0
}
```

Possible per-object states:

- accepted
- duplicate
- rejected_schema
- rejected_scope
- rejected_policy
- quarantined_content
- pending_normalization
- pending_correlation
- superseded
- withdrawn

`confirmed_findings` must remain zero for exchange ingestion itself. Only the existing deterministic finding pipeline can create authoritative findings.

Outbound receipts should distinguish queued, sent, acknowledged, rejected, partially accepted, expired, and failed deliveries.

## 10. CTI Content Trust Boundary

Threat-intelligence text may contain descriptions, analyst notes, report prose, URLs, labels, campaign narratives, or other content that is safe to store but unsafe to interpret as instructions.

```text
External CTI Object
       |
       v
Transport Validation
       |
       v
Schema Validation
       |
       v
Trust = External / Untrusted
       |
       +--> bounded normalization
       +--> sensitive-content inspection
       +--> optional heuristic injection classification
       +--> context admission limits
       |
       v
Canonical Intelligence Evidence
       |
       v
AI Context Assembly
       |
       v
Monotonic Taint Preserved
```

### Required Invariant

> An authenticated intelligence source is a trusted transport/source identity, not a trusted model instruction channel.

Signing, TLS, authenticated collection membership, or source reputation cannot upgrade imported descriptive text into system policy or operator intent.

## 11. Preflight Content Classifier

OpenAssetWatch may use an optional heuristic classifier before untrusted textual intelligence enters model context.

Suggested output:

```json
{
  "content_id": "external-intel-122",
  "classification": "suspicious_instruction_content",
  "score": 0.84,
  "trust_state": "external_untrusted",
  "recommended_treatment": "restrict_model_projection"
}
```

Rules:

- classifier output is advisory;
- `safe` never upgrades trust;
- suspicious output may make handling more restrictive;
- classifier failure cannot widen access or disable deterministic controls;
- raw classifier prompts or full external documents should not be retained by default; and
- evaluation belongs under `ai-adversarial-input-and-injection-evaluation.md`.

## 12. Context Admission Budget

Resource limits should apply before expensive model processing.

```yaml
context_admission:
  max_total_bytes: 1048576
  max_objects: 100
  max_object_bytes: 65536
  max_untrusted_text_bytes: 262144
  max_nested_depth: 8
  max_decoded_expansion_ratio: 20
  max_external_sources: 16
```

The final values are deployment and task-class policy, but the control classes are required.

Admission limits protect against context flooding, parser amplification, encoded expansion, token-cost amplification, excessive retrieved evidence, and denial of service. Exceeding a limit should produce an explicit truncation, rejection, or fallback state rather than silently omitting material evidence.

## 13. Correlation and Verification Lifecycle

Inbound intelligence lifecycle:

```text
received
  -> schema_validated
  -> source_authenticated
  -> content_untrusted
  -> normalized
  -> correlated
  -> candidate
  -> corroborated
  -> verified | contradicted | expired | withdrawn
```

Important rules:

- source authentication does not skip `content_untrusted`;
- correlation is not verification;
- repeated copies from the same source family are not independent corroboration;
- vulnerability applicability still requires the existing deterministic component/version matcher;
- missing external data is unknown, not safe; and
- current security news or intelligence can trigger review but not prove compromise.

## 14. Sanitized Intelligence Publisher

Outbound sharing must pass through a dedicated publication path.

The publisher receives only:

- approved canonical object or artifact identifiers;
- approved collection and endpoint;
- expected content digest;
- approved share profile;
- approval record when required;
- expiration; and
- narrow publication capability.

The publisher must not receive:

- unrestricted database access;
- broad evidence search;
- model credentials;
- agent tools;
- a mutable model-generated artifact without digest binding; or
- authority to change collection scope.

### Shareability Checks

Before publication, validate:

- tenant and site policy;
- object shareability classification;
- customer-data restrictions;
- evidence provenance;
- sensitive-content inspection;
- secret and credential absence;
- destination allowlist;
- object/schema validity;
- unsupported-claim handling;
- content digest;
- version/withdrawal state;
- required human approval; and
- rate and batch limits.

Generated AI summaries are never automatically shareable merely because an internal analyst viewed them.

## 15. Outbound Lifecycle

```text
verified_internal_evidence
  -> share_candidate
  -> sanitized
  -> policy_approved
  -> human_approved_if_required
  -> publication_queued
  -> published
  -> delivery_confirmed | partially_accepted | rejected | failed
```

Inbound and outbound state names must not be conflated. `verified` inbound evidence is not equivalent to `approved_for_external_sharing`.

## 16. Derived Search and Storage

Exchange protocol state must not force OpenAssetWatch to adopt a new canonical datastore.

Canonical OpenAssetWatch records remain in the product-owned persistence model. Optional derived indexes or graph projections may accelerate:

- object lookup;
- relationship navigation;
- manifest comparison;
- full-text investigation; or
- current-intelligence correlation.

Derived stores are rebuildable and non-authoritative.

## 17. Failure and Health States

Suggested endpoint health states:

- healthy
- quiet_expected
- quiet_unexpected
- stale
- rate_limited
- authentication_failed
- authorization_failed
- schema_degraded
- capability_drift
- circuit_open
- paused
- disabled
- expired
- unknown

The dashboard should distinguish:

- no new intelligence;
- no data received;
- source late;
- authentication failure;
- processing incomplete; and
- source intentionally disabled.

## 18. Evaluation Requirements

Before enabling an exchange adapter, tests should cover:

- discovery bounds and capability drift;
- tenant isolation;
- collection and operation authorization;
- wrong-collection access;
- pagination and page-size bounds;
- duplicate and replay behavior;
- version rollback/conflict;
- withdrawal semantics;
- malformed object handling;
- partial batch receipts;
- source authentication without content-trust upgrade;
- prompt-injection text inside external objects;
- oversized and nested content;
- encoded expansion limits;
- provider outage and last-known-good behavior;
- outbound sensitive-data blocking;
- publisher identity isolation;
- destination substitution attempts;
- stale approvals;
- external rejection/partial acceptance; and
- deterministic finding authority preservation.

Any cross-tenant disclosure, unauthorized collection access, unsafe publication, credential leakage, or imported content becoming policy is a hard release blocker.

## 19. Implementation Sequence

### Phase 1 - Contracts

- endpoint schema;
- collection schema;
- object envelope;
- manifest and receipt contracts;
- authorization model;
- context-admission policy;
- tests using synthetic data only.

### Phase 2 - Read-only inbound adapter

- one reviewed exchange profile;
- discovery where needed;
- collection listing;
- manifest retrieval;
- bounded object retrieval;
- canonical normalization;
- checkpointing;
- no outbound publication.

### Phase 3 - Correlation and operations

- candidate relationship projection;
- Intelligence Watch integration;
- exchange health dashboard;
- AI context admission controls;
- adversarial-content evaluation.

### Phase 4 - Governed outbound sharing

- explicit share profiles;
- Safe Output Gate integration;
- sensitive-content inspection;
- approval workflow;
- narrow publisher identity;
- delivery receipts and reconciliation.

### Phase 5 - Additional compatibility profiles

Only after capability, licensing, data handling, evaluation, and operational requirements are independently reviewed.

## 20. Explicit Non-Goals

This design does not approve:

- automatic finding creation from external indicators;
- automatic vulnerability confirmation from external claims;
- feed content becoming AI policy;
- raw external text becoming Skill Pack instructions;
- unauthenticated public exchange endpoints;
- plaintext persisted credentials;
- collection access based only on a boolean `can_read` or `can_write` capability;
- arbitrary caller-supplied exchange URLs;
- AI-direct publication;
- unrestricted redistribution of third-party intelligence;
- deletion of local evidence because an external object was withdrawn;
- active scanning or exploitation; or
- mandatory external CTI dependencies.

## Documentation-Only Status

This document defines future OpenAssetWatch architecture. It does not claim that an exchange protocol adapter, collection service, manifest store, preflight classifier, or outbound publisher currently exists.