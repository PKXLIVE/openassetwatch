# Asset Intelligence Stack Gap Additions

## Purpose

This document records verified gaps in the current OpenAssetWatch design that
should be added to the product architecture and implemented through existing
OpenAssetWatch subsystems.

The additions are intentionally additive. They do not replace the current
collector, passive sensor, canonical evidence, deterministic classification,
finding, risk, connector, task-orchestration, AI Advisor, investigation, or
reporting architecture.

The design remains:

- asset-first;
- passive-first;
- evidence-first;
- deterministic where authority is required;
- read-only by default;
- local/self-hosted first;
- provider- and model-neutral;
- auditable;
- tenant- and site-scoped;
- human-controlled for high-impact action; and
- explicit about unknown, stale, partial, inferred, and conflicting state.

## Architecture Status

- Architecture state: `documented_direction`
- Gap disposition: accepted for phased implementation through existing subsystems
- Runtime change in this document: none
- Implementation rule: do not create a competing asset database, scanner stack,
  task engine, graph source of truth, or automation authority

The capabilities below are implementation targets. Runtime work should be split
into independently reviewable changes with migrations, tests, rollback, audit,
and observability before any capability is considered implemented.

---

## 1. Gap Disposition Summary

| Priority | Capability | Disposition | Primary owner in the existing stack |
| --- | --- | --- | --- |
| P0 | Asset Presence and Connectivity Session Ledger | add | canonical asset/evidence layer |
| P0 | Canonical Asset Field Authority and Asset Change Ledger | add | canonical asset/evidence layer |
| P0 | Relationship Evidence Ledger and Edge History | formalize and add | canonical evidence + relationship projection |
| P1 | Dependency-Aware Alert Compression | add | finding/alert/case operations |
| P1 | Quota-Aware Connector Credential Pool | add | connector credential boundary |
| P1 | Normalization Transformation Provenance Ledger | add | normalization/evidence provenance |
| P1 | Host-Pressure Adaptive Workload Governor | add | Platform Task Orchestrator |
| P1/P2 | Governed Passive Fingerprint Rule Packs and Collision CI | add after governance gates | deterministic classification |
| P2 | Worker Compatibility and Task Partition Contract | extend | Platform Task Orchestrator |
| P2 | Safe Fielded Asset and Relationship Query Grammar | add | Control Plane query/search boundary |

These are the accepted gaps from this research pass. Features that duplicate
existing architecture or conflict with the OpenAssetWatch safety boundary are
listed in the rejection section and should not be implemented.

---

## 2. Asset Presence and Connectivity Session Ledger

### Gap

OpenAssetWatch records observations, freshness, first-seen/last-seen context,
and collector/sensor health, but it does not yet define a canonical session
model that explains when an asset was observably present, when it became absent,
and when visibility was insufficient to make either claim.

A single `last_seen` value is not enough for laptops, mobile devices, guest
devices, intermittent IoT, maintenance equipment, moving assets, or assets that
regularly disappear and return.

### Required capability

Add an immutable/history-preserving presence-session model with a current-state
projection.

Suggested logical contract:

```text
presence_session_id
schema_version
tenant_id
site_id
asset_id

presence_state
  present
  absent
  unknown

started_at
ended_at
duration_seconds

start_evidence_id
end_evidence_id
source_type
source_id
observation_method
network_context_ref
address_context_ref

confidence
freshness_state
closure_reason
created_at
updated_at
```

### Presence rules

`present` requires current qualifying evidence from an approved source.

`absent` must not be inferred merely because no new event arrived. An absence
transition requires evidence that the source or observation path was healthy,
was expected to observe the asset, and exceeded a class/source-specific absence
window.

If the collector, passive sensor, connector, network path, or expected telemetry
is unhealthy or unknown, the asset presence state becomes `unknown`, not
`absent`.

This distinction is mandatory:

```text
no asset observation + healthy expected visibility = candidate absence
no asset observation + unhealthy/unknown visibility = unknown
```

Presence windows should be configurable by approved source and asset class. A
mobile device may legitimately disappear for hours while a continuously
connected switch may warrant a much shorter evaluation window.

### Session lifecycle

```text
unknown
  -> present
  -> absent
  -> present

present
  -> unknown      when the observation path becomes unreliable

unknown
  -> present      when fresh evidence resumes

unknown
  -> absent       only after trustworthy expected visibility supports absence
```

A new session should be created when an asset returns after a completed absence
period. Historical sessions remain immutable except for bounded completion
metadata written as the transition occurs.

### Required product uses

The ledger should support:

- currently present versus historically known assets;
- intermittent-device behavior;
- rogue or guest-device appearance windows;
- assets moving between network contexts;
- recurring disappearance/reappearance patterns;
- maintenance-device activity;
- asset presence timelines in investigations;
- presence-aware finding logic; and
- suppression of false absence conclusions during telemetry outages.

### Release blockers

Do not ship an `absent` state if source health cannot be evaluated. Do not use
AI output to create or close a canonical presence session.

---

## 3. Canonical Asset Field Authority and Asset Change Ledger

### Gap

OpenAssetWatch already evaluates source quality, freshness, directness, and
conflicts in deterministic classification. The same authority model is not yet
formalized across every mutable canonical asset field.

As the product adds endpoint collectors, passive sensors, network services,
cloud connectors, CMDB projections, operator corrections, and external
intelligence, each canonical field needs an explicit answer to:

> Which source is permitted to create, refresh, conflict with, or replace this
> value?

### Field authority policy

Define a versioned server-owned policy for each canonical field or field class.

Suggested modes include:

- `authoritative_when_verified`
- `stronger_and_newer_may_replace`
- `fill_if_unknown`
- `corroboration_only`
- `candidate_only`
- `operator_locked`
- `never_external_overwrite`

A source's own payload must never declare itself authoritative. Source trust,
authentication, collection method, tenant/site scope, and policy are established
by OpenAssetWatch.

Example conceptual policy:

```text
display_name
  operator-confirmed    -> operator_locked
  authenticated endpoint -> stronger_and_newer_may_replace unless locked
  reviewed connector     -> fill_if_unknown or conflict candidate
  passive sensor         -> corroboration_only
  external intelligence  -> candidate_only
```

Different fields may use different policies. Current IP address, hostname,
manufacturer, owner, business service, asset class, software version, and
external CMDB identifier do not have identical authority requirements.

### Asset Change Ledger

Every accepted material change to canonical asset state should create an
append-only change record.

Suggested contract:

```text
asset_change_id
schema_version
tenant_id
site_id
asset_id
field_id

old_value_digest
new_value_digest
old_value_ref
new_value_ref

old_source_ref
new_source_ref
triggering_evidence_ids[]

authority_policy_version
authority_decision
change_reason_code
conflict_id

changed_by_type
changed_by_id
changed_at
```

Sensitive values should be referenced or redacted according to classification
policy rather than copied into audit records unnecessarily.

### Change behavior

A weaker source may add corroboration without replacing the canonical value. A
credible conflicting source creates a conflict record instead of silently
winning or being discarded. Operator-confirmed values require an explicit
unlock or reviewed replacement path. Repeated identical evidence refreshes
freshness but should not generate meaningless semantic-change records.

The ledger is the historical explanation of *why canonical asset state changed*.
It is not a second current-state table.

### Required product uses

- asset history;
- source conflict explanation;
- rollback/review support;
- CMDB reconciliation;
- investigation timelines;
- audit reports;
- deterministic change-triggered findings; and
- AI explanation over server-issued change IDs without mutation authority.

---

## 4. Relationship Evidence Ledger and Edge History

### Gap

OpenAssetWatch already designs relationship and exposure graphs as evidence-backed
projections. The missing contract is a canonical relationship ledger that
preserves the provenance and lifecycle of every meaningful edge before it is
projected into a graph or search view.

### Required relationship contract

```text
relationship_id
schema_version
tenant_id
site_id

subject_type
subject_id
predicate
object_type
object_id

relationship_class
  identity
  network
  ownership
  software
  certificate
  dependency
  communication
  exposure
  external-corroboration

derivation_type
  directly_observed
  deterministic_derived
  inferred_candidate
  analyst_confirmed

source_refs[]
evidence_refs[]
first_seen_at
last_seen_at

confidence
freshness_state
verification_state

lifecycle_state
  active
  stale
  contradicted
  expired
  superseded

supersedes_relationship_id
policy_version
created_at
updated_at
```

### Required rules

Relationships must preserve source, evidence, time, scope, confidence,
freshness, verification, and derivation type. Traversal does not convert
correlation into proof. Weak transitive paths must never merge assets or confirm
a finding by themselves.

A relationship projection may be represented in PostgreSQL, a derived search
index, or an optional graph engine, but canonical evidence remains in the
OpenAssetWatch-owned relational model. A graph store is never the sole system
of record.

Historical edge changes must remain queryable so an investigation can answer:

- when did the edge first appear;
- when was it last observed;
- which evidence supported it;
- did independent sources corroborate it;
- did credible evidence contradict it;
- did the edge disappear and later return; and
- which version of an exposure path relied on it.

### Relationship change events

Recommended domain events:

```text
relationship.created
relationship.corroborated
relationship.conflicted
relationship.stale
relationship.expired
relationship.superseded
relationship.reactivated
```

Events are notifications about committed canonical state; they are not the
source of truth by themselves.

---

## 5. Dependency-Aware Alert Compression

### Gap

As OpenAssetWatch gains topology and dependency relationships, one upstream
failure may explain many child symptoms. Generating a separate operator
notification for every downstream symptom produces avoidable noise.

### Required behavior

Add a deterministic notification-compression layer that can suppress duplicate
*notifications* when a trusted dependency relationship explains the child
condition.

It must not delete, hide, merge away, or close the underlying evidence,
finding, health event, or child condition.

Conceptual state:

```text
child_condition = retained
child_finding = retained
child_evidence = retained
notification_state = suppressed_by_dependency
suppression_parent_relationship_id = rel_...
suppression_parent_event_id = evt_...
```

### Eligibility

Suppression requires:

- a current verified or sufficiently trusted dependency edge;
- compatible event timing;
- an upstream condition capable of explaining the downstream symptom;
- healthy enough telemetry to establish the causal relationship;
- a deterministic suppression rule; and
- no conflicting evidence showing an independent child failure.

If topology or causality is uncertain, fail open and show the child
notification.

### Operator experience

The parent alert should state that related child conditions were compressed and
allow expansion to the full evidence set. Operators must be able to inspect the
child count, affected assets, relationship path, evidence, and reason code.

This is alert-noise reduction, not automatic incident closure.

---

## 6. Quota-Aware Connector Credential Pool

### Gap

The connector architecture already separates credential storage, runtime access,
rotation, and audit. A connector instance currently assumes a credential
reference but does not yet define a governed pool for multiple equivalent
credentials with independent quotas, rate limits, health, and cooldown.

### Required capability

Allow an approved connector instance to reference a tenant-scoped credential
pool.

```text
connector instance
       |
       v
credential pool
  |- credential member A
  |- credential member B
  `- credential member N
```

Suggested member state:

```text
credential_member_id
connector_instance_id
tenant_id
credential_ref

enabled
health_state
quota_window_type
quota_limit
quota_used
quota_remaining
quota_reset_at

last_used_at
last_success_at
last_failure_at
last_failure_class
rate_limit_state
cooldown_until
circuit_state
created_at
updated_at
```

### Selection rules

The connector runtime may select only credentials that are:

- owned by the same tenant and connector scope;
- enabled;
- authorized for the requested capability;
- not expired or revoked;
- not in authentication quarantine;
- not inside a rate-limit cooldown; and
- within the configured quota budget.

Selection should be deterministic or policy-driven and auditable. It must not
use one customer's credentials for another customer, silently exceed operator
budgets, expose plaintext credentials to AI, or cycle indefinitely through
failed credentials.

### Failure handling

- authentication failure -> quarantine that member pending review or rotation;
- rate limit -> cooldown until a bounded retry time;
- quota exhausted -> member unavailable until reset;
- provider outage -> connector-level circuit behavior remains separate;
- all members unavailable -> connector becomes visibly degraded or
  rate-limited rather than pretending no records exist.

Credential-use audit records must contain references and outcomes, never secret
values.

---

## 7. Normalization Transformation Provenance Ledger

### Gap

OpenAssetWatch defines versioned normalization profiles and source preservation,
but derived canonical state should also retain a reproducible receipt showing
which reviewed transformation produced which output from which inputs.

### Transformation receipt

```text
transformation_receipt_id
schema_version
tenant_id

transformation_id
transformation_version
transformation_digest
policy_version

input_schema_ids[]
input_record_refs[]
input_digest

output_schema_ids[]
output_record_refs[]
output_digest

started_at
completed_at
status
failure_class
worker_id
trace_id
```

### Authority boundary

Authoritative transformations must be reviewed deterministic product logic or
approved declarative mappings interpreted by fixed OpenAssetWatch code.

The runtime must not permit:

- arbitrary code supplied in a mapping;
- shell execution;
- user-selected executable modules;
- model-generated transforms to become authoritative;
- transforms that widen tenant or site scope; or
- transforms that recursively create new collection authority.

AI may explain a transformation receipt or propose a candidate mapping for human
review, but it cannot silently change normalization behavior.

### Required uses

- replay and reproducibility;
- schema migration review;
- normalization regression analysis;
- evidence lineage;
- conflict explanation;
- source-specific drift investigation; and
- proving which transform version produced a finding input.

---

## 8. Host-Pressure Adaptive Workload Governor

### Gap

The Platform Task Orchestrator already defines task budgets, priorities, worker
health, concurrency, retry, leases, and fairness. It needs a feedback controller
that reduces background work when the self-hosted system is under sustained
resource pressure.

### Inputs

The governor may consume bounded local telemetry such as:

- CPU pressure/load;
- available memory and memory pressure;
- disk/IO pressure;
- queue depth and queue age;
- database health;
- local AI accelerator memory/utilization when applicable;
- process/worker health; and
- thermal state where the operating system exposes trustworthy telemetry.

No single metric should control the system without hysteresis and minimum
observation windows.

### States

```text
normal
constrained
severely_constrained
paused_for_host_health
recovering
```

Transitions should use separate enter/exit thresholds to prevent rapid
oscillation.

### Priority behavior

Throttle lower-value work first:

1. bulk/background enrichment;
2. maintenance that can safely wait;
3. large report rendering;
4. temporal rebuilds/backfills;
5. non-urgent connector imports.

Preserve reserved capacity for:

- ingestion of already-collected evidence;
- critical platform control operations;
- security-validation work;
- cancellation and cleanup;
- interactive operator requests within bounded limits; and
- audit/state persistence.

The governor reduces concurrency, delays new leases, or pauses eligible queues.
It does not silently cancel accepted work or discard partial results.

### Local-first requirement

Core product operation must remain useful on modest self-hosted systems. An
optional local AI workload must not starve evidence ingestion, database health,
or operator control.

---

## 9. Governed Passive Fingerprint Rule Packs and Collision CI

### Gap

The current deterministic classifier correctly uses a fixed reviewed registry.
As the passive evidence corpus grows, maintaining every mapping directly in
application source may become difficult to review, test, version, and update.

The future design should separate reviewed deterministic fingerprint *data*
from executable application logic without introducing dynamic plugins or
arbitrary expressions.

### Rule-pack contract

A rule pack is a versioned, signed/digested OpenAssetWatch artifact interpreted
only by fixed product code.

A rule may declare:

```text
fingerprint_rule_id
rule_version
rule_set_version
status
input_evidence_kinds[]
match_mode
bounded_pattern_refs[]
candidate_attributes
confidence_contribution
freshness_requirements
source_requirements
conflict_behavior
created_at
reviewed_at
expires_at
```

Allowed results are candidate classification/product attributes already defined
by the canonical model. A rule cannot add tools, network access, executable
code, destinations, permissions, or new collection behavior.

### Passive-only boundary

Initial rule packs may evaluate evidence already collected by approved endpoint
or passive sources. They must not trigger HTTP requests, banner grabs, port
probes, authentication tests, URL fetches, directory discovery, or arbitrary
network requests.

### Collision and regression CI

Every proposed rule-set version must be replayed against approved positive,
negative, conflicting, stale, malformed, and adversarial fixtures.

CI should detect at minimum:

- one observation matching incompatible products/classes;
- over-broad patterns;
- aliases that collide with existing identities;
- new/old rule disagreement;
- catastrophic regular-expression behavior;
- excessive evaluation cost;
- false-positive regression;
- false-negative regression on protected fixtures;
- unexpected match-rate expansion; and
- rule changes that alter finding/risk behavior without an explicit review.

A critical collision or safety regression blocks promotion even when aggregate
accuracy improves.

### Supply-chain rule

Third-party fingerprint databases or rule corpora must not be copied into the
product merely because their ideas were useful during research. Any actual
third-party data/code import requires separate source, license, provenance,
redistribution, integrity, and maintenance review.

---

## 10. Worker Compatibility and Task Partition Contract

### Gap

The Platform Task Orchestrator already models worker version, capability digest,
health, leases, and checkpoints. Distributed deployments additionally need an
explicit compatibility gate between control-plane, task, evidence, checkpoint,
and worker schema versions.

### Worker compatibility profile

```text
worker_id
worker_version
worker_class
capability_manifest_digest
supported_task_types[]
supported_task_schema_versions[]
supported_evidence_schema_versions[]
supported_checkpoint_versions[]
minimum_control_plane_version
maximum_control_plane_version
isolation_profile
last_qualified_at
qualification_state
```

Suggested qualification states:

```text
compatible
upgrade_available
outdated_supported
incompatible
quarantined
```

An incompatible worker must not receive a task and then discover incompatibility
mid-execution.

### Task partition plan

Large bounded platform jobs should be splittable into independently retryable
partitions when the task type supports it.

```text
parent task
  -> partition plan
       |- partition 1
       |- partition 2
       |- partition N
  -> deterministic join
```

Each partition requires:

- partition identifier;
- immutable input scope;
- idempotency key;
- compatibility requirements;
- attempt history;
- checkpoint/reference;
- coverage state;
- result digest; and
- terminal status.

The parent becomes complete only when its explicit join policy is satisfied.
Partial completion must report uncovered partitions rather than presenting a
full result.

### Safety boundary

Do not implement automatic remote shell/SSH worker management as the product
upgrade mechanism. Worker upgrades remain explicit, packaged, signed,
operator-controlled, observable, and rollback-aware.

---

## 11. Safe Fielded Asset and Relationship Query Grammar

### Gap

As the asset, relationship, finding, and evidence model grows, operators need a
compact way to express structured read-only queries without receiving arbitrary
SQL, unrestricted scripting, or model-generated database code.

### Query model

Provide a server-owned grammar over an allowlisted semantic field registry.

Conceptual query:

```text
site = "office"
AND asset.category = "camera"
AND finding.severity >= "high"
AND relationship.predicate = "depends_on"
AND freshness != "stale"
```

The exact syntax is an implementation choice. The contract is more important
than the surface language.

### Required compiler boundary

```text
operator or AI candidate query
        |
        v
parse against versioned grammar
        |
        v
resolve allowlisted semantic fields
        |
        v
validate tenant/site authorization
        |
        v
apply row/result/time/depth budgets
        |
        v
compile to parameterized product query
        |
        v
execute read-only
        |
        v
return canonical IDs + coverage metadata
```

### Allowed behavior

Initial operators should be small and typed, such as equality/inequality,
ordered comparison for compatible fields, bounded membership, prefix, bounded
contains, boolean joins, approved time windows, and explicitly bounded
relationship traversal.

Arbitrary SQL, shell syntax, code execution, unrestricted regular expressions,
unbounded graph walks, arbitrary joins, and user-selected database tables are
out of scope.

AI may propose a semantic query, but the model never receives database
credentials and cannot bypass the compiler or authorization layer.

### Audit

Record the semantic query, authenticated actor, tenant/site scope, grammar
version, compiled-query digest, execution limits, result count, duration,
truncation/coverage state, and trace ID. Sensitive query values should be
redacted where policy requires.

---

## 12. Integration Into the Existing OpenAssetWatch Stack

These capabilities extend existing architecture. They should not create one new
service per logical component unless isolation, scale, or ownership later
requires it.

### Canonical asset and evidence layer

Extend the current asset/evidence/classification work with:

- Asset Presence and Connectivity Session Ledger;
- Canonical Asset Field Authority;
- Asset Change Ledger;
- Relationship Evidence Ledger;
- relationship edge history; and
- governed passive fingerprint rule evaluation.

Primary existing design references:

- `docs/ASSET_CLASSIFICATION_AND_EVIDENCE_FUSION.md`
- `docs/DETERMINISTIC_FINDINGS_AND_RISK.md`
- `docs/architecture/openassetwatch-platform-overview.md`
- `docs/architecture/external-intelligence-enrichment-roadmap.md`

### Connector layer

Extend `docs/architecture/connector-playbook-projection-architecture.md` with:

- credential pools;
- per-member quota and cooldown state;
- quota-aware selection;
- credential-member audit; and
- visible degraded behavior when all members are unavailable.

### Platform work layer

Extend `docs/architecture/platform-task-orchestration.md` with:

- Host-Pressure Adaptive Workload Governor;
- worker compatibility qualification;
- task partition plans;
- deterministic partition joins; and
- compatibility-aware worker admission.

### Finding, alert, and case layer

Extend the current detection/investigation architecture with:

- dependency-aware notification compression;
- suppression reason/evidence records;
- expansion to all retained child conditions; and
- no automatic closure based solely on dependency correlation.

Primary existing design references:

- `docs/architecture/detection-feedback-response-governance.md`
- `docs/architecture/security-investigation-case-operations.md`

### Query/search layer

Extend the Control Plane read/query boundary with the safe fielded semantic
query grammar. Optional search/graph systems remain derived accelerators, not
canonical state.

### Provenance layer

Transformation receipts should connect source ingestion, normalization,
canonical evidence, relationships, findings, and replay so an operator can
trace any authoritative derived value back to the exact input and transform
version.

---

## 13. Suggested Persistence Additions

Final names are subject to schema design review. The intended logical records
are:

```text
asset_presence_sessions
asset_field_authority_policies
asset_change_ledger
asset_relationships
asset_relationship_evidence
asset_relationship_history or append-only relationship revisions
notification_dependency_suppressions
connector_credential_pool_members
transformation_receipts
worker_compatibility_profiles
task_partition_plans
task_partitions
passive_fingerprint_rule_sets
passive_fingerprint_rule_evaluations
semantic_query_audit
```

Schema implementation must follow the repository's migration governance,
including additive-first migration, upgrade tests, rollback/recovery strategy,
tenant isolation, indexing review, and bounded retention.

---

## 14. Implementation Sequence

### Phase 1 — canonical asset state foundation (P0)

Implement together because they share identity, evidence, and timeline
semantics:

1. Asset Presence and Connectivity Session Ledger;
2. Canonical Asset Field Authority;
3. Asset Change Ledger; and
4. Relationship Evidence Ledger with edge history.

Required before release:

- migrations and fresh-install convergence;
- source-health-aware absence tests;
- source-authority conflict tests;
- idempotent replay tests;
- tenant/site isolation tests;
- relationship lifecycle tests;
- deterministic history reconstruction; and
- AI read-only evidence projection.

### Phase 2 — connector and operational-noise controls (P1)

1. Quota-Aware Connector Credential Pool;
2. Normalization Transformation Provenance Ledger; and
3. Dependency-Aware Alert Compression.

Required before release:

- credential secrecy and tenant isolation tests;
- quota/rate-limit reset tests;
- connector degraded-state tests;
- transformation replay tests;
- topology-conflict tests; and
- proof that suppression hides notifications only, not child evidence/state.

### Phase 3 — runtime resilience (P1/P2)

1. Host-Pressure Adaptive Workload Governor;
2. Worker Compatibility Gate; and
3. Task Partition Contract.

Required before release:

- pressure hysteresis tests;
- priority-reserve tests;
- cancellation/partial-result preservation;
- incompatible worker rejection;
- version-upgrade matrix;
- partition retry/idempotency tests; and
- deterministic join/coverage tests.

### Phase 4 — scalable passive classification (P1/P2)

Implement governed passive fingerprint rule packs only after the validation and
promotion pipeline exists.

Required before activation:

- immutable/digested rule artifacts;
- schema validation;
- collision CI;
- positive/negative/conflict/stale fixtures;
- performance budgets;
- supply-chain provenance review;
- rollback to the previous rule-set version; and
- deterministic classification authority unchanged.

### Phase 5 — operator query ergonomics (P2)

Implement the safe fielded semantic query compiler after canonical relationship
and field registries stabilize.

Required before release:

- allowlisted field registry;
- parameterized compilation;
- authorization and tenant-scope enforcement;
- query budgets and traversal limits;
- audit records;
- adversarial parser tests; and
- no model/database credential path.

---

## 15. Explicitly Discarded or Unwanted Features

The following capabilities are not needed for this architecture increment and
should not be added from the reviewed design space.

### Active/offensive collection behavior

Do not add:

- unrestricted network enumeration;
- broad port scanning;
- subdomain brute forcing or mutation;
- directory brute forcing;
- active HTTP path probing;
- banner grabbing initiated solely for fingerprinting;
- authentication/no-auth testing against discovered services;
- vulnerability probes or vulnerability verification;
- proof-of-concept execution;
- exploitation;
- credential testing, harvesting, or cracking;
- deep live-host crawling as an automatic discovery stage;
- arbitrary request generation;
- remote shells or command-and-control behavior; or
- recursive self-expansion of collection scope.

A separately reviewed safe-active capability may be considered in the future
for specific authorized use cases, but nothing in this document authorizes it.

### Duplicate architecture

Do not create:

- a second task engine beside Platform Task Orchestration;
- a second canonical asset database;
- a graph database as the authoritative system of record;
- a mandatory search cluster;
- a separate scanner-node control plane;
- a competing plugin framework for executable scanners; or
- another AI authority path around deterministic findings and policy.

### Unsafe automation

Do not add:

- automatic SSH-based worker upgrades;
- executable normalization mappings;
- model-authored authoritative transforms;
- dynamic rule code loaded from untrusted content;
- arbitrary SQL or unrestricted query scripting;
- automatic case closure from topology suppression; or
- automatic remediation based only on confidence/model output.

### Unnecessary scope expansion

Do not broaden OpenAssetWatch into a general people/account/financial
intelligence platform merely because external asset models can represent those
entities. New entity classes should be added only when they support the
product's asset-intelligence, defensive-security, ownership, exposure, or
operational use cases.

### Third-party material

Do not copy external fingerprint corpora, rule databases, source code,
diagrams, dashboards, documentation text, performance claims, or branded data
models into the product without the normal source-license and provenance review.
Independent OpenAssetWatch architecture ideas should remain native contracts.

---

## 16. Cross-Cutting Acceptance Criteria

Every capability in this document must satisfy all of the following before it
is marked implemented:

1. Canonical state remains OpenAssetWatch-owned.
2. Tenant and site scope are established before processing.
3. Evidence/provenance survives normalization and projection.
4. Missing telemetry is not converted to a safe/absent/zero state.
5. AI remains optional, read-only/advisory, and unable to override canonical
   asset, relationship, finding, authorization, or policy state.
6. Repeated delivery and replay are idempotent.
7. Historical state can be reconstructed without private model reasoning.
8. Resource and output sizes are bounded.
9. Failure and partial coverage are visible.
10. Every mutable policy or rule artifact is versioned and auditable.
11. Upgrade, rollback/recovery, and migration behavior are documented and
    tested.
12. Local/self-hosted operation does not require a hosted provider.
13. No accepted capability silently creates active-scanning authority.
14. Derived search or graph projections can be rebuilt from canonical records.
15. A reviewer can explain why every accepted state transition occurred using
    server-issued evidence, policy, and transformation identifiers.

---

## 17. Target Stack After These Additions

```text
OpenAssetWatch Control Tower
|
+-- Canonical Evidence and Asset State
|   +-- Presence Session Ledger
|   +-- Field Authority Policy
|   +-- Asset Change Ledger
|   +-- Relationship Evidence Ledger
|   +-- Relationship/edge history
|   `-- Governed passive fingerprint evaluation
|
+-- Deterministic Findings / Alerts / Cases
|   `-- Dependency-aware notification compression
|
+-- Connector Boundary
|   +-- Credential Broker
|   `-- Quota-Aware Credential Pools
|
+-- Normalization and Provenance
|   `-- Transformation Provenance Ledger
|
+-- Platform Task Orchestrator
|   +-- Host-Pressure Adaptive Workload Governor
|   +-- Worker Compatibility Gate
|   `-- Task Partition Plans and deterministic joins
|
+-- Control Plane Query Boundary
|   `-- Safe Fielded Asset/Relationship Query Compiler
|
+-- Optional Derived Search / Relationship Graph
|   `-- rebuildable projection only
|
`-- AI Advisor / Specialist Analysis
    `-- read-only explanation over server-issued canonical IDs
```

This target strengthens the existing OpenAssetWatch stack without converting it
into an active scanner, offensive framework, generic automation engine, or
third-party architecture clone.
