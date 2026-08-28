# AI Memory Trust-State Model

- **Status:** Documentation-only architecture
- **Purpose:** Define how candidate AI memory is classified, validated, persisted, expired, corrected, quarantined, and prevented from becoming authoritative security state
- **Related:** `docs/ai-security/PROMPT_INJECTION_POLICY_INDEX.md`, `docs/architecture/agent-investigation-control-loop.md`

## Core principle

```text
Memory is convenience state, not product truth.
Model-generated content cannot promote itself into trusted durable memory.
```

OpenAssetWatch must preserve a hard boundary between:

- authoritative normalized evidence;
- deterministic findings/decisions;
- investigation artifacts;
- user preferences;
- AI-derived summaries/hypotheses; and
- durable AI memory.

## Why a full lifecycle is needed

A simple `memory_write_eligible=true/false` field does not capture:

- provenance;
- review state;
- contradictions;
- evidence quality;
- persistence across sessions;
- staleness;
- retractions;
- poison propagation;
- downstream use; or
- recovery after compromise.

A memory item must have a state and immutable history of state transitions.

## Proposed states

```text
candidate
  -> untrusted
  -> reviewed
  -> corroborated
  -> validated
  -> approved-for-memory
  -> active
  -> stale
  -> superseded | retracted | quarantined
```

Not every item must pass through every state, but transitions must be explicit and policy-owned.

## State meanings

### `candidate`

A proposed memory item exists but has not been security-reviewed.

Typical sources:

- model output;
- user conversation;
- specialist summary;
- retrieved document summary;
- tool result summary;
- proposed preference;
- generated investigation note.

Candidate content has no instruction authority and no authorization effect.

### `untrusted`

The source is known to be external, model-generated, user-supplied, or otherwise non-authoritative.

It may be used in bounded read-only context when policy permits and always retains its trust/provenance labels.

### `reviewed`

A deterministic or human review has checked scope, sensitivity, content class, retention need, and obvious integrity problems.

`reviewed` does not mean factually true.

### `corroborated`

Independent evidence references support the proposition sufficiently for the memory's limited intended use.

Corroboration does not grant tool authority or product-truth status.

### `validated`

The item satisfies the defined schema, provenance, evidence-reference, scope, and conflict requirements for its memory type.

Validated memory is still not an authoritative OpenAssetWatch finding or evidence record.

### `approved-for-memory`

The memory policy/human gate has allowed durable persistence for a specific purpose and retention period.

Only product code can set this state.

### `active`

The item may be retrieved for its approved purpose within scope and freshness policy.

### `stale`

The item remains historically retained but should not be treated as current without revalidation.

### `superseded`

A newer approved memory item replaces it for current use. Historical provenance remains.

### `retracted`

The item is known to be invalid/incorrect or its source was retracted. It must not be used as current context.

### `quarantined`

The item or its source is under security/integrity review, including suspected injection or compromised-session state. It must not enter privileged/authorizing paths.

## Non-authoritative boundary

Even `validated` or `active` memory is non-authoritative.

If a remembered proposition must influence deterministic classification, vulnerability applicability, findings, or attention scoring, the underlying observation/evidence must enter the normal OpenAssetWatch evidence pipeline through its own validation contract.

Memory cannot serve as a shortcut around evidence ingestion.

## Proposed memory record

A future `oaw.ai-memory.v1` record may include:

```text
memory_id
memory_type
state
state_version
tenant_id
site_id
subject_scope
purpose
source_type
source_reference
source_trust
content_digest
normalized_content
created_at
observed_at
valid_from
expires_at
last_reviewed_at
retention_policy
sensitivity_class
injection_assessment
sanitization_state
model_generated
human_verified
supporting_evidence_ids
contradiction_evidence_ids
source_agent_principal_id
source_task_id
source_skill_pack_id
policy_version
supersedes_memory_id
retraction_reason_code
quarantine_reason_code
```

Sensitive free-text should be minimized. The exact schema requires review.

## Memory types

The system should define narrow types rather than a universal free-text memory bucket.

Potential types:

- `user_preference`
- `investigation_context`
- `non_authoritative_summary`
- `workflow_hint`
- `reporting_preference`
- `known_uncertainty`
- `temporary_task_context`

Types such as credentials, authorization grants, policy rules, deterministic findings, and tool permissions are explicitly prohibited as AI memory.

## Candidate creation

A model may propose a candidate memory item only through a strict schema.

The proposal cannot set:

- `approved-for-memory`;
- `active`;
- `human_verified`;
- trusted source class;
- tenant/site scope outside task scope;
- authoritative evidence IDs; or
- authorization-related fields.

Unknown or forbidden fields fail validation.

## Provenance

Every candidate must retain:

- originating actor/agent/task;
- source data references;
- provider/model/Skill Pack version when relevant;
- tenant/site scope;
- creation timestamp;
- content digest; and
- transformation lineage if it is a summary/derivation.

A summary never replaces the original source reference.

## Model-generated re-ingestion rule

Mandatory invariant:

```text
model-generated content re-entering memory starts as `candidate`
```

It may never be re-ingested as `validated`, `approved-for-memory`, or `active` merely because it came from a prior OpenAssetWatch agent.

This prevents poison laundering through repeated summarization.

## Memory write gate

The deterministic write gate should evaluate:

- authenticated actor/task;
- principal state;
- tenant/site/subject scope;
- memory type;
- source/provenance completeness;
- sensitive-data policy;
- injection/quarantine state;
- evidence support requirements;
- contradiction state;
- retention/expiration;
- duplicate/supersession behavior;
- human approval requirement; and
- security policy version.

Decisions:

- `allow-persist`
- `require-review`
- `deny`
- `quarantine`

The model does not make the final decision.

## Retrieval gate

Retrieval must apply:

- exact tenant/site/task scope;
- memory type allowlist;
- active state;
- freshness/expiration;
- sensitivity/external-processing rules;
- quarantine/retraction exclusion;
- maximum records/bytes;
- purpose compatibility; and
- provenance projection.

Retrieved memory must be labeled as memory, not authoritative evidence.

## Context assembly

Memory in model context should use an explicit envelope such as:

```text
content_origin = ai_memory
instruction_authority = none
model_generated = true/false
memory_state = active
source_trust = ...
may_influence_authorization = false
```

The actual field names should align to `AI_TRUST_LABELS.md`.

## Memory and user preferences

User preferences require special treatment.

An explicit authenticated user preference may be eligible for deterministic persistence without AI inference. Example: report format preference.

An inferred preference proposed by a model remains a candidate until separately validated according to policy.

A preference cannot override security, tenant, tool, data-classification, or approval policy.

## Conflict handling

Memory must preserve contradictions.

If current authoritative evidence conflicts with active memory:

- authoritative evidence wins for product facts;
- the memory should be marked stale/conflicted/quarantined as appropriate;
- the conflict is surfaced to the user/agent when relevant; and
- the memory must not cause deterministic evidence to be discarded.

## Time and freshness

Memory should include explicit validity/retention semantics.

Examples:

- temporary investigation context expires with or shortly after the investigation;
- user preferences may persist longer;
- environment-specific summaries need revalidation as evidence changes;
- security context should expire aggressively when freshness cannot be established.

Missing freshness is uncertainty, not confirmation that old memory remains valid.

## Corrections and retractions

Corrections should append state/history rather than rewrite provenance.

A retraction should include:

- reason code;
- actor/process that retracted;
- timestamp;
- affected descendants/derived memories; and
- downstream invalidation requirement.

## Dependency tracking

Where a memory item derives from other memory or evidence, store dependency references sufficient to find affected descendants.

When an upstream source becomes retracted/quarantined, dependent memories should be marked for revalidation or quarantine.

## Quarantine

Quarantine conditions include:

- suspected/confirmed injection;
- source principal compromised;
- source tool/server identity invalidated;
- provenance missing/tampered;
- cross-scope origin;
- material contradiction;
- policy violation;
- sensitive content in disallowed memory type; or
- incident-response containment.

Quarantined memory is excluded from privileged context and all authorization decisions.

## Compromised session behavior

When an agent/session is suspected compromised:

- new durable writes stop;
- pending memory candidates are quarantined;
- recently written items from the affected security window are reviewed;
- descendants are identified;
- active contexts using affected memory may require invalidation; and
- restoration occurs only after security revalidation.

See `AI_AGENT_COMPROMISE_RECOVERY_MODEL.md`.

## Memory deletion

Privacy-driven deletion and security-state retraction are separate concepts.

The system should retain only the minimum audit metadata permitted by retention/privacy policy while still ensuring a deleted memory cannot remain active in caches/vector indexes/derived summaries.

## Vector/embedding stores

An embedding index is a retrieval mechanism, not a trust store.

Required rules:

- canonical memory state lives outside the vector index;
- tenant/scope filtering occurs before/with retrieval;
- deleted/quarantined/retracted IDs are excluded;
- vector similarity cannot raise trust;
- embedding metadata includes stable memory ID and version;
- re-embedding does not create a new trusted proposition; and
- stale index entries are detectable/removable.

## Memory canaries

Canary memory entries may be evaluated as a security control only if:

- they contain no real sensitive data;
- they are deterministically marked and excluded from ordinary reasoning/results;
- access can be attributed to a principal/task;
- trips produce bounded telemetry; and
- false-positive behavior is understood.

Canaries are optional detective controls, never the primary security boundary.

## Audit events

Suggested events:

- `ai.memory.candidate_created`
- `ai.memory.reviewed`
- `ai.memory.corroborated`
- `ai.memory.validated`
- `ai.memory.approved`
- `ai.memory.activated`
- `ai.memory.stale`
- `ai.memory.superseded`
- `ai.memory.retracted`
- `ai.memory.quarantined`
- `ai.memory.write_denied`
- `ai.memory.retrieval_denied`
- `ai.memory.descendant_invalidated`
- `ai.memory.canary_trip`

## Reason codes

Candidate reason codes:

- `MEMORY_SOURCE_UNTRUSTED`
- `MEMORY_PROVENANCE_MISSING`
- `MEMORY_SCOPE_MISMATCH`
- `MEMORY_WRITE_NOT_ELIGIBLE`
- `MEMORY_REVIEW_REQUIRED`
- `MEMORY_CONTRADICTION_PRESENT`
- `MEMORY_EXPIRED`
- `MEMORY_STALE`
- `MEMORY_RETRACTED`
- `MEMORY_QUARANTINED`
- `MEMORY_SOURCE_COMPROMISED`
- `MEMORY_MODEL_SELF_PROMOTION_BLOCKED`
- `MEMORY_SENSITIVE_TYPE_DENY`

## Evaluation

Required tests:

- malicious document -> summary -> memory proposal;
- model marks its own output trusted;
- memory candidate references invented evidence;
- cross-tenant memory proposal;
- stale memory conflicts with fresh evidence;
- retracted upstream source;
- poisoned memory persists across session/restart;
- compromised agent writes before containment;
- memory vector index contains quarantined/stale ID;
- model-generated memory re-summarized and re-ingested;
- user preference attempts to override security policy;
- deletion followed by stale cache retrieval; and
- canary access.

Metrics:

- unauthorized durable memory write rate;
- memory poisoning success rate;
- cross-session poison persistence;
- quarantine enforcement rate;
- descendant invalidation completeness;
- stale/retracted retrieval rate;
- false-positive quarantine burden; and
- recovery success after compromise.

## Hard release blockers

For durable AI memory:

- model self-promotes memory into approved/active state;
- unapproved memory persists;
- cross-tenant memory becomes retrievable;
- quarantined/retracted memory enters privileged context;
- compromised memory survives security quarantine into privileged use;
- memory directly creates authoritative product facts; or
- deletion/retraction leaves active stale copies in the production retrieval path.

## Implementation order

1. Define narrow memory types and schema.
2. Implement immutable state-transition ledger.
3. Implement deterministic write gate.
4. Implement tenant/state-aware retrieval gate.
5. Add quarantine/retraction/dependency invalidation.
6. Add provider-facing trust envelope.
7. Add controlled UI review.
8. Add optional vector indexing only after canonical state enforcement.
9. Add canary research later.

Durable AI memory should remain disabled until the state machine and write/retrieval gates pass the required tests.