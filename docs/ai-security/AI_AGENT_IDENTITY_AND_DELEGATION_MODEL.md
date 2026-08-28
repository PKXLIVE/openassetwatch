# AI Agent Identity and Delegation Model

- **Status:** Documentation-only architecture
- **Purpose:** Define security principals, role binding, task-scoped authorization, and future capability-attenuated delegation for OpenAssetWatch agents
- **Related:** `docs/architecture/agent-investigation-control-loop.md`, `docs/architecture/skill-pack-contract.md`, `docs/ai-security/AI_TOOL_AUTHORIZATION_MODEL.md`

## Core principle

```text
Every agent action must be attributable to an authenticated, scoped, revocable principal.
Delegation may narrow authority. It may never create authority.
```

A model name, role prompt, Skill Pack, conversation ID, or provider session is not sufficient security identity.

## Why identity is required

Future investigations may involve multiple specialist tasks, local or hosted models, read-only tools, report composition, and eventually approved side-effect workflows. Without an explicit principal, OpenAssetWatch cannot reliably answer:

- who initiated the task;
- which agent instance acted;
- which role and Skill Pack were active;
- which tenant/site/assets were in scope;
- which capabilities were delegated;
- which credential was used;
- which tool request belongs to which task;
- whether a child widened authority;
- whether a revoked agent continued executing; or
- which outputs/memory writes must be invalidated after compromise.

## Principal layers

OpenAssetWatch should distinguish:

### Human or calling actor

The authenticated user/service that requested the work.

### Agent instance

The ephemeral security principal for one bounded agent execution context.

### Agent role

A reviewed product role such as identity investigator, vulnerability investigator, verifier, remediation planner, or report writer.

### Workload identity

The runtime/service identity used by product infrastructure. It should be short-lived and not exposed as a reusable secret to model context.

### Task identity

The exact coordinator-issued task packet and objective.

### Delegation identity

A future bounded parent-to-child grant that proves what was delegated, by whom, and under which constraints.

These identities are related but not interchangeable.

## Proposed agent principal contract

A future `oaw.agent-principal.v1` record should contain bounded fields such as:

```text
schema_version
agent_instance_id
role_id
role_version
runtime_identity
investigation_id
task_id
parent_agent_instance_id
initiating_actor_id
tenant_id
site_id
approved_scope_id
asset_ids or scope_reference
skill_pack_id
skill_pack_version
capability_set
tool_allowlist
credential_reference
created_at
expires_at
revoked_at
security_state
policy_version
coordinator_version
provider_route_id
model_identity_reference
artifact_identity_reference
```

The exact schema requires implementation review. Unknown fields should fail validation.

## Security state

Suggested principal states:

- `issued`
- `active`
- `suspended`
- `expired`
- `revoked`
- `quarantined`
- `completed`

Only `active` principals may request tools or delegation.

A model cannot modify its principal state.

## Role registry

The AI Component Registry should own reviewed role definitions.

A role record should define:

- stable role ID/version;
- purpose;
- allowed trigger families;
- compatible Skill Packs;
- maximum evidence classes;
- maximum capability classes;
- allowed tool families;
- default read/write posture;
- external-processing compatibility;
- verification requirement;
- human-review requirement;
- maximum task steps/time/evidence budget;
- whether delegation is ever permitted; and
- review/expiration state.

Role display names do not grant permissions.

## Effective authorization

The effective capabilities for an agent are the intersection of:

```text
initiating actor authorization
∩ tenant/site scope
∩ investigation scope
∩ coordinator task scope
∩ approved role capabilities
∩ approved Skill Pack limits
∩ deployment/provider policy
∩ tool gateway policy
∩ current principal state
```

Any empty or conflicting required intersection fails closed.

## Task packet binding

The existing investigation task packet remains the unit of work. Identity extends it by binding the packet to an agent principal.

A task packet should reference:

- investigation ID;
- task ID;
- principal ID;
- approved role;
- Skill Pack/version;
- objective;
- evidence IDs or bounded scope reference;
- exact tenant/site/entity scope;
- allowed tool IDs;
- maximum steps/evidence/bytes/runtime;
- required gates;
- deadline; and
- coordinator policy version.

A provider-facing prompt is not the task record.

## Delegation boundary

The initial OpenAssetWatch investigation design forbids recursive specialist spawning. That remains the safe default.

If nested delegation is added later, it must use a deterministic delegation contract.

## Proposed delegation grant

A future `oaw.agent-delegation.v1` record should contain:

```text
delegation_id
parent_agent_instance_id
child_role_id
child_task_id
investigation_id
objective_digest
tenant_scope
site_scope
entity_scope
allowed_evidence_classes
allowed_capabilities
allowed_tools
credential_scope
max_steps
max_runtime
max_output_bytes
expires_at
can_delegate_further
max_remaining_depth
policy_version
issued_at
```

The coordinator, not the parent model, issues the final grant.

## Capability attenuation

Mandatory invariant:

```text
child effective capability
  MUST be a subset of
parent delegated capability
```

A child must not gain authority because:

- its role has broader defaults;
- its Skill Pack mentions another tool;
- another agent recommends access;
- untrusted content asks for access;
- a provider supports additional native tools; or
- the parent agent holds broader credentials.

## Non-inheritance rules

The following must not automatically transfer to a child:

- broad parent credentials;
- unneeded evidence classes;
- parent output/publish authority;
- parent memory-write eligibility;
- parent delegation rights;
- cross-site or cross-tenant scope;
- human approval records;
- temporary policy exceptions; or
- privileged provider/session state.

## Delegation graph limits

Future recursive delegation requires product-owned graph controls.

Suggested policy inputs:

- maximum depth;
- maximum children per parent;
- maximum concurrent descendants;
- maximum total tasks per investigation;
- maximum total tool calls;
- maximum total tokens/cost/time;
- prohibited role-to-role edges;
- required verifier edges;
- cycle detection; and
- cancellation propagation.

A graph violation must block dispatch before a provider call begins.

## Cycle detection

The coordinator should reject a proposed edge when it would create a path from the child back to an ancestor.

Cycle identity uses stable task/agent IDs, not model-generated role names.

Detected cycles should produce a bounded reason code and ledger event rather than silently retrying.

## Fan-out protection

One malicious or ambiguous item must not trigger an unbounded set of specialists.

Fan-out policy should consider:

- trigger type;
- number of affected assets;
- role diversity actually needed;
- evidence availability;
- remaining budget;
- current systemic-risk state; and
- prior failures/retries.

The coordinator may degrade to a smaller read-only investigation or `inconclusive` result rather than expanding indefinitely.

## Credentials

Preferred pattern:

```text
agent principal
  -> approved tool request
  -> deterministic authorization
  -> gateway applies narrow short-lived service identity
  -> scoped service call
```

The model should not receive raw long-lived credentials.

Credential scope should bind at least:

- principal/task;
- tool/service;
- tenant/site/resource;
- operation class;
- expiration; and
- one-time/replay behavior where practical.

## Tool request binding

Every tool authorization event should include:

- initiating actor;
- agent principal;
- task;
- investigation;
- canonical tool identity;
- normalized parameters/digest;
- tenant/site scope;
- side-effect class;
- credential scope;
- destination;
- applicable approval; and
- policy version.

A valid human approval for one principal/task cannot be reused by another child unless the approval policy explicitly binds to both.

## Agent-to-agent authentication

Typed handoff content is still untrusted model output. Authentication proves who sent it, not that its claims are correct.

Each handoff should bind:

- sender principal;
- receiver principal or role;
- investigation/task IDs;
- message type;
- evidence references;
- content digest;
- scope;
- timestamp/expiry; and
- coordinator route/policy version.

Receiving agents cannot infer new permission from message text.

## Trust and consensus

Agent identity does not imply independent verification.

Two instances using the same model/provider/system instructions may share correlated errors. The coordinator must track verifier diversity separately from identity.

High-consequence claims require deterministic validation and/or human review according to policy regardless of agent count.

## Runtime attestation and component trust

Where practical, the principal should reference reviewed runtime/model/Skill Pack/tool versions used by the task.

A principal whose required component becomes revoked or invalid during a run should be suspended according to recovery policy.

## Revocation

Revocation must be effective at the Tool Gateway and coordinator, not merely in model instructions.

Revoking an agent principal should:

- deny future tool requests;
- stop new delegation;
- cancel or mark pending child work for revalidation;
- quarantine uncommitted memory/output proposals;
- preserve existing audit events; and
- trigger compromise review when appropriate.

## Expiration

Principals and delegation grants should be short-lived and bounded to a task/investigation. Expired identity cannot be silently refreshed by the model.

A restarted process must revalidate identity, scope, policy, and component state before resuming.

## Audit events

Suggested future event families:

- `agent.identity.issued`
- `agent.identity.activated`
- `agent.identity.suspended`
- `agent.identity.revoked`
- `agent.identity.expired`
- `agent.delegation.requested`
- `agent.delegation.allowed`
- `agent.delegation.denied`
- `agent.delegation.depth_blocked`
- `agent.delegation.fanout_blocked`
- `agent.delegation.cycle_blocked`
- `agent.capability.attenuated`
- `agent.scope.violation`

Logs should record IDs, hashes, policy versions, bounded reason codes, and scope references without secrets or unrestricted prompt content.

## Deterministic reason codes

Candidate bounded reason codes:

- `AGENT_IDENTITY_MISSING`
- `AGENT_IDENTITY_REVOKED`
- `AGENT_IDENTITY_EXPIRED`
- `ROLE_NOT_APPROVED`
- `TASK_BINDING_MISMATCH`
- `DELEGATION_NOT_ALLOWED`
- `DELEGATION_DEPTH_EXCEEDED`
- `DELEGATION_FANOUT_EXCEEDED`
- `DELEGATION_CYCLE_DETECTED`
- `CHILD_CAPABILITY_EXPANSION`
- `CHILD_SCOPE_EXPANSION`
- `CHILD_CREDENTIAL_EXPANSION`
- `DELEGATION_GRANT_EXPIRED`
- `AGENT_COMPONENT_UNTRUSTED`

## Required evaluation

Before enabling any recursive delegation, tests must prove:

- unknown/revoked principals cannot execute;
- child capabilities never exceed the grant;
- child tenant/site/entity scope cannot expand;
- parent approval is not silently inherited;
- depth/fan-out limits hold under adaptive attempts;
- cycles are rejected;
- late provider output after cancellation cannot cause action;
- credential use is task/tool scoped;
- compromised parent cancellation propagates correctly; and
- audit graph reconstruction is complete.

## Release blockers

Hard blockers for the applicable capability:

- unknown agent identity executes a tool;
- revoked/expired principal continues execution;
- unauthorized sub-agent is created;
- child authority exceeds parent delegation;
- delegation escapes tenant/site/task scope;
- delegation cycle executes;
- required identity/audit binding is missing; or
- approval/credential from one task is reused outside its binding.

## Explicit non-goals

This design does not approve recursive delegation, autonomous remediation, arbitrary agent discovery, peer-to-peer permission negotiation, self-issued credentials, self-modifying roles, or agent-created security principals.

## Implementation readiness

The principal/role registry and non-recursive task binding are the safest first implementation targets. Recursive delegation remains disabled until attenuation, graph controls, recovery, and evaluation gates are implemented.