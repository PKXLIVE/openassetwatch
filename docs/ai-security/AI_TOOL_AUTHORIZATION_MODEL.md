# AI Tool Authorization Model

- **Status:** Documentation-only architecture
- **Purpose:** Define the deterministic authorization boundary for any future AI or agent tool invocation.

## Core rule

```text
The model proposes a tool call.
The model does not authorize a tool call.
```

Native provider tool-calling, MCP tool selection, Skill Pack instructions, or another agent's recommendation may describe a request format. None of them bypass the OpenAssetWatch authorization boundary.

## Authorization inputs

Every proposed tool call must be evaluated against:

```text
original_user_intent
+ authenticated_actor
+ current_task
+ investigation_scope
+ proposed_tool_identity
+ proposed_parameters
+ data_classification
+ credential_scope
+ file/network/resource scope
+ side_effect_class
+ destination
+ tenant_scope
+ site_scope
+ source/content trust
+ human_approval_requirement
+ current approval record
+ rate/resource limits
```

Missing required authorization metadata is not interpreted as permission.

## Decisions

The deterministic authorizer returns one of:

- `allow`
- `require-approval`
- `deny`

Every non-trivial decision includes a stable bounded `reason_code` and audit event.

## Canonical tool identity

Display names are not sufficient. Future tool registry identity should include:

- integration ID;
- canonical tool ID;
- publisher/source;
- version;
- implementation digest;
- parameter-schema digest;
- transport;
- declared capability class;
- side-effect class;
- allowed destinations/resource classes;
- credential requirements;
- approved trust state;
- last review time;
- expiration/review deadline.

Description/schema drift invalidates prior review when security-relevant fields change.

## Capability classes

Suggested initial classes:

- `read-evidence`
- `read-asset`
- `read-finding`
- `read-temporal`
- `compose-report`
- `create-draft-artifact`
- `write-non-authoritative-workspace`
- `publish-internal`
- `publish-external`
- `change-configuration`
- `network-query`
- `remediation-action`

The first native agent runtime should remain primarily read-only. Side-effecting classes require separate design and approval gates.

## Side-effect classes

| Class | Examples | Default |
| --- | --- | --- |
| `none` | bounded database/API reads | allow only if scope and tool are approved |
| `reversible-local` | create temporary draft/workspace artifact | policy-dependent |
| `durable-internal` | save memory, dashboard, ticket draft, policy draft | independent write gate |
| `external-communication` | email, webhook, public/internal publisher outside the analysis boundary | approval/publisher policy |
| `security-control-change` | modify policy, firewall, endpoint, collector, account | deny unless explicitly designed and approved |
| `high-consequence` | destructive or safety/availability-sensitive action | explicit human approval and specialized workflow |

## Intent alignment

The authorizer must compare proposed action to the original user intent and current approved task, not merely the latest model message.

Examples of denial/escalation conditions:

- tool is not necessary for the task;
- requested resource is outside investigation scope;
- parameter introduces an unrelated target or destination;
- requested credential scope exceeds task need;
- output destination was not part of the user's approved objective;
- untrusted content is the only source requesting the action;
- tool/schema identity changed after approval;
- action combines untrusted input, sensitive reads, and lower-trust publication without required controls.

## Parameter validation

Parameters are validated by strict schemas and policy, including:

- unknown-field rejection;
- size/count limits;
- stable resource IDs instead of raw targets where possible;
- bounded enumerations;
- path/CIDR/URL/domain allowlists where applicable;
- tenant/site binding;
- prevention of parameter smuggling into description/free-text fields;
- destination normalization;
- TOCTOU protection for referenced artifacts/digests;
- no executable expressions unless a separately approved capability explicitly requires them.

## Credentials

AI runtimes should not receive broad application credentials. Preferred pattern:

```text
agent/model
  -> tool request
  -> authorization gate
  -> short-lived/narrow service identity
  -> tenant/site-scoped service call
```

The model never receives the raw credential when it can be held and applied by the gateway.

## Human approval

Human approval is required according to consequence, not model confidence.

Approval records should bind:

- user/approver identity;
- task ID;
- tool canonical ID/version;
- normalized parameter digest;
- destination;
- tenant/site scope;
- side-effect/consequence class;
- artifact/content digest when applicable;
- expiration;
- approval policy version.

A changed parameter, destination, tool digest, or artifact digest invalidates approval unless policy explicitly allows the bounded change.

The model cannot simulate, infer, or fabricate human approval.

## Output publication separation

The reasoning component should produce an approved candidate artifact. A separate publisher identity receives only the approved artifact/digest and destination. This prevents the analysis model from silently changing content between approval and publication.

## Proposed deterministic reason codes

- `TOOL_NOT_APPROVED`
- `TOOL_VERSION_UNAPPROVED`
- `TOOL_SCHEMA_DRIFT`
- `INTENT_ACTION_MISMATCH`
- `TASK_SCOPE_MISMATCH`
- `TENANT_SCOPE_MISMATCH`
- `SITE_SCOPE_MISMATCH`
- `PARAMETER_INVALID`
- `PARAMETER_SCOPE_EXPANSION`
- `DESTINATION_NOT_ALLOWLISTED`
- `CREDENTIAL_SCOPE_EXCESSIVE`
- `UNTRUSTED_CONTENT_REQUESTED_ACTION`
- `SENSITIVE_EGRESS_REQUIRES_APPROVAL`
- `HIGH_CONSEQUENCE_REQUIRES_APPROVAL`
- `APPROVAL_MISSING`
- `APPROVAL_EXPIRED`
- `APPROVAL_BINDING_CHANGED`
- `RATE_LIMIT_EXCEEDED`
- `SECURITY_VALIDATION_UNAVAILABLE`
- `POLICY_DENY`

## Suggested evaluation record

```json
{
  "authorization_id": "authz_...",
  "task_id": "task_...",
  "actor_id": "...",
  "tool_id": "integration/tool",
  "tool_version": "...",
  "schema_digest": "sha256:...",
  "parameter_digest": "sha256:...",
  "tenant_scope": "...",
  "site_scope": "...",
  "side_effect_class": "none",
  "destination_class": "internal",
  "decision": "allow",
  "reason_codes": [],
  "approval_required": false,
  "policy_version": "...",
  "evaluated_at": "..."
}
```

## Prompt-injection behavior

An injection detector may inform the authorizer, but authorization must remain safe even when detection fails. A tool request from a model exposed to hostile content is still constrained by scope, tool identity, parameters, side-effect class, destination, and approval requirements.

For high-consequence actions, an `unknown`, `suspicious`, `likely-injection`, or `confirmed-injection` context state should deny or require escalation according to policy.

## Release invariants

1. A model cannot self-approve.
2. A Skill Pack cannot widen permissions.
3. Tool display name cannot substitute for canonical identity.
4. Tenant/site mismatch fails closed.
5. Unknown destination for a side effect fails closed.
6. Changed tool/schema/artifact identity re-triggers authorization.
7. Credentials are scoped to the approved task/tool/resource.
8. Untrusted content cannot supply approval authority.
9. External publication is separated from reasoning identity.
10. Every decision is auditable with bounded reason codes.