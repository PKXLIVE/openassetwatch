# AI Human Approval Security Model

- **Status:** Documentation-only architecture
- **Purpose:** Protect human approval workflows from replay, manipulation, fatigue, misleading summaries, and unsafe action drift
- **Related:** `docs/ai-security/AI_TOOL_AUTHORIZATION_MODEL.md`, `docs/architecture/ai-agent-permission-output-security.md`

## Core principle

```text
Human approval is a security control only when the person is shown the material facts
and the approval is cryptographically/deterministically bound to the exact action.
```

Human approval is not automatically safe merely because a person clicked `Approve`.

## Threat model

Approval workflows may be attacked through:

- repeated prompts and fatigue;
- manufactured urgency;
- misleading or incomplete summaries;
- hidden side effects;
- destination substitution;
- parameter changes after approval;
- artifact changes after approval;
- reused or replayed approval records;
- fake approval statements in untrusted content;
- agent-generated claims that another person approved;
- excessive batching;
- default-action bias;
- buried uncertainty;
- forged evidence or unsupported confidence;
- approval prompts that omit credentials/permissions used; and
- repeated re-prompting after denial.

## Relationship to current tool authorization

`AI_TOOL_AUTHORIZATION_MODEL.md` already requires approval records to bind:

- approver identity;
- task;
- canonical tool/version;
- normalized parameter digest;
- destination;
- tenant/site scope;
- consequence class;
- content/artifact digest where applicable;
- expiration; and
- policy version.

This document adds the **human-factors and anti-manipulation requirements** around that binding.

## Approval object

A future `oaw.ai-approval.v1` record should contain bounded fields such as:

```text
approval_id
approval_policy_version
approver_identity
second_approver_identity (optional)
initiating_actor_id
agent_principal_id
investigation_id
task_id
action_type
canonical_tool_id
canonical_tool_version
parameter_digest
artifact_digest
destination
tenant_scope
site_scope
data_classification
credential_scope
side_effect_class
consequence_class
reversibility_class
requested_at
approved_at
expires_at
status
reason_for_approval
material_risks_digest
uncertainty_digest
```

The exact schema requires implementation review.

## Secure approval preview

The reviewer should see the following information directly from product-owned structured fields rather than only a model-written narrative.

### Original objective

What did the authenticated user actually ask OpenAssetWatch to accomplish?

### Exact proposed action

What operation will occur?

### Exact target

Which asset, site, resource, file, policy, service, account, or object is affected?

### Exact destination

Where will data or an artifact be sent/published?

### Data affected

What classifications and approximate quantity/scope of information are involved?

### Permission/capability used

Which capability, tool, and credential scope will be exercised?

### Side effects

What changes if the action succeeds?

### Reversibility

Can it be rolled back? What is the rollback requirement?

### Evidence

Which server-issued evidence or deterministic finding/decision justifies the request?

### Uncertainty

What is unknown, stale, conflicted, inferred, or unverified?

### Why approval is required

Which policy/reason code caused the gate?

A model may add a concise explanation, but it must not control the structured facts above.

## Action digest binding

Approval must bind to a canonical representation of the operation.

Conceptually:

```text
action_digest = hash(
  action_type
  + canonical_tool_identity
  + normalized_parameters
  + target
  + destination
  + scope
  + artifact/content_digest
  + consequence_class
  + policy_version
)
```

Any material change requires new authorization and usually a new approval.

## Material changes

Examples that invalidate approval:

- tool implementation/version changes;
- tool schema changes;
- target changes;
- destination changes;
- parameter value changes outside an explicitly approved bounded set;
- credential scope expands;
- tenant/site/entity scope expands;
- artifact/content digest changes;
- action becomes less reversible;
- consequence class increases;
- security policy changes; or
- approval expires.

The model cannot decide that a change is immaterial.

## Replay prevention

Approval records should be one-time or narrowly reusable according to explicit policy.

Controls:

- nonce/unique approval ID;
- task/action binding;
- expiry;
- execution-state transition after use;
- prevention of cross-task reuse;
- prevention of reuse after denial/revocation;
- idempotency rules for safe retry; and
- full audit trail.

## Approval states

Suggested states:

- `requested`
- `approved`
- `denied`
- `expired`
- `revoked`
- `consumed`
- `superseded`
- `cancelled`

Only an `approved` unexpired, unconsumed record with exact binding may satisfy a required gate.

## Consequence tiers

Suggested policy tiers:

### Tier 0 — no approval

Bounded read-only operations already permitted by scope/policy.

### Tier 1 — user confirmation

Reversible low-impact internal actions or durable drafts where policy requires acknowledgment.

### Tier 2 — explicit approval

External publication, sensitive egress, durable state changes, or security-relevant actions with bounded scope.

### Tier 3 — enhanced approval

Destructive, broad, cross-environment, safety/availability-impacting, credential-sensitive, or other high-consequence actions.

Potential controls include a second approver, separation of duties, maintenance window, rollback plan, and security review.

Current OpenAssetWatch remains advisory/read-only unless a separately approved future workflow introduces side effects.

## Approval fatigue controls

Human attention is finite and can be attacked.

The platform should enforce:

- per-user/per-agent/per-investigation approval request rate limits;
- deduplication of materially identical requests;
- cooldown after denial;
- no automatic repeated re-prompting after denial;
- escalation to security/systemic state on approval floods;
- batching only for homogeneous low-consequence actions when policy allows;
- maximum batch size;
- clear count and scope for batched actions; and
- ability to reject the entire batch safely.

## Manufactured urgency

Agent text such as "approve immediately" is not a policy signal.

Urgency shown to a reviewer should come from deterministic finding/decision/policy state where available.

Model-generated urgency language must be visually subordinate to authoritative fields and never bypass waiting periods, second approval, or review requirements.

## Misleading summaries

Approval should not depend on a single model-generated summary.

Required structured facts should be populated from trusted task/tool/evidence metadata.

If the narrative conflicts with structured metadata, the approval request should fail safe and log a context-integrity incident.

## Evidence integrity

Material claims in an approval request should use valid server-issued evidence references.

Unknown or out-of-scope evidence IDs fail validation.

A model's confidence is not evidence.

## Hidden consequences

The approval gate must calculate and display consequence fields independently of model wording, including:

- external communication;
- credential use;
- write/durable state;
- deletion/destruction;
- security-control change;
- cross-tenant/site effect;
- availability/safety effect; and
- publication destination trust.

## Separation of duties

For the highest-consequence classes, policy may require the requester/agent operator and approver to be distinct identities.

A second-person approval should be required when the project later introduces actions such as:

- broad destructive changes;
- cross-tenant administrative operations;
- security-policy changes;
- high-impact credential operations;
- safety-sensitive OT actions; or
- other actions designated by governance.

The model cannot act as the second approver.

## Dual approval

When enabled, both approvals must bind to the same action digest and policy version.

If the action changes after either approval, both are invalid unless policy explicitly defines a safe bounded amendment.

## Denial handling

A denial should:

- be recorded;
- stop the pending action;
- prevent the agent from simply rephrasing and resubmitting the same action automatically;
- require new evidence or explicit user initiation for reconsideration; and
- trigger incident/systemic handling when repeated denied requests indicate manipulation or runaway behavior.

## Cancellation

User cancellation invalidates pending approvals/actions.

Late model/tool output after cancellation must not resurrect the request.

## Approval artifacts

The approval UI should reference an immutable candidate artifact/digest for content publication.

A separate publisher identity should receive only:

- approved artifact ID/digest;
- destination;
- narrow publication capability;
- approval record; and
- expiry.

The publisher must not let the reasoning model rewrite the artifact after approval.

## Audit events

Suggested events:

- `ai.approval.requested`
- `ai.approval.approved`
- `ai.approval.denied`
- `ai.approval.expired`
- `ai.approval.revoked`
- `ai.approval.consumed`
- `ai.approval.binding_changed`
- `ai.approval.replay_blocked`
- `ai.approval.rate_limited`
- `ai.approval.fatigue_detected`
- `ai.approval.summary_mismatch`
- `ai.approval.dual_control_required`

Do not log secrets or full unrestricted model context.

## Deterministic reason codes

Candidate reason codes:

- `APPROVAL_REQUIRED`
- `APPROVAL_CONTEXT_INCOMPLETE`
- `APPROVAL_BINDING_CHANGED`
- `APPROVAL_EXPIRED`
- `APPROVAL_REVOKED`
- `APPROVAL_ALREADY_CONSUMED`
- `APPROVAL_REPLAY_BLOCKED`
- `APPROVAL_RATE_LIMIT_EXCEEDED`
- `APPROVAL_DENIAL_COOLDOWN`
- `APPROVAL_SUMMARY_METADATA_MISMATCH`
- `DUAL_APPROVAL_REQUIRED`
- `SEPARATION_OF_DUTIES_REQUIRED`
- `ACTION_CONSEQUENCE_ESCALATED`

## Evaluation

Required defensive tests include:

- injected evidence claiming "already approved";
- model fabricating an approver identity;
- target changed after approval;
- destination changed after approval;
- artifact changed after approval;
- credential scope expanded after approval;
- replay of consumed approval;
- reuse across task/tenant/site;
- repeated request after denial;
- approval flood;
- misleading model summary hiding external egress;
- manufactured urgency;
- batched heterogeneous actions presented as one approval;
- second approver missing when required;
- cancellation before execution; and
- late output after cancellation.

Metrics:

- forged-approval success rate;
- replay success rate;
- materially changed action execution rate;
- approval manipulation success rate;
- approval fatigue/re-prompt rate;
- human comprehension/task-success measure where usability testing exists; and
- benign approval burden.

## Hard release blockers

For side-effecting capabilities:

- agent/model fabricated approval is accepted;
- approval is reused across materially different action;
- material action change executes without reapproval;
- high-consequence action bypasses required second approval;
- denied/cancelled action executes;
- approval summary hides material structured risk without a blocking mismatch; or
- cross-tenant/site approval binding is bypassed.

## Explicit non-goals

This document does not authorize any new action capability. It defines the minimum secure approval architecture required if consequential action workflows are added later.