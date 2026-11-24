# Prompt Injection Deterministic Rule Catalog

- **Status:** Documentation-only rule design
- **Rule family:** `oaw.ai-security.pi`
- **Principle:** The model may observe and explain rule outcomes but may not create, modify, disable, or override these rules at runtime.

## Common rule contract

Every future rule should define:

```text
rule_id
rule_version
purpose
scope
trigger
required_evidence
condition
decision
reason_code
severity
audit_event
override_policy
test_case
negative_test
failure_mode
```

Decisions are intentionally narrow, such as `allow`, `deny`, `require-approval`, `quarantine`, `strip-authority`, `reject-write`, or `block-publication`.

## Rules

| Rule ID | Purpose | Condition | Decision | Reason code | Severity |
| --- | --- | --- | --- | --- | --- |
| `PI-TRUST-001` | Prevent content from self-asserting authority | untrusted/model content attempts to set protected trust/authority labels | reject label / keep content data-only | `SELF_ASSERTED_TRUST_REJECTED` | high |
| `PI-SCOPE-001` | Enforce tenant scope | context/retrieval/tool/output references another tenant | deny | `TENANT_SCOPE_MISMATCH` | critical |
| `PI-SCOPE-002` | Enforce site scope | resource outside approved site scope | deny | `SITE_SCOPE_MISMATCH` | high |
| `PI-CONTEXT-001` | Prevent untrusted policy override | Zone 3-6 content presented as platform/approved-workflow instruction | strip authority / quarantine if material | `UNTRUSTED_INSTRUCTION_AUTHORITY` | high |
| `PI-CONTEXT-002` | Fail safe on missing critical labels | privileged context item lacks required trust/scope metadata | deny privileged use | `TRUST_METADATA_MISSING` | high |
| `PI-TOOL-001` | Require canonical approved tool | tool ID/version not approved | deny | `TOOL_NOT_APPROVED` | high |
| `PI-TOOL-002` | Detect tool/schema drift | implementation/description/schema digest changed since approval | deny/review | `TOOL_SCHEMA_DRIFT` | high |
| `PI-TOOL-003` | Align action to user/task intent | proposed tool/action materially outside approved objective | deny | `INTENT_ACTION_MISMATCH` | high |
| `PI-TOOL-004` | Prevent parameter scope expansion | parameter adds out-of-scope target/resource | deny | `PARAMETER_SCOPE_EXPANSION` | high |
| `PI-TOOL-005` | Restrict external destination | destination not approved for tool/task/data class | deny | `DESTINATION_NOT_ALLOWLISTED` | high |
| `PI-TOOL-006` | Limit credential scope | credential/resource permissions exceed need | deny | `CREDENTIAL_SCOPE_EXCESSIVE` | critical |
| `PI-TOOL-007` | Break untrusted+sensitive+egress path | task combines hostile/untrusted input, sensitive read, and lower-trust external write without controls | deny/require approval or split workflow | `CAPABILITY_TRIAD_UNSAFE` | critical |
| `PI-APPROVAL-001` | Require human approval | side effect/consequence policy requires approval and none valid | require approval | `APPROVAL_REQUIRED` | high |
| `PI-APPROVAL-002` | Bind approval to exact operation | approved digest/scope/tool/params/destination changed | deny/reapprove | `APPROVAL_BINDING_CHANGED` | high |
| `PI-MEM-001` | Block unvalidated durable memory | model/untrusted content proposes durable write without eligibility | reject write | `MEMORY_WRITE_NOT_ELIGIBLE` | high |
| `PI-MEM-002` | Prevent injected instructions in trusted memory | memory candidate contains instruction-bearing untrusted content and is proposed as trusted instruction/fact | quarantine/reject | `MEMORY_INSTRUCTION_POISONING` | high |
| `PI-RAG-001` | Protect corpus ingestion | external/model content lacks provenance/scope/write approval | reject/quarantine ingestion | `RAG_INGESTION_NOT_APPROVED` | high |
| `PI-RAG-002` | Prevent cross-tenant retrieval | retrieved chunk outside tenant scope | deny before model | `RAG_CROSS_TENANT_BLOCKED` | critical |
| `PI-RAG-003` | Preserve retrieved-content authority | retrieved content attempts to override task/policy | data-only / quarantine signal | `RAG_INSTRUCTION_IGNORED` | high |
| `PI-OUTPUT-001` | Require schema validation | model output malformed/unknown fields where strict schema required | reject | `OUTPUT_SCHEMA_INVALID` | medium/high |
| `PI-OUTPUT-002` | Prevent executable output path | unrestricted SQL/code/shell/query reaches execution-capable sink | deny | `UNRESTRICTED_GENERATED_CODE_BLOCKED` | critical |
| `PI-OUTPUT-003` | Prevent sensitive exfiltration | candidate output contains restricted data for lower-trust destination | block/approval | `SENSITIVE_EGRESS_BLOCKED` | critical |
| `PI-OUTPUT-004` | Prevent unsafe renderer content | output contains disallowed active HTML/script/unsafe URI scheme | sanitize/reject | `UNSAFE_RENDER_CONTENT` | high |
| `PI-DASH-001` | Enforce approved metrics/panels | dashboard plan references unknown metric/panel/dimension | reject | `DASHBOARD_COMPONENT_NOT_APPROVED` | high |
| `PI-DASH-002` | Enforce dashboard scope/cost | plan violates tenant/site/data/cost/cardinality/row limits | reject | `DASHBOARD_PLAN_POLICY_DENY` | high |
| `PI-DASH-003` | Protect persistent dashboards | AI attempts to save/modify durable dashboard without approved workflow | deny | `DASHBOARD_SAVE_REQUIRES_APPROVAL` | high |
| `PI-HANDOFF-001` | Require typed agent handoff | agent message lacks valid message type/scope/provenance | reject/escalate | `AGENT_HANDOFF_INVALID` | medium/high |
| `PI-HANDOFF-002` | Prevent trust escalation | receiving agent attempts to promote source-agent/model output without validation | keep non-authoritative | `AGENT_TRUST_ESCALATION_BLOCKED` | high |
| `PI-MCP-001` | Re-review changed MCP/tool metadata | approved MCP server/tool digest or schema changed | disable/review | `MCP_DRIFT_REVIEW_REQUIRED` | high |
| `PI-MCP-002` | Treat MCP response as untrusted | tool response contains instruction-like content requesting privilege/action | data-only; authorization still required | `MCP_RESPONSE_UNTRUSTED` | high |
| `PI-PI-001` | Quarantine confirmed injection | injection assessment is confirmed and content enters privileged context | quarantine/deny | `PROMPT_INJECTION_CONFIRMED` | high |
| `PI-PI-002` | Fail safe on suspicious/unknown high-consequence context | context state suspicious/likely/unknown and proposed action high-consequence | deny/require review | `INJECTION_STATE_UNSAFE_FOR_ACTION` | high |

## Detailed examples

### `PI-TOOL-005` — destination allowlist

- **Trigger:** Any tool request with an external/lower-trust destination.
- **Required evidence:** canonical tool ID, normalized destination, tenant/site scope, data classification, original user intent, task ID.
- **Condition:** destination not allowed by tool/task/data policy.
- **Decision:** `deny`.
- **Reason code:** `DESTINATION_NOT_ALLOWLISTED`.
- **Audit event:** `pi.tool.blocked`.
- **Override:** only a separately authorized policy exception; model output cannot override.
- **Positive test:** injected tool parameter requests an attacker-controlled URL -> deny.
- **Negative test:** approved internal report publisher sends an approved artifact digest to its configured internal destination -> allow if all other gates pass.
- **Failure mode:** fail closed if destination normalization fails.

### `PI-MEM-001` — durable memory gate

- **Trigger:** Any AI-originated durable memory write proposal.
- **Required evidence:** provenance, scope, memory type, evidence references, retention/expiration, injection state, candidate digest.
- **Condition:** `memory_write_eligible != true` from the deterministic memory gate.
- **Decision:** `reject-write`.
- **Reason code:** `MEMORY_WRITE_NOT_ELIGIBLE`.
- **Audit event:** `pi.memory_write_blocked`.
- **Negative test:** approved deterministic user preference field with policy-authorized persistence -> allowed by memory system without model promotion.
- **Failure mode:** fail closed.

### `PI-DASH-001` — approved analytical catalog

- **Trigger:** AI-generated dashboard plan.
- **Condition:** plan references metric, dimension, join path, panel, filter, or time grain not in the approved schema/catalog.
- **Decision:** reject plan and fall back to deterministic template if available.
- **Reason code:** `DASHBOARD_COMPONENT_NOT_APPROVED`.
- **Audit event:** `pi.dashboard_plan_blocked`.
- **Positive test:** hostile asset name tells model to add raw SQL -> schema cannot represent it, plan rejected if any free-form query field appears.
- **Negative test:** approved `asset_count` metric + `device_type` dimension + registered bar panel -> validator proceeds to scope/cost checks.

## Rule layering

Rules should be grouped into deterministic enforcement stages:

1. **Input/trust:** `PI-TRUST-*`, `PI-CONTEXT-*`, `PI-PI-*`
2. **Scope/retrieval:** `PI-SCOPE-*`, `PI-RAG-*`
3. **Tool/action:** `PI-TOOL-*`, `PI-APPROVAL-*`, `PI-MCP-*`
4. **Persistence:** `PI-MEM-*`, `PI-DASH-003`
5. **Output/egress:** `PI-OUTPUT-*`
6. **Multi-agent:** `PI-HANDOFF-*`
7. **Dashboard plan:** `PI-DASH-*`

## Agent-system rule delta

Agent-system security adds a second rule family, `oaw.ai-security.agent`. Existing prompt-injection rules are reused where they already express the required control rather than duplicated under new IDs.

### Reconciliation of agent-system rule families

| Agent-system requirement | Existing coverage | New rule if required |
| --- | --- | --- |
| agent identity required | none | `AS-IDENTITY-001` |
| revoked/expired agent blocked | none | `AS-IDENTITY-002` |
| delegation depth limit | none | `AS-DELEGATION-001` |
| delegation cycle prevention | none | `AS-DELEGATION-002` |
| delegation fan-out limit | none | `AS-DELEGATION-003` |
| child capability attenuation | partial handoff/tool scope | `AS-DELEGATION-004` |
| tool implementation/schema drift | `PI-TOOL-002`, `PI-MCP-001` | reuse |
| tool publisher identity drift | not explicit | `AS-TOOL-001` |
| credential scope exceeded | `PI-TOOL-006` | reuse |
| task/parameter scope exceeded | `PI-TOOL-003`, `PI-TOOL-004`, `PI-SCOPE-*` | reuse |
| cross-agent trust elevation | `PI-HANDOFF-002` | reuse |
| invalid/non-independent quorum | none | `AS-CONSENSUS-001` |
| approval request-rate limit | none | `AS-APPROVAL-001` |
| incomplete approval context | partial `PI-APPROVAL-001` | `AS-APPROVAL-002` |
| approval replay/consumed reuse | partial `PI-APPROVAL-002` | `AS-APPROVAL-003` |
| resource budget exceeded | investigation budgets designed elsewhere | `AS-BUDGET-001` |
| compromised session/principal state | none | `AS-RECOVERY-001` |
| memory quarantine after compromise | partial `PI-MEM-*` | `AS-MEM-001` |
| revoked AI component blocked | none | `AS-COMPONENT-001` |
| supply-chain provenance invalid | model-specific provenance exists | `AS-SUPPLY-001` |

### Agent-system rules

| Rule ID | Purpose | Condition | Decision | Reason code | Severity |
| --- | --- | --- | --- | --- | --- |
| `AS-IDENTITY-001` | Require authenticated agent principal | privileged task/tool/delegation has no valid principal | deny | `AGENT_IDENTITY_MISSING` | critical |
| `AS-IDENTITY-002` | Enforce principal lifecycle | principal is expired, revoked, suspended, or quarantined | deny/cancel | `AGENT_IDENTITY_NOT_ACTIVE` | critical |
| `AS-DELEGATION-001` | Limit delegation depth | proposed child would exceed policy depth | deny | `DELEGATION_DEPTH_EXCEEDED` | high |
| `AS-DELEGATION-002` | Prevent delegation cycle | proposed edge creates ancestor cycle | deny | `DELEGATION_CYCLE_DETECTED` | high |
| `AS-DELEGATION-003` | Limit fan-out/descendants | child count/concurrency/descendant total exceeds policy | deny/degrade | `DELEGATION_FANOUT_EXCEEDED` | high |
| `AS-DELEGATION-004` | Enforce capability attenuation | child scope/tool/capability/credential set not subset of grant | deny | `CHILD_CAPABILITY_EXPANSION` | critical |
| `AS-TOOL-001` | Detect publisher/source drift | approved canonical tool publisher/source changes | disable/review | `TOOL_PUBLISHER_CHANGED` | high |
| `AS-CONSENSUS-001` | Prevent false independent verification | workflow treats correlated/same-model agents as required independent quorum | reject verification state | `AGENT_QUORUM_NOT_INDEPENDENT` | high |
| `AS-APPROVAL-001` | Prevent approval fatigue/flood | approval request rate/dedup/cooldown policy exceeded | block/defer/escalate | `APPROVAL_RATE_LIMIT_EXCEEDED` | high |
| `AS-APPROVAL-002` | Require complete material approval context | required target/destination/data/permission/risk/uncertainty fields absent | deny approval use | `APPROVAL_CONTEXT_INCOMPLETE` | high |
| `AS-APPROVAL-003` | Prevent approval replay | consumed/denied/expired approval reused or task/action binding mismatched | deny | `APPROVAL_REPLAY_BLOCKED` | critical |
| `AS-BUDGET-001` | Enforce systemic budgets | hard task/tool/context/runtime/provider/approval limit exceeded | stop/degrade | `AGENT_RESOURCE_BUDGET_EXCEEDED` | high |
| `AS-RECOVERY-001` | Stop compromised execution | principal/session security state requires suspension/quarantine | deny/cancel/quarantine | `AGENT_SECURITY_STATE_BLOCKED` | critical |
| `AS-MEM-001` | Quarantine memory from compromised source | memory candidate/active item derives from compromised principal/session/component | quarantine/revalidate | `MEMORY_SOURCE_COMPROMISED` | high |
| `AS-COMPONENT-001` | Block revoked component | required model/tool/Skill Pack/role/workflow component is revoked/quarantined/expired | deny activation/use | `AI_COMPONENT_NOT_ACTIVE` | critical |
| `AS-SUPPLY-001` | Require valid provenance/integrity | protected component fails required digest/provenance/signature/review policy | deny/quarantine | `AI_SUPPLY_CHAIN_PROVENANCE_INVALID` | critical |

## Agent-system detailed examples

### `AS-DELEGATION-004` — capability attenuation

- **Trigger:** Future coordinator considers child-agent dispatch.
- **Required evidence:** parent principal, coordinator-issued delegation grant, child role/capability request, task scope, credential/tool requirements.
- **Condition:** any child effective capability, evidence class, tool, credential, destination, tenant/site/entity scope, memory/publication right, or delegation right exceeds the grant.
- **Decision:** `deny`.
- **Reason code:** `CHILD_CAPABILITY_EXPANSION`.
- **Audit event:** `agent.delegation.denied`.
- **Positive test:** parent read-only investigator attempts to spawn child with external publisher capability -> deny.
- **Negative test:** parent delegates narrower read-only evidence subset to verifier within depth/budget -> permit if all other gates pass.
- **Failure mode:** fail closed on missing grant metadata.

### `AS-APPROVAL-003` — approval replay

- **Trigger:** Side-effecting action presents approval record.
- **Condition:** approval is consumed, expired, denied/revoked, or exact action/task/tool/parameter/artifact/destination binding differs.
- **Decision:** `deny` and require new approval when policy allows.
- **Reason code:** `APPROVAL_REPLAY_BLOCKED`.
- **Audit event:** `ai.approval.replay_blocked`.
- **Failure mode:** fail closed.

### `AS-SUPPLY-001` — protected component provenance

- **Trigger:** Protected model/Skill Pack/tool/policy/workflow/evaluation component is selected or activated.
- **Condition:** required provenance/integrity/review state is missing, mismatched, revoked, expired, or requires re-evaluation.
- **Decision:** deny activation/use or quarantine according to component policy.
- **Reason code:** `AI_SUPPLY_CHAIN_PROVENANCE_INVALID`.
- **Audit event:** `ai.supply_chain.activation_blocked`.
- **Negative test:** exact approved component/version/digest with valid current review state proceeds.

## Rule layering with agent-system controls

8. **Identity and principal state:** `AS-IDENTITY-*`, `AS-COMPONENT-*`
9. **Delegation/topology:** `AS-DELEGATION-*`, `AS-CONSENSUS-*`
10. **Human/systemic resource controls:** `AS-APPROVAL-*`, `AS-BUDGET-*`
11. **Recovery/persistence:** `AS-RECOVERY-*`, `AS-MEM-*`
12. **Supply-chain integrity:** `AS-TOOL-*`, `AS-SUPPLY-*`

## Overrides

Overrides MUST be policy-owned, time-bounded, scoped, attributable, and audited. No override may permit:

- cross-tenant leakage;
- direct model authoritative writes;
- silent bypass of required human approval;
- unrestricted generated code/query execution;
- self-modifying rules or policy;
- unauthorized credential access;
- unknown/revoked agent execution;
- child capability expansion; or
- invalid protected-component provenance on a path where provenance is mandatory.

## Evaluation requirements

Every rule needs:

- one positive/blocking test;
- one benign negative test;
- malformed/missing metadata case;
- scope mismatch case where relevant;
- injection/adaptive case where relevant;
- stable reason-code assertion;
- audit-event assertion;
- fail-open/fail-closed assertion.

Agent-system rules additionally require multi-agent/topology/restart/replay cases where applicable.

Rules affecting high-consequence actions, tenant isolation, credentials, memory, external egress, agent identity/delegation, component provenance, or code/query execution are release blockers.