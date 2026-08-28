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

## Overrides

Overrides MUST be policy-owned, time-bounded, scoped, attributable, and audited. No override may permit:

- cross-tenant leakage;
- direct model authoritative writes;
- silent bypass of required human approval;
- unrestricted generated code/query execution;
- self-modifying rules or policy;
- unauthorized credential access.

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

Rules affecting high-consequence actions, tenant isolation, credentials, memory, external egress, or code/query execution are release blockers.