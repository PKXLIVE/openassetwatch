# Prompt Injection Policy Index

- **Status:** Documentation-only normative design
- **Purpose:** Define the policy package that future runtime enforcement and Skill Packs must obey.

## Policy hierarchy

Policy is authoritative only when implemented through approved product configuration/code. Markdown describes the requirement; it does not itself grant or enforce permissions.

Every future policy should use normative language:

- **MUST / MUST NOT** — required security behavior
- **SHOULD / SHOULD NOT** — recommended behavior with documented exceptions
- **MAY** — optional behavior within all higher-priority constraints

## Common policy requirements

Every policy MUST define:

- purpose and scope;
- definitions;
- mandatory requirements;
- prohibited behavior;
- trust boundaries;
- tenant/site behavior;
- human-approval requirements;
- audit events and minimum-safe metadata;
- incident response;
- exceptions and expiration;
- enforcement owner;
- tests and release gates;
- review cadence and versioning.

## Proposed policy set

### 1. `AI_TRUST_BOUNDARY_POLICY.md`

**Purpose:** Define the trust-zone and instruction-authority model.

**Mandatory requirements:**

- External/user/tool/model content MUST be treated as data unless deterministic metadata grants a specific instruction role.
- `instruction_authority`, tenant scope, site scope, action eligibility, and memory eligibility MUST be assigned outside the model.
- Untrusted content MUST NOT widen permissions, alter policy, create authoritative facts, or bypass approval.
- Trust MUST NOT increase because another model summarized or relayed content.
- Unknown trust MUST fail safe for high-consequence actions.

### 2. `AI_UNTRUSTED_CONTENT_POLICY.md`

**Purpose:** Control ingestion and AI use of Zone 3-5 content.

**Mandatory requirements:**

- Untrusted content MUST carry provenance and trust labels before model use.
- Context MUST be bounded/minimized to task need.
- Injection scanning SHOULD be applied to user, retrieved, tool, document, and security-telemetry content.
- Detection results MUST NOT be the sole authorization control.
- Quarantined content MUST NOT enter privileged/action-capable context.
- Sanitization MUST preserve provenance and original digest.

### 3. `AI_CONTEXT_INTEGRITY_POLICY.md`

**Purpose:** Prevent authority confusion inside model context.

**Mandatory requirements:**

- System/platform policy, user intent, deterministic facts, untrusted content, and model output MUST remain distinguishable in context assembly.
- Evidence MUST NOT be concatenated into policy/instruction sections as authoritative text.
- Cross-tenant/site content MUST be rejected before context assembly.
- Stale/unrelated context SHOULD be excluded.
- Conflicting instruction signals MUST be surfaced and handled deterministically where consequence is material.

### 4. `AI_TOOL_AUTHORIZATION_POLICY.md`

**Purpose:** Require independent authorization for every model/agent tool request.

**Mandatory requirements:**

- Tool authorization MUST be enforced outside the model.
- Canonical tool identity/version/schema MUST be approved.
- User/task/scope alignment, parameters, destination, data classification, credential scope, side effect, and approval MUST be evaluated.
- The model MUST NOT self-approve.
- Missing critical authorization metadata MUST deny or require review.
- Side-effecting/high-consequence actions MUST use explicit approval policy.

### 5. `AI_MCP_SECURITY_POLICY.md`

**Purpose:** Protect future MCP/tool-server integrations.

**Mandatory requirements:**

- Tool/server identity MUST be canonical and versioned.
- Description/schema/implementation digests SHOULD be pinned or otherwise integrity-checked.
- Security-relevant drift MUST trigger re-review.
- Tool descriptions, resources, prompts, and responses MUST be treated as untrusted model content.
- An MCP server MUST NOT grant itself new permissions through metadata.
- New/changed side-effecting servers MUST require explicit approval before production use.

### 6. `AI_RAG_INGESTION_POLICY.md`

**Purpose:** Protect RAG corpus writes and retrieval.

**Mandatory requirements:**

- Corpus writes MUST be tenant-scoped and provenance-preserving.
- External content MUST NOT become trusted instruction through ingestion.
- Injection/quarantine state MUST be stored with the document/chunk or derivation.
- Model summaries MUST NOT enter durable corpus as trusted records without an independent write gate.
- Retrieval MUST preserve source/trust labels.
- Cross-tenant retrieval leakage MUST be a release-blocking failure.

### 7. `AI_MEMORY_WRITE_POLICY.md`

**Purpose:** Prevent durable memory poisoning.

**Mandatory requirements:**

- A model MUST NOT directly set durable memory eligibility.
- Memory candidates MUST include provenance, scope, purpose, evidence references, retention/expiration, and conflict state.
- Untrusted instructions MUST NOT be persisted as trusted memory.
- Sensitive data MUST follow retention/data-classification policy.
- Corrections/retractions MUST be possible without erasing audit history.
- Unknown/likely injection state MUST block privileged durable writes.

### 8. `AI_OUTPUT_HANDLING_POLICY.md`

**Purpose:** Treat model output as untrusted before rendering, execution, or publication.

**Mandatory requirements:**

- Structured outputs MUST be schema validated.
- Output MUST NOT be executed as code/query/shell merely because a model produced it.
- Renderers MUST prevent HTML/script execution unless an explicit safe renderer contract exists.
- Evidence references MUST be validated when claims depend on them.
- Output size, destination, and data classification MUST be bounded.
- Publisher identity SHOULD be separate from reasoning identity for consequential publication.

### 9. `AI_DATA_EXFILTRATION_POLICY.md`

**Purpose:** Prevent sensitive-data egress caused by prompt injection or confused-deputy behavior.

**Mandatory requirements:**

- Workflows MUST avoid combining untrusted input + sensitive reads + lower-trust external writes without independent controls.
- Sensitive egress MUST be destination- and approval-scoped.
- Credentials/secrets MUST NOT be exposed to model context when a gateway can hold them.
- Encoded/obfuscated output MUST still be subject to data-loss checks where applicable.
- Injection-caused external exfiltration is a zero-tolerance release blocker.

### 10. `AI_HUMAN_APPROVAL_POLICY.md`

**Purpose:** Bind human approval to consequential actions.

**Mandatory requirements:**

- Approval MUST bind actor, task, tool/action, normalized parameters or artifact digest, destination, scope, policy version, and expiration.
- Changed bindings MUST invalidate approval unless policy explicitly permits the bounded change.
- The model MUST NOT simulate or infer approval.
- High-consequence and safety-impacting actions MUST require explicit human approval.

### 11. `AI_MULTI_AGENT_HANDOFF_POLICY.md`

**Purpose:** Prevent trust escalation through agent delegation.

**Mandatory requirements:**

- Handoffs MUST use typed contracts distinguishing instruction, evidence, hypothesis, recommendation, untrusted content, fact reference, and requested action.
- Trust MUST NOT increase merely because content came from another agent.
- Child agents MUST NOT inherit broader permissions than their task requires.
- The coordinator MUST own delegation and scope.
- Same-model consensus MUST NOT count as independent verification.

### 12. `AI_DASHBOARD_GENERATION_POLICY.md`

**Purpose:** Constrain AI-generated investigation dashboards.

**Mandatory requirements:**

- AI MUST select from approved metric/panel/dimension catalogs using stable IDs.
- AI MUST NOT emit unrestricted SQL, shell, code, arbitrary query language, invented joins, or unregistered fields for execution.
- Dashboard plans MUST be schema validated and deterministically authorized for tenant/site scope, data classification, cost, cardinality, and row limits.
- Generated dashboards MUST be temporary by default.
- Saving/modifying durable dashboards requires an approved workflow.

### 13. `AI_PROMPT_INJECTION_RESPONSE_POLICY.md`

**Purpose:** Define containment and recovery.

**Mandatory requirements:**

- Likely/confirmed injection incidents MUST isolate affected context and review tool, memory, RAG, data-access, and egress activity.
- Relevant credentials/sessions MUST be evaluated when exposure is possible.
- Affected cached/memory context MUST be invalidated when required.
- Every confirmed incident SHOULD produce a regression case before closure.
- Forensic evidence MUST minimize unnecessary sensitive content.

### 14. `AI_SECURITY_LOGGING_POLICY.md`

**Purpose:** Record enough security evidence without creating a new sensitive-data store.

**Mandatory requirements:**

- Events MUST use stable types and reason codes.
- Logs SHOULD store IDs, hashes, scope, tool identity, policy version, timestamps, decisions, and bounded forensic metadata.
- Secrets, credentials, and full sensitive prompts MUST NOT be logged by default.
- Access to detailed forensic excerpts MUST be restricted and auditable.

Suggested events include:

`pi.input.scanned`, `pi.input.suspicious`, `pi.indirect.detected`, `pi.context.quarantined`, `pi.tool.blocked`, `pi.tool.approval_requested`, `pi.output.blocked`, `pi.exfiltration.blocked`, `pi.memory_write_blocked`, `pi.rag_ingestion_quarantined`, `pi.dashboard_plan_blocked`, `pi.agent_handoff_blocked`, `pi.policy_violation`, `pi.test.failure`.

### 15. `AI_SECURITY_EVALUATION_POLICY.md`

**Purpose:** Require adversarial evaluation before release and after incidents/changes.

**Mandatory requirements:**

- Evaluation MUST cover direct, indirect, obfuscated, multilingual, RAG, memory, tool/MCP, multi-agent, multimodal, output, and exfiltration attacks applicable to the capability.
- Repeated/adaptive attempts MUST be included; one-shot testing is insufficient.
- Release-blocker events MUST fail the capability regardless of average detection score.
- False-positive impact and benign task utility MUST be measured.
- Every confirmed incident MUST add regression coverage.
- Dataset/tool licensing MUST be approved before bundling into the repository or release process.

## Exceptions

Exceptions to a MUST requirement require:

- documented owner;
- bounded scope;
- security rationale;
- compensating control;
- expiration date;
- approval record;
- test/evaluation evidence;
- audit trail.

No exception may authorize cross-tenant leakage, direct AI authoritative writes, or bypass of required human approval for high-consequence action.

## Review cadence

Policies should be reviewed when:

- model/agent/tool architecture changes;
- a new external processing mode is added;
- a new MCP/tool/RAG/memory capability is enabled;
- a material injection incident occurs;
- a relevant standard/taxonomy or attack class materially changes;
- at a regular security-governance cadence even without a triggering change.

## Runtime boundary

These policy definitions are not runtime controls until represented in versioned product policy/schema/code. Skill Pack text MUST NOT be used as a substitute for deterministic enforcement.