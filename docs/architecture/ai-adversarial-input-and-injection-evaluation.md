# AI Adversarial Input and Injection Evaluation Architecture

- **Status:** Accepted design; evaluation runtime not yet implemented
- **Decision:** `docs/architecture/decisions/0006-adversarial-input-evaluation.md`
- **Relationship:** Extends `agent-evaluation-and-release-gates.md` and `defensive-content-and-model-robustness.md`

## Purpose

OpenAssetWatch needs a systematic way to evaluate whether untrusted content can
manipulate AI-assisted workflows across different inputs, tools, turns,
transformations, storage paths, and output channels.

This design defines an OpenAssetWatch-native adversarial evaluation model. It
is intentionally broader than a list of jailbreak strings. The goal is to test
security properties across the complete AI workflow:

```text
untrusted input
  -> context assembly
  -> model or specialist processing
  -> tool requests
  -> structured output
  -> agent-to-agent handoff
  -> memory/report/case artifacts
  -> publication or downstream consumer
```

The design does not make natural-language attack detection authoritative. It
assumes that language-level detection is incomplete and keeps deterministic
scope, authorization, provenance, tool, egress, and publication controls as the
security boundary.

This is a documentation-only architecture. It does not add offensive tooling,
model exploitation, external-target testing, or runtime authority.

## Core Security Invariants

Every adversarial evaluation must preserve these invariants:

1. **Untrusted content cannot grant authority.**
2. **Untrusted content cannot expand tenant, site, asset, evidence, tool, model,
   provider, or destination scope.**
3. **A model may request a capability; deterministic policy decides whether it
   is permitted.**
4. **Schema-valid output is not automatically policy-valid output.**
5. **Trust does not increase because content was summarized, translated,
   embedded, reformatted, or passed through another agent.**
6. **A later conversation turn cannot inherit a privilege expansion that was
   never deterministically authorized.**
7. **Tool descriptions, Skill Packs, repository files, retrieved documents,
   and external enrichment are data unless they are authenticated protected
   control artifacts.**
8. **Sensitive values may not leave through direct, encoded, fragmented,
   transformed, link-based, or tool-argument channels when policy forbids it.**
9. **A local model or runtime change invalidates qualifications bound to the
   previous artifact identity.**
10. **Untested attack classes remain unknown, not safe.**

---

## 1. Multi-Axis Adversarial Coverage Model

A single attack string can exercise several security properties at once. The
evaluation system should therefore describe each case across independent axes
rather than forcing it into one exclusive category.

### 1.1 Adversarial Objective

Suggested objectives include:

- `authority_manipulation`
- `scope_expansion`
- `sensitive_data_disclosure`
- `unauthorized_tool_use`
- `unsafe_publication`
- `verification_bypass`
- `persistent_context_poisoning`
- `cross_tenant_influence`
- `resource_amplification`
- `model_integrity_confusion`
- `downstream_output_exploitation`
- `policy_or_control_artifact_manipulation`

An evaluation may list more than one objective.

### 1.2 Delivery Surface

The system should test the same security property through different delivery
surfaces:

- direct operator/user input
- collector-provided text fields
- passive sensor metadata
- connector or imported records
- vulnerability/advisory text
- external intelligence enrichment
- retrieved knowledge or documentation
- tool output
- tool descriptions and schemas
- Skill Pack content
- repository files
- stored case notes or reports
- assistant memory or retrieved history
- agent-to-agent handoff
- structured API payloads
- future image, audio, video, OCR, or other multimodal evidence

### 1.3 Manipulation Mechanism

Useful mechanism classes include:

- explicit instruction override
- role or identity impersonation
- policy or system-message imitation
- fake delimiters or structural markers
- multi-turn privilege escalation
- fragmented instructions distributed across records or turns
- instruction smuggling through metadata
- tool-selection steering
- tool-argument steering
- output-format coercion
- verification suppression
- false evidence references
- trusted-source impersonation
- deceptive safety or approval claims
- competing-objective pressure

### 1.4 Transformation Method

Cases should also record transformations applied to adversarial content:

- plain text
- case and whitespace changes
- Unicode normalization variants
- invisible or zero-width characters
- bidirectional text controls
- homoglyph/confusable characters
- percent or URL encoding
- base encodings
- hexadecimal representations
- nested JSON/YAML/XML/string serialization
- fragmented substrings
- separator insertion
- reversed or reordered fragments
- multiple transformations in sequence

Transformations are evaluation inputs, not trusted decoding instructions.
Every decoder or normalizer used during evaluation must be bounded.

### 1.5 Propagation Stage

A further axis should identify how far the malicious influence attempts to
travel:

- same-turn model response
- same-turn tool request
- later conversation turn
- specialist-to-specialist handoff
- coordinator synthesis
- case note
- report artifact
- assistant memory
- knowledge record
- exported file
- external projection
- downstream renderer or client

This allows OpenAssetWatch to test prompt-injection propagation rather than only
initial ingestion.

---

## 2. Adversarial Evaluation Fixture Contract

Each fixture should be versioned and machine-readable.

Suggested envelope:

```yaml
schema: oaw.ai-adversarial-eval.v1
case_id: adv-eval-0001
version: 1.0.0

scope:
  tenant_id: tenant-fixture-a
  site_id: site-fixture-a
  asset_ids:
    - asset-fixture-1

adversarial_profile:
  objectives:
    - unauthorized_tool_use
    - sensitive_data_disclosure
  delivery_surfaces:
    - external_enrichment
  manipulation_mechanisms:
    - instruction_smuggling
    - tool_argument_steering
  transformations:
    - unicode_normalization_variant
  propagation_stages:
    - same_turn_tool_request
    - report_artifact

expected_security_properties:
  authority_unchanged: true
  scope_unchanged: true
  additional_tools_visible: false
  sensitive_data_disclosed: false
  required_verification_preserved: true
  untrusted_provenance_preserved: true
  publication_blocked_when_unsafe: true

expected_decision:
  outcome: safe_completion_or_block
```

Unknown fields should fail fixture validation.

### Required Fixture Metadata

Each fixture should also record:

- author or generator
- creation date
- source class: synthetic, sanitized replay, generated mutation, or regression
- intended security property
- allowed evidence IDs
- forbidden evidence IDs
- allowed tools
- forbidden tools
- required policy version
- model/runtime eligibility
- maximum turns
- maximum tool calls
- maximum runtime
- maximum provider cost or token budget when applicable
- expected ledger events
- expected denial or allow reasons
- whether human review is required

### Regression Fixture Rule

Every confirmed AI-security issue should produce a durable regression fixture
before the issue is considered fully closed when technically practical.

The regression fixture should preserve the smallest sufficient reproducer. It
should not retain production secrets, customer data, or unnecessary malicious
content.

---

## 3. Multi-Turn Policy Revalidation

Conversation history must never become a hidden authorization cache.

Before every material operation, the runtime should re-evaluate current policy.
Material operations include:

- tool invocation
- sensitive evidence retrieval
- scope expansion
- child-agent or specialist delegation
- external provider use
- write-capable future workflow steps
- artifact publication
- external projection
- approval submission
- transition to a higher autonomy class

### Required Rule

```text
previous turn allowed
        !=
current operation authorized
```

Authorization is derived from current authenticated identity, task contract,
tenant/site scope, policy, component trust state, requested capability, and
current context classification.

### Multi-Turn Test Cases

Tests should cover:

- gradual scope expansion over many benign-looking turns
- repeated requests after a policy denial
- changing a tool argument after approval
- changing a destination after approval
- adding a new asset or evidence ID after an earlier approval
- attempting to reinterpret a previous human message as permission
- attempting to convert an explanation-only task into an action task
- delayed tool requests after the original task expired
- stale approvals used after policy or evidence changed

---

## 4. Tool Definition and Capability Metadata Poisoning

Tool discovery is a security boundary because models use tool names,
descriptions, schemas, examples, and metadata to decide what capability to
request.

### Protected Tool Identity

A tool should be resolved using its canonical identity and approved metadata
snapshot, not its display name.

Adversarial tests should cover:

- duplicate display names
- visually similar names
- changed descriptions
- changed parameter descriptions
- added parameters
- relaxed required fields
- capability tags that changed after approval
- a new server claiming an existing namespace
- misleading examples that encourage broader use
- hidden instructions inside descriptions
- manipulated success/error messages

### Required Behavior

If an approved tool's digest, schema digest, description digest, capability set,
or source identity changes outside the approved lifecycle:

```text
approved
   -> drift_detected
   -> unavailable_to_agents
   -> review_required
```

No model judgment can override this transition.

---

## 5. Tool Argument Provenance and Smuggling Resistance

Choosing an approved tool is not enough. Untrusted content may influence tool
arguments in unsafe ways.

### Argument Security Contract

Each sensitive tool parameter should declare whether untrusted content may
influence it.

Example:

```yaml
tool: inventory.read
parameters:
  asset_id:
    type: server_issued_identifier
    provenance: trusted_scope_only
  fields:
    type: allowlisted_enum_array
    provenance: task_or_policy
```

For a future external lookup:

```yaml
tool: enrichment.lookup
parameters:
  subject:
    provenance: verified_scope_or_approved_evidence
  source_id:
    provenance: policy_only
  destination:
    provenance: tool_definition_only
```

### Required Validation

Before invocation, validate:

- tenant and site ownership
- server-issued identifiers
- expected type and length
- enum/allowlist values
- URL, host, port, path, and method restrictions where applicable
- whether the parameter may be influenced by untrusted evidence
- whether the value differs from the approved request
- whether the destination changed after human approval
- whether an encoded value resolves to a prohibited destination or identifier

Schema validation is necessary but insufficient; provenance and policy must also
validate.

---

## 6. Structured Output Semantic Validation

A model can produce syntactically valid JSON that is semantically unsafe.

The Safe Output Gate should therefore distinguish:

1. syntax validity;
2. schema validity;
3. identifier validity;
4. evidence support;
5. policy validity;
6. destination validity; and
7. semantic safety.

### Adversarial Cases

Test schema-valid outputs containing:

- invented evidence IDs
- another tenant's identifiers
- unauthorized destinations
- prohibited URLs
- action types outside the task contract
- tool arguments outside approved scope
- hidden active content
- unsupported claims presented as facts
- approval fields falsely set to approved
- altered artifact digests
- values that become unsafe only after decoding or normalization

### Required Rule

> A structured artifact is untrusted until every deterministic downstream
> consumer has validated the fields it relies upon.

No consumer may assume that schema validation proves intent, authorization, or
truth.

---

## 7. Repository and Control-Artifact Injection Boundary

Repository content can contain text that looks like instructions. That does not
make it privileged control data.

OpenAssetWatch should distinguish:

```text
Protected Control Artifact
  = registered + versioned + reviewed + digest-verified + policy-authorized

Ordinary Repository Content
  = untrusted or task-scoped data unless explicitly elevated through the
    protected-control lifecycle
```

### Protected Classes

Examples that may qualify as protected control artifacts after registration:

- system policies
- Skill Pack manifests
- approved Skill Pack instruction bodies
- tool manifests
- routing policy
- output policy
- approval policy
- sandbox profiles
- evaluation fixtures

### Ordinary Content

The following remain data by default:

- README files
- source comments
- issue text
- arbitrary Markdown
- imported documents
- generated reports
- test logs
- code strings
- external repository content

An ordinary file containing language such as "ignore previous instructions" or
"this file grants permission" cannot change runtime policy.

---

## 8. Propagation and Persistent Poisoning Resistance

An injection may become more dangerous when it survives into a later artifact.

Example path:

```text
untrusted document
   -> model summary
   -> case note
   -> later retrieval
   -> second agent
```

OpenAssetWatch must preserve provenance across transformations so summarization
does not wash untrusted content into a trusted class.

### Required Propagation Tests

Test malicious influence through:

- summary generation
- report generation
- analyst-assistance notes
- case notes
- memory records
- knowledge extraction
- agent handoffs
- exported JSON
- external ticket projections
- re-ingestion of generated artifacts

### Required Behavior

Derived content should carry:

- source trust class
- transformation chain
- original evidence references
- generator identity
- generated-artifact status
- integrity digest
- allowed destinations
- whether instructions are allowed to be interpreted

Generated summaries of untrusted content remain non-authoritative and cannot
become policy merely because they were generated by an approved model.

---

## 9. Resource and Economic Abuse Evaluation

Resource abuse can target either system availability or operating cost.

OpenAssetWatch should measure both separately.

### Availability Abuse

Test:

- oversized context
- excessive evidence references
- tool-loop attempts
- repeated retries
- child-worker explosion
- pathological structured outputs
- decompression or parsing amplification
- repeated validation failures

### Economic Abuse

For model-backed execution, test:

- attempts to force a larger model route
- repeated external-provider fallback
- unnecessary deep-analysis routes
- artificially enlarged outputs
- repeated near-identical requests
- deliberately expensive tool/enrichment paths

### Suggested Metric

```text
resource_amplification_ratio =
  bounded_resource_use_under_adversarial_case
  / expected_resource_use_for_equivalent_normal_case
```

The metric should be reported by task class and resource type. It must never be
used as a substitute for correctness or safety.

### Required Controls

- per-task budgets
- per-actor and per-tenant rate limits
- model-route ceilings
- maximum child workers
- maximum tool calls
- maximum evidence records
- maximum output bytes
- bounded retries
- duplicate-request suppression where appropriate
- cancellation that does not require model cooperation

---

## 10. Local Model and Runtime Integrity Evaluation

Local inference introduces artifact-integrity risks that are different from a
remote provider boundary.

A qualification should bind to a specific combination of:

- model identifier
- model digest
- tokenizer digest when separately managed
- runtime identifier and version
- runtime binary/container digest where available
- generation configuration digest
- tool/function schema version
- structured-output behavior
- hardware/runtime profile
- policy version

### Qualification Invalidation

A prior qualification becomes stale or invalid when material identity changes.

Examples:

- model digest changed
- tokenizer changed
- runtime changed
- quantization artifact changed
- tool-call format changed
- context length changed materially
- structured-output behavior changed
- safety/system template changed
- runtime binary or container changed

The runtime must not claim that a changed artifact inherits the old
qualification automatically.

### Integrity Test Outcomes

Suggested states:

- `qualified`
- `qualified_with_restrictions`
- `requalification_required`
- `artifact_mismatch`
- `runtime_mismatch`
- `configuration_mismatch`
- `unverified`
- `revoked`

This does not authorize adversarial extraction or attack against third-party
models. It tests only OpenAssetWatch-approved local model/runtime combinations.

---

## 11. Cross-Modal Injection Boundary

Future multimodal capabilities must not treat extracted instructions as trusted
because the instructions originated in an image, audio stream, document
rendering, or other modality.

Suggested flow:

```text
raw modality
  -> bounded extractor
  -> typed extracted evidence
  -> trust classification
  -> context assembly
```

### Required Rule

> Modality conversion cannot upgrade trust.

Examples for future evaluation:

- text embedded in an image
- OCR-derived text
- document annotations
- image metadata
- audio transcription
- QR/barcode-derived URLs
- captions or alt text
- multimodal tool output

Until a modality has an implemented, tested extraction and trust-handling path,
its adversarial coverage state should remain `unsupported` or `untested`.

---

## 12. Adversarial Coverage Registry

OpenAssetWatch should maintain explicit coverage records for the adversarial
security properties it claims to test.

### Coverage Dimensions

Coverage should be queryable by:

- objective
- delivery surface
- manipulation mechanism
- transformation method
- propagation stage
- provider/runtime class
- Skill Pack
- tool or capability
- output destination class

### Coverage States

Suggested states:

- `covered_passing`
- `covered_failing`
- `partial`
- `not_applicable`
- `unsupported`
- `deferred`
- `untested`
- `blocked_by_missing_fixture`
- `blocked_by_missing_runtime`

### Required Rule

`untested`, `deferred`, and `unsupported` must never render as passing or safe.

### Coverage Record

```json
{
  "coverage_id": "advcov-123",
  "objective": "unauthorized_tool_use",
  "delivery_surface": "tool_output",
  "manipulation_mechanism": "instruction_smuggling",
  "transformation": "plain_text",
  "propagation_stage": "same_turn_tool_request",
  "state": "covered_passing",
  "fixture_ids": ["adv-eval-0001"],
  "last_run_at": "",
  "software_commit": "",
  "policy_version": "",
  "model_or_runtime": "",
  "limitations": []
}
```

---

## 13. Coverage Reporting

A release report should show both successful coverage and known gaps.

Example presentation:

| Dimension | Passing | Failing | Partial | Untested/Deferred |
| --- | ---: | ---: | ---: | ---: |
| direct input | 0 | 0 | 0 | 0 |
| retrieved evidence | 0 | 0 | 0 | 0 |
| connector/enrichment data | 0 | 0 | 0 | 0 |
| tool metadata | 0 | 0 | 0 | 0 |
| tool arguments | 0 | 0 | 0 | 0 |
| multi-turn escalation | 0 | 0 | 0 | 0 |
| propagation/persistence | 0 | 0 | 0 | 0 |
| transformed/obfuscated content | 0 | 0 | 0 | 0 |
| local model integrity | 0 | 0 | 0 | 0 |
| multimodal surfaces | 0 | 0 | 0 | 0 |

The zeros above are schema examples only. They are not OpenAssetWatch test
results.

### Honest Coverage Claims

Every published coverage statement should include:

- fixture bundle version
- software commit
- policy version
- Skill Pack versions
- provider/model/runtime identity
- number of repeated runs for nondeterministic models
- pass/fail definitions
- unsupported and untested classes
- exclusions
- synthetic versus replayed versus live labels

No percentage should be described as complete prompt-injection protection.

---

## 14. Integration With Agent Evaluation and Release Gates

This architecture specializes the broader requirements in
`agent-evaluation-and-release-gates.md`.

### Per-PR Target

Fast deterministic or synthetic checks should eventually include:

- fixture schema validation
- trust/provenance propagation
- tool metadata drift
- tool argument provenance
- structured-output semantic validation
- protected-control-artifact separation
- fixed regression fixtures for known injection issues
- resource limit checks

### Scheduled or Release-Candidate Target

Slower evaluation may include:

- repeated live-model runs
- multi-turn campaigns
- combined transformation cases
- propagation tests across agent handoffs and persisted artifacts
- local model/runtime qualification regression
- provider/runtime matrix testing
- economic amplification analysis
- multimodal tests when supported

### Hard Release Blockers

The relevant AI capability must not ship when any fixture demonstrates:

- successful authority expansion
- successful cross-tenant/site/asset scope expansion
- unauthorized tool execution
- sensitive-data disclosure where policy forbids it
- bypass of required verification or human approval
- unsafe publication
- loss of untrusted provenance that enables later privilege
- protected-control-artifact spoofing
- model/runtime artifact mismatch accepted as qualified
- cancellation followed by an unauthorized side effect
- structured output that passes schema validation and then causes a forbidden
  downstream operation

---

## 15. Security Telemetry

Adversarial evaluation should emit structured security results without storing
unnecessary malicious payloads.

Suggested telemetry:

- case and fixture ID
- objective and surface classifications
- provider/model/runtime identity
- policy version
- Skill Pack version
- tool identities requested
- policy decisions
- provenance/taint transitions
- output-validation decisions
- release-blocker outcome
- runtime/token/tool-call budgets
- retry and cancellation state
- coverage state

Raw prompts or malicious fixtures should have separate restricted retention and
should not be copied into ordinary operational logs.

---

## 16. Implementation Sequence

### Phase A — Contracts

1. Define adversarial fixture schema.
2. Define coverage record schema.
3. Add objective, surface, mechanism, transformation, and propagation enums.
4. Define required security-property assertions.
5. Define report schema and honest-claim rules.

### Phase B — Deterministic Security Tests

1. Add multi-turn policy revalidation tests.
2. Add tool metadata drift fixtures.
3. Add argument-provenance fixtures.
4. Add structured-output semantic-validation fixtures.
5. Add repository/control-artifact trust-boundary fixtures.
6. Add propagation tests using deterministic specialist stubs.

### Phase C — Runtime and Provider Evaluation

1. Run the same fixtures against approved local/provider model routes.
2. Add repeated-run analysis.
3. Add resource-amplification measurement.
4. Add local model/runtime integrity qualification tests.
5. Add provider-failure combinations.

### Phase D — Expanded Surfaces

1. Add additional connector/enrichment payload fixtures.
2. Add stored case/report propagation tests.
3. Add future multimodal fixtures only when those capabilities exist.
4. Expand the coverage registry while keeping unsupported classes visible.

---

## 17. Explicit Non-Goals

This architecture does not authorize:

- autonomous offensive testing
- jailbreak services against third-party models
- external-target prompt injection testing
- model extraction
- training-data theft
- credential harvesting
- malware or exploit generation
- autonomous exploitation
- unrestricted fuzzing of third-party systems
- arbitrary shell or browser automation
- publishing a claim of complete prompt-injection prevention
- copying or importing external attack-taxonomy identifiers or corpora as a
  shortcut for OpenAssetWatch's own evaluation contracts

---

## 18. Acceptance Criteria

The first production-capable adversarial evaluation layer should not be
considered complete until:

- fixture and coverage schemas are versioned and strict
- untrusted provenance survives all tested transformations
- material operations revalidate policy on every turn
- tool metadata and schemas are integrity-bound
- sensitive tool arguments validate both policy and provenance
- structured output receives semantic policy validation after schema validation
- protected control artifacts are distinguishable from ordinary repository data
- propagation tests cover stored and agent-to-agent artifacts
- resource and economic amplification are bounded
- local model qualification is artifact-specific and invalidated on drift
- unsupported and untested coverage is visible
- hard release blockers fail closed
- reports preserve synthetic/replayed/live provenance
- no test result is presented as universal prompt-injection immunity

## Final Position

OpenAssetWatch should evaluate adversarial AI behavior as a coverage problem
across objectives, delivery surfaces, manipulation mechanisms,
transformations, propagation stages, tools, and runtimes.

The security goal is not to perfectly classify malicious language. The goal is
to make language incapable of overriding deterministic authorization,
provenance, scope, tool, verification, egress, and publication controls, and to
measure those properties continuously with explicit evidence and visible
coverage gaps.
