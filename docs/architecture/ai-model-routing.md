# AI Model Routing and Execution Policy

## Purpose

OpenAssetWatch should not treat every AI request as requiring the same model or
execution environment. Asset classification, collector-health summaries,
complex risk analysis, and executive reporting have different requirements for
cost, latency, privacy, evidence quality, and reasoning depth.

The AI Model Routing and Execution Policy defines how OpenAssetWatch selects the
least expensive and least invasive execution path that can safely complete a
request. The routing layer sits beneath the AI Advisor and above deterministic
rules, local model runtimes, optional external model providers, and future human
review workflows.

The design follows one core principle:

> Use the minimum level of AI required for the task, and do not use an LLM when
> deterministic logic or an insufficient-evidence response is more appropriate.

This document describes the target architecture. It does not claim measured
cost savings, latency improvements, or model quality until OpenAssetWatch has
implemented and benchmarked the design with reproducible tests.

## Design Goals

The routing layer should:

- preserve deterministic rules as the source of truth for repeatable findings
- prefer local processing for routine and privacy-sensitive work
- use external frontier models only when policy permits and the task requires it
- refuse to invent conclusions when evidence is incomplete
- make provider selection explicit, configurable, and auditable
- support offline and air-gapped deployments
- track latency, token use, estimated cost, fallbacks, and validation outcomes
- remain provider-neutral so models can change without redesigning the Advisor

## Position in the Architecture

```text
Collectors and Sensors
        |
        v
Normalization, Enrichment, and Deterministic Risk Rules
        |
        v
AI Advisor Task Request
        |
        v
AI Model Router and Execution Policy
        |-- Deterministic code or templates
        |-- Local lightweight model
        |-- Local advanced model
        |-- Optional external frontier model
        |-- Human review
        `-- Insufficient-evidence response
        |
        v
Validated, Evidence-Linked Advisor Output
        |
        v
Audit, Usage, Cost, and Quality Telemetry
```

The router does not replace the AI Advisor orchestrator, specialist agents,
evidence layer, or tool gateway. It decides how an approved advisory task should
be executed after evidence and policy context have been assembled.

## Execution Tiers

OpenAssetWatch should define capability tiers rather than hard-code the
architecture around specific model names.

### Tier 0: Deterministic execution

Use code, rules, lookups, templates, and schema validation when the task does not
require generative reasoning.

Appropriate work includes:

- risk-score calculation
- known device and vendor mappings
- duplicate and stale-asset detection
- evidence completeness checks
- policy evaluation
- security-tool coverage checks
- structured report assembly where prose generation is unnecessary

Tier 0 should be preferred whenever it can produce a complete and reliable
answer.

### Tier 1: Local lightweight model

Use a small local model for bounded tasks with clear evidence and limited
reasoning depth.

Appropriate work may include:

- short asset summaries
- device-category suggestions from normalized evidence
- collector-health explanations
- plain-language descriptions of deterministic findings
- label cleanup and structured classification
- simple remediation guidance based on approved templates

The response must still pass schema, evidence-reference, and safety validation.

### Tier 2: Local advanced model

Use a more capable local model for tasks requiring longer context, correlation,
or more detailed reasoning.

Appropriate work may include:

- multi-asset correlation
- segmentation recommendations
- environment-level posture summaries
- technical remediation reports
- analysis of conflicting but sufficiently complete evidence
- longer executive or operational reports

Tier 2 may run on the primary OpenAssetWatch server or on a dedicated local AI
host with sufficient CPU, memory, or GPU resources.

### Tier 3: Optional external frontier model

Use an external high-capability model only when all of the following are true:

- the task requires reasoning that lower tiers could not complete acceptably
- cloud processing is permitted by deployment and tenant policy
- required redaction or minimization has completed successfully
- evidence is sufficiently complete to support a grounded conclusion
- cost and latency budgets permit escalation
- the request is auditable and associated with a known user, tenant, or system
  workflow

External model use should be disabled by default for privacy-focused
deployments.

### Human review

The router should select human review when:

- evidence conflicts materially
- the requested conclusion could cause significant business or security impact
- model outputs repeatedly fail validation
- policy requires approval for a particular report or recommendation
- the task exceeds configured cost, sensitivity, or autonomy limits

Human review is a valid routing result, not a system failure.

### Insufficient evidence

The router must not escalate merely because evidence is missing. A more capable
model cannot turn absent evidence into a reliable finding.

When the minimum evidence set is not available, the correct result is an
explicit insufficient-evidence response that identifies:

- what is known
- what is missing
- why a conclusion cannot be made safely
- what low-risk evidence could improve confidence

## AI Task Request Contract

Every routed request should use a structured contract rather than sending an
unclassified free-form prompt directly to a provider.

Suggested fields:

- `request_id`
- `tenant_id`
- `user_id` or `system_actor`
- `task_type`
- `asset_ids`
- `evidence_refs`
- `evidence_completeness`
- `sensitivity`
- `complexity`
- `required_confidence`
- `allow_cloud`
- `redaction_required`
- `max_latency_ms`
- `max_estimated_cost_usd`
- `preferred_tier`
- `fallback_tiers`
- `output_schema`
- `created_at`

Example:

```json
{
  "request_id": "ai-request-123",
  "tenant_id": "tenant-home-lab",
  "system_actor": "ai_advisor",
  "task_type": "asset_explanation",
  "asset_ids": ["asset-123"],
  "evidence_refs": [
    "assets/asset-123",
    "network_observations/456",
    "findings/finding-789"
  ],
  "evidence_completeness": "sufficient",
  "sensitivity": "internal",
  "complexity": "low",
  "required_confidence": 0.8,
  "allow_cloud": false,
  "redaction_required": true,
  "max_latency_ms": 5000,
  "max_estimated_cost_usd": 0.01,
  "preferred_tier": "local_lightweight",
  "fallback_tiers": ["local_advanced"],
  "output_schema": "ai_finding_v1",
  "created_at": "2026-07-23T00:00:00Z"
}
```

## Routing Inputs

The router should evaluate at least the following inputs.

### Task type

Examples include:

- `device_classification`
- `asset_explanation`
- `collector_health_summary`
- `risk_explanation`
- `segmentation_recommendation`
- `environment_summary`
- `technical_report`
- `executive_report`
- `splunk_search_suggestion`

Each task type should declare an allowed set of tiers, minimum evidence, output
schema, and escalation policy.

### Evidence quality

Routing decisions must consider:

- completeness
- freshness
- source diversity
- confidence of upstream detections
- whether evidence is direct or inferred
- whether records conflict

Evidence quality must influence finding confidence independently from model
confidence.

### Data sensitivity

Sensitivity may include:

- `public`
- `internal`
- `confidential`
- `restricted`

Sensitive fields such as hostnames, usernames, internal IP addresses, MAC
addresses, network relationships, and installed software may be restricted to
local processing or replaced with stable aliases before external processing.

### Complexity

Complexity should be determined from measurable request characteristics where
possible, such as:

- number of assets and evidence records
- number of conflicting observations
- requested output length
- number of analytical steps
- required framework mappings
- whether cross-asset correlation is needed

### Resource availability

The router should account for:

- available local model runtimes
- model health and queue depth
- CPU, memory, and GPU capacity
- internet availability
- provider rate limits
- configured latency budgets

### Policy and cost limits

Tenant and deployment policy should be able to override routing preferences.
Examples include local-only mode, cloud prohibition, per-request cost limits,
monthly budgets, and approved provider allowlists.

## Example Task-to-Tier Guidance

| OpenAssetWatch task | Preferred route | Possible fallback |
| --- | --- | --- |
| Calculate deterministic risk score | Tier 0 | None |
| Identify a known vendor from a MAC prefix | Tier 0 | Tier 1 for explanation |
| Summarize collector health | Tier 0 or Tier 1 | Tier 2 |
| Explain a deterministic finding | Tier 1 | Tier 2 |
| Suggest a device category from strong evidence | Tier 1 | Tier 2 |
| Correlate several assets with conflicting evidence | Tier 2 | Tier 3 or human review |
| Recommend segmentation across an environment | Tier 2 | Tier 3 or human review |
| Generate a detailed executive risk report | Tier 2 | Tier 3 |
| Analyze a high-risk asset with incomplete evidence | Insufficient evidence | Human review |

## Escalation and Fallback

Escalation should be policy-driven and bounded.

A lower tier may escalate when:

- output does not match the required schema
- required evidence references are missing
- a deterministic validator rejects the answer
- confidence is below the task threshold
- the model explicitly reports that the task exceeds its capability
- the request times out and an approved fallback remains available

Escalation must not occur when:

- cloud use is prohibited
- evidence is insufficient
- redaction fails
- the request exceeds its cost budget
- the next provider is unhealthy or not approved
- the task is outside the AI Advisor's advisory scope

Every escalation should record the original route, failure reason, selected
fallback, and final outcome.

## Privacy and Redaction Policy

Before any external provider call, OpenAssetWatch should apply data minimization
and redaction.

Possible controls include:

- replace asset identifiers with temporary aliases
- omit raw packet data and unrestricted logs
- remove secrets, tokens, credentials, and private keys
- mask usernames, hostnames, internal IP addresses, and MAC addresses when not
  required for the task
- send derived facts and evidence summaries instead of complete source records
- prevent cross-tenant evidence from entering the same request
- retain a local mapping so external output can be safely re-associated with
  internal records

Example future policy:

```yaml
ai_policy:
  cloud_allowed: true
  redact_before_cloud: true
  never_send_raw_inventory_to_cloud: true
  local_only_fields:
    - hostname
    - username
    - internal_ip
    - mac_address
  frontier_minimum_complexity: high
  require_complete_evidence_for_frontier: true
```

## Provider Abstraction

The AI Advisor should interact with providers through a common adapter
interface. Provider-specific SDKs, request formats, and credentials should not
leak into task definitions or evidence schemas.

A provider adapter should expose metadata such as:

- provider ID
- deployment type: deterministic, local, or external
- supported task and output types
- context limit
- structured-output capability
- health status
- configured cost rates
- privacy classification
- timeout and retry policy
- model version or digest
- artifact manifest, provenance, advisory, and qualification-binding state for
  local generative models

Local runtimes may include Ollama, llama.cpp, vLLM, or another compatible
runtime. External providers remain optional integrations selected through
configuration and policy.

Runtime reachability is not model approval. When a local artifact manifest is
configured, the router may select that model only when complete immutable
lineage, an exact artifact/runtime qualification binding, and reviewed artifact
advisory evaluation all permit use. A compatibility declaration never grants
authorization. The provider-neutral contract is documented in
[`MODEL_ARTIFACT_PROVENANCE.md`](../MODEL_ARTIFACT_PROVENANCE.md).

## Output Validation

All routes must produce the same validated OpenAssetWatch output contract.
Validation should include:

- JSON or typed-schema validation
- evidence-reference validation
- tenant-scope validation
- severity and confidence validation
- secret and sensitive-data scanning
- unsupported-claim checks where practical
- separation of observed facts, inferences, and recommendations
- bounded response size

A provider response that fails validation must not be presented as a completed
finding without correction, fallback, or human review.

## Audit and Telemetry

Each routed request should generate an audit record containing:

- request and tenant identifiers
- task type
- selected tier and provider
- model name and version
- routing reasons
- evidence references used
- whether redaction occurred
- input and output token counts when available
- estimated cost
- queue time and response latency
- validation result
- fallback or escalation history
- final status
- user or system actor
- timestamps

Sensitive prompt content should not be copied into general application logs.
Where prompt retention is required for debugging, it should be explicitly
enabled, access-controlled, redacted, and time-limited.

## AI Usage and Routing Dashboard

A future Control Tower view should make AI behavior transparent. Useful metrics
include:

- requests by task type
- requests by execution tier
- local versus external processing percentage
- deterministic routes that avoided an LLM call
- average and percentile response latency
- token usage and estimated cost
- estimated cost avoided compared with a configured baseline
- provider failure and fallback counts
- requests blocked by privacy or policy
- insufficient-evidence outcomes
- output validation failures
- human-review referrals

Any claimed savings or performance improvement must be labeled as measured,
estimated, or synthetic and must include the comparison method.

## Deployment Profiles

### Private Local

- deterministic and local tiers only
- external providers disabled
- suitable for privacy-focused and air-gapped environments

### Balanced Hybrid

- deterministic and local tiers preferred
- external frontier tier available for approved complex tasks
- redaction, cost limits, and audit required

### Cloud Enhanced

- external models available more broadly
- local or deterministic processing still preferred for routine work
- tenant policy, minimization, and cost controls remain mandatory

## Example Future Configuration

```yaml
ai:
  enabled: true
  deployment_profile: balanced_hybrid
  default_route: local_lightweight

  tiers:
    deterministic:
      enabled: true

    local_lightweight:
      enabled: true
      provider: local_openai_compatible
      base_url: http://localhost:11434/v1
      model: configured-small-model

    local_advanced:
      enabled: false
      provider: local_openai_compatible
      base_url: http://ai-host:8000/v1
      model: configured-advanced-model

    frontier:
      enabled: false
      provider: configured_external_provider
      model: configured-frontier-model
      require_redaction: true

  routing:
    block_on_insufficient_evidence: true
    require_evidence_references: true
    require_human_review_above_cost_usd: 1.00

    tasks:
      device_classification:
        preferred: deterministic
        fallback: [local_lightweight]

      asset_summary:
        preferred: local_lightweight
        fallback: [local_advanced]

      risk_explanation:
        preferred: local_advanced
        fallback: [frontier, human_review]
        frontier_requires:
          - cloud_allowed
          - redaction_complete
          - evidence_complete

      executive_report:
        preferred: local_advanced
        fallback: [frontier]
```

## Security Requirements

- The router must enforce tenant isolation before provider selection.
- Provider credentials must remain in an approved secrets store.
- External providers must be explicitly enabled and allowlisted.
- Raw collector submissions must not be sent to an LLM by default.
- Tool execution remains governed by the AI Tool Gateway, not the model router.
- Model-generated instructions must not bypass approval or capability checks.
- Prompt and evidence inputs must be treated as untrusted content.
- Routing policies and provider configuration changes must be audited.
- A failed policy or redaction check must fail closed.
- Configured invalid or mismatched local model provenance must fail closed
  without hiding the runtime's separate availability state.
- Model output must never approve its own artifact, qualification, or advisory
  state.

## Phased Implementation

### Phase 1: Routing foundation

- define the AI task request schema
- define task types and execution tiers
- implement deterministic routing decisions
- record route selection and reasons
- add provider placeholders and routing tests
- add explicit insufficient-evidence outcomes

### Phase 2: One local and one optional external provider

- connect one local provider-compatible runtime
- connect one optional external provider
- implement provider health checks
- implement cloud permission and redaction policy
- add bounded timeout, retry, and fallback behavior

### Phase 3: Routing telemetry

- record latency, token use, estimated cost, and outcomes
- add an AI usage and routing view
- display local, external, deterministic, and blocked request proportions

### Phase 4: Quality-based escalation

- add structured-output and evidence validators
- compare output quality across tiers
- escalate only after a lower tier fails an approved acceptance test
- add reproducible routing benchmarks and regression gates

## Acceptance Criteria

The first production-capable router should not be considered complete until:

- every AI request has a typed task and tenant context
- deterministic execution can be selected without an LLM call
- local-only policy is enforced and tested
- external provider use is disabled by default
- insufficient evidence cannot trigger unsupported model speculation
- provider responses are validated against a common output schema
- route selection, redaction, cost, latency, and fallback are audited
- routing tests cover privacy, failure, cost, and escalation boundaries
- benchmark documentation clearly separates measured, estimated, and synthetic
  results

## Relationship to Other AI Documents

- `docs/architecture/ai-advisor.md` defines the overall AI Advisor deployment
  and provider direction.
- `docs/architecture/ai-agent-architecture.md` defines evidence, specialist
  agents, memory, tool safety, and the broader implementation roadmap.
- `docs/architecture/hub-spoke-ai-showcase.md` documents the implemented
  showcase foundation.

The model router complements these components by deciding which execution tier
should handle each approved advisory task.
