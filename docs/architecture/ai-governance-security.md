# AI Governance, Security, and Policy Enforcement

## Purpose

OpenAssetWatch should treat artificial intelligence as a controlled platform capability, not as a direct connection between a user prompt and a model. Models, agents, tools, evidence, and external processing must operate within a common governance and security framework.

This document defines a provider-neutral target architecture for controlling AI behavior across local, hybrid, and externally hosted deployments. It describes original OpenAssetWatch design requirements and does not reproduce any third-party product architecture, branding, terminology, or implementation.

## Core Principle

> Every AI request must be governed, scoped, validated, and audited before it reaches a model or tool.

AI must remain optional. Asset discovery, normalization, evidence storage, deterministic findings, and core risk analysis must continue to function when no model is configured.

## Position in the Architecture

```text
Users and OpenAssetWatch Services
                |
                v
        Typed AI Task Request
                |
                v
       AI Governance Policy Plane
                |
                v
   AI Security and Enforcement Gateway
                |
                v
       Model and Task Routing Layer
          |          |          |
          v          v          v
  Deterministic   Local AI   Approved External AI
                |
                v
       Isolated Agent Runtime
                |
                v
       Approved Tool Gateway
                |
                v
 OpenAssetWatch Evidence and Services
                |
                v
     Validation, Audit, and Telemetry
```

The governance plane determines what is allowed. The routing layer determines the minimum execution tier needed. The isolated agent runtime constrains tasks that require iterative reasoning or tool use. The Tool Gateway remains the only approved path to OpenAssetWatch services and evidence.

## Governance Policy Plane

The governance policy plane should provide one consistent source of truth for AI configuration and restrictions.

Policies should control:

- whether AI is enabled
- allowed deployment profiles
- allowed model providers and execution locations
- whether external processing is permitted
- data classifications allowed for each execution location
- redaction and minimization requirements
- task-specific token, cost, latency, and concurrency limits
- enabled agents and their allowed tools
- approval requirements
- prompt, response, and audit retention
- tenant-specific overrides
- model and agent version allowlists

Policy decisions must be deterministic, testable, and fail closed.

## Example Future Governance Policy

```yaml
ai_governance:
  enabled: true
  deployment_profile: balanced_hybrid

  execution:
    deterministic_enabled: true
    local_enabled: true
    external_enabled: false

  limits:
    max_input_tokens_per_request: 8000
    max_output_tokens_per_request: 2000
    max_concurrent_requests: 4
    daily_estimated_cost_usd: 5.00
    max_retries: 1
    max_execution_seconds: 60

  privacy:
    raw_inventory_external_processing: false
    redact_hostnames: true
    redact_usernames: true
    redact_internal_addresses: true
    redact_hardware_addresses: true

  agents:
    asset_advisor:
      enabled: true
      allowed_tools:
        - asset_read
        - finding_read
        - report_generate
      external_processing: false
```

The example is illustrative. Production policy should use versioned schemas, explicit defaults, validation, and migration support.

## Security Layers

### Request security

Before routing, OpenAssetWatch should verify:

- authenticated user or system identity
- tenant scope
- permitted task type
- valid evidence references
- data sensitivity classification
- requested autonomy level
- token, cost, and latency budgets
- required approval state

Unclassified free-form requests should not bypass the typed request contract.

### Input and prompt security

Prompt and evidence content must be treated as untrusted input.

Controls should include:

- prompt-injection detection and containment
- secret and credential scanning
- sensitive-data redaction
- evidence minimization
- source labeling and trust metadata
- bounded context assembly
- removal of executable instructions from untrusted evidence where practical
- explicit separation of system policy, user intent, and evidence content

A model must not be allowed to reinterpret evidence text as authorization to change policy, call tools, access another tenant, or reveal restricted data.

### Model security

Model security controls should include:

- approved model and version registry
- capability metadata
- structured output requirements
- response-size limits
- unsupported-claim detection where practical
- evidence-reference validation
- safety classification of outputs
- health, timeout, and failure handling
- reproducible evaluation before production enablement

Model confidence must never replace evidence quality.

### Agent security

Agent security is separate from model security because agents may plan, loop, retain state, and request tools.

Controls should include:

- unique agent identity
- task-scoped authorization
- explicit tool allowlists
- read-only defaults
- bounded iteration count
- execution time and resource limits
- restricted network egress
- no direct database credentials
- no direct collector control
- no host filesystem access by default
- temporary workspaces
- request-scoped memory
- complete tool-call audit records

Agents must not receive broad application credentials. They should use narrowly scoped, short-lived service authorization through the Tool Gateway.

## Isolated Agent Runtime

Simple text generation does not always require a sandbox. Isolation is required when an AI task can:

- call one or more tools
- perform multi-step investigation
- execute generated code in an approved future workflow
- maintain temporary state
- interact with external services
- request an action that could affect systems or users

The isolated runtime should enforce:

- ephemeral execution environments
- CPU, memory, storage, and time limits
- no arbitrary shell by default
- no unrestricted outbound network access
- no direct access to host services
- no direct access to secrets
- Tool Gateway access only
- per-request tenant identity
- automatic cleanup
- auditable start, stop, and failure events

### Execution modes

OpenAssetWatch should distinguish among:

1. **Model-only task** — bounded generation using approved evidence; no tools.
2. **Read-only agent task** — isolated agent with approved evidence and read-only tools.
3. **Human-approved action task** — isolated agent plus an explicit approval workflow and tightly scoped action tool.
4. **Disallowed task** — outside project policy, capability, or safety boundaries.

## Tool Enforcement

Models and agents must not call backend APIs or integrations directly.

```text
Model or Agent
      |
      v
Approved Tool Request
      |
      v
Tool Gateway
      |
      +-- identity check
      +-- tenant check
      +-- policy check
      +-- capability check
      +-- input validation
      +-- approval check
      +-- rate limit
      +-- audit record
      |
      v
Tenant-Scoped Service Call
```

Native model tool-calling features may be used only as a request format. They must not bypass the OpenAssetWatch Tool Gateway.

## Token and Resource Enforcement

Token limits belong in the enforcement layer, not only in provider configuration.

Each task type should define:

- maximum input tokens
- maximum output tokens
- maximum evidence records
- maximum context age
- maximum estimated cost
- maximum retries
- maximum execution time
- maximum concurrent executions

Example:

```yaml
ai_task_limits:
  asset_summary:
    max_input_tokens: 4000
    max_output_tokens: 800
    max_evidence_records: 25
    max_estimated_cost_usd: 0.01

  executive_report:
    max_input_tokens: 24000
    max_output_tokens: 4000
    max_evidence_records: 250
    max_estimated_cost_usd: 0.25
```

Requests that exceed policy should be reduced safely, divided into approved subtasks, sent for human review, or denied. The system must not silently truncate evidence in a way that changes the conclusion.

## Data Classification and External Processing

Suggested sensitivity classes:

- `public`
- `internal`
- `confidential`
- `restricted`

Policy should determine which classes may be processed locally or externally. External processing should be disabled by default for privacy-focused deployments.

Before an approved external call, OpenAssetWatch should:

- minimize the evidence set
- replace internal identifiers with request-scoped aliases
- remove secrets and credentials
- redact unnecessary names and addresses
- prevent cross-tenant mixing
- record which transformations occurred
- retain a local mapping for safe result association

A failed redaction or classification check must fail closed.

## Human Approval

Human approval should be required when:

- a task requests a system-changing action
- policy considers the data or outcome high impact
- the output could trigger significant operational decisions
- the estimated cost exceeds a configured threshold
- evidence conflicts materially
- repeated validation failures occur
- a new tool, model, or agent capability is being introduced

Approval must be explicit, scoped, time-bound where practical, and recorded with the approving identity and affected resources.

## Provider and Hardware Neutrality

The architecture must be based on capabilities, not vendor names.

A provider or runtime should declare:

- local or external execution
- supported task types
- structured-output support
- tool-request support
- streaming support
- context limits
- health status
- latency characteristics
- configured cost rates
- supported sensitivity classes
- hardware requirements
- model version or digest

OpenAssetWatch should support CPU, GPU, accelerator, or remote inference where available without making any particular hardware platform mandatory.

## Security Events and Audit

Security-relevant events should include:

- policy allow or deny
- redaction success or failure
- provider selection
- model or agent version
- tool request and outcome
- approval request and decision
- sandbox start and stop
- timeout or resource-limit event
- output validation failure
- tenant-scope violation attempt
- secret-detection event
- fallback or escalation

Sensitive prompt content should not be logged by default. Audit records should retain metadata, hashes, evidence references, and policy decisions needed for review.

## Phased Implementation

### Phase 1: Policy foundation

- define versioned governance policy schema
- define task and sensitivity classifications
- enforce typed AI requests
- add fail-closed policy decisions
- audit configuration and policy changes

### Phase 2: Input and output controls

- implement minimization and redaction
- add secret scanning
- add structured output validation
- validate evidence references and tenant scope

### Phase 3: Agent isolation

- introduce an ephemeral runtime for read-only agents
- restrict network and filesystem access
- issue short-lived Tool Gateway authorization
- enforce time and resource limits

### Phase 4: Approval and controlled actions

- add human approval records
- add narrowly scoped action tools
- add rollback and stop conditions
- preserve read-only defaults

## Acceptance Criteria

The governance and enforcement layer should not be considered production-capable until:

- every AI request has tenant, task, sensitivity, and actor context
- policy decisions are deterministic and tested
- external processing is disabled by default
- redaction failures deny external processing
- agents cannot call services outside the Tool Gateway
- agent execution is bounded and isolated
- tool credentials are short-lived and narrowly scoped
- every action-capable workflow requires explicit approval
- policy, model, agent, and tool decisions are auditable
- no particular model, provider, runtime, or hardware vendor is required

## Relationship to Other Documents

- `docs/architecture/ai-advisor.md` defines the overall Advisor role.
- `docs/architecture/ai-model-routing.md` defines execution-tier selection.
- `docs/architecture/ai-agent-architecture.md` defines evidence, specialist agents, memory, and Tool Gateway direction.
- `docs/architecture/ai-observability-operations.md` defines operational telemetry and dashboard requirements.
