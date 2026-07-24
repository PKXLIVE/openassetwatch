# Defensive AI and Security Architecture Gap Backlog

## Purpose

This document records architecture patterns reviewed from several public AI-security and agent-security projects so OpenAssetWatch can preserve useful ideas for future implementation without expanding the current build scope.

The reviewed projects were:

- `0x4m4/hexstrike-ai`
- `Ed1s0nZ/CyberStrikeAI`
- `nolabs-ai/nono`
- `CyberSunil/LLMVault`
- `Fangcun-AI/SkillWard`

The goal is not to copy those systems or turn OpenAssetWatch into a penetration-testing framework. The goal is to identify defensive architecture gaps, document safe design directions, and define boundaries for future work.

## Decision Summary

OpenAssetWatch should preserve the following future design directions:

1. Evidence-based exposure-path analysis.
2. Replayable analysis and decision records.
3. Resumable and bounded tool execution.
4. Per-tool isolation and credential proxying.
5. Integration and MCP trust review.
6. AI security validation and adversarial testing.
7. Runtime guardrails for suspicious integrations.
8. Separate audit, execution-monitoring, and approval records.
9. Safer workflow graphs with deterministic joins and validation.
10. Strict rejection of exploit generation, credential theft, WebShell, C2, and arbitrary command capabilities.

These are future architecture items. They do not change the current passive-first, advisory-first, read-only-default project scope.

---

## 1. Exposure Path Analyzer

### Gap

OpenAssetWatch already plans to correlate assets, services, vulnerabilities, business context, identities, network observations, missing controls, and risk findings. The current architecture does not yet clearly define how these facts combine into a multi-step exposure path.

A single finding may not explain the full risk. The meaningful risk may exist in the relationship between several observed conditions.

Example:

```text
External Exposure
        |
        v
Router or Gateway
        |
        v
Outdated Management Service
        |
        v
Flat or Weakly Segmented Network
        |
        v
Unmanaged IoT Device
        |
        v
Sensitive Workstation or Service
```

### Proposed Component

Add a future **Exposure Path Analyzer** that builds defensive, evidence-backed paths across OpenAssetWatch records.

The component must remain advisory. It may identify a plausible route from exposure to impact, but it must not execute, validate through exploitation, or claim compromise without evidence.

### Suggested Node Types

- asset
- service
- vulnerability
- external exposure
- identity
- network segment
- software
- security control
- collector
- finding
- business service
- data classification

### Suggested Edge Types

- `hosts`
- `communicates_with`
- `reachable_from`
- `shares_segment_with`
- `affected_by`
- `lacks_control`
- `authenticated_by`
- `depends_on`
- `exposed_to`
- `owned_by`
- `observed_by`
- `inferred_reachability`

### Required Edge Metadata

Every relationship should include:

- edge identifier
- source node
- destination node
- relationship type
- observed or inferred status
- evidence references
- first seen
- last seen
- confidence
- tenant or deployment scope
- derivation method
- rule or model version
- stale status

### Suggested Path Output

```json
{
  "path_id": "exposure-path-001",
  "title": "External management exposure may provide a route to an unmanaged device",
  "status": "advisory",
  "confidence": "medium",
  "nodes": [
    "external-exposure-1",
    "asset-router-1",
    "service-admin-https",
    "segment-iot",
    "asset-camera-7"
  ],
  "edges": [
    "edge-1",
    "edge-2",
    "edge-3",
    "edge-4"
  ],
  "evidence_refs": [
    "observation-31",
    "finding-18",
    "asset-7"
  ],
  "uncertainties": [
    "No exploitability validation was performed",
    "Layer-3 reachability is inferred from available topology evidence"
  ],
  "recommended_control": "Restrict management access and isolate the IoT segment"
}
```

### Ranking Inputs

A future path score may consider:

- evidence quality
- external exposure
- known exploitation status from approved enrichment
- vulnerability severity
- asset criticality
- identity privilege
- network reachability confidence
- missing security controls
- path length
- stale evidence
- compensating controls
- business impact

The score must not be based only on model confidence.

### Control-Break Analysis

The analyzer should identify the smallest defensive changes that would interrupt the path, such as:

- remove public exposure
- restrict a management interface
- patch a vulnerable service
- isolate a network segment
- require MFA
- disable an unused account
- add endpoint security coverage
- remove an unnecessary trust relationship

This creates actionable defensive value without requiring offensive execution.

---

## 2. Analysis Replay and Provenance

### Gap

AI-generated conclusions are difficult to review when only the final answer is retained. OpenAssetWatch needs a replayable record showing how evidence became a recommendation, without storing private chain-of-thought.

### Proposed Component

Add a future **Analysis Replay Record** for important AI findings and exposure paths.

Example:

```text
1. Asset discovered by collector
2. Service observed
3. Vulnerability enrichment matched
4. Missing control identified
5. Reachability relationship inferred
6. Exposure path calculated
7. Recommendation generated
8. Evidence validation completed
```

### Replay Record Fields

- replay identifier
- task identifier
- requesting actor
- tenant or deployment scope
- model and agent identifiers
- rules and schema versions
- selected evidence references
- deterministic transformations
- inferred relationships
- validation results
- generated outputs
- approval events
- timestamps
- execution status
- reason for stop or failure

### Required Distinctions

The replay view must separate:

- observed fact
- imported enrichment
- deterministic rule result
- inferred relationship
- AI recommendation
- human decision

It should explain what happened without exposing hidden prompts or private deliberation.

---

## 3. Resumable and Bounded Tool Execution

### Gap

The current AI architecture defines budgets, retries, timeouts, and cancellation, but it should explicitly define how long-running tools continue without blocking one agent turn or flooding model context.

### Proposed Execution Model

```text
Agent requests tool
        |
        v
Execution Service creates execution record
        |
        v
Worker runs approved tool
        |
        +-- completes during bounded wait --> canonical result returned
        |
        `-- still running --> execution_id returned; worker continues
```

### Suggested Execution States

- queued
- preparing
- running
- background_running
- waiting_for_approval
- completed
- partial
- failed
- cancelled
- hard_timeout
- orphaned

### Control Operations

Future tool-control operations should include:

- get execution status
- wait for a bounded interval
- retrieve bounded partial output
- cancel execution
- retry when policy permits
- resume a paused workflow

### Output Governance

Every tool should have:

- maximum output bytes
- maximum model-facing bytes
- truncation indicator
- bounded head and tail preview
- optional artifact reference for the full result
- redaction before storage
- canonical normalized result

The same canonical result should be used by:

- the agent
- audit and monitoring views
- persistent execution records
- resumed workflows

This prevents a later continuation from seeing a different result than the original agent saw.

### Suggested Execution Result

```json
{
  "execution_id": "exec-123",
  "state": "partial",
  "tool": "vulnerability_enrichment",
  "result_truncated": true,
  "artifact_ref": "artifacts/exec-123/result.json",
  "output_bytes_seen": 10485760,
  "output_bytes_loaded": 262144,
  "retryable": true,
  "cancel_requested": false
}
```

### External Integration Resilience

External MCP servers and integrations should have:

- per-server concurrency limits
- global concurrency limits
- circuit breakers
- failure thresholds
- cooldown periods
- request timeouts
- hard execution timeouts
- stale-job reconciliation
- orphan detection
- health status

---

## 4. Per-Tool Isolation and Credential Proxying

### Gap

A general agent sandbox is not enough if every delegated tool inherits the same filesystem, network, and credential permissions.

### Proposed Architecture

```text
AI Agent Sandbox
        |
        v
Tool Broker
        |
        v
Per-Tool Child Sandbox
   |-- dedicated filesystem grants
   |-- dedicated network allowlist
   |-- dedicated credential scope
   |-- invocation restrictions
   |-- output limits
   `-- independent audit events
```

### Design Rule

The policy must live outside the prompt and outside the model's control. An agent may request a tool, but it must not be able to widen that tool's policy.

### Per-Tool Policy Fields

- tool name and version
- command or adapter identifier
- allowed caller roles
- read-only status
- filesystem read paths
- filesystem write paths
- network default policy
- allowed hosts
- allowed methods and paths
- credential references
- invocation argument rules
- environment variables
- timeout
- concurrency limit
- output limit
- audit level
- approval requirement

### Credential Proxy

Where possible, a tool should not receive the underlying reusable secret. A credential proxy should inject authentication only for approved destinations and operations.

Example:

```yaml
tool: vulnerability_lookup
network:
  default: deny
  allow:
    - method: GET
      host: approved-vulnerability-source
      path: /api/v1/vulnerabilities/*
credentials:
  direct_secret_access: false
  injected_by_proxy: true
filesystem:
  read: []
  write:
    - /tmp/openassetwatch-tool-output
```

### Required Principle

A reporting tool must not inherit the network rights of an enrichment tool. A GitHub integration must not inherit database access. An external assistant must not inherit collector credentials.

---

## 5. Integration Trust Gate

### Gap

The architecture requires tools and MCP integrations to be reviewed, but it does not yet define a complete onboarding and lifecycle process for third-party integrations, skills, plugins, model adapters, and external agent runtimes.

### Proposed Component

Add a future **Integration Trust Gate**.

```text
Integration Submitted
        |
        v
Manifest and Source Validation
        |
        v
Static Security Analysis
        |
        v
Semantic Intent Review
        |
        v
Declared-versus-Observed Capability Check
        |
        v
Optional Sandbox Verification
        |
        v
Human Approval
        |
        v
Approved Integration Registry
```

### Supported Future Targets

- MCP servers
- OpenClaw skills
- external assistant adapters
- AI agent skills
- model-provider adapters
- report plugins
- vulnerability enrichment adapters
- repository packages
- archives
- local source projects

### Static Review Checks

- source and license
- pinned version or commit
- checksums
- signature or provenance
- dependency inventory
- install and build scripts
- post-install behavior
- secret scanning
- obfuscation and encoded content
- hidden files
- dangerous command patterns
- prompt or tool-description poisoning
- environment-variable access
- filesystem access
- outbound network destinations
- remote code download
- persistence behavior
- privilege escalation behavior
- declared permissions versus implementation

### Semantic Review Checks

- stated purpose versus likely behavior
- hidden or misleading instructions
- deceptive tool descriptions
- credential collection intent
- unauthorized data transfer
- excessive permissions
- dangerous side effects
- policy bypass instructions

### Runtime Verification

Only suspicious or uncertain integrations should proceed to dynamic verification. The verification environment should use:

- isolated container or sandbox
- no production data
- no reusable credentials
- synthetic files
- decoy tokens and honeypot values
- restricted outbound network
- process monitoring
- filesystem monitoring
- environment access monitoring
- dependency-install monitoring
- timeout and resource limits

### Integration Lifecycle States

- unreviewed
- quarantined
- static_review_passed
- semantic_review_required
- sandbox_review_required
- approved
- approved_with_restrictions
- expired
- revoked
- rejected

### Review Result

A review should return:

- verdict
- confidence
- severity
- evidence
- affected files and lines
- observed behavior
- declared-versus-actual differences
- required restrictions
- remediation guidance
- approved version
- expiration or re-review date

A clean review means no relevant risk was found during the review. It must not be presented as a guarantee that an integration is risk-free.

---

## 6. Runtime Guard for External Skills and MCP

### Gap

Pre-deployment review cannot identify every behavior, especially when code downloads dependencies or constructs actions dynamically.

### Proposed Component

Add a future **Runtime Integration Guard** for experimental or higher-risk integrations.

The guard may observe:

- tool calls
- subprocess creation
- file writes
- sensitive path reads
- environment-variable reads
- network destinations
- credential access attempts
- persistence attempts
- dynamic downloads
- output containing prompt injection
- unexpected capability changes

### Guard Outcomes

- allow
- allow with redaction
- allow with restricted output
- require human approval
- block
- terminate integration
- quarantine integration version

The guard is a secondary control. It does not replace static review, authorization, per-tool policy, or sandboxing.

---

## 7. AI Security Validation Program

### Gap

OpenAssetWatch documents AI safety principles, but these principles should become repeatable security tests and release gates.

### Proposed Deliverable

Create a future **AI Security Test Matrix** and connect it to the planned Agent Evaluation Harness.

### Required Test Categories

| Category | OpenAssetWatch validation scenario |
| --- | --- |
| Direct prompt injection | User text attempts to override system and tenant policy |
| Indirect prompt injection | Asset metadata or enrichment contains malicious instructions |
| Stored injection | Previously stored notes attempt to control a later agent run |
| Sensitive information disclosure | Model is asked for tokens, prompts, secrets, or hidden records |
| Prompt leakage | Model is asked to reveal protected system instructions |
| Cross-tenant retrieval | One tenant attempts to retrieve another tenant's evidence |
| Excessive agency | Agent requests a tool or action beyond its role |
| Confused deputy | Approved tool is redirected toward an unauthorized target |
| Unsafe output handling | Model output contains dangerous markup, commands, or links |
| Supply-chain compromise | Integration package or manifest differs from the approved version |
| Poisoned enrichment | External source attempts to alter policy or inject false facts |
| Misinformation | Model asserts vulnerability or compromise without evidence |
| Resource exhaustion | Recursive agents, oversized context, or unbounded output |
| Memory poisoning | Non-authoritative memory conflicts with current evidence |
| Tool-description poisoning | External MCP metadata contains malicious instructions |
| Rug pull | Approved integration changes behavior in a later version |
| Output flooding | Tool attempts to overwhelm context or persistent storage |
| Cancellation failure | Child work continues after user or policy cancellation |

### Test Requirements

- deterministic fixtures where possible
- tenant-isolation fixtures
- synthetic secrets and decoys
- expected allow and deny outcomes
- versioned test cases
- CI-compatible subset
- isolated extended test environment
- evidence retained for failures
- regression test added for every confirmed issue

### Training-Lab Boundary

Deliberately vulnerable AI labs may be used only as isolated training or test inspiration. Their vulnerable code must not be imported into production components.

---

## 8. Workflow Graph Safety

### Gap

Future multi-agent and tool workflows need deterministic data flow, validation, safe joins, and dry-run behavior.

### Proposed Workflow Node Types

- start
- evidence retrieval
- deterministic rule
- agent
- tool
- condition
- validation
- human approval
- output
- end

### Required Workflow Controls

- static graph validation
- required start and output nodes
- no invalid incoming or outgoing edges
- cycle policy
- maximum node count
- maximum runtime
- maximum tool calls
- typed node inputs and outputs
- explicit named outputs
- safe condition language
- no arbitrary scripting in conditions
- dry-run mode
- fail-fast safety gates
- deterministic join strategies
- audit and replay records

### Suggested Join Strategies

- merge all upstream results
- first non-empty result
- explicit selected branch
- fail if any upstream safety check fails

### Structured Node Envelope

```json
{
  "kind": "agent",
  "node_id": "risk-agent-1",
  "node_type": "agent",
  "status": "completed",
  "output": {},
  "evidence_refs": [],
  "started_at": "",
  "completed_at": ""
}
```

Workflow expressions should support safe path reads and comparisons only. They must not become an arbitrary code-execution surface.

---

## 9. Separate Audit, Monitoring, and Approval Streams

### Gap

A single log stream cannot clearly answer who changed platform state, how a tool executed, and why an action was approved.

### Proposed Observability Streams

### Platform Audit

Records:

- login and authentication events
- role and permission changes
- configuration changes
- integration enablement or revocation
- model and provider changes
- policy changes
- data export

### Tool Execution Monitoring

Records:

- execution status
- duration
- resource usage
- partial output
- truncation
- retries
- cancellation
- timeout
- external MCP health

### Human Approval Log

Records:

- requested action
- tool and arguments
- target scope
- evidence summary
- approving actor
- approved, edited, or rejected status
- reason
- expiration

### Analysis Replay

Records:

- selected evidence
- deterministic transformations
- inferred relationships
- model and agent identifiers
- validation outcomes
- final advisory result

These streams may be correlated by shared task and execution identifiers, but they should remain logically distinct.

---

## 10. Asset Coverage and Risk-State Enhancements

### Gap

OpenAssetWatch has strong inventory goals, but future views should explicitly answer:

1. What exists?
2. What has been assessed?
3. Where is risk concentrated?
4. Which evidence is stale?
5. Which assets have never been evaluated?

### Suggested Future Fields

- first seen
- last seen
- last assessed
- assessment source
- assessment coverage state
- stale threshold
- related vulnerability count
- current risk state
- owner
- department
- business service
- environment
- criticality
- data sensitivity
- security-tool coverage
- collector coverage

### Suggested Coverage States

- unassessed
- scheduled
- assessed
- partially assessed
- stale
- failed
- excluded by policy

### Agent Query Limits

AI and external agents should receive bounded summaries rather than entire inventories. Full asset details should require explicit retrieval of a selected asset.

---

## 11. Failure Recovery and Graceful Degradation

### Gap

The architecture should define how AI features fail without affecting deterministic product functions.

### Required Behaviors

- collectors continue when AI is unavailable
- inventory remains usable without AI
- deterministic findings continue without AI
- reports have deterministic fallback templates
- external MCP failure does not block unrelated tools
- failed model routing does not silently change data-sharing policy
- partial results are clearly marked
- retries are bounded
- duplicate task execution is suppressed
- stale executions are reconciled
- integrations can be disabled independently

### Suggested Failure Record

```json
{
  "status": "stopped",
  "reason": "external_integration_circuit_open",
  "partial_result_available": true,
  "retry_after_seconds": 60,
  "human_review_recommended": false
}
```

---

## 12. Explicitly Rejected Capabilities

The reviewed projects also contain offensive or high-privilege capabilities that conflict with OpenAssetWatch's mission and threat model.

OpenAssetWatch must not adopt:

- autonomous penetration testing
- automated exploitation
- exploit or payload generation
- credential harvesting
- password cracking
- credential dumping
- WebShell management
- command-and-control listeners or beacons
- arbitrary command endpoints
- unrestricted shell execution
- unrestricted active scanning
- unauthorized browser automation
- destructive remediation
- automatic firewall or endpoint changes
- persistence mechanisms
- privilege escalation tooling

These capabilities would materially change the project's identity, legal risk, deployment security, and support burden.

---

## 13. Proposed Future Architecture

```text
OpenAssetWatch Evidence and Inventory
              |
              v
      Evidence Context Engine
              |
              +-----------------------------+
              |                             |
              v                             v
   Exposure Path Analyzer          AI Advisor Orchestrator
              |                             |
              v                             v
     Analysis Replay Record          Workflow Runtime
                                            |
                                            v
                                      Tool Gateway
                                            |
                              +-------------+-------------+
                              |                           |
                              v                           v
                     Internal Read-Only Tool      External Integration
                                                        |
                                                        v
                                                Integration Trust Gate
                                                        |
                                                        v
                                                  Per-Tool Sandbox
                                                        |
                                                        v
                                                  Runtime Guard
```

Cross-cutting controls:

- tenant isolation
- role authorization
- policy enforcement
- evidence provenance
- model and integration allowlists
- output redaction
- execution budgets
- audit logging
- human approval
- cancellation
- retention and deletion controls

---

## 14. Recommended Implementation Order

### Near-Term Documentation and Contracts

1. Define Exposure Path schema.
2. Define relationship and confidence schema.
3. Define canonical tool execution record.
4. Define integration manifest and lifecycle states.
5. Define AI security test matrix.
6. Define separate audit, monitor, and approval event types.

### After a Stable Read-Only Tool Gateway Exists

1. Add bounded execution identifiers and cancellation.
2. Add output caps and artifact references.
3. Add external MCP concurrency and circuit breakers.
4. Add approved integration registry.
5. Add static integration checks.

### Later Hardening

1. Add per-tool sandbox policies.
2. Add credential proxying.
3. Add runtime integration guard.
4. Add sandbox verification for suspicious integrations.
5. Add full AI adversarial test suite.

### Later Defensive Intelligence

1. Build a deterministic relationship graph.
2. Add evidence-backed exposure paths.
3. Add control-break recommendations.
4. Add analysis replay and path history.
5. Add optional AI explanation after deterministic path construction.

---

## 15. Scope Control

This backlog is intentionally documentation-only.

It does not require the project to implement all listed components now. Each item should be evaluated against current milestones, resource availability, security value, and maintenance burden.

A future item should be accepted only when it:

- supports passive asset visibility and defensive decision support
- preserves evidence as the source of truth
- does not require offensive execution
- can be isolated behind stable interfaces
- does not become a mandatory external dependency
- has clear success and removal criteria
- does not delay committed core-platform work

## Source Review Notes

The reviewed repositories were used as architectural references only.

Useful patterns preserved here include:

- multi-agent separation and vulnerability correlation
- replayable graph workflows
- resumable tool execution and output governance
- least-privilege child sandboxes
- credential proxies and endpoint restrictions
- staged static, semantic, and sandbox review
- MCP and skill supply-chain review
- adversarial AI security test categories

OpenAssetWatch should independently design and implement any future component, verify licensing before using code, and perform a fresh security review before adopting any dependency.

## Final Position

The most important defensive gap is exposure-path analysis: showing how assets, services, vulnerabilities, identities, topology, and missing controls combine into a plausible route to business impact.

The most important platform-security gaps are integration trust review, per-tool isolation, bounded execution, and repeatable AI security testing.

These capabilities can strengthen OpenAssetWatch later without changing its current passive-first and advisory-first direction, provided offensive automation remains explicitly out of scope.