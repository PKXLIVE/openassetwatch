# Defensive AI and Security Architecture Gap Backlog

## Purpose

This document records provider-neutral architecture patterns that OpenAssetWatch may use to close future defensive-intelligence, AI-governance, tool-security, and evidence-analysis gaps without expanding the current build scope.

The goal is not to copy an external platform or turn OpenAssetWatch into a penetration-testing framework. The goal is to preserve safe design directions, define implementation contracts, and document boundaries for later work.

Detailed requirements for AI-component inventory, permission-path analysis, trust-labeled context, safe output publication, protected control artifacts, agent-specific CI scanning, canonical tool identity, child-agent privilege control, artifact provenance, and verified enrichment knowledge are defined in:

- `docs/architecture/ai-agent-permission-output-security.md`

## Decision Summary

OpenAssetWatch should preserve the following future design directions:

1. Evidence-based exposure-path analysis.
2. Replayable analysis and decision records.
3. Resumable and bounded tool execution.
4. Per-tool isolation and credential proxying.
5. Integration and tool trust review.
6. AI security validation and adversarial testing.
7. Runtime guardrails for suspicious integrations.
8. Separate audit, execution-monitoring, approval, and replay records.
9. Safe workflow graphs with deterministic joins and validation.
10. Deterministic finding intelligence, ownership, confidence, evidence selection, and finding fusion.
11. Finding-validation state management.
12. Environment security context and explicit fact, inference, and hypothesis classification.
13. Scoped child workers and policy-filtered capability discovery.
14. Optional passive external-exposure enrichment restricted to verified owned scope.
15. AI-component and activity inventory.
16. Agent permission-path analysis.
17. Trust-labeled context assembly.
18. Safe output publication through a separate publisher identity.
19. Protected AI policy, prompt, workflow, and tool artifacts.
20. Agent-specific CI security scanning.
21. Tool identity collision, shadowing, and drift detection.
22. AI-generated artifact provenance.
23. Verified, expiring, and contradiction-aware enrichment knowledge.
24. Strict rejection of exploit generation, credential theft, remote shells, command-and-control features, and arbitrary command capabilities.

These are future architecture items. They do not change the current passive-first, advisory-first, evidence-first, and read-only-default project scope.

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

## 2. Finding Intelligence Pipeline

### Gap

Canonical findings may arrive from passive observations, collector inventory, vulnerability imports, cloud findings, endpoint telemetry, directory enrichment, configuration review, or external exposure intelligence. Without deterministic post-processing, duplicate conditions can inflate risk and conflicting sources can produce inconsistent results.

### Proposed Pipeline

```text
Normalized Observations
        |
        v
Deterministic Rules
        |
        v
Canonical Findings
        |
        v
Ownership Resolver
        |
        v
Confidence Engine
        |
        v
Evidence Selector
        |
        v
Finding Fusion Engine
        |
        v
Exposure Path Analyzer
        |
        v
Optional AI Explanation
```

### Ownership Resolver

Ownership resolution should distinguish:

- device or asset owner
- business service owner
- technical support owner
- department
- tenant
- application-owned behavior
- third-party or platform-owned behavior
- unknown ownership

### Confidence Engine

Confidence should use evidence quality rather than model certainty. Inputs may include:

- source reliability
- direct observation versus inference
- freshness
- source diversity
- corroboration
- contradictions
- identity match quality
- product and version match quality
- topology certainty

### Evidence Selector

The Evidence Selector should:

- choose the smallest sufficient evidence set
- retain source references
- prefer direct observations
- mark stale records
- preserve contradictory evidence
- exclude unrelated tenant data
- enforce context and report limits

### Finding Fusion

The Finding Fusion Engine should:

- correlate reports describing the same underlying condition
- retain all source evidence
- prevent duplicate risk inflation
- show corroboration and conflict
- preserve source-specific timestamps and states
- select one canonical finding
- recalculate confidence as evidence changes

Example:

```json
{
  "canonical_finding_id": "finding-401",
  "title": "Outdated service exposed externally",
  "source_findings": [
    "passive-service-22",
    "vulnerability-import-91",
    "external-exposure-13"
  ],
  "corroboration_count": 3,
  "confidence": "high",
  "conflicts": []
}
```

---

## 3. Evidence Statement Classification

Important conclusions should be classified explicitly as:

- `observed`
- `deterministically_derived`
- `corroborated`
- `inferred`
- `hypothesized`
- `unknown`

Example:

```json
{
  "statement": "The camera may reach the management workstation",
  "classification": "inferred",
  "confidence": 0.61,
  "supporting_evidence": ["flow-91", "segment-12"],
  "missing_evidence": ["firewall-policy", "route-table"],
  "validation_required": true
}
```

An inference must not be presented as an observed fact. A hypothesis must not become a deterministic finding without new evidence.

---

## 4. Finding Validation State Machine

### Proposed Stages

```text
Candidate Finding
      |
      v
Source and Schema Validation
      |
      v
Duplicate and Known-Noise Filtering
      |
      v
Evidence Sufficiency
      |
      v
Exposure and Reachability
      |
      v
Preconditions and Compensating Controls
      |
      v
Cross-Source Corroboration
      |
      v
Contradiction and Uncertainty Review
      |
      v
Validated / Needs Review / Rejected
```

### Suggested States

- `candidate`
- `insufficient_evidence`
- `needs_corroboration`
- `validated`
- `validated_with_assumptions`
- `rejected_false_positive`
- `superseded`
- `stale`

The validation pipeline should be deterministic wherever possible. AI may summarize conflicts but must not silently promote a finding.

---

## 5. Environment Security Context

OpenAssetWatch should support a lightweight, user-owned model of expected boundaries and critical relationships.

```text
Environment Security Context
|-- internet boundaries
|-- network segments
|-- trusted management networks
|-- critical assets
|-- sensitive services
|-- identity boundaries
|-- security controls
|-- expected communication paths
`-- prohibited communication paths
```

Example:

```yaml
environment_id: home-lab
critical_assets:
  - nas-01
  - workstation-admin
internet_ingress:
  expected:
    - asset: router-01
      service: vpn
  prohibited:
    - segment: iot
trusted_management_segments:
  - admin-vlan
sensitive_relationships:
  - source: iot-vlan
    target: workstation-vlan
    expected: false
```

This context is operator-owned policy, not automatic proof. Findings still require evidence.

---

## 6. Analysis Replay and Provenance

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

## 7. Resumable and Bounded Tool Execution

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

### External Integration Resilience

External tool servers and integrations should have:

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

## 8. Per-Tool Isolation and Credential Proxying

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

### Credential Proxy

Where possible, a tool should not receive the underlying reusable secret. A credential proxy should inject authentication only for approved destinations and operations.

Required sandbox controls should include:

- restricted filesystem visibility
- default-deny network access
- CPU, memory, storage, and process limits
- dangerous environment-variable removal
- argument-list subprocess invocation rather than interpolated shell strings
- temporary workspaces
- automatic cleanup

---

## 9. Integration Trust Gate

### Proposed Component

Add a future **Integration Trust Gate** for:

- tool servers
- agent skills
- external assistant adapters
- model-provider adapters
- report plugins
- vulnerability enrichment adapters
- repository packages
- archives
- local source projects

### Review Pipeline

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

### Lifecycle States

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

A clean review means no relevant risk was found during the review. It is not a guarantee that the integration is risk-free.

---

## 10. Runtime Integration Guard

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

Possible outcomes:

- allow
- allow with redaction
- allow with restricted output
- require human approval
- block
- terminate integration
- quarantine integration version

The guard is a secondary control. It does not replace static review, authorization, per-tool policy, or sandboxing.

---

## 11. Scoped Child Analysis Workers

Specialist child workers should receive explicit tenant, resource, evidence, tool, runtime, and destination scope.

Required rule:

> A child worker may receive less authority than its parent, never more.

Required controls:

- authenticated parent and child identities
- immutable parent policy ceiling
- no credential inheritance
- no external integrations unless separately approved
- bounded runtime and tool calls
- result schema validation
- cancellation propagation
- privilege-difference check before start

Detailed contracts are defined in `docs/architecture/ai-agent-permission-output-security.md`.

---

## 12. Policy-Filtered Capability Discovery

Large tool catalogs should be filtered in this order:

1. tenant authorization
2. actor and role authorization
3. integration approval state
4. tool-risk policy
5. task compatibility
6. semantic relevance

Semantic retrieval must never make an unauthorized tool visible.

---

## 13. AI Component, Permission, Context, and Output Security

The following architecture requirements are defined in detail in `docs/architecture/ai-agent-permission-output-security.md`:

- AI Component Registry
- unmanaged AI discovery
- AI Activity Relationship Graph
- Agent Permission Path Analyzer
- trust-labeled context assembly
- Safe Output Gate
- separate publisher identity
- independent security-validation budgets
- Protected Control Artifact Registry
- agent-specific static analysis and CI gates
- canonical tool identity
- collision, shadowing, and drift detection
- child-agent privilege controls
- policy-filtered capability discovery
- AI-generated artifact provenance
- verified and expiring enrichment knowledge
- destination trust classes
- runtime permission and egress monitoring

The central policy is:

> Untrusted input, sensitive read access, and lower-trust write access must never form an ungoverned path.

---

## 14. AI Security Validation Program

Required test categories include:

- direct prompt injection
- indirect prompt injection
- stored injection
- sensitive information disclosure
- prompt leakage
- cross-tenant retrieval
- excessive agency
- confused-deputy behavior
- unsafe output handling
- supply-chain compromise
- poisoned enrichment
- misinformation
- resource exhaustion
- memory poisoning
- tool-description poisoning
- integration behavior drift
- output flooding
- cancellation failure
- permission-path leakage
- publication without validation
- tool identity shadowing
- child-agent privilege expansion
- protected artifact drift

Tests should use deterministic fixtures, synthetic secrets, expected allow and deny outcomes, versioned cases, and regression coverage for every confirmed issue.

---

## 15. Workflow Graph Safety

Future workflows should support:

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

Required controls:

- static graph validation
- typed node inputs and outputs
- no arbitrary scripting in conditions
- dry-run mode
- maximum nodes, runtime, and tool calls
- deterministic join strategies
- fail-fast safety gates
- audit and replay records

---

## 16. Separate Audit, Monitoring, Approval, and Replay Streams

### Platform Audit

Records identity, authentication, permission, configuration, policy, integration, and export changes.

### Tool Execution Monitoring

Records status, duration, resource use, partial output, truncation, retries, cancellation, timeout, and integration health.

### Human Approval Log

Records requested action, arguments, scope, evidence summary, decision, reason, approver, and expiration.

### Analysis Replay

Records selected evidence, deterministic transformations, inferred relationships, validation outcomes, and final advisory output.

These streams should correlate through task and execution identifiers while remaining logically distinct.

---

## 17. Asset Coverage and Risk-State Enhancements

Future views should answer:

1. What exists?
2. What has been assessed?
3. Where is risk concentrated?
4. Which evidence is stale?
5. Which assets have never been evaluated?

Suggested coverage states:

- unassessed
- scheduled
- assessed
- partially assessed
- stale
- failed
- excluded_by_policy

AI and external agents should receive bounded summaries rather than entire inventories.

---

## 18. Passive External Exposure Enrichment

A future optional connector may use approved passive sources to identify externally indexed assets and exposure indicators.

Required architecture:

```text
Owned Scope Registry
       |
       v
Query Builder
       |
       v
Approved Passive Source
       |
       v
Result Normalizer
       |
       v
Ownership Verification
       |
       v
External Exposure Candidate
       |
       v
Human Confirmation
```

Safeguards:

- verified owned domains and ranges only
- no login attempts
- no payload submission
- no bypass queries
- provider terms and rate limits enforced
- sensitive results redacted
- human confirmation before attaching to an asset
- optional feature because scope may be shared externally

---

## 19. Verified and Expiring Enrichment Knowledge

External research must not be promoted automatically into trusted knowledge.

Required states:

- candidate
- verified
- corroborated
- contradicted
- expired
- rejected

Required metadata:

- source
- retrieval date
- content digest
- source trust class
- affected product and version mapping
- validation status
- contradictions
- expiration and refresh date

Detailed requirements are defined in `docs/architecture/ai-agent-permission-output-security.md`.

---

## 20. Failure Recovery and Graceful Degradation

Required behaviors:

- collectors continue when AI is unavailable
- inventory remains usable without AI
- deterministic findings continue without AI
- reports have deterministic fallback templates
- external integration failure does not block unrelated tools
- failed routing does not silently change data-sharing policy
- partial results are clearly marked
- retries are bounded
- duplicate task execution is suppressed
- stale executions are reconciled
- integrations can be disabled independently
- failed output validation prevents publication

---

## 21. Explicitly Rejected Capabilities

OpenAssetWatch must not adopt:

- autonomous penetration testing
- automated exploitation
- exploit or payload generation
- credential harvesting
- password cracking
- credential dumping
- remote shell management
- command-and-control listeners or beacons
- arbitrary command endpoints
- unrestricted shell execution
- prohibited: unrestricted active scanning
- destructive remediation
- automatic firewall or endpoint changes
- persistence mechanisms
- privilege-escalation tooling
- self-expanding agent permissions
- automatic publication to public destinations
- automatic promotion of search results into trusted knowledge

---

## 22. Proposed Future Architecture

```text
OpenAssetWatch Evidence and Inventory
              |
              v
      Finding Intelligence Pipeline
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

AI Component Registry and Activity Graph
              |
              v
      Permission Path Analyzer
              |
              v
       Trust-Labeled Context
              |
              v
      Candidate Output Artifact
              |
              v
          Safe Output Gate
              |
              v
     Separate Publisher Identity
```

Cross-cutting controls:

- tenant isolation
- role authorization
- policy enforcement
- evidence provenance
- model and integration allowlists
- output redaction
- execution budgets
- independent validation budgets
- protected control artifacts
- canonical tool identities
- audit logging
- human approval
- cancellation
- retention and deletion controls

---

## 23. Recommended Implementation Order

### Near-Term Documentation and Contracts

1. Define canonical finding, ownership, confidence, evidence-selection, and fusion schemas.
2. Define Exposure Path and relationship schemas.
3. Define evidence statement classifications.
4. Define finding-validation states.
5. Define Environment Security Context.
6. Define AI component and activity schemas.
7. Define trust-labeled context schema.
8. Define canonical tool identity.
9. Define output artifact and destination policy contracts.
10. Define child-worker privilege envelope.
11. Define verified-knowledge lifecycle.

### After a Stable Read-Only Tool Gateway Exists

1. Add bounded execution identifiers and cancellation.
2. Add output caps and artifact references.
3. Add integration concurrency and circuit breakers.
4. Add approved integration and AI component registries.
5. Add static integration and agent-code checks.
6. Add policy-filtered capability discovery.
7. Add permission-path evaluation.

### Later Hardening

1. Add per-tool sandbox policies.
2. Add credential proxying.
3. Add runtime integration and egress monitoring.
4. Add protected control artifact integrity checks.
5. Add Safe Output Gate and separate publisher identities.
6. Add full adversarial AI test suite.
7. Add tool shadowing and drift detection.

### Later Defensive Intelligence

1. Build deterministic relationship graph.
2. Add finding fusion and validation.
3. Add evidence-backed exposure paths.
4. Add control-break recommendations.
5. Add path history and replay.
6. Add optional AI explanation after deterministic construction.
7. Add optional passive external exposure enrichment.

---

## 24. Scope Control

This backlog is intentionally documentation-only.

A future item should be accepted only when it:

- supports passive asset visibility and defensive decision support
- preserves evidence as the source of truth
- does not require offensive execution
- can be isolated behind stable interfaces
- does not become a mandatory external dependency
- has clear success and removal criteria
- does not delay committed core-platform work
- uses provider-neutral contracts
- can fail safely without disabling deterministic product functions

## Final Position

The most important defensive-intelligence gap is exposure-path analysis supported by deterministic finding ownership, confidence, evidence selection, fusion, and validation.

The most important agent-security gap is permission-path analysis across untrusted input, sensitive reads, and lower-trust writes. The most important workflow control is separation between read-only generation and narrowly authorized publication.

These capabilities can strengthen OpenAssetWatch without changing its passive-first, evidence-first, and advisory-first direction, provided offensive automation remains explicitly out of scope.
