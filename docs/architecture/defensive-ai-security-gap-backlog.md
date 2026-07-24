# Defensive Intelligence and AI Security Architecture Backlog

## Purpose

This document preserves defensive architecture patterns identified through review of public security, agent, application-analysis, and AI-safety projects. It converts those patterns into original OpenAssetWatch design requirements without naming, endorsing, or depending on the source projects.

The goal is to close future architecture gaps while preserving the current project direction:

- passive-first collection
- deterministic evidence and findings
- advisory-only AI
- local-first operation
- provider-neutral integrations
- read-only defaults
- explicit tenant and policy boundaries
- no autonomous offensive execution

This is a future-build backlog. It does not expand the current implementation scope.

## Decision Summary

OpenAssetWatch should preserve the following future design directions:

1. A deterministic Finding Intelligence Pipeline.
2. Evidence-backed exposure-path analysis.
3. A formal finding-validation state machine.
4. Explicit separation of facts, derivations, inferences, and hypotheses.
5. A lightweight Environment Security Context.
6. Finding fusion across collectors and external enrichment sources.
7. Replayable analysis and provenance records.
8. Resumable, cancellable, and output-bounded tool execution.
9. Per-tool child sandboxes and credential proxying.
10. Integration trust review for tools, skills, plugins, and protocol servers.
11. Runtime monitoring for uncertain integrations.
12. Scoped child analysis workers.
13. Policy-filtered capability discovery for large tool catalogs.
14. Optional passive external-exposure enrichment.
15. Repeatable AI security validation and adversarial testing.
16. Separate audit, execution-monitoring, approval, and replay streams.
17. Graceful degradation when AI or an integration is unavailable.
18. Explicit rejection of autonomous exploitation and high-privilege offensive features.

---

## 1. Finding Intelligence Pipeline

### Gap

OpenAssetWatch can collect observations and generate deterministic findings, but future multi-source environments will need a clear pipeline between raw findings and user-facing risk conclusions.

The platform should not rely on an AI model to decide ownership, remove duplicate findings, determine evidence quality, or construct the authoritative risk record.

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

### Pipeline Principles

- Each stage should have a versioned input and output contract.
- Stages should add metadata rather than silently deleting source evidence.
- Deterministic stages remain authoritative.
- AI may explain or summarize a result after deterministic processing.
- Every transformation should be reproducible from stored evidence and rule versions.
- A failure in an optional stage should not invalidate earlier deterministic results.

### Canonical Finding Requirements

A canonical finding should include:

- finding identifier
- tenant or deployment scope
- title and normalized category
- affected asset and service references
- severity
- status
- first seen and last seen
- source finding references
- evidence references
- ownership metadata
- confidence metadata
- statement classification
- rule and schema versions
- stale status
- remediation guidance
- related exposure paths

---

## 2. Ownership Resolution

### Gap

Data from operating systems, applications, infrastructure, network sensors, cloud sources, and third-party libraries may describe code or assets not owned by the user or not controlled by the same team.

Without ownership resolution, the platform may assign responsibility incorrectly or inflate risk with findings that belong to a dependency, shared service, or external provider.

### Proposed Component

Add a future **Ownership Resolver** that assigns one or more ownership dimensions:

- asset owner
- technical owner
- business owner
- support group
- application owner
- network owner
- data owner
- third-party or dependency owner
- unknown owner

### Ownership Evidence

Ownership may be derived from:

- collector metadata
- directory and identity enrichment
- CMDB or ITSM data
- cloud tags
- repository metadata
- package or dependency boundaries
- manually assigned asset ownership
- network segment ownership
- business-service relationships

### Ownership Result

```json
{
  "asset_id": "asset-123",
  "ownership": {
    "technical_owner": "team-network",
    "business_owner": "business-unit-1",
    "support_group": "service-desk-network",
    "classification": "first_party"
  },
  "evidence_refs": ["cmdb-record-18", "collector-observation-91"],
  "confidence": 0.92,
  "status": "corroborated"
}
```

Ownership must never be inferred solely from an AI-generated guess.

---

## 3. Confidence Engine

### Gap

A single generic confidence score is not enough. Confidence should reflect evidence quality, source agreement, freshness, directness, and unresolved contradictions.

### Confidence Inputs

A deterministic confidence engine may consider:

- direct observation versus imported claim
- number of independent sources
- source reliability
- evidence freshness
- asset identity confidence
- service fingerprint confidence
- version match quality
- reachability certainty
- ownership certainty
- contradictions
- missing expected evidence
- rule specificity

### Confidence Dimensions

Suggested dimensions:

- `identity_confidence`
- `evidence_confidence`
- `reachability_confidence`
- `ownership_confidence`
- `finding_confidence`
- `path_confidence`

### Confidence Labels

- confirmed
- high
- medium
- low
- insufficient
- conflicting

A model confidence score must not replace these evidence-derived values.

---

## 4. Evidence Selection Engine

### Gap

Raw observations can be large, repetitive, stale, or irrelevant. Sending all available records to users or AI systems creates noise and increases privacy and context risks.

### Proposed Component

Add a future **Evidence Selection Engine** that prepares the smallest sufficient evidence set for a finding, path, report, or AI task.

### Responsibilities

- remove duplicates
- prefer direct evidence over summaries
- retain source references
- label stale records
- include contradictory evidence
- exclude secrets and unnecessary sensitive fields
- enforce tenant scope
- rank evidence by relevance and quality
- cap evidence volume
- preserve omitted-evidence counts
- create deterministic summaries where practical

### Evidence Bundle

```json
{
  "bundle_id": "evidence-bundle-81",
  "purpose": "validate-finding",
  "selected": ["obs-1", "obs-9", "vuln-import-7"],
  "excluded_counts": {
    "duplicate": 14,
    "stale": 3,
    "out_of_scope": 2
  },
  "contradictions": ["obs-12"],
  "sensitivity": "internal",
  "selection_rule_version": "1.0"
}
```

---

## 5. Finding Fusion Engine

### Gap

The same underlying condition may arrive from passive discovery, local software inventory, vulnerability enrichment, cloud posture, endpoint tooling, configuration analysis, and external exposure sources.

Treating each source as a separate risk can inflate counts and hide source agreement.

### Proposed Component

Add a future **Finding Fusion Engine** that correlates related source findings into one canonical finding while retaining every source record.

### Fusion Responsibilities

- normalize titles and categories
- correlate asset, service, software, and vulnerability identity
- group findings describing the same condition
- retain source-specific timestamps and states
- identify source agreement and disagreement
- select a canonical severity using policy
- prevent duplicate risk inflation
- increase confidence when independent sources corroborate
- preserve conflicts for analyst review
- support split and merge correction

### Example

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
  "conflicts": [],
  "fusion_rule_version": "1.0"
}
```

### Fusion Safety

- Fusion must be reversible.
- Source findings must remain independently inspectable.
- Conflicting versions or asset identities must not be silently merged.
- AI may recommend a merge but must not perform authoritative fusion without deterministic checks.

---

## 6. Statement Evidence Classification

### Gap

Security conclusions often mix direct facts, deterministic calculations, structural inferences, and unproven hypotheses. A generic confidence field can make an inference look like an observation.

### Required Classifications

Every important statement should use one of these classifications:

- `observed_fact`
- `imported_fact`
- `deterministic_derivation`
- `corroborated_conclusion`
- `structural_inference`
- `hypothesis`
- `unknown`

### Example

```json
{
  "statement": "The device may reach the management workstation",
  "classification": "structural_inference",
  "confidence": 0.61,
  "supporting_evidence": ["flow-91", "segment-12"],
  "missing_evidence": ["firewall-policy", "route-table"],
  "validation_required": true
}
```

### Presentation Rule

User interfaces and reports should visually distinguish:

- observed facts
- inferred relationships
- unresolved hypotheses
- recommendations

The system must not present an inference as a confirmed observation.

---

## 7. Finding Validation State Machine

### Gap

The project needs a formal process for moving a candidate finding into a validated state.

### Proposed Validation Stages

```text
Candidate Finding
      |
      v
Stage 0 - Schema and source validation
      |
      v
Stage 1 - Duplicate and known-noise review
      |
      v
Stage 2 - Evidence sufficiency
      |
      v
Stage 3 - Exposure and reachability
      |
      v
Stage 4 - Preconditions and compensating controls
      |
      v
Stage 5 - Cross-source corroboration
      |
      v
Stage 6 - Contradiction and uncertainty review
      |
      v
Validated / Needs Review / Rejected
```

### Suggested States

- candidate
- source_invalid
- duplicate_candidate
- insufficient_evidence
- needs_corroboration
- needs_human_review
- validated
- validated_with_assumptions
- rejected_false_positive
- superseded
- stale
- resolved

### Validation Questions

- Is the source authentic and in scope?
- Does the evidence actually support the finding?
- Is the affected asset identity reliable?
- Is the vulnerable service or condition reachable?
- Are required attacker or failure preconditions realistic?
- Do compensating controls reduce or eliminate exposure?
- Do independent sources agree?
- Does any evidence contradict the conclusion?
- Is the result current enough to act on?

### AI Role

AI may summarize conflicting evidence or explain why a validation stage failed. It must not silently promote a candidate to validated status.

---

## 8. Environment Security Context

### Gap

Exposure and risk cannot be prioritized accurately without understanding environment boundaries, critical assets, expected communication, and compensating controls.

### Proposed Component

Add a lightweight **Environment Security Context** that is operator-owned and versioned.

### Suggested Fields

- critical assets
- sensitive services
- business services
- internet boundaries
- network segments
- trusted management networks
- expected communication paths
- prohibited communication paths
- identity trust boundaries
- security controls
- accepted risks
- maintenance windows
- asset criticality rules
- data sensitivity

### Example

```yaml
environment_id: site-1
critical_assets:
  - storage-01
  - admin-workstation
internet_ingress:
  expected:
    - asset: gateway-01
      service: remote-access
  prohibited:
    - segment: iot
trusted_management_segments:
  - admin-network
sensitive_relationships:
  - source: iot-network
    target: admin-network
    expected: false
```

### Freshness

The context must include:

- version
- owner
- last reviewed
- expiration or review date
- stale status

Stale security context should be rejected or clearly marked before it influences high-confidence conclusions.

---

## 9. Exposure Path Analyzer

### Gap

A single finding may not explain the full risk. The meaningful concern may exist in relationships among external exposure, vulnerable services, weak segmentation, identities, missing controls, and critical assets.

### Proposed Component

Add a future **Exposure Path Analyzer** that builds defensive, evidence-backed paths across OpenAssetWatch records.

The analyzer must remain advisory. It must not execute the path, validate it through exploitation, or claim compromise without direct evidence.

### Suggested Node Types

- asset
- service
- vulnerability
- external exposure
- identity
- account
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
- `trusts`
- `administers`

### Required Edge Metadata

- edge identifier
- source and destination nodes
- relationship type
- statement classification
- evidence references
- first seen and last seen
- confidence
- tenant scope
- derivation method
- rule or model version
- stale status

### Path Output

```json
{
  "path_id": "exposure-path-001",
  "title": "External management exposure may provide a route to a sensitive asset",
  "status": "advisory",
  "confidence": "medium",
  "nodes": [
    "external-exposure-1",
    "asset-gateway-1",
    "service-admin-https",
    "segment-iot",
    "asset-sensitive-7"
  ],
  "evidence_refs": ["observation-31", "finding-18", "asset-7"],
  "uncertainties": [
    "No exploitability validation was performed",
    "Layer-3 reachability is inferred from available topology evidence"
  ],
  "recommended_control": "Restrict management access and isolate the affected segment"
}
```

### Ranking Inputs

- evidence quality
- external exposure
- approved exploitation-status enrichment
- vulnerability severity
- asset criticality
- identity privilege
- reachability confidence
- missing controls
- path length
- stale evidence
- compensating controls
- business impact

The score must not be based only on AI confidence.

### Control-Break Analysis

The analyzer should identify defensive changes that interrupt the path:

- remove public exposure
- restrict management access
- patch or retire a vulnerable service
- isolate a segment
- require stronger authentication
- disable an unused account
- add endpoint or network controls
- remove an unnecessary trust relationship

---

## 10. Analysis Replay and Provenance

### Gap

Users need to understand how evidence became a finding or exposure path without relying on hidden model reasoning.

### Proposed Component

Add an **Analysis Replay Record** that stores observable inputs, transformations, tool calls, validation steps, and outputs.

### Replay Example

```text
1. Asset observed
2. Service identified
3. Version evidence normalized
4. Vulnerability enrichment matched
5. Missing control identified
6. Reachability relationship inferred
7. Finding validation completed
8. Exposure path calculated
9. Advisory recommendation generated
```

### Replay Fields

- replay identifier
- task identifier
- requesting actor
- tenant scope
- selected evidence references
- deterministic transformations
- inferred relationships
- rules and schema versions
- model and agent identifiers when used
- tool executions
- validation outcomes
- approval events
- generated outputs
- timestamps
- stop or failure reason

### Required Distinctions

Replay views must separate:

- observed input
- imported enrichment
- deterministic transformation
- inferred relationship
- AI-generated explanation
- human decision

Private chain-of-thought is neither required nor appropriate for this record.

---

## 11. Resumable and Bounded Tool Execution

### Gap

Long-running tools can block agent turns, flood context, consume resources, and complicate cancellation.

### Proposed Execution Model

```text
Agent requests tool
        |
        v
Execution Service creates record
        |
        v
Worker runs approved tool
        |
        +-- completes during bounded wait --> canonical result
        |
        `-- still running --> execution_id; worker continues
```

### Suggested States

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

- get execution status
- wait for a bounded interval
- retrieve bounded partial output
- cancel execution
- retry when policy permits
- resume a paused workflow

### Output Governance

Every tool should define:

- maximum output bytes
- maximum model-facing bytes
- truncation indicator
- bounded preview
- artifact reference for full output
- redaction before persistence
- canonical normalized result

The same canonical result should be used by the agent, monitoring records, persistence, and resumed workflows.

### External Integration Resilience

- per-integration concurrency limits
- global concurrency limits
- circuit breakers
- failure thresholds
- cooldown periods
- request and hard timeouts
- stale-job reconciliation
- orphan detection
- health state

---

## 12. Per-Tool Isolation and Credential Proxying

### Gap

A general agent sandbox is insufficient when every delegated tool inherits the same filesystem, network, and credential permissions.

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
   |-- argument restrictions
   |-- output limits
   `-- independent audit events
```

### Design Rules

- Policy must live outside prompts and outside model control.
- A tool must not inherit broader permissions from the calling agent.
- Credentials should be short-lived and operation-scoped.
- Direct access to reusable secrets should be avoided.
- Filesystem and network access should default to deny.
- Subprocess calls should use structured argument arrays rather than interpolated shell strings.
- Dangerous environment variables should be stripped from untrusted execution contexts.

### Credential Proxy

A credential proxy may inject authentication only for approved destinations, methods, and paths.

```yaml
tool: vulnerability_lookup
network:
  default: deny
  allow:
    - method: GET
      host: approved-source
      path: /api/v1/vulnerabilities/*
credentials:
  direct_secret_access: false
  injected_by_proxy: true
filesystem:
  read: []
  write:
    - /tmp/openassetwatch-tool-output
```

---

## 13. Integration Trust Gate

### Gap

The architecture needs a complete onboarding and lifecycle process for protocol servers, skills, plugins, external assistants, model adapters, and enrichment connectors.

### Proposed Pipeline

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

### Static Review Checks

- source and license
- pinned version or commit
- checksum and provenance
- dependency inventory
- install and build scripts
- post-install behavior
- secret scanning
- hidden or encoded content
- dangerous commands
- prompt or tool-description poisoning
- environment-variable access
- filesystem access
- outbound destinations
- dynamic code download
- persistence behavior
- privilege escalation behavior
- declared permissions versus implementation

### Runtime Verification

Uncertain integrations may be executed only in an isolated verification environment using:

- synthetic data
- no reusable credentials
- decoy secrets
- restricted egress
- process and filesystem monitoring
- dependency-install monitoring
- time and resource limits

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

A clean result means no relevant risk was found during the review. It is not a guarantee of safety.

---

## 14. Runtime Integration Guard

### Gap

Pre-deployment review cannot identify every dynamic behavior.

### Monitored Behaviors

- tool calls
- subprocess creation
- sensitive path reads
- file writes
- environment-variable reads
- network destinations
- credential access attempts
- persistence attempts
- dynamic downloads
- output containing prompt injection
- capability changes

### Outcomes

- allow
- allow with redaction
- require approval
- block
- terminate
- quarantine version

The runtime guard is a secondary control and does not replace authorization, sandboxing, or static review.

---

## 15. Scoped Child Analysis Workers

### Gap

Future specialist agents may need parallel delegation, but unrestricted child agents can expand scope, inherit credentials, or expose excessive tools.

### Proposed Task Envelope

```json
{
  "task_id": "task-123",
  "parent_task_id": "task-100",
  "agent_role": "exposure_path_analysis",
  "tenant_id": "tenant-1",
  "asset_scope": ["asset-123", "asset-456"],
  "allowed_tools": [
    "read_asset",
    "read_relationships",
    "read_findings"
  ],
  "external_tools_allowed": false,
  "max_runtime_seconds": 45,
  "max_tool_calls": 8,
  "result_schema": "exposure_path_candidate.v1"
}
```

### Required Rules

- A child may receive less authority than its parent, never more.
- Scope must be explicit and immutable during execution.
- Child workers must not inherit credentials by default.
- External tool access must be independently approved.
- Child count, runtime, tokens, and tool calls must be bounded.
- Cancellation must propagate to child work.
- Child outputs must use structured schemas and evidence references.

---

## 16. Policy-Filtered Capability Discovery

### Gap

Large tool catalogs can overwhelm model context and expose capabilities irrelevant to a task.

### Proposed Flow

```text
Agent Task
    |
    v
Authorization and Tenant Filter
    |
    v
Role and Risk Filter
    |
    v
Approved Integration Filter
    |
    v
Semantic Capability Retrieval
    |
    v
Relevant Tools Only
```

### Rule

Semantic relevance ranking must occur only after authorization, tenant, approval-state, and risk filters. Retrieval must never make an unauthorized capability visible.

### Capability Metadata

- capability identifier
- purpose
- read-only or action-capable
- allowed roles
- tenant support
- sensitivity limits
- required approvals
- integration trust state
- input and output schemas
- resource costs
- version

---

## 17. Passive External Exposure Connector

### Gap

OpenAssetWatch is strongest on local and internal visibility. A future optional connector could identify publicly indexed evidence associated with verified owned scope.

### Potential Sources

- search indexes
- certificate transparency data
- public code repositories
- internet-exposure indexes
- public cloud metadata
- archived URLs
- organization-controlled domain records

### Proposed Flow

```text
Owned Scope Registry
       |
       v
Policy-Approved Query Builder
       |
       v
Approved Passive Provider
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

### Safeguards

- verified owned domains or ranges only
- no login attempts
- no payload submission
- no bypass queries
- no automatic vulnerability classification
- provider terms and rate limits enforced
- sensitive results redacted
- human confirmation before attaching results to an asset
- explicit tenant policy for external scope transmission

This connector should remain optional because queries may disclose customer scope to an external service.

---

## 18. Workflow Graph Safety

### Proposed Node Types

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

### Required Controls

- static graph validation
- required start and output nodes
- cycle policy
- node and runtime limits
- typed inputs and outputs
- named outputs
- safe condition language
- no arbitrary scripting
- dry-run mode
- fail-fast safety gates
- deterministic join strategies
- audit and replay records

### Join Strategies

- merge all upstream results
- first non-empty result
- explicit selected branch
- fail if any upstream safety check fails

---

## 19. AI Security Validation Program

### Required Test Categories

| Category | Validation scenario |
| --- | --- |
| Direct prompt injection | User text attempts to override policy |
| Indirect prompt injection | Asset or enrichment data contains malicious instructions |
| Stored injection | Persisted support context attacks a later run |
| Sensitive disclosure | Model is asked for secrets or hidden records |
| Cross-tenant retrieval | One tenant requests another tenant's evidence |
| Excessive agency | Agent requests a capability beyond its role |
| Confused deputy | Approved tool is redirected to an unauthorized target |
| Unsafe output | Generated content contains dangerous markup or commands |
| Supply-chain compromise | Integration differs from approved provenance |
| Poisoned enrichment | External data attempts to alter policy or facts |
| Misinformation | Model asserts vulnerability without evidence |
| Resource exhaustion | Recursive workers or unbounded context/output |
| Memory poisoning | Non-authoritative context conflicts with current evidence |
| Tool-description poisoning | Integration metadata includes malicious instructions |
| Capability rug pull | Approved integration changes behavior in a new version |
| Cancellation failure | Work continues after cancellation |

### Test Requirements

- deterministic fixtures where possible
- synthetic secrets and decoys
- tenant-isolation fixtures
- expected allow and deny outcomes
- versioned cases
- CI-compatible subset
- isolated extended environment
- retained failure evidence
- regression test for each confirmed issue

Deliberately vulnerable training systems may be used only in isolated test environments. Their insecure code must not be imported into production components.

---

## 20. Separate Operational Record Streams

### Platform Audit

Records who changed platform state:

- authentication events
- role and policy changes
- integration lifecycle changes
- model configuration changes
- data exports

### Tool Execution Monitoring

Records how work ran:

- status
- duration
- resource use
- retries
- truncation
- cancellation
- timeout
- partial output

### Human Approval Log

Records why a proposed action was approved, edited, or rejected.

### Analysis Replay

Records how evidence, deterministic transformations, inferences, and optional AI explanations produced the final advisory result.

The streams should share task and execution identifiers but remain logically distinct.

---

## 21. Asset Coverage and Assessment State

Future views should answer:

1. What exists?
2. What has been assessed?
3. Where is risk concentrated?
4. Which evidence is stale?
5. Which assets have never been evaluated?

### Suggested Fields

- first seen
- last seen
- last assessed
- assessment source
- coverage state
- stale threshold
- finding count
- risk state
- owner
- business service
- environment
- criticality
- data sensitivity
- collector coverage
- security-control coverage

### Coverage States

- unassessed
- scheduled
- assessed
- partially_assessed
- stale
- failed
- excluded_by_policy

AI and external agents should receive bounded summaries rather than entire inventories.

---

## 22. Graceful Degradation

### Required Behaviors

- collectors continue when AI is unavailable
- inventory remains usable without AI
- deterministic findings continue without AI
- deterministic report templates remain available
- one failed integration does not block unrelated work
- failed routing does not weaken privacy policy
- partial results are clearly marked
- retries are bounded
- duplicate execution is suppressed
- stale jobs are reconciled
- integrations can be disabled independently

### Failure Record

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

## 23. Explicitly Rejected Capabilities

OpenAssetWatch must not adopt:

- autonomous penetration testing
- automated exploitation
- exploit or payload generation
- credential harvesting or cracking
- credential dumping
- remote shell management
- command-and-control listeners or beacons
- arbitrary command endpoints
- unrestricted shell execution
- unrestricted active scanning
- destructive remediation
- automatic firewall or endpoint changes
- persistence mechanisms
- privilege escalation tooling
- child agents that expand their own scope
- privileged containers as a normal deployment requirement

These capabilities would materially change the project's identity, legal risk, threat model, and maintenance burden.

---

## 24. Proposed Future Architecture

```text
Collectors and Enrichment Sources
              |
              v
      Normalized Observations
              |
              v
      Deterministic Rules
              |
              v
       Canonical Findings
              |
      +-------+--------+----------------+
      |                |                |
      v                v                v
 Ownership         Confidence      Evidence Selection
      |                |                |
      +----------------+----------------+
                       |
                       v
                Finding Fusion
                       |
                       v
             Finding Validation
                       |
                       v
          Exposure Path Analyzer
                       |
          +------------+-------------+
          |                          |
          v                          v
 Analysis Replay             Optional AI Advisor
                                         |
                                         v
                                  Workflow Runtime
                                         |
                                         v
                                    Tool Gateway
                                         |
                            +------------+------------+
                            |                         |
                            v                         v
                  Internal Read-Only Tool     External Integration
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
- data classification
- evidence provenance
- execution budgets
- approval controls
- cancellation
- output redaction
- retention limits
- audit and monitoring

---

## 25. Recommended Implementation Order

### Architecture Contracts

1. Statement classification schema.
2. Canonical finding schema.
3. Ownership and confidence schemas.
4. Finding-fusion contract.
5. Finding-validation state machine.
6. Environment Security Context schema.
7. Exposure-path node and edge schema.
8. Canonical tool-execution record.
9. Scoped child-worker task envelope.
10. Integration manifest and lifecycle schema.

### After Core Inventory and Rules Stabilize

1. Ownership Resolver.
2. Confidence Engine.
3. Evidence Selection Engine.
4. Finding Fusion Engine.
5. Coverage and stale-evidence states.
6. Analysis replay for deterministic findings.

### After a Stable Read-Only Tool Gateway Exists

1. Bounded execution identifiers.
2. Cancellation and timeout propagation.
3. Output caps and artifact references.
4. External integration circuit breakers.
5. Policy-filtered capability discovery.
6. Approved integration registry.

### Later Defensive Intelligence

1. Environment Security Context.
2. Deterministic relationship graph.
3. Finding-validation workflow.
4. Evidence-backed exposure paths.
5. Control-break recommendations.
6. Optional AI explanation after deterministic path construction.
7. Optional passive external-exposure enrichment.

### Later Hardening

1. Per-tool child sandboxes.
2. Credential proxying.
3. Runtime integration guard.
4. Sandbox verification for uncertain integrations.
5. Full AI adversarial test suite.

---

## 26. Scope Control

This backlog is documentation-only. A future item should be accepted only when it:

- supports passive visibility and defensive decision support
- preserves evidence as the source of truth
- does not require offensive execution
- can be isolated behind stable interfaces
- does not become a mandatory external dependency
- has clear success and removal criteria
- does not delay committed core-platform milestones

## Originality and Independence

The ideas in this document are expressed as original OpenAssetWatch requirements and generic architectural patterns. The document intentionally contains no source-project or vendor names, third-party branding, copied diagrams, performance claims, or implementation-specific identifiers.

Any future implementation must be independently designed, security-reviewed, and tested. Third-party code must not be copied without an explicit license and provenance review.

## Final Position

The most important defensive gaps are:

1. turning observations into trustworthy canonical findings through ownership, confidence, evidence selection, and fusion;
2. validating findings before escalation;
3. showing evidence-backed exposure paths without executing them;
4. constraining agents and tools through immutable scope and least privilege; and
5. testing AI and integration behavior as security-sensitive platform components.

These additions strengthen the future OpenAssetWatch architecture without changing its passive-first, deterministic, advisory-only direction.
