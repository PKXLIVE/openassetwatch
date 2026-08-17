# AI Agent Permission, Context, and Safe Output Architecture

## Purpose

This document defines future OpenAssetWatch architecture requirements for AI-component inventory, agent permission-path analysis, trust-labeled context handling, protected output publication, agent-specific security scanning, and verified enrichment knowledge.

The design closes gaps identified through public security research and architecture review. It uses provider-neutral terminology and does not reproduce external product names, branded terminology, proprietary diagrams, or third-party implementation details.

This is a documentation-only design. It does not authorize autonomous remediation, arbitrary command execution, unrestricted scanning, or direct publication by an AI agent.

## Core Principles

OpenAssetWatch should apply these rules to every future AI workflow:

1. Inventory every AI component and its owner.
2. Treat activity and permission relationships as security-relevant graph data.
3. Never let untrusted content become authorization.
4. Analyze permission combinations, not only individual permissions.
5. Separate content generation from publication authority.
6. Reserve independent resources for security validation.
7. Protect prompts, policies, workflows, tool definitions, and approval rules as security-sensitive artifacts.
8. Scan agent code and configuration for agent-specific failure modes.
9. Identify tools by immutable identity, not display name alone.
10. Preserve provenance for AI-generated artifacts.
11. Validate and expire external enrichment knowledge.
12. Keep deterministic controls authoritative and AI optional.

---

## 1. AI Component Registry

### Gap

A model registry alone does not describe the full AI attack surface. Future OpenAssetWatch deployments may include models, agents, tools, workflows, retrieval sources, runtime workers, external processing endpoints, and support integrations.

Without a common registry, an operator cannot reliably identify unmanaged components, ownership gaps, stale approvals, or unknown data paths.

### Proposed Component

Add a future **AI Component Registry**.

```text
AI Component Registry
|-- Models
|-- Agents and Agent Roles
|-- Tool Servers and Tools
|-- Skills and Extensions
|-- Prompt and Policy Packages
|-- Workflow Definitions
|-- Retrieval and Knowledge Sources
|-- Embedding and Reranking Services
|-- Model and Tool Adapters
|-- Runtime Workers
|-- External Processing Endpoints
`-- Output Publishers
```

### Required Fields

Each component record should include:

- component identifier
- component type
- display name
- owner
- maintainer
- tenant or deployment scope
- source and provenance
- version
- digest or checksum
- deployment location
- enabled status
- trust state
- data classifications handled
- identities used
- reachable services
- tools or capabilities exposed
- parent and child relationships
- last observed activity
- last review date
- next review or expiration date
- rollback version
- removal procedure

### Suggested Trust States

- `approved`
- `approved_with_restrictions`
- `unmanaged`
- `unknown`
- `inactive`
- `expired`
- `quarantined`
- `revoked`

### Unmanaged AI Detection

The registry should compare approved inventory with observed runtime activity. A component should be flagged when it:

- appears in telemetry but is not registered
- runs an unapproved version
- uses an unknown identity
- accesses a resource outside its approved scope
- exposes a new tool or endpoint
- changes its parameter schema or declared capabilities
- remains active after approval expiration

Example finding:

```json
{
  "finding_type": "unmanaged_ai_component",
  "component_type": "tool_server",
  "observed_identity": "runtime-worker-17",
  "trust_state": "unknown",
  "first_seen": "",
  "last_seen": "",
  "recommended_action": "Quarantine access and complete ownership and capability review"
}
```

---

## 2. AI Activity Relationship Graph

### Gap

Static inventory answers what is configured. It does not show which user, workload, agent, model, tool, resource, and output destination participated in a real operation.

### Proposed Component

Add a future **AI Activity Relationship Graph**.

```text
Actor Identity
      |
      v
AI Request
      |
      v
Agent or Workflow
      |
      v
Model Route
      |
      v
Tool Server and Tool
      |
      v
Asset, Repository, Evidence, or Data
      |
      v
Output Artifact
      |
      v
Destination or Publisher
```

### Suggested Node Types

- user identity
- workload identity
- AI request
- agent
- child agent
- workflow
- model
- tool server
- tool
- evidence source
- asset
- repository
- knowledge record
- output artifact
- destination
- approval record
- publisher identity

### Suggested Edge Types

- `invoked`
- `routed_to`
- `used_model`
- `requested_tool`
- `delegated_to`
- `authenticated_as`
- `accessed_resource`
- `read_from`
- `wrote_to`
- `generated`
- `validated_by`
- `approved_by`
- `published_to`
- `originated_from`

### Required Uses

The graph should answer:

- Which actor initiated this operation?
- Which agent and model processed it?
- Which tools were called?
- Which sensitive resources were read?
- Which destination received the output?
- Did a child worker receive broader permissions than its task required?
- Did the workflow cross a trust or data-classification boundary?

This graph should integrate with the broader Exposure Path Analyzer rather than become an unrelated telemetry store.

---

## 3. Agent Permission Path Analyzer

### Gap

An individual permission can look reasonable while a combination of permissions creates a critical data-leak path.

The highest-risk pattern is:

```text
Untrusted Input
      +
Sensitive Read Access
      +
Lower-Trust or Public Write Access
```

An agent that combines these capabilities can be manipulated into bridging data between trust zones even when each permission was approved separately.

### Proposed Component

Add a future **Agent Permission Path Analyzer**.

It should evaluate:

- input trust level
- readable resources
- writable resources
- output destinations
- public or external channels
- data classifications
- delegation paths
- inherited permissions
- publisher identities
- approval requirements
- redaction gates
- security-validation stages

### Example Permission Path

```text
Public Untrusted Content
          |
          v
Read-Only Analysis Agent
          |
          +--> Confidential Evidence Store
          |
          `--> Public Output Destination
```

### Required Policy Rule

> An agent that consumes untrusted content must not be able to read higher-trust information and publish to a lower-trust destination without deterministic policy enforcement, output validation, and a separately authorized publisher.

### Suggested Finding

```json
{
  "finding_type": "agent_permission_path",
  "severity": "critical",
  "input_boundary": "public_untrusted",
  "sensitive_read_scope": ["restricted_evidence"],
  "write_scope": ["public_destination"],
  "path_status": "policy_confirmed",
  "controls_present": [],
  "recommended_controls": [
    "remove cross-scope read access",
    "remove direct publishing authority",
    "add deterministic output inspection",
    "require a separate publisher identity",
    "require explicit approval"
  ]
}
```

### Path Evaluation Inputs

A future risk score should consider:

- input trust
- data sensitivity
- destination trust
- direct versus delegated access
- whether the path is deterministic or inferred
- approval presence
- redaction status
- output scanning status
- tool and model trust state
- whether the path crosses tenant boundaries
- whether controls fail closed

---

## 4. Trust-Labeled Context Assembly

### Gap

The model context is an attack surface. Issue text, comments, documents, retrieved memory, external enrichment, repository files, and tool output may contain malicious instructions.

### Proposed Extension

Extend the Evidence Context Engine so every context object carries explicit trust and instruction metadata.

### Suggested Trust Classes

- `system_policy`
- `operator_instruction`
- `approved_workflow_instruction`
- `trusted_configuration`
- `verified_evidence`
- `deterministic_derivation`
- `external_enrichment`
- `user_supplied_data`
- `public_untrusted_content`
- `tool_output_untrusted`
- `assistant_memory_non_authoritative`

### Context Object Fields

- context object identifier
- source
- source actor
- tenant scope
- trust class
- data classification
- whether it may contain instructions
- whether it may influence authorization
- whether it may be quoted to a model
- allowed destinations
- required sanitization
- expiration
- evidence references
- integrity digest

### Required Separation

```text
Instructions
  = authenticated policy and approved operator intent

Evidence
  = data to analyze

Untrusted Content
  = data that must never grant permission or alter policy
```

### Enforcement Rules

- Evidence text must not alter tool allowlists.
- Tool output must not grant access to another tenant.
- Retrieved memory must not override current evidence.
- External enrichment must not become policy.
- A model must not infer authorization from natural-language content.
- Authorization must be determined by deterministic code before model execution.
- Context assembly must minimize data and exclude unrelated sensitive records.

### Example Context Envelope

```json
{
  "context_id": "context-901",
  "trust_class": "public_untrusted_content",
  "data_classification": "public",
  "may_contain_instructions": true,
  "may_influence_authorization": false,
  "allowed_destinations": ["internal_analysis_only"],
  "sanitization_required": true,
  "source_ref": "external-content-18"
}
```

---

## 5. Safe Output Gate

### Gap

Human approval inside an agent runtime is not sufficient when the same runtime also possesses publication authority. The system should separate generation, inspection, approval, and publication.

### Proposed Architecture

```text
Read-Only Agent or Workflow
          |
          v
Candidate Output Artifact
          |
          v
Deterministic Schema Validation
          |
          v
Secret and Sensitive-Data Scan
          |
          v
Injection and Malicious-Content Scan
          |
          v
Policy and Destination Check
          |
          v
Human Approval When Required
          |
          v
Separate Publisher Identity
          |
          v
Approved Destination
```

### Candidate Output Types

- reports
- support responses
- tickets
- code changes
- pull requests
- comments
- notifications
- configuration suggestions
- policy drafts
- workflow definitions
- exported files

### Required Rule

> The identity that generates content must not automatically possess the authority to publish or apply it.

### Output Artifact Contract

```json
{
  "artifact_id": "artifact-123",
  "task_id": "task-456",
  "artifact_type": "report",
  "content_digest": "sha256:",
  "destination_class": "internal",
  "generated_by": "agent-role-reporting",
  "validation_state": "pending",
  "contains_sensitive_data": false,
  "approval_required": true,
  "publisher_scope": "report-publish-only",
  "expires_at": ""
}
```

### Validation Stages

The Safe Output Gate should perform:

- type and schema validation
- destination allowlist validation
- tenant-scope validation
- secret scanning
- restricted-data scanning
- unsupported-claim checks
- malicious-link checks where applicable
- prompt-injection and hidden-instruction checks
- policy-marker removal checks
- evidence-reference validation
- output-size limits
- content-digest generation

### Publisher Identity

The publisher should receive only:

- approved artifact identifier
- expected content digest
- destination
- narrow publication capability
- approval record
- expiration

It must not receive:

- the model credential
- broad tool access
- unrestricted evidence access
- the complete model context
- the ability to alter the approved artifact silently

---

## 6. Independent Security-Validation Budget

### Gap

If a primary agent exhausts the shared runtime, token, storage, or compute budget, the system may be unable to inspect its final output safely.

### Proposed Requirement

Every action-capable or externally publishing workflow should reserve a separate security-validation budget.

```yaml
execution_budgets:
  primary_analysis:
    max_runtime_seconds: 120
    max_model_tokens: 12000
    max_tool_calls: 20

  security_validation:
    reserved: true
    max_runtime_seconds: 30
    max_model_tokens: 3000
    max_artifact_bytes: 1048576

  publication:
    max_runtime_seconds: 15
    max_attempts: 1
```

### Reserved Functions

Independent capacity should exist for:

- output validation
- sensitive-data scanning
- policy evaluation
- threat detection
- approval recording
- audit persistence
- cancellation
- cleanup

Security validation must fail closed when its reserved capacity is unavailable.

---

## 7. Protected Control Artifact Registry

### Gap

Prompts, tool definitions, routing policies, workflow graphs, approval rules, and redaction policies can change agent behavior without application-code changes.

### Proposed Component

Add a future **Protected Control Artifact Registry**.

### Protected Artifact Types

- system prompts
- agent role definitions
- task templates
- model-routing policy
- tool manifests
- tool allowlists
- output-destination policy
- approval policy
- redaction rules
- workflow graphs
- sandbox profiles
- integration manifests
- trust labels
- security test fixtures
- publisher permissions

### Required Metadata

- artifact identifier
- type
- owner
- approver
- repository path or storage location
- version
- digest
- active version
- last change
- review status
- rollback version
- runtime verification status

### Required Controls

- version control
- protected review
- checksum or signature verification
- change approval
- drift detection
- rollback
- audit logging
- runtime integrity verification
- automatic disablement when critical drift is detected

Example policy:

```yaml
protected_artifact:
  path: policies/ai/tool-access.yaml
  change_requires:
    - security_review
    - designated_owner_approval
  runtime_drift_action: disable_affected_workflow
```

---

## 8. Agent-Specific Static Analysis and CI Security Gates

### Gap

General source scanners often do not understand agent tool boundaries, tool configuration, prompt construction, delegation, or approval bypass paths.

### Proposed Deliverable

Create a future **Agent Security Static Analysis Rule Set** and CI gate.

### Required Detection Categories

#### Tool-boundary data flow

Detect untrusted data flowing from:

- user input
- public content
- retrieved documents
- tool output
- external enrichment
- assistant memory

into sensitive sinks such as:

- process execution
- dynamic evaluation
- database queries
- filesystem writes
- network calls
- tool invocations
- memory persistence
- public output

#### Prompt and context construction

Detect:

- raw user input inserted into system instructions
- policy and evidence concatenated without trust separation
- untrusted tool descriptions treated as instructions
- missing context trust labels
- retrieval results written to memory automatically

#### Tool and integration configuration

Detect:

- missing authentication
- unpinned integrations
- broad filesystem permissions
- unrestricted network access
- hardcoded credentials
- excessive environment-variable exposure
- unsafe installation hooks
- dynamic downloads
- unknown provenance
- configuration drift from an approved baseline

#### Agent controls

Detect:

- missing iteration limits
- missing timeouts
- missing cancellation
- unrestricted code execution
- auto-approval of all tools
- human-approval bypass
- self-modifying permissions
- trace or attribution suppression

#### Delegation

Detect:

- child agent inherits all parent permissions
- child agent can expand scope
- child agent can add integrations
- delegation without authenticated identity
- child agent can bypass approval
- child agent can write authoritative memory without validation

### CI Requirements

The scanner should support:

- structured JSON output
- standard security-report export
- severity thresholds
- fail-on-new behavior
- saved baselines
- suppressions with written justification
- file and line attribution
- stable rule identifiers
- regression fixtures
- separate informational, warning, and blocking tiers

### Baseline Adoption

A baseline should allow the project to block new regressions without claiming that historical warnings are acceptable. Existing findings should retain owners and remediation plans.

---

## 9. Tool Identity Collision, Shadowing, and Drift

### Gap

Display names are not sufficient tool identities. A malicious or accidental integration may register a duplicate or deceptively similar tool name.

### Canonical Tool Identity

A tool should be identified by:

- integration identifier
- canonical tool identifier
- publisher or source
- version
- digest
- transport
- parameter schema digest
- declared capabilities
- approved behavior profile

Example:

```json
{
  "canonical_tool_id": "integration-12/tool-read-asset",
  "display_name": "read_asset",
  "version": "1.2.0",
  "digest": "sha256:",
  "schema_digest": "sha256:",
  "trust_state": "approved",
  "namespace": "inventory.read"
}
```

### Required Detection

The Tool Gateway should block or require review when:

- an unapproved tool claims an approved display name
- a tool registers a confusingly similar name
- a description changes after approval
- a parameter schema changes
- declared behavior changes
- a package digest changes
- a new server claims an established namespace
- the observed tool list differs from the approved baseline

### Runtime Resolution

Agents should receive canonical identifiers and policy-filtered descriptions. Display names should be treated as presentation metadata only.

---

## 10. Scoped Child-Agent Privileges

### Gap

Delegated workers can become privilege-escalation paths when they inherit the full authority of the parent.

### Required Rule

> A child agent may receive less authority than its parent, never more.

### Required Child Task Envelope

```json
{
  "task_id": "task-123",
  "parent_task_id": "task-100",
  "agent_role": "evidence_review",
  "tenant_id": "tenant-1",
  "resource_scope": ["asset-123"],
  "allowed_tools": ["read_asset", "read_findings"],
  "allowed_destinations": ["parent_task_only"],
  "external_integrations_allowed": false,
  "max_runtime_seconds": 45,
  "max_tool_calls": 8,
  "result_schema": "evidence_review.v1"
}
```

### Delegation Controls

- authenticated parent and child identities
- explicit task purpose
- explicit tenant and resource scope
- independent tool allowlist
- no direct credential inheritance
- no external integrations unless separately approved
- bounded runtime and tool calls
- result schema validation
- cancellation propagation
- immutable parent policy ceiling
- audit event for spawn, completion, cancellation, and failure

### Privilege-Difference Check

Before starting a child, the scheduler should compare parent and child privileges and reject any unauthorized expansion.

---

## 11. Policy-Filtered Capability Discovery

### Gap

Large tool catalogs consume model context and may expose capabilities that are irrelevant or unauthorized.

### Proposed Architecture

```text
Agent Task
    |
    v
Authorization and Tenant Filter
    |
    v
Trust and Risk Filter
    |
    v
Capability Relevance Index
    |
    v
Bounded Tool Set
    |
    v
Agent Context
```

### Required Ordering

1. tenant authorization
2. actor and role authorization
3. integration approval state
4. tool-risk policy
5. task compatibility
6. semantic relevance

Semantic retrieval must never make an unauthorized tool visible.

### Capability Record

- canonical tool identifier
- capability tags
- risk class
- read or write behavior
- required approval
- supported data classes
- tenant eligibility
- integration trust state
- parameter schema
- expected result schema

---

## 12. AI-Generated Artifact Provenance

### Gap

AI-generated code, reports, policies, workflows, and configuration should be reviewable without relying on unreliable authorship detection.

### Proposed Metadata

- artifact identifier
- artifact type
- generated by human, deterministic template, or AI
- task identifier
- agent identifier
- model identifier and version
- policy version
- evidence references
- generation timestamp
- original content digest
- final content digest
- validation steps performed
- security scans performed
- human reviewer
- approval state
- publisher identity
- destination
- post-generation modifications

### Supported Artifacts

- reports
- queries
- code suggestions
- detection rules
- configuration templates
- policy drafts
- workflow definitions
- remediation instructions
- tickets and comments

AI provenance must not replace normal code review, security testing, or approval.

---

## 13. Verified and Expiring Enrichment Knowledge

### Gap

Hybrid vulnerability research can combine deterministic rules, structured advisories, semantic retrieval, and external research. Automatically saving external search results into trusted long-term memory creates a poisoning and staleness risk.

### Proposed Pipeline

```text
Deterministic Rules
       +
Structured Security Sources
       +
Semantic Retrieval
       +
Optional External Research
       |
       v
Candidate Enrichment
       |
       v
Source Validation
       |
       v
Product and Version Mapping
       |
       v
Expiration and Refresh Policy
       |
       v
Approved Knowledge Record
```

### Required Knowledge Fields

- knowledge record identifier
- source identifier
- source location
- retrieval date
- content digest
- source trust class
- affected product identifiers
- affected version range
- evidence excerpts or structured facts
- validation status
- corroborating sources
- contradictions
- tenant applicability
- expiration date
- refresh schedule
- last reviewer

### Suggested States

- `candidate`
- `verified`
- `corroborated`
- `contradicted`
- `expired`
- `rejected`

### Required Rules

- External research must not become authoritative automatically.
- Search results must be treated as untrusted input.
- Knowledge must expire or refresh.
- Contradictory sources must remain visible.
- Product and version matching must be deterministic where possible.
- AI may summarize evidence but must not manufacture affected-version claims.

---

## 14. Public and External Output Policy

### Gap

A generic write permission does not express whether a destination is internal, tenant-private, external, or public.

### Destination Trust Classes

- `internal_private`
- `tenant_private`
- `approved_partner`
- `external_restricted`
- `public`

### Output Policy Inputs

- artifact data classification
- destination trust class
- actor
- publisher identity
- tenant
- evidence sources
- redaction status
- approval status
- artifact digest
- expiration

### Required Denials

The system should deny publication when:

- the destination is lower trust than the artifact classification permits
- secret scanning fails
- validation is incomplete
- the approved digest does not match
- the approval expired
- the publisher identity exceeds its narrow scope
- tenant ownership is ambiguous
- untrusted content remains embedded as executable instructions

---

## 15. Runtime Permission and Egress Monitoring

### Gap

Static review cannot detect every dynamic behavior or permission-path change.

### Proposed Runtime Signals

- input trust class
- resources read
- tools requested
- files written
- network destinations
- output destinations
- publisher calls
- child-agent delegation
- credential proxy use
- policy denials
- redaction events
- artifact digest changes

### Runtime Outcomes

- allow
- allow with redaction
- require approval
- block tool call
- block publication
- cancel child task
- quarantine integration
- disable affected workflow

Runtime monitoring is a secondary control and does not replace static analysis, authorization, sandboxing, or review.

---

## 16. Proposed Architecture

```text
Authenticated Actor
        |
        v
Typed AI Task Request
        |
        v
Governance and Permission Policy
        |
        +------------------------------+
        |                              |
        v                              v
Trust-Labeled Context Engine    AI Component Registry
        |                              |
        v                              v
Read-Only Agent Runtime       Activity Relationship Graph
        |                              |
        v                              v
Policy-Filtered Tool Gateway  Permission Path Analyzer
        |
        v
Candidate Output Artifact
        |
        v
Safe Output Gate
  |-- schema validation
  |-- evidence validation
  |-- secret and data scan
  |-- malicious-content scan
  |-- destination policy
  `-- approval
        |
        v
Separate Publisher Identity
        |
        v
Approved Destination
```

Cross-cutting controls:

- tenant isolation
- immutable policy ceilings
- canonical component and tool identities
- protected control artifacts
- independent validation budgets
- provenance
- bounded execution
- cancellation
- audit and replay
- retention and expiration

---

## 17. Implementation Roadmap

### Phase A: Architecture Contracts

- define AI component schema
- define trust-labeled context schema
- define canonical tool identity
- define output artifact contract
- define destination trust classes
- define child-task privilege envelope
- define knowledge-record lifecycle

### Phase B: Inventory and Integrity

- register models, agents, tools, workflows, and publishers
- add ownership and review status
- add protected control artifact digests
- detect version and schema drift
- identify unmanaged runtime components

### Phase C: Permission and Context Controls

- add permission-path evaluation
- label all context inputs
- prevent evidence from influencing authorization
- add privilege-difference checks for child workers
- add policy-filtered capability discovery

### Phase D: Safe Output Publication

- create candidate output artifacts
- add deterministic validation
- add secret and data-classification scanning
- add approval records
- add separate narrow publisher identities
- enforce digest matching

### Phase E: Agent Security CI

- add tool-boundary taint rules
- add prompt and context construction rules
- scan tool and integration configuration
- add delegation and approval-bypass rules
- support baseline and fail-on-new behavior
- publish structured security results

### Phase F: Runtime Correlation

- build AI activity graph
- correlate input, reads, tools, outputs, and destinations
- detect dynamic permission paths
- add runtime publication blocking
- integrate findings with the Exposure Path Analyzer

### Phase G: Verified Knowledge

- add candidate enrichment records
- require source, digest, and retrieval date
- add verification and contradiction states
- add expiration and refresh
- prevent automatic promotion from search result to trusted knowledge

---

## 18. Acceptance Criteria

The first production-capable implementation should not be considered complete until:

- every AI component has an owner, version, digest, and trust state
- observed components can be reconciled against the approved registry
- context objects carry trust and data classifications
- untrusted content cannot modify authorization
- permission paths are evaluated across input, read, and write boundaries
- child-agent authority cannot exceed the parent policy ceiling
- tools use canonical identities and drift detection
- action-capable outputs pass an independent Safe Output Gate
- generation and publication identities are separate
- validation retains independent reserved resources
- protected control artifacts are integrity checked
- agent-specific CI rules block new high-risk regressions
- AI-generated artifacts preserve provenance
- external enrichment records have source, validation, and expiration metadata
- deterministic collection, findings, and reports remain functional without AI

---

## 19. Explicitly Rejected Capabilities

This architecture does not authorize:

- autonomous exploitation
- arbitrary command execution
- unrestricted terminal access
- credential harvesting
- credential cracking
- remote shell management
- command-and-control features
- self-expanding agent privileges
- child agents adding their own tools or integrations
- automatic publication to public destinations
- unrestricted external research over arbitrary targets
- silent external processing
- automatic promotion of search results into trusted knowledge
- AI modification of approval or routing policy

---

## Final Position

The most important new control is permission-path analysis across untrusted input, sensitive reads, and lower-trust writes. The most important workflow control is separation between read-only content generation and narrowly authorized publication.

Together with trust-labeled context, protected control artifacts, canonical tool identity, scoped child workers, agent-specific CI scanning, provenance, and expiring enrichment knowledge, these requirements close major security gaps without changing OpenAssetWatch's passive-first, evidence-first, and advisory-first mission.
