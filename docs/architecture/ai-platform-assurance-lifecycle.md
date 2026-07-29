# AI Platform Assurance and Intelligence Lifecycle

## Purpose

This document extends the OpenAssetWatch AI and defensive-intelligence architecture with provider-neutral assurance requirements for policy compilation, threat-model lifecycle, agent autonomy, deterministic finding enrichment, evidence reproducibility, model reliability, sandbox posture, tool identity, network egress, rollback, and incident response.

The design records reusable architecture patterns identified through public research. It does not reproduce third-party branding, diagrams, implementation details, performance claims, or source-project names.

This is a future-build design. It does not authorize autonomous remediation, arbitrary command execution, unrestricted scanning, exploitation, or direct publication by an AI agent.

## Relationship to Existing Architecture

This document complements:

- `local-agentic-ai-design.md`
- `defensive-ai-security-gap-backlog.md`
- `ai-agent-permission-output-security.md`
- `experimental-external-ai-support.md`

Those documents define routing, scheduling, specialist agents, exposure paths, integration review, permission-path analysis, and safe publication. This document focuses on the assurance lifecycle that makes those components inspectable, reproducible, enforceable, and recoverable.

## Core Principles

1. Human-friendly policy must compile into a fully resolved runtime contract.
2. Runtime enforcement must not depend on natural-language instructions.
3. Untrusted content remains untrusted even when it is inside a valid schema.
4. Threat models, policies, evidence, and execution manifests must be versioned artifacts.
5. Detection, confidence, severity, reachability, and visibility are separate concepts.
6. Intelligence enrichment should be additive, deterministic where possible, and independently versioned.
7. Missing coverage, unavailable analyzers, truncation, and degraded isolation must be reported explicitly.
8. Security controls fail closed when the requested protection cannot engage.
9. AI outputs are advisory artifacts until deterministic validation and approval complete.
10. Every long-running agent or worker must have an owner, lease, stop condition, and kill switch.
11. Trust decisions must resist downgrade, drift, tool shadowing, and policy weakening.
12. Rollback and audit records are security controls, not convenience features.

## Target Architecture

```text
Operator Policy and Environment Security Context
                        |
                        v
             Policy and Manifest Compiler
                        |
                        v
          Resolved Capability Manifest + Digest
                        |
                        v
          Orchestrator / Scheduler / Agent Runtime
                        |
              +---------+----------+
              |                    |
              v                    v
     Strict Isolation Layer     Model-Only Route
              |
              v
        Tool and Egress Gateway
              |
              v
      Canonical Evidence and Findings
              |
              v
       Finding Intelligence Pipeline
              |
              v
 Evidence Bundle / Coverage / Replay / Scorecards
              |
              v
           Safe Output Gate
              |
              v
       Approved Publisher or Report

Cross-cutting controls:
- component and activity registry
- permission-path analysis
- append-oriented audit integrity
- rollback and recovery
- incident response and revocation
- coverage and quality regression
```

---

## 1. Policy Authoring and Resolved Capability Manifests

### Gap

Human-authored policies may use inheritance, reusable groups, aliases, defaults, and environment-specific overrides. Those features are useful for maintainers but are dangerous if the runtime must interpret them while executing an agent task.

OpenAssetWatch needs a deterministic boundary between policy authoring and enforcement.

### Proposed Components

Add a future **Policy Compiler** and **Resolved Capability Manifest**.

```text
Human-Authored Policy
  |-- reusable groups
  |-- inheritance
  |-- deployment overrides
  |-- comments and descriptions
          |
          v
Policy Compiler
  |-- resolve inheritance
  |-- expand groups
  |-- apply deny precedence
  |-- validate schemas
  |-- calculate digests
          |
          v
Resolved Capability Manifest
  |-- no inheritance
  |-- no aliases
  |-- no hooks
  |-- no unresolved defaults
  `-- enforcement-relevant fields only
```

### Required Manifest Domains

A resolved manifest should describe:

- actor and workload identity
- tenant and resource scope
- task type and autonomy mode
- model and route eligibility
- tool identifiers and versions
- filesystem read, write, and read-write grants
- explicit denied paths
- network mode
- permitted hosts, ports, methods, and paths
- local IPC permissions
- credential routes
- process and subprocess permissions
- command argument restrictions
- environment-variable allowlist
- output destination classes
- execution and cost budgets
- approval requirements
- audit level
- rollback eligibility
- expiration
- revocation state

### Suggested Manifest Envelope

```json
{
  "manifest_version": "1.0.0",
  "manifest_id": "capability-manifest-123",
  "task_id": "task-456",
  "tenant_id": "tenant-1",
  "actor_id": "agent-risk-review",
  "autonomy_mode": "delegated_read_only",
  "resource_scope": ["asset-123"],
  "filesystem": {
    "read": ["/workspace/evidence"],
    "write": ["/workspace/output"],
    "deny": ["/workspace/secrets"]
  },
  "network": {
    "mode": "proxy",
    "allow": [
      {
        "host": "approved-source.example",
        "port": 443,
        "methods": ["GET"],
        "paths": ["/advisories/*"]
      }
    ]
  },
  "tools": ["inventory.read", "findings.read"],
  "credentials": [],
  "destinations": ["parent_task_only"],
  "budgets": {
    "max_runtime_seconds": 60,
    "max_tool_calls": 8,
    "max_output_bytes": 262144
  },
  "approval_required": false,
  "expires_at": "",
  "source_policy_digests": ["sha256:"],
  "manifest_digest": "sha256:"
}
```

### Runtime Rules

- Runtime components should consume only resolved manifests.
- A manifest must be immutable for the life of one task.
- Any privilege increase requires a new manifest and new authorization decision.
- Deny rules take precedence over allow rules.
- A missing or empty allowlist means deny all for that capability domain.
- Lower-precedence policy must not weaken a higher-precedence restriction.
- Manifest parsing, lookup, signature, and schema errors fail closed.
- The manifest digest must appear in audit and replay records.

### Explainability and Dry Run

The compiler should support:

- `why_allowed`
- `why_denied`
- policy source tracing
- effective-permission diff
- dry-run simulation
- privilege-expansion warnings
- manifest export for review

The operator should be able to see exactly which rule produced each effective capability.

---

## 2. Security Policy Merge and Non-Overridable Deny Floors

### Gap

Policy composition can accidentally weaken security when local overrides, tenant policy, integration defaults, and emergency restrictions are merged without explicit precedence.

### Required Merge Law

OpenAssetWatch should apply these rules:

1. Emergency deny policy wins over every other layer.
2. Tenant policy may narrow deployment policy but may not widen it.
3. Task policy may narrow tenant policy but may not widen it.
4. Child-agent policy may narrow parent policy but may not widen it.
5. Tool policy may narrow agent policy but may not widen it.
6. A blocklist wins over an otherwise trusted signature or allowlist.
7. Security-relevant merge conflicts fail closed.

### Non-Overridable Deny Floor

The platform should have a deny floor for destinations and capabilities that normal configuration cannot override, such as:

- cloud instance metadata endpoints
- link-local metadata services
- loopback access from a sandbox unless explicitly required for local IPC
- private or reserved addresses from external-enrichment routes
- raw socket and packet access
- host container-management sockets
- credential stores
- collector enrollment secrets
- cross-tenant resource access
- direct database credentials for agents
- publication to public destinations from a generation identity

An emergency administrator may modify the deny floor only through a separately protected change process.

---

## 3. Environment Threat Model as a Managed Artifact

### Gap

Threat-model context can become vague conversation text, disappear with model context, or remain stale after the environment changes.

### Proposed Artifact Pair

For each deployment or environment, maintain:

- a canonical machine-readable security-context file
- a human-readable rendered document

The machine-readable version is authoritative. The human-readable version is generated for review and discussion.

### Suggested Content

- critical assets and business services
- entry points
- external exposure boundaries
- network and identity trust boundaries
- trusted inputs
- untrusted inputs
- expected communication paths
- prohibited communication paths
- in-scope risk classes
- explicitly deferred or out-of-scope classes
- focus areas
- known issue shapes and recurring patterns
- minimum evidence requirements
- verification expectations
- remediation retest expectations
- data classifications
- compensating controls

### Lifecycle States

- `draft`
- `active`
- `stale`
- `refresh_required`
- `invalid`
- `retired`

### Freshness and Drift

The system should calculate a context digest from relevant topology, policy, critical-asset, identity, and exposure inputs.

When the environment changes materially:

- mark the context stale
- identify the changed inputs
- prevent high-impact analysis from silently using stale context
- require explicit operator acceptance when a stale model must be used temporarily
- record the exception in audit and replay data

### Important Boundary

The environment threat model may:

- change analysis priority
- narrow or expand focus areas
- supply expected controls
- influence verification requirements

It must not serve as proof that a finding exists. Findings still require current evidence.

---

## 4. Goal, Scope, Consent, and Autonomy Contract

### Gap

An agent may receive a natural-language request without a durable statement of objective, scope, success criteria, prohibited actions, or operator consent.

### Proposed Goal Contract

Every agent task should include:

- authenticated requester
- business or operator objective
- tenant and environment
- asset and evidence scope
- allowed task class
- prohibited actions
- data classifications
- permitted tools
- permitted destinations
- success criteria
- evidence requirements
- stop conditions
- execution budgets
- approval requirements
- consent record
- expiration

### Suggested Autonomy Modes

- `explain_only` — model-only explanation; no tools
- `guided_read_only` — user remains in the loop while approved read tools are used
- `delegated_read_only` — bounded read-only task runs without turn-by-turn approval
- `scheduled_background` — approved recurring read-only job
- `approval_gated_action` — future narrow action after separate validation and approval
- `denied` — outside policy or project scope

OpenAssetWatch should not provide an unrestricted autonomous-active mode.

### Consent and Invocation Rules

- Auto-invocation is disabled by default.
- Recurring jobs require explicit schedule ownership and expiration.
- A task must be re-authorized when scope, tool set, destination, or autonomy mode changes.
- The system should not infer consent from previous conversations.
- The requester must be able to cancel or revoke a running task.
- A tool call that changes risk class requires a new authorization check.

### Goal Revalidation Points

Revalidate the goal contract before:

- tool execution
- child-agent delegation
- external processing
- sensitive evidence retrieval
- public or external publication
- conversion from read-only to action-capable behavior

---

## 5. Capability Triad Guard

### Gap

The most dangerous agent sessions combine three capabilities:

1. processing untrusted input
2. accessing sensitive resources or state-changing tools
3. communicating externally or changing state outside the isolated workspace

### Proposed Rule

An agent session should normally possess no more than two of these three capability classes.

```text
A. Untrusted Input
B. Sensitive or State-Changing Access
C. External or Persistent Output
```

A session that requires all three must:

- use a narrowly resolved capability manifest
- run in strict isolation
- reserve independent security-validation capacity
- pass deterministic output validation
- require explicit human approval
- use a separate publisher identity
- have an immediate kill switch

Where practical, split the workflow so no single runtime holds all three capabilities.

### Capability Matrix

The AI Component Registry should store A/B/C values for each agent role and workflow. Changes that move a component from one or two classes into all three should be treated as a critical privilege expansion.

### Checker Isolation

Validation and checker agents should receive:

- validated summaries
- canonical findings
- bounded evidence references

They should not receive raw untrusted content when a validated representation can satisfy the task.

---

## 6. Agent Lifecycle, Leases, and Kill Switches

### Gap

Background agents and child workers can continue running after the user leaves, after the parent fails, or after policy is revoked.

### Required Lifecycle Metadata

- execution identifier
- owner
- parent execution
- task purpose
- manifest digest
- start time
- lease expiration
- heartbeat interval
- last heartbeat
- current state
- current budget use
- cancellation state
- cleanup state
- output artifact references

### Suggested States

- `created`
- `authorized`
- `queued`
- `starting`
- `running`
- `waiting_for_approval`
- `background_running`
- `cancelling`
- `cancelled`
- `completed`
- `failed`
- `hard_timeout`
- `orphaned`
- `quarantined`

### Required Controls

- maximum reasoning iterations
- maximum tool calls
- maximum child workers
- maximum runtime
- maximum cost
- maximum evidence records
- no-progress detection
- repeated-action detection
- bounded retries
- cancellation propagation
- parent-death handling
- orphan reconciliation
- automatic cleanup

### Kill Switch Levels

- global AI kill switch
- tenant kill switch
- component kill switch
- workflow kill switch
- tool kill switch
- publisher kill switch
- external-processing kill switch

Kill switches must be deterministic and must not depend on a model cooperating.

### Background Worker Rules

Every background worker must have:

- a named owner
- a documented purpose
- an expiration
- a bounded schedule
- a revocation path
- a health signal
- a cleanup procedure

A background worker without a current lease should stop and be reconciled as orphaned.

---

## 7. Authenticated Inter-Agent Communication and History Integrity

### Gap

Multi-agent systems may accept messages from unauthenticated children, replay old task messages, deserialize unsafe objects, or trust modified conversation history.

### Task Message Envelope

```json
{
  "message_id": "message-123",
  "task_id": "task-456",
  "parent_task_id": "task-100",
  "sender_identity": "agent-evidence-review",
  "recipient_identity": "agent-reporting",
  "tenant_id": "tenant-1",
  "sequence": 4,
  "issued_at": "",
  "expires_at": "",
  "nonce": "",
  "payload_schema": "finding-handoff.v1",
  "payload_digest": "sha256:",
  "signature": ""
}
```

### Required Controls

- authenticated sender and recipient
- encrypted transport when messages cross process or host boundaries
- message expiration
- nonce or replay protection
- monotonically increasing sequence where appropriate
- schema validation
- payload-size limits
- safe serialization only
- no arbitrary object deserialization
- tenant and task binding
- message and response audit events

### History Integrity

Conversation and workflow history should include:

- append-oriented event records
- event sequence numbers
- content digests
- actor identity
- source classification
- correction and supersession records
- tamper and truncation detection

History is context, not authority. Current evidence and policy override recalled conversation state.

---

## 8. Canonical Finding and Additive Intelligence Engine Contract

### Gap

Each new detector can create its own output shape, scoring behavior, and duplicate-handling logic. This increases coupling and makes confidence and evidence inconsistent.

### Proposed Contract

Every detector should emit a **Canonical Finding**. Detectors identify candidate conditions; they should not directly invoke downstream intelligence engines.

```text
Detector
   |
   v
Canonical Finding
   |
   v
Shared Intelligence Pipeline
```

### Minimum Canonical Fields

- finding identifier
- title
- category
- original severity
- detector identifier and version
- affected assets or resources
- observed timestamps
- source records
- raw evidence references
- rule identifier
- standards mappings where justified
- coverage state
- limitations

### Shared Intelligence Pipeline

```text
Canonical Finding
    |
    v
Ownership Resolution
    |
    v
Confidence Calculation
    |
    v
Evidence Aggregation and Selection
    |
    v
Triage and Visibility
    |
    v
Finding Fusion
    |
    v
Posture and Relationship Analysis
    |
    v
Reachability
    |
    v
Exposure Paths
    |
    v
Deterministic Explanation and Reporting
```

### Intelligence Engine Contract

Each engine should document:

- purpose
- input schema
- deterministic and non-deterministic dependencies
- processing rules
- output fields
- engine version
- limitations
- failure behavior
- regression fixtures

### Additive-Only Rule

Intelligence engines should:

- add new metadata
- preserve original detector output
- preserve original severity
- preserve source-specific timestamps
- preserve conflicting evidence
- never delete a finding
- never hide an engine failure

A failed enrichment stage should not erase the finding or present the scan as complete without a coverage warning.

---

## 9. Detection Coverage Registry and Blind-Spot Accounting

### Gap

A scanner can report zero findings when an analyzer never ran, a dependency was missing, a file cap was reached, or a timeout truncated the analysis.

### Proposed Component

Add a future **Detection Coverage Registry** and **Coverage Regression Harness**.

### Coverage Entry Fields

- capability identifier
- supported platforms and data sources
- detector and rule versions
- expected evidence types
- expected confidence range
- prerequisites
- external dependencies
- time, file, and size limits
- known blind spots
- reference fixtures
- last verified version
- owner

### Required Coverage States

- `complete`
- `partial`
- `skipped_by_policy`
- `skipped_by_limit`
- `dependency_unavailable`
- `timeout`
- `failed`
- `unsupported`
- `not_applicable`

A non-complete state must include a reason and any limit that was reached.

### Regression Corpus

Maintain a controlled corpus of known conditions that verifies:

- detector coverage does not shrink silently
- evidence quality remains stable
- duplicate handling remains stable
- confidence changes are intentional
- path construction does not over-connect unrelated findings
- false-positive suppressions do not hide protected findings

### Comparison Buckets

A comparison harness may classify results as:

- common
- newly detected
- missing
- duplicate
- changed evidence
- improved evidence
- degraded evidence
- changed severity
- changed confidence

### Control Tower Use

Future coverage views should show:

- enabled capabilities
- unavailable analyzers
- partial analysis
- stale rules
- untested platforms
- missing reference fixtures
- last successful regression
- evidence drift

Zero findings must never be confused with zero coverage.

---

## 10. Confidence, Severity, Reachability, and Visibility Separation

### Gap

A single risk number can blur whether a finding is severe, well-proven, reachable, relevant, or simply visible by default.

### Required Axes

#### Severity

How harmful the condition could be if real and applicable.

#### Confidence

How strongly the current evidence supports the finding.

#### Reachability

Whether a credible path exists from an entry point to the affected condition.

#### Visibility

Whether the finding is highlighted, shown, queued for review, or hidden by default.

#### Priority

How urgently the operator should investigate or remediate it after considering business context and controls.

### Confidence Dimensions

A versioned confidence calculation may include:

- detector precision
- ownership relevance
- evidence quality
- context relevance
- source corroboration
- freshness
- reachability
- exploitability or practical impact signal

The full breakdown and reason should be retained.

### Required Rules

- A high-severity, low-confidence finding becomes a verification task, not an automatic dismissal.
- A low-severity, high-confidence condition may still be useful operational hygiene.
- Reachability may influence priority without overwriting original severity.
- Hidden-by-default findings remain stored and reviewable.
- Multi-source agreement may increase confidence only within a bounded range.
- Metadata conflicts should dampen corroboration bonuses.
- Unresolved evidence should cap confidence.
- Confidence algorithm versions must be stored with results.

---

## 11. Structured Evidence Bundles and Stable Content Hashing

### Gap

Evidence may be scattered across snippets, collector records, imported findings, topology observations, and enrichment responses.

### Proposed Evidence Bundle

```json
{
  "evidence_id": "evidence-bundle-123",
  "version": "1.0.0",
  "items": [],
  "primary_item": "evidence-item-1",
  "evidence_types": [],
  "sources": [],
  "quality": "good",
  "verification_status": "partially_verified",
  "source_availability": "available",
  "reproducible": true,
  "reproduction": {},
  "correlation": [],
  "cross_references": [],
  "content_hash": "sha256:",
  "observed_at": "",
  "item_count": 0
}
```

### Evidence Item Fields

- evidence item identifier
- type
- source
- source record identifier
- asset or finding identifiers
- observed timestamp
- location or locator
- normalized excerpt
- confidence
- source availability
- generated or transformed status
- integrity digest
- metadata

### Quality Bands

- `excellent` — exact, directly resolvable, reproducible evidence
- `good` — strong location and supporting content
- `moderate` — attributable but not fully pinned
- `weak` — heuristic or indirect
- `missing` — no usable evidence

### Verification States

- `verified`
- `partially_verified`
- `source_only`
- `imported_only`
- `generated`
- `needs_review`
- `unknown`

### Stable Hashing

The content hash should derive from normalized evidence content and stable locators. Volatile timestamps should not change the stable evidence identity unless the observed content changed.

This supports:

- golden regression tests
- drift detection
- deduplication
- replay
- before-and-after remediation comparison
- tamper detection

### Audit Separation

Audit and evidence-integrity records must be written outside any directory writable by the analyzed target or untrusted tool. Per-run nonces, sequence numbers, and content hashes should make record injection detectable.

---

## 12. Analysis Run Manifest and Reproducibility Bundle

### Gap

A result cannot be reproduced when the system does not retain which policies, tools, model routes, rules, versions, limits, and coverage states produced it.

### Proposed Run Manifest

Each important analysis should record:

- run identifier
- input artifact and evidence digests
- tenant and environment
- threat-model digest
- capability-manifest digest
- collector and normalization versions
- detector and rule versions
- intelligence-engine versions
- model and runtime identifiers
- tool identifiers and digests
- integration versions
- network mode
- external sources contacted
- limits and budgets
- coverage states
- omissions and truncation
- output artifact digests
- start and completion timestamps
- final status

### Atomic Completion

A run should become `completed` only after:

1. outputs are written to temporary paths
2. schemas validate
3. output digests are calculated
4. the run manifest is written
5. audit persistence succeeds
6. temporary artifacts are atomically promoted

A partially written result should remain `failed` or `partial`, not `completed`.

### Reproducibility Bundle

A portable bundle may include:

- run manifest
- canonical findings
- evidence bundles
- coverage summary
- replay events
- deterministic configuration
- redacted logs
- report artifacts

Secrets, reusable credentials, private keys, and unrelated raw data must be excluded.

---

## 13. Finding Fusion, Root-Cause Clustering, and Variant Review

### Gap

As detectors grow, duplicate findings can inflate risk and obscure the underlying condition.

### Finding Fusion

Fusion should use semantic identity based on:

- issue class
- affected asset or resource
- location or evidence relationship
- rule aliases
- value fingerprint where safe
- time window

### Deterministic Conflict Resolution

- severity: retain all source severities and use the worst supported value for the canonical view
- ownership: use the highest-confidence supported attribution
- location: use the strongest evidence as primary and keep all locations
- category: use a documented precedence table
- timestamps: preserve source-specific first and last seen values
- status: do not let one source silently close another active condition

### Root-Cause Clustering

The system should group findings by shared root cause rather than only by scanner line or source. A cluster should retain:

- member findings
- common evidence
- suspected root cause
- affected assets
- variants
- confidence
- remediation candidate
- validation status

### Variant Review

After a finding is validated, OpenAssetWatch may search existing inventory and evidence for defensively similar conditions. Variant review must remain read-only and scope-bound.

### Remediation and Control Retest

A finding or exposure path should support:

- before-state evidence
- expected control change
- after-state evidence
- path recalculation
- remaining variants
- validation outcome
- regression status

A change is not considered effective merely because configuration changed. The relevant evidence and path should be reassessed.

---

## 14. Exposure-Path Roles and Subset Deduplication

### Gap

Graph correlation can create "finding soup" by connecting every nearby condition.

### Required Path Roles

Each finding or relationship in a path should be classified as:

- `required`
- `supporting`
- `context_only`
- `mitigating`
- `excluded`

### Safe Chaining Rules

- Every required step must have evidence.
- Inferred edges must be labeled and confidence-bounded.
- A path should identify its entry point and potential impact.
- Mitigating controls must be represented, not ignored.
- A longer path must not be preferred merely because it contains more findings.
- Subset paths should be deduplicated when a stronger superset adds no new meaning.
- Path confidence should explain which step limits the result.
- The system must not claim exploitation or compromise.

---

## 15. Model Reliability Scorecards and Calibrated Aggregation

### Gap

Model quality varies by task type. Majority vote among models may amplify shared errors, and a model should not grade itself.

### Proposed Components

- **Verified Outcome Ledger**
- **Model Reliability Scorecard**
- **Replay Evaluation Harness**
- **Calibrated Aggregation Layer**

### Verified Outcome Ledger

A verified outcome should include:

- task class
- candidate result
- ground-truth or human-validated outcome
- supporting evidence
- validator identity
- validation method
- date
- applicable policy and schema versions

### Reliability by Task Class

Track reliability separately for tasks such as:

- classification
- evidence summarization
- finding explanation
- relationship analysis
- remediation writing
- report generation
- structured extraction

A model may be reliable for one class and weak for another.

### Aggregation Requirements

When multiple models or agents evaluate the same result, record:

- panel size
- member verdicts
- member reliability for the task class
- agreement and disagreement
- calibrated probability or confidence
- uncertainty interval
- aggregation method
- fallback reason
- convergence state

### Required Boundaries

- Do not treat majority vote as ground truth.
- Use validated outcomes to update scorecards.
- Preserve dissent and uncertainty.
- A validator should be operationally independent from the producer where practical.
- Model diversity is defense-in-depth, not a security boundary.
- Schema-valid output remains untrusted until semantic checks complete.
- Routing may consider task-specific reliability but must still obey privacy and policy.

---

## 16. Sandbox Capability Attestation and Strict Profiles

### Gap

An application may request a sandbox profile that the host cannot actually enforce. Silent downgrade can create a false sense of isolation.

### Proposed Component

Add a future **Sandbox Capability Attestation** record.

### Suggested Profiles

- `model_only` — no tools or subprocesses
- `read_only_agent_strict` — read-only tools, blocked network unless explicitly proxied
- `tool_strict` — per-tool child sandbox with narrow resources
- `observation_lab` — records would-be denials for controlled testing only
- `debug_lab` — isolated non-production diagnostics

Production should not expose an unrestricted profile to agents.

### Capability Probe

Before running, determine whether the host supports the requested controls:

- filesystem isolation
- read allowlisting
- write allowlisting
- process isolation
- network isolation
- endpoint-filtered proxying
- syscall restrictions where supported
- CPU and memory limits
- process-count limits
- temporary workspace isolation
- environment sanitization
- audit event capture

### Attestation Record

```json
{
  "profile": "read_only_agent_strict",
  "requested_controls": [],
  "enforced_controls": [],
  "unavailable_controls": [],
  "degraded": false,
  "host_capability_digest": "sha256:",
  "decision": "allow"
}
```

### Required Rules

- Strict profiles fail closed when a required control is unavailable.
- The platform must never convert "sandbox unavailable" into "zero findings" or a successful result.
- Observation mode is not enforcement and must be labeled clearly.
- Capability probe results should be cached only with host and software-version binding.
- A host change or security-module change invalidates the cache.
- Production agents must not require privileged containers by default.

### Untrusted Process Defaults

- network blocked unless an approved proxy route exists
- target evidence read-only
- output workspace writable and ephemeral
- empty synthetic home directory
- no host terminal input
- dangerous environment variables removed
- no core dumps
- CPU, memory, file-size, and process-count limits
- no host process or credential visibility

---

## 17. Sandbox Calibration and Drift Detection

### Gap

Hardcoded allowlists may break or widen silently when a tool version changes.

### Controlled Calibration

A lab-only calibration process may observe a tool's required files, endpoints, and environment during a controlled probe.

The result should be bound to:

- tool digest
- tool version
- environment signature
- probe arguments
- operating-system profile
- timestamp

### Important Boundary

Calibration is a portability and drift-detection aid. It is not proof that a tool is safe because the tool already executed during the probe.

Trust must come from:

- source review
- package provenance
- signature or digest verification
- Integration Trust Gate status
- sandboxed runtime behavior

A calibrated profile should require human review before becoming an approved manifest input.

---

## 18. Tool Binary Identity, Path Safety, and Invocation Policy

### Gap

A tool can be replaced through path shadowing, symlink changes, writable executable substitution, or package drift while retaining the same display name.

### Resolved Tool Identity

Consider:

- canonical path
- file type
- device and inode where applicable
- size
- modification time
- content digest
- package provenance
- signature status
- version
- parameter-schema digest

### Path Rules

- Canonicalize at the enforcement boundary.
- Compare path components, not string prefixes.
- Account for symlinks and platform aliases.
- Prevent time-of-check/time-of-use replacement.
- Do not execute binaries from agent-writable directories.
- Do not trust `PATH` supplied by the task or target.
- Tool resolution changes require a new manifest or task failure.

### Invocation Rules

- Treat argv and environment values as untrusted bytes.
- Non-text input must not bypass policy.
- Deny patterns evaluate before allow patterns.
- Argument schemas must have length, type, enumeration, and path constraints.
- Shell interpolation is prohibited unless a narrowly reviewed adapter requires it.
- Approval timeout, backend failure, malformed approval requests, and missing approval services result in denial.

### Release Artifact Hygiene

Before publishing an agent, integration, or tool package, scan for:

- source maps
- debug symbols not intended for release
- internal configuration
- test credentials
- environment files
- local paths
- private endpoints
- build metadata that reveals sensitive infrastructure

---

## 19. Network Egress Broker and DNS-Rebinding Resistance

### Gap

Host allowlists can be bypassed through DNS changes, redirects, permissive wildcards, or direct credential use.

### Egress Architecture

```text
Sandboxed Tool
      |
      v
Local Egress Broker
      |-- host allowlist
      |-- port policy
      |-- method and path policy
      |-- credential injection
      |-- redirect validation
      |-- response-size limits
      `-- audit
      |
      v
Approved External Destination
```

### Required Rules

- Default deny.
- Empty allowlist means deny all.
- Resolve a hostname, validate all returned addresses, and connect only to validated addresses.
- Revalidate redirects before following them.
- Reject loopback, private, link-local, multicast, reserved, and metadata addresses for external routes.
- Define wildcard semantics explicitly so a suffix pattern does not match unrelated names.
- Permit only required ports.
- Apply method and path restrictions when credentials or sensitive data are involved.
- Limit request and response sizes.
- Limit redirects and retries.
- Audit allowed and denied attempts without logging secrets.

### Credential Routing

- Real credentials remain in the broker or secrets service.
- The child receives no reusable upstream credential.
- Prefer short-lived, route-scoped credentials.
- Inject credentials only after destination policy passes.
- Do not place real credentials in command arguments, logs, error strings, or temporary files.
- Redact before formatting, not after logging.
- Credential-route failure must not fall back to a child-supplied credential.

A non-sensitive placeholder token may be used to verify that the tool followed the managed broker path, but it must never be accepted by the upstream service.

---

## 20. Integration Trust, Attestation, and Anti-Downgrade

### Gap

A signed package can still be outside policy, a lower-precedence configuration can weaken trust, and an update can add privileges without changing the package name.

### Required Trust Checks

- cryptographic signature or trusted digest
- trusted root
- signer identity
- source repository or publisher identity
- build or workflow identity where available
- release reference
- artifact digest
- manifest digest
- version
- license and maintenance state

### Trust Rules

- Blocklists override trusted signatures.
- Trust policies merge only additively or more strictly.
- An unsigned downgrade is prohibited.
- Version rollback requires explicit approval and an approved prior digest.
- A package cannot overwrite protected files.
- Registry and archive paths must reject traversal.
- Approval is tied to a specific version, digest, schema, and capability set.
- New tools, hosts, credentials, write paths, destinations, or child-agent rights trigger re-review.
- Verification failure must be actionable and fail closed.

### Security Change Impact Review

For every component update, compare old and new resolved manifests and report:

- added and removed tools
- new filesystem grants
- new network destinations
- new credentials
- new data classes
- new output destinations
- increased budgets
- changed sandbox requirements
- changed model or provider route
- changed schemas
- changed ownership or publisher

Privilege-expanding changes should not activate automatically.

---

## 21. Rollback Snapshot and Restore Governance

### Gap

Future action-capable workflows may create files or modify narrowly scoped configuration. A rollback feature can itself leak secrets, restore outside scope, or produce false confidence.

### Required Snapshot Rules

- Snapshot only the explicitly approved root.
- Exclude secrets, caches, large generated data, and unrelated files.
- Bound snapshot size and file count.
- Record object digests.
- Preserve ownership and permission metadata only when needed.
- Audit every exclusion rule.
- Treat symlinks carefully.
- Encrypt snapshots when they contain sensitive configuration.
- Assign retention and deletion policy.

### Restore Rules

- Dry run before restore.
- Validate all target paths.
- Prevent restore outside the approved root.
- Verify object-store integrity.
- Fail loudly on hash mismatch.
- Require approval for destructive overwrite.
- Record restored, skipped, conflicted, and failed items.
- Revalidate the affected control after restore.

### Boundary

Rollback is available only for changes the platform can faithfully snapshot. It must not claim to reverse external notifications, remote API side effects, credential disclosure, or network traffic.

---

## 22. Append-Oriented Audit Ledger Integrity

### Gap

An attacker or faulty integration may alter, truncate, reorder, or inject audit records.

### Proposed Ledger Controls

- monotonic sequence number
- event identifier
- actor and workload identity
- tenant and task identifiers
- previous-event digest
- current-event digest
- trusted timestamp
- manifest and policy digests
- event type
- redacted details
- storage acknowledgment

### Required Rules

- Audit storage is outside agent-writable paths.
- Redaction happens before event formatting.
- Ledger truncation and sequence gaps are detectable.
- Event correction creates a superseding record rather than mutating history.
- Retention changes are audited.
- Export includes integrity metadata.
- Critical denial, approval, publication, credential, rollback, and revocation events are retained even if dashboard metrics are unavailable.

---

## 23. Staged Passive Integration Assessment

### Gap

Starting an unknown integration immediately may execute install hooks, access credentials, or contact external services before review completes.

### Proposed Stages

#### Stage 0 — Metadata Intake

- source and ownership
- license
- version and digest
- package and dependency metadata
- declared capabilities

#### Stage 1 — Static Source and Configuration Review

- code and manifest review
- install and build scripts
- tool descriptions and parameter schemas
- network and filesystem declarations
- credential behavior
- prompt or policy content

#### Stage 2 — Protocol Metadata Inspection

- initialize an isolated session
- enumerate tools, resources, and prompts
- compare with declared capabilities
- do not call tools

#### Stage 3 — Isolated Behavioral Verification

- synthetic data only
- decoy tokens and files
- restricted network
- bounded tool calls
- process, file, environment, and network monitoring

#### Stage 4 — Read-Only Canary Pilot

- one lab tenant
- narrow capability manifest
- short expiration
- enhanced monitoring
- no publication authority

#### Stage 5 — Restricted Approval

- approved version and digest
- explicit limitations
- named owner
- review expiration
- rollback and removal procedures

### Stage Rules

- Failure at any stage prevents automatic promotion.
- Capability drift returns the integration to quarantine.
- Community packages and skills must not auto-install.
- A clean review means no relevant risk was found during the review, not that the integration is risk-free.

---

## 24. Safe Probe and Benchmark Modes

### Gap

Optional live enrichment can touch real services, while benchmark runs become irreproducible when they depend on current network responses or model drift.

### Safe Probe Envelope

A future read-only probe should require:

- explicit scope and authorization
- off-by-default configuration
- one narrowly defined request
- strict timeout
- rate limit
- no credential mutation
- no state-changing methods
- masked target storage
- status-only or minimal response retention
- destination allowlist
- full audit metadata

### Benchmark Mode

Benchmark and regression runs should:

- use fixed offline fixtures where possible
- disable live probes
- pin rules, tools, schemas, and models
- record hardware and runtime profiles
- use deterministic seeds where applicable
- freeze external knowledge snapshots
- label measured, estimated, and synthetic results
- report omitted or unavailable capabilities

### Partial and Truncated Results

Any file, dependency, record, time, token, or output limit that truncates analysis must set:

- `coverage_state=partial`
- `limit_type`
- `limit_value`
- `observed_count`
- `unprocessed_count`, when known
- operator guidance

---

## 25. Output Rendering and Active-Content Neutralization

### Gap

Generated or tool-provided content can trigger network requests or script execution when rendered in rich interfaces.

### Required Controls

Before rendering or publishing:

- strip or neutralize auto-fetching images
- block embedded frames
- block script-capable links
- block data and script URI schemes
- neutralize active HTML
- validate redirects
- display untrusted links without automatic fetching
- render plain text or a restricted markup subset by default
- remove hidden policy or instruction markers
- scan generated patches and code semantically
- prevent automatic application of generated code

Input-side sanitization is not sufficient. The final output must pass the Safe Output Gate independently.

### Sensitive Logging

- Do not log full prompts by default.
- Do not log credentials, private keys, bearer tokens, or secret-bearing URLs.
- Redact before calling string-formatting or debug functions.
- Bound error messages and stack traces exposed to users.
- Keep debug traces short-lived and access-controlled.

---

## 26. Security Invariants for Untrusted Context

OpenAssetWatch should codify engineering invariants that tests can enforce.

### Invariant 1 — No Natural-Language Trust Grant

No source record, issue, document, asset description, tool output, or retrieved memory may grant authorization through text.

### Invariant 2 — Untrusted Data Remains Untrusted

A schema-valid or well-formatted AI artifact may still be semantically malicious. Downstream consumers must validate it against deterministic evidence and policy.

### Invariant 3 — Configuration Review Is Not Source Trust

A clean configuration review does not make the analyzed content trusted and does not relax sandbox or output controls.

### Invariant 4 — Isolation and Output Treatment Are Independent

Sandboxing limits tool effects. Output validation limits poisoned artifacts. Neither replaces the other.

### Invariant 5 — AI Cannot Expand Its Own Authority

No agent, child worker, prompt, memory record, or tool response may widen its manifest, add credentials, change destinations, or disable audit.

### Invariant 6 — Security Failure Is Not a Clean Result

Missing isolation, missing analyzers, invalid policy, failed validation, or unavailable audit persistence must produce a visible failure or partial state, never "no findings."

---

## 27. Incident Response for AI and Agent Workflows

### Detection Inputs

- abnormal tool use
- permission-path violations
- unexpected destinations
- credential-route failures
- component drift
- audit gaps
- tool shadowing
- excessive loops or resource use
- unexplained publication
- cross-tenant access attempts
- sandbox setup or escape indicators

### Containment Actions

- activate appropriate kill switch
- cancel active tasks and child workers
- revoke short-lived credentials
- disable publisher identities
- quarantine affected tools, models, integrations, or policies
- block external processing
- preserve audit and evidence artifacts
- prevent new schedules from starting

### Investigation

Use the component and activity graph to determine:

- initiating actor
- affected tenants
- evidence accessed
- tools used
- destinations contacted
- artifacts generated
- publications completed
- credentials potentially exposed
- child workers involved

### Recovery

- restore approved policy and manifests
- rotate affected credentials
- remove or replace compromised components
- validate audit-ledger integrity
- reconcile orphaned work
- rerun affected deterministic analysis
- retest controls and exposure paths
- document unresolved uncertainty

### Lessons Learned

- add a regression fixture
- update the threat model
- update permission-path rules
- update the Integration Trust Gate
- review whether the capability manifest was broader than necessary
- record control and process improvements

---

## 28. Recommended Implementation Roadmap

### Phase A — Contracts and Schemas

1. Define the resolved capability-manifest schema.
2. Define policy precedence and merge rules.
3. Define the goal and consent contract.
4. Define the capability-triad classification.
5. Define agent lifecycle and lease records.
6. Define authenticated handoff envelopes.
7. Define canonical finding and evidence-bundle schemas.
8. Define coverage states and run manifests.
9. Define audit-ledger integrity fields.
10. Define incident-response kill-switch scopes.

### Phase B — Deterministic Assurance Foundation

1. Implement policy compilation and dry run.
2. Add manifest digesting and effective-permission diff.
3. Add coverage-state reporting.
4. Add stable evidence hashes.
5. Add atomic run completion.
6. Add threat-model freshness and drift checks.
7. Add lifecycle leases and orphan reconciliation.
8. Add release-artifact hygiene checks.

### Phase C — Tool and Integration Enforcement

1. Enforce canonical tool identity.
2. Add path and argument policy.
3. Add network deny floors and rebinding-resistant egress.
4. Add brokered credential routes.
5. Add sandbox capability attestation.
6. Add strict-profile fail-closed behavior.
7. Add staged passive integration assessment.
8. Add component-update impact review.

### Phase D — Finding Intelligence Quality

1. Add canonical detector adapters.
2. Add additive ownership, confidence, evidence, and triage stages.
3. Add deterministic fusion and conflict handling.
4. Add coverage registry and reference corpus.
5. Add root-cause clustering and variant review.
6. Add remediation and control retest records.
7. Refine exposure-path roles and subset deduplication.

### Phase E — AI Reliability and Adversarial Validation

1. Create a verified-outcome ledger.
2. Add task-class model scorecards.
3. Add replay evaluation.
4. Add uncertainty-aware aggregation.
5. Add untrusted-output semantic validation.
6. Add active-content neutralization.
7. Exercise kill switches and recovery runbooks.

### Phase F — Controlled Rollback and Advanced Operations

1. Add scoped snapshot and dry-run restore.
2. Add append-oriented audit integrity checks.
3. Add canary deployment for integrations.
4. Add coverage and assurance dashboards.
5. Add incident graph investigation views.

---

## 29. Acceptance Criteria

This assurance layer should not be considered production-capable until:

- every agent task has a resolved, immutable capability manifest
- policy compilation and privilege diffs are deterministic
- critical deny floors cannot be weakened by lower-precedence policy
- every task has a goal, scope, consent, budget, and stop condition
- all long-running work has leases, heartbeats, cancellation, and cleanup
- inter-agent messages are authenticated, scoped, schema-valid, and replay-resistant
- findings use canonical schemas and additive versioned enrichment
- incomplete coverage cannot appear as a clean result
- confidence, severity, reachability, visibility, and priority remain distinct
- evidence bundles are content-addressed and reproducible
- run manifests record all material versions, limits, and omissions
- strict isolation fails closed when unavailable
- tool identity resists path replacement and shadowing
- external routes enforce address, host, method, path, and credential policy
- component updates cannot silently expand privilege
- rollback is scoped, integrity-checked, and honest about non-reversible effects
- audit tampering and truncation are detectable
- AI outputs remain untrusted until deterministic validation completes
- global and scoped kill switches work without model cooperation

## 30. Explicit Non-Goals

This design does not authorize:

- autonomous penetration testing
- exploit or payload generation
- credential collection or cracking
- remote shells
- command-and-control functionality
- unrestricted browser automation
- unrestricted shell access
- privileged containers as a normal deployment requirement
- self-modifying agent permissions
- silent policy downgrade
- automatic public publication
- automatic application of AI-generated code or configuration
- active validation against systems without explicit scope and approval

## Final Position

OpenAssetWatch should treat AI assurance as a complete lifecycle: author policy, compile capabilities, validate the environment context, execute within enforceable bounds, produce canonical evidence, measure coverage, assess reliability, validate outputs, publish through a separate authority, and retain enough integrity and recovery information to investigate failures.

The strongest architecture is not the one with the most agents or models. It is the one that can clearly explain what was allowed, what actually ran, what evidence supported the result, what protections were enforced, what remained uncertain, and how the operator can stop or recover the system safely.
