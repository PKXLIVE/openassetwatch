# AI Architecture Research and Gap Index

## Purpose

This index keeps the OpenAssetWatch AI and defensive-intelligence research work organized, discoverable, and controlled. It links the architecture documents created from public research while preserving a provider-neutral design and preventing interesting ideas from becoming unplanned implementation scope.

The documents in this index describe original OpenAssetWatch requirements. They do not reproduce third-party branding, diagrams, implementation details, or performance claims.

## Research Intake Rule

OpenAssetWatch should use external resources as design inputs, not as templates to copy.

For each researched idea:

1. Identify the underlying security or architecture problem.
2. Confirm that the problem is relevant to OpenAssetWatch.
3. Compare it with existing project controls.
4. Record only the uncovered gap.
5. Express the solution in OpenAssetWatch terminology.
6. Preserve passive-first, advisory-first, evidence-first, and read-only-default behavior.
7. Add explicit security boundaries and non-goals.
8. Defer implementation until current roadmap prerequisites exist.
9. Perform fresh license, maintenance, and security review before adopting any code or dependency.

## Documentation Language Rule

Generic architecture documents should:

- avoid source-project and provider names
- avoid copied product terminology
- avoid copied diagrams and screenshots
- avoid third-party benchmark or performance claims
- define capability-based interfaces
- identify assumptions and limitations
- use original OpenAssetWatch schemas and component names
- keep rejected offensive capabilities explicit

A document evaluating a deliberately selected compatibility target may identify that target when the identity is necessary to preserve the decision. That exception does not allow source names to enter the generic platform architecture.

## Canonical Research-Derived Documents

### Local Agentic AI Design Direction

File: `local-agentic-ai-design.md`

Covers:

- specialist-agent orchestration
- model and task routing
- compute profiles
- local-first execution
- scheduling
- provider and hardware independence
- evidence-context preparation
- structured handoffs
- background and distributed work
- resource and usage observability

### Defensive AI and Security Architecture Gap Backlog

File: `defensive-ai-security-gap-backlog.md`

Covers:

- deterministic finding intelligence
- finding validation
- ownership, confidence, evidence, triage, and fusion
- exposure-path analysis
- analysis replay
- bounded tool execution
- per-tool isolation
- integration trust review
- AI security testing
- passive external exposure enrichment
- graceful degradation
- rejected offensive capabilities

### AI Agent Permission, Context, and Safe Output Architecture

File: `ai-agent-permission-output-security.md`

Covers:

- AI component inventory
- runtime activity relationships
- permission-path analysis
- trust-labeled context
- safe output validation
- separate publisher identities
- protected control artifacts
- agent-specific CI checks
- tool shadowing and drift
- scoped child workers
- capability discovery
- AI-generated artifact provenance
- expiring enrichment knowledge

### AI Platform Assurance and Intelligence Lifecycle

File: `ai-platform-assurance-lifecycle.md`

Covers:

- policy compilation and resolved capability manifests
- policy merge and deny floors
- environment threat-model lifecycle
- goal, scope, consent, and autonomy contracts
- capability-triad controls
- lifecycle leases and kill switches
- authenticated inter-agent communication
- canonical findings and additive intelligence engines
- detection coverage and blind-spot accounting
- confidence, severity, reachability, and visibility separation
- structured evidence bundles and stable hashes
- reproducibility manifests
- root-cause and variant review
- model reliability scorecards
- sandbox capability attestation
- tool binary identity and path safety
- egress and credential brokering
- anti-downgrade controls
- rollback and audit integrity
- staged integration assessment
- safe probe and benchmark modes
- output rendering safety
- incident response

### Security Investigation and Case Operations Architecture

File: `security-investigation-case-operations.md`

Covers:

- canonical security signals, findings, cases, artifacts, and timelines
- separate source, deterministic, AI, and analyst assessments
- deterministic correlation and idempotent case formation
- race-safe assignment and atomic claim semantics
- server-anchored service targets, snooze, and shift handoff
- deterministic investigation narratives and entity pivots
- append-only investigation ledger and safe replay
- structured reports with explicit unknowns
- typed read-only playbooks and duplicate-job suppression
- optional analyst-reviewed operational lessons after case closure
- canonical case state with external systems treated as projections

### Detection, Feedback, and Response Governance Architecture

File: `detection-feedback-response-governance.md`

Covers:

- versioned detector and rule lifecycle
- deterministic detector-quality and tuning recommendations
- coverage snapshots and drift monitoring
- separate deterministic-substrate and live-agent evaluations
- synthetic incidents with backing telemetry
- reproducible evaluation provenance and history
- authenticated, reviewable, retractable analyst feedback
- feedback poisoning and training-eligibility controls
- versioned feature contracts and schema-compatibility gates
- multi-metric candidate model promotion
- shadow, canary, hot-reload, rollback, and model cards
- AI-generated detection drafts that require validation and review
- recommendation-first response plans
- blast radius, dry run, approval, rollback, and post-change verification
- defensive what-if analysis with explicit simulation limits

### Connector, Playbook, and External Projection Architecture

File: `connector-playbook-projection-architecture.md`

Covers:

- self-describing connector definitions and explicit capabilities
- tenant-scoped connector instances, checkpoints, health, and circuit breakers
- canonical evidence-ingress envelopes
- token-bound and signed universal evidence inboxes
- template-bound parsing, rate limits, and replay protection
- credential authority separation and stateless connection testing
- source preservation, unmapped fields, and schema-drift detection
- trusted extension identity, collision, and override controls
- production-safe custom-extension packaging
- admin-only read-only definition and health views
- typed playbook catalogs and run records
- canonical-state-first external projection
- signed, idempotent inbound status convergence
- explicit egress profiles and air-gap verification

### Experimental External Support Integration

File: `experimental-external-ai-support.md`

Covers a separately approved, optional support-assistant experiment. It remains outside the OpenAssetWatch core and must not become a source of authoritative evidence, a required dependency, or a competing architecture.

## Gap Taxonomy

Future research findings should be assigned to one or more categories:

- asset and evidence collection
- normalization and identity resolution
- vulnerability and exposure enrichment
- finding intelligence
- attack and exposure paths
- security signals and case formation
- investigation workflow and analyst operations
- detection content and tuning
- feedback and model lifecycle
- response planning and verification
- connectors and evidence ingress
- playbooks and extension packaging
- external projections and data convergence
- AI routing and scheduling
- agent orchestration
- permissions and authorization
- context and prompt security
- tools and integration security
- sandboxing and egress
- output and publication safety
- supply-chain and provenance
- observability and audit
- quality and evaluation
- coverage and blind spots
- rollback and recovery
- incident response
- privacy and tenant isolation
- operator usability

## Status Model

Every architecture item should use one of these states:

- `research_candidate` — potentially useful but not yet accepted
- `documented_direction` — accepted as a future design requirement
- `contract_ready` — schemas and acceptance criteria are defined
- `prototype_approved` — a bounded proof of concept is authorized
- `implementation_planned` — prerequisites and owner are assigned
- `implemented` — code and tests exist
- `deferred` — valuable but not appropriate for the current roadmap
- `rejected` — conflicts with project mission, security, or maintenance goals
- `superseded` — replaced by a newer design

Documentation alone does not move an item beyond `documented_direction`.

## Scope-Control Test

A research-derived item should remain in the roadmap only when it:

- improves asset visibility, evidence quality, defensive prioritization, or platform security
- can be isolated behind stable interfaces
- preserves deterministic evidence as the source of truth
- does not require offensive execution
- does not make an external service mandatory
- has a clear owner and acceptance criteria before implementation
- has a removal or rollback strategy
- does not delay committed collector, normalization, Control Plane, or dashboard work

## Rejection Test

Reject or redesign an idea when it requires:

- autonomous exploitation
- credential theft or cracking
- unrestricted active scanning
- remote shells or command-and-control behavior
- arbitrary command endpoints
- privileged deployment by default
- automatic public publication
- self-expanding agent permissions
- bypassing the Tool Gateway
- treating model output as authoritative evidence
- cross-tenant context or memory
- weakening approval, audit, or isolation controls
- copying proprietary product behavior or branding

## Duplicate-Control Process

Before adding a new architecture item:

1. Search the documents in this index.
2. Identify whether the item is already covered as a component, rule, schema, or acceptance criterion.
3. Extend the most specific existing document rather than creating a competing component.
4. Create a new document only when the idea introduces a distinct lifecycle or trust boundary.
5. Add a relationship note to this index.

## Research Review Record

For internal tracking, a research review may record:

- review identifier
- review date
- reviewer
- resource class
- architecture areas inspected
- useful patterns
- rejected patterns
- existing controls that already cover the issue
- newly documented gaps
- affected architecture documents
- follow-up date

The generic architecture documents should contain the accepted requirement, not the source name.

## Implementation Gate

Before converting a documented direction into code, require:

- named owner
- current-roadmap fit
- threat model
- dependency and license review
- versioned schema
- security acceptance criteria
- test plan
- migration and rollback plan
- observability plan
- data-retention plan
- failure and degradation behavior
- user-facing explanation

## Final Position

Research should continuously improve OpenAssetWatch without continuously changing its identity. The project should absorb strong defensive patterns, translate them into original provider-neutral controls, and keep them documented until the core platform is ready to implement them safely.
