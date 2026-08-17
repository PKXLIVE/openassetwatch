# Local Agentic AI Design Direction

## Purpose

This document extends the OpenAssetWatch AI architecture with a vendor-neutral design direction for local-first agentic computing, dynamic model selection, workload-aware scheduling, and distributed specialist agents.

The design is based on broad architectural patterns in modern AI systems. It does not reproduce any third-party implementation, product naming, branding, or proprietary design.

## Design Goals

OpenAssetWatch should evolve toward an AI architecture that is:

- evidence-grounded
- local-first
- hardware-independent
- model-independent
- modular
- auditable
- resource-aware
- advisory-first
- safe by default

The AI layer should help users understand their environment without replacing deterministic collection, normalization, enrichment, finding generation, or policy enforcement.

## Agentic Processing Model

OpenAssetWatch should use an orchestrated group of specialist agents rather than depend on one general-purpose model for every task.

```text
User Request
     |
     v
AI Orchestrator
     |
     +--------------------+--------------------+--------------------+
     |                    |                    |                    |
     v                    v                    v                    v
Reasoning Agent     Discovery Agent      Risk Agent         Reporting Agent
     |                    |                    |                    |
     +--------------------+--------------------+--------------------+
                              |
                              v
                    Shared Evidence Context
```

Potential specialist agents include:

- Asset Intelligence Agent
- Discovery Analysis Agent
- Inventory Normalization Agent
- Network Behavior Agent
- Exposure and Risk Agent
- Security Tooling Coverage Agent
- Segmentation Advisor
- IoT and OT Advisor
- Data Quality Agent
- Detection Advisor
- Report Writer
- Evidence Validation Agent

Each agent should receive only the evidence, tools, permissions, and tenant context required for its role.

## Orchestrator Responsibilities

The AI Orchestrator should coordinate work across agents and remain separate from the models that perform individual tasks.

Its responsibilities should include:

- classifying the user request
- selecting the appropriate specialist agent or workflow
- assembling evidence context
- applying tenant and policy boundaries
- choosing an execution profile
- selecting an approved model
- enforcing token and time limits
- managing handoffs between agents
- collecting structured outputs
- validating that conclusions cite evidence
- writing audit events
- returning a unified response

The orchestrator should not bypass the Tool Gateway, evidence controls, approval controls, or tenant boundaries.

## Dynamic Model Selection

OpenAssetWatch should not assume that one model is best for all workloads.

A model-routing layer should select an approved model according to task type, sensitivity, expected latency, context size, cost constraints, and available hardware.

| Workload | Example OpenAssetWatch task | Preferred characteristics |
| --- | --- | --- |
| Fast reasoning | Classify an observed device | Low latency, small context |
| Evidence synthesis | Explain why an asset is risky | Strong structured reasoning |
| Coding support | Suggest a detection or query | Code-aware model |
| Research | Summarize vulnerability enrichment | Larger context, source discipline |
| Report writing | Produce an executive summary | Strong writing and formatting |
| Batch analysis | Re-evaluate many stale assets | High throughput, low cost |
| Background work | Normalize descriptions or tags | Small local model |

Model selection must remain configurable and vendor-neutral.

## Model Routing Layer

The model-routing layer should evaluate:

- task category
- agent role
- input sensitivity
- evidence volume
- context-window requirement
- required response format
- latency target
- cost ceiling
- local hardware availability
- model health
- model allowlist
- tenant policy
- offline or air-gapped mode

The router should support fallback behavior when a preferred model is unavailable. Fallbacks must preserve safety, tenant isolation, and data-sharing rules.

A fallback must never silently send local or sensitive evidence to an external provider when policy requires local execution.

## Compute Profiles

AI tasks should be assigned a compute profile before execution.

Suggested profiles:

### Lightweight

For classification, tagging, short summaries, and simple explanation tasks.

Expected behavior:

- small local model
- short context
- low token budget
- fast response

### Interactive

For user-facing questions that require evidence retrieval and concise reasoning.

Expected behavior:

- low-to-moderate latency
- bounded context
- structured citations

### Analysis

For multi-source asset, exposure, and security-tooling analysis.

Expected behavior:

- larger context
- more retrieval steps
- specialist-agent collaboration
- stronger validation

### Research

For vulnerability, firmware, product, or framework enrichment that may require external sources when permitted.

Expected behavior:

- explicit source handling
- external-data policy checks
- longer execution window
- clear separation between observed facts and external enrichment

### Batch

For scheduled reprocessing of many assets or findings.

Expected behavior:

- queue-based execution
- concurrency limits
- resumable jobs
- cost and throughput controls

### Background

For non-urgent enrichment, metadata cleanup, report preparation, or memory maintenance.

Expected behavior:

- lowest-cost approved model
- idle-resource preference
- safe cancellation and retry

## AI Scheduler

A future AI Scheduler should manage the execution of interactive and asynchronous AI work.

Responsibilities should include:

- workload classification
- queue selection
- model assignment
- hardware assignment
- concurrency control
- token budgeting
- retry policy
- timeout enforcement
- priority handling
- background scheduling
- job cancellation
- health-aware failover
- cost and usage accounting

The scheduler should expose clear job states such as:

- queued
- preparing evidence
- running
- waiting for approval
- retrying
- completed
- failed
- cancelled

## Local-First AI Strategy

OpenAssetWatch should prioritize AI execution in this order:

1. local inference on the OpenAssetWatch host
2. self-hosted inference on a trusted internal system
3. optional external AI provider when explicitly configured and permitted

Benefits include:

- improved privacy
- offline operation
- reduced recurring cost
- better control over sensitive inventory data
- support for home, lab, small-business, and regulated environments
- easier air-gapped deployment

External AI should remain optional. Core collection, inventory, findings, and deterministic reports must continue to function without it.

## Local Model Management

A future Local Model Manager should provide:

- model registration
- model metadata
- capability tags
- quantization information
- context-window information
- hardware requirements
- health checks
- model loading and unloading
- approved-model allowlists
- version pinning
- checksum or provenance validation
- rollback to a prior model

Suggested model capability tags include:

- reasoning
- classification
- coding
- summarization
- report-writing
- embedding
- reranking
- vision

OpenAssetWatch should not hard-code a particular model family or runtime.

## Hardware Independence

The AI architecture should support:

- CPU-only deployments
- integrated accelerators
- consumer GPUs
- workstation GPUs
- enterprise accelerators
- remote inference nodes
- multi-node self-hosted clusters

The scheduler should use capability discovery rather than vendor-specific assumptions.

Suggested hardware capability fields:

- device type
- available memory
- supported precision
- supported runtimes
- current utilization
- temperature or throttling state, when available
- estimated model capacity
- local or remote location
- tenant eligibility

## Evidence Context Engine

The Evidence Context Engine should prepare the smallest trustworthy context required for each task.

It should:

- retrieve tenant-scoped evidence
- resolve asset and finding relationships
- remove secrets and sensitive fields
- mark stale evidence
- preserve source references
- calculate evidence quality
- deduplicate repeated records
- summarize large evidence sets deterministically where possible
- enforce context-size limits
- provide structured evidence cards to agents

The engine should favor evidence selection over dumping entire raw records into a model context.

## Multi-Agent Collaboration

Agents should collaborate through structured handoffs rather than unrestricted free-form conversation.

Example flow:

```text
Discovery Analysis Agent
        |
        v
Inventory Normalization Agent
        |
        v
Exposure and Risk Agent
        |
        v
Segmentation Advisor
        |
        v
Report Writer
```

A handoff should include:

- source agent
- target agent
- task objective
- related asset IDs
- related finding IDs
- evidence references
- confidence
- unresolved questions
- recommended next step
- execution limits

Agents should not pass secrets, unsupported assumptions, hidden prompts, or unrestricted raw data through handoffs.

## Distributed Agent Execution

OpenAssetWatch may eventually execute agents across multiple trusted nodes.

Potential uses include:

- running lightweight models on a collector host
- running larger models on a local workstation
- using a dedicated internal inference server
- processing batch jobs on a separate worker
- keeping sensitive tenant workloads on assigned nodes

Distributed execution must include:

- authenticated worker registration
- node capability reporting
- encrypted transport
- tenant-aware scheduling
- signed or verified job envelopes
- strict tool permissions
- job-level audit records
- revocation support
- timeout and cancellation controls

Collectors should not automatically become AI execution nodes merely because they are enrolled in OpenAssetWatch.

## Resource and Usage Observability

The AI subsystem should expose operational metrics without exposing sensitive prompts or evidence.

Useful metrics include:

- requests by agent
- requests by task type
- model utilization
- queue depth
- response latency
- token usage
- estimated cost
- local versus external execution
- failure and retry rate
- context size
- evidence retrieval time
- tool calls by category
- approval wait time
- jobs by compute profile

Dashboards should help operators understand adoption, efficiency, resource pressure, and model-routing behavior.

## Safety and Policy Controls

All new scheduling and routing capabilities remain subordinate to existing OpenAssetWatch AI safety principles.

Required controls include:

- advisory-first behavior
- read-only defaults
- tenant isolation
- role-based authorization
- approved-model allowlists
- external data-sharing policy
- tool allowlists
- evidence validation
- secrets redaction
- human approval for high-impact actions
- audit logging
- rate and resource limits
- safe cancellation

A faster or more capable model must never receive broader permissions simply because it is selected for a task.

## Proposed Architecture Components

The long-term AI architecture should include these logical components:

- AI Orchestrator
- AI Scheduler
- Model Routing Layer
- Evidence Context Engine
- Local Model Manager
- Compute Profile Manager
- Background AI Workers
- Distributed Agent Execution Layer
- AI Usage and Cost Observability
- Agent Evaluation Harness

These components may be implemented gradually and do not need to begin as separate services.

## Recommended Implementation Roadmap

### Phase A: Architecture Contracts

- define compute-profile schema
- define model-capability schema
- define routed-task envelope
- define scheduler job states
- define agent handoff schema
- define resource-usage audit events

### Phase B: Single-Node Scheduler

- local in-process or queue-backed scheduler
- one approved local model
- one optional external provider
- lightweight and interactive profiles
- bounded retries and timeouts
- usage logging

### Phase C: Model Routing

- task-to-model rules
- tenant model allowlists
- local-first fallback chain
- model health checks
- explicit external-provider policy
- structured routing audit records

### Phase D: Specialist-Agent Workflows

- discovery-to-inventory workflow
- inventory-to-risk workflow
- risk-to-report workflow
- evidence validation before final output
- structured handoff records

### Phase E: Background and Batch Work

- scheduled inventory analysis
- stale asset review
- recurring security-tooling coverage summaries
- queued report generation
- job pause, resume, retry, and cancellation

### Phase F: Distributed Execution

- trusted worker enrollment
- capability-aware scheduling
- remote inference nodes
- tenant-aware workload placement
- worker revocation
- distributed audit and health monitoring

## Non-Goals

This design does not authorize:

- autonomous remediation
- arbitrary command execution
- unrestricted scanning
- unapproved external data sharing
- cross-tenant model context
- silent fallback to external providers
- vendor-specific hardware dependency
- unsupported claims presented as findings

## Summary

OpenAssetWatch should treat AI as a controlled, evidence-backed orchestration layer. Specialist agents, dynamic model routing, compute profiles, local-first inference, and workload scheduling can improve capability and efficiency while preserving the project's core safety principles.

The architecture should remain transparent, inspectable, vendor-neutral, and useful even when no AI model is configured.