# AI Observability and Operations

## Purpose

OpenAssetWatch should make AI behavior visible, measurable, and reviewable. Operators need to understand which tasks use deterministic logic, which tasks use local or external models, how much time and cost each route consumes, why requests are blocked or escalated, and whether outputs meet quality and evidence requirements.

This document defines a provider-neutral observability and operations design. It describes original OpenAssetWatch requirements and intentionally avoids third-party product names, branded terminology, screenshots, and vendor-specific dashboard layouts.

## Core Principle

> AI activity should be observable with the same rigor as collectors, assets, findings, and policy decisions.

Metrics should support operations and accountability without exposing sensitive prompt content, secrets, or raw tenant evidence.

## Objectives

The AI operations capability should help users:

- understand AI usage and adoption
- compare deterministic, local, and external execution
- measure token and resource efficiency
- monitor latency, failures, fallbacks, and queue health
- identify costly or inefficient tasks
- verify policy, privacy, and redaction controls
- measure quality and evidence-grounding outcomes
- calculate defensible cost and performance comparisons
- investigate operational incidents involving models or agents

## Architecture

```text
AI Task Requests
       |
       v
Governance and Routing Decisions
       |
       v
Model or Agent Execution
       |
       v
Validation and Tool Outcomes
       |
       v
Structured Telemetry Events
       |
       +-- Operational metrics
       +-- Audit records
       +-- Cost and token accounting
       +-- Quality evaluation
       +-- Security events
       |
       v
AI Operations Dashboard and Reports
```

Telemetry should be produced by the governance, routing, provider-adapter, agent-runtime, Tool Gateway, and validation layers. The dashboard must not rely on a model to explain its own health or compliance.

## Telemetry Event Contract

Each AI request should produce one or more structured events linked by a request identifier.

Suggested fields:

- `event_id`
- `request_id`
- `parent_request_id`
- `tenant_id`
- `actor_id`
- `task_type`
- `execution_mode`
- `selected_tier`
- `provider_id`
- `model_id`
- `model_version`
- `agent_id`
- `policy_version`
- `route_reason`
- `input_tokens`
- `output_tokens`
- `evidence_record_count`
- `queue_latency_ms`
- `execution_latency_ms`
- `validation_latency_ms`
- `estimated_cost_usd`
- `actual_cost_usd`
- `redaction_applied`
- `policy_result`
- `validation_result`
- `fallback_count`
- `final_status`
- `created_at`

Prompt text and raw evidence should not be included by default. Where debugging requires retained content, access should be explicit, time-limited, tenant-scoped, redacted, and audited.

## Primary Metrics

### Request volume

Track:

- total requests
- requests by task type
- requests by execution tier
- requests by deployment location
- requests by model or agent capability
- requests by tenant or site where authorized
- scheduled versus interactive requests
- requests completed without a model

### Routing efficiency

Track:

- deterministic execution percentage
- local execution percentage
- external execution percentage
- insufficient-evidence outcomes
- human-review referrals
- fallback and escalation counts
- route changes caused by policy
- route changes caused by provider health
- requests denied because no approved route was available

### Token and context efficiency

Track:

- input and output tokens
- tokens by task type
- tokens by execution tier
- average tokens per completed task
- context utilization percentage
- evidence records per request
- repeated or duplicated context
- requests reduced or divided because of limits
- output-to-input token ratio

Token metrics must be treated as unavailable when a runtime cannot provide reliable counts. Estimates should be labeled as estimates.

### Cost and savings

Track:

- estimated and actual cost
- cost by task type
- cost by execution tier
- cost by tenant where appropriate
- cost per successful validated output
- cost of retries and fallbacks
- budget utilization
- cost avoided through deterministic or local execution

Cost avoided should be calculated against a configurable baseline, not presented as a universal fact.

A defensible comparison should record:

- baseline route
- baseline rate source
- compared request set
- time period
- excluded requests
- whether token counts were measured or estimated
- whether the result is measured, estimated, or synthetic

### Latency and reliability

Track:

- queue latency
- time to first response when available
- total execution latency
- validation latency
- percentile latency by task and tier
- timeout rate
- provider or runtime failure rate
- retry rate
- cancellation rate
- agent sandbox startup time
- Tool Gateway latency

### Quality and grounding

Track:

- schema-validation success
- evidence-reference success
- unsupported-claim detections
- secret or sensitive-data detections
- confidence below threshold
- human corrections
- user feedback where collected
- deterministic evaluation score
- regression-suite results
- output rejection rate

Quality comparisons must use the same task set and acceptance criteria across routes.

### Security and policy

Track:

- policy denials
- external-processing denials
- redaction failures
- sensitivity-classification failures
- cross-tenant access attempts
- unapproved tool requests
- approval-required outcomes
- resource-limit terminations
- sandbox isolation failures
- model or agent version not on the allowlist

## AI Operations Dashboard

The Control Tower should eventually include an **AI Operations** view. It should present information in layers so a home user can understand the summary while an operator can investigate details.

### Summary cards

Recommended top-level cards:

- requests in selected period
- deterministic execution percentage
- local execution percentage
- external execution percentage
- tokens processed
- estimated or actual cost
- average response latency
- failed or blocked requests

### Usage and routing trends

Recommended visualizations:

- request volume over time by execution tier
- task distribution
- local versus external processing trend
- fallback and escalation trend
- provider or runtime health trend
- adoption by feature or agent

### Cost and token efficiency

Recommended visualizations:

- cost by task type
- cost by execution tier
- cumulative cost against budget
- token volume over time
- high-token tasks
- cost per validated result
- estimated cost avoided against the selected baseline

### Quality and reliability

Recommended visualizations:

- validation success trend
- failure and timeout trend
- latency percentiles
- evidence-grounding success
- low-confidence outcome trend
- human-review and correction volume

### Policy and security

Recommended visualizations:

- blocked requests by reason
- redaction events
- external-processing attempts
- unapproved tool requests
- approval queue
- security events over time

### Operational tables

Useful drill-down tables include:

- recent failed requests
- recent policy denials
- highest-cost requests
- highest-token requests
- repeated fallbacks
- low-confidence outputs
- agent sandbox failures
- model and policy version changes

## Dashboard Design Principles

The dashboard should:

- answer the most important questions at a glance
- use clear labels rather than provider jargon
- separate measured, estimated, and synthetic values
- support time, tenant, site, task, tier, and status filters
- provide drill-down from every summary metric
- avoid exposing prompt text in summary views
- use tables for investigation, not as the dominant overview
- remain usable when only deterministic execution is enabled
- clearly identify missing telemetry rather than displaying zero

OpenAssetWatch should borrow general information-design principles, not reproduce any third-party visual layout.

## Health and Service-Level Indicators

Suggested health indicators:

- routing decision availability
- policy evaluation availability
- local runtime health
- approved external endpoint health
- queue depth
- request age
- validation backlog
- Tool Gateway availability
- isolated runtime capacity
- telemetry ingestion freshness

Initial service objectives may include:

- routing decisions complete within a bounded time
- policy checks fail closed
- no cross-tenant telemetry exposure
- telemetry available within a defined freshness window
- critical audit events retained even when dashboard storage is unavailable

Exact objectives should be established after baseline testing.

## Storage and Retention

OpenAssetWatch should separate:

1. **Operational metrics** — aggregated and suitable for dashboards.
2. **Audit records** — append-oriented records of decisions and actions.
3. **Evaluation results** — reproducible quality and regression evidence.
4. **Debug traces** — restricted, short-lived, and disabled by default.

Retention should be configurable by data type and deployment profile. Raw prompts, model responses, and evidence payloads should not be retained by default.

## Privacy and Tenant Isolation

AI telemetry may itself contain sensitive metadata. Controls should include:

- tenant-scoped queries
- role-based access
- restricted cost visibility where required
- identifier aliasing in aggregate views
- no cross-tenant dashboards
- redaction of sensitive error messages
- audit of exports
- bounded retention

Aggregate reporting must not allow users to infer another tenant's model usage, assets, identities, or costs.

## External Observability Integration

OpenAssetWatch should expose vendor-neutral telemetry interfaces so users can forward AI operations data to an observability or security platform of their choice.

Potential interfaces include:

- structured JSON events
- standard metrics endpoints
- standard distributed tracing
- webhooks for critical events
- scheduled report export

The core schema should remain independent of any external analytics product.

## Benchmark and Savings Methodology

OpenAssetWatch must not claim performance or cost improvements without reproducible evidence.

Every published comparison should include:

- benchmark name and version
- dataset or task set
- execution tiers compared
- hardware and runtime profile described generically
- model version or digest
- policy and routing configuration
- warm or cold execution state
- token-count method
- latency measurement method
- cost-rate assumptions
- quality acceptance threshold
- number of runs
- date and software version

Results should be labeled:

- **measured** — directly observed in the stated environment
- **estimated** — calculated using measured usage and documented assumptions
- **synthetic** — produced from a simulation or test workload

## Alerts and Notifications

Potential operational alerts include:

- budget threshold exceeded
- sudden token-volume increase
- repeated fallback or timeout
- local runtime unavailable
- external processing attempted while disabled
- redaction failure
- validation failure rate above threshold
- agent sandbox capacity exhausted
- cross-tenant policy violation attempt
- telemetry freshness failure

Notifications should include request metadata and safe diagnostic context without exposing raw evidence or secrets.

## Phased Implementation

### Phase 1: Structured telemetry

- define versioned event schemas
- record routing, policy, latency, status, and validation metadata
- separate audit records from dashboard metrics
- add privacy and tenant tests

### Phase 2: Initial AI Operations view

- add summary cards
- show execution-tier distribution
- show latency, tokens, failures, and policy blocks
- support time and task filters
- use seeded data until real telemetry is available

### Phase 3: Cost and quality accounting

- add configurable cost rates
- add budget tracking
- add deterministic evaluation results
- add measured versus estimated labels
- add cost per validated result

### Phase 4: Advanced operations

- add alerting
- add benchmark history
- add agent-runtime health
- add Tool Gateway performance
- add export through vendor-neutral telemetry interfaces

## Acceptance Criteria

The initial production-capable AI operations layer should not be considered complete until:

- every request can be traced from policy decision to final status
- tenant isolation is enforced in telemetry storage and queries
- measured and estimated values are visibly distinguished
- cost savings require an explicit baseline
- prompts and raw evidence are not logged by default
- failures, fallbacks, policy blocks, and validation outcomes are visible
- the dashboard works for deterministic-only and local-only deployments
- quality metrics use reproducible acceptance criteria
- telemetry schemas are independent of any external analytics vendor

## Relationship to Other Documents

- `docs/architecture/ai-advisor.md` defines the overall Advisor role.
- `docs/architecture/ai-model-routing.md` defines execution-tier selection.
- `docs/architecture/ai-governance-security.md` defines policy enforcement and agent isolation.
- `docs/architecture/ai-agent-architecture.md` defines evidence, specialist agents, memory, and Tool Gateway direction.
