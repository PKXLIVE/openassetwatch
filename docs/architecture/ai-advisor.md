# AI Advisor Architecture

The first read-only Hub-and-Spoke AI Showcase foundation is implemented and is
documented in `docs/architecture/hub-spoke-ai-showcase.md`. It adds a
deterministic local provider, an explicitly gated provider-compatible
interface, bounded evidence tools, typed answers, audit metadata, and a focused
Control Tower UI view. The implemented versioned rules engine and its authority
boundary are documented in `docs/DETERMINISTIC_FINDINGS_AND_RISK.md`.
The deeper sections linked below remain the canonical direction for future
agents, memory, tool adapters, approvals, and enterprise controls.

This page is the short navigation entry for the OpenAssetWatch AI Advisor.
Canonical AI architecture details live in
`docs/architecture/ai-agent-architecture.md`.

The official AI architecture pattern is **Hierarchical Hub-and-Spoke + Shared
Evidence Blackboard**. Control Tower is the hub/coordinator. Endpoint
collectors, passive network sensors, integrations, `open_detector`,
MCP-style tools, and AI modules are spokes. The AI Advisor reads normalized
evidence and findings, then produces advisory, evidence-linked explanations,
summaries, reports, and recommendations.

For the model-tier selection, privacy-aware escalation, cost controls,
insufficient-evidence handling, and routing telemetry design, see
`docs/architecture/ai-model-routing.md`.

For centralized AI policy, request security, model and agent controls, isolated
execution, token enforcement, and human approval, see
`docs/architecture/ai-governance-security.md`.

For AI usage, cost, token, latency, quality, policy, and operations telemetry,
see `docs/architecture/ai-observability-operations.md`.

For the future AI evidence card model and AI finding output schema, see the
`AI Evidence and Finding Schema` section in
`docs/architecture/ai-agent-architecture.md`.

Key sections:

- For the official architecture pattern, see `Official architecture pattern`.
- For the Mermaid system view, see `High-level system diagram`.
- For the docs-friendly visual artifact, see
  `docs/architecture/ai-advisor-architecture.md`.
- For hub, spoke, blackboard, reviewer, and policy responsibilities, see
  `Component responsibilities`.
- For ingestion-to-advisor behavior, see `Data flow`.
- For the Asset Intelligence Store / Evidence Blackboard model, see
  `Shared Evidence Blackboard`.
- For advisor roles and the Reviewer / Evaluator layer, see
  `AI Advisor modules` and `AI Specialist Agent Roles`.
- For evidence card and AI finding output contracts, see
  `AI Evidence and Finding Schema`.
- For safety, trust, prompt-injection, tenant, privacy, and audit boundaries,
  see `Safety and trust boundaries`, `Prompt-injection and untrusted-data
  handling`, `Tenant and privacy boundaries`, and `Auditability and
  explainability`.
- For local/offline LLM and future BYOK provider direction, see
  `Local/offline LLM and BYOK future support`.
- For MCP and tool safety, see `MCP integration model` and
  `AI Tool Gateway and MCP Safety Model`.
- For allowed and disallowed AI behavior, see `What AI is allowed to do` and
  `What AI is not allowed to do`.
- For the phased implementation direction, see `Future roadmap` and
  `Implementation checklist`.

Design rules:

- AI runs after collection, normalization, and deterministic risk scoring.
- Deterministic rules and scores remain the source of truth.
- The Shared Evidence Blackboard is the source of truth for AI-readable
  evidence context.
- AI consumes normalized evidence, not raw packet captures by default.
- AI output must cite assets, observations, detector results, findings, or
  evidence records wherever practical.
- AI is read-only and advisory by default.
- AI must not execute commands, run scans, capture packets, modify systems,
  change policy, isolate devices, or remediate findings unless a future
  explicit policy and human approval workflow is added.

## Current and Future Operating Model

For the future AI Tool Gateway and MCP/tool-adapter safety model, see the
`AI Tool Gateway and MCP Safety Model` section in
`docs/architecture/ai-agent-architecture.md`.

For the vendor-neutral MCP, toolset, and telemetry integration direction, see
`docs/architecture/ai-mcp-and-telemetry-integration-direction.md`.

For the future AI memory, audit, and agent handoff model, see the
`AI Memory, Audit, and Agent Handoff Model` section in
`docs/architecture/ai-agent-architecture.md`.

For the phased future implementation plan, see the
`AI Advisor Implementation Roadmap` section in
`docs/architecture/ai-agent-architecture.md`.

The OpenAssetWatch AI Advisor is an advisory layer that runs after data
collection, normalization, deterministic finding evaluation, and deterministic
risk scoring. The implemented versioned rules engine and its authority boundary
are documented in `docs/DETERMINISTIC_FINDINGS_AND_RISK.md`.

AI should not replace deterministic scoring rules. Rule-based checks remain the
source of truth for repeatable findings such as exposed services, weak device
posture, stale assets, missing updates, or risky configuration patterns. The AI
Advisor should summarize those findings, explain why they matter, prioritize
remediation, and help non-technical users understand what to fix first.

The first AI integration consumes normalized asset and risk data, not raw
packet captures. Advisor output includes evidence references back to the
collected data that produced each recommendation, such as asset identifiers,
observed services, timestamps, collector source evidence, and rule IDs.

Provider support is optional and pluggable. The deterministic provider is the
current offline default. Local model runtimes should be supported later for
privacy-focused deployments. External model services may also be optional
integrations controlled by deployment and tenant policy.

Provider configuration alone should not determine which model handles every
request. The future AI Model Router should select among deterministic logic,
local lightweight models, local advanced models, optional external models,
human review, or an insufficient-evidence response based on task type, evidence
quality, sensitivity, policy, cost, latency, and available resources.

AI output is advisory only. The AI Advisor must not automatically make network
changes, modify firewall rules, quarantine devices, change router settings, or
perform remediation actions without an explicit future human-approved workflow.

## Deployment Models

The AI Advisor should support multiple deployment models so families and small
operators can choose the privacy, cost, and resource profile that fits them.

### Local/self-hosted AI Advisor

The local model runs on the main OpenAssetWatch server or on a dedicated device
with enough CPU, memory, or accelerator resources. It should connect through a
provider-neutral local runtime interface.

This is the preferred option for privacy-focused users who do not want asset,
risk, or home network data sent to external model providers.

### Cloud/VPS AI Advisor

The cloud/VPS model runs on the OpenAssetWatch cloud or VPS backend. This
supports a service-style deployment where collectors send normalized data to the
backend and the backend performs advisory analysis.

This model may use a self-hosted remote inference service or an approved
external model API depending on deployment configuration.

### External provider AI Advisor

External provider support should be optional and disabled by default for
privacy. Integrations should use provider-neutral adapters and capability
metadata rather than embedding vendor-specific behavior into task definitions.

The provider should be configurable through settings or environment variables so
deployments can explicitly choose whether data leaves the local or VPS
environment.

## Design Rules

- AI runs after collection, normalization, and rule-based risk scoring.
- AI consumes normalized asset and risk data, not raw packet captures by default.
- AI explains findings, summarizes risk, prioritizes remediation, and helps
  users understand what to fix first.
- AI includes evidence references from collected data.
- AI is advisory only.
- AI must not automatically make network changes.
- AI provider selection should be configurable through settings or environment
  variables later.
- The router should prefer deterministic or local execution when it can satisfy
  the task safely.
- A stronger model must not be used as a substitute for missing evidence.
- External model use must be policy-controlled, redacted where required, and
  audited.
- Routing telemetry and benchmarks must distinguish measured, estimated, and
  synthetic results.
- Architecture documents should remain independent of model, runtime, hardware,
  and cloud vendors.

## Future Configuration

```yaml
ai:
  enabled: true
  deployment_mode: local
  provider: configured_local_provider
  runtime: configured_local_runtime
  model: configured_model
  include_raw_logs: false
  include_asset_evidence: true
  advisory_only: true
```

The single-provider example above remains useful for an initial deployment. The
longer-term tiered and policy-aware configuration is documented in
`docs/architecture/ai-model-routing.md`.

## Future SIEM Integration

OpenAssetWatch should eventually provide a SIEM integration package.

The integration should ingest OpenAssetWatch JSON events and provide
SIEM-specific knowledge objects without forcing SIEM naming conventions into
the OpenAssetWatch core schema. The core schema should stay clean and portable;
the integration package should map OpenAssetWatch fields to common SIEM field
names where appropriate.

The future add-on should provide:

- Event type definitions.
- Field extractions.
- Eventtypes and tags.
- Common field mappings where appropriate.
- Support for asset inventory, discovery events, collector health, risk
  findings, future network/service discovery events, and AI Advisor events.

Potential event types:

- `openassetwatch:asset`
- `openassetwatch:collector`
- `openassetwatch:finding`
- `openassetwatch:network`
- `openassetwatch:service`
- `openassetwatch:ai_advisor`

Potential mapping areas:

- Assets/Identity.
- Network Traffic.
- Vulnerabilities.
- Alerts.
- Change and inventory reporting.

This is future scope only. The SIEM integration package should not be built
until the core OpenAssetWatch event schemas are stable enough to map cleanly.
