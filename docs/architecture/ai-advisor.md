# AI Advisor Architecture

For the foundational AI Advisor purpose, value, evidence, safety principles,
and agent architecture direction, see
`docs/architecture/ai-agent-architecture.md`.

For the future AI evidence card model and AI finding output schema, see the
`AI Evidence and Finding Schema` section in
`docs/architecture/ai-agent-architecture.md`.

The OpenAssetWatch AI Advisor is a future advisory layer that runs after data
collection, normalization, and rule-based risk scoring.

AI should not replace deterministic scoring rules. Rule-based checks remain the
source of truth for repeatable findings such as exposed services, weak device
posture, stale assets, missing updates, or risky configuration patterns. The AI
Advisor should summarize those findings, explain why they matter, prioritize
remediation, and help non-technical users understand what to fix first.

The first AI integration should consume normalized asset and risk data, not raw
packet captures. Advisor output should include evidence references back to the
collected data that produced each recommendation, such as asset identifiers,
observed services, timestamps, collector source evidence, and rule IDs.

Provider support should be optional and pluggable. A local Qwen or other local
LLM provider should be supported later for privacy-focused deployments. External
providers such as Claude, OpenAI, or Gemini can also be optional integrations
later, controlled by deployment configuration.

AI output is advisory only. The AI Advisor must not automatically make network
changes, modify firewall rules, quarantine devices, change router settings, or
perform remediation actions without an explicit future human-approved workflow.

## Deployment Models

The AI Advisor should support multiple deployment models so families and small
operators can choose the privacy, cost, and resource profile that fits them.

### Local/self-hosted AI Advisor

The local model runs on the main OpenAssetWatch server or on a dedicated device
with enough CPU, memory, or GPU resources. It can use Qwen through Ollama,
llama.cpp, vLLM, or another local runtime.

This is the preferred option for privacy-focused users who do not want asset,
risk, or home network data sent to cloud LLM providers.

### Cloud/VPS AI Advisor

The cloud/VPS model runs on the OpenAssetWatch cloud or VPS backend. This
supports a SaaS-like deployment where collectors send normalized data to the
backend and the backend performs advisory analysis.

This model can use a cloud-hosted Qwen instance, a GPU VPS, or an external LLM
API depending on deployment configuration.

### External provider AI Advisor

External provider support should be optional and disabled by default for
privacy. Future integrations may include Claude, OpenAI, Gemini, or other API
providers.

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

## Future Configuration

```yaml
ai:
  enabled: true
  deployment_mode: local
  provider: qwen
  runtime: ollama
  model: qwen
  include_raw_logs: false
  include_asset_evidence: true
  advisory_only: true
```

## Future Splunk Integration

OpenAssetWatch should eventually provide a Splunk Technology Add-on named
`TA-openassetwatch`.

The add-on should ingest OpenAssetWatch JSON events and provide Splunk-specific
knowledge objects without forcing Splunk naming conventions into the
OpenAssetWatch core schema. The core schema should stay clean and portable; the
Technology Add-on should map OpenAssetWatch fields to Splunk and CIM-compatible
field names where appropriate.

The future add-on should provide:

- Sourcetype definitions.
- Field extractions.
- Eventtypes and tags.
- CIM-compatible field mappings where appropriate.
- Support for asset inventory, discovery events, collector health, risk
  findings, future network/service discovery events, and AI Advisor events.

Potential sourcetypes:

- `openassetwatch:asset`
- `openassetwatch:collector`
- `openassetwatch:finding`
- `openassetwatch:network`
- `openassetwatch:service`
- `openassetwatch:ai_advisor`

Potential CIM mapping areas:

- Assets/Identity.
- Network Traffic.
- Vulnerabilities.
- Alerts.
- Change/Inventory-style reporting.

This is future scope only. The Splunk Technology Add-on should not be built
until the core OpenAssetWatch event schemas are stable enough to map cleanly.
