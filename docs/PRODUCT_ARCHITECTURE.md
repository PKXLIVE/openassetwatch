# Product Architecture

OpenAssetWatch is a defensive asset intelligence platform. It discovers what
assets exist, explains what they are doing, identifies risk, and guides
remediation. It remains asset-first, passive-first, evidence-first, and
remediation-focused.

The product architecture is OpenAssetWatch-owned. New capabilities must extend
its existing evidence, policy, and deterministic authority boundaries rather
than create a competing source of truth or redirect the product into unrelated
security tooling.

OpenAssetWatch is not copying any external project wholesale. Private research
material and reference architecture patterns are inputs only. OpenAssetWatch
keeps defensive concepts that fit its own product direction and rejects unsafe
or offensive platform behavior.

The first implemented hub-and-spoke AI showcase, its normalized observation
batch contract, provider boundary, and current limitations are documented in
`docs/architecture/hub-spoke-ai-showcase.md`.
The Linux-first passive sensor, cross-platform replay, privacy boundary, and
deployment model are documented in `docs/PASSIVE_SENSOR_MVP.md`. Hardened
systemd deployment and authorized SPAN validation are documented in
`docs/SENSOR_LINUX_DEPLOYMENT.md`.
Its one-time enrollment, site/sensor-bound bearer credential, rotation,
revocation, and certificate-migration boundary are documented in
`docs/SENSOR_ENROLLMENT.md`.
The authoritative deterministic rule registry, finding lifecycle, explainable
asset/site risk formula, API, AI boundary, and safe extension process are
documented in `docs/DETERMINISTIC_FINDINGS_AND_RISK.md`.
The deterministic asset model, source-aware evidence fusion, confidence and
conflict rules, managed-capability expectations, local vendor catalog, APIs,
and AI authority boundary are documented in
`docs/ASSET_CLASSIFICATION_AND_EVIDENCE_FUSION.md`.
The normalized software/firmware model, conservative version comparison,
reviewed offline advisory catalog, deterministic matcher, finding/risk
integration, AI boundary, dashboard, performance harness, and future adapter
contract are documented in
`docs/SOFTWARE_AND_VULNERABILITY_INTELLIGENCE.md`.
The optional additive design for Certificate Transparency, passive DNS,
Internet-exposure observations, relationship projections, local redaction, and
provider-neutral external-intelligence adapters is documented in
`docs/architecture/external-intelligence-enrichment-roadmap.md` and governed by
`docs/architecture/decisions/0002-additive-external-intelligence-enrichment.md`.
It extends existing evidence workflows and must not replace current collectors,
sensors, asset authority, findings, risk, AI boundaries, or local-first
operation.

Accepted native design expansions are documented in:

- `docs/architecture/agent-investigation-control-loop.md` - deterministic
  triage, isolated specialist tasks, correlation, verification, human review,
  and the Agent Run Ledger;
- `docs/architecture/skill-pack-contract.md` - versioned first-party Skill Pack
  instructions and schemas under the existing policy/tool boundary;
- `docs/architecture/capability-provider-contract.md` - separation between
  OpenAssetWatch-owned capability meaning and replaceable provider
  implementations;
- `docs/architecture/agent-evaluation-and-release-gates.md` - evidence,
  permission, isolation, verification, prompt-injection, and release tests; and
- `docs/architecture/temporal-intelligence-roadmap.md` - deterministic
  historical baselines, expected ranges, deviation candidates, and future
  provider-neutral forecasting.

These design documents do not claim that their future runtimes are implemented.

## Hub-And-Spoke Control Plane

The Control Tower hub owns the API, PostgreSQL evidence store, site and sensor
identity, health/freshness, deterministic classification and history, risk and
findings projection, AI Advisor, controlled tool gateway, authentication
boundary, audit metadata, and cross-site views.

Future investigation control state, Agent Run Ledger records, Skill Pack
selection, capability/provider bindings, and temporal signal/expectation
projections also belong to the hub. A model/provider may execute bounded
analysis, but it does not own these lifecycle records or their accepted state
transitions.

Endpoint collectors, passive network sensors, and future SNMP, cloud,
vulnerability, identity, and SIEM connectors are spokes. A spoke belongs to a
site, keeps a stable identity, and sends authenticated outbound observations.
Spokes should cache bounded observations during outages and retry idempotently;
they should expose no inbound management port by default.

Optional external-intelligence adapters are future bounded enrichment spokes.
They may submit provenance-tagged observations only after verified-scope,
source-license, privacy, and capability checks. They are not authoritative asset
inventories and must degrade independently when a provider is unavailable.

The AI primarily runs at the hub over normalized evidence. It receives no
arbitrary shell, SQL, filesystem, operating-system, packet-capture, or spoke
management access.

## Authority Order

The implemented authority order remains:

```text
authenticated normalized evidence
  -> deterministic classification and matching
  -> deterministic findings and attention scoring
  -> bounded investigation and AI explanation
  -> human review
```

Future specialist agents, Skill Packs, temporal analytics, and provider
implementations operate inside the bounded investigation/AI layer. They cannot
skip or replace the deterministic layers above them.

## Hybrid Runtime

OpenAssetWatch is intentionally hybrid:

- Go is used for agent, sensor, collector, CLI, local inventory, network
  observations, service wrappers, installers, and safe diagnostics.
- Python is used for AI Advisor, enrichment, scoring, reporting,
  SIEM/export experiments, evaluation harness, investigation orchestration,
  temporal analytics, and LLM workflows.

This split keeps local endpoint and sensor collection small, portable, and easy
to package while preserving Python for analysis, reporting, evaluation, and AI
workflows that benefit from the Python ecosystem.

Advisory publication is a separate product-owned static distribution service,
not part of a customer hub runtime. It serves only signed public advisory
indexes and immutable signed bundles. Self-hosted, hosted, and hybrid hubs
consume those vendor-neutral artifacts through the same reviewed trust,
approval, activation, finding, risk, and AI evidence contracts.

## Native Investigation Architecture

OpenAssetWatch may coordinate multiple bounded specialist analyses when one
finding or question benefits from independent perspectives. The coordinator is
product code and owns scope, budgets, task dispatch, state transitions,
correlation, verification requirements, cancellation, recovery, and audit.

First-pass specialists should receive isolated contexts drawn from the same
server-issued evidence rather than seeing peer conclusions. Typed specialist
outputs remain advisory hypotheses until deterministic correlation and an
independent verification stage evaluate them. Agent agreement is not proof.

The investigation state and ledger are OpenAssetWatch records. Model
conversation memory is not the system of record.

## Skill Packs

OpenAssetWatch Skill Packs are first-party, versioned instruction and schema
packages for repeatable specialist analysis. They may narrow task behavior but
cannot add tools, expand scope, bypass tenant/site controls, change provider
privacy policy, or grant write authority.

The reserved `configs/skills/` namespace is intended for this future contract.
Initial Skill Packs are configuration-only; arbitrary executable scripts,
self-installing content, and recursive specialist spawning are not part of the
initial runtime.

## Capability And Provider Boundary

A capability is an OpenAssetWatch-owned product contract. A provider is one
replaceable implementation of that contract.

Provider output is always untrusted until OpenAssetWatch validates its schema,
evidence references, scope, size, and permitted state. Provider changes must not
change authoritative asset, evidence, finding, risk, authorization, or approval
semantics.

A local-only deployment must never silently send data to a hosted provider after
a local failure. Crossing a privacy boundary requires explicit operator
configuration.

## Temporal Intelligence

Temporal Intelligence is an optional analytical layer over OpenAssetWatch-owned
historical evidence. It should begin with deterministic, explainable baselines
for signals such as asset population, collector/sensor health, finding backlog,
vulnerability backlog, software/firmware transition, and security-tool coverage.

Expected ranges and forecast artifacts are context, not facts. A temporal
deviation may feed a separately reviewed deterministic rule or investigation,
but it cannot directly confirm compromise, vulnerability, asset identity, or
risk.

Advanced forecasting providers are later work and must remain optional. They
must be evaluated against transparent deterministic baselines with time-split
backtesting, missing-data cases, privacy review, and resource limits.

## Evaluation And Release Gates

Agent and temporal capabilities require evaluation of product behavior, not only
response quality. Release gates must cover evidence integrity, scope isolation,
tool boundaries, authoritative-write protection, verification, false closure,
prompt injection, cancellation, provider failure, privacy, and repeated-run
variance.

Synthetic, deterministic, local-model, hosted-model, and end-to-end results must
be labeled separately. No single aggregate score may hide a hard safety failure.

## Deployment Models

OpenAssetWatch should support multiple enterprise deployment models:

- Self-hosted/customer-managed: customers run the control plane, storage,
  agents, sensors, and connectors in their own environment.
- Hosted/cloud-managed: OpenAssetWatch hosts the control plane and managed
  services while customers deploy scoped collection components as needed.
- Hybrid hosted control plane with customer-managed agents, sensors, and
  connectors: OpenAssetWatch manages central product services while customers
  keep local collection and connector execution under their control.

All deployment models must preserve passive-first collection, scoped
configuration, auditability, tenant/site boundaries, and evidence provenance.
Optional external providers must never become required for core discovery,
classification, findings, risk, reporting, or AI explanation.

## Deployment Identity

Future hosted, self-hosted, and hybrid deployments need a durable identity model
so the control plane can distinguish tenant, site, deployment, installed agent
or sensor instance, normalized OpenAssetWatch asset, and future external CMDB
mappings.

The intended identity fields are:

- `tenant_id`: customer/account boundary. Optional in self-hosted single-tenant
  mode for now.
- `site_id`: required environment, site, workspace, or operational boundary.
- `deployment_id`: unique GUID for an installer or deployment package. It is
  safe to log and should come from deployment config, enrollment config, or an
  installer wrapper.
- `agent_id`: unique installed agent instance ID, generated on first install or
  first run and persisted locally.
- `sensor_id`: unique installed sensor instance ID, generated on first install
  or first run and persisted locally.
- `asset_id`: OpenAssetWatch asset identity after normalization and matching.
- `external_ci_id`: optional external CMDB CI identifier for future
  reconciliation.
- `external_ci_source`: optional external CMDB source name.

Signed binaries and installers should remain generic where possible. Enrollment
tokens, license keys, signing keys, and customer secrets must be represented as
secret references or placeholders, never committed raw values. `deployment_id`
is safe to log; enrollment tokens are secrets.

## Licensing Direction

OpenAssetWatch is a licensed product. Licensing and entitlement design will be
added later as a dedicated control-plane workstream. Do not implement license
enforcement in this pass.

Future license checks should support:

- edition and feature entitlements
- tenant and site limits
- agent and sensor limits
- connector limits
- optional analytical/provider capabilities
- offline and self-hosted operation
- auditable entitlement decisions

License keys, signing keys, entitlement secrets, provider API keys, and customer
secrets must not be stored in the repository. Future implementations should use
CI/CD secret references and deployment-specific secret stores.

## Native Extension Boundaries

OpenAssetWatch may add new capabilities only when they preserve the following
boundaries:

- authoritative relational/product records remain the system of record;
- optional providers do not become mandatory platform dependencies;
- extensions use typed capability and evidence contracts;
- product policy owns tools, scope, approval, and state transitions;
- external or model-generated content is untrusted data;
- Agent Run Ledger and audit records store bounded lifecycle facts rather than
  hidden reasoning;
- graphs, search indexes, vector stores, and provider session memory remain
  projections or advisory helpers rather than authority;
- prompt-injection resistance and public/private data boundaries are release
  concerns; and
- local-first/privacy-first operation remains available.

New capability design must not turn OpenAssetWatch into an offensive testing,
unsafe payload, credential attack, command-and-control, terminal, or raw scanner
platform.

## Product Inspiration Boundaries

External products may be reviewed privately for general inspiration, but
OpenAssetWatch documentation must describe vendor-neutral design principles and
original project direction. Private research and reference architecture
patterns may inform planning for:

- Advisor Run Ledger
- Evidence Ledger
- evaluation harness
- asset, finding, and evidence graph
- workbench UX
- connector security
- audit integrity
- prompt-injection defense
- self-hosted/privacy-first posture
- provider-neutral external-intelligence enrichment
- Certificate Transparency and public-record monitoring
- local redaction and safe investigation launchers
- MCP toolset design and vendor-neutral telemetry

For the SMB/personal asset intelligence product direction, see
`docs/architecture/smb-asset-intelligence-product-direction.md`.

For the AI/MCP toolset, gateway, and OpenTelemetry/OTLP integration direction,
see
`docs/architecture/ai-mcp-and-telemetry-integration-direction.md`.

These ideas must be adapted to OpenAssetWatch's purpose and safety posture.
They do not justify copying another product wholesale, importing unsafe source
project tools, or changing OpenAssetWatch into an offensive testing, unsafe
payload, credential attack, C2, terminal, raw scanner, people-search, or
restricted-data redistribution platform.

## Current Non-Goals

This architecture note does not by itself implement the accepted future
capabilities. In the current design expansion, do not:

- implement license enforcement
- add new hosted service behavior
- add offensive tools
- enable executable or user-installed Skill Packs
- add recursive specialist spawning
- add write-capable specialist tools
- make advanced forecasting a required dependency
- make forecast/model output authoritative
- change quarantine policy
- add raw command wrappers or arbitrary arguments
- add credentials or secrets
- add active Internet scanning or third-party scan orchestration
- submit discovered URLs or customer data to external providers
- treat external observations as confirmed assets or findings
