# Product Architecture

OpenAssetWatch is a defensive asset intelligence platform. It discovers what
assets exist, explains what they are doing, identifies risk, and guides
remediation. It remains asset-first, passive-first, evidence-first, and
remediation-focused.

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

## Hub-And-Spoke Control Plane

The Control Tower hub owns the API, PostgreSQL evidence store, site and sensor
identity, health/freshness, deterministic classification and history, risk and
findings projection, AI Advisor, controlled tool gateway, authentication
boundary, audit metadata, and cross-site views.

Endpoint collectors, passive network sensors, and future SNMP, cloud,
vulnerability, identity, and SIEM connectors are spokes. A spoke belongs to a
site, keeps a stable identity, and sends authenticated outbound observations.
Spokes should cache bounded observations during outages and retry idempotently;
they should expose no inbound management port by default.

The AI primarily runs at the hub over normalized evidence. It receives no
arbitrary shell, SQL, filesystem, operating-system, packet-capture, or spoke
management access.

## Hybrid Runtime

OpenAssetWatch is intentionally hybrid:

- Go is used for agent, sensor, collector, CLI, local inventory, network
  observations, service wrappers, installers, and safe diagnostics.
- Python is used for AI Advisor, enrichment, scoring, reporting,
  SIEM/export experiments, evaluation harness, and LLM workflows.

This split keeps local endpoint and sensor collection small, portable, and easy
to package while preserving Python for analysis, reporting, evaluation, and AI
workflows that benefit from the Python ecosystem.

Advisory publication is a separate product-owned static distribution service,
not part of a customer hub runtime. It serves only signed public advisory
indexes and immutable signed bundles. Self-hosted, hosted, and hybrid hubs
consume those vendor-neutral artifacts through the same reviewed trust,
approval, activation, finding, risk, and AI evidence contracts.

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
- offline and self-hosted operation
- auditable entitlement decisions

License keys, signing keys, entitlement secrets, and customer secrets must not
be stored in the repository. Future implementations should use CI/CD secret
references and deployment-specific secret stores.

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
- MCP toolset design and vendor-neutral telemetry

For the SMB/personal asset intelligence product direction, see
`docs/architecture/smb-asset-intelligence-product-direction.md`.

For the AI/MCP toolset, gateway, and OpenTelemetry/OTLP integration direction,
see
`docs/architecture/ai-mcp-and-telemetry-integration-direction.md`.

These ideas must be adapted to OpenAssetWatch's purpose and safety posture.
They do not justify copying another product wholesale, importing unsafe
external tools, or changing OpenAssetWatch into an offensive testing, unsafe
payload, credential attack, C2, terminal, or raw scanner platform.

## Current Non-Goals

This architecture note does not add product features. In this pass, do not:

- implement license enforcement
- add new hosted service behavior
- add offensive tools
- work on Skills
- change quarantine policy
- add raw command wrappers or arbitrary arguments
- add credentials or secrets
