# Product Architecture

OpenAssetWatch is a defensive asset intelligence platform. It discovers what
assets exist, explains what they are doing, identifies risk, and guides
remediation. It remains asset-first, passive-first, evidence-first, and
remediation-focused.

OpenAssetWatch is not copying AiSOC or the prior source/reference project
wholesale. AiSOC and the prior source material are reference inputs only. OAW
keeps defensive concepts that fit its own product direction and rejects unsafe
or offensive platform behavior.

## Hybrid Runtime

OpenAssetWatch is intentionally hybrid:

- Go is used for agent, sensor, collector, CLI, local inventory, network
  observations, service wrappers, installers, and safe diagnostics.
- Python is used for AI Advisor, enrichment, scoring, reporting,
  Splunk/export experiments, evaluation harness, and LLM workflows.

This split keeps local endpoint and sensor collection small, portable, and easy
to package while preserving Python for analysis, reporting, evaluation, and AI
workflows that benefit from the Python ecosystem.

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

AiSOC inspiration is future product and control-plane inspiration only. It may
inform planning for:

- Advisor Run Ledger
- Evidence Ledger
- evaluation harness
- asset, finding, and evidence graph
- workbench UX
- connector security
- audit integrity
- prompt-injection defense
- self-hosted/privacy-first posture

These ideas must be adapted to OpenAssetWatch's purpose and safety posture.
They do not justify copying another product wholesale, importing unsafe source
project tools, or changing OAW into a penetration testing, exploitation,
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
