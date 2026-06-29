# AI MCP and Telemetry Integration Direction

This note defines vendor-neutral OpenAssetWatch architecture direction for MCP,
AI tool access, and telemetry export.

This is docs-only. It does not implement MCP servers, add third-party
monitoring integration, copy external repositories, add scanner behavior, or
authorize unsafe tools.

External products may be reviewed privately for general inspiration, but
OpenAssetWatch documentation must describe vendor-neutral design principles and
original project direction.

## Product Stance

AI/MCP is part of the OpenAssetWatch end-state product experience. It should be
the controlled interface that lets AI assist with detection review, evidence
navigation, finding explanation, confidence scoring, reporting, and approved
tool use.

AI/MCP should not bypass the OpenAssetWatch evidence model, tenant model,
safety policy, or audit model. The database remains the source of truth. AI and
MCP tools should operate on evidence that OpenAssetWatch collected,
normalized, enriched, and scored.

## Vendor-Neutral Design Inputs

The current architecture direction keeps these general product patterns without
naming or depending on external vendors:

| Concept | Useful pattern | OpenAssetWatch adaptation |
| --- | --- | --- |
| Knowledge and context retrieval | Keeps knowledge data server-side or tenant-local while exposing a narrow retrieval interface to AI clients. | Support a clean local bridge and remote gateway pattern. Keep customer knowledge, findings, and evidence out of bundled clients. Separate environments and avoid command collisions. |
| Domain-specific evidence lookup | Exposes focused capabilities such as code, file, diff, configuration, and approved finding review without broad access to the underlying system. | Model future toolsets as narrow, named capabilities with explicit approval semantics. Application-security and SBOM findings can become evidence inputs, but OpenAssetWatch should not become a broad code scanner in the SMB MVP. |
| Remote MCP gateway | Groups tools by toolset, supports selecting only required toolsets, supports excluding risky tools, and documents required permissions per tool. | Use toolsets and explicit tool metadata to reduce context bloat and safety risk. Require OpenAssetWatch capabilities, tenant scope, and resource-level permissions for every tool. |
| Local bridge and hosted gateway | Supports both remote HTTP endpoints and local stdio bridges for self-hosted or local deployments. | Provide both hosted and local/self-hosted MCP deployment patterns. Hosted deployments can use OAuth later; local deployments can use local tokens or service accounts. |
| Vendor-neutral telemetry | Uses OpenTelemetry/OTLP to collect and route traces, metrics, and logs through standard collector paths. | Use OpenTelemetry/OTLP as the preferred path for OpenAssetWatch service, collector, and AI/MCP observability. Do not make any commercial observability vendor required. |

## OpenAssetWatch MCP Shape

OpenAssetWatch should have one controlled MCP gateway rather than letting AI
clients call internal APIs, collectors, databases, or third-party tools
directly.

The gateway should support:

- remote HTTP transport for hosted or VPS deployments
- local stdio bridge for self-hosted and desktop deployments
- scoped service-account or OAuth-based authentication
- tenant, site, deployment, collector, and asset boundaries
- toolset filtering so small users only expose what they need
- per-tool metadata and permission checks
- audit records for every tool call and output
- evidence references in tool outputs wherever practical

The gateway should be treated as a control point, not as a convenience wrapper.
If a user or AI agent cannot do something safely through the gateway, the task
should stop and explain what permission, evidence, approval, or capability is
missing.

## Initial Toolsets

OpenAssetWatch MCP toolsets should start narrow and evidence-oriented.

| Toolset | Purpose | Default behavior |
| --- | --- | --- |
| `inventory` | Search assets, list new or stale assets, show collector status, and inspect normalized asset records. | Read-only |
| `evidence` | Retrieve evidence cards, source references, observation summaries, and data-quality notes. | Read-only |
| `findings` | Search findings, explain severity and confidence, and group related findings. | Read-only |
| `behavior` | Review passive behavior baselines, changed peers, changed services, and anomaly candidates. | Read-only |
| `coverage` | Show missing EDR, MDM, logging, vulnerability, identity, or inventory evidence where available. | Read-only |
| `reports` | Draft executive summaries, technical remediation reports, weekly reviews, and owner-facing notes. | Draft-only unless explicitly exported |
| `telemetry` | Inspect OpenAssetWatch service health, collector health, queue health, and AI/MCP workflow health. | Read-only |
| `integrations` | Read or export approved data for future SIEM, observability, ticketing, or CMDB workflows. | Read-only by default |
| `application_security_ingest` | Ingest or summarize external application-security, SBOM, SCA, or CI findings as evidence attached to assets and applications. | Read-only import or staged review |
| `actions` | Future approval-gated diagnostics, ticket creation, or notification workflows. | Disabled until policy, approval, and audit controls exist |

The default install should expose only the smallest useful toolsets. Advanced
toolsets should be enabled deliberately by the deployment or administrator.

## Detection-Assist Workflow

AI/MCP should sit in the normal evidence and finding workflow:

```text
Collectors and connectors
-> normalized evidence
-> deterministic rules and baseline checks
-> evidence cards
-> AI/MCP detection assistance
-> confidence, explanation, and recommendation
-> report or approval-gated next step
```

The AI/MCP layer should help:

- correlate evidence from multiple sources
- identify findings that deserve attention
- explain why an asset or behavior is risky
- assign confidence based on evidence quality
- identify evidence gaps
- reduce duplicate or noisy findings
- generate safe validation steps
- produce user-appropriate reports

The AI/MCP layer should not:

- invent evidence
- claim compromise without support
- start active scanning by default
- run arbitrary shell commands
- trigger unrestricted scans
- open a terminal, remote shell, or webshell
- capture packets by default
- collect credentials
- brute force authentication
- perform lateral movement
- run exploit or payload workflows
- bypass production authentication
- execute self-updates
- modify firewall, endpoint, collector, or network settings automatically
- bypass tenant or site boundaries

## Authentication And Permissions

OpenAssetWatch should follow a layered permission model:

- MCP access permission: whether the user or service account can use MCP at all
- toolset permission: which toolsets can be exposed
- tool permission: which tools inside a toolset can run
- resource permission: which tenants, sites, assets, collectors, findings, or
  integrations the tool can access
- action permission: whether a write, export, notification, or diagnostic
  action is allowed
- approval requirement: whether a human approval record is required before
  execution

Hosted deployments may eventually support OAuth-based login. Local and
self-hosted deployments may use local tokens, service accounts, or deployment
keys. Secrets must not be embedded in plugins, docs, generated configs, or
bundled clients.

## OpenTelemetry Direction

OpenTelemetry should be the preferred observability standard for
OpenAssetWatch's own runtime telemetry.

OpenAssetWatch should eventually emit:

- Control Tower traces, metrics, and logs
- ingestion and normalization worker metrics
- queue depth and job latency metrics
- collector check-in and health metrics
- AI/MCP request, tool-call, denial, approval, and latency metrics
- report-generation and export-job metrics

OTLP should be treated as a vendor-neutral lane. Users should be able to send
OpenAssetWatch telemetry to a local OpenTelemetry Collector, a compatible
observability backend, or no external backend at all.

Commercial observability integration can be useful later, but it should be an
optional export target, not the required observability architecture.

## External Observability Integration Direction

OpenAssetWatch should not require any specific commercial observability
platform.

Future observability work may include:

- exporting OpenAssetWatch service telemetry through OTLP
- exporting selected findings, assets, or health metrics to an approved
  observability backend
- reading approved external hosts, services, monitors, incidents, logs, traces,
  or security findings as optional enrichment
- using policy-scoped tool permissions, tool filtering, and resource-level
  access checks

Any observability connector should be tenant-scoped, least-privilege, and
explicit about what data leaves OpenAssetWatch.

## Application Security And Code Evidence Direction

Domain-specific MCP interfaces can expose code, file, diff, config, and
approval workflows to AI clients without broad tool access.

For OpenAssetWatch, application security should be treated as an evidence
source before it is treated as a native scanner. Useful future inputs include:

- SBOM records
- SCA findings
- CI/CD security findings
- repository metadata
- application ownership
- runtime deployment evidence
- secrets-scanning findings from approved external systems

These inputs should attach to assets, applications, services, owners, and
findings. Native scanning can be considered later only if it remains scoped,
safe, and aligned with the Security Tool Policy.

## Non-Goals

This direction does not authorize:

- copying external product or vendor code
- embedding customer evidence or knowledge data into MCP client bundles
- exposing arbitrary database access to AI clients
- exposing raw shell, unrestricted filesystem, or unrestricted code execution
- adding remote actions before approval, policy, and audit controls exist
- making any commercial observability provider a required dependency
- introducing vendor lock-in
- replacing deterministic rules with model-only detection

## Reference Boundary

External products and open-source examples may be reviewed privately for broad
research context, but committed OpenAssetWatch documentation should describe
vendor-neutral principles, original product direction, and OpenAssetWatch
safety boundaries.
