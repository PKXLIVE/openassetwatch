# SMB Asset Intelligence Product Direction

This note translates private research context and existing OpenAssetWatch
architecture into a right-sized product direction for small/medium business,
personal, home lab, and privacy-focused self-hosted users.

This is docs-only. It does not implement product behavior, copy an external
product, authorize unsafe tools, or reposition OpenAssetWatch toward the
Fortune 500, national government, or critical-infrastructure customer base that
enterprise cyber exposure platforms normally pursue.

## North Star

OpenAssetWatch should become a simple, deployable asset intelligence and cyber
exposure advisor for users who cannot buy, staff, or operate million-dollar
enterprise platforms.

The core experience should answer five questions:

- What assets exist here?
- What changed recently?
- What looks unmanaged, exposed, outdated, or abnormal?
- What should I fix first?
- What evidence supports that recommendation?

AI/MCP is part of the end-state product experience. It should run as a
controlled advisor and detection-assist layer that helps review evidence,
explain findings, assign confidence, and guide the end user through what
OpenAssetWatch observed.

The product should provide enough detail for trust and auditability, but should
not force the user to understand enterprise CAASM, SIEM, EDR, AppSec, network
detection, or vulnerability-management terminology before they get value.

## Target Users

OpenAssetWatch should optimize first for:

- personal/home lab users who want to understand a home or lab network
- small businesses without a full security team
- medium businesses with lean IT or security staff
- privacy-focused users who prefer local or self-hosted operation
- small MSP-like operators who need visibility without heavy enterprise tooling

The initial user should not need a security operations center, a data engineer,
or a professional services engagement to deploy the product.

The existing deployment sizing work can still support larger lab or simulated
production shapes, but the product experience should feel excellent at 10 to
1,000 assets before it tries to feel enterprise-scale.

## Product Positioning

OpenAssetWatch should not try to be a cheaper copy of an enterprise exposure
platform. It should be a different product with a clear defensive goal:

```text
Give small operators a safe, local-first way to understand their assets,
reduce blind spots, and decide what to fix next.
```

The product should borrow the useful product pattern, not the enterprise market
posture. The valuable pattern is unified asset truth, contextual risk, behavior
awareness, and remediation guidance. The OpenAssetWatch difference is easy
deployment, safe defaults, local/privacy-friendly operation, and progressive
detail for non-specialists.

## Research Signals

Private research material points to several repeating themes:

| Research signal | OpenAssetWatch adaptation |
| --- | --- |
| Application security tools create noise when they are fragmented, static, or disconnected from runtime and ownership context. | Avoid a pile of raw alerts. Normalize findings into one evidence-backed risk queue with owner, asset, source, confidence, and next step. |
| Asset intelligence depends on fingerprinting, deduplication, conflict resolution, context, and behavior baselines. | Build a local asset intelligence layer that reconciles agent, network, router, DNS, DHCP, cloud, and optional security-tool evidence into a single asset view. |
| Enterprise users value a single source of truth across devices, users, networks, applications, cloud, and security controls. | For SMB/personal use, start with devices and network observations, then add users, cloud accounts, applications, and data stores as lightweight enrichment. |
| Traffic anomaly detection is more useful when it is asset-centric, baseline-driven, confidence-scored, and visual. | Add passive behavior baselines that explain unusual new peers, protocols, services, or volume changes without claiming compromise without evidence. |
| AI-powered defense is attractive, but many organizations lack budget, resources, and expertise to operate AI security tools. | Make AI/MCP a core end-state advisor and detection-assist layer that is evidence-cited, local-provider capable, and useful without requiring the user to tune models or prompts. |
| Enterprise platforms may disconnect or quarantine assets when behavior deviates from a baseline. | Keep OpenAssetWatch advisory by default. Any future containment, ticketing, active scan, or network change must require explicit approval and policy checks. |

## What To Emulate

OpenAssetWatch should emulate these product goals:

- complete and trustworthy asset inventory
- reconciliation across multiple noisy data sources
- asset fingerprinting and deduplication
- local context around what an asset is and what it normally does
- confidence scoring for findings and anomalies
- prioritization that helps users focus on what matters
- remediation guidance tied to evidence
- simple dashboards that turn raw telemetry into decisions
- reporting that supports both technical and non-technical readers

The user-facing result should feel like an asset map plus a practical advisor,
not a log search interface.

## What Not To Emulate

OpenAssetWatch should avoid these enterprise or high-risk patterns:

- global crowdsourced device intelligence as a required dependency
- public industry benchmarking as a core feature
- automatic quarantine, disconnect, or remediation by default
- full enterprise AppSec scanning across SAST, SCA, IaC, secrets, SBOM, IDE,
  Git, CI/CD, containers, and production runtime in the core MVP
- Fortune 500 procurement, deployment, or professional-services assumptions
- alert volume as a measure of product value
- offensive testing, exploit execution, credential collection, or raw scanner
  launcher behavior

Application-security and software-supply-chain findings may become useful
inputs later, but OpenAssetWatch should ingest or summarize those findings
before it tries to become a full AppSec scanner itself.

## First Screen Experience

The first screen should make the product immediately useful:

- known assets
- new or unknown assets
- stale or missing assets
- risky services or exposures
- missing security protections
- recent changes
- top recommended fixes
- evidence quality and confidence

The first screen should not begin with product marketing, raw event tables, or
configuration-heavy workflows. A small operator should be able to open the app
and understand whether anything changed, what needs attention, and why.

## Progressive Detail Model

To provide detail without overwhelming the user, every finding should support a
progressive detail ladder:

1. Plain-language summary.
2. Why it matters.
3. Recommended action.
4. Safe validation steps.
5. Evidence cards.
6. Raw source references for advanced review.

The default view should be calm and decision-oriented. Deeper evidence should
be available when the user needs to audit, troubleshoot, or learn.

## Core MVP Capabilities

The SMB/personal MVP should prioritize:

- local Control Tower deployment with simple setup
- endpoint agent inventory for Windows, macOS, and Linux where available
- passive local network observations through an optional sensor
- asset identity reconciliation and duplicate detection
- observed services, software, operating systems, and device type clues
- new asset and changed asset detection
- stale asset and stale collector detection
- security tooling coverage checks where evidence exists
- AI-assisted evidence review, finding explanation, and prioritization
- deterministic risk rules before AI recommendations
- evidence-linked findings and reports
- exportable summaries for owners, family members, clients, or auditors

The MVP should preserve core ingestion, normalization, and evidence storage if
the AI worker is paused or temporarily unavailable, but the product direction
should not treat AI/MCP as optional. The intended experience includes AI/MCP
assistance for detection review, finding explanation, prioritization, confidence
scoring, and evidence navigation. AI should run on evidence OpenAssetWatch has
already collected, and should not replace deterministic rules or basic asset
ingestion.

## Later Capabilities

Later phases can add:

- behavior baselines by asset, peer, protocol, service, and time window
- confidence-scored anomaly findings
- router, firewall, DNS, DHCP, identity, cloud, and vulnerability connectors
- MCP toolsets for inventory, evidence, findings, behavior, reports, and
  telemetry
- OpenTelemetry/OTLP export for OpenAssetWatch service and collector telemetry
- simple ticket creation with approval
- SIEM export and advisor workflows
- local LLM summaries and remediation plans
- optional external LLM providers with explicit data-sharing controls
- community or curated device profiles, if privacy and provenance are clear
- application-security or SBOM finding ingestion as an asset and exposure
  input

These features should remain evidence-first, advisory-first, and safe by
default.

## Data Model Implications

The product direction favors a graph-like asset intelligence model, even if the
first implementation stores it in ordinary relational tables.

Important objects include:

- asset
- site
- collector
- sensor
- identity or owner
- network observation
- software observation
- service observation
- security tooling observation
- vulnerability or exposure enrichment
- behavior baseline
- evidence card
- finding
- recommendation
- remediation state

Every derived conclusion should remain traceable to evidence. When the product
deduplicates assets, merges records, infers a device type, or flags a behavior
change, the UI and reports should preserve why that conclusion was reached.

## AI Advisor Fit

The existing AI Advisor architecture aligns well with the research. The AI
Advisor should be the explainer and prioritizer for the asset intelligence
layer, not the source of truth.

In the end-state product, the AI/MCP layer should run as part of the normal
detection and finding workflow. It should help correlate evidence, identify
which detections deserve attention, explain why a finding matters, and guide
the user through the supporting evidence.

Useful AI Advisor jobs include:

- explain why an asset is risky
- summarize what changed this week
- assist detection review with evidence-linked confidence
- identify unmanaged or under-protected devices
- group similar findings into a fix plan
- write an executive or family-friendly summary
- produce a technical remediation checklist
- suggest safe validation steps
- explain evidence gaps and confidence limits

AI must not invent evidence, claim compromise without support, run active
scans, execute commands, modify network controls, or remediate automatically.

## Deployment Principles

The SMB/personal version should be boring to deploy:

- single-node local mode first
- optional sensor, not mandatory sensor
- AI/MCP included in the end-state architecture
- small installs may run AI/MCP on the same host when resources allow
- larger installs may isolate AI/MCP on a separate worker or server
- opinionated defaults
- clear health checks
- no required cloud account
- no required enterprise identity provider
- no required SIEM
- no required packet capture
- no default active scanning

The product should support a path from "one local server and a few agents" to a
larger multi-node deployment, but small users should not feel punished for
starting small.

## Product Guardrails

OpenAssetWatch should remain:

- passive-first
- evidence-first
- advisory-first
- privacy-conscious
- easy to deploy
- easy to understand
- safe by default
- auditable
- local/self-hosted capable

The product should not become a penetration-testing platform, autonomous
remediation system, raw scanner launcher, credential attack tool, or enterprise
only CAASM clone.

## Roadmap Shaping

The practical roadmap should be:

1. Establish asset truth.
2. Reconcile and deduplicate evidence.
3. Add understandable risk and coverage findings.
4. Make the first screen useful for non-experts.
5. Add reports and remediation plans.
6. Add behavior baselines.
7. Add core read-only AI/MCP detection assistance and evidence summaries.
8. Add more connectors and exports.
9. Add approval-gated diagnostics only after safety controls exist.

This order keeps the product usable while the AI/MCP layer matures, but the
end-state product should assume AI/MCP is part of the normal evidence and
finding workflow.

## Reference Boundary

External products may be reviewed privately for general inspiration, but
OpenAssetWatch documentation must describe vendor-neutral design principles and
original project direction.
