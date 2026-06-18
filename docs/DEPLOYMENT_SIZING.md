# Deployment Sizing Baseline

This document defines a concise OpenAssetWatch MVP deployment sizing baseline.
It is planning guidance only. It does not add deployment scripts, installer
logic, service behavior, scheduling, active collection behavior, or package
manager commands.

## Terminology

- Control Tower: central OpenAssetWatch server and product-facing name for the
  main operator-facing deployment.
- control plane: technical architecture term for the API, orchestration,
  policy, ingestion, and management services behind Control Tower.
- Agent: endpoint or local collector that gathers passive local inventory and
  submits observations.
- Sensor: optional passive network, IoT, or OT collector for environments that
  need network-side visibility.
- AI/MCP layer: optional intelligence and tool-gateway layer for AI Advisor,
  approved MCP servers, and evidence-based analysis workflows.

## Preferred Deployment Target

Control Tower is Linux-first for MVP server deployment. Windows Server support
is secondary and should come later after the Linux deployment shape is stable.
Containerized deployment is future and optional.

Endpoint agents remain cross-platform. The server preference does not change
the agent goal of supporting Windows, Linux, and macOS endpoints.

## MVP Simulated-Production Topology

The preferred simulated-production MVP uses four Linux servers:

| Server | Responsibilities |
| --- | --- |
| Control Tower | API, future UI, reverse proxy/TLS, agent check-in, inventory ingestion |
| Database | PostgreSQL, asset inventory, agent state, check-in history |
| Worker/Queue | normalization, enrichment, future policy/config jobs |
| AI/MCP | MCP gateway, approved MCP servers, AI Advisor workers |
| Optional Sensor | passive network, IoT, or OT observations where deployed; not required for the four-server MVP baseline |

For MVP, reverse proxy and TLS termination should live on the Control Tower
server. A separate reverse proxy server is not required for the baseline
deployment. Fewer required servers makes OpenAssetWatch easier to deploy,
operate, evaluate, and sell, which makes the MVP more attractive for early
customer or lab environments.

A separate edge or reverse proxy tier can be added later for high availability,
enterprise network segmentation, dedicated WAF policy, or advanced ingress
controls.

## Sizing Tiers

| Tier | Shape | Device Target | Notes |
| --- | --- | --- | --- |
| Single-node lab | 1 Linux server | 500-1,000 devices | AI disabled or external API only |
| MVP simulated production | 4 Linux servers | 10,000 target, 25,000 stretch | 90-day retention |
| Standard production | 4-5 Linux servers | 25,000-50,000 devices | separate Control Tower, database, worker, and AI/MCP roles |
| Enterprise scale | horizontally scaled services | 100,000+ devices | horizontal API/worker scaling, HA database, queue scaling, archive storage |

## Throughput Assumptions

- Agents check in every 5 minutes.
- Agents submit full inventory every 6-24 hours.
- Average inventory payload is 100-500 KB.
- 10,000 devices at a 5-minute check-in interval is approximately
  33 check-ins/sec.
- 50,000 devices at a 5-minute check-in interval is approximately
  167 check-ins/sec.
- AI must be asynchronous and must not block ingestion.

Inventory ingestion and check-in should remain fast, boring, and durable.
Normalization, enrichment, policy jobs, and AI Advisor work should run behind
queues or worker boundaries so client submissions are accepted without waiting
on expensive analysis.

## Storage Estimates For 10,000 Devices

These estimates use daily retained inventory/observation volume after basic
normalization. Real deployments should tune retention by payload shape,
deduplication, compression, and evidence retention policy.

| Daily Volume | Approximate Daily Storage | Approximate 90-Day Storage |
| --- | ---: | ---: |
| 100 KB/device/day | 1 GB/day | 90 GB |
| 250 KB/device/day | 2.5 GB/day | 225 GB |
| 500 KB/device/day | 5 GB/day | 450 GB |
| 1 MB/device/day | 10 GB/day | 900 GB |

For MVP simulated production, plan for 1-2 TB NVMe database storage. This
leaves room for indexes, write amplification, retained observations, check-in
history, asset/finding state, and operational headroom.

## Server Spec Estimates

| Role | Suggested Baseline |
| --- | --- |
| Control Tower | 4-8 vCPU, 16-32 GB RAM, 200-500 GB SSD |
| Database | 8 vCPU, 32-64 GB RAM, 1-2 TB NVMe |
| Worker/Queue | 4-8 vCPU, 16-32 GB RAM, 200-500 GB SSD |
| AI/MCP | 8-16 vCPU, 32-64 GB RAM, GPU optional |
| Optional sensor | 4-8 vCPU, 16-32 GB RAM |

The AI/MCP server can be right-sized later based on whether AI Advisor work
uses local models, hosted model APIs, lightweight heuristics, or a mixture of
those approaches.

## Safety Boundaries

This sizing baseline does not change OpenAssetWatch's safe deployment posture:

- no active scanning by default
- no offensive tooling
- no credential collection
- no package-manager execution by the running agent
- no service-manager execution by planning commands
- no synchronous AI dependency in the ingestion path
