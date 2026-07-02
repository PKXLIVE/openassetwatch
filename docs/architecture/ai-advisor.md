# AI Advisor Architecture

This page is the short navigation entry for the OpenAssetWatch AI Advisor.
Canonical AI architecture details live in
`docs/architecture/ai-agent-architecture.md`.

The official AI architecture pattern is **Hierarchical Hub-and-Spoke + Shared
Evidence Blackboard**. Control Tower is the hub/coordinator. Endpoint
collectors, passive network sensors, integrations, `open_detector`,
MCP-style tools, and AI modules are spokes. The AI Advisor reads normalized
evidence and findings, then produces advisory, evidence-linked explanations,
summaries, reports, and recommendations.

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
