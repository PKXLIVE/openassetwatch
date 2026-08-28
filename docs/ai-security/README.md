# AI Security Architecture

- **Status:** Documentation-only architecture package
- **Primary focus:** Prompt injection, agent hijacking, untrusted-content containment, tool authorization, memory/RAG protection, safe output, and adversarial evaluation
- **Current runtime authority:** Existing OpenAssetWatch deterministic controls remain authoritative

## Purpose

This directory defines the OpenAssetWatch defensive architecture for prompt injection and related agentic-AI attacks. It is an additive security layer over the existing evidence-first platform. It does not authorize new model privileges, autonomous remediation, unrestricted tool use, arbitrary network access, or direct AI writes to authoritative state.

The architecture is based on the August 2026 prompt-injection research and implementation specification supplied for project review. That research concludes that prompt injection cannot be treated as a filtering problem alone. The platform must assume malicious instructions may reach a model and therefore enforce trust, authorization, scope, memory, output, and action boundaries outside the model.

## Core invariant

```text
Prompt instructions are not a security boundary.
External content is data, never authority.
The model proposes; deterministic OpenAssetWatch controls decide.
```

## Relationship to existing OpenAssetWatch architecture

This package extends, but does not replace:

- `docs/architecture/ai-governance-security.md`
- `docs/architecture/ai-agent-permission-output-security.md`
- `docs/architecture/skill-pack-contract.md`
- `docs/architecture/agent-evaluation-and-release-gates.md`
- `docs/architecture/ai-agent-architecture.md`
- `docs/EXPLAINABLE_RISK_DECISION_MODEL.md`

The existing OpenAssetWatch Skill Pack contract remains the canonical future runtime format. External Agent Skills conventions are useful research inputs, but this package does not replace the accepted `configs/skills/<skill-id>/skill.yaml + instructions.md + schemas + evals` direction.

## Authority order

```text
authenticated observations
  -> deterministic validation and normalization
  -> deterministic facts, classifications, findings, and decisions
  -> trust-labeled bounded AI context
  -> advisory AI interpretation or plan
  -> deterministic authorization and output gates
  -> human approval where required
  -> narrowly scoped execution or publication
```

AI-generated content, summaries, classifications, recommendations, dashboard plans, and tool proposals are non-authoritative until validated by the appropriate deterministic boundary.

## Documents

- [`PROMPT_INJECTION_SECURITY_ARCHITECTURE.md`](PROMPT_INJECTION_SECURITY_ARCHITECTURE.md) — overall architecture and defensive model
- [`AI_TRUST_ZONE_MODEL.md`](AI_TRUST_ZONE_MODEL.md) — trust zones and permitted flows
- [`AI_TRUST_LABELS.md`](AI_TRUST_LABELS.md) — deterministic provenance and instruction-authority labels
- [`AI_TOOL_AUTHORIZATION_MODEL.md`](AI_TOOL_AUTHORIZATION_MODEL.md) — out-of-model tool-call authorization
- [`PROMPT_INJECTION_SKILL_CATALOG.md`](PROMPT_INJECTION_SKILL_CATALOG.md) — proposed bounded defensive Skill Packs
- [`PROMPT_INJECTION_POLICY_INDEX.md`](PROMPT_INJECTION_POLICY_INDEX.md) — normative policy package design
- [`PROMPT_INJECTION_RULE_CATALOG.md`](PROMPT_INJECTION_RULE_CATALOG.md) — deterministic rule IDs and decisions
- [`PROMPT_INJECTION_THREAT_MODEL.md`](PROMPT_INJECTION_THREAT_MODEL.md) — assets, actors, entry points, trust boundaries, and attack paths
- [`PROMPT_INJECTION_EVALUATION_STANDARD.md`](PROMPT_INJECTION_EVALUATION_STANDARD.md) — adaptive evaluation, metrics, and release blockers
- [`PROMPT_INJECTION_IMPLEMENTATION_ROADMAP.md`](PROMPT_INJECTION_IMPLEMENTATION_ROADMAP.md) — phased implementation sequence and definition of done

## Security principles

1. Prompt wording, role descriptions, and system messages are never treated as the sole enforcement boundary.
2. External content remains non-authoritative even when delivered by an authenticated collector, connector, tool, or agent.
3. Trust metadata is assigned by deterministic code and cannot be self-asserted by external content.
4. Tool access is least-privilege, scoped, bounded, and authorized outside the model.
5. A model cannot approve its own tool request, widen tenant/site scope, or grant itself permissions.
6. Read-only operation is preferred; consequential actions require explicit human approval and narrow publisher/action identities.
7. Durable memory, RAG ingestion, and saved dashboards require independent write gates.
8. Model output is untrusted until schema, policy, scope, destination, and data-loss checks pass.
9. Same-model agreement is not independent verification.
10. Missing evidence is uncertainty, not safety.
11. Cross-tenant isolation and site scope are deterministic invariants.
12. Every denial or approval escalation produces a bounded reason code and audit event.
13. Prompt-injection detection improves visibility but is not sufficient authorization.
14. Repeated/adaptive adversarial testing is required; one-shot success rates are not enough.
15. Any capability that is safe only when prompt injection never succeeds is architecturally unsafe.

## Scope of hostile content

The platform must assume hostile instructions can appear in user input, documents, web content, email, tickets, repository text, RAG results, tool output, MCP metadata, agent handoffs, model-generated summaries, and security telemetry such as hostnames, DNS names, service banners, certificate subjects, SNMP text, mDNS/SSDP metadata, DHCP names, package labels, firmware names, CVE/advisory descriptions, IOC text, SIEM events, syslog messages, and scanner output.

Authentication of the transport or collector does not grant instruction authority to the content field itself.

## Documentation-only boundary

Nothing in this directory means a runtime control exists unless the corresponding implementation, tests, and release gates are merged elsewhere. New prompt-injection Skill Packs, policies, rules, RAG/memory gates, MCP controls, adaptive dashboards, or tool authorization must be implemented through separate reviewed work.