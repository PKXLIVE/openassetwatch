# AI Security Architecture

- **Status:** Documentation-only architecture package
- **Primary focus:** Prompt injection, agent hijacking, untrusted-content containment, agent identity/delegation, systemic multi-agent safety, tool authorization/integrity, memory/RAG protection, human-approval security, supply-chain integrity, compromise recovery, safe output, and adversarial evaluation
- **Current runtime authority:** Existing OpenAssetWatch deterministic controls remain authoritative

## Purpose

This directory defines the OpenAssetWatch defensive architecture for prompt injection and broader agent-system security. It is an additive security layer over the existing evidence-first platform. It does not authorize new model privileges, autonomous remediation, unrestricted tool use, arbitrary network access, recursive agent spawning, or direct AI writes to authoritative state.

The architecture assumes malicious instructions or misleading content may eventually reach a model. Security therefore depends on deterministic identity, trust, scope, authorization, persistence, approval, supply-chain, recovery, and output boundaries outside the model.

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
- `docs/architecture/agent-investigation-control-loop.md`
- `docs/architecture/agent-evaluation-and-release-gates.md`
- `docs/architecture/ai-agent-architecture.md`
- `docs/MODEL_ARTIFACT_PROVENANCE.md`
- `docs/EXPLAINABLE_RISK_DECISION_MODEL.md`

The existing OpenAssetWatch Skill Pack contract remains the canonical future runtime format. External Agent Skills conventions are useful research inputs, but this package does not replace the accepted `configs/skills/<skill-id>/skill.yaml + instructions.md + schemas + evals` direction.

## Authority order

```text
authenticated observations
  -> deterministic validation and normalization
  -> deterministic facts, classifications, findings, and decisions
  -> trust-labeled bounded AI context
  -> advisory AI interpretation or plan
  -> deterministic identity/scope/authorization/output/persistence gates
  -> human approval where required
  -> narrowly scoped execution or publication
```

AI-generated content, summaries, classifications, recommendations, dashboard plans, tool proposals, memory candidates, and agent-to-agent messages are non-authoritative until validated by the appropriate deterministic boundary.

## Prompt-injection foundation documents

- [`PROMPT_INJECTION_SECURITY_ARCHITECTURE.md`](PROMPT_INJECTION_SECURITY_ARCHITECTURE.md) — overall architecture and defensive model
- [`AI_TRUST_ZONE_MODEL.md`](AI_TRUST_ZONE_MODEL.md) — trust zones and permitted flows
- [`AI_TRUST_LABELS.md`](AI_TRUST_LABELS.md) — deterministic provenance and instruction-authority labels
- [`AI_TOOL_AUTHORIZATION_MODEL.md`](AI_TOOL_AUTHORIZATION_MODEL.md) — out-of-model tool-call authorization
- [`PROMPT_INJECTION_SKILL_CATALOG.md`](PROMPT_INJECTION_SKILL_CATALOG.md) — proposed bounded defensive Skill Packs
- [`PROMPT_INJECTION_POLICY_INDEX.md`](PROMPT_INJECTION_POLICY_INDEX.md) — normative policy package design
- [`PROMPT_INJECTION_RULE_CATALOG.md`](PROMPT_INJECTION_RULE_CATALOG.md) — deterministic rule IDs and decisions
- [`PROMPT_INJECTION_THREAT_MODEL.md`](PROMPT_INJECTION_THREAT_MODEL.md) — assets, actors, entry points, trust boundaries, and attack paths
- [`PROMPT_INJECTION_EVALUATION_STANDARD.md`](PROMPT_INJECTION_EVALUATION_STANDARD.md) — adaptive evaluation, agent-system extensions, metrics, and release blockers
- [`PROMPT_INJECTION_IMPLEMENTATION_ROADMAP.md`](PROMPT_INJECTION_IMPLEMENTATION_ROADMAP.md) — baseline and agent-system phased implementation sequence

## Agent-system security delta documents

- [`AI_AGENT_TRAPS_SECURITY_DELTA.md`](AI_AGENT_TRAPS_SECURITY_DELTA.md) — reconciled net-new agent-system security gaps over current OpenAssetWatch architecture
- [`AI_AGENT_IDENTITY_AND_DELEGATION_MODEL.md`](AI_AGENT_IDENTITY_AND_DELEGATION_MODEL.md) — authenticated principals, role/task binding, delegation grants, capability attenuation, revocation, and topology constraints
- [`SYSTEMIC_AGENT_SECURITY_ARCHITECTURE.md`](SYSTEMIC_AGENT_SECURITY_ARCHITECTURE.md) — congestion/cascade, correlated consensus, graph limits, circuit breakers, resource budgets, and systemic recovery behavior
- [`AI_HUMAN_APPROVAL_SECURITY_MODEL.md`](AI_HUMAN_APPROVAL_SECURITY_MODEL.md) — exact action binding, anti-fatigue, replay prevention, material-risk presentation, and optional dual control
- [`AI_MEMORY_TRUST_STATE_MODEL.md`](AI_MEMORY_TRUST_STATE_MODEL.md) — candidate-to-active memory lifecycle, quarantine, retraction, dependency invalidation, and poison-laundering prevention
- [`AI_AGENT_SUPPLY_CHAIN_SECURITY.md`](AI_AGENT_SUPPLY_CHAIN_SECURITY.md) — Skill Pack/tool/policy/workflow/model/control provenance, integrity, re-review, quarantine, revocation, and rollback
- [`AI_AGENT_COMPROMISE_RECOVERY_MODEL.md`](AI_AGENT_COMPROMISE_RECOVERY_MODEL.md) — principal suspension, credential/tool cancellation, memory/output quarantine, descendant invalidation, clean-context rebuild, and restoration gates

## Security principles

1. Prompt wording, role descriptions, and system messages are never treated as the sole enforcement boundary.
2. External content remains non-authoritative even when delivered by an authenticated collector, connector, tool, or agent.
3. Trust metadata is assigned by deterministic code and cannot be self-asserted by external content.
4. Every privileged agent/task must be attributable to a scoped, expiring, revocable principal before broader agent capabilities are enabled.
5. Delegation may attenuate capabilities; it may never create or widen them.
6. Tool access is least-privilege, scoped, bounded, and authorized outside the model.
7. A model cannot approve its own tool request, widen tenant/site scope, or grant itself permissions.
8. Read-only operation is preferred; consequential actions require exact human approval binding and narrow publisher/action identities.
9. Human approval is not automatically safe; approval fatigue, replay, misleading summaries, and material action drift require deterministic protections.
10. Durable memory, RAG ingestion, and saved dashboards require independent write gates.
11. Model output is untrusted until schema, policy, scope, destination, and data-loss checks pass.
12. Same-model agreement is not independent verification.
13. Missing evidence is uncertainty, not safety.
14. Cross-tenant isolation and site scope are deterministic invariants.
15. Every denial or approval escalation produces a bounded reason code and audit event.
16. Prompt-injection detection improves visibility but is not sufficient authorization.
17. Protected AI components require provenance, integrity, review, drift detection, and revocation appropriate to their risk.
18. Compromised agent state must be suspendable/revocable outside the model and must not silently survive restart or contaminate privileged memory/output.
19. Repeated/adaptive adversarial testing is required; one-shot success rates are not enough.
20. Any capability that is safe only when prompt injection or semantic manipulation never succeeds is architecturally unsafe.

## Scope of hostile content

The platform must assume hostile instructions or semantic manipulation can appear in user input, documents, web content, email, tickets, repository text, RAG results, tool output, MCP metadata, agent handoffs, model-generated summaries, durable memory, and security telemetry such as hostnames, DNS names, service banners, certificate subjects, SNMP text, mDNS/SSDP metadata, DHCP names, package labels, firmware names, CVE/advisory descriptions, IOC text, SIEM events, syslog messages, and scanner output.

Authentication of the transport or collector does not grant instruction authority to the content field itself.

## Documentation-only boundary

Nothing in this directory means a runtime control exists unless the corresponding implementation, tests, and release gates are merged elsewhere. New defensive Skill Packs, agent principals/delegation, RAG/memory gates, MCP controls, systemic circuit breakers, secure approval workflows, supply-chain activation gates, adaptive dashboards, or recovery behavior must be implemented through separate reviewed work.