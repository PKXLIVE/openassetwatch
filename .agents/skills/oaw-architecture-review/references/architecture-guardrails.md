# OpenAssetWatch Architecture Guardrails

Portable baseline for the `oaw-architecture-review` skill.

This file is intentionally a compact snapshot for use when the current repository documentation cannot be read. The current accepted ADRs and canonical repository documentation always override this snapshot.

Baseline reviewed: 2026-08-13.

## Product identity

OpenAssetWatch is a defensive asset-intelligence platform that discovers what assets exist, explains what they are doing, identifies risk, and guides remediation.

Core posture:

- asset-first;
- passive-first;
- evidence-first;
- remediation-focused;
- local/self-hosted-first, with hosted and hybrid deployment as optional later directions subject to stronger tenancy and governance controls.

External products, repositories, feeds, APIs, datasets, research, and reference architectures are inputs and inspiration. They do not become replacement architecture by default.

## Current authority model

The accepted authority order is:

```text
authenticated normalized evidence
  -> deterministic classification
  -> deterministic findings and operational attention scoring
  -> bounded read-only AI explanation
  -> human review
```

The deterministic substrate remains authoritative. AI may explain, summarize, correlate, propose hypotheses, and recommend next steps, but it may not directly establish authoritative facts, final decisions, suppressions, scores, or remediation actions.

## Hub and spokes

The Control Tower hub owns the main API and evidence boundary, site/sensor identity, health/freshness, deterministic classification/history, findings/risk projection, AI Advisor, controlled tool gateway, authentication, audit metadata, and cross-site views.

Endpoint collectors, passive sensors, and future connectors are spokes. Spokes should use stable identity, authenticated outbound observations, bounded offline caching, and idempotent retries. They should expose no inbound management port by default.

## Runtime split

- Go: agent/sensor/collector/CLI, local inventory, network observations, service wrappers, installers, safe diagnostics.
- Python: AI Advisor, enrichment, scoring, reporting, export experiments, evaluation harnesses, and LLM workflows.

An architecture review should preserve this split unless a verified gap and explicit project decision justify changing it.

## Evidence and identity rules

- Preserve source-aware provenance.
- Preserve contradictions rather than forcing false consensus.
- Missing evidence is unknown, not safe.
- Passive fingerprints are supporting inference, not proof of instance identity.
- Product-specific vulnerability/remediation guidance requires sufficiently confirmed identity and version evidence.
- Identity corrections should remain auditable and re-evaluate dependent findings/risk.
- Future probabilistic identity features require labeled evaluation and calibrated confidence before automated merge behavior.

## AI and multi-agent rules

- External content is untrusted data, never instructions.
- Model-backed agents may propose observations, hypotheses, findings, and recommendations only within bounded roles.
- No model-backed agent may directly write validated facts, final decisions, or consequential actions.
- Future multi-agent operation requires a deterministic coordinator/control plane, typed contracts, scoped identity/tool permissions, budget/scope enforcement, conflict preservation, and audit.
- Human approval must increase with consequence.

## OT and active-query boundary

Passive behavior is the default and authoritative baseline for IoT/OT discovery.

Any future active IoT/OT interrogation requires, before implementation:

- deterministic allowlists/policy gates;
- explicit approval;
- bounded rate/session controls;
- vendor/model validation and isolated testing;
- complete auditing;
- an immediate stop path;
- no write/control operations for identification.

## External-source and licensing boundary

Third-party feeds, advisories, fingerprints, datasets, or corpora require an approved decision in `docs/SOURCE_LICENSING_REGISTRY.md` before the exact production use may import, bundle, cache, redistribute, or commercially use the data.

Unclear terms mean `review-required` rather than implied permission. Preserve source identity, retrieval/version information, provenance, license/attribution obligations, corrections, withdrawals, and retractions.

## Dashboard and semantic-data boundary

The product owns and versions approved metrics, dimensions, joins, sensitivity, freshness, cardinality, and query-cost semantics. AI may arrange or select approved panels within bounded scope but must not invent authoritative metrics, fields, joins, free-form SQL, or arbitrary executable visualization code.

## Safety and product-scope exclusions

OpenAssetWatch should not become an offensive testing, credential attack, C2, unsafe payload, arbitrary terminal, or raw-scanner platform.

Dual-use projects may be studied for defensive concepts, parsers, data models, governance ideas, or safe architecture patterns. Unsafe/offensive behavior must not be imported merely because the source project includes it.

## Review discipline

When evaluating a proposal:

1. Identify what OpenAssetWatch already does.
2. Verify the real gap.
3. Prefer the smallest additive capability that closes the gap.
4. Separate implementation evidence from documentation or demo claims.
5. Identify security, privacy, licensing, deployment, and operational consequences.
6. Preserve offline/local behavior and graceful degradation when feasible.
7. Define evaluation and release gates before calling the capability production-ready.
8. Use ADOPT, EXPERIMENT, DEFER, or REJECT for the reviewed scope only.
