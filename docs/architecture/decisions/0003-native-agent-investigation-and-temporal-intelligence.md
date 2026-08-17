# ADR-0003: Native Agent Investigation and Temporal Intelligence

- **Status:** Accepted
- **Date:** 2026-08-17
- **Decision owner:** Project owner and OpenAssetWatch maintainers

## Context

OpenAssetWatch already has a deterministic, local-first, passive-first,
evidence-first foundation. The Control Tower owns normalized evidence,
classification, software and vulnerability matching, findings, attention
scoring, provider policy, authentication boundaries, and audit metadata. The AI
Advisor is read-only and advisory.

The next design gap is not another source of truth. The gap is a safe way to:

- investigate one finding, change, data-quality issue, or analyst question from
  multiple bounded perspectives;
- preserve investigation state across multiple steps without relying on model
  memory;
- reuse reviewed task expertise without giving instruction bundles new
  permissions;
- keep model/provider choice separate from product authority;
- evaluate agent behavior with explicit expected and forbidden outcomes; and
- add historical and forecasting context without turning prediction into fact.

These capabilities must strengthen the current product rather than replace its
collectors, passive sensor, evidence store, deterministic engines, finding
lifecycle, Operational Attention Score, AI Advisor, or deployment model.

## Decision

OpenAssetWatch adopts a native **Agent Investigation Control Loop** and a native
**Temporal Intelligence** workstream as additive architecture.

The hub remains the authority. Specialist agents, reusable Skill Packs,
provider implementations, and temporal forecasting methods operate behind
OpenAssetWatch-owned contracts and may only produce bounded advisory artifacts,
observations, hypotheses, expected ranges, or recommendations.

The implemented authority order remains:

```text
authenticated normalized evidence
  -> deterministic classification and matching
  -> deterministic findings and attention scoring
  -> bounded investigation and AI explanation
  -> human review
```

Nothing in this ADR changes the authority of the deterministic layers above it.

## Non-negotiable invariants

1. **The deterministic core remains privileged.** Asset identity,
   normalization, evidence persistence, vulnerability matching, finding state,
   attention scoring, authorization, scope, approval, and audit policy are not
   delegated to a model or provider.
2. **Investigation routing is code-controlled.** Models may recommend a line of
   inquiry, but the coordinator decides which specialist roles, tools, evidence,
   budgets, and gates are allowed.
3. **Specialist output is advisory.** A specialist may propose a hypothesis,
   contradiction, confidence assessment, missing-evidence request, or
   recommendation. It may not write an authoritative fact, finding, score,
   suppression, classification, asset merge/split, or remediation action.
4. **Independent context is the default.** Parallel specialists should receive
   task-specific evidence packages rather than each other's conclusions unless
   the coordinator deliberately starts a later synthesis or verification stage.
5. **Evidence references are mandatory.** A material claim must cite
   server-issued evidence identifiers or be labeled unsupported/inconclusive.
6. **All tools pass through the existing controlled gateway.** A Skill Pack,
   specialist, provider, or model cannot add tools, widen scope, create network
   targets, or grant itself permissions.
7. **Skill Packs cannot grant authority.** They describe repeatable reasoning
   and output contracts. Effective permissions are the intersection of product
   policy, user authorization, site/tenant scope, capability metadata, and tool
   allowlists.
8. **Capability and provider are separate concepts.** OpenAssetWatch owns the
   capability contract. A provider implements that contract and is replaceable
   without changing authoritative state or public schemas.
9. **The investigation ledger excludes private chain-of-thought.** Store typed
   lifecycle events, evidence references, decisions, guardrail outcomes, and
   concise reasoning summaries. Do not require or expose hidden deliberation.
10. **Human judgment remains explicit.** Consequential actions and any future
    write path remain subject to the approval tiers already required by the
    product architecture.
11. **Temporal output is evidence context, not truth.** Expected ranges,
    forecasts, and anomaly candidates never confirm compromise, vulnerability,
    ownership, or risk by themselves.
12. **OpenAssetWatch must remain useful without any external AI or forecasting
    provider.** Local deterministic behavior remains the compatibility and
    fallback baseline.
13. **Passive-first remains unchanged.** Investigation and temporal analytics do
    not authorize active scanning, packet injection, credential access,
    exploitation, arbitrary command execution, or OT control operations.

## Accepted architecture decisions

### AIT-01 — Investigation Control State

Create a durable OpenAssetWatch-owned investigation state model. The state must
record the objective, trigger, authorized scope, evidence snapshot, specialist
tasks, hypotheses, contradictions, verification results, gates, budget,
status, stop reason, and next safe transition.

Model conversation history is not the system of record for this state.

### AIT-02 — Deterministic triage and dispatch

A deterministic coordinator decides whether an investigation is needed and
selects bounded specialist tasks from reviewed role and Skill Pack metadata.
Model-produced routing may be advisory input only.

### AIT-03 — Independent specialist investigations

When multiple perspectives are useful, specialists run with isolated task
contexts. Their outputs are typed and independently attributable. They should
not see peer conclusions during the first-pass investigation stage unless the
workflow explicitly requires shared context.

### AIT-04 — Deterministic correlation

Correlation of specialist outputs is performed by product code over typed
artifacts and evidence references. Correlation may group supporting claims,
preserve conflicts, identify missing evidence, and request verification. It
must not treat agent agreement as proof.

### AIT-05 — Independent verification gate

A material hypothesis that would influence remediation, prioritization, or a
saved investigation conclusion must pass an independent verification stage.
Verification returns `supported`, `unsupported`, or `inconclusive` with evidence
references and missing-evidence notes. Failed or inconclusive verification does
not silently close the investigation.

### AIT-06 — Agent Run Ledger

Add an append-only, bounded investigation ledger containing typed events such
as run start/end, task dispatch, evidence access, tool allow/deny, guardrail
result, specialist output, correlation result, verification result, human
review, cancellation, budget exhaustion, and recovery.

Raw prompts, provider credentials, hidden reasoning, authorization headers, and
unbounded provider payloads are not required ledger fields.

### AIT-07 — OpenAssetWatch Skill Packs

Define versioned, native Skill Packs under the reserved `configs/skills/`
namespace. A Skill Pack contains reviewed instructions and deterministic input,
output, evidence, tool, budget, and review metadata. Initial Skill Packs are
configuration-only and may not contain arbitrary executable scripts.

### AIT-08 — Capability/provider boundary

Define provider-neutral capability contracts owned by OpenAssetWatch. Provider
implementations may be local deterministic code, a local model service, or an
explicitly configured hosted service. Provider changes must not alter asset,
evidence, finding, or risk authority.

No automatic fallback may cross a configured privacy or trust boundary. A local
provider failure must not silently cause data to be sent to a hosted provider.

### AIT-09 — Agent evaluation and release gates

Every specialist role, Skill Pack, routing change, guardrail change, provider
adapter, or investigation-state change requires evaluation against versioned
fixtures. Evaluation must test both expected outcomes and forbidden behavior,
including scope violations, unsupported claims, unauthorized tools, false
closure, prompt injection, evidence leakage, and authoritative-write attempts.

### AIT-10 — Deterministic temporal baseline first

Temporal Intelligence begins with transparent statistical baselines over
OpenAssetWatch-owned historical signals. Initial methods should be simple,
reproducible, and easy to explain, such as rolling robust summaries, change
rates, seasonal comparison, and bounded trend estimates.

### AIT-11 — Optional forecast providers later

More advanced forecasting may be added only behind a provider-neutral temporal
contract after sufficient historical data, time-split evaluation, privacy
review, resource budgeting, and failure-mode testing exist. The deterministic
baseline remains available and comparable.

### AIT-12 — Temporal findings remain deterministic

A forecast or expected-range violation may become input to a deterministic
candidate-finding rule, but the finding rule owns the threshold, persistence,
freshness, missing-data behavior, and lifecycle. The forecasting component does
not create authoritative findings directly.

## Initial specialist role families

The first implementation should remain small and map to existing evidence:

- Asset Identity and Classification Investigator
- Exposure and Vulnerability Investigator
- Behavior and Change Investigator
- Security Coverage Investigator
- Data Quality Investigator
- IoT and OT Context Investigator
- Remediation Planner
- Report Writer
- Independent Verifier

Roles may be added only when a distinct evidence need and evaluation surface
exist. A role name does not grant access to any tool or data.

## Initial temporal signal families

Start only with signals that already have clear OpenAssetWatch provenance:

- asset population and newly observed asset counts;
- stale or disappearing asset counts;
- collector and sensor check-in health;
- finding creation, reopen, close, and backlog counts;
- vulnerability-match and remediation-backlog counts;
- software/firmware version transition progress;
- security-tool coverage changes; and
- bounded aggregate network-observation counts where the current privacy model
  permits them.

## Sequencing

### Phase 0 — Contracts and documentation

- define investigation state and ledger schemas;
- define role and Skill Pack contracts;
- define capability/provider boundaries;
- define evaluation fixtures and release blockers;
- define temporal signal and expectation schemas.

### Phase 1 — Deterministic investigation substrate

- deterministic triage and dispatch;
- isolated specialist task packets;
- deterministic demo specialist outputs for testing;
- correlation and verification state machines;
- append-only run ledger;
- read-only investigation UI projection.

### Phase 2 — Reviewed Skill Packs and provider adapters

- initial first-party Skill Packs;
- local provider adapter behind the capability contract;
- optional hosted provider adapter with explicit data-sharing configuration;
- provider health, budgets, cancellation, and resumable runs;
- adversarial and repeated-run evaluation.

### Phase 3 — Temporal Intelligence baseline

- normalized historical signal projection;
- transparent baseline and expected-range calculations;
- deviation candidates and deterministic attention rules;
- trend and expected-range dashboards;
- Advisor explanations over temporal evidence.

### Phase 4 — Advanced forecasting research

- time-split and backtesting corpus;
- optional advanced forecasting provider;
- resource and privacy benchmarks;
- comparative release report against deterministic baselines;
- no production enablement unless it improves useful accuracy without weakening
  explainability, privacy, or reliability.

## Rejected alternatives

- Replacing the deterministic Control Tower with an LLM-driven controller.
- Letting specialists freely chat until they reach consensus.
- Treating multi-agent agreement as verification.
- Allowing a model to choose arbitrary tools, URLs, files, commands, or scope.
- Allowing Skill Packs to ship unrestricted scripts or permission grants.
- Using provider session memory as authoritative investigation state.
- Automatically sending local data to a different provider after a failure.
- Treating a forecast as proof that an asset is compromised or vulnerable.
- Folding forecast confidence directly into the Operational Attention Score
  without a separately reviewed deterministic decision model.
- Adding active scanning or offensive behavior as part of investigation.

## Consequences

### Positive

- Adds deeper investigations while preserving current authority boundaries.
- Makes parallel analysis auditable and resistant to shared-context anchoring.
- Creates reusable task expertise without turning prompts into permissions.
- Makes agent/provider replacement possible without replacing product state.
- Converts agent safety rules into testable release requirements.
- Adds historical and expected-behavior context without making prediction an
  oracle.
- Preserves local-first operation and an offline deterministic path.

### Costs and risks

- Adds state-machine, schema, UI, evaluation, and audit complexity.
- Requires careful privacy controls around persisted investigation artifacts.
- Parallel specialist runs can increase compute, latency, and provider cost.
- Temporal models can produce plausible but wrong forecasts when data is sparse,
  missing, shifted, or seasonally unusual.
- Skill and provider versioning require long-term compatibility discipline.

These costs are acceptable only if the implementation remains bounded,
observable, reversible, and independently testable.

## Implementation status

This ADR records accepted architecture direction only. It does not claim that
multi-agent investigation, Skill Packs, provider runtime adapters, temporal
forecasting, or the new evaluation gates are implemented.

Canonical source code and subsystem documentation continue to control current
runtime behavior.