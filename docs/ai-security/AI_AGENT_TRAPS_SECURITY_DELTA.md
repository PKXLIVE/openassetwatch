# AI Agent Traps Security Delta

- **Status:** Documentation-only architecture delta; implementation requires separate reviewed work
- **Purpose:** Extend the existing prompt-injection security architecture into broader agent-system security without replacing current OpenAssetWatch authority boundaries
- **Baseline:** `docs/ai-security/`, `docs/architecture/agent-investigation-control-loop.md`, `docs/architecture/skill-pack-contract.md`, `docs/architecture/ai-agent-permission-output-security.md`, `docs/architecture/agent-evaluation-and-release-gates.md`

## Purpose

Prompt injection is only one way an AI-enabled workflow can be manipulated. A capable agent can also be affected through memory and retrieval, delegated tasks, compromised tools, correlated multi-agent behavior, supply-chain drift, resource exhaustion, unsafe approval flows, and persistent state.

This document records the **net-new security delta** after reconciling independent agent-system security research with the current OpenAssetWatch architecture.

It deliberately does not create a parallel framework. Existing OpenAssetWatch controls remain canonical where they already cover the requirement.

## Authority boundary

The current authority order remains:

```text
authenticated normalized evidence
  -> deterministic classification and matching
  -> deterministic findings and attention scoring
  -> bounded investigation and AI explanation
  -> human review
```

Agent-system security adds controls around identity, delegation, memory, tools, approval, systemic behavior, and recovery. It does not give models authority over product truth.

## Existing strong coverage

The current repository already provides or designs substantial foundations that this delta reuses.

### Deterministic investigation coordinator

`docs/architecture/agent-investigation-control-loop.md` already establishes:

- product-code triage rather than model-owned routing;
- bounded specialist task packets;
- exact site/asset/evidence/tool scope;
- context isolation between first-pass specialists;
- deterministic correlation;
- independent verification;
- finite task/step/time/provider budgets;
- cancellation and resumable state;
- append-only Agent Run Ledger events; and
- no recursive specialist spawning in the initial runtime.

The new systemic-security design extends those constraints rather than replacing them.

### Skill Pack permissions

`docs/architecture/skill-pack-contract.md` already establishes that a Skill Pack:

- cannot grant itself a role;
- cannot add tools;
- cannot widen tenant/site/investigation scope;
- cannot bypass human approval;
- cannot disable auditing;
- cannot write authoritative records; and
- cannot recursively launch another Skill Pack or specialist.

New defensive Skill Packs remain advisory and are subject to the same contract.

### Tool identity and authorization

`docs/ai-security/AI_TOOL_AUTHORIZATION_MODEL.md` already requires:

- canonical tool identity;
- implementation and schema digests;
- approved capability and side-effect classes;
- tenant/site/task/intent alignment;
- credential and destination scope;
- approval binding;
- drift-triggered reauthorization; and
- deterministic `allow`, `require-approval`, or `deny` decisions.

The new tool-integrity work primarily expands publisher identity, transport integrity, quarantine, and lifecycle review.

### Agent relationship and permission-path design

`docs/architecture/ai-agent-permission-output-security.md` already defines:

- an AI Component Registry;
- an AI Activity Relationship Graph;
- permission-path analysis;
- protected control artifacts;
- separate output publisher identity; and
- agent-specific static-analysis concepts.

The new agent-risk graph and supply-chain design should reuse these structures.

### Model artifact provenance

`docs/MODEL_ARTIFACT_PROVENANCE.md` already implements the strongest existing supply-chain pattern for local model artifacts:

- immutable source identity;
- conversion/quantization lineage;
- exact artifact digests;
- qualification binding;
- invalidation on relevant change; and
- fail-closed local Advisor use when required provenance is invalid.

Future Skill Pack, tool, policy, workflow, and agent-package provenance should follow the same philosophy.

### Evaluation foundation

`docs/architecture/agent-evaluation-and-release-gates.md` and `docs/ai-security/PROMPT_INJECTION_EVALUATION_STANDARD.md` already require:

- cross-scope isolation;
- evidence integrity;
- authority protection;
- prompt-injection testing;
- context isolation;
- false-closure testing;
- cancellation/budget tests;
- repeated non-deterministic runs; and
- hard release blockers.

The delta extends these into systemic, approval-manipulation, delegation, recovery, and persistent-state testing.

## Net-new architecture gaps

### 1. Authenticated agent principal

OpenAssetWatch needs an explicit security principal for every agent/runtime task rather than relying only on role names and task records.

Required properties:

- unique agent instance identity;
- approved role identity;
- workload/runtime identity;
- investigation and task binding;
- parent agent/coordinator identity;
- tenant/site/entity scope;
- approved Skill Pack/version;
- capabilities and tool allowlist;
- credential identity and expiration;
- model/runtime/artifact identity where applicable;
- policy version;
- creation, expiry, revocation, and security state.

Unknown or revoked principals must fail closed for tool, memory, delegation, and publication paths.

### 2. Capability-attenuated delegation

If recursive delegation is introduced later, a child must receive a strict subset of the delegator's effective capabilities.

```text
child_effective_capabilities
  subset-of
parent_delegated_capabilities
```

Delegation must never mean `copy parent permissions`.

The coordinator must enforce:

- maximum depth;
- maximum fan-out;
- cycle detection;
- task/objective binding;
- evidence/data scope;
- tool/capability attenuation;
- credential attenuation;
- deadline/budget;
- cancellation propagation; and
- explicit parent/child provenance.

The initial implementation remains non-recursive until this contract exists and passes release gates.

### 3. Systemic multi-agent controls

Even read-only specialists can create systemic failures through correlated reasoning, fan-out, context amplification, shared-state poisoning, or resource exhaustion.

Required future controls include:

- authenticated agent topology;
- bounded task graph;
- cycle detection;
- concurrency/fan-out limits;
- global and per-agent budgets;
- correlated-failure/cascade signals;
- circuit breakers;
- coordinator kill switch;
- no trust increase from consensus alone; and
- no same-model outputs counted as independent verification.

### 4. Human-approval security

Existing approval binding is strong, but the human reviewer is itself an attack surface.

Future approval controls should cover:

- approval fatigue;
- manufactured urgency;
- misleading summaries;
- hidden side effects;
- replay/reuse;
- excessive approval frequency;
- approval after material action change;
- separation of duties; and
- dual control for the highest-consequence classes.

Approval must remain bound to exact action identity and context.

### 5. Full memory trust-state lifecycle

The current prompt-injection architecture requires memory write gates but does not yet define the full lifecycle of a candidate memory item.

A future memory trust state should distinguish:

```text
candidate
  -> untrusted
  -> reviewed
  -> corroborated
  -> validated
  -> approved-for-memory
  -> active
  -> stale
  -> superseded | retracted | quarantined
```

Model-generated summaries must re-enter the lifecycle as `candidate`; they cannot launder their own output into validated memory.

Durable memory remains non-authoritative. If a remembered proposition needs to influence deterministic product state, it must be converted into or corroborated by a separately validated OpenAssetWatch evidence record.

### 6. Agent/tool/control supply-chain enforcement

The repository already designs protected control artifacts and implements model-artifact provenance. The remaining delta is to apply similar lifecycle requirements to:

- Skill Packs;
- agent role packages;
- prompts/instructions;
- policy bundles;
- tool manifests;
- MCP/tool-server packages;
- workflow definitions;
- retrieval corpora and benchmark/evaluation bundles; and
- publisher identities.

Security-relevant change must trigger re-review and, where appropriate, re-evaluation.

### 7. Agent compromise recovery

Prompt-injection incident response needs a broader compromised-agent recovery state machine.

Recovery must be able to:

- suspend execution;
- revoke task/agent credentials;
- cancel pending tool calls;
- quarantine context and memory writes;
- block candidate output artifacts;
- invalidate downstream tasks;
- inspect access/egress activity;
- rebuild clean context;
- restore only after policy revalidation; and
- add regression coverage before closure.

### 8. Resource-abuse and systemic DoS controls

Current investigations are finite, but future tool-capable or recursive systems need explicit protection against:

- delegation storms;
- retrieval explosions;
- context flooding;
- oversized tool responses;
- repeated tool calls;
- token/API/CPU/GPU/memory/storage exhaustion;
- repeated approval prompts; and
- failure loops.

Resource exhaustion must end in an explicit blocked/inconclusive state, never fabricated success.

### 9. Canaries and tripwires

Canaries may provide useful detection for unauthorized retrieval, memory access, credential harvesting, or exfiltration attempts.

They are research-stage and must satisfy:

- no real PII/secrets;
- deterministic canary identity;
- exclusion from ordinary asset/finding logic;
- low false-positive design;
- bounded audit metadata; and
- no operational dependence on attacker triggering them.

## Security-domain attack surfaces

OpenAssetWatch must treat attacker-controlled security data as potential agent-system input, including:

- hostnames and DNS names;
- certificate subjects/SANs;
- service banners and HTTP metadata;
- SNMP, SSDP, mDNS, DHCP, and NetBIOS text;
- software/package/firmware labels;
- CVE and advisory descriptions;
- threat-intelligence comments;
- SIEM/syslog/scanner output;
- endpoint telemetry;
- ticket and incident notes;
- enrichment API responses; and
- uploaded documents or repository content.

Authentication of the collector/source does not grant instruction authority to those strings.

## Semantic manipulation boundary

Some attacks manipulate framing, urgency, reviewer confidence, or evidence ordering without obvious injection markers.

OpenAssetWatch must therefore remain safe even when semantic detection fails:

- free text cannot authorize actions;
- evidence IDs and scope remain server-owned;
- dashboard/query plans remain catalog-constrained;
- action authorization remains deterministic;
- memory writes remain gated;
- human approval remains bound to exact action context; and
- model confidence cannot substitute for evidence quality.

## Skill Pack delta

New standalone defensive Skill Pack candidates:

- `agent-identity-review`
- `delegation-security-review`
- `systemic-agent-risk-review`
- `human-approval-security-review`
- `tool-integrity-review`
- `agent-supply-chain-review`

Existing Skill Packs to expand:

- `context-integrity-review` — semantic manipulation/framing and context distortion;
- `memory-poisoning-review` — trust-state lifecycle, cross-session persistence, quarantine;
- `mcp-injection-review` — canonical publisher/tool identity and drift/rug-pull review;
- `prompt-injection-incident-response` — compromised-agent recovery and downstream invalidation.

These Skill Packs inspect and explain. They do not implement the security boundary.

## Policy delta

New policy areas:

- agent identity;
- delegation/capability attenuation;
- systemic multi-agent safety;
- tool integrity/lifecycle;
- agent/control supply-chain integrity;
- agent resource limits.

Existing policies to expand:

- human approval — anti-fatigue and approval-manipulation protection;
- incident response — compromised-agent recovery;
- security logging/evaluation — topology, memory-state, approval-rate, tool-drift, and systemic events.

## Deterministic rule delta

The rule catalog should add only missing controls and reuse existing prompt-injection rules where equivalent.

New rule families include:

- agent identity required/revoked;
- delegation depth/fan-out/cycle limits;
- capability attenuation;
- publisher identity drift;
- invalid multi-agent quorum/verification claim;
- approval rate/fatigue limits;
- incomplete approval context;
- approval replay;
- resource budget exceeded;
- compromised session state;
- memory quarantine;
- revoked AI component; and
- invalid supply-chain provenance.

## Evaluation delta

Future evaluation should add six agent-system dimensions:

1. perception/content manipulation;
2. semantic/reasoning manipulation;
3. cognitive-state/memory persistence;
4. behavioral/action control;
5. systemic/multi-agent behavior; and
6. human-approval manipulation.

Additional metrics include:

- semantic-manipulation success;
- delegation escape rate;
- multi-agent cascade rate;
- consensus-poisoning rate;
- human-approval manipulation/fatigue rate;
- systemic resource-exhaustion rate;
- compromised-state persistence across restart;
- recovery success rate; and
- mean time to containment.

## Additional hard release blockers

For capabilities that expose the relevant surface, release must be blocked by:

- unknown/revoked agent identity executing;
- unauthorized sub-agent/delegation creation;
- child capability broader than delegated parent capability;
- delegation outside approved task/scope;
- cross-agent privilege amplification;
- tool/publisher/schema drift executing without required re-review;
- approval forged, replayed, or reused after material change;
- required material risk hidden from the approval record;
- compromised memory surviving quarantine into privileged use;
- compromised session restored without security revalidation;
- multi-agent cascade crossing tenant/site boundaries; or
- systemic resource loop continuing after a configured hard limit.

## Sequencing

The recommended delta sequence is:

```text
A. agent identity and topology
  -> B. tool/transport integrity
  -> C. delegation and systemic controls
  -> D. cognitive-state integrity
  -> E. secure human approvals
  -> F. agent/control supply chain
  -> G. systemic adaptive evaluation
```

This sequence overlays the existing prompt-injection roadmap. It does not authorize recursive agents, tools, durable memory, or side effects before their earlier baseline gates are complete.

## Architecture rule

> Detection provides signal. Deterministic containment, authorization, scope, identity, and recovery provide the security boundary.

Any agent capability that is safe only when the model recognizes every malicious input must be redesigned before implementation.