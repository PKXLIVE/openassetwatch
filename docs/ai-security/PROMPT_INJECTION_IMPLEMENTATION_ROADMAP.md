# Prompt Injection Security Implementation Roadmap

- **Status:** Architecture roadmap; implementation requires separate reviewed PRs
- **Goal:** Add prompt-injection containment without weakening OpenAssetWatch's deterministic, local-first, passive-first, evidence-first authority model.

## Sequencing principle

Do not begin by granting agents more tools and then attempt to add prompt-injection defenses around them. Build the deterministic security substrate first, protect the current read-only AI Advisor, then add capabilities only after their authorization, persistence, output, and evaluation gates exist.

## Phase 0 — Security invariants and trust labels

### Objective
Create the product-owned trust/authority vocabulary and machine-enforced metadata needed by every later AI feature.

### Architecture artifacts

- `AI_TRUST_ZONE_MODEL.md`
- `AI_TRUST_LABELS.md`
- initial rule IDs from `PROMPT_INJECTION_RULE_CATALOG.md`
- protected policy/control artifact definitions

### Implementation candidates

- versioned trust-label schema;
- deterministic label assignment at context ingestion;
- source/tenant/site/provenance envelopes;
- instruction-authority field owned by platform code;
- content/integrity digests;
- injection assessment state as an advisory signal;
- audit events and bounded reason codes.

### Required tests

- external content cannot set protected labels;
- authenticated telemetry payload text remains instruction-authority `none`;
- model output remains non-authoritative;
- cross-tenant/site label mismatch fails closed;
- missing critical labels block privileged paths;
- transformations preserve provenance.

### Definition of done

- all model-facing context objects use the approved envelope or a compatible deterministic projection;
- un-self-assertable labels are enforced outside the model;
- existing read-only advisor continues to function;
- no new model write/action authority is introduced.

## Phase 1 — Untrusted-content boundaries for the current AI Advisor

### Objective
Protect existing AI explanation workflows before introducing more agency.

### Skill Pack candidates

- `prompt-injection-assess`
- `untrusted-content-triage`
- `indirect-injection-defense`
- `context-integrity-review`
- `output-exfiltration-review`
- `prompt-injection-evaluation`

### Implementation candidates

- bounded context sections separating policy, user intent, deterministic facts, and untrusted text;
- canonicalization/sanitization pipeline where appropriate;
- prompt-injection scanning signal;
- quarantine path;
- safe output schema/renderer checks;
- security telemetry;
- fast regression/adversarial suite.

### Release gates

- injected hostnames/banners/advisory text cannot select tools or alter authoritative facts;
- no cross-scope evidence exposure;
- provider output cannot create unknown evidence references;
- unsafe renderer content is rejected/escaped;
- detection false positives measured on benign security text.

### Definition of done

The current advisor remains read-only and useful while hostile text can be safely analyzed without granting instruction authority.

## Phase 2 — Tool and action authorization

### Objective
Create the out-of-model authorization boundary before any new tool-capable agent workflow.

### Architecture artifacts

- `AI_TOOL_AUTHORIZATION_MODEL.md`
- `AI_TOOL_AUTHORIZATION_POLICY.md` (future policy file)
- human-approval and publisher identity contracts

### Skill Pack candidates

- `tool-intent-authorization-review`
- `prompt-injection-incident-response`

### Implementation candidates

- canonical tool registry identity/digests;
- deterministic allow/require-approval/deny authorizer;
- parameter and destination validation;
- short-lived/narrow credential brokerage;
- consequence classes;
- approval binding and expiration;
- independent publisher/action identity;
- kill switch/circuit breaker.

### Release gates

- model cannot self-approve;
- injected content cannot widen parameters, destinations, tenant/site scope, or credentials;
- changed tool/schema identity invalidates prior approval;
- high-consequence action without approval = zero;
- adaptive repeated tool-injection testing meets zero-tolerance blockers.

### Definition of done

No model or Skill Pack can cause a tool side effect without passing deterministic authorization, and high-consequence actions have verified human approval.

## Phase 3 — RAG and memory protection

### Objective
Allow retrieval and future memory without creating persistent prompt-injection paths.

### Skill Pack candidates

- `rag-security-review`
- `memory-poisoning-review`

### Implementation candidates

- corpus ingestion/write gate;
- document/chunk provenance and trust labels;
- quarantine status stored with corpus objects;
- tenant-scoped retrieval filters before model access;
- retrieval trust preservation;
- durable memory candidate schema;
- memory-write eligibility gate;
- expiration/retention;
- corrections/retractions;
- review of model-generated summaries before durable reuse.

### Release gates

- cross-tenant retrieval leakage = zero;
- unreviewed hostile document cannot become trusted memory;
- model cannot set memory eligibility;
- injection persists only in quarantined/non-authoritative data, not privileged memory;
- memory/corpus rollback and invalidation are testable.

### Definition of done

RAG and memory remain useful data services while untrusted content cannot self-promote into instruction, policy, or authoritative fact.

## Phase 4 — MCP and multi-agent protection

### Objective
Add integration and delegation controls before broader multi-agent operation.

### Skill Pack candidates

- `mcp-injection-review`
- `context-integrity-review`
- `prompt-injection-incident-response`

### Implementation candidates

- MCP/tool-server registry;
- canonical tool identity and publisher/version/digest;
- description/schema drift detection;
- tool responses labeled as untrusted;
- per-agent task identity and scoped capability;
- typed handoff contracts;
- coordinator-owned delegation;
- no automatic trust propagation;
- independent verification requirements.

### Release gates

- changed tool descriptions/schemas force re-review;
- MCP response text cannot grant permissions;
- child agent cannot expand scope or inherit all parent permissions by default;
- handoff type/provenance missing -> fail safe;
- same-model consensus cannot promote a hypothesis to authoritative fact.

### Definition of done

Multi-agent/MCP interactions preserve the same trust, scope, and authorization boundaries as single-agent operation.

## Phase 5 — Adaptive investigation dashboards and advanced workflows

### Objective
Add interactive AI-generated analytical workspaces without giving the model arbitrary query authority.

### Implementation candidates

- semantic metrics catalog with stable IDs;
- approved panel/dimension/time-grain registry;
- strict dashboard-plan schema;
- deterministic tenant/site/data-classification validator;
- query-cost/row/cardinality limits;
- deterministic query generation from approved semantic objects;
- temporary-by-default workspace;
- explicit audited save/publish path;
- per-panel provenance and freshness.

### Skill Pack candidates

Prompt-injection defensive Skill Packs may be invoked by the dashboard planner's security boundary, especially `indirect-injection-defense`, `context-integrity-review`, and `output-exfiltration-review`.

### Release gates

- zero raw SQL/shell/code execution path from model output;
- unknown metrics/panels/dimensions rejected;
- malicious asset/log/advisory text cannot alter authorization or query scope;
- cost/cardinality limits enforced;
- persistent save without approval = zero;
- deterministic fallback dashboard remains available.

### Definition of done

The AI can select and arrange approved analytical components while every executable data operation is generated/authorized outside the model.

## Phase 6 — Adaptive evaluation and continuous improvement

### Objective
Make prompt-injection resilience a release-engineering discipline rather than a one-time feature.

### Implementation candidates

- versioned prompt-injection eval bundle;
- approved public datasets where licensing permits;
- synthetic OpenAssetWatch security-telemetry cases;
- adaptive k=1/k=10/k=100 campaign support;
- multilingual/multimodal suites;
- RAG/memory/MCP/multi-agent suites;
- incident-to-regression automation;
- release-gate integration;
- benchmark transparency report.

### Release gates

All zero-tolerance blockers in `PROMPT_INJECTION_EVALUATION_STANDARD.md`.

### Definition of done

- CI/release process blocks regressions in deterministic security invariants;
- scheduled adaptive evaluations measure model/provider drift;
- every confirmed incident creates a regression case;
- security and benign-utility metrics are tracked together;
- model improvements do not justify removing containment controls.

## Implementation readiness matrix

| Capability | Research maturity | Design maturity | Implement now? | Further research/licensing? | Priority |
| --- | --- | --- | --- | --- | --- |
| deterministic trust labels | high | high | yes, after schema review | no | MVP |
| trust-zone context envelopes | high | high | yes | no | MVP |
| content/injection assessment signal | high | medium | yes as defense-in-depth | model/tool licensing may apply | Phase 1 |
| capability-triad analysis | high | high | yes | no | MVP |
| external tool authorization | high | high | after owner/security review | no | Phase 2 |
| human approval bindings | high | high | with tool auth | no | Phase 2 |
| RAG ingestion/retrieval gates | high | medium | after RAG architecture review | dataset/tool licenses | Phase 3 |
| durable memory gate | medium/high | medium | after memory contract | some evaluation research | Phase 3 |
| MCP identity/hash drift | medium/high | medium | when MCP runtime exists | current MCP standards review | Phase 4 |
| typed multi-agent handoffs | high | high | when multi-agent runtime exists | no | Phase 4 |
| multimodal injection review | medium | medium | later | benchmark/model research | Phase 4 |
| semantic-layer dashboard plans | medium/high | medium/high | after metrics-layer design | dependency licensing if adopted | Phase 5 |
| adaptive repeated eval harness | high | medium/high | yes, incremental | dataset licenses | Phase 1 onward |
| capability-isolated dual-model architecture | promising/high research | medium design | targeted prototype only | implementation/dependency review | Advanced |

## Owner decisions before code

Before implementation, architecture/security owners should approve:

1. canonical trust-label schema and names;
2. prompt-injection assessment state semantics;
3. initial Skill Pack list and which remain documentation-only;
4. tool consequence classes and approval tiers;
5. durable memory/RAG write authority;
6. approved detector/guard model dependencies and licenses;
7. MCP/tool registry identity/digest approach;
8. dashboard semantic-layer implementation choice;
9. evaluation datasets/tools and licensing;
10. zero-tolerance release blockers and exception policy.

## Agent-system security roadmap delta

The following phases extend the baseline roadmap using the architecture in:

- `AI_AGENT_TRAPS_SECURITY_DELTA.md`
- `AI_AGENT_IDENTITY_AND_DELEGATION_MODEL.md`
- `SYSTEMIC_AGENT_SECURITY_ARCHITECTURE.md`
- `AI_HUMAN_APPROVAL_SECURITY_MODEL.md`
- `AI_MEMORY_TRUST_STATE_MODEL.md`
- `AI_AGENT_SUPPLY_CHAIN_SECURITY.md`
- `AI_AGENT_COMPROMISE_RECOVERY_MODEL.md`

They do not authorize recursive agents or side effects by themselves.

### Delta Phase A — Agent identity and topology

#### Objective
Give every agent/runtime task an authenticated, scoped, expiring, revocable principal and make task relationships reconstructable.

#### Prerequisites
- current investigation/task contract;
- AI Component Registry direction;
- tenant/site scope contracts;
- Skill Pack versioning.

#### Implementation candidates
- `oaw.agent-principal.v1` schema;
- role registry linkage;
- principal issuance/expiry/revocation;
- principal binding to task/investigation/Skill Pack/model route;
- topology/relationship projection;
- unknown/revoked identity deterministic rules;
- audit events.

#### Tests
- missing/expired/revoked identity;
- task/tenant/site mismatch;
- tool request without valid principal;
- restart preserves revocation;
- identity cannot be self-issued by model.

#### Definition of done
Every agent/tool request can be attributed to a valid principal and unknown/revoked principals fail closed.

### Delta Phase B — Tool and transport integrity

#### Objective
Complete canonical tool/component lifecycle integrity beyond basic tool authorization.

#### Prerequisites
- baseline Phase 2 tool authorizer;
- principal identity from Phase A;
- component registry.

#### Implementation candidates
- canonical publisher/tool identity;
- implementation/schema/capability/destination/credential-profile digests;
- drift detection and re-review state;
- revoked/quarantined tool state;
- transport/egress restrictions;
- tool-integrity Skill Pack and rules.

#### Tests
- implementation/schema/publisher drift;
- destination expansion;
- credential-scope change;
- revoked tool still configured;
- model/tool metadata self-asserts approval.

#### Definition of done
Security-relevant tool change cannot continue privileged execution without required re-review.

### Delta Phase C — Delegation and systemic controls

#### Objective
Define future safe delegation and prevent graph/cascade/resource failures.

#### Prerequisites
- Phase A identity;
- Phase B tool integrity for any tool-capable child;
- coordinator state/ledger;
- budgets and cancellation.

#### Implementation candidates
- `oaw.agent-delegation.v1`;
- capability attenuation;
- max depth/fan-out/descendants;
- cycle detection;
- correlation/diversity metadata;
- systemic circuit breakers;
- global agent-runtime kill switch;
- descendant invalidation.

#### Tests
- child > parent grant;
- cycle/depth/fan-out+1;
- one hostile input -> N tasks;
- same-model false consensus;
- approval flood;
- cross-tenant cascade;
- cancellation propagation.

#### Definition of done
If recursive delegation is ever enabled, child authority is always attenuated and topology/resource limits fail closed. Until then recursive delegation remains disabled.

### Delta Phase D — Cognitive-state integrity

#### Objective
Implement full memory trust lifecycle and persistence containment.

#### Prerequisites
- baseline Phase 3 memory/RAG gates;
- trust labels;
- principal identity;
- dependency/provenance references.

#### Implementation candidates
- memory states `candidate` through `quarantined`;
- state-transition ledger;
- deterministic write/retrieval gates;
- stale/superseded/retracted handling;
- descendant invalidation;
- compromised-source quarantine;
- vector-index state enforcement.

#### Tests
- model self-promotion;
- poison laundering through summaries;
- cross-session/restart persistence;
- stale/retracted retrieval;
- compromised principal memory writes;
- cache/vector stale copies.

#### Definition of done
Only approved active memory is retrievable for its bounded purpose, and memory can never become authoritative product truth directly.

### Delta Phase E — Secure human approvals

#### Objective
Protect the reviewer from fatigue/manipulation and bind approval to material action facts.

#### Prerequisites
- tool authorization;
- candidate artifact/output gate;
- principal/task identity;
- consequence classes.

#### Implementation candidates
- structured approval preview;
- exact action digest binding;
- consumption/replay protection;
- rate limit/cooldown/dedup;
- denial re-prompt controls;
- separation of duties;
- optional dual approval for highest consequence;
- summary/structured-metadata mismatch blocking.

#### Tests
- forged "already approved" text;
- action/destination/artifact changes;
- replay/consumed approval;
- repeated request after denial;
- approval flood;
- manufactured urgency;
- hidden external egress;
- missing second approver.

#### Definition of done
Consequential actions cannot execute from stale, replayed, incomplete, or manipulated approval state.

### Delta Phase F — Agent/control supply chain

#### Objective
Extend provenance and protected-artifact controls across the agent stack.

#### Prerequisites
- AI Component Registry;
- existing model-artifact provenance;
- Skill Pack version/digest contract;
- tool-integrity state.

#### Implementation candidates
- protected component identity/status;
- Skill Pack instruction/schema digests;
- role/prompt/policy/workflow integrity;
- quarantine/revocation/rollback;
- evaluation bundle identity;
- signatures/attestations where current release architecture supports them;
- runtime integrity checks.

#### Tests
- silent Skill Pack instruction change;
- policy/workflow digest mismatch;
- revoked component activation;
- evaluation bundle weakening;
- model provenance mismatch;
- rollback history integrity.

#### Definition of done
Protected AI components cannot activate on privileged paths without the required current provenance, integrity, review, and evaluation state.

### Delta Phase G — Systemic adaptive evaluation and recovery

#### Objective
Validate Phases A-F under repeated, persistent, multi-agent, approval, resource, supply-chain, and recovery attacks.

#### Prerequisites
- applicable Phases A-F implementation;
- versioned eval bundles;
- compromise security-state model.

#### Implementation candidates
- expanded agent-system eval families;
- multi-agent scale/fan-out campaigns;
- persistence across session/restart/memory;
- approval-fatigue simulations;
- tool/component drift campaigns;
- compromise/recovery simulation;
- descendant invalidation checks;
- release report.

#### Release gates
All baseline and agent-system zero-tolerance blockers in `PROMPT_INJECTION_EVALUATION_STANDARD.md`.

#### Definition of done
Repeated/adaptive attacks cannot cross deterministic identity, scope, authorization, persistence, approval, supply-chain, recovery, or tenant boundaries, and security controls retain acceptable benign utility.

## Delta implementation readiness

| Capability | Current design status | Earliest action | Dependency | Priority |
| --- | --- | --- | --- | --- |
| agent principal + role binding | new focused design | detailed schema/implementation design | investigation/task identity | A |
| topology/risk graph projection | partial existing design | extend existing AI activity graph | principal IDs | A |
| tool publisher/drift lifecycle | partial existing design | expand tool registry/authorization | tool gateway | B |
| capability-attenuated delegation | new focused design | keep disabled; implement only before recursive delegation | A + coordinator | C |
| cycle/fan-out/systemic circuit breakers | partial budgets, new systemic design | implement limits before recursive/multi-agent expansion | A | C |
| memory trust-state lifecycle | new focused design over existing write-gate direction | schema/state design | trust labels + RAG/memory | D |
| approval anti-fatigue/replay model | new focused design over existing binding | UI/schema/policy design | tool auth + principals | E |
| protected Skill Pack/control provenance | partial existing protected-artifact design | bind loader/runtime activation when implemented | component registry | F |
| compromised-agent recovery | new focused design | implement security state before broad action/recursive capability | A-D | A/G |
| canaries/tripwires | research-stage | prototype/evaluate only | telemetry | later |

## Additional owner decisions before implementation

11. agent-principal schema, identity substrate, and credential broker approach;
12. whether/when recursive delegation is allowed at all;
13. maximum topology depth/fan-out/concurrency and default systemic budgets;
14. approval consequence tiers and which require dual control;
15. memory types allowed for durable AI persistence;
16. protected component types that require signatures versus hashes/review only;
17. recovery/quarantine retention and operator workflow;
18. whether canaries/tripwires are worth product complexity;
19. external evaluation tools/datasets permitted for CI after licensing review.

## Explicitly prohibited sequencing

Do not:

- add broad tool authority before Phase 2 controls;
- enable durable AI memory before Phase 3 and Delta D gates;
- allow MCP dynamic discovery to imply approval;
- allow child agents to inherit unrestricted parent capabilities;
- enable recursive delegation before Delta A/C identity+attenuation+graph controls;
- add free-form model-generated SQL/query/code as a shortcut to Phase 5;
- treat human approval as safe without exact action binding and replay protection;
- load protected Skill Packs/tools/policies with invalid required provenance;
- resume compromised agent state after restart without revalidation;
- relax containment because a newer model or detector scores better on one-shot tests.

## Final architecture readiness condition

A workstream is ready for implementation only when its trust labels, deterministic rules, scope/authorization behavior, identity/delegation behavior where applicable, audit events, failure/recovery behavior, tests, release blockers, and rollback path are documented and approved.