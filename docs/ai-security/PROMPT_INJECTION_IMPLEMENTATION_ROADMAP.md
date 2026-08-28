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

## Explicitly prohibited sequencing

Do not:

- add broad tool authority before Phase 2 controls;
- enable durable AI memory before Phase 3 gates;
- allow MCP dynamic discovery to imply approval;
- allow child agents to inherit unrestricted parent capabilities;
- add free-form model-generated SQL/query/code as a shortcut to Phase 5;
- relax containment because a newer model or detector scores better on one-shot tests.

## Final architecture readiness condition

A workstream is ready for implementation only when its trust labels, deterministic rules, scope/authorization behavior, audit events, failure behavior, tests, release blockers, and rollback path are documented and approved.