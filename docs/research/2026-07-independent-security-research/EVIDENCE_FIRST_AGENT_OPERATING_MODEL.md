# Evidence-First Multi-Agent Security Operating Model

## Status

Independent research input. Not an implementation commitment.

## Core conclusion

A hub-and-spoke security analysis system should use a deterministic coordinator for scope, permissions, evidence packaging, schemas, budgets, validation, and audit. Language models may perform bounded analytical tasks, but they must not create authoritative facts, make final decisions, or execute remediation.

## Evidence states

Keep the following states separate:

1. raw observation;
2. normalized evidence;
3. validated fact;
4. hypothesis;
5. finding;
6. recommendation;
7. decision; and
8. action.

Model output may propose hypotheses, draft findings, or recommendations. A deterministic validator or human reviewer must approve promotion to a validated fact. Decisions and actions remain outside model authority.

## Fact lifecycle

Use an append-only lifecycle:

- observed;
- corroborated;
- validated;
- rejected;
- superseded; and
- retracted.

Corrections and retractions must remain auditable and should trigger re-evaluation of dependent findings and recommendations.

## Deterministic coordinator responsibilities

The coordinator should enforce:

- tenant, site, user, and asset scope;
- need-to-know evidence packages;
- specialist allowlists;
- typed input and output contracts;
- time, cost, token, and retry budgets;
- permission and tool authorization;
- credential scope and expiration;
- network egress restrictions;
- synchronization before synthesis;
- validation and fact-state transitions;
- conflict detection;
- human-review routing; and
- audit logging.

A model may assist with drafting task decomposition, choosing from approved specialist roles, interpreting disagreement, and producing a draft synthesis. Those outputs remain advisory and validated downstream.

## Bounded specialist roles

Recommended roles include:

- asset identity analyst;
- vulnerability analyst;
- threat-intelligence analyst;
- exposure analyst;
- misconfiguration analyst;
- IoT and firmware analyst;
- OT safety analyst;
- attack-path analyst;
- risk-prioritization analyst;
- remediation advisor;
- evidence verifier;
- governance reviewer;
- user-communication advisor; and
- dashboard and visualization planner.

Every role should define purpose, allowed evidence, allowed tools, prohibited tools, output schema, confidence requirements, refusal conditions, escalation rules, and evaluation criteria.

## Typed handoff contract

Every handoff should include:

- task and parent identifiers;
- coordinator and specialist identities;
- tenant and site scope;
- user-delegated authority;
- bounded question and exclusions;
- evidence references with provenance;
- allowed assumptions;
- allowed and prohibited tools;
- output schema;
- uncertainty and contradiction fields;
- completion criteria;
- budget and expiration; and
- escalation rules.

Free text should remain inside clearly marked data fields. Schema-valid output can still be wrong, so structured output does not replace evidence validation.

## Read and write permissions

Specialists may read assigned evidence and validated facts and may write proposals, hypotheses, and draft findings. They cannot write validated facts, final decisions, or actions.

Evidence verifiers may recheck sources and write critiques or verification outcomes but cannot self-promote a fact.

The deterministic control plane performs normalization, scope enforcement, validation, and authorized fact-state transitions. Humans approve consequential findings, exceptions, decisions, and actions.

## Verification and disagreement

Prefer verification in this order:

1. deterministic recomputation or source re-query;
2. signature, hash, schema, and provenance checks;
3. source-authority comparison;
4. independent specialist review; and
5. human review for unresolved ambiguity.

Agreement among agents using the same model, evidence, and prompts is not independent verification. Contradictions should remain visible and auditable rather than being silently averaged.

## Security boundaries

- Treat advisories, threat feeds, webpages, logs, hostnames, asset names, comments, and tool metadata as untrusted data.
- Separate instructions from retrieved content structurally.
- Pin and review tool definitions.
- Use per-agent short-lived identities and scoped credentials.
- Enforce permissions outside the model.
- Restrict network egress and URL access.
- Validate all memory writes before they become durable.
- Isolate tenants and sites in every data and tool path.
- Require human approval before consequential, irreversible, credential, endpoint-isolation, remediation, OT, or physical actions.
- Keep audit records append-only or tamper-evident.

## Human-approval tiers

- Tier 0: read and analyze within deterministic scope.
- Tier 1: low-impact reversible administration only after explicit policy approval and full logging.
- Tier 2: consequential or reversible-with-effort actions require human approval.
- Tier 3: high-consequence, irreversible, remediation, identity, credential, OT, or physical actions require mandatory human approval.

Research-only agents should remain Tier 0 until a later approved architecture decision.

## Failure and recovery

Required behavior includes:

- typed failure states;
- timeouts and bounded retries;
- circuit breakers;
- partial-result marking;
- no fabricated fields to satisfy a schema;
- no promotion after failed validation;
- human takeover;
- safe fallback or degraded operation;
- deterministic replay from the evidence ledger; and
- retraction propagation after incorrect or compromised evidence is discovered.

## Observability and audit

Record the user request, coordinator plan, specialist selected, evidence supplied, scope and permission decision, tools called, model and prompt versions, output, validation result, confidence, contradictions, cost, latency, human review, final decision, correction, retraction, and downstream action.

Sensitive prompt and response content should be minimized and protected separately from routine metrics.

## Evaluation

Measure task correctness, evidence completeness, citation correctness, unsupported-claim rate, disagreement detection, escalation quality, tool-use correctness, permission violations, tenant isolation, resilience to untrusted content, false closure, human-review burden, reproducibility, calibration, latency, cost, and correction behavior.

## Rejected patterns

- Security enforced only by prompt instructions.
- Any model writing validated facts directly.
- Same-model agreement treated as validation.
- A model used as the sole arbiter of truth or authorization.
- Free-text handoffs carrying implicit authority.
- Broad standing credentials shared across agents.
- Autonomous high-consequence remediation.
- Destructive fact updates that erase history.

## Durable findings

- `AGENT-RES-001` — the coordinator should be a deterministic control plane.
- `AGENT-RES-002` — evidence-state separation and append-only lifecycle protect authority.
- `AGENT-SEC-001` — external content is data, not instructions.
- `AGENT-SEC-002` — no model directly writes validated facts, decisions, or actions.
- `AGENT-SEC-003` — short-lived per-agent identities reduce blast radius.
- `AGENT-GOV-001` — consequential actions require tiered human approval.
- `AGENT-GOV-002` — disagreement must be preserved and verified.
- `AGENT-EVAL-001` — evaluation must include reliability, evidence integrity, permission compliance, and false closure.
