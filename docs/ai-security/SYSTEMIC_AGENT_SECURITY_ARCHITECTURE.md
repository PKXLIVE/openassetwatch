# Systemic Agent Security Architecture

- **Status:** Documentation-only architecture
- **Purpose:** Prevent multi-agent coordination, delegation, correlation, and resource effects from creating security failures even when individual agents are read-only or correctly scoped
- **Related:** `docs/architecture/agent-investigation-control-loop.md`, `docs/ai-security/AI_AGENT_IDENTITY_AND_DELEGATION_MODEL.md`, `docs/architecture/agent-evaluation-and-release-gates.md`

## Core principle

```text
A collection of individually bounded agents can still create an unsafe system.
System-level limits must be enforced by deterministic product code.
```

OpenAssetWatch must evaluate the investigation topology, shared state, correlated outputs, resource use, and approval burden as security-relevant behavior.

## Scope

This architecture covers future risks from:

- task congestion and fan-out;
- interdependent cascading failure;
- recursive delegation;
- cycles/deadlocks;
- correlated model error;
- false consensus;
- split/compositional attack payloads;
- shared-state poisoning;
- fabricated or duplicated agent identities;
- coordinator/routing manipulation;
- resource exhaustion;
- verification overload;
- approval overload; and
- cross-tenant cascade.

The initial OpenAssetWatch investigation design remains non-recursive and read-only. These controls define what must exist before that boundary is relaxed.

## System topology

The coordinator owns the graph of active work.

```text
Authenticated actor
        |
        v
Investigation
        |
        v
Deterministic coordinator
   |        |        |
   v        v        v
Task A    Task B    Task C
Agent A   Agent B   Agent C
   |        |        |
   +--------+--------+
            |
            v
Deterministic correlation
            |
            v
Independent verification
            |
            v
Human review / bounded output
```

If nested delegation is enabled later, each child edge remains coordinator-authorized and appears in the same graph.

## Graph state

Suggested node types:

- investigation;
- task;
- agent principal;
- role;
- Skill Pack;
- model/runtime;
- tool;
- credential;
- evidence scope;
- memory object;
- output artifact;
- approval record; and
- destination.

Suggested edge types:

- `initiated`
- `assigned`
- `delegated_to`
- `used_skill`
- `used_model`
- `requested_tool`
- `authenticated_as`
- `read_evidence`
- `wrote_candidate_memory`
- `generated_artifact`
- `verified`
- `approved`
- `published_to`

Graph identity comes from server-issued IDs, never free-text agent names.

## Systemic risk classes

### Congestion

An attacker or ambiguous trigger causes excessive concurrent work, repeated retrieval, verification storms, or approval requests.

Controls:

- per-investigation task cap;
- per-role concurrency cap;
- per-trigger fan-out table;
- deduplication of substantially identical work;
- total step/tool/token/time budgets;
- backpressure;
- circuit breaker; and
- explicit `budget_exhausted`/`systemic_limit` state.

### Interdependence cascade

One incorrect or poisoned input influences many downstream tasks and creates correlated recommendations.

Controls:

- first-pass specialist isolation;
- provenance preserved across every derived artifact;
- deterministic correlation rather than free-form aggregation;
- independent verifier with minimum context;
- no confidence increase from agent count alone;
- shared input/source concentration surfaced to reviewer; and
- ability to invalidate descendants when upstream evidence is retracted/quarantined.

### Correlated or tacit consensus

Multiple agents return similar conclusions because they share the same model, prompt family, evidence source, or bias.

Controls:

- track provider/model/system instruction/Skill Pack diversity;
- never treat same-model agreement as independent verification;
- preserve contradictions;
- require deterministic evidence checks for material claims;
- use genuinely independent verifier routes only when available and useful; and
- retain human review for high-consequence decisions.

### Compositional fragment

A malicious instruction is split across evidence records, tool results, turns, or agents and becomes meaningful only after aggregation.

Controls:

- preserve trust/provenance on every fragment;
- treat correlated untrusted content as untrusted after combination;
- scan/validate assembled context, not only individual items;
- cap cross-source context expansion;
- block authorization from semantic composition; and
- test split-payload campaigns across multiple tasks.

### Fabricated identity / sybil behavior

Unreviewed agent instances or duplicate identities attempt to influence routing, quorum, or trust.

Controls:

- authenticated agent principals;
- coordinator-issued identities only;
- unique active principal constraints;
- role registry;
- revoked/expired principal denial;
- quorum/verification rules based on trusted principal diversity rather than display names; and
- component inventory reconciliation.

## Topology policy

The coordinator should enforce versioned limits such as:

```text
max_tasks_per_investigation
max_parallel_tasks
max_delegation_depth
max_children_per_agent
max_total_descendants
max_tool_calls
max_evidence_records
max_context_bytes
max_model_tokens
max_wall_clock_seconds
max_provider_cost
max_verification_retries
max_approval_requests
```

Limits may vary by role/task type but must have safe defaults.

## Cycle and deadlock prevention

A proposed delegation edge must be rejected before dispatch if it creates a cycle.

The coordinator should also detect non-graph deadlock patterns such as:

- A waits for B while B waits for A;
- repeated verifier escalation without new evidence;
- repeated evidence requests for unavailable classes; and
- failed tasks automatically spawning replacements without bounded retry.

Recovery should stop or degrade the run rather than create more agents.

## Capability attenuation

Systemic safety depends on each child being no more privileged than the parent grant.

See `AI_AGENT_IDENTITY_AND_DELEGATION_MODEL.md`.

The coordinator must reject any proposed edge that widens:

- tenant/site/entity scope;
- evidence classes;
- tool classes;
- credential scope;
- output destinations;
- memory rights;
- publication rights;
- delegation depth; or
- consequence class.

## Coordinator integrity

The coordinator is security-sensitive product code.

It must not let model output directly control:

- role registry;
- route table;
- task budgets;
- scope;
- tool allowlists;
- agent identities;
- quorum rules;
- human-approval requirements; or
- recovery state.

A model may propose a routing suggestion only when product policy validates it against an allowlisted route set.

## Correlation and consensus

### Deterministic correlation

Correlation should group typed claims, validate evidence IDs, preserve conflicts, and compute source/role diversity metadata.

It must not calculate truth from majority vote.

### Verification independence

A verifier should receive the claim and minimum evidence needed to test it, not the original specialist's hidden reasoning.

Independence metadata should record:

- same/different provider;
- same/different model family;
- same/different Skill Pack or system instruction;
- shared evidence-source concentration;
- deterministic checks performed.

### Quorum

If a future workflow uses quorum, quorum is a policy for workflow progression, not proof of factual truth.

High-consequence actions still require required deterministic and human gates.

## Shared state

Shared blackboards, memory, retrieved summaries, and correlation packets are systemic attack surfaces.

Rules:

- first-pass specialists consume authoritative evidence and task context, not peer hypotheses;
- model output enters shared state as non-authoritative typed artifacts;
- memory writes follow the memory trust-state model;
- correlation cannot silently overwrite conflicting claims;
- retracted/quarantined upstream evidence invalidates dependent derived artifacts; and
- model-generated summaries cannot become policy or authorization.

## Cascade invalidation

Every derived task/hypothesis/artifact should retain parent evidence/task references sufficient to invalidate descendants.

Examples:

- source advisory retracted -> dependent investigation hypotheses require revalidation;
- agent principal revoked -> pending descendants paused/revalidated;
- tool identity drift -> outputs produced after unreviewed drift marked untrusted/quarantined;
- compromised memory item -> tasks that consumed it require review.

## Resource budgets

Resource security includes more than tokens.

Budgets should cover:

- API/model calls;
- tool calls;
- CPU/GPU time;
- memory;
- disk/temp storage;
- network bytes;
- retrieval records/bytes;
- context size;
- artifact size;
- human approval requests; and
- total investigation duration.

Security validation should retain reserved capacity so an agent cannot exhaust all resources and prevent its own inspection/cancellation.

## Circuit breakers

Potential breakers:

### Per-agent

Trigger on repeated denied tools, repeated invalid outputs, excessive retries, or compromised security state.

### Per-investigation

Trigger on fan-out, cycles, budget exhaustion, repeated verification failure, abnormal approval volume, or correlated action bursts.

### Per-tool/server

Trigger on identity drift, error spike, security alert, unexpected destination, or revoked publisher.

### Global agent-runtime

Emergency disable for new agent tasks while preserving deterministic collection and core product functions.

The kill switch must not disable core passive collection, deterministic findings, or local product access unless a separate incident requires it.

## Approval overload

Human attention is a finite systemic resource.

The coordinator should prevent agents from generating unbounded approval requests through:

- approval rate limits;
- cooldown after denial;
- deduplication of identical requests;
- batching only homogeneous low-risk operations when policy allows;
- automatic block of repeated materially identical denied requests; and
- escalation to an incident/systemic-risk state on approval floods.

See `AI_HUMAN_APPROVAL_SECURITY_MODEL.md`.

## Systemic telemetry

Suggested events:

- `agent.graph.edge_requested`
- `agent.graph.edge_denied`
- `agent.graph.cycle_blocked`
- `agent.graph.fanout_blocked`
- `agent.graph.depth_blocked`
- `agent.systemic.cascade_detected`
- `agent.systemic.circuit_opened`
- `agent.systemic.circuit_closed`
- `agent.systemic.budget_exhausted`
- `agent.systemic.approval_flood`
- `agent.consensus.nonindependent`
- `agent.kill_switch.enabled`
- `agent.kill_switch.disabled`

Use minimum-safe metadata and no private chain-of-thought.

## Deterministic reason codes

Candidate reason codes:

- `AGENT_GRAPH_CYCLE`
- `AGENT_GRAPH_DEPTH_EXCEEDED`
- `AGENT_GRAPH_FANOUT_EXCEEDED`
- `AGENT_TOTAL_TASK_LIMIT`
- `AGENT_RESOURCE_BUDGET_EXCEEDED`
- `AGENT_VERIFICATION_RETRY_LIMIT`
- `AGENT_CORRELATED_VERIFIER_SET`
- `AGENT_QUORUM_POLICY_INVALID`
- `AGENT_CASCADE_QUARANTINED`
- `AGENT_APPROVAL_RATE_EXCEEDED`
- `AGENT_SYSTEMIC_CIRCUIT_OPEN`
- `AGENT_GLOBAL_KILL_SWITCH`

## Evaluation

Systemic tests should include:

- one poisoned input triggering N candidate tasks;
- nested delegation attempt to max depth+1;
- fan-out attempts above limit;
- cyclic delegation proposal;
- split payload across multiple evidence items/agents;
- identical same-model agents voting on one wrong hypothesis;
- shared poisoned memory consumed by multiple specialists;
- tool failure causing retry storm;
- repeated denial causing approval flood;
- cancellation during large fan-out;
- compromised upstream principal invalidating descendants;
- cross-tenant cascade attempt; and
- restart/resume with previous circuit-breaker state.

Metrics include:

- multi-agent cascade rate;
- delegation escape rate;
- consensus poisoning rate;
- systemic resource exhaustion rate;
- time to circuit break;
- cancellation propagation success;
- descendant invalidation completeness; and
- benign task utility under systemic limits.

## Hard release blockers

For recursive or multi-agent capabilities:

- an unauthorized child is dispatched;
- a cycle executes;
- depth/fan-out hard limit is bypassed;
- child capability expands;
- cross-tenant cascade occurs;
- revoked/compromised principal continues spawning work;
- approval flood bypasses configured policy;
- global/capability kill switch cannot halt new work; or
- systemic budget exhaustion results in unreviewed side effects.

## Deployment posture

OpenAssetWatch can implement the non-recursive principal/topology/budget model before recursive delegation. That provides useful security and observability without expanding agency.

Recursive delegation remains an advanced capability and should remain disabled until all applicable identity, attenuation, recovery, approval, and evaluation gates pass.