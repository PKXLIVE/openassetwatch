# AI Agent Compromise Recovery Model

- **Status:** Documentation-only architecture
- **Purpose:** Define containment, quarantine, credential revocation, downstream invalidation, clean-context restoration, and regression requirements when an agent/runtime is suspected or confirmed compromised
- **Related:** `docs/ai-security/PROMPT_INJECTION_POLICY_INDEX.md`, `docs/architecture/agent-investigation-control-loop.md`, `docs/ai-security/AI_MEMORY_TRUST_STATE_MODEL.md`

## Core principle

```text
A compromised or materially suspect agent/session must not be trusted to repair itself.
Recovery is controlled by deterministic platform state and separately authorized operators.
```

Recovery must assume that the affected context, tool outputs, memory proposals, descendant tasks, and candidate artifacts may be contaminated.

## Scope

This model covers recovery after:

- prompt injection or indirect injection with material control impact;
- unauthorized tool request/execution;
- suspected data exfiltration;
- compromised/poisoned memory;
- tool/server identity drift or compromise;
- agent identity misuse;
- delegation/scope escape;
- corrupted coordinator/Skill Pack/policy artifact;
- supply-chain provenance failure;
- cross-tenant access attempt;
- runaway/systemic resource event; or
- other security event that invalidates agent trust.

## Security states

A future agent/session security state should distinguish:

- `healthy`
- `suspected`
- `suspended`
- `quarantined`
- `under_review`
- `cleared`
- `revoked`
- `restored`
- `closed`

A model cannot set or clear these states.

## Recovery lifecycle

```text
suspected
  -> execution suspended
  -> credentials revoked or frozen
  -> active/pending tool calls cancelled
  -> session/context quarantined
  -> pending memory writes quarantined
  -> descendant tasks paused/invalidated
  -> candidate outputs blocked
  -> access and egress reviewed
  -> durable state reviewed
  -> clean context rebuilt
  -> policy/component identity revalidated
  -> controlled restoration
  -> regression test added
  -> incident closed
```

Some incidents may move directly from `suspected` to `revoked` or require broader incident response.

## Detection sources

Triggers may come from:

- deterministic rule violation;
- tool authorization denial pattern;
- confirmed/likely injection signal;
- cross-scope access attempt;
- canary/tripwire;
- component digest/provenance drift;
- human security report;
- anomalous delegation graph;
- output/DLP block;
- memory quarantine event;
- repeated approval manipulation; or
- external security advisory/operator decision.

A single low-confidence detector signal may not justify full compromise classification, but high-consequence paths should fail safe while review occurs.

## Immediate containment

When policy marks a principal/session `suspended` or `quarantined`:

- Tool Gateway denies new tool requests;
- coordinator denies new delegation;
- pending side-effecting actions are cancelled where safely possible;
- pending approvals are invalidated or paused;
- new durable memory/RAG writes are blocked;
- candidate publications are blocked;
- descendant tasks are paused and marked for revalidation;
- local provider sessions may be discarded when supported;
- short-lived credentials/tokens are revoked; and
- the Agent Run Ledger records containment.

Containment should not stop deterministic collection/findings unless the incident specifically affects those subsystems.

## Credential response

Credentials exposed or reachable through the affected execution path must be evaluated.

Potential actions:

- revoke task-scoped token;
- rotate/revoke wider service credential if exposure cannot be excluded;
- invalidate delegated credentials;
- expire publication capability;
- revoke MCP/tool-server session;
- block affected provider route; and
- require operator review for any long-lived secret that entered model context.

The model does not receive new credentials during recovery.

## Tool-call cancellation

The platform should track tool requests by stable authorization/action IDs.

Recovery must distinguish:

- request proposed but not authorized;
- authorized but not dispatched;
- dispatched/in-progress;
- completed;
- failed;
- uncertain/timeout.

For uncertain completion, the system must verify external state before retrying or declaring containment complete.

## Session/context quarantine

Quarantine should preserve enough metadata for investigation while preventing reuse.

The quarantined context should not be re-supplied to a clean agent except through a bounded forensic review path that labels all content untrusted.

Model/provider conversation state is not the authoritative recovery record.

## Memory review

See `AI_MEMORY_TRUST_STATE_MODEL.md`.

On compromise:

- pending memory candidates from the affected principal/session become quarantined;
- recently activated memory items in the affected time window are identified;
- descendant/derived memories are discovered;
- retrieval caches/index entries are invalidated as needed;
- authoritative evidence is not deleted merely because an AI session was compromised; and
- only separately revalidated memory may return to `active`.

## RAG and retrieval review

If a poisoned retrieval source triggered the incident:

- quarantine/disable the offending document/chunk/source as policy allows;
- preserve original source provenance/digest;
- identify tasks that consumed it;
- re-evaluate derived summaries/memory;
- verify cross-tenant scope; and
- restore retrieval only after the ingestion/source state is reviewed.

## Descendant task invalidation

A task is potentially affected when it consumed:

- output from the compromised principal;
- memory derived from that principal;
- tool output from a compromised/drifted tool;
- poisoned shared state; or
- coordinator route/state created during the compromised window.

Affected descendants should be marked:

- `revalidation_required`
- `quarantined`
- `cancelled`

according to impact and completion state.

Completed advisory outputs remain historical artifacts but should receive a visible invalidation/review marker when their support was compromised.

## Candidate artifact blocking

Reports, dashboard plans, tickets, messages, code/config drafts, or other output artifacts created during the compromised window must not be published/applied until revalidated.

If an artifact was already published, the incident review records destination, digest, time, approver, and potential containment/removal steps.

## Access review

Review should reconstruct from structured logs/graph data:

- evidence/resources read;
- tools requested/used;
- credentials applied;
- destinations contacted;
- files/objects written;
- memory/RAG writes proposed/completed;
- descendants spawned;
- approvals requested/consumed; and
- outputs published.

Do not require private chain-of-thought to perform this analysis.

## Exfiltration assessment

Where sensitive data and external communication were both reachable, determine:

- what sensitive records entered context;
- what data appeared in candidate/output artifacts;
- what destinations were requested/used;
- whether DLP/output gates blocked transmission;
- whether the tool/server had alternate egress;
- whether encoded/indirect exfiltration occurred; and
- whether credentials/secrets require rotation.

Unknown outcome remains unknown; do not report `no exfiltration` without evidence.

## Forensic evidence

Preferred immutable/bounded artifacts:

- Agent Run Ledger events;
- agent principal/delegation records;
- tool authorization decisions;
- approval records/action digests;
- canonical component/tool identities/digests;
- memory/RAG state-transition ledger;
- candidate/output artifact digests;
- policy/Skill Pack/model/runtime versions;
- security reason codes;
- timestamps;
- sanitized excerpts only where required for incident analysis.

Do not log secrets, authorization headers, raw customer packet payloads, or complete sensitive prompts by default.

## Clean-context rebuild

Restoration uses a new validated execution context.

It should:

- create/issue a new agent principal;
- use current approved role/Skill Pack/policy versions;
- re-resolve authoritative evidence from product stores;
- exclude quarantined/retracted memory;
- exclude compromised provider session history;
- revalidate tool identities;
- revalidate tenant/site/task scope;
- re-evaluate required approvals; and
- record the restoration lineage.

Do not copy the compromised context wholesale into a new session.

## Component revalidation

If compromise involved a component rather than only content, recovery requires its trust state to be restored separately.

Examples:

- Skill Pack digest mismatch -> review/reapprove or rollback;
- tool/schema drift -> canonical identity review;
- model provenance/qualification failure -> requalification;
- policy/rule integrity failure -> restore approved artifact and evaluate impact;
- workflow graph tampering -> restore approved version before restart.

## Restoration criteria

A run/capability may return to service only when applicable conditions are met:

- compromised principal revoked/closed;
- required credentials rotated/revoked;
- pending side effects resolved;
- affected memory/RAG/output state reviewed;
- component identities/policies valid;
- clean context built;
- regression test added for confirmed failure;
- relevant release blockers pass; and
- authorized human/security review records restoration when required.

## Restart behavior

A process restart does not clear compromise state.

Persisted security state must prevent:

- revoked principal resurrection;
- quarantined memory becoming active;
- paused action replay;
- stale approval reuse;
- old tool identity bypass;
- cancelled task automatic retry; and
- circuit-breaker/kill-switch state loss when policy requires persistence.

## Rollback and retry

Retries after security incidents require a new task/execution identity unless explicitly designed otherwise.

A retry must not reuse:

- compromised provider state;
- consumed approval;
- revoked credential;
- invalidated artifact;
- quarantined memory; or
- stale tool authorization.

## Incident relationship

Prompt-injection incidents remain one trigger class. This broader model covers compromised-agent/system recovery regardless of initial cause.

The `prompt-injection-incident-response` Skill Pack may guide operator analysis but cannot revoke credentials, change states, or restore a principal directly.

## Audit events

Suggested events:

- `agent.security.suspected`
- `agent.security.suspended`
- `agent.security.quarantined`
- `agent.security.revoked`
- `agent.tool_calls.cancelled`
- `agent.credentials.revoked`
- `agent.descendants.invalidated`
- `agent.memory.quarantined`
- `agent.output.blocked`
- `agent.egress.reviewed`
- `agent.context.rebuilt`
- `agent.component.revalidated`
- `agent.security.restored`
- `agent.security.closed`
- `agent.regression.required`

## Reason codes

Candidate reason codes:

- `AGENT_COMPROMISE_SUSPECTED`
- `AGENT_COMPROMISE_CONFIRMED`
- `AGENT_PRINCIPAL_SUSPENDED`
- `AGENT_CREDENTIAL_REVOKED`
- `AGENT_CONTEXT_QUARANTINED`
- `AGENT_DESCENDANT_REVALIDATION_REQUIRED`
- `AGENT_MEMORY_QUARANTINED`
- `AGENT_OUTPUT_QUARANTINED`
- `AGENT_TOOL_STATE_UNCERTAIN`
- `AGENT_EGRESS_REVIEW_REQUIRED`
- `AGENT_COMPONENT_REVALIDATION_REQUIRED`
- `AGENT_RESTART_STATE_BLOCKED`
- `AGENT_RESTORATION_GATES_INCOMPLETE`

## Evaluation

Required tests include:

- injected agent becomes `suspected` during a tool-capable run;
- pending tool denied after suspension;
- in-flight uncertain tool result handled without blind retry;
- child tasks paused after parent compromise;
- compromised memory proposal quarantined;
- already-active memory in affected time window reviewed;
- candidate artifact cannot publish after compromise;
- revoked principal remains revoked after process restart;
- stale approval cannot be replayed;
- clean context excludes poisoned memory/session history;
- component drift incident requires revalidation;
- cross-tenant access attempt triggers broader containment; and
- regression test is required before incident closure.

Metrics:

- time to containment;
- cancellation propagation success;
- credential revocation completion;
- descendant invalidation completeness;
- compromised-state persistence rate;
- recovery success rate;
- false-positive suspension burden; and
- repeat incident rate after restoration.

## Hard release blockers

For agent-capable runtimes:

- revoked/suspended principal executes new side effect;
- compromised memory survives quarantine into privileged context;
- descendant continues privileged execution after required invalidation;
- candidate output publishes after quarantine without revalidation;
- process restart clears required compromise state;
- cancelled/consumed approval is replayed;
- clean context includes quarantined source state; or
- restoration occurs while mandatory gates remain incomplete.

## Implementation sequence

1. Add persistent security state to agent/task control objects.
2. Connect principal revocation to coordinator/tool gateway.
3. Add pending-action cancellation state.
4. Add memory/output quarantine hooks.
5. Add descendant dependency/invalidation tracking.
6. Add access/egress review projection.
7. Add clean-context reconstruction.
8. Add restart/resume enforcement.
9. Add regression/closure gates.
10. Add operator UI for incident/recovery status.

This recovery model must exist before OpenAssetWatch introduces broad action-capable or recursive agent workflows.