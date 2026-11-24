# AI Trust Zone Model

- **Status:** Documentation-only architecture
- **Purpose:** Define where AI context originates, what authority it carries, and which deterministic gates are required before data may influence actions or durable state.

## Zones

| Zone | Name | Examples | Instruction authority | May directly change authoritative state? |
| --- | --- | --- | --- | --- |
| 0 | Authoritative platform policy | versioned policy, approved control artifacts, hard-coded invariants | authoritative | only through deterministic platform code |
| 1 | Authenticated deterministic facts | normalized evidence, persisted findings, risk/decision records, verified scopes | none unless explicitly a policy object | no direct AI write |
| 2 | Approved internal structured data | reviewed CMDB fields, approved catalogs, scoped configuration | none by default | only through deterministic workflows |
| 3 | User input | prompts, operator questions, task objectives | task intent only within user authorization | no |
| 4 | External retrieved content | web, email, tickets, documents, advisories, RAG results, tool output | none | no |
| 5 | Unknown or hostile content | suspicious payloads, quarantined text, untrusted multimodal content | none | no |
| 6 | Model-generated content | summaries, plans, recommendations, tool proposals, dashboard plans | none | no |

## Fundamental rule

```text
Higher data quality does not automatically create higher instruction authority.
```

A signed or authenticated source may prove provenance without making free-form text an instruction. A model-generated summary may become a useful derived artifact without becoming an authoritative fact. A human-readable label inside content cannot promote its own zone.

## Allowed influence

### Zone 0

Zone 0 controls policy, authorization, limits, trust-label schemas, rule versions, tool registries, and human-approval requirements. Zone 0 is not supplied by retrieved content or model output.

### Zone 1

Zone 1 may be used as authoritative evidence input to deterministic decisions and bounded AI explanations. AI may read only the subset authorized for the task and scope.

### Zone 2

Zone 2 may influence deterministic decisions only through a reviewed adapter or policy-specific mapping. The model does not convert Zone 2 text into policy.

### Zone 3

Zone 3 establishes user intent but is still constrained by authentication, tenant/site scope, role, product capability, and policy. User text cannot grant permissions the user does not possess.

### Zones 4 and 5

Zones 4 and 5 are data-only. They may be summarized or analyzed in a quarantined/read-only workflow but cannot directly:

- alter system or product policy;
- widen tool access;
- set tenant/site scope;
- write durable memory;
- create authoritative findings;
- trigger external publication;
- approve a consequential action;
- install or alter skills/tools;
- save dashboard or policy changes.

Zone 5 receives the strongest quarantine and containment behavior.

### Zone 6

Zone 6 output is always non-authoritative until validated. A model cannot promote its own content into Zone 0/1/2. A deterministic workflow may create a new authoritative record from validated inputs, but the record must retain source provenance and the model must not be the final validator.

## Transition gates

| From | To | Required gate |
| --- | --- | --- |
| 3/4/5 -> model context | bounded AI input | provenance envelope, scope check, context minimization, injection signal, sanitization policy |
| 6 -> tool request | action proposal | tool authorization, parameter validation, destination/scope validation, approval policy |
| 6 -> durable memory | memory candidate | memory-write eligibility, provenance, data classification, conflict check, expiration, approval if required |
| 4/5/6 -> RAG corpus | corpus candidate | ingestion review, source policy, tenant scope, injection/quarantine status, duplication and retention rules |
| 6 -> saved dashboard/policy | durable artifact | schema validation, stable IDs, authorization, human approval where required, publisher identity |
| 6 -> authoritative fact | prohibited direct path | must be re-derived/verified by deterministic logic or human-reviewed workflow |

## Quarantine semantics

A quarantined object remains available for forensic review but must not enter privileged context or action-capable workflows. Quarantine should record:

- source reference;
- content digest;
- tenant/site scope;
- detection state;
- reason codes;
- time observed;
- parser/sanitizer versions;
- approved forensic excerpt if needed.

## Trust does not propagate through transformation

These transformations preserve or lower trust unless an explicit deterministic review promotes the result:

```text
web page -> parser -> text
image -> OCR -> text
email -> summary
RAG chunk -> reranker -> context
agent output -> handoff
model summary -> memory candidate
```

For example, OCR text from an otherwise trusted image remains external/untrusted content; a summary of a hostile document remains model-generated content with the hostile source provenance attached.

## Cross-tenant rule

Tenant and site scope are not natural-language labels. They are deterministic metadata applied by the platform. Any scope mismatch fails closed before model access, retrieval, tool use, memory write, or publication.

## Default failure behavior

When the platform cannot determine trust zone, instruction authority, tenant/site scope, or action eligibility:

- preserve the object as data where safe;
- set the unknown/suspicious status explicitly;
- deny high-consequence actions;
- avoid durable memory writes;
- require review if the workflow cannot proceed safely;
- emit a bounded reason code and audit event.

## Security invariants

1. External content cannot self-promote.
2. Model output cannot self-promote.
3. Authentication of transport does not create instruction authority for payload text.
4. Zone 4/5 data cannot directly invoke tools.
5. Zone 6 cannot directly publish, persist, or modify authoritative state.
6. Tenant/site scope is enforced before model context assembly.
7. Trust metadata survives transformations and handoffs.
8. Unknown trust fails safe for consequential actions.