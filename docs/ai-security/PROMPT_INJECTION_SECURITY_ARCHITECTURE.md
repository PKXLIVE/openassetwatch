# Prompt Injection Security Architecture

- **Status:** Approved-for-review architecture; not implemented by this document
- **Scope:** Direct/indirect prompt injection, jailbreaks, context poisoning, RAG/memory poisoning, MCP/tool injection, multi-agent propagation, output/exfiltration, multimodal injection, and adaptive evaluation

## Problem statement

Prompt injection exists because models process trusted instructions and untrusted content in the same reasoning substrate. The platform therefore cannot rely on the model to perfectly distinguish instruction from data under adversarial conditions.

OpenAssetWatch must design for the case where malicious content reaches the model and influences its reasoning. The security objective is not merely to classify or sanitize the attack. The objective is to prevent model compromise from becoming authorization compromise, cross-scope access, durable state corruption, data exfiltration, or unsafe action.

## Threat classes

The architecture covers:

- direct instruction override and jailbreak attempts;
- indirect injection embedded in documents, web content, email, tickets, repositories, tools, APIs, or security telemetry;
- system-prompt or hidden-context extraction;
- multilingual, obfuscated, encoded, typoglycemic, multi-turn, delayed-trigger, and adaptive variants;
- RAG corpus poisoning and retrieval-context manipulation;
- durable memory poisoning;
- MCP/tool-description, schema, parameter, and response poisoning;
- cross-agent instruction propagation and trust confusion;
- model-output attacks on downstream renderers or executors;
- data exfiltration through allowed destinations or covert encoding;
- multimodal injection in images, OCR, QR codes, transcripts, and metadata;
- dashboard/query manipulation through hostile labels, findings, logs, or retrieved context.

## Defensive architecture

```text
Source content
  -> deterministic source/trust labeling
  -> canonicalization and bounded parsing
  -> injection assessment / quarantine signal
  -> context minimization and separation
  -> bounded model or specialist Skill Pack
  -> structured proposal
  -> deterministic validation / authorization
  -> human approval when consequence requires it
  -> narrow execution or publication identity
  -> audit + regression evidence
```

The model may influence interpretation. It does not become the authority that decides access, scope, persistence, or execution.

## Required control planes

### 1. Trust and provenance plane

Every context item needs deterministic provenance and instruction-authority metadata before it enters a model request. External content cannot self-label as trusted, approved, verified, or action-eligible.

### 2. Context integrity plane

Context assembly must keep these concepts separate:

```text
policy / approved instructions
facts / deterministic derivations
user intent
untrusted external content
model-generated content
```

Untrusted text may be quoted or summarized for analysis, but it cannot alter the tool allowlist, tenant/site scope, policy version, publisher destination, memory eligibility, or human-approval requirement.

### 3. Capability and permission plane

The effective capability of an AI task is the intersection of:

```text
user authorization
∩ tenant/site scope
∩ investigation/task scope
∩ product capability policy
∩ tool registry state
∩ Skill Pack allowlist
∩ data-classification policy
∩ destination policy
∩ approval state
```

No prompt or Skill Pack may widen that intersection.

### 4. Tool/action authorization plane

Every proposed tool call is independently authorized outside the model. The authorization decision is based on the original user intent, current task, proposed tool, parameters, data classification, side effect, destination, scope, and approval requirement.

The model cannot self-approve, manufacture approval evidence, or reinterpret untrusted content as authorization.

### 5. RAG and memory plane

Corpus writes and durable memory writes require independent eligibility decisions. A model reading untrusted content cannot directly persist that content as trusted memory, policy, fact, or workflow instruction.

### 6. Output and publication plane

Generated output remains untrusted until it passes type/schema validation, tenant/site validation, sensitive-data scanning, destination policy, malicious-link/content checks where applicable, evidence-reference validation, and human approval when required.

The identity that generates an artifact should not automatically be the identity that publishes or applies it.

### 7. Evaluation and incident plane

Prompt-injection defenses must be tested adaptively and repeatedly, including direct, indirect, multilingual, obfuscated, RAG, memory, MCP/tool, multi-agent, multimodal, and exfiltration scenarios. Confirmed or likely injection events must feed an incident-to-regression loop.

## The capability-triad rule

The architecture must prevent a single model execution path from combining all three of the following without deterministic controls:

1. untrusted-content exposure;
2. sensitive/private read capability; and
3. external or lower-trust communication/write capability.

When a workflow needs all three business functions, the capabilities must be separated through independent authorization, scoped tools, validation, and human approval rather than placed in one unconstrained agent context.

## Prompt-injection assessment states

The platform may maintain an advisory assessment state:

- `clean`
- `suspicious`
- `likely-injection`
- `confirmed-injection`
- `unknown`

These states support containment and telemetry. They are not the sole tool/action authorization mechanism.

For high-consequence operations, `suspicious`, `likely-injection`, `confirmed-injection`, and `unknown` must fail safe according to policy.

## Input processing requirements

Before untrusted content is exposed to a model, the platform SHOULD:

- preserve source identity and timestamps;
- canonicalize Unicode and bounded encodings where safe;
- remove or neutralize executable/active markup when the task does not require it;
- separate metadata from content;
- identify hidden or transformed text when possible;
- apply injection scanning and content-classification signals;
- minimize context to only records needed for the task;
- retain trust labels through summaries and transformations;
- quarantine content that crosses a configured severity or policy threshold.

Sanitization is defense-in-depth. It is not permission.

## Security telemetry as untrusted content

Security data is attacker-controllable in many real environments. The following fields must never gain instruction authority simply because they arrived through a trusted sensor or API:

- hostnames and FQDNs;
- DNS names;
- HTTP titles and service banners;
- certificate subjects and SAN text;
- SNMP descriptive strings;
- DHCP names;
- mDNS and SSDP names/descriptions;
- package/software labels;
- firmware labels;
- CVE and advisory prose;
- IOC and threat-report descriptions;
- syslog and SIEM message bodies;
- ticket descriptions;
- scanner output;
- repository issue/PR/comment text.

The envelope may be trusted as an authenticated observation while the contained string remains `instruction_authority=none`.

## RAG requirements

RAG security must apply at ingestion, retrieval, and use:

- corpus writes are provenance checked and policy scoped;
- unreviewed external documents remain untrusted;
- retrieval results preserve source and trust labels;
- retrieved instructions cannot override the task or policy;
- cross-tenant retrieval is blocked before the model sees content;
- model-generated summaries cannot become trusted corpus content without a write gate;
- poisoned or suspicious records may be quarantined without deleting forensic provenance;
- ingestion, retrieval, and memory events are auditable.

## MCP and tool requirements

Future MCP/tool integrations must use immutable canonical identity rather than display name alone. Security-relevant identity should include integration ID, canonical tool ID, publisher/source, version, digest, schema digest, transport, declared capability, and review state.

Tool descriptions and responses remain untrusted model context. Description/schema drift must trigger re-review. A previously approved server may not silently gain new capability through a description or schema change.

## Multi-agent requirements

Every agent handoff should use a typed contract that distinguishes:

- instruction;
- evidence;
- hypothesis;
- recommendation;
- untrusted content;
- authoritative fact reference;
- requested action.

Trust does not increase because another model produced the content. A receiving agent must reapply the same trust-zone and authorization rules. Same-model or same-provider consensus is not independent verification.

## Dashboard-generation requirements

AI-generated investigation dashboards must be constrained to approved analytical building blocks. The model may select stable metric IDs, dimensions, time grains, filters, and panel types from an approved semantic catalog.

The model must not emit unrestricted SQL, shell, executable code, arbitrary query language, unregistered joins, or invented fields. A deterministic validator checks scope, metric IDs, dimension compatibility, tenant/site authorization, query cost, row/cardinality limits, data classification, and persistence permissions.

Generated dashboards are temporary by default. Saving or modifying durable dashboards requires an explicit approved workflow.

## Output and exfiltration requirements

Before output crosses a trust or destination boundary:

- validate the output schema;
- verify evidence references;
- apply destination policy;
- scan for secrets/restricted data according to policy;
- validate links/markup appropriate to the renderer;
- prevent model-generated content from executing as code or query text;
- require human approval for consequential external publication or sensitive-data release;
- use a narrow publisher identity instead of the reasoning agent identity.

## Incident lifecycle

```text
detected
  -> contained
  -> context isolated
  -> tool activity reviewed
  -> memory/RAG writes reviewed
  -> data access reviewed
  -> exfiltration assessed
  -> credentials evaluated
  -> affected context invalidated
  -> forensic evidence retained
  -> rule/test updated
  -> regression case added
  -> closed
```

Full sensitive prompts should not be logged by default. Store bounded metadata, hashes, reason codes, provenance, scope, and approved forensic excerpts only where necessary.

## Zero-tolerance release blockers

Any verified occurrence of the following in an applicable evaluation blocks release of the affected capability:

- cross-tenant data leakage;
- unauthorized credential access;
- direct AI write to authoritative security facts or decisions;
- unapproved durable memory persistence;
- unauthorized tool execution;
- high-consequence action without required approval;
- injection-caused external data exfiltration;
- injected content changing deterministic rules/policy;
- injection-caused unrestricted network/file access;
- unrestricted AI-generated SQL/code/tool plans reaching execution;
- bypass of tenant/site scope;
- injected content modifying saved dashboards or policies without approval.

## Explicit non-goals

This architecture does not approve autonomous high-consequence remediation, arbitrary shell access, unrestricted web/network access, self-modifying policy, user-supplied executable skills, self-installing MCP servers, direct AI database writes, or any design whose safety depends on prompt injection never succeeding.