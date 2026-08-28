# AI Trust and Provenance Labels

- **Status:** Documentation-only architecture
- **Purpose:** Define deterministic labels that survive context assembly, RAG retrieval, agent handoffs, memory proposals, tool requests, and output publication.

## Design rule

Security-relevant labels are assigned by trusted platform code. External content, model output, Skill Packs, tool descriptions, and agent messages cannot self-assert or overwrite them.

## Required labels

| Label | Example values | Authority | Notes |
| --- | --- | --- | --- |
| `source_trust` | `authoritative`, `approved`, `authenticated-untrusted-payload`, `external`, `unknown`, `hostile` | deterministic | Describes the source/envelope, not instruction authority |
| `instruction_authority` | `platform-policy`, `approved-workflow`, `operator-intent`, `none` | deterministic | External evidence text normally receives `none` |
| `content_origin` | `collector`, `sensor`, `user`, `web`, `email`, `ticket`, `rag`, `tool`, `mcp`, `agent`, `model`, `file`, `multimodal` | deterministic | Origin category |
| `content_type` | bounded MIME/domain type | deterministic parser | Never inferred into authority |
| `tenant_scope` | stable tenant ID | deterministic | Must never come from prompt text |
| `site_scope` | stable site ID(s) | deterministic | Must never come from prompt text |
| `retrieval_source` | stable connector/corpus/tool ID | deterministic | Includes version/digest where relevant |
| `evidence_id` | server-issued ID | deterministic | Used for citation and audit |
| `observed_at` | timestamp | source + validation | Original observation time |
| `processed_at` | timestamp | deterministic | Processing time |
| `freshness` | `fresh`, `aging`, `stale`, `unknown` | deterministic | Age is not confidence |
| `injection_scan_status` | `not-scanned`, `clean`, `suspicious`, `likely-injection`, `confirmed-injection`, `unknown` | scanner/gate | Advisory signal, not authorization alone |
| `sanitization_status` | `not-required`, `raw`, `canonicalized`, `sanitized`, `quarantined`, `failed` | deterministic pipeline | Preserve original digest when transformed |
| `model_generated` | boolean | deterministic | True for model-produced text/artifacts |
| `human_verified` | boolean + verifier ref | deterministic workflow | Cannot be set by model text |
| `tool_generated` | boolean + tool identity | deterministic gateway | Tool output remains untrusted content unless separately reviewed |
| `memory_write_eligible` | boolean | deterministic memory gate | Never model-controlled |
| `action_eligible` | boolean | deterministic authorization gate | Does not imply human approval already exists |
| `data_classification` | project-approved classifications | deterministic | Used for routing and egress policy |
| `destination_class` | `internal`, `restricted`, `external`, `public`, etc. | deterministic | Used by output/tool gate |
| `integrity_digest` | content/schema digest | deterministic | Detects drift and TOCTOU changes |

## Un-self-assertable labels

The following MUST NOT be accepted from free-form content or model output:

- `instruction_authority`
- `source_trust`
- `tenant_scope`
- `site_scope`
- `human_verified`
- `memory_write_eligible`
- `action_eligible`
- `data_classification`
- `destination_class`

If a connector supplies claims about these concepts, they are treated as source data until a reviewed adapter maps them into product-owned labels.

## Context envelope

A model-facing context object should use a bounded envelope similar to:

```json
{
  "context_id": "ctx_...",
  "source_ref": "...",
  "source_trust": "authenticated-untrusted-payload",
  "instruction_authority": "none",
  "content_origin": "sensor",
  "content_type": "text/plain",
  "tenant_scope": "tenant_...",
  "site_scope": "site_...",
  "evidence_id": "ev_...",
  "observed_at": "...",
  "freshness": "fresh",
  "injection_scan_status": "unknown",
  "sanitization_status": "canonicalized",
  "data_classification": "internal",
  "model_generated": false,
  "human_verified": false,
  "memory_write_eligible": false,
  "action_eligible": false,
  "integrity_digest": "sha256:...",
  "content": "..."
}
```

The model may read `content`; it cannot alter the envelope fields that govern authorization.

## Security telemetry example

An authenticated sensor may submit a hostname containing malicious instructions. The correct representation is conceptually:

```text
source_trust = authenticated-untrusted-payload
content_origin = sensor
instruction_authority = none
human_verified = false
action_eligible = false
content = <attacker-controlled hostname>
```

The sensor identity is authenticated. The hostname text is still data.

## Label propagation

When content is transformed:

- preserve `tenant_scope`, `site_scope`, source references, and original digest;
- set `model_generated=true` for model summaries;
- retain the least-trusted relevant `source_trust` in the derivation chain;
- never convert `instruction_authority=none` to an instruction authority merely through summarization;
- preserve injection/quarantine reasons;
- create a new derived-object ID rather than overwriting source provenance.

## Handoff labels

Agent-to-agent handoffs should include both a message type and trust metadata:

```json
{
  "message_type": "evidence|hypothesis|recommendation|instruction|requested-action|untrusted-content",
  "instruction_authority": "none",
  "source_agent_id": "...",
  "source_model_id": "...",
  "evidence_ids": [],
  "tenant_scope": "...",
  "site_scope": "...",
  "model_generated": true,
  "human_verified": false
}
```

Only coordinator-issued typed task instructions may receive approved workflow instruction authority. A specialist model cannot grant that authority to another model.

## Memory-write eligibility

A memory candidate must include:

- provenance;
- tenant/user/project scope;
- source trust;
- model-generated flag;
- evidence references;
- contradiction state;
- expiration/retention policy;
- injection scan status;
- reason for persistence;
- reviewer/validator state.

`memory_write_eligible=true` is assigned only after the independent gate passes.

## Action eligibility

`action_eligible=true` means the proposed action is within the product and scope policy. It does not bypass:

- tool-specific authorization;
- parameter validation;
- destination validation;
- human approval;
- rate limits;
- safety controls;
- publisher/action identity checks.

## Failure behavior

Missing or malformed critical labels must fail closed for privileged operations. The platform may still permit bounded read-only analysis if tenant/site isolation and data policy are known and no side effect is possible.

## Audit requirements

Security-relevant label transitions should record:

- object ID;
- prior/new value;
- deterministic rule or adapter version;
- actor/component responsible;
- timestamp;
- reason code;
- evidence/provenance references.

Full content is not required in the audit log by default.