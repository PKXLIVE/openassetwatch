# Prompt Injection Defensive Skill Catalog

- **Status:** Documentation-only design catalog
- **Runtime contract:** `docs/architecture/skill-pack-contract.md`
- **Reserved future location:** `configs/skills/<skill-id>/`

## Design decision

Prompt-injection defense should use multiple bounded first-party Skill Packs rather than one monolithic security prompt. Smaller Skill Packs provide clearer triggering, narrower evidence/tool requirements, independent evaluation, simpler versioning, and reduced blast radius.

The deterministic coordinator owns selection. A model may suggest a Skill Pack but cannot install, activate, or grant it permissions.

## Standard future Skill Pack shape

```text
configs/skills/<skill-id>/
  skill.yaml
  instructions.md
  input.schema.json
  output.schema.json
  references/
    *.md
  evals/
    *.json
```

Prompt-injection policy and authorization must remain in product code/policy, not only in `instructions.md`.

## Catalog

| Skill ID | Purpose | Trigger | Tools | Authority | Human approval | Phase |
| --- | --- | --- | --- | --- | --- | --- |
| `prompt-injection-assess` | Route/classify a potential injection and identify relevant defensive workflow | Untrusted content is about to enter AI context or an injection alert exists | read-only context/evidence metadata | advisory | no | 1 |
| `untrusted-content-triage` | Review provenance, trust labels, parsing, sanitization, and quarantine need | Zone 3-5 content ingestion | read-only content metadata/scanner results | advisory | no | 1 |
| `indirect-injection-defense` | Analyze embedded instructions in retrieved/tool/document content and recommend containment | RAG/tool/web/email/document content enters context | read-only context/retrieval evidence | advisory | no | 1 |
| `context-integrity-review` | Identify instruction conflicts, trust confusion, scope ambiguity, or unsafe context assembly | Context integrity alert, conflicting instructions, suspicious handoff | read-only context metadata | advisory | no | 1 |
| `tool-intent-authorization-review` | Explain whether a proposed tool call aligns with user intent and security policy | Before any AI-requested tool invocation | read-only tool/task/authz metadata | proposes-only | for consequential actions | 2 |
| `rag-security-review` | Review corpus ingestion/retrieval provenance, poisoning indicators, and quarantine state | RAG write/read security review | read-only corpus/retrieval metadata | advisory | corpus write approval may be required | 3 |
| `memory-poisoning-review` | Review candidate durable memory and recommend allow/deny/escalate | Any AI-originated durable memory proposal | read-only memory/evidence metadata | proposes-only | according to memory policy | 3 |
| `mcp-injection-review` | Review MCP/tool identity, description/schema drift, responses, and poisoning indicators | New MCP/tool registration, drift, or suspicious response | read-only registry/hash/policy metadata | advisory | new/changed server approval | 4 |
| `output-exfiltration-review` | Review candidate output for restricted data, unsafe destinations, hidden instructions, and exfiltration paths | Before publication/egress of AI-generated artifact | read-only artifact/DLP/destination metadata | advisory | external/sensitive publication | 1-2 |
| `multimodal-injection-review` | Review image/OCR/audio/transcript-derived context for hidden instructions and trust propagation | Multimodal content enters AI context | read-only media/OCR metadata | advisory | no | 3-4 |
| `prompt-injection-incident-response` | Guide containment, context invalidation, evidence review, and regression capture | `likely-injection` or `confirmed-injection`, or material policy violation | read-only IR/audit evidence; containment requests through separate workflow | advisory | containment/action policy | 2+ |
| `prompt-injection-evaluation` | Run/interpret approved adversarial suites and produce release-gate evidence | Pre-release, scheduled security evaluation, regression | evaluation harness only | advisory/gate evidence | no | 1+ |

## 1. `prompt-injection-assess`

### Purpose
Classify the observed scenario, map likely attack surfaces, and route to the narrowest follow-up review.

### Inputs
- task/user intent reference;
- trust-zone labels;
- source/provenance metadata;
- bounded content excerpt or scanner features;
- applicable tenant/site scope;
- current injection assessment state.

### Allowed operations
- read evidence metadata;
- inspect bounded text/features;
- map to internal taxonomy categories;
- recommend quarantine, context review, tool review, or incident response.

### Prohibited operations
- no tool execution;
- no authorization changes;
- no durable memory writes;
- no authoritative finding creation;
- no scope expansion.

### Output
`classification`, `reason_codes`, `confidence`, `affected_surfaces`, `evidence_ids`, `recommended_skill`, `containment_recommended`, `limitations`.

## 2. `untrusted-content-triage`

Focuses on the data path before model use: source, parser, canonicalization, sanitization, trust labels, hidden content, and quarantine. It must never claim sanitized content is trusted instruction.

Required negative tests include benign code/docs containing phrases such as "ignore previous" in legitimate discussion so the Skill Pack does not turn phrase matching into policy.

## 3. `indirect-injection-defense`

Reviews retrieved content without giving it tool authority. The output should identify:

- suspected instruction-bearing spans or metadata;
- direct vs indirect delivery;
- potential downstream capability affected;
- whether the content can remain in a read-only/quarantined context;
- whether a more privileged task must be split into a separate execution.

It must not produce a sanitized version that silently loses source provenance.

## 4. `context-integrity-review`

Reviews the assembled context contract, not only the text. It checks:

- instruction-authority labels;
- policy/user/evidence separation;
- contradictory task instructions;
- cross-scope data;
- stale or unrelated context;
- model-generated content reused as fact;
- agent handoff type mismatches.

## 5. `tool-intent-authorization-review`

This Skill Pack produces evidence for the deterministic Tool Gateway. It never makes the final authorization decision.

Suggested output:

```json
{
  "recommended_decision": "allow|require-approval|deny",
  "reason_codes": [],
  "intent_alignment": "aligned|unclear|misaligned",
  "scope_alignment": "aligned|unclear|misaligned",
  "side_effect_class": "...",
  "destination_class": "...",
  "evidence_ids": [],
  "requires_human_approval": false,
  "limitations": []
}
```

The deterministic authorizer independently validates all fields.

## 6. `rag-security-review`

Covers both corpus writes and retrieval use. It evaluates provenance, scope, injection/quarantine signals, document updates, summaries, and retrieval paths. It cannot write the corpus directly.

## 7. `memory-poisoning-review`

A memory proposal remains Zone 6/model-generated content. This Skill Pack assesses whether the proposal is supported, scoped, non-sensitive, non-instructional, time-bounded, and eligible for deterministic/human validation. It cannot set `memory_write_eligible=true`.

## 8. `mcp-injection-review`

Reviews immutable identity, publisher, version, implementation digest, schema digest, capabilities, transport, description changes, tool responses, and destination/data access. It treats descriptions and responses as untrusted content.

A description/schema change after approval must be surfaced as a new review condition.

## 9. `output-exfiltration-review`

Runs before external or lower-trust publication. It considers sensitive-data classification, evidence IDs, destination policy, suspicious markup/links, encoded output, and whether untrusted content influenced the proposed destination.

It cannot publish the artifact.

## 10. `multimodal-injection-review`

Preserves the full transformation chain:

```text
media source -> parser/OCR/transcription -> derived text -> AI context
```

Derived text inherits the source trust and gains `model_generated=true` when a model performed the transformation. OCR/transcription does not promote authority.

## 11. `prompt-injection-incident-response`

Guides the documented lifecycle:

```text
detected -> contained -> context isolated -> tool activity reviewed -> memory/RAG writes reviewed -> data access reviewed -> exfiltration assessed -> credentials evaluated -> context invalidated -> evidence retained -> rule/test updated -> regression added -> closed
```

The Skill Pack may recommend containment but does not itself revoke credentials or change controls unless a separate future action workflow authorizes that capability.

## 12. `prompt-injection-evaluation`

Interprets approved evaluation cases and release-blocker evidence. It should report:

- taxonomy coverage;
- attack-success rate;
- detection precision/recall;
- false-positive/negative rates;
- unauthorized tool/side-effect rate;
- exfiltration rate;
- memory-poisoning rate;
- cross-scope leakage rate;
- utility under attack;
- repeated-attempt robustness;
- release-blocker events.

A model's narrative does not override the deterministic gate result.

## `instructions.md` common structure

Each future defensive Skill Pack instruction file should use this structure:

```markdown
# <Skill title>

## Purpose
## Trigger Conditions
## Trust Boundary
## Inputs
## Required Preconditions
## Authority Rules
## Allowed Operations
## Prohibited Operations
## Procedure
## Detection or Review Logic
## Evidence Requirements
## Decision/Recommendation Logic
## Escalation
## Human Approval Boundary
## Output Contract
## Audit Requirements
## Failure Behavior
## Test Requirements
## References
```

The file should be task guidance, not the sole security policy.

## Manifest requirements

The existing OpenAssetWatch `skill.yaml` design should carry strict, machine-enforced metadata such as:

- Skill Pack ID/version/status;
- role family;
- read-only flag;
- required evidence types;
- allowed tool IDs;
- required capabilities;
- max steps/evidence/output budgets;
- verification/human-review requirements;
- external-processing compatibility;
- input/output schema paths;
- instruction file path.

Prompt-injection Skill Packs should also eventually require reviewed trust-label/input-surface compatibility, but exact manifest fields must be added through the canonical Skill Pack schema rather than ad-hoc Markdown frontmatter.

## Approval/evaluation requirements

A defensive Skill Pack may not be promoted to `approved` until fixtures cover:

- expected benign use;
- direct injection;
- indirect injection;
- obfuscated/multilingual variants where applicable;
- missing/unknown trust labels;
- cross-tenant/site references;
- forbidden tool/action attempts;
- malformed output;
- evidence-ID fabrication;
- repeated/adaptive attempts;
- false-positive scenarios;
- provider/model variation when non-deterministic.

## Security invariants

- Skill Packs cannot grant permissions.
- Skill Packs cannot change trust labels.
- Skill Packs cannot promote model output to authoritative state.
- Skill Packs cannot self-select protected tools.
- Skill Packs cannot disable auditing or approval requirements.
- Skill Pack output is Zone 6 until validated.
- Recursive delegation remains owned by the deterministic coordinator.