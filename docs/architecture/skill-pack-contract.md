# OpenAssetWatch Skill Pack Contract

- **Status:** Accepted design; runtime not yet implemented
- **Decision:** `docs/architecture/decisions/0003-native-agent-investigation-and-temporal-intelligence.md`

## Purpose

OpenAssetWatch Skill Packs are versioned, reviewable instruction and schema
packages for repeatable AI-assisted analysis. They let the project encode
specialized investigation behavior without turning prompts into permissions or
hard-wiring every reasoning workflow into application code.

Skill Packs are an additive layer above the existing evidence, policy, and tool
gateway boundaries. They do not replace deterministic classification,
vulnerability matching, finding rules, risk scoring, or human review.

## Core rule

```text
Skill Pack instructions describe how to reason.
OpenAssetWatch policy decides what may be seen or done.
```

A Skill Pack can narrow behavior. It cannot widen effective permissions.

## Reserved location

The existing `configs/skills/` namespace is the intended future location for
first-party Skill Packs.

Suggested layout:

```text
configs/skills/
  <skill-id>/
    skill.yaml
    instructions.md
    input.schema.json
    output.schema.json
    evals/
      *.json
```

Initial Skill Packs are configuration and documentation only. Arbitrary
executable scripts are not part of the first runtime.

## Manifest contract

A future `skill.yaml` should use a strict schema and reject unknown fields.
Suggested fields:

```yaml
schema_version: oaw.skill.v1
id: asset-identity-review
version: 1.0.0
title: Asset Identity Review
description: Review bounded asset identity evidence and identify uncertainty.
role_family: asset-identity-investigator
status: approved
read_only: true
required_evidence_types:
  - asset
  - classification_evidence
  - asset_history
allowed_tool_ids:
  - asset.read
  - asset.history.read
  - evidence.read
  - classification.read
required_capabilities:
  - investigation.read
max_steps: 4
max_evidence_records: 50
max_output_bytes: 16384
requires_verification: true
requires_human_review: false
external_processing: deployment-policy
input_schema: input.schema.json
output_schema: output.schema.json
instructions: instructions.md
```

The exact field names may change before implementation, but the manifest must
express identity, version, status, evidence requirements, tool limits, scope
requirements, budgets, output schema, verification, review, and provider-data
policy.

## Skill lifecycle

Suggested states:

- `draft`
- `review`
- `approved`
- `disabled`
- `deprecated`

Only `approved` Skill Packs may be selected by a production investigation
coordinator.

A version change that modifies tool requirements, evidence requirements,
provider behavior, output schema, or safety constraints requires a new review
and evaluation run.

## Selection and routing

A model does not get to install or activate a Skill Pack.

The deterministic coordinator should select a Skill Pack by:

1. trigger type;
2. approved specialist role;
3. evidence availability;
4. tenant/site scope;
5. product capability availability;
6. deployment provider policy; and
7. current Skill Pack status/version.

A model may suggest that a different reviewed Skill Pack is useful, but the
coordinator owns the final selection.

## Effective permissions

Effective access is the intersection of:

```text
user authorization
∩ tenant/site scope
∩ investigation scope
∩ product capability policy
∩ tool allowlist
∩ Skill Pack allowlist
```

A Skill Pack cannot:

- grant a new role;
- add a tool;
- change a tool from read-only to write-capable;
- expand the investigation scope;
- introduce an arbitrary URL/IP/CIDR/hostname target;
- override tenant isolation;
- bypass a human approval requirement;
- disable auditing;
- change provider privacy policy; or
- write directly to an authoritative OpenAssetWatch record.

## Tool categories

The first Skill Pack runtime should use only bounded read-only tools already
owned by the OpenAssetWatch gateway.

Candidate tool families include:

- `asset.read`
- `asset.history.read`
- `evidence.read`
- `classification.read`
- `component.read`
- `vulnerability.read`
- `finding.read`
- `risk_factors.read`
- `collector.read`
- `sensor.read`
- `changes.read`
- `temporal.read`
- `report.compose`

`report.compose` may generate a report artifact but must not deliver it to an
external destination without a separate approved workflow.

## Instruction file requirements

`instructions.md` should contain task-specific guidance only. It should not
contain security policy that belongs in product code.

A good instruction file should define:

- the purpose of the review;
- what evidence is meaningful;
- how to distinguish observed facts from hypotheses;
- what uncertainty must be surfaced;
- what output fields are required;
- which conclusions require verification; and
- safe validation or remediation guidance boundaries.

It should not contain:

- credentials or secrets;
- raw customer identifiers;
- hidden administrator instructions;
- unrestricted tool commands;
- shell snippets intended for execution;
- arbitrary network targets;
- instructions to ignore product policy;
- permission escalation language; or
- claims that authorization is implied by the Skill Pack itself.

## Input schema

A Skill Pack input should reference product-owned objects rather than copy
unbounded source content.

Typical input fields:

- `investigation_id`
- `task_id`
- `objective`
- `site_id`
- `asset_ids`
- `evidence_ids`
- `finding_ids`
- `as_of`
- `known_uncertainties`
- `policy_context`

The coordinator should resolve these references into a bounded provider-facing
projection after applying redaction, scope, and size controls.

## Output schema

Each Skill Pack owns a strict output schema appropriate to its role. Common
fields should include:

- `status`
- `observations`
- `hypotheses`
- `evidence_ids`
- `contradiction_evidence_ids`
- `confidence`
- `missing_evidence`
- `verification_required`
- `recommended_next_step`
- `reasoning_summary`

An output schema should be narrower than a general natural-language response.
Unknown evidence IDs, unsupported state transitions, and malformed outputs fail
closed.

## Evidence discipline

Skill Pack output must follow these rules:

- material claims cite valid server-issued evidence IDs;
- missing evidence is explicit;
- stale evidence retains its original timestamp/freshness;
- contradiction evidence is preserved rather than discarded;
- confidence reflects evidence quality, not model tone;
- absence of data is not evidence of safety;
- model agreement is not independent corroboration; and
- a hypothesis remains advisory until the investigation lifecycle verifies it.

## Provider independence

Skill Packs are provider-neutral. They should not contain provider-specific
prompt syntax, API keys, endpoint URLs, or model-specific output parsing rules.

Provider adapters may translate the same OpenAssetWatch task contract into a
provider request, but the Skill Pack and its output schema remain stable.

Changing providers must not change effective permissions or the authoritative
meaning of evidence IDs.

## External-processing policy

A Skill Pack may declare that it is compatible with external processing, local
processing only, or deployment-policy-controlled processing. That declaration
is a compatibility constraint, not permission.

The deployment still decides whether external AI is enabled and what data may
leave the local environment.

A provider failure must not silently change the external-processing mode.

## First-party Skill Pack candidates

The first set should remain small and map directly to existing evidence:

### Asset Identity Review

Purpose: assess identity/classification evidence quality, contradictions, and
manual merge/split review needs.

### Vulnerability Applicability Review

Purpose: explain deterministic match evidence, version uncertainty, and missing
applicability prerequisites without declaring unsupported vulnerabilities.

### Security Coverage Review

Purpose: analyze management/security tooling presence, freshness, and coverage
gaps.

### Behavior and Change Review

Purpose: explain bounded asset/service/site/freshness changes over time.

### Data Quality Review

Purpose: identify stale, incomplete, inconsistent, or malformed evidence and
recommend collection/normalization follow-up.

### IoT and OT Context Review

Purpose: interpret passive special-purpose-device evidence conservatively and
recommend non-disruptive validation.

### Remediation Planning

Purpose: convert verified findings and investigation conclusions into ordered,
reversible, evidence-linked remediation guidance.

### Investigation Report

Purpose: generate a concise technical or executive narrative from approved
investigation artifacts without changing the underlying evidence.

## Recursive delegation boundary

Initial Skill Packs may not launch other Skill Packs or specialist agents.
Delegation belongs to the deterministic investigation coordinator.

This avoids hidden task graphs, uncontrolled fan-out, budget multiplication,
and permission confusion.

A future nested-workflow capability would require its own explicit contract and
release gate.

## Versioning and reproducibility

Every investigation task should record:

- Skill Pack ID and version;
- input/output schema versions;
- coordinator policy version;
- provider adapter/version;
- selected model identifier when applicable;
- evaluation bundle version; and
- evidence snapshot/as-of time.

This makes a result explainable even after instructions or providers evolve.

## Evaluation requirement

An approved Skill Pack must have versioned fixtures covering:

- expected evidence use;
- required uncertainty language/fields;
- invalid evidence IDs;
- missing evidence;
- contradictory evidence;
- prompt-injection content inside evidence;
- cross-scope evidence attempts;
- forbidden tool attempts;
- authoritative-write attempts;
- malformed provider output;
- cancellation/budget conditions; and
- repeated-run behavior for any non-deterministic provider.

A Skill Pack cannot be promoted to `approved` solely because a few example
responses look good.

## Update and rollback

Skill Pack updates should be immutable by version. An administrator may change
which approved version is active, but existing investigation records continue
to reference the version that actually ran.

Rollback means selecting a prior approved version for new tasks. It does not
rewrite historical task records.

## Security review checklist

Before approving a Skill Pack:

1. Confirm its purpose maps to a real product capability.
2. Confirm all tools are necessary and read-only for the initial runtime.
3. Confirm scope is supplied by product IDs rather than raw targets.
4. Confirm instructions contain no secrets or permission overrides.
5. Validate strict input/output schemas.
6. Confirm external-processing compatibility.
7. Run adversarial and missing-evidence fixtures.
8. Verify unknown evidence IDs fail closed.
9. Verify the Skill Pack cannot alter authoritative state.
10. Record the approved version and evaluation result.

## Explicit non-goals

The initial Skill Pack design does not approve:

- arbitrary scripts;
- shell commands;
- self-installing content;
- network scanners;
- user-supplied executable plugins;
- recursive agent spawning;
- permission grants;
- direct database writes;
- provider-specific state as product truth; or
- marketplace/distribution behavior.

## Documentation-only status

This document defines a future native OpenAssetWatch contract. The reserved
`configs/skills/` directory does not imply that a Skill Pack loader or runtime
is currently implemented.