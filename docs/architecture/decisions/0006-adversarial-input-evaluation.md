# ADR-0006: Adversarial Input and Injection Evaluation

- **Status:** Accepted
- **Date:** 2026-08-27

## Context

OpenAssetWatch already defines evidence-first AI behavior, trust-labeled
context, tool and permission boundaries, independent verification, safe output,
protected control artifacts, Skill Pack limits, and hard agent release gates.

The existing evaluation direction includes prompt-injection resistance, but it
does not yet define a systematic coverage model for how hostile influence may
arrive through different surfaces, accumulate across turns, steer tool
arguments, survive into persistent artifacts, exploit structurally valid
outputs, or interact with a changed local model/runtime artifact.

A list of known prompt strings is not a sufficient security model. Language-level
classification can help detect obvious attacks, but deterministic scope,
authorization, provenance, tool, verification, egress, and publication controls
must remain the security boundary.

OpenAssetWatch also requires a native design and provenance boundary. External
security research may identify useful problem classes, but canonical product
architecture must use independently defined OpenAssetWatch contracts rather
than importing external taxonomy identifiers, corpora, branded terminology, or
source-specific structure.

## Decision

OpenAssetWatch will adopt an **Adversarial Input and Injection Evaluation**
architecture that treats AI security as a multidimensional coverage problem.

The canonical design is documented at:

- `docs/architecture/ai-adversarial-input-and-injection-evaluation.md`

The evaluation model will independently classify cases by:

- adversarial objective;
- delivery surface;
- manipulation mechanism;
- transformation method;
- propagation stage; and
- affected tool, Skill Pack, provider/model/runtime, or output destination.

The model is intentionally non-exclusive: one case may exercise several axes.

## Security Invariants

The design must preserve these non-negotiable properties:

1. untrusted content cannot grant authority;
2. scope cannot expand through natural language;
3. tool selection and tool arguments remain subject to deterministic policy;
4. structured output remains untrusted after schema validation;
5. trust cannot increase through summarization or transformation;
6. every material operation revalidates authorization against current state;
7. ordinary repository or retrieved content cannot impersonate a protected
   control artifact;
8. sensitive data cannot leave through transformed or indirect output channels
   when policy forbids it;
9. model/runtime qualification is bound to artifact identity; and
10. untested coverage remains explicitly unknown.

## Evaluation Requirements

Future implementation should provide:

- versioned strict fixture contracts;
- a coverage registry;
- multi-turn policy-revalidation tests;
- tool metadata and schema drift tests;
- tool-argument provenance validation;
- semantic validation of structured model output;
- persistent propagation and prompt-worm resistance tests;
- resource and economic amplification evaluation;
- local model/runtime integrity qualification;
- cross-modal trust-preservation tests when multimodal features exist;
- repeated-run evaluation for nondeterministic providers; and
- honest coverage reports that expose unsupported, deferred, partial, and
  untested classes.

Every confirmed AI-security issue should become a regression fixture when
technically practical.

## Relationship to Existing Architecture

This decision extends rather than replaces:

- `docs/architecture/agent-evaluation-and-release-gates.md`;
- `docs/architecture/ai-agent-permission-output-security.md`;
- `docs/architecture/defensive-content-and-model-robustness.md`;
- `docs/architecture/skill-pack-contract.md`; and
- `docs/architecture/ai-platform-assurance-lifecycle.md`.

The broader agent evaluation document remains the release-gate authority. The
new adversarial architecture adds specialized coverage dimensions and fixtures
for injection, propagation, semantic-output, tool, resource, and model-integrity
failure modes.

## Implementation Sequence

Implementation should proceed in this order:

1. fixture and coverage schemas;
2. deterministic policy/provenance/tool/output tests;
3. multi-turn and persistence/propagation fixtures;
4. repeated model/provider evaluation;
5. local model/runtime integrity qualification;
6. resource-amplification measurement; and
7. multimodal cases only after corresponding product capabilities exist.

No implementation phase may weaken the existing hard release blockers.

## Explicit Rejections

This decision does not authorize:

- external-target prompt-injection testing;
- third-party model attack services;
- model extraction;
- jailbreak-as-a-service behavior;
- exploit or malware generation;
- unrestricted active scanning;
- credential harvesting;
- autonomous offensive testing; or
- importing an external taxonomy or attack corpus into canonical product
  architecture without a separate licensing/provenance decision.

## Consequences

### Positive

- AI-security coverage becomes measurable instead of anecdotal.
- New delivery surfaces can be added without redesigning the entire test model.
- Tool, output, storage, and local-model risks are evaluated alongside prompt
  text rather than treated as unrelated controls.
- Persistent and multi-turn attacks receive explicit regression coverage.
- Unknown or unsupported areas remain visible to operators and maintainers.

### Costs

- The fixture matrix can grow quickly and requires scope discipline.
- Repeated live-model evaluation consumes additional compute and time.
- Coverage claims require careful versioning and provenance.
- New tools, Skill Packs, providers, and modalities will require dedicated
  adversarial fixtures before strong safety claims are justified.

## Final Position

OpenAssetWatch will not claim that prompt injection can be solved by recognizing
all malicious language. The project will instead enforce deterministic security
boundaries around model behavior and continuously test those boundaries across
multiple attack surfaces, transformations, turns, propagation paths, tools, and
runtime identities.
