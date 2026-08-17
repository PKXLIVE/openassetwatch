# Native Design Provenance Boundary

OpenAssetWatch architecture documents describe OpenAssetWatch product
requirements, contracts, and implementation decisions in native project
terminology.

When maintainers study outside material during research, accepted concepts must
be re-derived against OpenAssetWatch's own requirements before they enter
canonical design. Canonical architecture should describe the product capability,
why OpenAssetWatch needs it, its authority boundary, its safety constraints, and
its evaluation requirements rather than preserving research-source names or
implementation-specific branding.

This rule does not remove legal attribution obligations when third-party code,
data, documentation, or other licensed content is actually imported. Those
cases remain governed by the Source Licensing Registry and repository license
policy. The rule applies to independently implemented architecture concepts,
not to material that legally requires attribution.

## Design requirements

Canonical architecture additions should:

- use OpenAssetWatch-owned capability and schema names;
- fit the existing asset-first, passive-first, evidence-first direction;
- preserve the deterministic authority model;
- document the gap being closed;
- define explicit non-goals and release blockers;
- avoid copying source-specific APIs, class names, prompts, diagrams, or
  branding when independently designing a similar capability; and
- send any actual third-party code/data reuse through the normal licensing and
  provenance review.

## Review question

Before merging a native architecture expansion, reviewers should be able to
answer:

> Would this document still make complete sense if the research material that
> prompted the idea disappeared tomorrow?

If not, the design is not yet sufficiently OpenAssetWatch-native.
