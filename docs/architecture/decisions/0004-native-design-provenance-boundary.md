# ADR-0004: Native Design Provenance Boundary

- **Status:** Accepted
- **Date:** 2026-08-17
- **Decision owner:** Project owner and OpenAssetWatch maintainers

## Context

OpenAssetWatch may study public technical material to identify useful patterns or
coverage gaps. Canonical architecture, however, should remain understandable,
maintainable, and independently implementable as OpenAssetWatch design.

The project also has a separate licensing obligation when third-party code,
data, documentation, or other licensed material is actually imported. These two
cases must not be confused.

## Decision

Canonical OpenAssetWatch architecture documents will describe accepted concepts
using OpenAssetWatch-owned terminology, contracts, requirements, and boundaries.
They will not preserve research-source branding, source-specific APIs, copied
prompts, copied diagrams, or source-specific class names merely because outside
material helped identify an architectural opportunity.

If third-party code, data, or other licensed material is actually incorporated,
the Source Licensing Registry and repository license/provenance requirements
still apply. This ADR does not remove attribution obligations.

## Requirements

A native design expansion must:

1. identify the OpenAssetWatch gap it closes;
2. explain how it extends rather than replaces existing architecture;
3. use OpenAssetWatch-owned capability and schema vocabulary;
4. preserve current authority and safety boundaries;
5. define implementation and release gates independently;
6. avoid dependency on source-specific branding or architecture names; and
7. remain coherent if the research material that prompted the design is no
   longer available.

## Consequence

Research can broaden the project's thinking without turning canonical design
into a catalog of other products or projects. Implementation decisions remain
traceable to OpenAssetWatch requirements, while actual third-party reuse remains
traceable through licensing and provenance controls.

## Implementation status

This ADR is a documentation and review rule. It does not add runtime behavior.
