# Architecture Decision Records

Architecture Decision Records (ADRs) capture accepted decisions that affect
multiple OpenAssetWatch subsystems or constrain future implementation.

## Records

| ADR | Status | Decision |
| --- | --- | --- |
| [`0001-research-aligned-expansion.md`](0001-research-aligned-expansion.md) | Accepted | Preserve the deterministic local-first foundation and adopt the phased research-aligned expansion direction. |
| [`0002-additive-external-intelligence-enrichment.md`](0002-additive-external-intelligence-enrichment.md) | Accepted | Add optional external intelligence through existing evidence boundaries without replacing the current platform, collectors, risk workflows, or product direction. |

## Status meanings

- **Proposed** — under review; not approved for implementation.
- **Accepted** — approved direction; implementation may still require detailed
  design and release gates.
- **Superseded** — replaced by a later ADR.
- **Rejected** — considered and deliberately not adopted.
- **Deprecated** — retained for history but no longer preferred.

An accepted ADR is not proof that its future capabilities are implemented.
Canonical subsystem documentation and source code control current behavior.