# Architecture Decision Records

Architecture Decision Records (ADRs) capture accepted decisions that affect
multiple OpenAssetWatch subsystems or constrain future implementation.

## Records

| ADR | Status | Decision |
| --- | --- | --- |
| [`0001-research-aligned-expansion.md`](0001-research-aligned-expansion.md) | Accepted | Preserve the deterministic local-first foundation and adopt the phased research-aligned expansion direction. |
| [`0002-additive-external-intelligence-enrichment.md`](0002-additive-external-intelligence-enrichment.md) | Accepted | Add optional external intelligence through existing evidence boundaries without replacing the current platform, collectors, risk workflows, or product direction. |
| [`0003-native-agent-investigation-and-temporal-intelligence.md`](0003-native-agent-investigation-and-temporal-intelligence.md) | Accepted | Add OpenAssetWatch-owned investigation control, Skill Pack, capability/provider, evaluation, and temporal-intelligence contracts without changing deterministic authority. |
| [`0004-native-design-provenance-boundary.md`](0004-native-design-provenance-boundary.md) | Accepted | Keep canonical architecture in OpenAssetWatch-native terminology while preserving normal licensing/provenance obligations for any actual third-party material. |
| [`0005-defensive-content-and-model-robustness.md`](0005-defensive-content-and-model-robustness.md) | Accepted | Add invariant-versus-heuristic AI safety, monotonic context taint, sensitive-egress protection, current security-intelligence normalization, and bounded parser/model robustness evaluation without changing deterministic authority. |
| [`0006-adversarial-input-evaluation.md`](0006-adversarial-input-evaluation.md) | Accepted | Add multidimensional adversarial-input coverage, multi-turn policy revalidation, tool and structured-output attack tests, propagation resistance, resource-abuse evaluation, and artifact-bound local-model qualification. |

## Status meanings

- **Proposed** — under review; not approved for implementation.
- **Accepted** — approved direction; implementation may still require detailed
  design and release gates.
- **Superseded** — replaced by a later ADR.
- **Rejected** — considered and deliberately not adopted.
- **Deprecated** — retained for history but no longer preferred.

An accepted ADR is not proof that its future capabilities are implemented.
Canonical subsystem documentation and source code control current behavior.
