# Continuous Threat Exposure Management

OpenAssetWatch approaches continuous threat exposure management (CTEM) as a
deterministic, evidence-first loop over its existing asset, finding, and
decision records: scoping, discovery, prioritization, validation, and
mobilization. AI may explain results; it never decides them.

## Documents

| Document | Purpose |
| --- | --- |
| [CTEM_DECISION_LAYER.md](CTEM_DECISION_LAYER.md) | The implemented deterministic decision layer: action bands, reason codes, recomputation, persistence, and limits |
| [CTEM_IMPLEMENTATION_ROADMAP.md](CTEM_IMPLEMENTATION_ROADMAP.md) | Current capability status and the recommended order of the next CTEM capabilities |
| [CTEM_CAPABILITY_GAP_SYNTHESIS.md](CTEM_CAPABILITY_GAP_SYNTHESIS.md) | Research synthesis: CTEM capabilities classified against OpenAssetWatch, with the detail behind each gap |
| [CTEM_REPOSITORY_KNOWLEDGE_MAP.md](CTEM_REPOSITORY_KNOWLEDGE_MAP.md) | Which implementation, tests, decisions, and designs inform CTEM work, and recorded conflicts |

## Status labels

CTEM documents label each capability with one of:

| Label | Meaning |
| --- | --- |
| IMPLEMENTED | Code and tests are on `main`. |
| PARTIAL | Some required elements are on `main`. |
| PROPOSED | An open pull request or accepted design describes it; no runtime yet. |
| FUTURE | Identified and sequenced, with no design yet. |
| NOT IMPLEMENTED | Absent, including when deliberately out of scope. |

## Documentation rule

CTEM documents describe OpenAssetWatch capabilities in OpenAssetWatch terms.
They never name external products, vendors, or projects that were studied as
research, and they do not record which source suggested an idea. Public
standards and datasets may be named where technical correctness requires it.
