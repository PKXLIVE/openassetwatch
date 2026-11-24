# ADR-0005: Defensive Content and Model Robustness

- Status: Accepted
- Date: 2026-08-27
- Scope: architecture direction only

## Context

OpenAssetWatch already defines deterministic authority, trust-labeled AI context,
permission-path analysis, safe output publication, signed advisory ingestion,
external intelligence enrichment, agent evaluation, and model routing.

Further architecture review identified remaining gaps around:

- distinguishing structural AI security guarantees from heuristic content
  detection;
- preserving untrusted provenance after model transformations;
- detecting sensitive values after common reversible transformations;
- applying one reusable sensitive-content inspection boundary to generated and
  imported artifacts;
- tracking current security intelligence without treating publications as
  authoritative vulnerability evidence;
- robustness testing of OpenAssetWatch-owned parsers and input contracts;
- adversarial/degraded-input evaluation of future OpenAssetWatch-owned ML
  models;
- preserving feature, model, ensemble, and score provenance;
- optimizing reviewed remote-source retrieval without bypassing existing trust
  controls.

These capabilities must remain additive and cannot change the project's
passive-first, evidence-first, deterministic-authority, local-first, or
human-supervised boundaries.

## Decision

Accept `docs/architecture/defensive-content-and-model-robustness.md` as the
canonical future design for these gaps.

OpenAssetWatch will use the following architectural rules:

1. Security controls are explicitly classified as invariant, heuristic, or
   advisory.
2. Heuristic detections cannot weaken or override deterministic invariant
   denials.
3. Untrusted context taint is derived from provenance and remains monotonic
   within a task.
4. Request-scoped textual provenance fences may be used as defense in depth but
   never as authorization.
5. The Safe Output Gate may use a bounded transform closure to detect protected
   values after common reversible transformations.
6. Sensitive-content inspection becomes a reusable platform capability for
   OpenAssetWatch artifacts and egress, not a general endpoint DLP crawler.
7. Current security intelligence is normalized, clustered, and matched for
   relevance but remains non-authoritative until corroborated through existing
   evidence and finding pipelines.
8. Parser robustness testing is limited to OpenAssetWatch-owned code and
   approved isolated fixtures and produces minimized regression cases rather
   than exploit artifacts.
9. Adversarial model evaluation is limited to OpenAssetWatch-owned candidate
   models and controlled datasets; abstention is preferred to confident output
   under material uncertainty.
10. Future ML-assisted scores must retain feature, model, aggregation,
    disagreement, and uncertainty provenance.
11. Conditional remote-source retrieval is an optimization only and cannot
    bypass signatures, provenance, license checks, replay protection, downgrade
    policy, approval, activation, revocation, or last-known-good behavior.

## Authority Boundary

The accepted authority order remains:

```text
authenticated normalized evidence
  -> deterministic classification and matching
  -> deterministic findings and attention scoring
  -> bounded investigation and AI/ML analysis
  -> deterministic validation and safe-output controls
  -> human review
```

AI or ML output cannot directly become an authoritative identity,
classification, vulnerability match, finding, risk score, compromise state, or
remediation action.

Security-intelligence publications cannot prove vulnerability applicability or
compromise.

## Rejected Directions

This ADR does not authorize:

- exploit or shellcode generation;
- external-target fuzzing or autonomous vulnerability discovery against third
  parties;
- credential harvesting;
- general-purpose endpoint DLP crawling by default;
- third-party model attack services;
- model extraction against systems outside OpenAssetWatch;
- automatic retraining from unreviewed labels;
- automatic remediation based solely on model confidence or anomaly score;
- public-news volume as a risk multiplier without deterministic relevance and
  deduplication.

## Implementation Sequence

Implementation should proceed only through separate reviewed increments:

1. contracts and invariant/heuristic classification;
2. monotonic taint and sensitive-output inspection;
3. bounded transform-aware egress controls;
4. current-security-intelligence normalization and clustering;
5. parser robustness harness;
6. model robustness evaluation after a production-relevant ML capability
   exists;
7. conditional-source transport optimization.

Each increment requires its own tests, security review, documentation, and
rollback plan. An accepted ADR is not proof that any runtime capability is
implemented.

## Consequences

### Positive

- Security guarantees become easier to reason about and test.
- Prompt-injection defenses no longer depend on language classification alone.
- Sensitive-data egress receives a stronger deterministic boundary.
- Current security events can improve prioritization without contaminating
  finding authority.
- Parser and ML failures become reproducible release artifacts.
- ML-assisted scoring becomes more explainable and auditable.

### Tradeoffs

- More contracts and telemetry are required.
- Transform-aware egress inspection and robustness testing require strict
  resource budgets.
- Security-intelligence clustering introduces additional source-quality and
  freshness governance.
- Model robustness work is deferred until a real production-relevant model
  task exists, avoiding speculative ML infrastructure.

## Related Documents

- `docs/architecture/defensive-content-and-model-robustness.md`
- `docs/architecture/ai-agent-permission-output-security.md`
- `docs/architecture/agent-evaluation-and-release-gates.md`
- `docs/architecture/external-intelligence-enrichment-roadmap.md`
- `docs/SOFTWARE_AND_VULNERABILITY_INTELLIGENCE.md`
- `docs/TRUSTED_ADVISORY_FEEDS.md`
