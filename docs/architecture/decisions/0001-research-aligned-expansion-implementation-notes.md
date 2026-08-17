# ADR-0001 Implementation Note — Explainable Risk Decision Model

ADR-0001 accepted a phased research-aligned expansion while preserving the
current deterministic authority model.

The first focused architecture document produced under that decision is:

- [`../../EXPLAINABLE_RISK_DECISION_MODEL.md`](../../EXPLAINABLE_RISK_DECISION_MODEL.md)

It resolves the detailed-design portion of ADR decisions DR-01, DR-02, and
DR-03 by defining:

- the existing 0-100 `oaw.risk.v1` value as the Operational Attention Score;
- separate severity, exploitation, exposure, importance, confidence, freshness,
  urgency, remediation-value, and verification constructs;
- the proposed additive `oaw.decision.v1` contract;
- plain-language `Monitor`, `Plan`, `Prioritize`, and `Act Now` action bands;
- deterministic reason codes and ordered decision rules;
- missing-evidence and uncertainty behavior;
- persistence, API, UI, AI, evaluation, and release-gate requirements;
- a phased implementation path that does not change current production behavior.

This note does not amend or supersede ADR-0001. It records the design artifact
created from the accepted decision. Production behavior remains unchanged until
a separate implementation is reviewed and merged.
