# Explainable Risk Decision Model

The canonical design is maintained at:

- [`../EXPLAINABLE_RISK_DECISION_MODEL.md`](../EXPLAINABLE_RISK_DECISION_MODEL.md)

That document defines the approved, not-yet-implemented `oaw.decision.v1`
architecture: separate decision factors, uncertainty, urgency, SSVC-inspired
action bands, persistence direction, APIs, UI behavior, AI authority boundaries,
evaluation requirements, release blockers, and phased implementation.

Current production behavior remains defined by:

- [`../DETERMINISTIC_FINDINGS_AND_RISK.md`](../DETERMINISTIC_FINDINGS_AND_RISK.md)
- [`../SOFTWARE_AND_VULNERABILITY_INTELLIGENCE.md`](../SOFTWARE_AND_VULNERABILITY_INTELLIGENCE.md)

The 0-100 `oaw.risk.v1` Operational Attention Score remains implemented and
unchanged. `oaw.decision.v1` is architecture direction only until a separate
reviewed implementation is merged.
