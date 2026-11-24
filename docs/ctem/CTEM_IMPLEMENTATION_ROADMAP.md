# CTEM Implementation Roadmap

**Status:** planning document, refreshed after the decision layer (`CTEM-GAP-01`)
was implemented. Capability detail is in
[CTEM_CAPABILITY_GAP_SYNTHESIS.md](CTEM_CAPABILITY_GAP_SYNTHESIS.md).

## Current status by CTEM stage

| Stage | Capability | Status |
| --- | --- | --- |
| Scoping | Site as the scope boundary | IMPLEMENTED |
| Scoping | Asset importance and business-service context (`CTEM-GAP-02`) | NOT IMPLEMENTED |
| Scoping | Verified external scope (`CTEM-GAP-03`) | PROPOSED (accepted design) |
| Scoping | Rule-based asset groups (`CTEM-GAP-11`) | FUTURE |
| Scoping | Scoped review cycles (`CTEM-GAP-14`) | FUTURE |
| Discovery | Endpoint, passive, and collector inventory; classification | IMPLEMENTED |
| Discovery | Reversible identity merge and split | PROPOSED (accepted design) |
| Prioritization | Deterministic findings and Operational Attention Score | IMPLEMENTED |
| Prioritization | Known-exploited catalog evidence | IMPLEMENTED |
| Prioritization | **Deterministic decision layer: action bands, reason codes, history (`CTEM-GAP-01`)** | **IMPLEMENTED (v1)** |
| Prioritization | Evidence-derived exposure state (`CTEM-GAP-03`) | PROPOSED (accepted design) |
| Prioritization | Exploit-likelihood context (`CTEM-GAP-08`) | PROPOSED (accepted design, source-gated) |
| Prioritization | Compensating-control assessment (`CTEM-GAP-07`) | PROPOSED (proposed design on main) |
| Prioritization | Relationship and path hints (`CTEM-GAP-13`) | FUTURE |
| Validation | Resolution on fresh affirmative evidence | IMPLEMENTED |
| Validation | Verification guidance and records (`CTEM-GAP-06`) | PROPOSED (proposed design on main) |
| Mobilization | Manual work tracking | IMPLEMENTED |
| Mobilization | Shared-treatment grouping (`CTEM-GAP-05`) | FUTURE |
| Mobilization | Target dates from action bands (`CTEM-GAP-12`) | FUTURE |
| Mobilization | Exception governance and applicability statements (`CTEM-GAP-04`) | PROPOSED (accepted design) |
| Cross-cutting | Outcome metrics (`CTEM-GAP-09`) | FUTURE |
| Cross-cutting | Tamper-evident governance history (`CTEM-GAP-10`) | FUTURE |
| Cross-cutting | AI explanation of decisions | NOT IMPLEMENTED (boundary documented) |

## What the decision layer changed

Implementing `CTEM-GAP-01` surfaced these facts, which change the order:

1. **Act Now is unreachable** until a finding can carry confirmed exposure or a
   critical asset. Under the approved rules, known exploitation reaches Act Now
   only with reachability or a critical asset. So asset importance and exposure
   now directly limit the value of the decision layer.
2. **Asset importance is the cheapest unlock.** It is a local, audited
   assignment with no external source, collection change, or licensing gate.
   Exposure needs a scope registry, external evidence, and path reasoning.
3. **Decision history now exists.** Together with work-tracking events, it
   gives dated band transitions and work changes. Verification records and
   outcome metrics can build on real data instead of waiting for a new store.
4. **Target dates depend on complete bands.** Deriving dates from bands before
   Act Now is reachable would encode an incomplete scale, so they move after
   importance.
5. **Two append-only governance tables exist** (work events and decision
   history). Tamper-evident chaining is now more valuable and still small.
6. **Exploit likelihood does not change any v1 band.** The approved rules use
   it as a separate field and reason, not as a band driver, and it remains
   source-gated.

## Recommended order

| Order | Capability | Why now | Depends on |
| --- | --- | --- | --- |
| 1 | `CTEM-GAP-02` asset importance (audited assignment; business services later) | Enables the first Act Now rule (known exploitation on a critical asset, exposure not ruled out); local and unblocked | Decision layer (done) |
| 2 | `CTEM-GAP-06` verification guidance and records | Answers "did remediation reduce exposure?" by joining work status, decision history, and later evidence | Decision layer, work tracking (done) |
| 3 | `CTEM-GAP-09` outcome metrics | Time in each band, time to verified resolution, and done-but-unverified work, from existing history | `CTEM-GAP-06` for the verification metrics |
| 4 | `CTEM-GAP-03` exposure state and verified scope | Enables the remaining Act Now rule (known exploitation that is reachable) | Scope registry, approved external sources |
| 5 | `CTEM-GAP-05` shared-treatment grouping | Groups findings one fix closes; independent of bands | Fixed-version data on findings |
| 6 | `CTEM-GAP-10` tamper-evident governance history | Two append-only tables now benefit | None |
| 7 | `CTEM-GAP-12` target dates from action bands | Needs a complete band scale | `CTEM-GAP-02` |
| 8 | `CTEM-GAP-08` exploit-likelihood context | Separate field and reason only | Source Licensing Registry decision |
| 9 | `CTEM-GAP-04` exception governance | High value, but real two-person approval is blocked | Per-user identity |
| 10 | `CTEM-GAP-11` asset groups, then `CTEM-GAP-14` review cycles | Reporting and scoping conveniences | `CTEM-GAP-09` |
| 11 | `CTEM-GAP-07` control assessment, `CTEM-GAP-13` path hints | Research-gated | `CTEM-GAP-03`, relationship ledger |

## Decision-layer follow-ups

Smaller items that extend `CTEM-GAP-01` without a new gap:

- asset and site decision summaries (highest band, counts by band, uncertain
  findings), as aggregations of current finding decisions;
- known exploitation from a reviewed advisory's own flag, as a second
  canonical exploitation source;
- a fix-available reason, once findings carry a structured fixed version;
- a read-only AI Advisor tool that explains a persisted decision, under the
  documented boundary;
- decision-history temporal signals (for example, Prioritize findings per site
  over time) through the existing temporal registry.

## Recommended next implementation

**`CTEM-GAP-02`: audited asset importance.** Scope it as:

- an additive assignment record per asset with value, assigner label,
  verification marker (unverified, like work tracking), reason, and timestamps,
  plus append-only history;
- separation of duties for lowering importance recorded but not enforceable
  until per-user identity exists (the same limit as exception governance);
- a ruleset `oaw.decision.rules.v2` that adds the approved Act Now rule for
  known exploitation on a critical asset when exposure is not ruled out, with
  before-and-after fixtures and a `ruleset-changed` transition for every
  affected finding;
- recomputation of the asset's decisions when importance changes, through
  deterministic finding evaluation.
