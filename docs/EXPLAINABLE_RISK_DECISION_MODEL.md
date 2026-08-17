# Explainable Risk Decision Model

- **Status:** Approved architecture; not yet implemented
- **Decision record:** `docs/architecture/decisions/0001-research-aligned-expansion.md`
- **Current scoring engine:** `oaw.risk.v1`
- **Proposed decision contract:** `oaw.decision.v1`
- **Primary research:** `REM-RES-001`, `EXT-RES-003`, `EXT-RES-004`,
  `ID-RES-010`, `REM-SAFE-002`, `EVAL-CAL-001`, and `EVAL-GATE-001`

## Purpose

OpenAssetWatch needs to tell a user what deserves attention, why it deserves
attention, how certain the evidence is, and what action should happen next.
Those questions cannot be answered honestly by one opaque number.

This document defines a deterministic decision layer that preserves the current
0-100 Operational Attention Score while adding separately visible decision
factors, uncertainty, urgency, and SSVC-inspired action bands.

The model is designed for families, labs, home networks, small businesses, and
future managed deployments. It must remain understandable to a non-specialist
without hiding the evidence a security professional needs.

This document does not change production behavior. Existing source, schema,
API, and database names that use `risk` remain unchanged until a separate
implementation is reviewed and merged.

## Non-goals

This design does not:

- replace the deterministic finding engine with an AI model;
- claim that the current score is a probability of compromise or loss;
- multiply CVSS, EPSS, KEV, business importance, and remediation effort into
  one pseudo-scientific value;
- permit an LLM to create findings, decision factors, action bands, exceptions,
  risk acceptance, or remediation state;
- equate missing evidence with low risk;
- automatically execute remediation;
- define universal remediation deadlines for every environment;
- claim formal SSVC conformance before a reviewed mapping and validation pass;
- introduce active network or OT interrogation;
- change the finding lifecycle, acknowledgement, or suppression semantics.

## Authority order

The decision model extends, but does not weaken, the implemented authority
order:

```text
authenticated normalized evidence
  -> deterministic identity, classification, and vulnerability matching
  -> deterministic findings and lifecycle
  -> Operational Attention Score (`oaw.risk.v1`)
  -> deterministic decision factors and action band (`oaw.decision.v1`)
  -> bounded read-only AI explanation
  -> human review and approved workflow
```

The AI Advisor may explain a persisted decision and cite its evidence. It may
not select the authoritative action band, change an input, or write decision
state.

## Five questions the product must answer

Every finding detail and asset drilldown should make these five answers visible:

1. **What is wrong?**
   The authoritative finding and its technical severity.
2. **Why does it matter here?**
   Exploitation, exposure, asset importance, operational impact, and safety
   context.
3. **How sure are we?**
   Evidence confidence, freshness, contradictions, and missing information.
4. **How quickly should I respond?**
   A deterministic urgency and action band.
5. **What produces the most useful reduction in risk?**
   An evidence-backed remediation option, expected benefit, effort, safety,
   verification, and rollback context.

## Separate decision constructs

The following constructs must remain separately stored, returned, displayed,
and auditable.

| Construct | Meaning | Must not be confused with |
| --- | --- | --- |
| Finding severity | Potential technical impact of the weakness or condition | Complete environmental risk |
| Operational Attention Score | Deterministic 0-100 ranking of active findings on an asset or site | Probability of compromise, expected loss, or urgency |
| Exploitation status | Whether exploitation is confirmed, plausible, unobserved, or unknown | Technical severity |
| Exploit probability | A time-stamped external forecast such as EPSS, when approved and available | Known exploitation or complete risk |
| Exposure | Evidence that an attacker can reach or meaningfully interact with the affected surface | Presence of an open port alone |
| Asset importance | Consequence of losing or degrading the asset in this environment | Vulnerability severity |
| Operational or safety impact | Potential effect on availability, physical process, safety, or essential service | Generic business criticality |
| Evidence confidence | Quality and agreement of the evidence supporting the finding and context | Probability that exploitation will occur |
| Evidence freshness | Age and continued validity of the supporting observations | Evidence confidence |
| Urgency | How quickly review or action should begin | Severity or the 0-100 score |
| Action band | The recommended decision state: Monitor, Plan, Prioritize, or Act Now | Automated execution authority |
| Remediation value | Expected reduction in exposure or consequence from a proposed action | Remediation effort alone |
| Remediation effort | Cost, skill, downtime, dependencies, and reversibility | Risk reduction |
| Verification state | Strength of evidence that a change actually removed or reduced the condition | Ticket completion or user attestation |

## Current Operational Attention Score

`oaw.risk.v1` remains the current deterministic asset and site ranking engine.
It combines reviewed finding severity weights, deterministic confidence, and
evidence freshness. Category caps and duplicate-category decay prevent one class
of repetitive findings from dominating an asset score.

The score remains useful for:

- sorting assets and sites;
- identifying where the largest concentration of reviewed findings exists;
- maintaining compatibility with existing APIs, tables, tests, and UI;
- explaining the contribution of each persisted finding;
- showing deterministic change after a finding resolves or reopens.

The score is not:

- a probability;
- a financial-loss estimate;
- a substitute for exploitation or exposure evidence;
- a remediation SLA;
- a reason to treat low-confidence evidence as safe;
- an SSVC decision outcome.

### Uncertainty boundary

A low-confidence or stale finding contributes less to the scalar today. The new
decision layer must counter the misleading interpretation that a smaller
contribution means a safer condition.

Whenever confidence or freshness reduces an otherwise material contribution,
the decision record must expose:

- `uncertainty_present: true`;
- the exact missing, stale, inferred, or conflicting factor;
- whether verification is required before product-specific remediation;
- the score contribution before and after the confidence/freshness adjustment;
- a plain-language warning that uncertainty reduced prioritization, not the
  potential impact.

A finding cannot be closed merely because uncertainty increased.

## Proposed `oaw.decision.v1` contract

The decision layer is finding-centered. Asset and site decisions are
aggregations of current finding decisions, not independent AI conclusions.

### Finding decision

A future authoritative finding-decision record should include:

```text
decision_id
schema_version = oaw.decision.v1
decision_ruleset_version
finding_id
finding_rule_id
site_id
asset_id or sensor_id
calculated_at
data_as_of
action_band
urgency
attention_score_contribution
severity
exploitation_status
exploit_probability
exposure_state
asset_importance
operational_impact
safety_impact
evidence_confidence
evidence_freshness
uncertainty_present
verification_required
remediation_availability
remediation_value
remediation_effort
recommended_response_window
reason_codes
evidence_references
limitations
```

All enums and reason codes must be bounded. External source text, hostnames,
software names, banners, advisory descriptions, and model output cannot become
rule identifiers or executable expressions.

### Asset decision summary

An asset summary should include:

- current Operational Attention Score and formula version;
- highest action band among current findings;
- count of findings by action band;
- count of uncertain findings;
- highest urgency;
- most consequential deterministic reason codes;
- top remediation opportunities by expected risk reduction;
- data freshness and earliest expiring input;
- accepted-risk, suppression, and VEX overlays without deleting the underlying
  finding state.

### Site decision summary

A site summary should include:

- the persisted site Operational Attention Score;
- distribution of assets and findings by action band;
- assets requiring immediate review;
- concentration of unknown or stale evidence;
- top shared remediation opportunities;
- collector and sensor health conditions affecting confidence;
- explicit warning when incomplete collection may hide exposure.

## Decision-factor taxonomy

### Technical severity

Technical severity comes from the authoritative finding rule or a reviewed
advisory source. It remains one of:

- informational;
- low;
- medium;
- high;
- critical.

A model cannot change severity. A source adapter cannot raise severity unless
its mapping and provenance are reviewed.

### Exploitation status

The initial bounded vocabulary should be:

| Value | Meaning |
| --- | --- |
| `known-exploited` | A reviewed source explicitly confirms exploitation in the wild. |
| `public-exploit-evidence` | A reviewed source confirms public exploit or proof-of-concept availability but not exploitation in the environment. |
| `no-known-exploitation` | Reviewed sources do not currently report known exploitation. This is not proof that exploitation is impossible. |
| `unknown` | No approved current source can establish the status. |
| `not-applicable` | The finding type does not have an exploitation concept. |

`known-exploited` must be tied to source, source version, retrieval time,
advisory identity, and freshness. It cannot be inferred from model text or a
keyword in untrusted feed content.

### Exploit probability

EPSS or a future approved forecast is optional and separate:

```text
probability
percentile
model_version
score_date
source
source_record_id
freshness
```

Absence of a probability produces `unknown`, never zero. The probability does
not directly change severity and must not be multiplied by CVSS or the
Operational Attention Score.

### Exposure state

The proposed vocabulary is:

| Value | Required evidence |
| --- | --- |
| `internet-reachable` | Reviewed externally observed or configuration-derived reachability to the affected service. |
| `externally-reachable` | Reachable from an untrusted or partner boundary without proving public Internet exposure. |
| `internally-reachable` | Reachable from one or more relevant internal segments. |
| `segmented` | A reviewed control limits reachability, but bypass or alternate paths are not ruled out. |
| `not-reachable` | Fresh affirmative evidence shows the affected surface is not reachable from the evaluated threat boundary. |
| `unknown` | Reachability cannot be established from current evidence. |
| `not-applicable` | The finding does not depend on network reachability. |

A listening port, passive service observation, local process, or hostname alone
cannot prove Internet exposure. An absent observation cannot prove
`not-reachable`.

The current repository does not yet have a complete durable exposure model.
Until that exists, most findings will carry `unknown` or `not-applicable`.
That is an honest intermediate state.

### Asset importance

Asset importance should be environment-specific and deterministic.

Priority of authority:

1. audited user- or administrator-assigned importance;
2. imported reviewed CMDB or policy assignment;
3. deterministic OpenAssetWatch default based on a confirmed asset role;
4. `unknown`.

Proposed values:

- `critical`;
- `high`;
- `standard`;
- `low`;
- `unknown`.

A router, gateway, identity system, backup target, security control, or OT
controller may receive a suggested importance, but suggestions must remain
separate from an approved assignment. The AI Advisor may explain or recommend a
review; it cannot write the value.

### Operational impact

Proposed values:

- `severe` — loss significantly disrupts essential operations;
- `major` — meaningful service or business disruption;
- `moderate` — localized or recoverable disruption;
- `minor` — limited operational effect;
- `unknown`;
- `not-applicable`.

### Safety impact

Proposed values:

- `potential-life-safety`;
- `potential-physical-process`;
- `availability-only`;
- `none-known`;
- `unknown`;
- `not-applicable`.

`none-known` means current reviewed evidence contains no identified safety
impact. It does not mean the device is proven safe. Any safety-impacting action
requires human approval and vendor or operator validation.

### Evidence confidence

OpenAssetWatch's current confidence values are deterministic implementation
weights, not calibrated probabilities. The decision layer should expose a
human-readable evidence band:

| Band | Meaning |
| --- | --- |
| `high` | Multiple strong or direct sources agree with no material contradiction. |
| `medium` | Sufficient evidence supports the conclusion, but some inputs are indirect, aging, or single-source. |
| `low` | The conclusion is plausible but materially inferred, stale, or weakly corroborated. |
| `insufficient` | Evidence is inadequate for a product-specific or high-consequence conclusion. |
| `conflicted` | Material strong sources disagree. |

The original numeric implementation value may remain for compatibility and
reproducibility, but the UI must not label it as a probability unless a future
calibration program justifies that claim.

### Urgency

Urgency is derived from deterministic factors and shown separately from
severity and score.

Proposed values:

| Urgency | Meaning |
| --- | --- |
| `immediate` | Begin review or containment now. Delay may materially increase consequence. |
| `expedited` | Address ahead of routine work. Validate and plan promptly. |
| `scheduled` | Include in the next appropriate maintenance or remediation cycle. |
| `monitor` | Continue observation and revisit when evidence or context changes. |
| `verification-required` | Resolve material uncertainty before selecting product-specific remediation. |

### Remediation availability

Proposed values:

- `vendor-fix-available`;
- `supported-configuration-change`;
- `compensating-control-available`;
- `replacement-required`;
- `monitoring-only`;
- `no-known-remediation`;
- `unknown`.

### Remediation value

Remediation value estimates the expected reduction produced by an approved
option. It is not computed by multiplying unrelated ordinal values.

Proposed values:

- `very-high` — removes known-exploited or high-consequence exposure, or closes
  a shared choke point affecting many findings;
- `high` — materially reduces reachability, exploitability, or consequence;
- `moderate` — reduces one material factor without resolving the complete
  condition;
- `low` — limited reduction or mainly improves visibility;
- `unknown` — evidence is insufficient to estimate benefit.

### Remediation effort

Proposed values:

- `low` — reversible, low-downtime, routine action;
- `moderate` — coordination, testing, or maintenance window required;
- `high` — significant downtime, replacement, specialized skill, or dependent
  changes;
- `prohibited-without-approval` — safety, availability, identity, or broad
  network consequences require explicit approval;
- `unknown`.

Effort influences ordering among otherwise similar options. It must never erase
an `Act Now` decision.

## Action bands

OpenAssetWatch should use plain-language action bands that are inspired by SSVC
decision transparency but are not presented as formal SSVC compliance until the
mapping is independently validated.

| Product band | Internal intent | User meaning |
| --- | --- | --- |
| `Monitor` | Track | Keep observing; no immediate change is justified by current evidence. |
| `Plan` | Track* | Create a reviewed remediation or evidence-gathering plan. |
| `Prioritize` | Attend | Move ahead of routine work and resolve dependencies quickly. |
| `Act Now` | Act | Begin immediate human-reviewed response, containment, or escalation. |

The action band is not an execution command. `Act Now` means a person should
begin the approved response workflow.

### Ordered decision approach

The decision engine should apply reviewed ordered rules, not a free-form model
or opaque arithmetic formula.

An initial ruleset should follow this order:

1. Validate that the finding is current and authoritative.
2. Evaluate compromise or safety escalation conditions.
3. Evaluate known exploitation.
4. Evaluate exposure and reachability.
5. Evaluate asset importance and operational consequence.
6. Evaluate technical severity.
7. Evaluate remediation availability and verification requirements.
8. Apply uncertainty rules.
9. Select one action band and urgency.
10. Persist reason codes and every input used.

### Baseline action-band rules

The following are architecture requirements for a future reviewed rule table.
Exact identifiers and thresholds will be versioned during implementation.

#### `Act Now`

Use `Act Now` when any reviewed rule establishes one of these conditions:

- confirmed compromise or persistence evidence requires incident-response
  escalation;
- known exploitation affects a confirmed vulnerable component and the affected
  surface is Internet-reachable or externally reachable;
- known exploitation affects a critical asset and exposure is not affirmatively
  ruled out;
- a critical finding has potential life-safety or physical-process impact;
- an identity, credential, or security-control failure creates immediate broad
  exposure;
- a time-sensitive compensating control is the only available way to prevent
  material consequence.

Low confidence cannot silently downgrade one of these to `Monitor`. When the
critical input itself is uncertain, use `verification-required` urgency and
retain the highest justified provisional band with a prominent uncertainty
warning.

#### `Prioritize`

Use `Prioritize` when:

- a high or critical confirmed finding is internally or externally reachable;
- known exploitation applies but reachability is unknown or a reviewed
  segmentation control limits exposure;
- a high-importance asset has a confirmed material weakness with an available
  fix;
- an unsupported or end-of-life product exposes a material service;
- a material identity, version, or exposure uncertainty must be resolved before
  safe product-specific remediation;
- one remediation removes a shared high-value exposure across multiple assets.

#### `Plan`

Use `Plan` when:

- a confirmed finding has no evidence of urgent exploitation or exposure, but
  a supported remediation should enter the next appropriate change cycle;
- an inventory or identity gap requires planned evidence collection;
- a compensating control is appropriate while waiting for a vendor fix;
- replacement is required but immediate isolation is not justified;
- the user must establish ownership, maintenance window, or rollback before
  proceeding.

#### `Monitor`

Use `Monitor` when:

- the finding is informational or low consequence and current evidence does not
  justify a change;
- a reviewed compensating control is effective and current, while the
  underlying condition remains visible;
- the finding is acknowledged for observation with no accepted claim of
  resolution;
- the product is waiting on a future evidence or advisory update.

`Monitor` must not be used merely because evidence is missing, stale, or
uncollected.

## Reason codes

Each decision must include bounded reason codes. Examples:

```text
EXPLOITATION_KNOWN
EXPLOIT_PROBABILITY_HIGH
EXPOSURE_INTERNET_REACHABLE
EXPOSURE_UNKNOWN
ASSET_IMPORTANCE_CRITICAL
SAFETY_IMPACT_POSSIBLE
SEVERITY_CRITICAL
VERSION_UNKNOWN
IDENTITY_UNCERTAIN
EVIDENCE_STALE
EVIDENCE_CONFLICTED
FIX_AVAILABLE
COMPENSATING_CONTROL_AVAILABLE
REPLACEMENT_REQUIRED
VERIFICATION_REQUIRED
RISK_ACCEPTANCE_ACTIVE
VEX_NOT_AFFECTED_REVIEWED
```

Reason-code definitions are reviewed code and documentation. External text
cannot define or select them.

## Missing and conflicting evidence

Missing evidence is a first-class result.

The decision layer must:

- preserve `unknown`, `insufficient`, and `conflicted` states;
- prohibit automatic conversion of missing values to zero, false, no, or low;
- show which evidence would change the decision;
- prevent stale evidence from resolving a finding;
- re-evaluate decisions when identity, component, advisory, exposure, or asset
  importance changes;
- retain the previous decision and change reason in history;
- escalate to human review when two strong sources materially disagree.

The product should be able to explain:

> The Operational Attention Score is lower because firmware identity is
> inferred. The potential severity remains high. Confirm the model and firmware
> version before applying product-specific instructions.

## Risk acceptance, suppression, and VEX

These concepts must remain separate.

| Mechanism | Meaning | Effect |
| --- | --- | --- |
| Acknowledgement | A person has reviewed the finding | Does not remove score or action band |
| Suppression | An audited time-bounded product policy hides or excludes a finding from current prioritization | Does not change historical evidence or prove not affected |
| Risk acceptance | An authorized owner accepts residual risk for a stated scope and period | Adds a governance overlay; does not rewrite finding facts |
| VEX | A reviewed applicability assertion for a specific product and vulnerability | May change applicability only after issuer, scope, status, justification, and evidence validation |
| Resolution | Fresh affirmative evidence proves the deterministic condition ended | Closes the finding under existing lifecycle rules |

A future decision summary should show active overlays and expiration dates.
Expired acceptance, suppression, or VEX review must trigger re-evaluation.

## Remediation guidance contract

The decision record does not contain executable remediation. A separate guided
remediation record may reference the decision and include:

- prerequisites;
- exact asset identity and version evidence;
- recommended option;
- alternatives and compensating controls;
- expected risk reduction;
- effort and downtime;
- safety and availability impact;
- backup and pre-change checks;
- rollback plan;
- stop conditions;
- verification method;
- vendor or authoritative sources;
- incident-response escalation criteria.

Product-specific steps must be blocked when identity or version confidence is
`insufficient` or `conflicted`.

Patching must not be presented as proof that an attacker was evicted or that
trust was restored.

## Persistence model

A future additive schema should preserve current records and introduce:

- `decision_evaluation_runs` — ruleset version, scope, requester, status,
  timestamps, and bounded failure metadata;
- `finding_decisions` — current decision projection for a finding;
- `finding_decision_history` — append-only material decision transitions;
- `decision_factors` — normalized inputs, source, evidence reference, freshness,
  confidence, and reason code;
- `asset_decision_summaries` — current asset aggregation;
- `site_decision_summaries` — current site aggregation;
- `asset_importance_assignments` — audited environment-specific assignments;
- future `risk_acceptances` and `vex_assertions` under their own governance
  models.

The current `asset_risk_scores`, `site_risk_scores`, and `risk_factors` remain
unchanged for compatibility.

Decision history should record:

- previous and new action band;
- previous and new urgency;
- changed factor and source;
- ruleset version;
- evaluation time;
- evidence time;
- transition reason;
- whether the transition was caused by new evidence, a policy assignment,
  source withdrawal, VEX, risk acceptance, or expiration.

## Evaluation and recalculation

Decision evaluation should be targeted and deterministic.

Trigger examples:

- finding opened, updated, resolved, or reopened;
- component or firmware identity changed;
- vulnerability match changed;
- reviewed advisory imported, modified, or withdrawn;
- known-exploitation or probability source updated;
- exposure evidence changed;
- asset importance assignment changed;
- sensor or collector freshness changed materially;
- suppression, VEX, or risk acceptance began or expired;
- decision ruleset version changed.

Older evaluations cannot overwrite a newer projection. Reconciliation must use
transactional or equivalent concurrency guards.

## API direction

Existing endpoints remain compatible. A future additive API may expose:

```text
GET /api/v1/decisions/rules
GET /api/v1/decisions/findings/{finding_id}
GET /api/v1/decisions/assets/{asset_id}?site_id=...
GET /api/v1/decisions/sites/{site_id}
POST /api/v1/admin/decisions/evaluate
```

Read responses should contain:

- schema and ruleset version;
- score plus formula version;
- action band and urgency;
- all decision factors;
- uncertainty and verification requirements;
- bounded evidence references;
- reason codes;
- data freshness;
- applicable governance overlays;
- limitations.

Mutating endpoints must fail closed without configured authorization and must
never accept model-authored rules or expressions.

## User experience

### Finding view

The primary decision block should appear in this order:

```text
Action: Act Now
Urgency: Immediate
Operational Attention Score: 78 / 100
Technical Severity: High
Evidence Confidence: Medium
Uncertainty: Firmware version inferred
Known Exploitation: Confirmed by reviewed source
Exposure: Internet-reachable
Asset Importance: Critical
Remediation: Vendor fix available
Verification: Required after change
```

The user should then see:

- **Why this decision** — reason codes translated to plain language;
- **Evidence** — source, record, observed time, freshness, and confidence;
- **What is unknown** — missing or conflicting factors;
- **What would change the decision** — evidence or controls that could raise or
  lower urgency;
- **Recommended next steps** — advisory-only, bounded, and evidence-backed;
- **Technical details** — finding ID, rule version, decision version, score
  factors, and catalog provenance.

### Asset view

Show:

- highest action band;
- Operational Attention Score;
- active findings by band;
- uncertainty count;
- most valuable remediation opportunity;
- evidence freshness;
- current acceptance, suppression, or VEX overlays;
- drilldowns into every contributing finding.

### Dashboard

The overview dashboard should prioritize:

- assets requiring `Act Now`;
- assets requiring `Prioritize`;
- high-impact findings with low or conflicted confidence;
- known-exploited findings;
- unknown exposure on critical assets;
- remediation opportunities with high expected value;
- stale collectors or sensors reducing confidence.

The numeric score remains useful for sorting within an action band. It should
not determine the action band by itself.

### Plain-language communication

Home and small-business users should see direct language:

> This router needs attention now because the installed firmware is confirmed
> affected, exploitation is known, and the management interface is reachable
> from the Internet. Back up the configuration, confirm the exact hardware
> revision, then follow the vendor update procedure. If the update cannot be
> applied today, restrict external access and verify the restriction.

Technical users can expand the underlying source records and rule factors.

## AI Advisor boundary

The AI Advisor may:

- explain the action band and factors;
- compare two persisted decisions;
- summarize uncertainty;
- describe evidence that would confirm or reduce risk;
- propose bounded remediation options;
- tailor language to the user's skill level without changing facts;
- generate a temporary investigation dashboard from approved decision metrics
  after the adaptive-workspace architecture is implemented.

The AI Advisor may not:

- calculate an authoritative factor;
- change asset importance;
- select a different action band;
- create an exception, VEX statement, or risk acceptance;
- suppress or resolve a finding;
- execute remediation;
- invent a source, fixed version, exposure state, or evidence ID;
- hide uncertainty.

## Versioning and compatibility

- `oaw.risk.v1` remains the score formula until a separate ADR explicitly
  changes it.
- `oaw.decision.v1` is additive.
- Decision rules are versioned independently from finding and score rules.
- Historical decisions retain their original ruleset version.
- A rule change requires deterministic before/after fixtures and documented
  migration impact.
- Existing API fields may keep `risk` names; new user-facing copy should use
  `Operational Attention Score`.
- External integrations may receive both compatibility fields and the new
  decision contract during a deprecation window.

## Implementation phases

### Phase 0 — Documentation and vocabulary

- adopt this architecture document;
- keep `oaw.risk.v1` behavior unchanged;
- align UI and documentation terminology;
- define bounded factor and reason-code registries;
- define test fixtures and release gates.

### Phase 1 — Uncertainty and score explanation

- expose `uncertainty_present` and reason codes using current evidence;
- display severity, confidence, and freshness separately;
- label the scalar as Operational Attention Score;
- preserve existing APIs and database schema where possible;
- add deterministic tests proving missing evidence never becomes a safe label.

### Phase 2 — Deterministic action bands using current evidence

- add `oaw.decision.v1` persistence and history;
- calculate finding action bands from current severity, confidence, freshness,
  finding type, reviewed `known_exploited`, and asset role evidence;
- treat unavailable exposure and importance as `unknown`;
- add asset and site summaries;
- keep the AI read-only.

### Phase 3 — Reviewed exploitation and exposure enrichment

- add approved KEV and EPSS adapters only after licensing review;
- preserve EPSS as a separate dated probability;
- add normalized exposure evidence and freshness;
- add feed health and source failure detection;
- re-evaluate decisions on corrections and withdrawals.

### Phase 4 — Governance and remediation value

- add audited asset importance assignments;
- add risk acceptance and VEX governance;
- add structured remediation options, effort, expected reduction, rollback, and
  verification;
- add consequence-tier approval requirements.

### Phase 5 — Calibration and public evaluation

- evaluate action-band consistency on a labeled time-split corpus;
- measure evidence completeness, false closure, ranking stability, and human
  review burden;
- publish failures and limitations;
- calibrate only factors that have defensible ground truth;
- never relabel implementation weights as probabilities without evidence.

## Required tests

A future implementation must include:

### Determinism

- identical inputs produce identical decisions and reason-code ordering;
- ruleset versions are stable and explicit;
- older evaluations cannot overwrite newer state;
- duplicate evidence does not inflate exploitation, exposure, or confidence.

### Missing evidence

- absent EPSS produces `unknown`, not zero;
- absent exposure produces `unknown`, not `not-reachable`;
- absent asset importance produces `unknown`, not `low`;
- stale evidence cannot resolve a finding;
- insufficient identity or version blocks product-specific remediation;
- uncertainty cannot silently downgrade an otherwise material condition to
  `Monitor`.

### Action bands

- known-exploited plus confirmed external exposure produces `Act Now` under the
  reviewed rule;
- known-exploited plus unknown exposure remains at least `Prioritize` for a
  confirmed affected component;
- a supported medium finding without urgent context produces `Plan`;
- an informational current condition with complete evidence may produce
  `Monitor`;
- the Operational Attention Score alone cannot select an action band.

### Governance

- acknowledgement does not change the authoritative decision;
- suppression, risk acceptance, VEX, and resolution remain distinct;
- expired overlays trigger re-evaluation;
- unauthorized importance or acceptance changes fail closed;
- every mutation is audited.

### AI security

- model output cannot change factors or bands;
- unknown evidence and decision IDs reject provider output;
- malicious asset, advisory, and finding text cannot select rules;
- prompt injection cannot suppress uncertainty or trigger remediation;
- same-model agreement is not treated as independent verification.

### Isolation and performance

- site and future tenant boundaries apply at the database query boundary;
- decision summaries cannot leak another site or tenant;
- full and targeted evaluations have explicit input and output bounds;
- repeated evaluation remains idempotent;
- synthetic performance results are clearly labeled and separate from
  production claims.

## Release blockers

The decision capability must not ship when any of these are true:

- an LLM can write or override a factor, action band, finding, score, decision,
  or governance record;
- missing evidence is converted to a safe or low state;
- an external source lacks an approved licensing-registry decision;
- untrusted source content can define rules or reason codes;
- a finding can close without affirmative evidence;
- an action band lacks persisted reason codes and evidence references;
- site or tenant data can cross authorization boundaries;
- an `Act Now` result automatically executes a high-consequence action;
- active OT interrogation is introduced without its separate deterministic
  approval and safety architecture;
- synthetic or self-consistency results are presented as production accuracy.

## Example decisions

### Known-exploited Internet-facing router

```text
Finding: vulnerable-component
Severity: high
Known exploitation: yes
Exposure: internet-reachable
Asset importance: critical
Evidence confidence: high
Action band: Act Now
Urgency: immediate
Operational Attention Score: shown separately
```

Reasoning: exploitation, reachability, and gateway importance justify immediate
human-reviewed response. The score did not select the band.

### Firmware identity is inferred

```text
Finding: advisory-identity-uncertain
Severity: informational gap finding
Potential advisory severity: high
Firmware identity: inferred
Exposure: unknown
Evidence confidence: insufficient
Action band: Prioritize
Urgency: verification-required
```

Reasoning: the system cannot claim the product is affected, but the possible
consequence justifies prompt identity and version verification. It must not
provide model-specific update steps yet.

### Confirmed medium package finding with a supported fix

```text
Finding: vulnerable-component
Severity: medium
Known exploitation: no-known-exploitation
Exposure: internally-reachable
Asset importance: standard
Fix: available
Evidence confidence: high
Action band: Plan
Urgency: scheduled
```

Reasoning: a confirmed issue should enter the next appropriate maintenance
cycle. The lack of known exploitation is not a guarantee of safety.

### Stale collection on an important asset

```text
Finding: asset-stale
Severity: low
Asset importance: high
Evidence freshness: stale
Exposure: unknown
Action band: Plan
Urgency: verification-required
Uncertainty: present
```

Reasoning: stale collection lowers the score contribution but increases
uncertainty. The correct next step is to restore evidence, not declare the asset
safe.

## Acceptance criteria for architectural readiness

The design is ready for a Codex implementation plan only when:

- factor enums and reason codes are reviewed;
- the initial ordered action-band rule table is written and approved;
- the additive schema and history behavior are defined;
- current API compatibility is documented;
- authorization requirements are explicit;
- source licensing decisions exist for any new external input;
- test fixtures cover the missing-evidence and release-blocker cases;
- UI language is reviewed for home, SMB, and technical audiences;
- no action or remediation execution is included in the first implementation;
- performance bounds and failure behavior are defined.

## Related documentation

- `docs/DETERMINISTIC_FINDINGS_AND_RISK.md`
- `docs/SOFTWARE_AND_VULNERABILITY_INTELLIGENCE.md`
- `docs/RESEARCH_INTEGRATION_AND_ARCHITECTURE_GAP_MATRIX.md`
- `docs/SOURCE_LICENSING_REGISTRY.md`
- `docs/architecture/ai-advisor.md`
- `docs/architecture/ai-agent-architecture.md`
- `docs/architecture/decisions/0001-research-aligned-expansion.md`
- `docs/research/2026-07-independent-security-research/EXPLAINABLE_RISK_AND_REMEDIATION.md`
- `docs/research/2026-07-independent-security-research/EVALUATION_AND_RELEASE_GATES.md`
