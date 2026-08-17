# Native Agent Expansion Implementation Plan

- **Status:** Planning only; no runtime work is authorized by this file
- **Decision:** `docs/architecture/decisions/0003-native-agent-investigation-and-temporal-intelligence.md`

## Purpose

This plan turns the accepted investigation, Skill Pack, capability/provider,
evaluation, and temporal-intelligence designs into small implementation units.
It exists so future coding work can land incrementally without creating a
second control plane or weakening the current OpenAssetWatch authority model.

## Sequencing rule

Each work package must preserve this order:

```text
schema and deterministic policy
  -> tests and failure cases
  -> read-only runtime
  -> UI projection
  -> optional model/provider integration
```

Provider integration never comes before the deterministic contract and release
gates it must obey.

## Work Package A — Investigation schemas

### Deliverables

- `oaw.investigation.v1`
- `oaw.investigation-task.v1`
- `oaw.investigation-output.v1`
- `oaw.verification.v1`
- ledger event schema
- state-transition table

### Acceptance criteria

- strict schemas reject unknown fields;
- evidence IDs are bounded references;
- tenant/site/scope fields are explicit;
- budgets and stop reasons are first-class;
- no write-capable action fields exist; and
- schema tests cover malformed and oversized records.

## Work Package B — Deterministic coordinator

### Deliverables

- trigger-to-route registry;
- role selection rules;
- Skill Pack selection hook;
- budget enforcement;
- cancellation state;
- transition validator.

### Acceptance criteria

- routing is reproducible from the same structured inputs;
- a model cannot add a route or role;
- unsupported triggers fail closed;
- scope is immutable within a task;
- cancellation stops future dispatch; and
- no provider dependency is required.

## Work Package C — Agent Run Ledger

### Deliverables

- append-only ledger persistence;
- idempotent event identity;
- read-only API projection;
- bounded event metadata;
- retention policy hooks.

### Acceptance criteria

- duplicate retries do not duplicate accepted events;
- restart/resume preserves lifecycle ordering;
- hidden reasoning is not required;
- secrets and raw authorization data are excluded; and
- every investigation transition is attributable.

## Work Package D — Synthetic specialist runtime

### Deliverables

- deterministic specialist fixtures for each initial role;
- simulated success/failure/timeout/malformed-output paths;
- task-result validator.

### Acceptance criteria

- full investigation flow works without an LLM;
- correlation and verification can be tested offline;
- provider failures are reproducible; and
- UI/API work can begin without external credentials.

## Work Package E — Deterministic correlation

### Deliverables

- hypothesis normalization;
- duplicate grouping;
- conflict preservation;
- evidence-reference validation;
- missing-evidence classification;
- verification routing.

### Acceptance criteria

- agreement does not automatically increase confidence;
- conflicts remain visible;
- invalid evidence IDs reject the hypothesis;
- identical retries are idempotent; and
- correlation output is fully deterministic.

## Work Package F — Verification state machine

### Deliverables

- verifier task contract;
- supported/unsupported/inconclusive results;
- evidence-request transition;
- maximum verification retries;
- human-review handoff.

### Acceptance criteria

- unsupported and inconclusive states cannot be treated as complete;
- verification never writes authoritative findings;
- stale/new evidence is rechecked before resume; and
- false-closure fixtures block release.

## Work Package G — Skill Pack validator

### Deliverables

- strict `skill.yaml` schema;
- instruction/input/output file validation;
- allowed-tool validation;
- version/status registry;
- evaluation-fixture discovery.

### Acceptance criteria

- only approved Skill Packs are selectable;
- unknown manifest fields fail;
- no arbitrary scripts are loaded;
- Skill Packs cannot grant new tools or scope;
- recursive specialist spawning is unavailable; and
- historical tasks retain exact Skill Pack versions.

## Work Package H — First-party Skill Packs

Initial packs:

- Asset Identity Review
- Vulnerability Applicability Review
- Security Coverage Review
- Behavior and Change Review
- Data Quality Review
- IoT and OT Context Review
- Remediation Planning
- Investigation Report

Each pack should land separately with its fixtures and evaluation results.

## Work Package I — Agent evaluation harness

### Deliverables

- versioned fixture loader;
- expected and forbidden behavior checks;
- ledger assertions;
- scope/tool/authority checks;
- prompt-injection fixtures;
- repeated-run report contract.

### Acceptance criteria

- hard blockers are machine-enforced;
- synthetic versus model-backed results are labeled;
- per-case failure evidence is retained;
- one aggregate score cannot hide a safety failure; and
- the harness runs fully offline for deterministic fixtures.

## Work Package J — Read-only investigation API and UI

### Deliverables

- investigation list/detail projection;
- task status;
- hypothesis/conflict view;
- verification view;
- evidence timeline;
- Agent Run Ledger timeline;
- cancel/review controls with existing authorization patterns.

### Acceptance criteria

- UI shows uncertainty and conflict;
- no agent-agreement visualization implies truth;
- raw hidden reasoning is never displayed;
- cross-site access is blocked; and
- all state-changing review controls are auditable.

## Work Package K — Local provider adapter

### Deliverables

- native capability/provider binding;
- bounded provider-facing projection;
- strict response validator;
- timeout/cancel behavior;
- health/status projection.

### Acceptance criteria

- provider has no direct database/tool access;
- local-only mode stays local;
- malformed output fails closed;
- provider outage does not break deterministic core operation; and
- all non-deterministic paths pass repeated-run evaluation.

## Work Package L — Optional hosted provider adapter

This work package is separate from local provider support.

### Required gates

- explicit external-processing enablement;
- provider/privacy configuration;
- secrets stored outside tracked files;
- bounded data projection;
- no automatic local-to-hosted fallback;
- evaluation parity with local contract; and
- customer-visible mode/status.

## Work Package M — Temporal signal registry

### Deliverables

- metric/signal definitions;
- deterministic bucketing;
- missingness/completeness state;
- duplicate/backfill handling;
- read-only trend API.

Start with a small number of existing evidence-backed signals rather than every
available timestamped field.

## Work Package N — Deterministic temporal baselines

### Deliverables

- robust rolling baseline;
- seasonal comparison where enough history exists;
- bounded trend/rate-of-change methods;
- expected-range artifact;
- data-quality/confidence state.

### Acceptance criteria

- methods are deterministic and versioned;
- sparse data reduces confidence or blocks output;
- expected range is visible;
- no forecast directly creates a finding; and
- backtests use only information available before each cutoff.

## Work Package O — Temporal deviation rules

### Deliverables

- deterministic deviation registry;
- minimum-history/completeness gates;
- persistence/freshness rules;
- candidate deviation lifecycle;
- optional investigation trigger.

### Acceptance criteria

- forecast provider cannot choose production thresholds;
- collection outages are distinguishable from asset changes;
- a deviation is not labeled compromise; and
- finding integration uses the normal deterministic lifecycle.

## Work Package P — Advanced forecasting research

This is last, optional, and blocked until enough real historical data exists.

### Required gates

- deterministic baseline already shipped;
- time-split benchmark corpus;
- resource/latency measurements;
- missing/outage cases;
- uncertainty output;
- privacy review;
- provider-neutral adapter; and
- measurable improvement on a defined product outcome.

If the advanced method does not outperform the deterministic baseline in a
useful, stable, explainable way, do not enable it.

## Parallelism guidance

Safe parallel development after schemas stabilize:

- ledger persistence and synthetic specialist fixtures;
- Skill Pack validator and evaluation harness;
- investigation UI projections and deterministic correlation;
- temporal signal registry and temporal UI groundwork.

Provider adapters should wait for coordinator, schema, and evaluation contracts.

## Release discipline

Each implementation PR should state:

- work package ID;
- authoritative state affected;
- new schemas/state transitions;
- tools/capabilities added;
- privacy boundary;
- tests/evaluation run;
- known limitations;
- rollback path; and
- whether any provider/network dependency was introduced.

## Stop conditions

Pause implementation and return to design if a work package requires:

- direct AI writes to authoritative state;
- unrestricted commands, SQL, filesystem, URLs, IPs, or CIDRs;
- recursive uncontrolled agent fan-out;
- hidden provider authority;
- active OT interrogation without its own approved safety architecture;
- silent external data sharing; or
- a forecasting result to replace deterministic finding logic.

## Planning-only status

No item in this plan is implemented merely because it appears here. Each work
package requires its own reviewed PR, tests, and release gates.