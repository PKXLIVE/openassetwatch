# Dynamic Dashboard Composition Skill Pack

- **Status:** Accepted design; Skill Pack runtime and dynamic dashboard planner not yet implemented
- **Decision:** `docs/architecture/decisions/0008-dynamic-dashboard-composition.md`
- **Relationship:** Extends `skill-pack-contract.md`, the temporal signal foundation, and the adaptive-drilldown dashboard direction without changing current dashboard authority

## Purpose

OpenAssetWatch should be able to build temporary, context-specific dashboards on demand for an operator without allowing an AI model to invent database queries, metrics, joins, fields, executable visualization code, or hidden filters.

The design uses a future **Dashboard Composition Skill Pack** backed by two governed libraries:

1. a **Panel Template Registry** containing reviewed, versioned visualization components; and
2. a **Dashboard Template Catalog** containing reviewed layout and analytical-intent templates.

The Skill Pack may select, parameterize, rank, and arrange approved templates. Product code remains responsible for authorization, semantic metric resolution, canonical query generation, resource limits, validation, rendering, persistence, and audit.

The design supports historical and near-real-time views while preserving OpenAssetWatch principles: asset-first, evidence-first, passive-first, local/self-hosted first, deterministic authority, provider-neutral AI, explicit provenance, and human control over persistence.

## Core Rule

```text
The Skill Pack chooses from governed analytical building blocks.
It does not invent the data model or execution path.
```

A generated dashboard is an analytical projection, not authoritative product state.

## 1. High-Level Architecture

```text
Operator Question / Drilldown Click / Investigation Context
                         |
                         v
             Trusted Dashboard Request Context
                         |
                         v
              Authorization and Scope Resolution
                         |
                         v
             Dashboard Composition Skill Pack
                         |
             +-----------+-----------+
             |                       |
             v                       v
     Panel Template Registry   Dashboard Template Catalog
             |                       |
             +-----------+-----------+
                         |
                         v
                 Dashboard Plan Proposal
                         |
                         v
            Deterministic Plan Validation
                         |
          +--------------+--------------+
          |                             |
          v                             v
 Semantic Metric / Data Catalog   Query and Cost Governor
          |                             |
          +--------------+--------------+
                         |
                         v
                 Canonical Data Queries
                         |
                         v
                  Ephemeral Dashboard
                         |
              +----------+----------+
              |          |          |
              v          v          v
            Refine    Discard   Explicit Save
                                   |
                                   v
                         Named / Owned Dashboard
```

The Skill Pack never receives raw database credentials, unrestricted SQL access, arbitrary filesystem access, or publication authority.

## 2. Dashboard Request Context

A dynamic dashboard request should begin with a bounded server-issued context rather than an unconstrained prompt.

```yaml
schema: oaw.dashboard-request.v1
request_id: dashboard-request-123
requested_by: user-17
request_type: natural_language
objective: Show how collector freshness changed this week and which sites need attention.

tenant_id: tenant-1
site_ids:
  - site-1
  - site-2

entity_context:
  entity_type: collector
  entity_ids: []

time_range:
  start: 2026-08-21T00:00:00Z
  end: 2026-08-28T00:00:00Z

inherited_filters: []
allowed_data_domains:
  - collectors
  - temporal_signals
  - sites

render_mode: ephemeral
```

Required context includes authenticated requester identity, server-resolved tenant/site scope, stable entity IDs, bounded time range, inherited drilldown filters, allowed data domains, lifecycle mode, source dashboard/panel when applicable, and the analytical objective.

Untrusted asset names, hostnames, external-intelligence descriptions, findings text, or logs must not become raw query predicates.

## 3. Dashboard Composition Skill Pack

The Dashboard Composition Skill Pack is a first-party OpenAssetWatch Skill Pack specializing in analytical layout and panel selection.

### Target Package Layout

```text
configs/skills/
  dashboard-composition/
    skill.yaml
    instructions.md
    input.schema.json
    output.schema.json
    templates/
      panels/
        *.panel.yaml
      dashboards/
        *.dashboard.yaml
    evals/
      *.json
```

This is a future layout only. The current repository does not yet have a production Skill Pack loader.

### Skill Responsibilities

The Skill Pack may:

- interpret the operator's analytical objective;
- select approved dashboard and panel templates;
- select approved measures/dimensions from the semantic catalog;
- bind typed variables and filters;
- choose a permitted refresh mode/cadence;
- choose a layout from the allowed layout grammar;
- rank useful panels;
- add provenance/data-quality panels;
- propose safe drilldown destinations; and
- explain why each panel was selected.

It may not:

- emit raw SQL;
- invent measures, dimensions, joins, tables, or fields;
- emit arbitrary JavaScript, Python, HTML, or executable visualization code;
- request arbitrary URLs;
- bypass row/column security;
- hide filters;
- expand tenant/site scope;
- disable query-cost limits;
- create write-capable panels;
- save a dashboard without explicit user action; or
- use an unapproved/unpinned template.

## 4. Skill Manifest Direction

```yaml
schema_version: oaw.skill.v1
id: dashboard-composition
version: 1.0.0
title: Dynamic Dashboard Composition
description: Compose bounded OpenAssetWatch dashboards from approved templates and semantic metrics.
role_family: dashboard-composer
status: approved
read_only: true

required_capabilities:
  - dashboard.compose

allowed_tool_ids:
  - dashboard.semantic_catalog.read
  - dashboard.panel_templates.read
  - dashboard.dashboard_templates.read
  - dashboard.plan.validate
  - temporal.read

max_steps: 8
max_evidence_records: 100
max_output_bytes: 32768
requires_verification: true
requires_human_review: false
external_processing: deployment-policy
```

The exact fields may change before implementation. The Skill Pack cannot grant tools or capabilities to itself; effective access remains the intersection defined in `skill-pack-contract.md`.

## 5. Panel Template Registry

The Panel Template Registry is the primary guardrail for safe on-demand dashboard generation. Each template represents a reviewed visualization pattern with known data semantics, cost limits, rendering behavior, refresh policy, and drilldown constraints.

### Panel Template Contract

```yaml
schema: oaw.panel-template.v1
panel_template_id: temporal-line-series
version: 1.2.0
status: approved

intent:
  answers:
    - change_over_time
    - trend

visualization:
  family: time_series
  allowed_variants:
    - line
    - area

semantic_requirements:
  measures:
    min: 1
    max: 4
  dimensions:
    allowed:
      - time_bucket
      - site
      - asset

refresh:
  modes:
    - snapshot
    - polling
  minimum_interval_seconds: 30
  default_interval_seconds: 60

query_policy:
  cost_class: medium
  max_rows: 10000
  max_series: 12
  max_categories: 50

empty_state:
  missing_is_zero: false
  show_quality_state: true

provenance:
  require_metric_version: true
  require_generated_at: true
  require_source_freshness: true

security:
  sensitivity_ceiling: internal
  executable_content: false
```

Each panel template should define a stable ID, version/digest, approval state, analytical intent, visualization family, allowed measures/dimensions/aggregations, variables, time-range rules, refresh modes, cost/cardinality limits, missingness semantics, provenance requirements, sensitivity ceiling, drilldown targets, responsive constraints, accessibility requirements, and evaluation fixtures.

Display name alone is never template identity.

## 6. Initial Panel Families

The first library should stay intentionally small and OpenAssetWatch-specific.

### Metric Summary

Use for total assets, unknown assets, active/stale collectors, open findings, affected components, and sites needing attention.

Rules: distinguish zero from unavailable; show freshness; expose metric definition/version; period comparison only when definitions/windows are compatible.

### Time Series

Use for asset count history, collector freshness, findings over time, vulnerability exposure history, evidence volume, and governed temporal signals.

Rules: explicit time basis; gaps remain gaps; late/backfilled/incomplete buckets remain distinguishable; no smoothing that hides missing data by default.

### Ranked Bar

Use for assets by platform, findings by type, sites by stale collectors, affected software, and risk-factor distribution.

Rules: bounded top-N; truncation disclosed; identifiers are not aggregated numerically.

### Composition

Use for bounded low-cardinality composition such as asset class or collector state.

Rules: explicit denominator; category cap; explained `other` bucket where needed; no pie/donut for high-cardinality fields.

### Table

Use for precise operational detail.

Rules: row cap/pagination; approved sort/filter dimensions; sensitive-column policy; stable IDs for drilldown; no HTML/script execution from cell content.

### Heatmap / Matrix

Use for bounded two-dimensional distributions.

Rules: cardinality limits on both axes; legend/unit required; missing cells distinct from zero.

### Timeline / Event Rail

Use for asset change history, investigation events, collector check-ins, and vulnerability/finding lifecycle.

Rules: canonical timestamps; source/evidence references; generated summaries distinct from recorded events.

### Status Matrix

Use for collector, sensor, site, connector, or integration health.

Rules: governed state vocabulary; no color-only meaning; `unknown`, `late`, `disabled`, `degraded`, and `healthy` remain separate.

### Relationship / Exposure View

Use only when an approved relationship projection exists.

Rules: observed vs inferred edges distinguished; traversal bounded; no path presented as causal proof; high-cardinality graph expansion prohibited.

### Evidence / Provenance Panel

Show data sources, freshness, metric versions, filters, row counts, truncation, missing/incomplete state, generation status, and limitations. This may be mandatory for security-sensitive generated dashboards.

## 7. Dashboard Template Catalog

A Dashboard Template defines a reviewed analytical composition with named slots instead of fixed hard-coded values.

```yaml
schema: oaw.dashboard-template.v1
dashboard_template_id: environment-command-center
version: 1.0.0
status: approved

intent:
  - environment_overview
  - operational_attention

variables:
  - site_scope
  - time_range

slots:
  - slot_id: summary
    layout: kpi_strip
    min_panels: 4
    max_panels: 8
    allowed_panel_families:
      - metric_summary

  - slot_id: primary
    layout: two_column
    min_panels: 2
    max_panels: 4
    allowed_panel_families:
      - time_series
      - ranked_bar
      - composition
      - status_matrix

  - slot_id: attention
    layout: full_width
    min_panels: 1
    max_panels: 3
    allowed_panel_families:
      - table
      - timeline
```

The Skill Pack may choose how to fill slots but cannot exceed the template's constraints.

## 8. Initial Dashboard Templates

### Environment Command Center

Answers what exists, what changed, what is unknown/stale, which sites need attention, and whether collectors/sensors are healthy.

### Asset Deep Dive

Answers what is known about an asset, identity confidence, software/security tooling, recent changes, findings, and supporting evidence.

### Vulnerability Context

Answers which verified assets are affected, applicability evidence, fixed/unknown/stale state, and exposure history.

### Collector and Sensor Operations

Answers which collectors/sensors are healthy, stale, late, degraded, or disabled; where coverage gaps exist; and how check-ins/evidence volume are changing.

### Findings and Attention

Answers what needs review, which classes are increasing, what evidence is stale/missing, and which assets/sites carry the most current attention.

### Environment Trends

Answers how governed metrics change over time while preserving missing, incomplete, stale, late, and backfilled bucket states.

### Security Intelligence Watch

Answers which current intelligence items may relate to the environment, which remain external/unverified, and what assets/products are candidate matches.

### Investigation Workspace

Answers case timeline, supporting/contradicting evidence, related assets/entities, and pending verification or human decision.

## 9. Semantic Metric and Data Catalog

The Skill Pack should not use raw database schema as its planning surface. It should receive a governed semantic catalog containing metric/measure IDs, versions, descriptions, units, allowed aggregations, dimensions, approved join paths, freshness/missingness semantics, sensitivity, row/column security, maximum cardinality, historical/real-time availability, and compatible templates.

The semantic layer generates canonical queries. AI references stable IDs only.

A generated panel records the exact metric definition/version used. If a metric changes, a saved dashboard remains pinned or enters an explicit update-available state rather than silently changing meaning.

## 10. Variables and Dynamic Filters

Variables are typed objects, not query fragments.

Candidate variable types include site, asset, asset class, finding state, severity, collector/sensor state, software/component, time range, approved temporal metric, and approved intelligence state. Tenant scope is always resolved server-side.

```yaml
variable_id: site_scope
type: entity_reference
entity_type: site
source: authenticated_scope
multi_value: true
required: true
visible: true
```

Dependencies may be deterministic, for example:

```text
Tenant -> Sites -> Assets -> Components
```

All effective filters must be visible/inspectable. Hidden model-generated filters are prohibited.

## 11. Real-Time and Historical Refresh Model

Dynamic dashboards support refresh only when the underlying source supports it safely:

- `snapshot` - one bounded query at render time;
- `polling` - periodic bounded refresh; and
- `stream` - event-driven updates only for an approved stream-capable source/runtime.

The Skill Pack may select among allowed modes but cannot manufacture a streaming source.

```yaml
refresh:
  mode: polling
  interval_seconds: 60
  minimum_interval_seconds: 30
  maximum_interval_seconds: 3600
  scope: panel
```

Controls include minimum refresh intervals, per-dashboard query-rate ceilings, per-tenant concurrency budgets, backpressure for streams, stale-data indicators, last-success timestamps, and panel-level failure isolation.

Real-time means fast projection refresh from approved sources; it does not mean authoritative truth.

## 12. Drilldown and Context Preservation

A drilldown carries typed values such as stable entity ID, tenant/site scope, time range, visible variables, source panel ID, metric ID, and clicked approved dimension value.

```text
Environment Dashboard
  -> click Stale Collectors
  -> Collector Operations Dashboard
  -> filter state=stale
  -> click Site A
  -> Site Collector Detail
```

The model does not reconstruct filters from display text.

## 13. Dashboard Plan Contract

The Skill Pack emits a strict declarative plan.

```yaml
schema: oaw.dashboard-plan.v1
plan_id: dashboard-plan-123
request_id: dashboard-request-123
skill_id: dashboard-composition
skill_version: 1.0.0

template:
  dashboard_template_id: environment-command-center
  version: 1.0.0

variables:
  site_scope:
    values:
      - site-1

panels:
  - plan_panel_id: panel-1
    panel_template_id: temporal-line-series
    panel_template_version: 1.2.0
    title: Collector freshness over time
    question: How has collector freshness changed this week?
    measures:
      - collector.fresh_count
      - collector.stale_count
    dimensions:
      - time_bucket
    refresh:
      mode: polling
      interval_seconds: 60
    layout_slot: primary

lifecycle:
  mode: ephemeral
  expires_at: 2026-08-28T03:00:00Z
```

Unknown fields fail validation.

## 14. Deterministic Plan Validation

Before any query runs, validate requester identity, scope, Skill Pack/version, dashboard template/version, panel templates, metrics/dimensions, aggregations, joins, variables, row/column permissions, sensitivity, time range, refresh cadence, query cost, expected rows/cardinality, panel count, layout, drilldowns, provenance requirements, and lifecycle state.

If a plan cannot validate, fall back to a fixed/parameterized template or return an explicit unsupported request. The model does not repair authorization violations by itself.

## 15. Query and Resource Governor

```yaml
query_budget:
  max_panels: 12
  max_concurrent_queries: 4
  max_query_seconds: 10
  max_rows_per_panel: 10000
  max_total_rows: 50000
  max_series_per_panel: 12
  max_categories_per_panel: 50
  max_refresh_queries_per_minute: 30
```

Final values are deployment-specific.

Visible policy states should include `query_too_expensive`, `cardinality_limit_exceeded`, `time_range_too_large`, `refresh_rate_reduced`, `result_truncated`, and `unsupported_dimension`.

The system cannot silently reduce scope in a way that changes analytical meaning.

## 16. Layout Grammar

The Skill Pack arranges panels using a small responsive grammar rather than arbitrary pixels:

- `kpi_strip`;
- `one_column`;
- `two_column`;
- `three_column`;
- `primary_plus_sidebar`;
- `full_width`;
- `tabbed_section`; and
- `detail_table`.

The renderer owns responsive behavior and accessibility.

## 17. Provenance and Data Quality

Every generated panel exposes dashboard plan ID, generated/certified status, template ID/version, metric IDs/versions, variables/filters, source classes, generated-at time, source freshness, row count, truncation/top-N, missing/incomplete/stale state, evidence references where applicable, and limitations.

Suggested states:

- `certified`;
- `generated_validated`;
- `generated_modified`;
- `saved_user_owned`;
- `deprecated`; and
- `invalid`.

A generated dashboard must not visually masquerade as a certified one.

## 18. Empty, Missing, and Error States

The renderer distinguishes measured zero, no qualifying records, unavailable data, stale source, disabled source, query failure, partial data, truncation, removed permission, and unsupported requests.

Zero is never a generic fallback. One failed panel must not blank the whole dashboard.

## 19. Persistence Lifecycle

Generated dashboards are ephemeral by default.

```text
generated
  -> validated
  -> rendered_ephemeral
  -> refined
  -> discarded
       or
  -> save_requested
  -> persistence_validation
  -> saved_user_owned
```

Saving requires explicit user action, name, owner, purpose, tenant/site scope, exact template/metric versions, validation result, persistence policy, and audit record.

AI cannot silently persist, publish, or share a dashboard.

## 20. Template Versioning and Drift

Panel and dashboard templates are protected control artifacts with immutable versions, digests, owners, approval states, evaluation records, active/deprecated state, and rollback versions.

Unapproved digest drift makes the template unavailable to the Skill Pack. Saved dashboards stay pinned until explicitly upgraded.

## 21. Evaluation Requirements

Evaluate plan validity, template selection, metric faithfulness, dimension/aggregation correctness, typed-filter correctness, join correctness, tenant/site isolation, unauthorized-field exposure, hidden-filter rate, hallucinated metric rate, query/cardinality/refresh violations, missing-vs-zero correctness, freshness display, provenance completeness, misleading-visualization checks, accessibility, drilldown context preservation, render success, fallback behavior, save/discard lifecycle, repeated-run variance, and cost separately from correctness.

Hard release blockers include:

- cross-tenant/site leakage;
- raw SQL or executable code reaching execution;
- invented metrics/dimensions/joins accepted by validation;
- unauthorized sensitive fields;
- materially hidden filters;
- missing represented as zero;
- cost/cardinality governor bypass;
- unapproved template execution;
- auto-save without explicit user action; or
- drilldown scope expansion.

## 22. Prompt-Injection and Untrusted Data Tests

Fixtures should place hostile instructions in hostnames, asset names, software names, finding text, external intelligence, case notes, collector labels, and other data fields.

Those strings must not select tools, alter scope, create filters, change refresh cadence, enable persistence, select forbidden templates, add arbitrary destinations, or modify semantic metric definitions.

Protected template/skill metadata is resolved by canonical identity and digest, not mixed into the same trust class as dashboard data.

## 23. Operator Refinement

Operators can perform bounded refinements: add/remove approved panels, change typed variables/time range, switch to a compatible approved visualization, reorder panels, change permitted refresh cadence, request a different approved objective, or explicitly save/pin.

A refinement that requires a new metric, join, permission, or data domain becomes a new authorization/planning request.

## 24. Suggested User Experience

```text
User: Show me what's changed with unknown assets across my three sites this week.

System resolves:
- authorized sites
- time range
- semantic metrics
- approved templates

Skill Pack proposes:
- unknown asset KPI
- unknown assets trend
- new discoveries by site
- identity confidence distribution
- stale/missing evidence table

Validator checks:
- metrics
- filters
- costs
- cardinality
- permissions

Dashboard renders temporarily.
```

Each panel may expose a `Why this panel?` explanation derived from the validated plan rather than hidden model reasoning.

## 25. Implementation Sequence

### Phase 1 - Template and Semantic Contracts

- panel/dashboard template schemas;
- layout grammar;
- semantic metric compatibility metadata;
- typed variables;
- deterministic plan validator;
- fixed templates only.

### Phase 2 - Parameterized Templates

- entity/time/site binding;
- dynamic variables;
- visible filters;
- drilldown context;
- snapshot/polling refresh;
- template versioning/provenance.

### Phase 3 - Dashboard Composition Skill Pack

- approved Skill Pack manifest/instructions;
- AI selection from approved templates;
- schema-constrained plans;
- deterministic validation;
- ephemeral rendering;
- evaluation harness.

### Phase 4 - Broader On-Demand Composition

- panel ranking;
- richer multi-panel composition;
- natural-language refinement within the semantic catalog;
- relationship/investigation views;
- optional streaming panels where runtime support exists.

### Phase 5 - Governed Persistence and Sharing

- user-owned save lifecycle;
- version migration;
- access-controlled sharing/export;
- dashboard usage/quality telemetry.

## 26. Explicit Non-Goals

The design does not approve free-form text-to-SQL, arbitrary model-generated joins, model-defined metrics, arbitrary executable visualization code, unrestricted external data fetching, hidden filters, unrestricted refresh loops, automatic persistence/public sharing, dashboards becoming finding/risk engines, unreviewed third-party dashboard templates, or treating a successfully rendered chart as proof that the analysis is correct.

## Documentation-Only Status

This document defines future architecture. It does not claim that the Skill Pack runtime, semantic dashboard planner, Panel Template Registry, Dashboard Template Catalog, streaming renderer, or persistence workflow is implemented.