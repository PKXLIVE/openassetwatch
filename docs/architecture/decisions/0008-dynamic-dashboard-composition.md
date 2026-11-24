# ADR-0008: Governed Dynamic Dashboard Composition

- **Status:** Accepted
- **Date:** 2026-08-28

## Context

OpenAssetWatch already has an accepted direction for AI-generated drilldown dashboards: AI may select and arrange approved analytical components, while semantic metrics, query generation, authorization, cost limits, validation, provenance, and persistence remain deterministic product responsibilities.

The platform also has a native Skill Pack contract. What remained missing was a concrete bridge between those two designs: a first-party Skill Pack that can build dashboards on demand from a governed library of panel and dashboard templates instead of improvising visualization structures, raw queries, or executable code.

Real-time and historical monitoring introduce additional requirements around refresh cadence, variable-driven filtering, drilldown context, missing/stale states, query cost, cardinality, and panel-level failure isolation.

## Decision

OpenAssetWatch accepts a future **Dashboard Composition Skill Pack** backed by:

- a versioned **Panel Template Registry**;
- a versioned **Dashboard Template Catalog**;
- a governed semantic metric/data catalog;
- typed visible dashboard variables and deterministic dependencies;
- a strict declarative Dashboard Plan contract;
- deterministic plan validation;
- canonical server-side query generation;
- query, cardinality, concurrency, and refresh governors;
- snapshot, bounded polling, and approved stream refresh modes;
- safe drilldown context preservation using stable IDs;
- explicit generated-versus-certified provenance; and
- ephemeral-by-default dashboard lifecycle with explicit save/persist actions.

The Skill Pack may choose and parameterize approved templates. It cannot grant permissions, emit raw SQL, invent metrics/joins/dimensions, execute arbitrary visualization code, create hidden filters, widen scope, bypass resource policy, or save/share a dashboard without explicit product authorization and user action.

## Authority Boundary

```text
operator objective
  -> authenticated dashboard request context
  -> deterministic scope resolution
  -> Dashboard Composition Skill Pack proposal
  -> deterministic template/semantic/policy validation
  -> canonical query generation
  -> bounded rendering
  -> ephemeral analytical dashboard
  -> explicit user save if desired
```

AI controls proposal/composition only. Product code controls execution and persistence.

## Template Model

Panel templates define approved visualization families, semantic requirements, variable bindings, refresh policy, query/cardinality limits, missingness semantics, provenance requirements, sensitivity ceilings, drilldowns, accessibility metadata, versions, and digests.

Dashboard templates define analytical intent, typed variables, layout slots, permitted panel families, panel count limits, and responsive layout grammar.

Templates are protected control artifacts. Unapproved digest drift removes a template from Skill Pack eligibility until review completes.

## Real-Time Model

Three refresh classes are accepted:

- `snapshot` for one bounded render query;
- `polling` for governed periodic refresh; and
- `stream` only where an approved runtime/data source provides a bounded event stream.

A Skill Pack may select only supported modes and cannot manufacture a streaming source. Refresh rate remains subject to per-panel floors and dashboard/tenant budgets.

## Safety Invariants

- Raw database schema is not the model's primary planning surface.
- Raw SQL and executable chart code do not originate from the Skill Pack.
- Every effective filter is typed and inspectable.
- Stable IDs, not display text, drive drilldowns and scope.
- Missing/unavailable data is never silently rendered as measured zero.
- One panel failure does not invalidate or blank unrelated panels.
- Generated dashboards are visibly distinct from certified dashboards.
- Dynamic dashboard composition cannot create or modify findings, risk, asset identity, or other authoritative state.
- Generated dashboards are ephemeral by default.
- Saving requires explicit user intent, ownership, scope, exact template/metric versions, validation, and audit.
- Untrusted data strings cannot alter templates, metrics, filters, refresh, persistence, or tool selection.

## Initial Template Families

The initial panel library should focus on metric summaries, time series, ranked bars, low-cardinality composition, tables, heatmaps/matrices, timelines, health/status matrices, bounded relationship views, and provenance/data-quality panels.

The initial dashboard library should focus on Environment Command Center, Asset Deep Dive, Vulnerability Context, Collector and Sensor Operations, Findings and Attention, Environment Trends, Security Intelligence Watch, and Investigation Workspace.

## Evaluation

Release evaluation must cover template and metric faithfulness, typed-filter correctness, join restrictions, tenant/site isolation, hidden filters, hallucinated metrics/dimensions/joins, query/cardinality/refresh policy, missing-vs-zero semantics, provenance, freshness, misleading visualization patterns, accessibility, drilldown scope, render failure isolation, persistence lifecycle, prompt injection through source data, and repeated-run variance.

Hard blockers include cross-scope data leakage, raw SQL or executable code reaching execution, invented semantic objects accepted by validation, unauthorized sensitive fields, hidden material filters, cost/cardinality governor bypass, unapproved template execution, auto-save, and scope-expanding drilldowns.

## Implementation Sequence

1. Define panel/dashboard template schemas, layout grammar, semantic compatibility metadata, typed variables, and deterministic validators.
2. Implement fixed and parameterized templates with visible filters and bounded snapshot/polling refresh.
3. Add the Dashboard Composition Skill Pack with strict plan output and ephemeral rendering.
4. Expand composition/refinement and safe drilldowns; add streaming panels only where runtime support is approved.
5. Add governed persistence, sharing/export, version migration, and quality telemetry.

## Rejected Alternatives

OpenAssetWatch will not use free-form text-to-SQL, AI-invented joins or metrics, arbitrary executable visualization code, hidden model-generated filters, unrestricted refresh loops, automatic persistent dashboard creation, automatic public sharing, or unreviewed third-party template imports as production defaults.

## Consequences

### Positive

- On-demand dashboards become faster and more consistent because the agent composes from known building blocks.
- Template reuse improves safety, visual consistency, evaluation, accessibility, and performance predictability.
- Real-time and historical panels share explicit refresh/freshness contracts.
- Users retain control over persistence and scope.

### Cost

- OpenAssetWatch must maintain semantic metric metadata, template schemas, versions, evaluation fixtures, plan validation, and query/resource governance.
- Template coverage must grow deliberately to support new analytical intents.
- Saved generated dashboards require version-pinning and migration policy.

## Implementation Status

Architecture direction only. No Dashboard Composition Skill Pack runtime, template registry, semantic dashboard planner, dynamic query engine, stream renderer, or generated-dashboard persistence workflow is implemented by this ADR.