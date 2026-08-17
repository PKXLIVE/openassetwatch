# AI-Generated Security Drilldown Dashboards

## Status

Independent research input. Not an implementation commitment.

## Core conclusion

A security and asset-intelligence platform can safely create temporary, context-specific drilldown dashboards when the AI is limited to selecting and arranging approved analytical components. The safe boundary ends before free-form SQL, invented joins, arbitrary scripts, or executable visualization code.

The recommended pattern is:

```text
trusted click context
  -> approved semantic catalog
  -> AI dashboard-plan proposal
  -> deterministic schema and policy validation
  -> canonical query generation by the semantic layer
  -> query cost and cardinality enforcement
  -> temporary dashboard with provenance
  -> explicit user approval before save
```

Generated dashboards should be temporary by default. Saving should be an explicit, named, owned, and audited action.

## Maturity by pattern

### Mature and safe baseline

- Fixed drilldown templates.
- Parameterized templates using typed filters and stable entity IDs.
- Rule- and constraint-based visualization recommendation.
- Declarative visualization grammars such as Vega-Lite.
- Approved semantic measures and dimensions.

### Strong next step

- AI selection and ranking from an approved panel library.
- AI composition from approved measures, dimensions, filters, and chart types.
- Schema-constrained declarative visualization plans.

### Guarded analyst-only capability

- Human-reviewed query authoring behind deterministic policy and cost controls.

### Rejected for unattended use

- Free-form text-to-SQL.
- AI-invented joins or metrics.
- Arbitrary Python, JavaScript, or visualization code.
- Fully free-form persistent dashboard creation.

## Why unrestricted query generation is unsafe

Research on enterprise-oriented text-to-SQL shows a substantial accuracy collapse compared with simpler academic benchmarks. Silent wrong answers are more dangerous than visible query errors because users may trust an incorrect number.

Security-specific risks include:

- cross-tenant data leakage;
- unauthorized column access;
- hidden or inherited filters;
- incorrect joins;
- invented metrics;
- unbounded scans;
- high-cardinality explosions;
- excessive query cost;
- prompt injection through asset names, hostnames, logs, or feed content; and
- charts that render successfully while communicating a false conclusion.

## Safe architecture pattern

### 1. Trusted drilldown context

A click should produce a bounded context containing:

- stable entity type and entity ID;
- tenant and site;
- invoking user and resolved permissions;
- time range;
- active filters;
- source panel and source query;
- clicked dimension value;
- allowed data domains; and
- reason for the drilldown.

Use stable IDs rather than fuzzy matching on display names. Asset names, hostnames, and labels are untrusted content and must not become executable predicates.

### 2. Semantic layer

The AI should see a governed catalog rather than raw database structure.

The catalog should contain:

- canonical measure IDs;
- dimensions;
- entities;
- allowed join paths;
- data types and units;
- descriptions and synonyms;
- freshness metadata;
- sensitivity tags;
- row and column security;
- permitted aggregations;
- maximum cardinality; and
- approved visualization templates.

Metric definitions should be versioned and reviewed. The semantic layer, not the AI, produces canonical queries.

### 3. Dashboard-plan proposal

The AI may propose:

- questions to answer;
- approved panels to include;
- measure and dimension references;
- approved filters;
- chart type;
- layout;
- plain-language titles;
- evidence panels;
- confidence and freshness displays; and
- safe follow-up pivots.

It must not emit raw SQL, executable code, free-text predicates, or unknown fields.

### 4. Deterministic validation

Validate:

- plan schema;
- entity scope;
- tenant and user authorization;
- measure and dimension existence;
- join-path allowlist;
- row and column security;
- chart-type allowlist;
- aggregation correctness;
- filter type and binding;
- freshness requirements;
- query cost;
- row limits;
- group-by cardinality;
- sensitive-field handling;
- rendering constraints; and
- lifecycle state.

If the plan fails validation, is too expensive, has excessive cardinality, or has low confidence, fall back to a fixed or parameterized template.

### 5. Temporary rendering

Generated workspaces should be read-only and ephemeral by default. No schema, data, or canonical dashboard changes occur during generation.

The user may:

- inspect;
- refine using approved operations;
- discard;
- export where authorized; or
- explicitly save with name, owner, purpose, and governance metadata.

## Dashboard-plan conceptual requirements

### Context

- entity type and stable ID;
- tenant and site;
- user scope;
- timestamp;
- source panel;
- source query;
- requested analytical objective.

### Filters

- explicit typed filters only;
- source: user, system, or inherited click;
- no hidden free-text predicate;
- stable dimension IDs;
- visible filter chips in the UI.

### Panels

- approved metric or measure ID;
- approved dimensions;
- approved join path;
- approved aggregation;
- vetted panel template or schema-valid declarative visual encoding;
- title and question answered;
- evidence references;
- uncertainty handling.

### Provenance

- measure definition and version;
- source query ID;
- filters;
- data freshness;
- row count;
- cardinality;
- top-N or truncation notice;
- generated-versus-certified status.

### Safety envelope

- maximum rows;
- maximum query time or cost;
- maximum series and categories;
- approved chart types;
- sensitivity level;
- save policy;
- expiration.

## Security controls

- Enforce tenant scope server-side.
- Use both row-level and column/object-level security.
- Treat all collected data as untrusted.
- Bind parameters rather than interpolating strings.
- Prevent private-network or external callbacks from visualization specs.
- Disallow scripts, plugins, expressions, and unknown marks.
- Apply query governors and timeouts.
- Limit high-cardinality dimensions.
- Log plan, validation, query, result metadata, and save/discard outcome.
- Distinguish AI-composed panels from certified panels.
- Require explicit approval before persistence.

## Evidence-first user experience

Every panel should explain:

- why it was selected;
- which question it answers;
- metric definition;
- source and freshness;
- filters;
- confidence;
- whether data is incomplete;
- whether results are top-N or truncated; and
- known limitations.

Do not render an empty chart in a way that implies zero when the result is unknown or unavailable.

Use safe visualization defaults:

- avoid truncated axes unless clearly justified;
- avoid dual axes by default;
- avoid inverted scales;
- prevent aggregation over identifiers;
- prevent high-cardinality labels;
- disclose top-N truncation; and
- distinguish correlation from causation.

## Example drilldowns

### Asset

- identity and confidence;
- evidence timeline;
- operating system, software, and firmware;
- open services;
- vulnerability and lifecycle context;
- exposure;
- related assets and network relationships;
- risk factors;
- recommended evidence-gathering and remediation steps.

### Vulnerability

- affected assets by confidence;
- KEV and EPSS;
- exposure distribution;
- asset importance;
- remediation status;
- verification tier;
- exception and VEX state;
- historical priority changes.

### Unknown assets

- discovery time;
- site and segment;
- evidence-signal distribution;
- identity-confidence bands;
- possible classes;
- missing evidence;
- changes in identifiers;
- recommended next evidence source.

### Collector or sensor

- health;
- check-ins;
- evidence volume;
- site coverage;
- freshness;
- affected assets;
- gaps and failures;
- configuration or enrollment state.

### Risk factor

- factor definition;
- assets affected;
- evidence source;
- how the factor influences action priority;
- stale or missing evidence;
- actions that would reduce the factor.

## Phased delivery

### Crawl

- fixed and parameterized drilldowns;
- semantic metrics catalog;
- stable entity IDs;
- permissions;
- provenance;
- query governors;
- audit;
- template coverage for common intents.

### Walk

- AI selection from approved panels;
- AI composition from approved metrics and dimensions;
- schema-constrained dashboard plans;
- temporary-only generated dashboards;
- deterministic validation;
- evaluation instrumentation.

### Run

- broader multi-panel composition;
- natural-language refinement within the approved semantic catalog;
- optional human-reviewed query authoring for advanced analysts;
- continued temporary-by-default behavior.

## Evaluation

Measure:

- plan validity;
- render success;
- metric faithfulness;
- filter and join correctness;
- hallucinated-field rate;
- cost and cardinality policy violations;
- cross-tenant leakage;
- sensitive-field exposure;
- chart appropriateness;
- misleading-visualization rate;
- provenance completeness;
- freshness display;
- user task success;
- trust calibration;
- save/discard behavior;
- dashboard sprawl;
- latency; and
- generation cost.

Release-blocking failures include cross-tenant leakage, unauthorized fields, a hallucinated metric that changes a number, or bypass of cost/cardinality policy.

## Rejected patterns

- Free-form SQL from prompts containing untrusted data.
- AI-invented measures, dimensions, joins, or filters.
- Auto-saving generated dashboards.
- Charts without provenance, filters, or freshness.
- Unbounded query execution.
- Executable visualization code.
- Prompt-only security controls.
- Hidden filters.
- Misleading axis defaults.

## Research conclusion

The difficult and valuable engineering is the semantic layer, approved panel catalog, policy engine, query governor, provenance model, and evaluation framework. The AI planner is a bounded user-experience layer over that foundation.
