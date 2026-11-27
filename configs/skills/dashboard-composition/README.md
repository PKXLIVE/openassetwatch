# Dashboard Composition Skill Pack

Draft version **0.1.0**. Starting commit
`912f59d6d96800108e7cbdc2f1a3956f860b0fc2`. This package owns Milestone C's
canonical contract set. Its manifest has no tool permissions or capabilities.
Draft records are ineligible for execution. The fixtures illustrate the wire
shapes and do not establish runtime availability.

## Contract map

| File | Responsibility |
| --- | --- |
| `skill.yaml`, `instructions.md`, `schemas/skill.schema.json` | Draft manifest, composition guidance, and manifest shape. |
| `input.schema.json` | Bounded, server-issued request with actor and request IDs, an authorization decision reference, tenant and site scope, time context, inherited filters, and eligible catalog pins. |
| `output.schema.json` | Generated proposal or an explicit unsupported result. The proposal selects approved refs, visible variables and filters, slots, refresh, and drilldown action IDs. |
| `schemas/common.schema.json` | Shared types for IDs, versions, digests, time, scope, layout grammar, typed variables and filters, dependency edges, and drilldown context. |
| `schemas/panel-template.schema.json`, `schemas/dashboard-template.schema.json` | Versioned templates, slot compatibility, accessibility, resource bounds, and availability. |
| `schemas/semantic-catalog.schema.json`, `catalog/` | Reviewed-source candidates, scalar metric definitions, and deferred topics. |
| `schemas/panel-data.schema.json`, `schemas/dashboard-view.schema.json` | Product-owned data, quality, provenance, and ephemeral view records. |
| `integrity.json`, `schemas/integrity.schema.json` | SHA-256 digests of exact UTF-8 package files. |
| `examples/`, `evals/` | Synthetic examples and rejection cases for shape and policy review. |

The schemas use JSON Schema Draft 2020-12. Register the package schema files
locally by their `$id` before validating. The URNs are identifiers and do not
resolve through the network. Use date-time format checking. A future loader
must reject duplicate object keys, apply size limits before parsing, confine
artifact paths to the approved package, and compare each pin against an
independently approved registry or release record. A file digest detects drift
from known bytes. It grants no approval. The index covers package content and
excludes itself and Git attributes. Checked-out JSON, YAML, and Markdown use LF.

## Catalog approval and scope binding

A designated OpenAssetWatch maintainer owns catalog approval under the
product's release policy. Domain and API owners review metric semantics and
source mappings. Security reviewers check scope, sensitivity, resource limits,
and drilldown destinations. The product-owned registry records the authorized
approver, approval ID, release pin, approval policy version, reviewed artifact
pins, allowed deployment scope, and decision state, including expiry and
revocation. The Skill Pack has no approval authority.

A release becomes eligible after review, recorded approval, and activation for
the deployment. The server projects only approved and available dashboard
templates, panel templates, and metrics it can use for this request. Every
selected artifact and its required dependencies, including source definitions,
must be in the reviewed release and usable under the request's scope and
deployment policy. The request's `eligible_catalog.approval` references that
decision by `approval_id` and `policy_version` and pins the release by ID,
version, and SHA-256 digest of the immutable release manifest containing the
reviewed member pins. Each listed member has its own exact pin. A null
approval requires all three lists to be empty.

Before issuing the request and again before use, future product code verifies
the release and member bytes against the trusted approval record and checks
the current decision, policy version, availability, and revocation state.
An artifact status or package integrity index by itself has no approval
authority. Changed bytes, dependencies, or capabilities require a new version
and review. Never overwrite an approved version. Missing, expired, or revoked
approval, unknown versions, digest drift, and unavailable dependencies fail
closed.

The product authenticates the actor and derives the tenant, allowed sites,
and data domains from trusted server-side identity, resource membership, and
policy. It binds those decisions, entity and time constraints, and inherited
filters to the request ID, actor, decision ID, policy version, and expiry.
The request carries that scope and an opaque `authorization` reference.
Product code must resolve those IDs against trusted server state and reauthorize
before reads. The fields confer no authority on their own.

Proposal filters and variables can narrow the authorized request only within
its inherited constraints. For drilldowns the server resolves the source plan,
approved action, and destination entity by stable ID. It carries forward the
source tenant, effective filters, and time context and restricts sites and
entities to the intersection of the source scope and the actor's current
authorization. There must be no tenant change, unauthorized target, scope
expansion, or removal of inherited constraints.

The current findings and site risk routes use the shared admin-token check
when configured. That check and the routes' site selectors provide no
actor-to-tenant or actor-to-site binding. The authorization decision record,
approval registry, scope binding, and pre-read enforcement are future product
integration. See the [admin-token check](../../../backend/app/main.py#L430)
and [tool authorization model](../../../docs/ai-security/AI_TOOL_AUTHORIZATION_MODEL.md).

## Source evidence

| Draft metric | Existing read source | Meaning and limits |
| --- | --- | --- |
| `findings.count_by_status` | `GET /api/v1/findings` with one `site_id` and one lifecycle `status`. See the [route](../../../backend/app/main.py#L2637), [response](../../../backend/app/finding_contracts.py#L71), [count query](../../../backend/app/finding_store.py#L803), and [lifecycle writes](../../../backend/app/finding_store.py#L897). | `total` counts the full filtered set of stored findings at read time. Evaluation and lifecycle actions update those rows. Pagination and `truncated` describe the returned items. Display the selected status. The aggregate observation time is `not_provided`. Per-item evidence, evaluation, and update timestamps cannot date the full count. |
| `risk.site_attention_score` | `GET /api/v1/risk/sites/{site_id}`. See the [route](../../../backend/app/main.py#L3368), [response](../../../backend/app/finding_contracts.py#L200), [asset timestamp](../../../backend/app/risk.py#L317), [site calculation](../../../backend/app/risk.py#L436), and [evaluation write](../../../backend/app/finding_service.py#L178). | `score` is the stored integer from 0 to 100. An evaluation writes it and the route reads it without recomputing. `data_as_of` is the latest available observation timestamp among the site's scored assets, using asset `observed_at` with `last_seen_at` as a fallback. It can be null and establishes no coverage guarantee. Preserve it as `observed_as_of`, along with separate `calculated_at`, `retrieved_at`, `formula_version`, and `evaluation_run_id` provenance. Treat absence as a missing measurement once the product has established authorization and confirmed absence. |

Neither source nor current product policy supplies a freshness threshold for
these two metrics. Both draft records use `classification: unknown` and
`threshold_seconds: null`. Successful reads keep panel and source freshness
`unknown`, even when the site score includes an observation timestamp.
Findings counts carry `observed_as_of: null`. Risk scores with no
`data_as_of` also carry null and can still have a calculated value. The
backend's evidence freshness thresholds apply to individual inputs. Formula,
calculation, and retrieval metadata establish neither observation time nor
metric freshness. See the [existing evidence policy](../../../docs/DETERMINISTIC_FINDINGS_AND_RISK.md#operational-attention-score).

Both sources support current snapshots for a single site. The template and
metric bindings are deferred until reviewed and integrated under a server-side
authorization boundary. Catalog definitions create no endpoint, query
implementation, or browser access. [Deferred topics](catalog/deferred.json)
record prerequisites without defining unsupported metrics.

## Deterministic validation

1. Resolve the actor, request, and authorization decision against trusted
   server state. A narrower subset needs explicit, visible selection and must
   answer the stated objective.
2. Verify the Skill Pack pin and its own approval. Resolve dashboard templates,
   panel templates, metrics, and sources by exact version and digest against
   the request's eligible projection and the current catalog approval.
3. Check unique section, slot, panel, variable, and binding IDs by key. Validate
   layout ordering, declared slots and occupancy, exact per-slot metric pins,
   allowed variants, data shapes, metrics, dimensions, aggregations, and
   permitted refresh modes. V1 metrics are direct scalar reads with no joins.
   Enforce request, catalog, and deployment query and cardinality budgets
   before executing a read. Here both example sources allow snapshot only.
4. Apply required and inherited filters, accepting only typed values within
   authorized scope. A variable with a filter dimension must match the typed
   value of each corresponding effective filter in its dashboard. Verify that
   deterministic dependencies form an acyclic graph. The reference rule restricts asset
   choices to the authorized selected sites. Evaluate parents first and
   revalidate child selections when parents change. Scope and effective
   material filters are inspectable, including per-panel filters. Reject
   unsupported, contradictory, invisible, or omitted required filters.
   V1 site IDs use the bounded canonical grammar in the hub contracts. Sites
   enrolled through a broader input path need an authorized canonical ID before
   use in this catalog. Check time ordering and size in product code. A snapshot
   metric cannot answer a historical request without an explicit, compatible source.
5. Accept only approved drilldown actions for the selected metric and panel.
   The product constructs drilldown context with stable entity and source IDs,
   narrowed authorized scope, effective filters, and the inherited time
   context. Product routes resolve destination selectors. Labels and
   objectives remain untrusted text.
6. Generate queries, authorize reads, and produce render data in product
   code. Source results use separate completeness and freshness. For example,
   a complete measured count of zero is ready, an empty record set is empty,
   and a missing measurement has no value. Stale values retain the original
   measurement time when known. Partial results expose truncation or
   incomplete coverage. Unavailable and error results lack a measurement.
   Row count describes rendered rows. A scalar carries one row, including a
   measured zero. A table carries its exact row length. Unavailable data
   carries no measured row count. Never infer freshness from retrieval time.
   The product supplies actual provenance, timestamps, formula versions, scope, and evidence
   references before render. An unreadable source affects its own panel.
7. Validate dashboard expiry and assign view and plan IDs in product code.
   Show the generated origin for validated and modified views. This contract
   covers ephemeral views. Saving, sharing, certification, and execution
   require independent product workflows and authorization.

## Fixture use

The request examples use synthetic authorization IDs and an empty eligible
catalog with null approval because every bundled artifact is draft. The
unsupported fixture is the matching valid outcome at this stage. The plan,
drilldown, and view fixtures illustrate structurally
valid payloads for future integration and are ineligible for runtime use. The
zero, missing, and stored score fixtures illustrate measurement outcomes for
the same view. The score fixture preserves three distinct timestamps and
unknown freshness. Validate the variable graph example by checking its
variables and dependencies against the shared definitions and checking the
graph separately.

The shape cases in `evals/cases.json` mutate a base fixture with JSON Patch
`add` semantics and must fail schema validation. Semantic cases identify
deterministic checks the future product code must perform after schema
validation. Cases that isolate another policy rule assume the earlier draft
approval gate is satisfied in the evaluation harness. No fixture can grant
approval to the draft files.

## Design authorities

[ADR-0008](../../../docs/architecture/decisions/0008-dynamic-dashboard-composition.md) ·
[Dashboard composition](../../../docs/architecture/dashboard-composition-skill-pack.md) ·
[Skill Pack contract](../../../docs/architecture/skill-pack-contract.md) ·
[Artifact integrity and trust](../../../docs/ai-security/AI_AGENT_SUPPLY_CHAIN_SECURITY.md)
