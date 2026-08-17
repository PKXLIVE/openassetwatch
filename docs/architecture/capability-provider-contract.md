# Capability and Provider Contract

- **Status:** Accepted design; not yet implemented as a general runtime
- **Decision:** `docs/architecture/decisions/0003-native-agent-investigation-and-temporal-intelligence.md`

## Purpose

OpenAssetWatch needs a stable way to add optional analytical capabilities and
replaceable provider implementations without allowing an external runtime,
model, connector, or plugin to become the product's authority.

This contract separates two concepts:

- a **capability** is an OpenAssetWatch-owned product contract describing an
  allowed outcome; and
- a **provider** is one implementation of that capability.

The distinction keeps product behavior stable when a provider is changed,
disabled, unavailable, local, or hosted.

## Core rule

```text
OpenAssetWatch owns capability meaning, scope, policy, schemas, and validation.
Providers execute a bounded implementation and return untrusted results.
```

A provider does not define what OpenAssetWatch is allowed to do.

## Deterministic core is not replaceable

The following remain privileged product responsibilities rather than general
provider extension points:

- collector and sensor authentication;
- normalized evidence ingestion;
- tenant/site scope enforcement;
- authoritative asset identity;
- classification evidence persistence;
- software/firmware normalization;
- vulnerability applicability/matching;
- deterministic finding lifecycle;
- Operational Attention Score calculation;
- suppression/risk-acceptance governance;
- authorization and human approval policy;
- audit integrity; and
- accepted state transitions.

Optional capabilities may read or propose against these records but cannot
replace their ownership.

## Capability definition

A capability definition should include at least:

- stable `capability_id`;
- version;
- description of the caller-visible outcome;
- input schema;
- output schema;
- side-effect classification;
- required product permissions;
- required evidence types;
- allowed scope types;
- maximum data volume;
- privacy classification;
- human-approval requirement;
- validation rules;
- provider compatibility requirements;
- timeout/budget rules; and
- audit requirements.

Example capability families:

- `investigation.asset_identity_review`
- `investigation.vulnerability_review`
- `investigation.data_quality_review`
- `investigation.verify_hypothesis`
- `report.compose_investigation`
- `temporal.expected_range`
- `temporal.deviation_review`

Capability IDs are product vocabulary. They should not contain vendor or model
names.

## Provider definition

A provider definition should contain implementation metadata rather than
product authority:

- stable `provider_id`;
- provider type such as `deterministic`, `local_model`, or `hosted_model`;
- supported capability IDs and versions;
- runtime endpoint/adapter identity;
- health-check method;
- maximum request/response size;
- timeout and concurrency limits;
- external-processing classification;
- credential reference requirements;
- sensitive-data handling policy;
- supported cancellation/resume behavior;
- adapter version; and
- evaluation status.

Credentials remain runtime secrets. Provider metadata may reference secret
identifiers but must not contain secret values.

## Capability binding

A deployment binds an approved provider to a capability through explicit
configuration.

Conceptually:

```text
capability contract
       |
       v
policy + tenant/site + user authorization
       |
       v
approved provider binding
       |
       v
bounded provider request
       |
       v
strict output validation
       |
       v
OpenAssetWatch advisory artifact
```

The binding must fail closed when the provider is disabled, unhealthy,
unapproved for the capability, or inconsistent with deployment privacy policy.

## Provider result trust

All provider output is untrusted until OpenAssetWatch validates it.

Validation should include:

- JSON/schema validation;
- output byte/record limits;
- evidence-ID allowlist validation;
- entity scope validation;
- known enum/state validation;
- unsupported-field rejection;
- secret/control-character filtering where relevant;
- confidence ceilings based on evidence quality;
- prohibited action/state-change checks; and
- provider/capability version compatibility.

A valid schema does not prove a conclusion is correct. Investigation and
verification gates still apply.

## Provider-facing data projection

Providers receive a bounded projection, not database or filesystem access.

The projection should be constructed by OpenAssetWatch after authorization and
redaction. It may include:

- stable task/run IDs;
- objective;
- evidence cards;
- permitted entity metadata;
- product facts already authoritative;
- Skill Pack instructions;
- output schema; and
- bounded policy reminders.

It must exclude unrelated tenant/site data, secrets, credentials, raw packet
payloads, arbitrary filesystem content, raw SQL, authorization headers, and
unrestricted URLs or targets.

## Local and hosted provider policy

Provider placement is a deployment policy decision.

OpenAssetWatch should distinguish:

- `local_only`
- `external_allowed`
- `external_required` only for a capability that cannot operate locally and is
  explicitly enabled by the operator

The preferred default for current AI behavior remains local/deterministic where
possible.

A local provider failure must never silently cause the same data to be sent to a
hosted provider. Crossing a privacy boundary requires explicit configuration,
not automatic failover.

## Fallback behavior

Fallback is allowed only when all candidates are already approved inside the
same trust/data-sharing boundary.

Examples:

- deterministic local implementation -> another local implementation may be
  allowed if configured;
- local model -> hosted model is not an implicit fallback;
- external provider A -> external provider B is not an implicit fallback if
  their privacy, region, or contract classification differs.

When no approved provider remains, the capability returns `unavailable` or a
bounded deterministic fallback result rather than expanding its own authority.

## Side-effect classification

Initial capability classes should be:

- `read_only`
- `artifact_only` — creates an internal report/investigation artifact but does
  not contact or modify an external system
- `approval_required` — reserved for future explicitly reviewed workflows
- `prohibited`

Agent-investigation and temporal-intelligence capabilities start as
`read_only` or `artifact_only`.

A provider cannot reclassify a capability's side-effect level.

## Tool execution boundary

Providers do not receive direct tool execution permission. The OpenAssetWatch
coordinator decides when a bounded tool is called and validates its inputs and
outputs through the existing gateway.

A model/provider may request a tool only through an OpenAssetWatch-controlled
request object. The gateway may deny the request regardless of provider output.

Tool descriptions supplied by a provider are not trusted configuration.

## Provider health and observability

Each provider binding should expose bounded operational status:

- configured/enabled state;
- local versus external mode;
- supported capability versions;
- last successful health check;
- latency/error counters;
- timeout/cancellation counters;
- current concurrency/budget status; and
- last evaluation version.

Status surfaces must not reveal API keys, authorization headers, hidden prompts,
or unrestricted endpoint details to users who lack administrative access.

## Audit requirements

Every capability execution should be attributable to:

- caller/user or system trigger;
- tenant/site/scope;
- capability ID/version;
- provider ID/adapter version;
- Skill Pack ID/version when applicable;
- evidence IDs supplied;
- tool IDs used;
- start/end timestamps;
- outcome/status;
- validation result; and
- human approval when required.

This audit record is distinct from provider telemetry.

## Provider telemetry boundary

OpenAssetWatch should not assume provider tracing is safe to enable with raw
inputs and outputs. Product-owned auditability must work independently.

If provider tracing is enabled, the deployment must decide:

- whether content is included;
- whether data leaves the deployment;
- retention period;
- tenant/site identifiers exposed;
- secret redaction; and
- whether the trace can be linked back to an OpenAssetWatch run without
  becoming the source of truth.

## Provider cancellation and recovery

The capability runtime should support deterministic cancellation even when a
provider has limited cancellation support.

On cancel:

- no new tools are dispatched;
- late provider output is ignored or stored only as rejected diagnostic data;
- investigation state records the cancellation;
- provider billing/usage metadata may still be recorded if already incurred;
- resume requires a new validated task transition.

Long-running resumability should be implemented in OpenAssetWatch control state,
not assumed from provider session memory.

## Compatibility and versioning

Capabilities and providers are versioned independently.

A provider adapter should declare the exact capability contract versions it
supports. An incompatible binding fails at configuration/startup rather than
attempting best-effort field guessing.

Schema migrations must preserve historical investigation records and their
original capability/provider versions.

## Initial provider classes

### Deterministic provider

Used for fixtures, demonstrations, simple structured analyses, and safe fallback
behavior. It makes no model call and should remain available for core evaluation
and offline operation.

### Local model provider

Calls an explicitly configured local model endpoint through a bounded adapter.
Local transport rules, response validation, and resource limits remain product
controlled.

### Hosted model provider

Available only when external processing is deliberately enabled. It receives
only the provider-facing projection allowed by deployment policy.

## Future non-AI analytical providers

The same capability boundary may be used for optional analytical engines such
as temporal forecasting, provided their results are still validated and
advisory. This avoids creating a separate authority model for every analytical
library.

## Release requirements

A new provider adapter cannot be enabled for a capability until it has:

1. strict schema support;
2. timeout/cancellation behavior;
3. size limits;
4. secret/redaction review;
5. privacy classification;
6. scope/evidence validation tests;
7. malformed-output tests;
8. provider-failure tests;
9. adversarial-content tests where a model sees untrusted evidence;
10. repeated-run evaluation for non-deterministic behavior; and
11. explicit operator configuration.

## Explicit non-goals

This contract does not create a general plugin marketplace, make every core
subsystem replaceable, permit provider-supplied executable code, grant providers
network-scanning authority, allow dynamic permission creation, or make external
provider services mandatory for OpenAssetWatch operation.

## Documentation-only status

This document defines a native extension boundary. The current AI provider
interface remains the implemented runtime until a future workstream implements
this broader contract.