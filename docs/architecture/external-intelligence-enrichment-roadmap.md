# External Intelligence Enrichment Roadmap

- **Status:** Accepted design expansion; implementation remains phased
- **Date:** 2026-08-05
- **Decision:** `docs/architecture/decisions/0002-additive-external-intelligence-enrichment.md`
- **Source governance:** `docs/SOURCE_LICENSING_REGISTRY.md`

## Purpose

This roadmap defines how OpenAssetWatch may add public-record, certificate,
Internet-exposure, passive-DNS, web-observation, and analyst-investigation
context to the capabilities that already exist.

This is an **additive expansion**. It does not replace or redirect the current
OpenAssetWatch architecture, collectors, passive sensor, asset model,
classification engine, evidence-fusion rules, deterministic findings and risk,
AI Advisor, local-first operation, or product identity.

The existing authority order remains unchanged:

```text
authenticated normalized OpenAssetWatch evidence
  -> deterministic classification and matching
  -> deterministic findings and attention scoring
  -> bounded read-only AI explanation
  -> human review
```

External intelligence may add observations, relationships, historical context,
and candidate findings. It does not become an authoritative inventory, identity
oracle, vulnerability confirmation, finding, score, decision, or action.

## Additive Architecture Invariant

Every external source and every capability inspired by an external project must
pass all of these tests:

1. It fills a documented OpenAssetWatch coverage gap.
2. It integrates through existing evidence and normalization boundaries.
3. It does not replace local collectors, passive sensors, or customer evidence.
4. OpenAssetWatch remains useful and operational when the source is unavailable,
   disabled, rate-limited, retired, or not licensed.
5. The integration is optional unless the capability is implemented from
   product-owned or clearly approved public material.
6. It preserves passive-first, authorized-use, evidence-first, and human-review
   requirements.
7. It does not turn OpenAssetWatch into a general people-search, credential
   collection, offensive scanning, exploitation, or data-resale platform.
8. It does not bypass the Source Licensing Registry or provider terms.

A source that fails any of these tests is rejected, deferred, or limited to
research/design inspiration.

## Relationship to Existing OpenAssetWatch Capabilities

The enrichment module sits beside existing spokes and feeds the same controlled
hub pipeline:

```text
Endpoint collectors ───────┐
Passive network sensors ───┼──> existing normalization and evidence fusion
Approved local connectors ─┤                 │
                           │                 ├──> deterministic classification
Optional external          │                 ├──> findings and attention score
intelligence adapters ─────┘                 ├──> history and relationships
                                             └──> bounded AI Advisor explanation
```

External observations must map to an existing OpenAssetWatch asset when the
evidence supports that relationship. When they cannot be safely mapped, they
remain separate candidate entities or hypotheses. They must not silently create,
merge, split, or reclassify authoritative asset records.

## Target Capability: External Intelligence Enrichment Module

The proposed module is a provider-neutral enrichment capability with six
bounded responsibilities:

1. **Scope governance** — determine what domains, public IPs, CIDRs, ASNs, and
   cloud identifiers are authorized for recurring enrichment.
2. **Read-only acquisition** — query approved public records or existing
   provider observations without active probing by OpenAssetWatch.
3. **Normalization** — convert source-specific records into a common observation
   envelope while retaining complete provenance.
4. **Correlation** — propose relationships to known assets without overriding
   existing identity or classification decisions.
5. **Evidence fusion** — corroborate, conflict, expire, or supersede external
   observations using the existing source-aware evidence model.
6. **Presentation** — expose source, freshness, confidence, limitations, and
   verification status to deterministic rules, dashboards, and the AI Advisor.

The module is not a replacement asset database and is not a standalone external
attack-surface product inside OpenAssetWatch.

## Scope Registry

Recurring external enrichment must operate only on a verified scope registry.
Manual analyst lookups may be allowed outside recurring scope only when they are
read-only, policy-approved, and clearly separated from managed customer scope.

Suggested scope fields:

```text
scope_id
tenant_id
site_id
scope_type              # root_domain, fqdn, public_ip, cidr, asn, cloud_id
scope_value
ownership_status        # proposed, verified, expired, rejected
verification_method
verification_evidence_id
approved_by
approved_at
expires_at
allowed_capabilities
blocked_providers
retention_policy
created_at
updated_at
```

Verification methods may eventually include DNS challenge, approved file
challenge, cloud-account linkage, customer attestation, contract inventory, or
an authorized administrator decision. A certificate name, WHOIS record, public
DNS result, or provider association alone must not prove current ownership.

## Provider-Neutral Observation Envelope

External data should extend the existing evidence contracts rather than create a
parallel source of truth. A normalized envelope may include:

```json
{
  "schema": "oaw.external_observation.v1",
  "observation_id": "uuid",
  "tenant_id": "tenant-or-null",
  "site_id": "site-or-null",
  "scope_id": "verified-scope-id",
  "provider_id": "provider-neutral-id",
  "provider_record_id": "source-record-id-or-null",
  "collection_mode": "public_record_lookup",
  "subject": {
    "type": "domain",
    "value": "example.com"
  },
  "predicate": "resolves_to",
  "object": {
    "type": "ip_address",
    "value": "203.0.113.10"
  },
  "observed_at": "2026-08-05T00:00:00Z",
  "retrieved_at": "2026-08-05T00:05:00Z",
  "first_seen": "2026-07-01T00:00:00Z",
  "last_seen": "2026-08-05T00:00:00Z",
  "freshness_state": "current",
  "confidence": 0.72,
  "verification_state": "externally_observed",
  "historical": false,
  "source_url": "provider-record-reference",
  "evidence_hash": "sha256:...",
  "license_profile_id": "provider-license-profile",
  "requires_verification": true,
  "raw_payload_retained": false
}
```

The final schema should reuse existing OpenAssetWatch evidence identifiers,
source metadata, timestamps, confidence vocabulary, and conflict handling where
possible. This example is a design target, not an implemented contract.

## Allowed Collection Capabilities

Adapters must declare capabilities. The initial allowlist is intentionally
read-only:

- `PUBLIC_RECORD_QUERY`
- `CERTIFICATE_TRANSPARENCY_LOOKUP`
- `PASSIVE_DNS_LOOKUP`
- `EXISTING_PROVIDER_OBSERVATION_LOOKUP`
- `DOMAIN_RELATIONSHIP_LOOKUP`
- `IP_RELATIONSHIP_LOOKUP`
- `CERTIFICATE_LOOKUP`
- `WHOIS_OR_REGISTRATION_LOOKUP`
- `USER_CONTROLLED_IMPORT`
- `MANUAL_INVESTIGATION_LAUNCHER`

The adapter interface must not expose a generic `scan_target`, `run_probe`,
`test_credentials`, `exploit`, `crawl_internal_url`, or arbitrary-request
method. Provider products may offer those functions, but their existence does
not authorize OpenAssetWatch to call them.

Any later safe-active capability remains governed by the separate IoT/OT and
active-query controls in ADR-0001 and requires its own accepted design.

## Asset and Evidence Relationship Graph

External enrichment can add a relationship view without replacing relational
records or deterministic identity. Supported relationship candidates may
include:

```text
domain       -> resolves_to       -> IP address
domain       -> redirects_to      -> domain
domain       -> loads_from        -> domain
hostname     -> covered_by        -> certificate
certificate  -> names             -> hostname
IP address   -> announced_by      -> ASN
IP address   -> exposes           -> observed service
service      -> identified_as     -> product hypothesis
product      -> potentially_maps  -> vulnerability candidate
domain       -> registered_by     -> registration observation
asset        -> corroborated_by   -> external observation
```

Every node and edge must retain source, time, scope, evidence, confidence,
historical/current state, and verification status. Relationship traversal must
not convert correlation into proof. Weak transitive paths must not trigger
asset merges.

A graph store is optional. The authoritative records remain the product-owned
relational evidence model. A graph projection, search index, or vector store may
support investigation but must not become the system of record.

## Observation and Finding Lifecycle

External evidence requires an explicit lifecycle:

```text
collected
  -> normalized
  -> scope_checked
  -> externally_observed
  -> corroborated or conflicted
  -> candidate_entity or candidate_finding
  -> verified or rejected
  -> expired or superseded
```

Recommended user-facing states:

| State | Meaning |
| --- | --- |
| `externally_observed` | A third party or public record reported the condition. |
| `corroborated` | At least one independent source supports the observation. |
| `candidate` | The evidence may justify review but is not a confirmed finding. |
| `verified` | Authorized OpenAssetWatch or human evidence confirmed it. |
| `conflicted` | Credible evidence disagrees and the disagreement is preserved. |
| `rejected` | Review determined the observation does not apply. |
| `expired` | The record is too old for its configured freshness policy. |
| `superseded` | A newer observation replaced it while retaining history. |

Examples:

```text
CT certificate entry
  -> candidate hostname
  -> passive DNS corroboration
  -> externally observed service
  -> authorized local or connector evidence
  -> verified asset relationship
```

```text
Provider banner identifies product version
  -> product/version hypothesis
  -> independent evidence comparison
  -> candidate vulnerability match
  -> deterministic matcher plus verified version evidence
  -> confirmed finding
```

A certificate entry does not prove a hostname is currently reachable. A service
banner does not prove a product identity. A CPE or version string does not prove
vulnerability applicability. Missing provider data remains unknown, not safe.

## Source-by-Source Design Disposition

The following dispositions define architecture intent only. Production access,
caching, commercial use, and redistribution remain blocked until the Source
Licensing Registry approves the exact use.

### Exploratores

**Useful patterns:**

- input-type-to-provider registry;
- analyst investigation launcher;
- locally managed tool catalog;
- local redaction before external sharing;
- clear distinction between search results and verified facts.

**OpenAssetWatch treatment:**

- independently implement compatible product-owned patterns;
- do not copy source code, branding, content catalogs, or bundled provider lists
  without a completed license and provenance review;
- keep people-search and unrelated personal OSINT outside the product scope;
- use it as workflow inspiration, not as a runtime dependency.

### Certificate Transparency and crt.sh

**Useful capability:**

- discover certificate and precertificate names associated with verified root
  domains;
- track issuance, issuer, SANs, wildcard use, validity, and first/last seen;
- detect new, unexpected, deprecated, or reappearing names.

**OpenAssetWatch treatment:**

- prioritize a native Certificate Transparency monitor as the first no-extra-cost
  enrichment capability;
- begin with a replaceable crt.sh adapter if approved;
- keep a provider-neutral CT interface so OpenAssetWatch can later consume
  additional logs or operate its own monitor;
- create candidate assets and certificate relationships, never confirmed assets
  solely from CT data;
- isolate rate limits, outage handling, backoff, caching, and freshness rules.

### urlscan.io

**Useful capability:**

- search existing web observations;
- derive redirect chains, contacted domains, IPs, certificates, response
  metadata, technologies, screenshots, and content hashes;
- identify unexpected third-party dependencies or historical page behavior.

**OpenAssetWatch treatment:**

- optional bring-your-own-key adapter only after terms review;
- search existing results before considering any submission;
- automatic URL submission disabled by default;
- any future submission requires verified authorization, explicit user action,
  safe visibility selection, redaction, and removal of tokens, query secrets,
  fragments, internal names, and personal data;
- store normalized metadata and hashes by default, not complete DOM, response
  bodies, cookies, or sensitive URLs;
- no unrestricted URL-fetch path in the hub.

### LeakIX

**Useful capability:**

- externally observed IP, port, service, certificate, software, ASN, reverse-DNS,
  and exposure metadata;
- interoperability ideas from the separately licensed `l9format` project.

**OpenAssetWatch treatment:**

- optional, read-only, bring-your-own-key research adapter unless commercial use
  is explicitly approved;
- retain provider record references and normalized metadata rather than exposed
  datasets, credentials, database contents, or complete reports;
- never redistribute LeakIX records as an OpenAssetWatch feed;
- do not include active scanning, credential checks, vulnerability testing, or
  provider scanner orchestration;
- evaluate `l9format` only as an optional import/export compatibility format;
  the native OpenAssetWatch evidence schema remains authoritative.

### ThreatCrowd

**Useful patterns:**

- domain, IP, certificate, file, and relationship pivots;
- graph-oriented investigation and visible source relationships.

**OpenAssetWatch treatment:**

- use as design inspiration for relationship navigation;
- do not make the service a required or authoritative dependency;
- keep file-malware and personal-email pivots outside the initial asset-focused
  scope unless a later accepted design establishes a defensive need;
- preserve provider independence and source timestamps because legacy/community
  services may change or disappear.

### ONYPHE

**Useful capability:**

- historical and current external observations for domains, IPs, certificates,
  passive DNS, services, products, and related exposure context.

**OpenAssetWatch treatment:**

- optional read-only, customer-supplied-key adapter after exact-use approval;
- restrict recurring queries to verified customer scope;
- store normalized observations, not a redistributable copy of the provider
  dataset;
- do not invoke on-demand scanning or other active functions;
- label product, CPE, version, risk, and vulnerability fields as provider
  assertions until independently verified.

### Netlas

**Useful capability:**

- host, domain, IP, WHOIS, certificate, discovery, and historical relationship
  observations;
- developer integration program that may support qualifying public security
  software.

**OpenAssetWatch treatment:**

- pursue the provider's developer-license review as the strongest initial
  optional integration candidate;
- do not assume the community plan authorizes commercial product integration;
- keep customer keys or approved project credentials in secret stores, never in
  the repository;
- use passive datasets only and exclude scanner-creation endpoints;
- retain a complete fallback path so product operation does not depend on
  approval or continued provider access.

## Provider and License Profile

Each adapter requires a machine-readable provider profile. Suggested fields:

```yaml
provider_id: example
status: disabled
capabilities:
  - EXISTING_PROVIDER_OBSERVATION_LOOKUP
authentication:
  mode: byo_api_key
  secret_reference_required: true
usage:
  commercial_use: review_required
  caching: review_required
  redistribution: prohibited
  raw_payload_retention: prohibited
  attribution_required: true
scope:
  verified_scope_required: true
  active_requests_allowed: false
privacy:
  pii_allowed: false
  secrets_allowed: false
review:
  reviewed_at: 2026-08-05
  next_review_at: null
  registry_record: docs/SOURCE_LICENSING_REGISTRY.md
```

Runtime enablement must fail closed when the adapter is disabled, its license
profile is absent or expired, the required scope is not verified, or a secret
reference is unavailable.

## Local Redaction and Safe Investigation

A local redaction utility can add value across the existing AI Advisor and
external-investigation workflow. It should operate before data leaves the local
or customer-controlled boundary.

Candidate categories:

- private IP addresses;
- internal hostnames and domains;
- usernames and email addresses;
- customer and site names;
- tokens, keys, cookies, and authorization headers;
- ticket, incident, and case identifiers;
- URL query parameters and fragments;
- file paths and share names;
- selected regulated or tenant-sensitive fields.

Redaction should be deterministic, auditable, reversible only by authorized
local users, and represented as a transformation of evidence rather than a
modification of the original record. Secrets should be removed, not merely
pseudonymized for restoration.

## Storage and Retention

Default retention should favor minimal normalized evidence:

Store by default:

- normalized subject, predicate, and object;
- source and provider record identifier;
- first seen, last seen, observed, and retrieved timestamps;
- freshness and historical state;
- evidence hash;
- confidence and verification state;
- source URL or non-secret reference;
- license profile and attribution metadata.

Do not store by default:

- exposed credentials or secrets;
- complete leaked documents or databases;
- cookies, authorization headers, or session data;
- complete page bodies or DOM captures;
- personal email lists;
- sensitive URL query strings;
- raw provider exports that cannot be redistributed or retained;
- unrelated third-party records outside verified scope.

Raw payload retention, when permitted and genuinely required, must be bounded,
encrypted, tenant-isolated, access-controlled, auditable, and governed by a
short explicit retention policy.

## AI Advisor Boundary

The AI Advisor may:

- summarize external observations with evidence citations;
- explain why an observation is relevant to a known asset;
- show corroborating and conflicting sources;
- identify missing verification steps;
- propose safe investigation questions;
- explain historical changes and relationships;
- generate bounded narrative from approved fields.

The AI Advisor may not:

- convert an external observation into a confirmed asset or finding;
- invent a relationship, product, version, CVE, ownership claim, or exposure;
- suppress disagreement or omit source limitations;
- request arbitrary URLs or invoke provider scanning functions;
- submit customer data to a provider;
- promote a candidate finding without deterministic validation or human review;
- write authoritative evidence, identity, classification, risk, or remediation
  state.

External text and provider data remain untrusted data and must never be treated
as instructions to the model, coordinator, adapter, or tool gateway.

## Candidate Deterministic Findings

After implementation and validation, external enrichment may support carefully
scoped candidate rules such as:

- new certificate name under a verified root domain;
- unexpected certificate issuer or wildcard certificate;
- certificate nearing expiration;
- deprecated hostname reappeared in CT or passive DNS;
- new public IP associated with a verified domain;
- externally observed service absent from internal inventory;
- unexpected hosting provider or ASN change;
- public administrative or remote-access service observation;
- web property redirecting to an unexpected domain;
- third-party script or dependency changed;
- historical asset or service reappeared;
- provider-observed product/version requiring local verification;
- asset present externally but absent from expected vulnerability-scanner
  coverage.

These should begin as candidate observations or review items. A source-specific
claim must not directly become a confirmed vulnerability, compromise, ownership
change, or remediation action.

## Implementation Sequence

### Phase 0 — Documentation and governance

- accept the additive architecture decision;
- register all candidate providers and source restrictions;
- define provider capability vocabulary;
- define verified-scope ownership and expiration requirements;
- define privacy, retention, and redaction controls;
- document explicit non-goals and release blockers.

### Phase 1 — Product-owned no-extra-cost substrate

- extend the existing evidence model with external-observation provenance;
- implement the scope registry;
- implement provider and license profiles;
- implement the provider-neutral adapter interface;
- implement Certificate Transparency collection behind the adapter boundary;
- add certificate, hostname, IP, ASN, and service relationship projections;
- add freshness, conflict, supersession, and expiry handling;
- add read-only dashboards and AI Advisor evidence presentation.

### Phase 2 — Optional approved providers

- apply for and evaluate the Netlas developer integration license;
- add a disabled-by-default Netlas read-only adapter if approved;
- evaluate ONYPHE customer-supplied-key access for exact internal use;
- evaluate restricted LeakIX metadata lookup and optional `l9format` imports;
- evaluate urlscan existing-result search with submissions disabled;
- add manual analyst launchers where API integration is not approved.

### Phase 3 — Evidence fusion and operationalization

- cross-source corroboration without naive confidence multiplication;
- source disagreement and stale-data presentation;
- deterministic candidate-finding rules;
- relationship timeline and change detection;
- dynamic drilldowns using the approved panel and semantic-metric model;
- provider health, quota, terms-review, and source-freshness monitoring;
- export of normalized OpenAssetWatch evidence without redistributing restricted
  provider payloads.

## Suggested Work Packages

1. **Scope Registry and Ownership Verification**
2. **External Observation Schema and Provenance Mapping**
3. **Provider Capability and License Profiles**
4. **Certificate Transparency Adapter**
5. **Certificate and Domain Relationship Projection**
6. **Freshness, Expiration, Conflict, and Supersession Rules**
7. **Local Redaction Utility**
8. **Manual Investigation Launcher Registry**
9. **Optional Provider Adapter SDK**
10. **External Observation Dashboard and AI Evidence View**
11. **Cross-Source Corroboration Evaluation**
12. **Provider Terms and Source Health Operations**

Each work package should have its own design, threat model, tests, and release
gates before coding or production enablement.

## Minimum Acceptance Criteria

No external adapter is production-ready until it demonstrates:

- exact source approval in the Source Licensing Registry;
- verified-scope enforcement;
- disabled-by-default behavior when appropriate;
- no active scan or arbitrary fetch path;
- no raw secret or credential ingestion;
- complete source, time, evidence, and license provenance;
- deterministic bounds, pagination, retry, rate-limit, and backoff behavior;
- tenant and site isolation;
- correction, conflict, expiry, and deletion behavior;
- malformed and adversarial payload handling;
- prompt-injection-safe treatment of external text;
- missing data represented as unknown;
- provider outage does not break core OpenAssetWatch operation;
- no external observation can directly write authoritative identity, finding,
  score, or action state;
- dashboards and AI output clearly distinguish observation from verification.

## Release Blockers

The following block release of the affected capability:

- unverified or overbroad recurring scope;
- automatic submission of customer or internal URLs without explicit approval;
- unrestricted SSRF-capable URL retrieval;
- provider credentials committed to code, configuration, logs, or examples;
- storage or redistribution forbidden by provider terms;
- raw leaked credentials, personal data, or database contents entering the
  product evidence store;
- active scanning presented as passive enrichment;
- external source treated as the sole authority;
- direct promotion of provider claims to confirmed assets, vulnerabilities,
  findings, or risk decisions;
- failure to preserve source disagreement, timestamps, or provenance;
- core platform failure when an optional provider is unavailable;
- AI treating provider-controlled text as instructions.

## Explicit Non-Goals

This roadmap does not approve:

- replacing existing OpenAssetWatch collectors, sensors, asset schemas, or risk
  workflows;
- continuous Internet-wide scanning by OpenAssetWatch;
- active probing through third-party providers;
- credential validation, default-password testing, exploitation, or exposed-data
  collection;
- people-search or broad personal OSINT;
- resale or redistribution of restricted provider data;
- a provider-specific core schema;
- silent asset creation, merge, split, or confirmation;
- a graph or vector database as the authoritative system of record;
- autonomous remediation or external ticket creation;
- any implementation whose free tier does not permit the intended use.

## Source References Reviewed for This Expansion

The following primary or provider-controlled references informed this design.
They are evidence for review, not permission to implement or redistribute data:

- Exploratores launch page: <https://sosintops.github.io/Exploratores/launchme.html>
- urlscan terms: <https://api.urlscan.io/terms/>
- urlscan API documentation: <https://urlscan.io/docs/api/>
- LeakIX terms: <https://leakix.net/terms-and-conditions>
- LeakIX API documentation: <https://docs.leakix.net/docs/api/>
- LeakIX `l9format`: <https://github.com/LeakIX/l9format>
- Certificate Transparency monitors: <https://certificate.transparency.dev/monitors/>
- crt.sh interface: <https://crt.sh/>
- ThreatCrowd API reference: <https://threatcrowd.blogspot.com/p/api.html>
- ONYPHE pricing: <https://www.onyphe.io/pricing/>
- ONYPHE API documentation: <https://search.onyphe.io/docs>
- Netlas pricing and developer-license information: <https://netlas.io/pricing/>
- Netlas API and data agreement: <https://netlas.io/legal/license_agreement/>
- Netlas API reference: <https://docs.netlas.io/api-reference/>

Terms, quotas, programs, endpoints, and licenses may change. Re-review is
required before implementation and at the cadence defined by the Source
Licensing Registry.

## Documentation-Only Status

This roadmap adds design direction only. It does not claim that the scope
registry, external observation schema, CT monitor, provider adapters, redaction
utility, relationship projection, dashboards, or finding rules are currently
implemented.
