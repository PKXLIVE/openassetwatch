# ADR-0002: Additive External Intelligence Enrichment

- **Status:** Accepted
- **Date:** 2026-08-05
- **Decision owner:** Project owner and OpenAssetWatch maintainers
- **Roadmap:** `docs/architecture/external-intelligence-enrichment-roadmap.md`
- **Source governance:** `docs/SOURCE_LICENSING_REGISTRY.md`

## Context

OpenAssetWatch can gain useful external context from public Certificate
Transparency records, passive DNS, Internet-exposure observations, web-analysis
records, certificate relationships, and provider-neutral investigation
patterns. Candidate sources reviewed for this direction include Exploratores,
urlscan.io, LeakIX, crt.sh and Certificate Transparency, ThreatCrowd, ONYPHE,
and Netlas.

These sources can help reveal unknown subdomains, public services, certificate
changes, historical infrastructure, unexpected web dependencies, and other
conditions that local passive or endpoint evidence may not see.

They also create material risks:

- redirecting the product away from its existing asset-first purpose;
- treating third-party observations as authoritative truth;
- creating provider lock-in or required paid dependencies;
- introducing active scanning through a nominally passive feature;
- submitting customer or sensitive data to external services;
- importing restricted, proprietary, personal, or leaked data;
- violating commercial-use, caching, attribution, or redistribution terms;
- weakening the current deterministic evidence and AI authority boundaries.

The project owner has clarified that this work is intended to expand
OpenAssetWatch, not replace what has already been built or change its direction.

## Decision

OpenAssetWatch accepts an **additive external intelligence enrichment** direction.

External sources may contribute optional observations, relationships, historical
context, and candidate findings through a provider-neutral enrichment boundary.
They may not replace the existing collectors, passive sensors, normalized asset
model, evidence-fusion engine, deterministic findings and risk, AI Advisor,
local-first operation, or product identity.

The existing authority order remains unchanged:

```text
authenticated normalized OpenAssetWatch evidence
  -> deterministic classification and matching
  -> deterministic findings and attention scoring
  -> bounded read-only AI explanation
  -> human review
```

External intelligence enters this order as untrusted, provenance-tagged evidence.
It does not become a parallel authority.

## Non-Negotiable Invariants

1. **Additive only.** No source or inspired capability may replace an existing
   OpenAssetWatch architectural component or redirect the product roadmap.
2. **Provider independence.** The core platform must operate without any
   optional external provider, account, API key, free tier, or network access.
3. **Existing evidence authority.** External records are observations or
   hypotheses until corroborated and verified through existing deterministic or
   authorized human workflows.
4. **No silent identity changes.** External data may not silently create,
   confirm, merge, split, or reclassify an authoritative asset.
5. **Passive-first.** Read-only public-record and existing-observation lookups do
   not authorize active probing, scanning, credential testing, or exploitation.
6. **Verified recurring scope.** Continuous enrichment is limited to approved
   domains, public IPs, CIDRs, ASNs, or other scope with recorded ownership or
   authorization evidence.
7. **Source governance.** The exact intended use must be approved in
   `docs/SOURCE_LICENSING_REGISTRY.md` before production access, caching,
   bundling, redistribution, or commercial integration.
8. **Minimal retention.** Store normalized evidence and references by default,
   not exposed credentials, leaked datasets, complete page bodies, cookies,
   tokens, or unrelated personal information.
9. **No arbitrary fetch.** The feature may not create an unrestricted URL fetch,
   redirect, browser, or SSRF-capable path in the hub.
10. **AI remains advisory.** Provider-controlled text is untrusted data, never
    instructions. AI may explain evidence but may not promote it to an
    authoritative fact, finding, score, decision, or action.
11. **Failure is non-destructive.** Provider outage, quota exhaustion, terms
    change, expiration, or removal must degrade enrichment only and must not
    break core platform behavior.
12. **Missing remains unknown.** No result, stale data, or provider failure may
    be interpreted as proof of safety or absence.

## Accepted Architecture Direction

### AD-01 — External Intelligence Enrichment Module

Create a provider-neutral, optional module that performs verified-scope checks,
read-only acquisition, normalization, correlation, evidence fusion, and
presentation through existing OpenAssetWatch contracts.

It is an enrichment module, not a replacement inventory, attack-surface product,
or second system of record.

### AD-02 — Scope Registry

Add a verified scope registry for recurring external enrichment. It records the
scope type and value, verification method and evidence, approver, allowed
capabilities, expiration, provider exclusions, and retention policy.

Public association alone does not prove ownership. Certificate names, WHOIS,
DNS, ASN, or provider records may support verification but cannot complete it by
themselves.

### AD-03 — Provider-Neutral Observation Contract

Normalize external data into a versioned observation envelope that preserves:

- provider and source record identity;
- scope and tenant/site boundary;
- subject, relationship, and object;
- observed, retrieved, first-seen, and last-seen times;
- current versus historical state;
- confidence and verification state;
- evidence hash and source reference;
- license/terms profile;
- raw-payload retention decision.

The final contract should extend existing evidence identifiers and provenance
rather than introduce a conflicting evidence model.

### AD-04 — Capability Allowlist

Adapters declare allowed capabilities such as Certificate Transparency lookup,
passive DNS lookup, existing provider observation lookup, certificate lookup,
registration lookup, relationship lookup, controlled user import, and manual
investigation launching.

The common adapter interface does not provide active scanning, credential
checking, arbitrary request execution, or unrestricted URL retrieval.

### AD-05 — Relationship Projection

Add source-aware relationships among domains, hostnames, IP addresses,
certificates, ASNs, services, and product hypotheses. Every relationship retains
source, evidence, time, freshness, confidence, scope, and verification state.

Relational records remain authoritative. A graph, search index, or vector store
may be a projection only.

### AD-06 — Observation Lifecycle

Use explicit states that distinguish externally observed, corroborated,
candidate, verified, conflicted, rejected, expired, and superseded evidence.

Provider product/version and vulnerability assertions remain candidates until
the existing deterministic matching and verification requirements are met.

### AD-07 — Certificate Transparency First

Prioritize a product-owned, no-extra-cost Certificate Transparency capability as
the first implementation target. A crt.sh adapter may bootstrap this work when
approved, but the interface remains replaceable and may later consume additional
logs or a product-operated monitor.

Certificate Transparency records create candidate names and certificate
relationships; they do not prove current reachability, ownership, deployment,
or vulnerability.

### AD-08 — Optional Provider Sequence

After the native substrate exists and exact source uses are approved:

1. evaluate the Netlas developer integration program;
2. evaluate customer-supplied-key, read-only ONYPHE enrichment;
3. evaluate restricted LeakIX metadata and optional `l9format` compatibility;
4. evaluate urlscan existing-result search with URL submission disabled;
5. retain Exploratores and ThreatCrowd primarily as workflow and relationship
   design inspiration unless later source decisions approve more.

No provider is entitled to implementation merely because it offers a free plan.

### AD-09 — Local Redaction

Add a local, auditable redaction capability before approved external sharing or
AI/provider workflows. Redaction may pseudonymize selected identifiers for
controlled restoration, but secrets must be removed rather than reversibly
masked.

### AD-10 — Source and Terms Operations

Provider adapters require machine-readable capability, authentication, privacy,
commercial-use, caching, redistribution, attribution, retention, and review
profiles. Runtime enablement fails closed when a required decision or verified
scope is absent or expired.

Actively used sources are re-reviewed at least annually and immediately after a
material terms, owner, endpoint, format, or licensing change.

## Consequences

### Positive

- Adds external visibility without replacing the existing platform.
- Preserves local-first and passive-first operation.
- Creates a common boundary for future sources and avoids provider-specific core
  schemas.
- Improves certificate, domain, public-service, and historical relationship
  context.
- Supports stronger evidence fusion and AI explanations while keeping external
  claims non-authoritative.
- Allows no-extra-cost capabilities to be built from approved public records
  before optional providers are considered.
- Makes licensing, privacy, retention, and source failure first-class controls.

### Costs and risks

- Requires new scope, provenance, lifecycle, source-health, and terms-review
  operations.
- Cross-source correlation can inflate confidence if independence is not
  evaluated carefully.
- Public and provider data may be stale, incomplete, inaccurate, poisoned, or
  historical.
- Optional providers may change quotas, APIs, free programs, terms, or
  availability.
- Sensitive URL submission and raw exposure data require strict prevention and
  testing.
- Relationship projections and timelines add storage and user-interface
  complexity.

## Rejected Alternatives

- Replacing local discovery with an Internet-exposure provider.
- Treating provider inventories as the OpenAssetWatch source of truth.
- Requiring a paid or free third-party account for normal product operation.
- Copying an external project wholesale into the repository.
- Adding a provider-specific core schema.
- Automatic submission of discovered URLs to a browser or scanning service.
- Active scanning, credential validation, exploitation, or exposed-data
  collection as part of passive enrichment.
- Importing or redistributing provider datasets without exact approval.
- Confirming vulnerabilities directly from banners, CPE strings, or provider
  assertions.
- Using a graph or vector database as the authoritative evidence store.
- Broad people-search or unrelated personal OSINT.

## Sequencing

### Phase 0 — Governance and design

- maintain this ADR and the detailed roadmap;
- register candidate sources;
- define scope verification, capability profiles, retention, and redaction;
- define release blockers and acceptance criteria.

### Phase 1 — Native additive substrate

- external observation extension to current evidence contracts;
- verified scope registry;
- provider-neutral adapter and license profiles;
- Certificate Transparency collection;
- relationship projections and timelines;
- freshness, conflict, expiry, and supersession;
- read-only dashboards and AI evidence display.

### Phase 2 — Approved optional adapters

- provider program and terms review;
- disabled-by-default integrations;
- customer-supplied secret references;
- read-only data access within verified scope;
- provider outage and quota handling.

### Phase 3 — Corroboration and candidate findings

- source independence analysis;
- cross-source conflict handling;
- deterministic candidate rules;
- approved drilldowns and operational source health;
- export of OpenAssetWatch-normalized evidence without restricted raw data.

## Implementation Status

This ADR records accepted architecture direction. It does not claim that the
scope registry, observation contract, Certificate Transparency monitor,
provider adapters, redaction utility, relationship projection, dashboards, or
candidate rules are implemented.

Implementation status remains governed by source code, canonical subsystem
documentation, and future updates to the research integration matrix.
