# External Intelligence Source Review

- **Review date:** 2026-08-05
- **Architecture roadmap:** `docs/architecture/external-intelligence-enrichment-roadmap.md`
- **Accepted decision:** `docs/architecture/decisions/0002-additive-external-intelligence-enrichment.md`
- **Canonical approval gate:** `docs/SOURCE_LICENSING_REGISTRY.md`

## Purpose

This document records the preliminary source-specific review for external
intelligence considered by the additive enrichment roadmap.

It does not approve production integration, commercial use, caching, bundling,
or redistribution. The canonical Source Licensing Registry must record an
`approved` or `approved-with-obligations` decision for the exact intended use
before implementation is enabled.

All sources are optional. None may replace OpenAssetWatch collectors, passive
sensors, normalized asset authority, deterministic findings and risk, AI
boundaries, or local-first operation.

## Preliminary Register

| Source | Intended additive value | Preliminary state | Permitted design treatment | Blocked until reviewed or approved |
| --- | --- | --- | --- | --- |
| Exploratores | Provider registry, investigation launcher, local redaction, analyst workflow ideas | `research-only` | Study workflow and independently implement product-owned patterns | Copying code, provider catalogs, branding, or content; production dependency; unrelated people-search OSINT |
| Certificate Transparency ecosystem | Certificate issuance monitoring, SAN discovery, certificate relationships, historical names | `approved for architecture design`; exact implementation source remains `review-required` | Design a native provider-neutral CT monitor and candidate-asset workflow | Assuming certificate presence proves ownership, reachability, deployment, or vulnerability; unreviewed caching or service dependency |
| crt.sh | Convenient query interface over Certificate Transparency data | `review-required` | Candidate bootstrap adapter behind replaceable CT interface | Production dependency, undocumented high-volume use, or treating service availability as guaranteed |
| urlscan.io | Existing page observations, redirects, contacted domains, certificates, IPs, technologies, screenshots, and hashes | `review-required` | Design disabled-by-default, search-existing-results adapter and manual launcher | Automatic submission; sensitive or internal URL submission; unrestricted fetch path; commercial product integration without exact approval; raw DOM/body retention by default |
| LeakIX platform | External service, certificate, software, ASN, reverse-DNS, and exposure observations | `research-only` for platform data pending written approval | Design restricted read-only metadata adapter and source references | External/commercial use without approval; redistribution; raw exposed data, credentials, or database contents; active scanning and credential checks |
| LeakIX `l9format` | Network-recon interoperability schema | `approved-with-obligations for design only` | Evaluate optional import/export compatibility while retaining native OpenAssetWatch schema | Treating the format as the system of record; code reuse before exact license/notice review and attribution implementation |
| ThreatCrowd | Relationship pivots among domains, IPs, certificates, and related indicators | `research-only` | Use graph-navigation and relationship-display concepts | Required live dependency; authoritative data use; broad personal-email pivots; assumptions about service continuity or accuracy |
| ONYPHE | Historical/current domain, IP, certificate, passive-DNS, service, product, and exposure observations | `review-required` | Design customer-supplied-key, read-only enrichment restricted to verified scope | On-demand scanning; data redistribution; shared project key; treating provider CPE/version/CVE assertions as verified; use outside licensed internal purpose |
| Netlas | Host, domain, IP, WHOIS, certificate, discovery, and historical relationships | `review-required`; developer-license application is a candidate next step | Design passive read-only adapter and apply for qualifying integration permission | Assuming Community access authorizes commercial integration; scanner endpoints; shared or committed credentials; provider-required core operation |

## Source Evidence and Current Constraints

### Exploratores

Reviewed location:

- <https://sosintops.github.io/Exploratores/launchme.html>

The useful outcome is the workflow pattern: select an input type, map it to an
appropriate provider or investigation path, redact sensitive values locally,
and remind analysts that external search results require verification.

OpenAssetWatch should implement its own provider registry and redaction design.
The code, catalog content, and exact license/provenance must be reviewed from the
official source before any reuse. Until then, this source remains design
inspiration only.

### Certificate Transparency and crt.sh

Reviewed locations:

- <https://certificate.transparency.dev/monitors/>
- <https://certificate.transparency.dev/logs/>
- <https://crt.sh/>

Certificate Transparency logs are public, auditable certificate records and are
intended to support monitoring for domain-related issuance. This supports an
OpenAssetWatch-native CT capability without making a commercial exposure
provider foundational.

The ecosystem-level design is approved. The exact crt.sh access pattern,
retention, query volume, attribution, failure behavior, and any applicable terms
must be reviewed before a production adapter is enabled.

### urlscan.io

Reviewed locations:

- <https://api.urlscan.io/terms/>
- <https://urlscan.io/docs/api/>
- <https://urlscan.io/docs/faq/>

The API can search existing observations and can submit URLs for browser-based
analysis. The provider requires permission to submit URLs, warns about
visibility and personal data, and asks product integrators or higher-volume
commercial users to contact it regarding acceptable use or a commercial
agreement.

OpenAssetWatch should therefore begin, if approved, with existing-result search
only. Submission remains disabled unless a later design adds explicit verified
scope, user approval, safe visibility, redaction, and exact commercial-use
permission.

### LeakIX

Reviewed locations:

- <https://leakix.net/terms-and-conditions>
- <https://docs.leakix.net/docs/api/>
- <https://github.com/LeakIX/l9format>

LeakIX terms restrict use to identifying, communicating, and resolving
vulnerabilities and exposures; restrict publication and distribution of
platform data; and require explicit prior written agreement for external or
commercial purposes unless a suitable commercial account applies.

The platform data therefore remains research-only for OpenAssetWatch until the
exact intended use is approved. A future adapter must not ingest exposed
credentials, leaked records, database contents, or complete reports.

The separate `l9format` repository identifies the SPDX license expression
`MIT` and may be useful as an optional interoperability format. Any use still
requires exact file and notice review, and it does not replace the
OpenAssetWatch evidence schema.

### ThreatCrowd

Reviewed location:

- <https://threatcrowd.blogspot.com/p/api.html>

The API reference demonstrates useful relationship pivots, but it is a legacy
community service with uncertain long-term availability and operating
assurances. OpenAssetWatch should keep the relationship-graph idea and avoid a
required runtime dependency.

### ONYPHE

Reviewed locations:

- <https://www.onyphe.io/pricing/>
- <https://search.onyphe.io/docs>
- <https://search.onyphe.io/docs/general-apis/search>

ONYPHE exposes read-only search APIs and rich external observations. Current
pricing material labels listed views for internal use and directs users to the
provider for other access or unrated API options.

A future integration therefore requires exact permission for the proposed
OpenAssetWatch use. It must be disabled by default, use a customer-supplied
secret reference, query verified scope only, and exclude provider scan
functions.

### Netlas

Reviewed locations:

- <https://netlas.io/pricing/>
- <https://netlas.io/legal/license_agreement/>
- <https://docs.netlas.io/api-reference/>

Netlas publishes a developer-license application path for developers integrating
Netlas into security software and asks applicants to provide a product or
GitHub repository link. Its API and data use are governed by plan-specific
license terms.

OpenAssetWatch should apply for the developer program before implementing a
shared integration. Approval, permitted data fields, caching, attribution,
redistribution, quotas, and commercial-use rights must be recorded in the
canonical Source Licensing Registry. A customer-supplied-key mode may still
require a separate exact-use decision.

## Required Decision Before Coding

For each proposed adapter, record all of the following in
`docs/SOURCE_LICENSING_REGISTRY.md`:

- exact source and official owner;
- exact API, dataset, or interface being used;
- exact OpenAssetWatch capability and deployment models;
- account and API-key ownership model;
- commercial-use permission;
- caching and raw-payload retention permission;
- modification, bundling, redistribution, and export permission;
- attribution, notice, and share-alike obligations;
- source-reference and per-record provenance requirements;
- rate limit, quota, and outage behavior;
- deletion, correction, withdrawal, and supersession behavior;
- privacy, personal-data, and tenant implications;
- active-versus-passive behavior;
- approval owner, review date, and next review date.

Unclear terms remain `review-required`. A free account, public website, open API,
or publicly visible record is not by itself permission to embed, cache,
redistribute, or use the data in a commercial product.

## Re-Review Triggers

Re-review immediately when any of the following changes:

- provider ownership;
- terms, license, plan, or pricing;
- API endpoint or schema;
- free-tier or developer-program conditions;
- source visibility or privacy behavior;
- permitted caching or redistribution;
- rate limits or authentication requirements;
- OpenAssetWatch deployment or monetization model;
- intended data retention or export behavior.

## Disclaimer

This is an engineering and product-governance review, not legal advice. Exact
commercial and redistribution rights should be confirmed with qualified counsel
or the provider before production use.
