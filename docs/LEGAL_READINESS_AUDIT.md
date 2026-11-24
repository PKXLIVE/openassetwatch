# OpenAssetWatch legal readiness audit

Baseline `0e51ef15cda080c53d52942551fc53265577692f`, reviewed 2026-11-24.
This is a record of engineering controls, distribution evidence, and open
decisions. Each release needs its own artifact review. Counsel determines
legal requirements and approves commercial terms where applicable.

## Audit matrix

| Area | Current state | Evidence | Risk | Action taken | Remaining work | Legal counsel required? |
| --- | --- | --- | --- | --- | --- | --- |
| Repository license | IMPLEMENTED / SUFFICIENT for the source declaration | [LICENSE](../LICENSE), [NOTICE](../NOTICE), [README](../README.md), [license metadata check](../scripts/check_license_metadata.py) | Project license declarations can be mistaken for proof about packaged third-party material. | Linked the license policy and distribution evidence. | Verify project license delivery in each artifact. | For license exceptions or scope disputes. |
| Contributor rights and DCO | IMPLEMENTED / SUFFICIENT as an engineering control | [DCO 1.1](../DCO), [contribution terms](../CONTRIBUTING.md), [DCO workflow](../.github/workflows/dco.yml) | Sign-offs attest to contributor rights. Alternate terms and ownership disputes need individual review. | Verified the signed-off contribution rules, rollout exceptions, and CI checker definition. | Confirm required-check settings and actual sign-offs on a future PR. | Yes for ownership disputes and alternate terms. |
| Go dependencies | PARTIAL | [go.mod](../go.mod), [go.sum](../go.sum), [Go inventory](DISTRIBUTION_LICENSE_INVENTORY.md#go-binaries) | Direct and toolchain-vendored linked code carries its own license and possible generated-data notices. | Verified the direct module and four platform graphs. Added the common Go notice text. | Match the Go toolchain, binary and notices per release target. | If exact upstream terms are unresolved. |
| Python dependencies | RELEASE BLOCKER for backend image redistribution | [Runtime lock](../backend/requirements.txt), [wheel evidence](DISTRIBUTION_LICENSE_INVENTORY.md#python-backend) | An LGPL driver and its native wheel dependencies require artifact-level review. Other compiled and generated components also need a license closure. | Documented all 26 pins, license materials, observed native files and the OpenSSL exception. | Review exact images and wheels, licenses, source, notices and relinking where applicable. | Yes for the driver exception and proposed redistribution method. |
| JavaScript and browser dependencies | PARTIAL | [Static dashboard](../backend/app/static/index.html), [hub entry point](../backend/app/main.py), [browser inventory](DISTRIBUTION_LICENSE_INVENTORY.md#collector-browser-and-build-tooling) | Framework documentation can load browser assets separately. Future UI additions may introduce a separate bundle or processor. | Verified the tracked dashboard has inline assets and system fonts. Identified default API documentation CDN references in the hash-locked framework wheel. | Revisit after browser asset changes or before bundling the generated documentation assets. | If external terms or data flows are unclear. |
| Container dependencies | RELEASE BLOCKER for project redistribution of unresolved images | [Backend Dockerfile](../backend/Dockerfile), [Compose](../docker-compose.yml), [legacy Compose](../installers/docker/docker-compose.yml) | Floating tags obscure the base OS, actual packages, and license changes. Separate-process use still needs its own distribution or service review. | Mapped base and service images, generated SPDX scans for four cached digests, detected backend cache drift, and recorded missing backend project notice delivery. | Rebuild from the current lock and attach image SBOMs, notices and source evidence to the exact redistributions. | Yes for unclear copyleft, source-available, and commercial terms. |
| Installer dependencies | PARTIAL, with a commercial MSI gate | [Installer overview](INSTALLERS.md), [MSI and toolchain inventory](DISTRIBUTION_LICENSE_INVENTORY.md#collector-browser-and-build-tooling) | Tool-supplied custom actions can ship inside the MSI. The tool package declares separate terms. | Located WiX and Util extension pin and terms. Separated embedded output from build-only tools and OS prerequisites. | Inspect final MSI tables and embedded binaries. Record notice and commercial-use decision. | Yes for applicable tool terms and redistribution. |
| Sensor distribution | PARTIAL | [Sensor implementation](../internal/sensor/), [Linux installer](../scripts/release/install_sensor_linux.py), [deployment guide](SENSOR_LINUX_DEPLOYMENT.md) | A local installer is available. A reviewed, labeled distribution bundle and source-to-binary provenance are still needed. | Reviewed source and history and completed the supplemental provenance review described below. Documented required notices and the authorized capture boundary. | Validate the exact sensor bundle. Revisit the source comparison if the historical reference is identified or implementation materially changes. | If a provenance or license issue is found. |
| Agent distribution | RELEASE BLOCKER for paths with missing notices | [Packaging](../packaging/agent/), [artifact inventory](DISTRIBUTION_LICENSE_INVENTORY.md#installer-and-release-inventory) | DEB/RPM validate first-party materials. Binary, TAR.GZ, MSI, and PKG paths do not carry them. Required Go notices are absent from the reviewed packaging paths. | Recorded format-specific payloads, package metadata and evidence gaps. | Deliver and validate required notices per package and public release asset. | If third-party package terms remain unresolved. |
| Third-party notices | PARTIAL | [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) | The notice foundation currently covers reviewed Go license text. It is not yet assembled into release assets. | Created a canonical starting artifact using verified text. | Add exact native/OS/MSI attributions where required and verify delivery alongside the covered artifacts. | For disputed obligations and notice delivery options. |
| External feeds and data | PARTIAL | [Source Licensing Registry](SOURCE_LICENSING_REGISTRY.md), [advisory publisher](../.github/workflows/advisory-mirror-publish.yml) | Approvals are limited to exact uses. Incomplete decisions for new data cannot authorize ingest, caching, or redistribution. | Clarified how to record unknown and inapplicable fields. Reviewed narrow signed-catalog scopes and provenance. | Complete production records for proposed sources and review retention, correction, geographic and privacy fields for each future use. | Yes for ambiguous data terms and commercial rights. |
| SBOM | PARTIAL | [Repository SBOM workflow](../.github/workflows/sbom.yml), [release validator](../scripts/release/validate_agent_release_publication.py) | Source scan does not cover the built package or OCI layer closure. Release manifests can still omit sidecar claims. | Generated local source and cached-image SPDX inventories. Added local validation for files claimed by manifest paths. | Generate and publish SBOMs for actual release artifacts and bind them to those digests. | Generally engineering. |
| Release metadata | PARTIAL | [Release pipeline](RELEASE_PIPELINE.md), [publication workflow](../.github/workflows/agent-release.yml), [validator tests](../scripts/release/test_agent_release_publication.py) | License identifiers, checksums, and build commits do not establish payload or signing completeness. | Added sidecar presence and containment tests. | Verify actual published materials, package notices, signing integration, and provenance attestations. | For distribution terms and related claims. |
| Trademark policy | IMPLEMENTED / SUFFICIENT as project guidance | [TRADEMARKS](../TRADEMARKS.md), [README](../README.md), [package naming](../packaging/agent/os-package-mapping.md), [MSI name](../packaging/agent/windows/OpenAssetWatchAgent.wxs) | The policy claims no registration. Language covering similar marks, modified installers, and fork naming merits review before commercial enforcement. | Verified consistent project and agent names across reviewed package paths and contributor docs. | Confirm official naming and distribution locations, clearance, and scope of commercial enforcement. | Yes for clearance, registration, and enforcement. |
| Privacy and data handling | PARTIAL | [Data-handling disclosure](DATA_HANDLING_AND_PRIVACY.md), [schema](../backend/app/migration_sql/0001_current_schema_baseline.sql) | Hub data can include device and operator identifiers. No general retention or verified erasure workflow was identified. Opt-in external AI can receive scoped evidence. | Documented data categories, local and external paths, audit visibility, and the limits of revocation and purge. | Define and test retention, deletion, backup expiry, disclosure and provider controls. | Yes for law applicability and privacy notices. |
| Authorized monitoring | IMPLEMENTED / SUFFICIENT as deployment guidance | [Sensor deployment](SENSOR_LINUX_DEPLOYMENT.md), [sensor overview](PASSIVE_SENSOR_MVP.md), [collector installation](setup/local-collector-installation.md) | Monitor scope and authorization rest with the operator. | Added deployment-specific authorization wording for passive capture and collector installation. | Review customer-facing use terms before commercial distribution. | Yes for jurisdiction-specific terms. |
| Hosted-service readiness | FUTURE COMMERCIAL REQUIREMENT | [Architecture](PRODUCT_ARCHITECTURE.md), [commercial checklist](COMMERCIAL_LEGAL_READINESS.md) | Hosted data and provider terms, retention, tenant handling, and network-copyleft exposure depend on the offered service. | Documented the review gate and commercial checklist. | Define the actual hosted model, processors, service terms, and operational controls. | Yes. |
| Customer contractual readiness | FUTURE COMMERCIAL REQUIREMENT | [Commercial checklist](COMMERCIAL_LEGAL_READINESS.md) | Contract terms may promise capabilities or obligations the deployment cannot meet. | Listed agreements, evidence and sign-off areas. | Develop reviewed terms, DPA and security exhibits for the actual offer. | Yes. |
| Export and sanctions | REQUIRES LEGAL COUNSEL | [Commercial checklist](COMMERCIAL_LEGAL_READINESS.md#commercial-legal-readiness) | Target markets, distribution methods, encryption and product capabilities determine the review. | Identified the evidence owners need to gather. | Obtain counsel determination before international commercial distribution. | Yes. |

## Sensor provenance review

The review covered sensor capture, decoding, aggregation, replay, batch contracts,
configuration and CLI vocabulary, package/service files, related tests, operator
documentation, and the changesets that introduced and hardened those paths.
The implementation uses native socket primitives and product-defined contracts.
The repository review found no explicit upstream import, attribution marker,
identified third-party sensor dependency, or concrete suspicious passage in the
reviewed material. Broad sharing of Ethernet, VLAN, and protocol parsing
concepts cannot establish copying.

A supplemental provenance review found no concrete evidence of copied material
within the scope examined. Historical provenance remains subject to
verification. Detailed supporting evidence is retained separately for
maintainer review. This assessment does not establish comprehensive copyright,
intellectual property, or licensing clearance.

Preserve any suspect material and report the file and match for review before
editing it.

## Control discrepancies

- The root license check verifies project wording and selected package metadata.
  It is not a component-license inventory. Retain the existing CI gate and use
  the [third-party policy](THIRD_PARTY_SOFTWARE_POLICY.md) for new dependencies.
- The dependency review workflow denies enumerated GPL, LGPL, and AGPL
  identifiers and is limited to public-repository PRs. A pre-existing locked
  LGPL dependency shows why the PR gate alone cannot establish inventory
  compliance. Evaluate the existing wheel through the required review process.
  [Dependency review workflow](../.github/workflows/dependency-review.yml)
- A repository SPDX workflow and a separate secret scan are defined. Neither
  supplies an artifact-specific license or distribution decision.
  [Repository SBOM workflow](../.github/workflows/sbom.yml)
  [Secret-scan workflow](../.github/workflows/gitleaks.yml)
- A valid sidecar path establishes local file presence. The release pipeline
  still needs separate artifact binding, format checks for future generated
  sidecars, and delivery validation in the publication job.
