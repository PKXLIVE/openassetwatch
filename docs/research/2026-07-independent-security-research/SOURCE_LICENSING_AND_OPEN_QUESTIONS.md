# Source Licensing, Evidence Caveats, and Open Questions

## Status

Independent research input. Licensing summaries are best-effort readings of public terms and are not legal advice.

## Why this register exists

The research repeatedly found that the most attractive security, fingerprint, threat-intelligence, and device-identification sources have different rights, update models, and operational risks. A source may be publicly accessible without being redistributable. A repository may be open source while its data files use a different license. A free API may prohibit caching, commercial reuse, or redistribution.

No third-party source should be bundled, mirrored, transformed, or exposed through the product until its license and operational requirements have a recorded decision.

## Preliminary source and licensing register

### Vulnerability and exploitation sources

| Source | Preliminary status | Important condition |
| --- | --- | --- |
| CISA KEV | CC0/public-domain style use | Strong candidate for local sync and redistribution with source attribution retained. |
| FIRST EPSS | Public daily score distribution | Confirm current service and redistribution terms before mirroring. Preserve score date and model version. |
| Official CVE List | Public CVE records | Preserve record provenance and CNA data. Do not assume all enriched fields exist. |
| NVD | Public government service | Treat as one input; respect API limits and attribution. Do not assume universal enrichment. |
| OSV | Open schema and aggregated records | Individual upstream records may carry their own terms; preserve source attribution. |
| GitHub Advisory Database | CC-BY 4.0 for database content | Attribution required. Confirm API and bulk-use limits. |
| ENISA EUVD | Public API | Bulk and redistribution terms remained unclear in the research and require re-verification. |
| CISA ICS and ICS Medical Advisories | Public government advisories | Preserve advisory identity and update history. |
| Vendor PSIRT/CSAF feeds | Vendor-specific | Review every vendor's terms and update behavior. |
| VulnCheck and other commercial enrichments | Commercial/freemium | Do not redistribute or assume rights from public access. |

### Threat-intelligence and knowledge sources

| Source | Preliminary status | Important condition |
| --- | --- | --- |
| MITRE ATT&CK | Publicly available with stated terms | Preserve version and source. |
| CWE and CAPEC | Publicly available with stated terms | Preserve identifiers, versions, and update dates. |
| STIX/TAXII | Open standards | Individual TAXII collections retain source-specific terms. |
| MISP | Open-source platform | Feed content may carry different licenses and sharing restrictions. |
| OpenCTI | Open-source platform | Connector data sources retain their own terms. |
| AlienVault OTX and similar exchanges | Service-specific | Review API, caching, and redistribution terms. |
| Censys and Shodan | Proprietary | Public search access does not permit redistribution of underlying scan data. |

### Fingerprint and identity sources

| Source | Preliminary status | Important condition |
| --- | --- | --- |
| Recog | BSD-2-Clause | Favorable candidate; preserve notices and verify data/content scope. |
| JA4 TLS client method | BSD-3-Clause | Favorable for the TLS client method. |
| Other JA4+ methods | FoxIO License 1.1 | Commercial or monetized use may require OEM permission. Review before bundling. |
| Nmap fingerprint data | NPSL | The license may treat software reading the data files as derivative. Requires legal review. |
| p0f | LGPL-2.1-only | Code is reusable under license, but fingerprints are substantially stale. |
| Fingerbank | Commercial DB/API | Current full corpus is not a freely redistributable open dataset. |
| Wappalyzer | Primary rules closed since 2023 | Community forks require separate provenance and license review. |
| USB ID repository | GPL-2.0-or-later or BSD-3-Clause | Favorable; preserve chosen-license obligations. |
| PCI ID repository | GPL-2.0-or-later or BSD-3-Clause | Favorable; preserve chosen-license obligations. |
| IEEE address registry | Public download, unclear standalone open license | Treat as legally cautious; formal review required before redistribution. |
| Bluetooth Assigned Numbers | Proprietary | Do not redistribute without a clear permitted-use basis. |
| FCC equipment data | Public government records | Individual exhibits may include confidentiality restrictions. |
| ICS Advisory Project | ODbL 1.0 | Attribution and share-alike database obligations apply. |
| NetreSec/4SICS captures | Free with attribution request | Preserve requested credit and confirm redistribution conditions. |
| endoflife.date | MIT code; data/source specifics require review | Useful convenience source, not authoritative universal hardware coverage. |

### Standards and posture sources

| Source | Preliminary status | Important condition |
| --- | --- | --- |
| CVSS | Open standard from FIRST | Preserve version and do not call Base score risk. |
| SSVC | Public guidance and reference implementations | Preserve tree/table version and terminology. |
| CSAF | OASIS standard | Vendor documents retain their own terms. |
| OpenVEX | Open specification | VEX documents are assertions and need issuer/provenance validation. |
| CycloneDX and SPDX | Open standards | Individual SBOM content and embedded licenses vary. |
| CIS Benchmarks | Licensed content | Do not redistribute benchmark text without permission. |
| DISA STIGs and SCAP content | Government/public distribution | Preserve version, benchmark identity, and source. |

## Required source decision record

For every proposed data source, document:

- source ID and owner;
- official location;
- source type;
- current license and version;
- copyright notice;
- attribution requirement;
- redistribution rights;
- transformation and derivative-data rights;
- commercial-use rights;
- caching and retention rights;
- API authentication;
- rate limits;
- bulk-download option;
- update cadence;
- correction and retraction mechanism;
- provenance fields;
- security risks;
- privacy risks;
- operational cost;
- accepted use: bundled, user-fetched, referenced, optional connector, or rejected;
- reviewer and date; and
- re-review trigger.

## Source-security requirements

All external data must be treated as untrusted.

Controls should include:

- domain and endpoint allowlists;
- TLS verification;
- authentication and scoped secrets;
- timeouts;
- response-size limits;
- archive and decompression limits;
- content hashing;
- signature verification where available;
- schema validation;
- raw-data quarantine;
- source version and retrieval date;
- duplicate detection;
- correction and retraction processing;
- prompt-injection isolation;
- no execution of downloaded content; and
- auditable source failures and stale-feed detection.

## Research claims requiring re-verification

The source studies explicitly flag the following for future validation:

- Current maintenance and release activity of many listed open-source projects.
- EUVD license, bulk-download, and redistribution terms.
- Current CVE-program funding and governance arrangements.
- Current availability and licenses of AIxCC cyber-reasoning systems.
- Real-world, non-vendor AI triage and vulnerability-discovery accuracy.
- Claims of fully autonomous vulnerability discovery by commercial labs.
- Current in-the-wild exploitation status of several 2026 AI-product vulnerabilities.
- Exact concurrent versus cumulative exposure counts for unauthenticated local-model services.
- Current Fingerbank corpus counts and privacy claims.
- Precise IEEE address-registry redistribution rights.
- Bluetooth Assigned Numbers permitted-use terms.
- Exact reuse implications of Nmap NPSL for a separate product.
- Current maintenance and terms of Wappalyzer community forks.
- CycloneDX VEX justification enumeration and current schema version.
- NIST SP 800-82 Rev. 3 exact printed page references for active-scanning guidance.
- NIST SP 800-82 Rev. 4 status and final guidance.
- BOD 26-04 primary decision-matrix wording and exact row structure.
- Current FDA medical-device cybersecurity guidance revision.
- Current IEC 62443 part revisions.
- Current OpenTelemetry GenAI semantic convention stability.
- Public datasets named in the evaluation report but not independently re-verified in that session.

## Unresolved product and industry problems

### Asset identity

- Stable identity under IP churn and MAC randomization.
- Privacy-respecting BYOD continuity.
- Clone and reimage disambiguation at first observation.
- Logical-service identity across ephemeral cloud and container instances.
- Silent OT assets with few strong identifiers.
- Calibration when labeled production identity data is scarce.

### IoT, OT, and firmware

- Reliable hardware and firmware naming beyond CPE.
- OEM, ODM, white-label, and rebadged product mapping.
- Safe passive OT fingerprinting with field-level accuracy evidence.
- A maintained, openly licensed OT fingerprint corpus.
- Firmware SBOM generation and VEX at scale.
- Safe, standardized, graduated active discovery for OT.

### Vulnerability and threat intelligence

- Turnkey multi-source enrichment that does not depend on universal NVD coverage.
- Retraction-aware and license-aware synchronization.
- EOL/EOS coverage for routers, printers, cameras, NAS, and appliances.
- Relevance filtering that makes threat intelligence useful to non-experts.
- Source-reputation and poisoning resistance.

### Agent safety

- Robust indirect prompt-injection defense.
- Safe durable agent memory.
- Evidence-integrity benchmarks for security agents.
- Delegation-chain authorization standards.
- Detection of correlated hallucination among same-model agents.
- Calibrated model confidence.

### Risk and remediation

- Independent validation of real-world AI triage benefits.
- Calibrated local prioritization thresholds.
- Safe remediation guidance under uncertain identity and version.
- Verification and false-closure measurement.
- Practical compromise assessment for homes and small businesses.
- OT risk acceptance and compensating-control validation.

### Dashboards and UX

- Security-specific evaluation datasets for generated analytical workspaces.
- Trust calibration for AI-composed views.
- Semantic catalog governance that remains simple for small deployments.
- Safe natural-language refinement without free-form query generation.
- Prevention of dashboard sprawl.

## Required distinction in future documents

Every future architecture or roadmap document should label statements as one of:

- implemented;
- designed but not implemented;
- research-backed recommendation;
- experimental;
- unsupported claim;
- deferred; or
- rejected.

This prevents research inputs from being mistaken for shipped capabilities.
