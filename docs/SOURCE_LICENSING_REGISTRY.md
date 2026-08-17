# Source Licensing Registry

OpenAssetWatch must review external data and fingerprint sources before they
are imported, bundled, cached, redistributed, or used in a commercial service.
This registry is the required decision gate established by
`docs/architecture/decisions/0001-research-aligned-expansion.md`.

A source appearing in research, documentation, or an adapter proposal does not
mean OpenAssetWatch is permitted to ship its data.

## Decision states

| State | Meaning |
| --- | --- |
| `approved` | Approved for the recorded use under the listed obligations. |
| `approved-with-obligations` | Usable only when attribution, share-alike, notice, scope, or other recorded obligations are satisfied. |
| `review-required` | No bundling, caching, redistribution, or production integration until the review is completed. |
| `research-only` | May be studied or linked, but its data may not be included in the product. |
| `prohibited` | Do not use for the recorded purpose. |
| `retired` | Previously considered or used but no longer approved. |

## Required source decision record

Every proposed source must record:

- source name and owner;
- official source location;
- intended capability and data categories;
- proposed access method;
- license, terms, or public-domain basis;
- whether downloading, caching, modification, bundling, redistribution, and
  commercial use are permitted;
- attribution, notice, share-alike, and source-code obligations;
- per-record provenance requirements;
- data-retention and deletion requirements;
- privacy or personal-data concerns;
- security and poisoning concerns;
- update, correction, withdrawal, and retraction behavior;
- geographic, export, or account restrictions;
- decision state;
- approving maintainer;
- review date and next review date;
- evidence used for the decision.

No adapter may weaken or omit the upstream provenance or license metadata.
Conflicting or unclear terms result in `review-required`, not implied
permission.

## Current product-owned material

| Source | Capability | Decision | Permitted use | Obligations and notes |
| --- | --- | --- | --- | --- |
| OpenAssetWatch synthetic advisory catalog | Demo and deterministic vulnerability tests | `approved` | Bundle, modify, redistribute, test | Apache-2.0; fictional data only; retain explicit synthetic and no-third-party-data labeling. |
| OpenAssetWatch synthetic signed advisory bundle | Trusted-feed synchronization, approval, activation, rollback, and security tests | `approved` | Bundle, modify, redistribute, test | Apache-2.0; fictional product-owned data only; preserve signed provenance/attribution and never substitute a production signing key. |
| OpenAssetWatch native rules, schemas, tests, and documentation | Product functionality | `approved` | Use under repository license | Preserve repository license and notices. |

## Vulnerability and lifecycle sources

The following approval is deliberately narrower than the OSV ecosystem bucket.
The PyPI bucket also contains records from source families with different
terms. Only records identified as `PYSEC-*` and carrying a matching per-record
source link to `pypa/advisory-database` are approved here.

| Source | Owner and official locations | Capability and access | Decision and permitted use | Obligations, controls, and review |
| --- | --- | --- | --- | --- |
| Python Packaging Advisory Database (`PYSEC-*` records only), transported by OSV.dev's PyPI GCS export | Python Packaging Authority; [database](https://github.com/pypa/advisory-database), [license](https://github.com/pypa/advisory-database/blob/main/LICENSE), [OSV data-source documentation](https://google.github.io/osv.dev/data/); exact transport paths `https://storage.googleapis.com/osv-vulnerabilities/PyPI/modified_id.csv` and `.../PyPI/PYSEC-*.json` | One-shot retrieval, normalization, local caching of normalized records, signing, commercial service use, and redistribution in an OpenAssetWatch catalog | `approved-with-obligations`; CC BY 4.0 permits sharing and adaptation, including commercial use, subject to its conditions | Preserve source record URL, `PYSEC` ID, retrieval/cursor time, checksums, CC-BY-4.0 identifier/link, contributor attribution, and OpenAssetWatch normalization notice. Do not relicense non-`PYSEC` OSV rows. Reject ambiguous provenance or unknown schema fields. No personal data is expected beyond public advisory credits; credits remain bounded attribution text. Treat source data as untrusted and note that the GCS export has HTTPS transport but no upstream dataset signature. Corrections and withdrawals arrive through modified records; per-record timestamps and withdrawals must remain monotonic, while removals require a reviewed full rebuild. Approved by project maintainer for this exact adapter scope on 2026-08-03; re-review by 2027-08-03 or immediately after ownership, license, schema, or endpoint change. |

The official signed-mirror foundation does not broaden this decision. It may
redistribute only the exact approved `PYSEC-*` normalized catalog and must keep
the CC-BY-4.0 identifier, contributor attribution, normalization notice, source
provenance, correction/withdrawal history, and immutable bundle evidence in the
signed index and artifacts. Other OSV source families and CISA KEV remain
outside the mirror until their own decisions are approved. The disabled source
template and publication controls are documented in `docs/ADVISORY_MIRROR.md`.

The following rows remain candidate sources. No live or offline adapter is
approved by these rows until its decision moves out of `review-required`.

| Source | Intended capability | Initial decision | Known considerations | Required next action |
| --- | --- | --- | --- | --- |
| CVE List / CVE Program | Canonical CVE identity and CNA records | `review-required` | Verify current license, bulk-download, attribution, and redistribution terms. | Primary-source legal/terms review. |
| NIST NVD | Supplemental enrichment and historical metadata | `review-required` | Do not treat as sole authority; verify current terms, API limits, bulk data, and notice requirements. | Primary-source terms and current operations review. |
| CISA Known Exploited Vulnerabilities | Known exploitation signal | `review-required` | Preferred first adapter candidate; confirm public-domain/CC0-style status and required attribution before bundling. | Complete source decision before adapter implementation. |
| FIRST EPSS | Exploitation-probability field | `review-required` | Probability must remain separate from severity and risk; verify API/data terms and attribution. | Terms and redistribution review. |
| OSV and aggregated upstream databases other than the exact PyPI/PYSEC approval above | Package vulnerability ranges | `review-required` | OSV aggregates sources with potentially different per-record licenses; ecosystem membership is not a license grant. | Complete one source-family decision record at a time. |
| GitHub Advisory Database | Open-source package advisories | `review-required` | Research indicates CC-BY-style obligations; verify current repository license and API terms. | Primary-source verification. |
| Vendor CSAF and PSIRT feeds | Product and firmware advisories | `review-required` | Terms differ by vendor; signatures and issuer identity may be relevant. | One decision record per vendor/source. |
| EU Vulnerability Database | Supplemental European vulnerability data | `review-required` | Bulk-use and redistribution terms were unresolved in the July 2026 research. | Re-verify official terms before design approval. |
| Operating-system security trackers | Distribution package status | `review-required` | Each distribution has separate terms and version semantics. | One decision record per distribution. |
| `endoflife.date` and vendor lifecycle pages | EOL/EOS status | `review-required` | Code license does not automatically grant rights to all underlying product data; vendor pages vary. | Separate code/data and vendor-source review. |
| CISA ICS and medical advisories | OT and medical-device advisories | `review-required` | Verify current formats, notices, update limitations, and vendor-authority handoffs. | Primary-source review. |
| ICS Advisory Project | Normalized ICS advisory dataset | `approved-with-obligations` for design only | Research reports ODbL 1.0; share-alike and attribution may affect derived databases. No product import approved yet. | Legal and architecture review before data use. |

## Fingerprint and identification sources

| Source or project | Intended capability | Initial decision | Known considerations | Required next action |
| --- | --- | --- | --- | --- |
| Recog | Service, HTTP, certificate, and SNMP fingerprints | `approved-with-obligations` for design only | Research reports BSD-2-Clause. No corpus import is approved until current license and provenance are re-verified. | Verify official repository and define attribution/provenance. |
| JA4 TLS client fingerprint | TLS behavioral signal | `approved-with-obligations` for design only | Research reports BSD-3-Clause for JA4 TLS client only. A fingerprint is supporting evidence, not identity proof. | Verify official license and exact files used. |
| JA4+ non-TLS methods | Additional protocol fingerprints | `prohibited` pending separate license | Research reports FoxIO commercial-use restrictions for multiple JA4+ methods. | Obtain explicit suitable license or do not use. |
| Nmap OS and service data files | OS/service fingerprints | `prohibited` pending legal review | NPSL may treat software reading the data as derivative; Debian/Gentoo concerns were identified. | Legal review; do not bundle or parse meanwhile. |
| Fingerbank database or API | DHCP and behavioral device fingerprints | `research-only` | Commercial database/API; vendor size and privacy claims are not independently audited. | Do not bundle; commercial agreement and privacy review required for any API use. |
| Wappalyzer current rules | Web technology fingerprints | `prohibited` | Current ruleset is closed-source; historical licensing does not authorize current data. | Use only a separately reviewed open continuation or native rules. |
| IEEE OUI registry | NIC-vendor hints | `review-required` | Public download but redistribution/copyright position is ambiguous; OUI identifies NIC vendor, not necessarily product brand. | Primary-source legal review; avoid corpus redistribution until resolved. |
| Bluetooth SIG Assigned Numbers | Bluetooth vendor/service identifiers | `prohibited` pending permission | Research identifies proprietary and reuse-restricted terms. | Obtain permission or avoid bundling. |
| USB ID and PCI ID repositories | Hardware identifiers | `approved-with-obligations` for design only | Research reports GPL-2.0-or-later or BSD-3-Clause alternatives. Select and document the applicable option. | Verify official current license and attribution. |
| p0f signatures | Passive TCP/IP stack fingerprints | `research-only` | LGPL code but signatures are materially stale; accuracy is unsuitable for authoritative identity. | Consider only as historical reference. |
| Censys and Shodan datasets | Internet exposure and fingerprints | `prohibited` for bundling | Proprietary data and terms; not redistributable as an OpenAssetWatch corpus. | External API use would require a separate commercial and privacy decision. |
| Community-submitted OpenAssetWatch fingerprints | Open corpus | `research-only` | Requires signing, evidence thresholds, moderation, poisoning resistance, privacy, licensing, correction, and retraction governance. | Complete corpus-governance design and pilot before accepting data. |

## Adapter approval checklist

Before merging an adapter or dataset:

1. Move the source to `approved` or `approved-with-obligations` for the exact
   intended use.
2. Link the decision to primary license or terms evidence.
3. Preserve source, source version, record identity, retrieval time, checksum,
   license, and provenance in the normalized catalog.
4. Define correction, withdrawal, retraction, and supersession behavior.
5. Define update cadence, cursor/checkpoint behavior, rate limits, and failure
   detection.
6. Prove that missing or failed source data remains unknown rather than safe.
7. Add license, attribution, parser, malformed-input, bounds, duplicate,
   correction, and withdrawal tests.
8. Confirm that the runtime does not introduce unrestricted URL fetching,
   redirects, credentials in references, or an SSRF-capable path.
9. Review privacy and tenant effects.
10. Update this registry when source ownership, terms, format, or access method
    changes.

## Review cadence

- Re-review a source before the first production import.
- Re-review at least annually for actively used sources.
- Re-review immediately after a license, owner, access, format, or terms change.
- Fail closed when a source's permission becomes unclear.

## Disclaimer

This registry is an engineering and governance control, not legal advice.
Unclear or high-impact terms should be reviewed by qualified counsel before
commercial redistribution.
