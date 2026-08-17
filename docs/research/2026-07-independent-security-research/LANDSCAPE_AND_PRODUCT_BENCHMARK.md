# AI Security, Asset Intelligence, and Product Benchmark

## Status

Independent research input. Not an implementation commitment and not evidence that a capability is already present in OpenAssetWatch.

## Executive conclusion

The durable value of AI in security in mid-2026 is concentrated in narrow, evidence-grounded, human-supervised work: enrichment, explanation, investigation assistance, report drafting, bounded vulnerability research, and analyst-guided triage. The strongest production-proven foundations remain deterministic data and workflow systems rather than autonomous AI.

The broad product opportunity is a local-first, evidence-traceable asset, vulnerability, and exposure intelligence product for homes and small businesses. The opportunity exists because the component technologies are fragmented, costly, hard to operate, and poorly integrated—not because no alternatives exist.

## What is working now

High-confidence, production-proven or operationally credible capabilities include:

- Official CVE records, CISA KEV, FIRST EPSS, OSV, GitHub Advisory Database, MITRE ATT&CK, STIX/TAXII, CWE, CAPEC, CPE, and package URLs.
- Hybrid asset discovery using passive observation, carefully controlled active discovery, endpoint collectors, and API integrations.
- Multi-signal fingerprinting that preserves provenance and confidence.
- Human-in-the-loop AI triage that presents evidence rather than issuing opaque verdicts.
- Identity attack-path graph analysis when underlying data is current.
- CIS, DISA STIG, SCAP/OpenSCAP, and policy-as-code approaches for posture assessment.
- Local AI runtimes for narrow tasks such as summarization, local retrieval, reranking, and report drafting when securely deployed.
- AI-assisted vulnerability research in expert-operated systems that combine classical analysis, fuzzing, program analysis, and models.

## What is not working safely or credibly

The research rejects or strongly cautions against:

- Autonomous remediation without human approval.
- LLM-only vulnerability judgments or version-range decisions.
- Black-box autonomous SOC replacement claims.
- Authoritative facts stored only in vector databases.
- Treating model consensus as independent verification.
- Prompt-level instructions as the primary security boundary.
- Product-safeguarded benchmark numbers presented as raw API security performance.
- Synthetic or self-consistency tests presented as production accuracy.
- AI-generated vulnerability-report volume without independent validation.
- Free-form agent access to shell, SQL, networks, credential stores, or side-effecting tools.

## Documented failure patterns

The studies identify several recurring failures:

- Indirect prompt injection and data exfiltration in production AI assistants.
- Tool and MCP poisoning, including remote code execution through untrusted tool infrastructure.
- Memory and retrieval poisoning that can persistently alter agent behavior.
- Open-source maintainers overwhelmed by low-quality AI-generated vulnerability reports.
- Local model services exposed without authentication or network controls.
- NVD enrichment degradation and governance instability creating structural gaps in CPE/CVSS/CWE coverage.
- Stale attack-graph edges creating false paths or hiding current ones.
- Benchmark performance collapsing on real schemas and repeated attempts.
- Vendor claims attributing vulnerability discovery to autonomous AI without independently proving the degree of autonomy.

## Armis-like product outcomes

The product benchmark found that Armis is best understood as a converged cyber-exposure platform assembled around:

- passive network collectors and agentless endpoint visibility;
- targeted active querying;
- IT, IoT, OT, IoMT, cloud, and unmanaged asset discovery;
- product classification and behavioral context;
- vulnerability and exposure aggregation;
- prioritization and remediation workflow;
- threat and early-warning intelligence; and
- executive and operational dashboards.

The benchmark separates reproducible outcomes from proprietary-scale moats.

### Publicly reproducible outcomes

An open local-first platform can legitimately pursue:

- passive and safe-active asset discovery;
- device type, vendor, model, OS, software, and firmware hypotheses;
- evidence-backed identity confidence;
- historical asset tracking;
- CVE, KEV, EPSS, OSV, GHSA, vendor-advisory, and lifecycle enrichment;
- CPE, purl, SBOM, CSAF, and VEX support;
- transparent SSVC-style prioritization;
- exposure and configuration findings;
- network relationship and basic attack-path context;
- ownership, ticketing, reporting, and verification workflows;
- unified asset and risk drilldowns; and
- local-first privacy and air-gapped operation.

### Proprietary-scale or inappropriate targets

The benchmark recommends rejecting or deferring:

- a global crowd-sourced behavioral corpus measured in billions of assets;
- dark-web, honeypot, and human-intelligence early-warning claims;
- deep OT digital twins and broad industrial protocol control;
- clinical IoMT profiling and associated regulatory burden;
- opaque multi-engine AI risk scores;
- mandatory multi-tenant SaaS as the starting model;
- autonomous blocking or remediation; and
- proprietary data sources that cannot legally be redistributed.

## Competitive differentiation opportunities

The strongest differentiation themes are:

1. **Explainability** — every identity, finding, priority, and recommendation links to evidence, confidence, source, freshness, and limitations.
2. **Local-first privacy** — customer evidence can remain local without mandatory cloud upload.
3. **Operational simplicity** — installation, onboarding, maintenance, and interpretation must be approachable for homes and small businesses.
4. **Unified experience** — avoid fragmented consoles for inventory, vulnerability prioritization, findings, and remediation.
5. **Open standards** — use CPE, purl, SPDX, CycloneDX, CSAF, VEX, SSVC, STIX/TAXII, and transparent schemas.
6. **Open identity and fingerprint intelligence** — create a governed, provenance-preserving alternative to closed fingerprint corpora.
7. **Non-expert-safe communication** — translate evidence into clear actions without hiding uncertainty.
8. **Research and benchmark transparency** — publish methodology, datasets, failure examples, and limitations.

## Minimum viable outcome set

The research recommends that a practical home/SMB product first deliver:

- local passive discovery;
- optional, explicitly approved safe active discovery;
- evidence-backed device identification with visible confidence;
- local vulnerability and lifecycle enrichment;
- separate CVSS, EPSS, KEV, exposure, confidence, and priority fields;
- plain-language evidence-first findings;
- one unified console;
- local data storage;
- simple export and notification; and
- measurable accuracy and safety gates.

## Advanced outcomes

Later research-backed opportunities include:

- locally learned behavior baselines;
- topology and relationship mapping;
- freshness-gated attack-path hints;
- SBOM and VEX workflows;
- community-contributed fingerprint intelligence;
- air-gapped feed synchronization;
- guided remediation with verification; and
- AI-composed temporary drilldown workspaces from approved analytical components.

## Durable landscape findings

Key durable identifiers from the landscape study include:

- `EXT-RES-001` — universal timely NVD enrichment can no longer be assumed.
- `EXT-RES-003` — KEV is a high-signal exploitation input but covers only a small portion of CVEs.
- `EXT-RES-004` — EPSS is a daily exploitation-probability signal, not a risk score.
- `EXT-RES-005` — OSV and GHSA are strong open package-vulnerability inputs.
- `EXT-RES-009` — model injection robustness is surface- and safeguard-dependent and degrades under repeated attack.
- `EXT-RES-010` — vector and memory stores are poisoning targets and cannot be the authoritative system of record.
- `EXT-RES-014` — unverified AI-generated vulnerability reports create substantial maintainer burden.
- `EXT-RES-015` — hybrid discovery and multi-signal fingerprinting are established commercially.
- `EXT-RES-019` — the credible AI-triage pattern remains human-supervised and evidence-showing.
- `EXT-RES-021` — no open system was found that clearly delivers end-to-end hybrid discovery, identity merging, and calibrated confidence.
- `EXT-RES-022` — indirect prompt injection is a recurring production pattern.
- `EXT-RES-023` — an AI-credited CVE is not proof of fully autonomous discovery.

## Product decision boundary

The research supports emulating product outcomes rather than copying a vendor's branding, interface, or proprietary implementation. Any adopted capability must preserve:

- passive-first collection;
- evidence-first decisions;
- deterministic authority;
- local-first options;
- visible uncertainty;
- human approval for consequential actions;
- license compliance; and
- measurable accuracy and safety.
