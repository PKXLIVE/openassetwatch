# CTEM Repository Knowledge Map

**Status:** Research and planning index. Not an architecture decision and not
an implementation claim.

- **Repository baseline:** `origin/main` at `07c4b9e` (2026-11-24; `main` then gained #189, documentation only), plus the
  decision layer added on this branch. Since the work-tracking merge (#190),
  `main` gained a packaging fix (#192), dependency and CI updates (#188, #193,
  #194), a template change (#191), and three architecture documents (#169
  defensive content and adversarial input, #171 dashboard composition, #175
  asset intelligence and decision-integrity gaps). None adds a migration.
- **Open proposals reviewed:** none remain open. PRs #169, #171, #175, and #189
  have merged. The #189 document (`docs/architecture/exposure-evidence-evolution.md`)
  still labels itself a proposed design, so its capabilities stay **proposed** here.
- **Capability gaps:** [CTEM_CAPABILITY_GAP_SYNTHESIS.md](CTEM_CAPABILITY_GAP_SYNTHESIS.md).

This map records which repository sources inform continuous threat exposure
management (CTEM) planning, what each capability's real status is, and where
sources conflict. Use it before deciding that a capability is missing.

## How sources were ranked

When sources disagree, this order applies:

1. current implementation and tests on `main`;
2. accepted architecture decisions (`docs/architecture/decisions/`);
3. newer committed design and research documentation;
4. older planning documents;
5. open pull requests, as proposals only.

## What was swept

- All 128 files under `docs/` on `main`, `README.md`, `configs/` (the
  `configs/skills/` namespace holds only `.gitkeep`), the backend
  (`backend/app/`, 55 test modules), the Go agent, sensor and CLI
  (`internal/`, `cmd/`, 47 Go test files), the Python collector, and the static
  web console.
- `docs/ctem/`, `docs/design/`, and `docs/security/` did not exist before this
  map. Security design lives in `docs/ai-security/` and `docs/architecture/`.
- Commit history of `docs/` from PR #119 through PR #190.
- Keyword search across docs and code for every term in the sweep request.
  `CTEM`, `exposure management`, `control effectiveness`, and
  `application inventory` occur nowhere on `main` or in any open PR. Before
  this map, no CTEM-framed analysis had been committed.

## Capability status

Status meanings: **implemented** (code and tests on `main`), **partial**,
**designed** (accepted direction, no runtime), **proposed** (a design that labels itself proposed, or an open PR),
**research-only**, and **missing**. CTEM stages are noted for orientation.

| Capability | Status | Implementation and tests | Design and research sources |
| --- | --- | --- | --- |
| Scope boundary per site | implemented | `site_id` on every evidence, finding, and risk record | `PRODUCT_ARCHITECTURE.md` (deployment identity) |
| Verified external scope registry (scoping) | designed | none | ADR-0002 AD-02; `external-intelligence-enrichment-roadmap.md` |
| Endpoint inventory, native software (discovery) | implemented | `internal/collector/`, `internal/agent/`, `canonical_ingestion*.py`, migration 0004; `test_native_software_collection.py`, `test_endpoint_agent_*` | `NATIVE_SOFTWARE_COLLECTION.md`, `ENDPOINT_AGENT_IDENTITY.md`, `CANONICAL_INGESTION_COMPATIBILITY.md` |
| Passive network discovery | implemented | `internal/sensor/`; sensor enrollment and check-in tests | `PASSIVE_SENSOR_MVP.md`, `SENSOR_ENROLLMENT.md` |
| Asset classification and evidence fusion | implemented | `classification*.py`; `test_classification*.py` | `ASSET_CLASSIFICATION_AND_EVIDENCE_FUSION.md` |
| Asset identity, reversible merge and split | partial (conflicts become findings; no merge/split) | `identity-conflict` rule in `findings.py` | ADR-0001 DR-04, DR-05; `research/.../ASSET_IDENTITY_AND_CONFIDENCE.md` |
| Asset presence, field authority, relationship ledger | designed | none | PR #175 (merged): `docs/architecture/asset-intelligence-stack-gap-additions.md` |
| Software and firmware normalization; version matching | implemented (firmware with limits) | `component_*`, `version_intelligence.py`, `vulnerability_matching.py`; `test_vulnerability_matching.py` | `SOFTWARE_AND_VULNERABILITY_INTELLIGENCE.md`; `research/.../IOT_OT_FIRMWARE_INTELLIGENCE.md` |
| End-of-life (EOL) lifecycle data | research-only | none | ADR-0001 DR-06; `SOURCE_LICENSING_REGISTRY.md` |
| KEV | implemented | `kev_*.py`, `known-exploited` AI tool; `test_kev_*` | known-exploited prioritization document in `docs/` |
| EPSS | designed | none | ADR-0001 DR-03, DR-06; `EXPLAINABLE_RISK_DECISION_MODEL.md` |
| Signed advisory feeds and offline mirror | implemented | `advisory_*.py`, `osv_pypi_*`; `test_advisory_*` | `TRUSTED_ADVISORY_FEEDS.md`, `ADVISORY_MIRROR.md` |
| Deterministic findings (10 rules) | implemented | `findings.py`, `finding_store.py`; `test_findings*.py` | `DETERMINISTIC_FINDINGS_AND_RISK.md` |
| Operational Attention Score `oaw.risk.v1` (prioritization) | implemented | `risk.py`; `test_risk.py` | ADR-0001 DR-01; `DETERMINISTIC_FINDINGS_AND_RISK.md` |
| Action bands and decision record `oaw.decision.v1` | implemented (v1; no Act Now rule yet) | `decisions.py`, `decision_store.py`, migration 0006; `test_decisions.py`, `test_decision_api.py`, gated decision database tests | ADR-0001 DR-02, DR-03; `EXPLAINABLE_RISK_DECISION_MODEL.md`; `docs/ctem/CTEM_DECISION_LAYER.md` |
| Exposure state per finding | designed (defaults to `unknown`) | none | `EXPLAINABLE_RISK_DECISION_MODEL.md` (exposure state); PR #189 |
| Asset importance and business services | designed | none | `EXPLAINABLE_RISK_DECISION_MODEL.md` (asset importance); `itsm-cmdb-enrichment-roadmap.md` |
| External exposure, Certificate Transparency, passive DNS | designed | none | ADR-0002 (AD-01 to AD-10) |
| Internet-facing reachability, attack paths | research-only | none | `research/.../EXPLAINABLE_RISK_AND_REMEDIATION.md`; `LANDSCAPE_AND_PRODUCT_BENCHMARK.md` (freshness-gated attack-path hints) |
| Compensating controls, control effectiveness | proposed | none | PR #189; `EXPLAINABLE_RISK_DECISION_MODEL.md` (remediation guidance) |
| Temporal baselines and deviations | implemented (context only) | `temporal_*.py`; `test_temporal*.py` | ADR-0003 AIT-10 to AIT-12; `TEMPORAL_*.md` |
| Finding resolution on fresh affirmative evidence (validation) | implemented | `finding_store.reconcile`; resolve/reopen tests | `DETERMINISTIC_FINDINGS_AND_RISK.md` |
| Remediation verification (before and after) | proposed | none | PR #189; ADR-0001 (REM-VERIFY-001 in the gap matrix) |
| Active validation, empirical testing | missing by design | none | ADR-0001 invariant 3 and DR-08; PR #189 limits it to authorized bounded tests |
| Manual work tracking: status, unverified owner, references (mobilization) | implemented | `finding_work_*.py`, migration 0005; `test_finding_work_*` | `FINDING_WORK_TRACKING.md` |
| Verified ownership (directory, CMDB) | designed | none | `identity-directory-enrichment-roadmap.md`, `itsm-cmdb-enrichment-roadmap.md` |
| Suppression with expiry | implemented (single finding) | `finding_store.suppress`; `test_findings_api.py` | `DETERMINISTIC_FINDINGS_AND_RISK.md` |
| Risk acceptance and VEX | designed | none | ADR-0001 DR-07; PR #175 exception ledger (merged): `docs/architecture/decision-integrity-and-evidence-snapshot-gaps.md` |
| Ticketing and outbound projection | designed | none | `connector-playbook-projection-architecture.md` |
| Service-level deadlines and escalation | designed (case scope only) | none | `security-investigation-case-operations.md` (`sla_due_at`) |
| Scanner result ingestion | designed | none | `vulnerability-scanner-enrichment-roadmap.md` |
| Cloud, container, identity, IoT/OT inventories | designed; IoT/OT passive classification partial | classification vendor catalog | `smb-asset-intelligence-product-direction.md`; identity, PAM, ITSM roadmaps; IoT/OT research |
| Application inventory | missing | none | none |
| Dashboards (fixed) | implemented | `backend/app/static/`, Control Tower endpoints | `CONTROL_TOWER_DEPLOYMENT.md` |
| Adaptive dashboards and semantic metrics | designed | none | ADR-0001 DR-13 to DR-15; ADR-0008 and `docs/architecture/dashboard-composition-skill-pack.md` (PR #171, merged) |
| Evidence quality and freshness | implemented per finding; source health partial | `evidence_freshness`, sensor and asset staleness rules | PR #189 (source freshness states) |
| AI Advisor, read-only tools | implemented | `ai_advisor.py` (`ReadOnlyHubTools` allowlist); `test_ai_advisor.py` | `architecture/ai-advisor*.md`; `docs/ai-security/` |
| Skill Packs | designed | `configs/skills/` reserved and empty | `skill-pack-contract.md`; ADR-0003 AIT-07 |
| Multi-agent investigation | designed | none | ADR-0003; `agent-investigation-control-loop.md` |

## Recorded conflicts

| ID | Conflict | Treatment |
| --- | --- | --- |
| `KM-C01` | The project documentation rule is stricter than ADR-0004. ADR-0004 bars research-source branding from canonical architecture. The owner rule bars external product, vendor, platform, and project names from **all** committed documentation, filenames, headings, identifiers, code comments, commit messages, and pull requests. | The owner rule applies. CTEM documents record what was learned as OpenAssetWatch capabilities and never identify the source. Research provenance stays in uncommitted working notes. |
| `KM-C02` | `RESEARCH_INTEGRATION_AND_ARCHITECTURE_GAP_MATRIX.md` assessed snapshot `76321ce` (July 2026). Its statuses predate KEV (#160), versioned migrations (#162), endpoint identity (#163), canonical ingestion (#166), temporal intelligence (#168, #174, #179), native software (#170), and work tracking (#190). For example, it lists KEV (`EXT-RES-003`) as partial, although KEV prioritization is now implemented. | Implementation wins. The matrix needs a refresh. This map uses current code. |
| `KM-C03` | PR #189 proposes linking an exposure to an owner, next action, **target date**, and work item. Implemented work tracking v1 deliberately excludes dates and SLA. | Not a contradiction: #189 is a proposal and v1 is a subset. Target dates should wait until action bands exist. |
| `KM-C04` | Some already-committed documents name external products. Examples are the July research benchmark under `docs/research/2026-07-independent-security-research/`, `PRODUCT_ARCHITECTURE.md`, ADR-0002 (AD-08 provider sequence), and the scanner and ITSM roadmaps. This conflicts with the owner documentation rule (`KM-C01`). | Recorded, not changed here. Cleaning up existing documents is a separate follow-up that needs owner review, because some names may be part of licensing or source-registry decisions. Some existing repository filenames also embed external organization or project names; this map describes those files instead of naming them. |
| `KM-C05` | Earlier task wording referred to manual work tracking as an external-capability "gap #2". No committed document defines that numbering. | The numbering is not authoritative. The gap synthesis assigns stable `CTEM-GAP-*` identifiers. Manual work tracking is implemented (#190). |
| `KM-C06` | `docs/EXPLAINABLE_RISK_DECISION_MODEL.md` and `docs/architecture/EXPLAINABLE_RISK_DECISION_MODEL.md` share a name. | Not a conflict: the `architecture/` file is a pointer to the canonical copy. |
| `KM-C07` | Migration version 5 is `0005_finding_work_tracking.sql` on `main`, and this branch adds version 6 (`0006_finding_decision_layer.sql`). An untracked `0005_ai_control_tower_foundation.sql` was reported in another worktree. | That migration must renumber to the next free version before it can land. If another version-6 migration lands first, the decision layer must renumber instead. |
| `KM-C08` | ADRs 0005 to 0008 are on `main` (PRs #169 and #171). | No collision. The decision layer needs no new ADR because it implements ADR-0001 DR-01 to DR-03. The next CTEM ADR, if one is needed, is 0009. |

## Sources behind each major CTEM decision

| CTEM planning decision | Informed by |
| --- | --- |
| Prioritization stays deterministic, explainable, and separate from AI | ADR-0001 invariants 1 and 2, DR-01 to DR-03; `EXPLAINABLE_RISK_DECISION_MODEL.md`; `risk.py`; `ai_advisor.py` read-only allowlist |
| Exposure is evidence-derived; missing evidence is `unknown` | `EXPLAINABLE_RISK_DECISION_MODEL.md` (exposure state); ADR-0002 invariant 12; PR #189 |
| Discovery stays passive-first; no active scanning or retest | ADR-0001 invariant 3, DR-08; `PRODUCT_ARCHITECTURE.md` non-goals; `SECURITY_TOOL_POLICY.md`; `collector-policy-and-bundles.md` |
| External attack surface is additive, scope-verified, read-only | ADR-0002; `external-intelligence-enrichment-roadmap.md` |
| Work completion never resolves a finding | `FINDING_WORK_TRACKING.md`; `finding_work_store.py`; gated finding-work database tests; PR #189 |
| Exceptions, accepted risk, and VEX stay separate from suppression | ADR-0001 DR-07; `EXPLAINABLE_RISK_DECISION_MODEL.md` (risk acceptance section); PR #175 |
| Control presence is not mitigation | PR #189 (mitigating controls) |
| Metrics state their unit; missing is not zero | PR #189 (counting); ADR-0001 DR-15; July research, adaptive dashboards |
| Vulnerability sources need licensing approval | ADR-0001 DR-05a, DR-06; `SOURCE_LICENSING_REGISTRY.md` |
| Native design, no copied product branding or code | ADR-0004; `NO_EXTERNAL_REFERENCE_POLICY.md`; `LICENSE_POLICY.md` |

## Confirmed missing

No implementation, accepted design, or open proposal exists for:

- application inventory;
- program-level outcome metrics (time to remediate, verification rate);
- tamper-evident chaining of audit or work events;
- rule-based asset groups or saved scopes beyond sites;
- a scoped review cycle (charter, exclusions, success criteria).

These are evaluated in the gap synthesis. Everything else in the capability
table has prior repository work that new design must extend, not replace.

## Maintenance

Refresh this map when `main` changes a capability's status, when an open
proposal merges or closes, or when a new ADR lands. Re-run the keyword sweep
against the new baseline rather than editing statuses from memory.
