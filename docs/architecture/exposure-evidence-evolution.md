# Exposure Evidence Evolution

**Status: Proposed design. Implementation and acceptance validation are pending.**

We will extend the existing asset, evidence, finding, advisory, workflow and
investigation boundaries to connect vulnerability observations to applicability,
exposure, mitigating controls and verified outcomes. These additions preserve
asset-first, passive-first, evidence-first and local-first operation. They do not
create another source of asset authority, a separate orchestration layer or a
model-owned risk engine.

## Evidence meanings

We will keep the following claims distinct in storage, explanations, dashboards
and exports. A stronger claim requires additional evidence; it does not follow
automatically from a weaker one.

| Claim | Meaning and required boundary |
| --- | --- |
| Vulnerability aggregation | We retain observations from multiple sources. Ingestion alone does not establish that records describe the same instance. |
| Applicability | We evaluate product, installed version, platform and configuration prerequisites for the specific subject. Missing prerequisites remain discovery needs. |
| Exposure correlation | We relate the affected component to an asset, service, endpoint and relevant path using dated evidence. A relationship is not proof of Internet reachability. |
| CVE-to-control correlation | We associate a specific vulnerability and subject with a relevant control mechanism, policy and scope. Control presence alone does not establish effectiveness. |
| Mitigation inference | Configuration and applicability support a reasoned assessment with explicit assumptions. We label this as inferred. |
| Observed prevention | Relevant telemetry shows a prevention event for a specific attempt, subject, path and time. Detection-only events and generic blocked traffic are insufficient. |
| Empirical testing | An authorized, bounded test records the method, conditions, result and limitations. A successful test supports only the tested scope and time. |
| Remediation verification | Comparable evidence demonstrates the intended change and the condition that resolves the finding. A completed work item alone is insufficient. |

The operational attention score will remain a prioritization aid. We will not
present it as a calibrated probability of compromise or treat a lower score as
proof that an exposure has been removed.

## Early advisory and applicability lifecycle

We will support an investigation record before a formal vulnerability identifier
or scanner detection identifier exists. It will retain stable native identity,
product and version assertions, configuration prerequisites, source evidence,
review state, effective time, revision history and withdrawal state. Identifier
aliases can be added later without inventing scanner coverage or creating a new
authoritative finding merely because an alias was assigned.

Reported, reviewed and withdrawn assertions will have explicit promotion rules.
A revision or withdrawal will supersede the relevant current assertion while
preserving its history. Late delivery, duplicate delivery and content changed
without a changed publication date must have deterministic handling. A reported
assertion cannot overwrite stronger reviewed evidence merely because it arrived
later. Withdrawal triggers reevaluation of dependent assessments; it does not
erase independently supported findings.

A product observation without a version can support inventory discovery and a
possible applicability assessment. It cannot establish an installed vulnerable
version. Product identity, version range, platform and configuration checks will
remain separately explainable, including which prerequisite needs collection or
demonstration. Confidence labels will not imply observed prevention or testing.

## Correlation, identity and counting

We will reconcile source records using scoped identifiers, component identity,
observation time and provenance. The same CVE on different components or assets
will remain separate exposure instances. When records are correlated, we will
retain their original evidence and the reason for the relationship. Conflicting
identifiers and reused addresses will enter review rather than force a merge.

DNS answers, provider dependencies, asset ownership and collection permission
will remain separate assertions. Sharing an address does not establish a shared
asset identity, ownership or authorization. Relationship history will retain its
subject, source, time, classification and limitations. A failed relationship
write must remain visible as incomplete attribution rather than a complete view.

Application findings will link to the exact service and endpoint when the
evidence supports that precision. A URL template or inferred association will be
explicitly labeled. URL hierarchy and endpoint linkage do not prove the route
through a firewall, address translation, load balancer or application control.

Every count will state its unit: observation, finding, component, service, host
or canonical asset. Totals across confidence tiers will use explicit set-union
semantics where a unique-subject count is intended. Overlapping tiers and
multiple ports must not silently inflate unique asset counts or make
classification changes look like a reduction in exposure.

## Mitigating controls and network paths

We will assess a control against the specific vulnerability, component, subject
and path. The assessment will retain mechanism, policy version, enforcement
mode, enabled state, exceptions, relevant evidence time and expiry. We will
distinguish blocking from detection, and include conditions that make the
assessment invalid or require reevaluation.

A firewall policy must apply to the relevant flow. An application control must
cover the affected endpoint and traffic. An endpoint control must address the
relevant behavior on the affected host. An installed product or an asset-level
passing status will not mitigate every vulnerability associated with that asset.

We will keep modeled connectivity separate from observed reachability. For a
public endpoint mapped to a private backend, the evidence must account for
address translation, listener and backend mapping, routing, control placement
and alternate paths within the assessment's scope. Missing topology remains a
validation need. No live production exploitation, new endpoint agent or policy
change is required by this design.

## Freshness and incomplete collection

We will extend existing advisory and collection health with distinct states for
last attempted retrieval, last successful validation/import, source-data age,
publication stagnation, never-initialized data and monitoring failure. Thresholds
will reflect each approved source's cadence and operational scope. A recently
received envelope can still contain old data.

Partial, failed, refused or stale collection will preserve the last supported
facts and expose their limitations. It cannot silently clear an affected finding
or promote an inference to a verified state. An intentionally disabled source
must remain distinguishable from a healthy enabled source.

## Work ownership and outcome verification

We will connect an exposure instance to an accountable owner, next action,
target date, work-item identity and verification requirements. Suppression,
accepted risk, mitigation and resolution will remain distinct decisions with
their own scope, evidence and review conditions.

Verification will compare the relevant before-and-after subject, component,
configuration and path. Policy changes, evidence expiry and contradictory
observations will reopen the appropriate assessment. Closing a ticket or losing
collection coverage will not resolve the underlying exposure.

## Access, audit and bounded investigation

We will apply object-scoped authorization to derived representations as well as
primary records: search results, exports, work-item views, investigation packets,
command payloads, logs and refused-import records. Masking must not leave a
secondary representation that exposes the protected evidence.

Operational activity and evidentiary lineage will retain their separate
purposes. Audit records will have controlled append and retention boundaries;
ordinary application actions must not silently rewrite their history. Failures
to preserve required audit evidence must be visible.

Investigation will use bounded, versioned evidence packets and typed outputs
under the existing coordinator and policy boundary. Packets will declare
redaction, omitted records, truncation, evidence identity and the evaluated
snapshot. Conclusions will retain supporting observations and rule versions,
without depending on private model reasoning. Unsupported or rejected claims
remain reviewable; model text cannot authorize a state transition. Independent
challenge checks will test the evidence and deterministic acceptance conditions.
Late, canceled and duplicate results cannot silently change authoritative state.

## Acceptance demonstrations

We will use synthetic fixtures and approved read-only evidence before proposing
runtime delivery. These are planned demonstrations, not reported test results.

| Demonstration | Required outcome |
| --- | --- |
| Advisory arrives before a formal or scanner identifier; version/configuration is missing | The investigation remains visible, with unmet prerequisites; no fabricated affected finding or scanner coverage. |
| Revision, withdrawal and delayed replay conflict | Deterministic current state and retained history; no weaker late assertion replacing stronger evidence. |
| Two sources report the same asset; one CVE affects two components | Supported reconciliation without losing source records or collapsing distinct exposure instances. |
| One asset has several services and overlapping confidence tiers | Explicit count units and unique-subject unions; no summed overlap presented as unique assets. |
| Shared DNS address rotates; endpoint attribution persistence fails | No unsupported identity/ownership/permission promotion; incomplete relationship evidence is visible. |
| A firewall, application control or endpoint control exists outside the relevant enforcement scope | Control presence remains distinct from mitigation and observed prevention. |
| Public endpoint maps to a private 10.x backend | The assessment exposes supported path evidence and missing topology without claiming unobserved reachability. |
| Fresh import contains old data; collection or monitoring fails | Data age and failure remain visible; prior affected state is not falsely cleared. |
| A completed work item leaves the affected component unchanged | Exposure remains unresolved pending comparable verification. |
| A restricted user requests derived views or investigation output | Unauthorized objects remain inaccessible in every representation, including rejected records and logs. |
| An injected assertion or late/canceled result reaches investigation review | Evidence and deterministic gates prevent unsupported authoritative changes. |

## Delivery sequence and decision gate

1. We will define fixtures, expected states and evidence contracts against the
   current canonical data model.
2. We will review the design alongside existing relationship, snapshot, workflow
   and investigation proposals, consolidating overlapping requirements.
3. We will validate applicability, correlation and freshness before extending
   control/path assessment and outcome verification.
4. We will propose narrowly scoped implementation work only after architecture,
   source eligibility, permission and acceptance requirements are satisfied.

This document approves no runtime change. Acceptance requires demonstrated
improvement in correlation accuracy, evidence completeness and analyst decisions,
with no unsupported finding closure, permission expansion or model authority.
