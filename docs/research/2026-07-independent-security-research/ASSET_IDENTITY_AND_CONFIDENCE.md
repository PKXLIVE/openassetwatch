# Asset Identity Resolution, Evidence Fusion, and Confidence

## Status

Independent research input. Not an implementation commitment.

## Core conclusion

No single observable identifier remains stable, unique, and difficult to spoof across the full lifecycle of IT, mobile, cloud, virtual, IoT, and OT assets. A defensible asset-intelligence platform must fuse multiple independent, provenance-tagged signals and maintain identity as a time-aware, correctable hypothesis rather than a permanent single-key lookup.

The recommended pattern is hybrid:

- deterministic matching on strong cryptographic, hardware-rooted, or authority-issued identifiers;
- probabilistic record linkage over supporting and weak signals;
- graph clustering with explicit protection against transitive over-merging;
- calibrated confidence rather than an unvalidated 0–100 score;
- reversible human-reviewed merge and split workflows; and
- bitemporal, append-only history with downstream re-evaluation of findings after identity correction.

## Evidence hierarchy

### Primary identity evidence

Primary evidence may establish identity when it is authenticated and uncontradicted:

- IEEE 802.1AR IDevID or equivalent cryptographically bound client identity;
- TPM-backed attestation using an Attestation Key or privacy-preserving attestation path;
- provider-issued cloud resource IDs;
- hypervisor or orchestrator IDs within their valid lifecycle scope;
- hardware-attested serial number or UUID;
- managed EDR or MDM agent identity while the installation remains valid;
- authenticated client certificates; and
- authoritative asset-management records with a trusted source and reconciliation policy.

A hard contradiction between two valid primary identifiers must block or split a merge regardless of agreement among weaker signals.

### Supporting evidence

Supporting signals corroborate identity but should not independently establish it in high-impact decisions:

- DHCP client identifier and DHCP fingerprint;
- LLDP/CDP topology;
- authenticated SNMP identifiers;
- BIOS or board identifiers;
- OS machine identifiers when not cloned;
- installed-software sets;
- TLS or JA4-family fingerprints;
- service banners;
- network and protocol behavior;
- switch, router, wireless-controller, or cloud relationship observations; and
- longitudinal co-occurrence.

### Weak evidence

Weak evidence is contextual, churn-prone, spoofable, or type-level only:

- IP address;
- hostname, FQDN, mDNS, or NetBIOS name;
- OUI alone;
- randomized or locally administered MAC address;
- HTTP User-Agent;
- open-port combinations;
- model or firmware string without stronger binding;
- passive behavioral fingerprints used as an instance identifier; and
- device-display names supplied by users or untrusted systems.

### Disqualifying evidence

Examples that should prevent an automatic merge include:

- different valid IDevIDs;
- different authenticated TPM identities;
- different cloud provider resource IDs for simultaneously existing resources;
- evidence that a UUID or machine ID came from a cloned image;
- cross-tenant scope conflict;
- incompatible physical location or lifecycle overlap; and
- a primary identity that was revoked, retired, or replaced.

## Asset-type guidance

### IT endpoints and servers

Prefer TPM/IDevID, managed-agent ID, hardware serial/UUID, and machine identity. Use hostname, IP, software set, and DHCP only as supporting evidence. Reimaging and cloned images require explicit lifecycle handling.

### Mobile and BYOD

Prefer MDM or platform attestation where available. Per-network or per-connection randomized MAC addresses must not be used for cross-network tracking. A privacy-respecting system may accept type-level continuity rather than attempting persistent personal-device tracking.

### IoT

Strong anchors are often absent. Use multi-signal type and model hypotheses from DHCP, mDNS, SSDP, TLS, OUI, behavior, and protocol evidence. Avoid claiming instance-level certainty without authenticated identifiers.

### OT

Prefer engineering records, serial or asset tags, protocol identity, and topology. Long silence must not imply decommissioning. Fragility limits active confirmation, so the system must preserve unknown states and lower confidence without declaring absence.

### Cloud

Provider resource IDs are authoritative for a specific resource instance but are lifecycle-scoped. Recreated resources may represent a new instance of the same logical service, so instance identity and service identity must remain distinct.

### Virtual machines and containers

Use hypervisor or orchestrator identifiers and agent identity. Shared SMBIOS UUIDs and machine IDs from cloned images are dangerous false-merge signals. Short-lived workload identity should not be confused with the logical application or service.

## Resolution pipeline

A scalable identity resolver generally follows:

1. **Blocking or candidate generation** — select plausible record pairs without quadratic comparison.
2. **Deterministic exclusions** — enforce tenant, lifecycle, primary-identifier, and impossible-overlap constraints.
3. **Pairwise matching** — compute evidence-aware match likelihood using source reliability, agreement, contradiction, and freshness.
4. **Clustering** — form assets while protecting against weak-link merge cascades.
5. **Canonicalization** — select current attributes using per-field source precedence without deleting source observations.
6. **Human review** — approve ambiguous or high-impact merges and splits.
7. **Downstream re-evaluation** — update vulnerability, finding, risk, and remediation assignments after identity changes.

## Recommended method

The research favors:

- exact deterministic matching for primary identifiers;
- Fellegi–Sunter or Bayesian match weighting for supporting and weak signals;
- source reliability and authentication weights;
- graph or correlation clustering with limits on transitive closure over weak edges;
- conservative auto-merge thresholds;
- human review near the threshold or for high-impact assets; and
- reversible operations recorded as events.

A chain of weak pairwise matches must not automatically collapse multiple assets into one. False merges are generally more dangerous than false splits because a false merge can assign the wrong vulnerabilities, inherit a patched state, or suppress a real finding.

## Confidence model

Identity confidence should account for:

- count of independent signals;
- strength class of each signal;
- agreement and contradiction;
- evidence freshness and time decay;
- observation frequency;
- source and sensor reliability;
- collector authentication;
- directly observed versus inferred values;
- spoofability;
- asset type;
- lifecycle context;
- human validation; and
- previous merge or split history.

The output should combine:

- a calibrated probability or interval where sufficient labeled data exists;
- an operator-facing evidence band such as Confirmed, Probable, Possible, or Unconfirmed;
- a visible evidence-completeness indicator; and
- an explanation of the strongest evidence and unresolved contradictions.

An uncalibrated 0–100 confidence value must not be presented as a probability.

## Calibration

Recommended evaluation includes:

- reliability diagrams;
- Brier score;
- log loss where appropriate;
- Expected Calibration Error with bin count disclosed;
- Platt or isotonic recalibration;
- scenario-specific calibration for IT, mobile, IoT, OT, cloud, and virtual assets; and
- held-out data that reflects IP churn, MAC randomization, reimaging, cloning, and silence.

ECE alone is insufficient because it is bin-sensitive and can be gamed. It should be paired with a proper scoring rule and visible reliability plots.

## Missing evidence and conflict

The model must distinguish:

- **unknown** — no evidence is available;
- **agree** — independent evidence supports the same identity;
- **disagree** — evidence conflicts;
- **stale** — evidence may once have been valid but no longer reflects current state; and
- **invalidated** — a lifecycle event or primary contradiction makes the evidence unusable.

Missing evidence is ignorance, not disagreement. A silent device is not necessarily absent. A missing agent does not prove replacement. A missing version does not prove a vulnerability is inapplicable.

## Time and history

Use bitemporal history:

- valid time records when the observation was true in the environment;
- transaction time records when the platform learned or corrected it.

Weak signals should decay according to their lifecycle:

- IP and lease-bound data: short half-life;
- randomized MAC: scoped to network or connection;
- behavioral fingerprints: sliding windows and drift monitoring;
- strong hardware or cryptographic anchors: no time decay, but explicit revocation, decommission, re-provisioning, or ownership-change events.

## Merge, split, and correction governance

A safe workflow should:

1. Auto-merge only on uncontradicted primary agreement above a calibrated threshold.
2. Recommend human-reviewed merges when supporting signals are persuasive but primary evidence is absent.
3. Block merges on primary contradiction.
4. Preserve all source records and provenance.
5. Make every merge reversible.
6. Split assets when later evidence proves they were distinct.
7. Record reason, evidence, actor, and timestamps.
8. Preserve historical links rather than deleting prior state.
9. Re-run affected classification, vulnerability matching, findings, risk, and remediation logic after correction.
10. Reopen, reassign, withdraw, or supersede dependent findings as required.

## Privacy requirements

- Respect MAC randomization and do not defeat it to track personal devices across networks.
- Avoid retaining full personal-device identifiers longer than operationally necessary.
- Use pseudonymization or hashing where full values are unnecessary.
- Treat TPM Endorsement Keys as privacy-sensitive permanent identifiers; prefer attestation keys, Privacy CA patterns, or Direct Anonymous Attestation.
- Isolate identity graphs by tenant and site.
- Authenticate collectors before granting their identity evidence a strong weight.
- Document why persistent identity is necessary and provide user controls for personal devices.

## Security threats

The identity subsystem must account for:

- MAC cloning;
- hostname and banner manipulation;
- reused certificates;
- adversarial behavioral mimicry;
- poisoned inventory feeds;
- malicious collectors;
- confidence inflation through many weak signals;
- cross-tenant collisions;
- suppression attacks through false merging; and
- incorrect inheritance of patch or VEX status.

## Evaluation

Report separately:

- pairwise precision, recall, and F1;
- cluster precision and recall;
- B-cubed precision, recall, and F1;
- false-merge and false-split rates;
- over-merge and under-merge rates;
- identity stability;
- time to correct;
- confidence calibration;
- human review burden;
- accuracy under IP churn and MAC randomization;
- performance on silent assets;
- clone and reimage handling; and
- downstream finding-correction accuracy.

B-cubed is a strong default clustering metric because it penalizes both impure merged clusters and fragmented true clusters without the large-cluster bias of some pairwise metrics.

## Durable findings

- `ID-RES-001` — multi-signal fusion is mandatory.
- `ID-RES-002` — Fellegi–Sunter provides a principled probabilistic backbone.
- `ID-RES-003` — blocking is required for scalable entity resolution.
- `ID-RES-004` — confidence calibration is non-negotiable.
- `ID-RES-005` — hardware and cryptographic anchors are strongest but sparse.
- `ID-RES-006` — TPM identity introduces privacy obligations.
- `ID-RES-007` — MAC randomization defeats cross-network MAC identity.
- `ID-RES-008` — cloned image identifiers must not establish identity.
- `ID-RES-009` — bitemporal event history is required for correction and audit.
- `ID-RES-010` — missing evidence is not negative evidence.
- `ID-RES-011` — identity corrections must re-evaluate dependent findings.
- `ID-RES-012` — transitive over-merging is a primary failure mode.
- `ID-RES-013` — naive evidence combination fails under high conflict.
- `ID-RES-014` — IoT fingerprinting evidence is usually type-level, not instance-level.
- `ID-RES-015` — vendor deduplication claims are not accuracy evidence.
- `ID-RES-019` — passive fingerprints are inference signals rather than identity proof.
- `ID-RES-020` — hybrid deterministic, probabilistic, graph, and human governance is the recommended architecture.
