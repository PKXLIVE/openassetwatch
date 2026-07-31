# Explainable Risk Prioritization and Guided Remediation

## Status

Independent research input. The second-pass remediation audit controls corrections to BOD 26-04 naming and interpretation, NIST OT-scanning citations, FDA guidance currency, and corrected research figures.

## Core conclusion

A security platform should not collapse cyber risk into one opaque AI-generated number. It should compute and display distinct evidence-backed constructs, use transparent decision rules to determine action priority, and treat a prioritized finding as the beginning of a decision process rather than permission to execute a change.

The authoritative pattern is:

```text
validated finding evidence
  -> severity
  -> exploitation signals
  -> local exposure and consequence
  -> transparent action band
  -> separate confidence
  -> guided remediation options
  -> human decision
  -> deterministic execution outside AI
  -> independent verification
```

## Keep these constructs separate

### Finding severity

Technical severity describes the inherent technical characteristics of the vulnerability. CVSS Base is a severity measure, not risk and not a complete patch-priority system.

### Exploit likelihood

EPSS is a daily probability that exploitation attempts will be observed in a future time window. It does not account for the user's environment, business impact, safety, or compensating controls.

### Known exploitation

CISA KEV records credible evidence that a vulnerability has been exploited in the wild and that a clear remediation action exists. Absence from KEV is not proof of safety.

### Exposure and reachability

Exposure asks whether an attacker can reach the vulnerable component through the internet, internal network, identity path, application path, or another asset.

### Consequence and asset importance

Consequence includes data, business, operational, mission, environmental, and physical-safety impact. OT and cyber-physical systems may require safety and availability to dominate the decision even when CVSS is moderate.

### Urgency

Urgency expresses time sensitivity. It is driven by exploitation evidence, reachability, automatability, technical control, and consequence.

### Confidence

Confidence expresses the quality, completeness, freshness, and agreement of the evidence. It is not risk and must remain visible alongside risk or priority.

### Remediation value

Remediation value expresses the expected benefit of an action relative to effort, cost, downtime, reversibility, and the number of assets or attack paths improved. It informs sequencing and should not be multiplied into a risk score.

## Explicit anti-pattern: EPSS multiplied by CVSS

FIRST guidance warns that multiplying a calibrated probability by an ordinal severity score produces a number without interpretable probabilistic meaning. CVSS, EPSS, KEV, exposure, importance, confidence, urgency, and remediation value should remain separate inputs to a transparent decision process.

## Recommended decision spine

The research favors an SSVC-style decision spine because prioritization is a decision that should be repeatable, reviewable, and explainable.

Useful decision inputs include:

- exploitation evidence: none, public proof of concept, or active exploitation;
- asset exposure: small, controlled, or open;
- automatability;
- technical impact: partial or total;
- mission importance;
- public-well-being or safety impact; and
- compensating controls as verified context.

Outcome bands can use standards-aligned internal labels:

- `Track`
- `Track*`
- `Attend`
- `Act`

A user-facing product may translate them into clearer language such as Monitor, Plan, Prioritize, and Act Now while preserving the standards mapping.

## BOD 26-04 research correction

The remediation audit confirms:

- The correct title is **Prioritizing Security Updates Based on Risk**.
- The directive was issued June 10, 2026.
- It supersedes BOD 19-02 and BOD 22-01.
- It prioritizes using public exposure, KEV status, automatability, and technical impact.
- The primary mechanism is an SSVC-informed combination matrix, not a simple count of how many criteria are true.
- The worst combinations require very rapid remediation and forensic triage.
- Unknown exposure is treated conservatively rather than as safe.
- Missing enrichment does not remove the requirement to act.

Federal deadlines are a reference example rather than an automatic service-level objective for homes or small businesses. The underlying decision logic is more reusable than the federal operational timelines.

## Missing evidence

The golden rule is:

> Missing evidence reduces confidence and may trigger verification or escalation. It must never silently lower risk or prove that a condition is absent.

Examples:

- Unknown version blocks product-specific patch instructions.
- Unknown exposure must remain unknown or be treated conservatively for prioritization.
- Missing KEV membership does not prove no exploitation.
- Missing agent data does not prove a device is unmanaged or absent without corroboration.
- Missing attack-graph edges do not prove no path exists.
- Missing VEX does not prove affected or not affected.

## Recommendation structure

A guided recommendation should contain separate fields for:

1. finding and asset references;
2. evidence supporting identity, version, and exposure;
3. evidence confidence;
4. action band and urgency;
5. recommended action;
6. alternative actions or compensating controls;
7. prerequisites;
8. required skill and authorization;
9. reversibility;
10. expected downtime;
11. safety or operational-impact flag;
12. expected risk reduction;
13. verification method and verification tier;
14. rollback plan;
15. stop conditions;
16. escalation criteria; and
17. official source citations.

Product-specific instructions must be tied to confirmed product identity, hardware revision, and version and should cite current official vendor documentation. The AI may summarize the procedure but must not invent commands or steps.

## Remediation types

The research covers:

- software patching;
- firmware updating;
- device replacement or retirement;
- configuration correction;
- service disabling;
- credential and certificate rotation;
- network segmentation;
- firewall or remote-access restriction;
- isolation;
- enhanced monitoring;
- compensating controls;
- risk acceptance;
- vendor escalation;
- incident-response escalation;
- evidence gathering;
- verification; and
- rollback.

Each action has different reversibility, downtime, safety, authorization, and evidence requirements.

## Evidence prerequisites

### Software patch

Require confirmed product and version, patch applicability, current backup or recovery option, dependencies, and change authority.

### Firmware update

Require exact hardware revision, current firmware, stable power, backup where available, maintenance window, and official vendor procedure. Wrong-revision firmware can brick a device.

### Configuration change

Require current configuration capture, dependency mapping, rollback, and change authority.

### Network restriction or isolation

Require traffic-flow evidence, device role, business owner, safety dependencies, and a least-disruptive proposed control.

### Replacement or retirement

Require owner, data-handling and sanitization requirements, replacement plan, dependencies, and approval.

### Risk acceptance or VEX suppression

Require named approver, scope, justification, supporting evidence, expiration, compensating controls, and revalidation triggers.

## Patch, eviction, and trust restoration

These are three different goals:

1. **Remove the vulnerability** — patch or mitigate the entry path.
2. **Remove the attacker** — evict persistence, invalidate sessions, and rotate credentials in the correct sequence.
3. **Restore trust** — rebuild or independently verify the system and dependent services.

A patch does not automatically remove stolen credentials, created accounts, web shells, cloud permissions, service-side persistence, or malicious sessions.

For high-risk known-exploitation cases, evidence may need to be preserved before patching or reimaging. The remediation audit confirms CISA guidance that patching can jeopardize the availability of forensic artifacts.

## Verification

Completion evidence should be graded from weaker to stronger:

1. self-attested;
2. collector-observed;
3. network-observed;
4. vendor-confirmed; and
5. qualified human-confirmed.

A ticket closure is not proof that risk is removed. Verification should test the corrected state or show that the original vulnerable condition, exposure, or attack path no longer applies.

Examples:

- patch: version read-back or rescan;
- firmware: build or firmware confirmation;
- service closure: network observation;
- exposure removal: external or path-based re-evaluation;
- configuration: read-back from an authoritative source;
- segmentation: validated flow behavior;
- certificate: chain and endpoint validation;
- compensating control: evidence that it blocks the relevant path;
- vulnerability not applicable: scoped, reviewed VEX plus supporting evidence; and
- device replacement: updated inventory and sanitization record.

Finding closure should require verification above self-attestation for security-relevant cases.

## VEX and risk acceptance

VEX is an assertion about whether a product is affected, not proof by itself.

Common states include:

- `not_affected`
- `affected`
- `fixed`
- `under_investigation`

A `not_affected` assertion should require a recognized justification or impact statement and should be:

- bound to the exact product, variant, version, and artifact;
- source- and issuer-traceable;
- signed or otherwise provenance-protected where possible;
- reviewed similarly to risk acceptance;
- time-bounded;
- revalidated on product, build, advisory, or evidence change; and
- challenged when runtime evidence contradicts it.

Unchecked internal VEX can become suppression laundering that makes real findings disappear.

## OT and unpatchable systems

For OT, cyber-physical, and other high-availability devices:

- safety and availability can outrank confidentiality;
- passive evidence is preferred;
- patching may require vendor support or a planned outage;
- active scanning may be unsafe;
- safety-certified configurations may not permit routine changes;
- compensating controls may be the only near-term option;
- segmentation, conduits, remote-access control, allowlisting, and passive monitoring may reduce risk;
- accepted risk must be documented, expiring, and linked to replacement planning; and
- any physical-world or safety-impacting action requires human and operational approval.

The remediation audit corrected the NIST citation to SP 800-82 Rev. 3 Appendix E.2 rather than Section 6.2.1 and replaced a vendor paraphrase with NIST's more measured active-scanning language.

## Human approval

A useful consequence model is:

- **Read and analyze** — autonomous when deterministically scoped.
- **Low-impact reversible administrative action** — may be automated with logging only after explicit product policy approval.
- **Consequential but reversible-with-effort** — human approval required.
- **High-consequence, irreversible, identity, credential, endpoint isolation, OT, or physical action** — mandatory human approval.
- **Safety-impacting action** — mandatory operator and safety review.

Research recommendations remain advisory. Execution should be performed by humans or deterministic automation under explicit authorization.

## Communication by audience

Tailor the explanation, not the evidence:

- Home users: one clear action, plain language, direct consequence, and simple backup warning.
- Small-business owners: business impact, downtime, cost, and prioritized short list.
- IT administrators: evidence, dependencies, change window, rollback, and verification.
- Security analysts: CVE, CVSS, EPSS, KEV, SSVC, exposure, attack paths, confidence, and source provenance.
- Network engineers: flows, zones, ACLs, conduits, and least-disruptive changes.
- OT operators: process consequence, safety, availability, certification, and vendor involvement.
- Executives: risk, obligation, cost, residual risk, and options with tradeoffs.

## Evaluation

Measure:

- recommendation correctness;
- official-source citation fidelity;
- fabricated-step rate;
- wrong-device rate;
- unsafe-action rate;
- rollback coverage;
- verification rate;
- false-closure rate;
- escalation quality;
- confidence calibration;
- user comprehension; and
- time to remediate by urgency band.

## Durable findings

- `REM-RES-001` — severity, urgency, confidence, and remediation value must remain separate.
- `REM-SAFE-001` — recommendation is not execution.
- `REM-SAFE-002` — missing identity, version, or exposure evidence blocks unsafe specificity.
- `REM-SAFE-003` — patching does not equal eviction or trust restoration.
- `REM-OT-001` — OT is passive-first and safety-governed.
- `REM-VEX-001` — VEX is an assertion requiring evidence, review, scope, and revalidation.
- `REM-VERIFY-001` — closure requires independent verification.
- `REM-COMMS-001` — tailor explanations without changing the underlying facts.
