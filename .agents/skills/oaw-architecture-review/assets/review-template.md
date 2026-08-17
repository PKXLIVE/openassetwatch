# OpenAssetWatch Architecture Review

## Decision

**Disposition:** `ADOPT | EXPERIMENT | DEFER | REJECT`

**Confidence:** `High | Medium | Low`

**One-line conclusion:**

## 1. Proposal

- **Capability/source:**
- **Problem it is meant to solve:**
- **Requested outcome:**
- **Scope reviewed:**

## 2. Current OpenAssetWatch Baseline

Describe the current capability that overlaps this proposal.

For each important statement, label it as one of:

- **Current OAW fact**
- **Inference**
- **Unknown / needs verification**

Include repository paths, ADRs, code, tests, or other evidence when available.

## 3. Verified Gap

State the specific gap that remains after accounting for existing OpenAssetWatch capability.

If no meaningful gap is verified, say so clearly.

## 4. Additive Value

Explain what the proposal adds that OpenAssetWatch does not already provide.

Classify the relationship:

`additive | overlapping | duplicative | conflicting | unrelated`

## 5. Proposed Integration Point

Describe where the capability would attach to the existing architecture without replacing authoritative components.

Cover affected areas as applicable:

- Control Tower/hub;
- collectors/sensors/spokes;
- normalized evidence;
- deterministic classification;
- findings/attention scoring;
- vulnerability/advisory intelligence;
- AI Advisor/agent workflows;
- APIs/data model;
- UI/dashboard;
- packaging/deployment;
- connectors/exports.

## 6. Architecture Conflicts or Drift Risk

Identify anything that could bypass or weaken:

- passive-first collection;
- local/self-hosted operation;
- deterministic authority;
- evidence provenance;
- current collectors/sensors;
- AI Advisor boundaries;
- human approval;
- product identity.

## 7. Security, Privacy, and OT Safety

Cover relevant trust boundaries, secrets, network paths, privileges, external processing, data retention, SSRF/URL fetching, command execution, prompt injection, poisoning, supply-chain exposure, tenancy, and active IoT/OT behavior.

## 8. Licensing and Source Governance

- **Registry state:**
- **Exact intended use approved?:**
- **Primary license/terms verified?:**
- **Attribution/provenance obligations:**
- **Caching/bundling/redistribution/commercial-use status:**
- **Required next review:**

If terms are unclear, mark the production use `review-required`.

## 9. Data, AI, and Authority Impact

Explain:

- new evidence/provenance fields;
- schema/API effects;
- confidence/conflict/freshness behavior;
- AI input/output changes;
- deterministic validation requirements;
- human approval requirements.

## 10. Operational Impact

- **Dependencies:**
- **Cost/rate limits/accounts:**
- **Offline behavior:**
- **Failure/degradation behavior:**
- **Update cadence:**
- **Performance/support burden:**
- **Rollback considerations:**

## 11. Validation and Release Gates

List the minimum design, test, evaluation, security, privacy, licensing, and documentation evidence required before production release.

## 12. Unknowns / Required Verification

List material unanswered questions. Do not hide uncertainty behind a favorable recommendation.

## 13. Recommendation

Explain why the chosen `ADOPT`, `EXPERIMENT`, `DEFER`, or `REJECT` disposition is appropriate for this exact scope.

If appropriate, identify the smallest next step that produces useful evidence without prematurely committing the architecture.

## Optional Codex Handoff

Include only when the user has asked to proceed after an `ADOPT` or `EXPERIMENT` decision.

### Objective

### In scope

### Explicitly out of scope

### Architecture invariants to preserve

### Files/docs to inspect first

### Acceptance criteria

### Required tests/evaluations

### Security/privacy/licensing gates

### Documentation updates

### Rollback/stop conditions
