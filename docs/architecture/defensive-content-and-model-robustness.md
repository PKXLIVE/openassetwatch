# Defensive Content and Model Robustness Architecture

## Purpose

This document defines accepted future OpenAssetWatch architecture for protecting
AI workflows and security intelligence pipelines against untrusted content,
sensitive-data leakage, parser failures, model instability, and ambiguous
machine-learning scores.

The design is additive. It does not replace collectors, passive sensors,
canonical evidence, deterministic classification, deterministic vulnerability
matching, findings, the Operational Attention Score, the AI Advisor, the
existing Safe Output Gate, or human review.

The architecture is provider-neutral and uses OpenAssetWatch-owned terminology.
It does not reproduce external project names, source-specific classes, copied
diagrams, or third-party implementation details. Any future code or data reuse
still requires the normal license and provenance review.

## Status

- Architecture state: `accepted_direction`
- Runtime impact: none
- Implementation authorization: none
- Current authority remains deterministic and evidence-first
- AI and future ML outputs remain advisory and non-authoritative

## Core Invariants

OpenAssetWatch should preserve these rules across every future implementation:

1. Structural security controls and heuristic detections are separate classes.
2. A heuristic detection may add evidence or block a request, but it may never
   weaken a structural security invariant.
3. Untrusted content never becomes authorization, policy, or trusted
   instruction because a model summarized, transformed, translated, or repeated
   it.
4. Taint created by untrusted content is monotonic for the lifetime of a task
   unless a deterministic policy explicitly creates a new bounded task with a
   new context contract.
5. Tool authorization is performed by deterministic policy outside the model.
6. Output destinations are authorized independently of content generation.
7. Sensitive-data inspection is a reusable platform capability, not a prompt
   instruction.
8. Internal robustness testing produces regression evidence, not offensive
   capability.
9. Model disagreement and uncertainty remain visible instead of being collapsed
   into a single unexplained score.
10. External intelligence is context and candidate evidence, not proof of a
    vulnerability, compromise, or asset identity.
11. Missing analysis is never presented as a clean result.
12. Every security-relevant layer reports whether it ran, degraded, failed, or
    was disabled.

---

## 1. AI Safety Invariant Framework

### 1.1 Gap

Natural-language inspection can identify many obvious prompt-injection or
malicious-content patterns, but language-based detection cannot provide a
complete security boundary. OpenAssetWatch therefore needs a formal distinction
between controls that enforce a property structurally and controls that score
content heuristically.

### 1.2 Control Classes

```text
AI Security Controls
|
|-- Invariant Controls
|   |-- tenant and site scope
|   |-- authenticated identity
|   |-- policy and capability ceiling
|   |-- provenance and taint
|   |-- tool authorization
|   |-- credential isolation
|   |-- network and destination policy
|   |-- egress restrictions
|   `-- output publication separation
|
`-- Heuristic Controls
    |-- suspicious-instruction detection
    |-- prompt-injection scoring
    |-- anomaly scoring
    |-- malicious-content classification
    `-- model-assisted content review
```

### 1.3 Invariant Finding Contract

Security findings emitted by these layers should identify their control class.

Suggested fields:

```json
{
  "control_id": "context.trust-boundary",
  "control_class": "invariant",
  "result": "blocked",
  "reason_code": "untrusted-content-authority-attempt",
  "task_id": "task-123",
  "tenant_id": "tenant-1",
  "evidence_refs": ["context-901"],
  "executed": true,
  "degraded": false
}
```

Suggested `control_class` values:

- `invariant`
- `heuristic`
- `advisory`

An invariant violation should block the protected operation regardless of a
heuristic score. A heuristic finding should be evaluated through its configured
threshold and may never override an invariant denial.

### 1.4 Fail-Closed Layer Behavior

If an invariant layer cannot execute safely, the protected operation should
fail closed.

Examples:

- policy compiler unavailable -> deny tool execution
- trust metadata missing -> do not treat content as trusted
- egress validator failure -> do not publish externally
- credential broker failure -> do not expose the raw credential
- destination resolver ambiguity -> deny external transmission

Every result should distinguish:

- `passed`
- `blocked`
- `failed_closed`
- `not_applicable`
- `disabled_by_policy`
- `degraded`
- `not_run`

`not_run` and `disabled_by_policy` must never be rendered as `passed`.

---

## 2. Monotonic Context Taint and Provenance Fencing

### 2.1 Gap

Existing trust-labeled context establishes the source and trust class of each
context object. OpenAssetWatch should additionally make taint a derived,
monotonic property of the assembled task context.

### 2.2 Monotonic Taint Rule

```text
Trusted Task Context
       +
Untrusted Evidence
       |
       v
Tainted Context
       |
       +--> summary remains tainted
       +--> translation remains tainted
       +--> extraction remains tainted
       +--> child result remains tainted unless policy creates a new
            independently validated task boundary
       `--> model cannot clear taint
```

Taint should be derived from input provenance rather than set by the model or
caller as an arbitrary boolean.

Suggested fields:

```json
{
  "context_id": "context-901",
  "trust_class": "public_untrusted_content",
  "taint_sources": ["external-record-18"],
  "tainted": true,
  "may_influence_authorization": false,
  "allowed_destinations": ["internal_analysis_only"],
  "integrity_digest": "sha256:..."
}
```

### 2.3 Request-Scoped Provenance Fence

When textual untrusted content is rendered into model context, the Evidence
Context Engine may create an unpredictable request-scoped fence identifier.

```text
Evidence Context Engine
        |
        v
Create request-scoped fence identifier
        |
        v
Render bounded untrusted span
        |
        v
Model processing
        |
        v
Validate fence integrity and output policy
```

The fence is defense in depth. It does not grant trust, prove safety, or replace
structured provenance.

Required properties:

- generated independently for each task or context build
- unpredictable to the untrusted source before context construction
- never accepted as authorization evidence
- bounded in length
- recorded only as safe metadata when needed for replay
- treated as an invariant violation if untrusted source material already
  contains the exact active fence identifier

Static delimiters alone should not be treated as a security boundary.

### 2.4 Context Derivation Rules

Any derived context object should retain:

- original source references
- original trust class
- taint state
- transformation type
- transformation component/version
- parent context ID
- output digest

A model-generated summary of untrusted content is still derived from untrusted
content and therefore remains non-authoritative.

---

## 3. Egress Transform Closure

### 3.1 Gap

Literal secret scanning can miss sensitive data that has been transformed
before publication. The Safe Output Gate should support a bounded set of
reversible or canonicalizing transformations when comparing candidate output
against registered sensitive values.

### 3.2 Architecture

```text
Candidate Output Artifact
        |
        v
Output Extraction
        |
        v
Canonicalization
        |
        +--> Unicode normalization
        +--> transport decoding where unambiguous
        +--> separator normalization
        +--> URL/percent normalization
        +--> bounded case normalization
        `--> other approved reversible transforms
        |
        v
Bounded Transform Closure
        |
        v
Sensitive-Value Matcher
        |
        v
Destination Policy
        |
        +--> allow
        +--> redact
        `--> block
```

### 3.3 Bounded Closure Requirements

The transform closure must be bounded by:

- maximum candidate size
- maximum transformations
- maximum recursion/fixpoint rounds
- maximum decoded expansion ratio
- maximum execution time
- maximum number of registered sensitive values

The engine must not attempt arbitrary decompression, executable decoding,
script evaluation, or unbounded recursive transformation.

### 3.4 Protected Destinations

Egress checks should apply to:

- reports
- external tickets
- webhook payloads
- notifications
- generated code changes
- exported evidence
- support bundles
- model responses
- tool-call arguments that cause external transmission
- links and embedded resources that may trigger automatic client requests

A visual or markup element that causes a client to fetch an external resource
is an egress surface and should be evaluated as such.

---

## 4. Sensitive Content Inspection Engine

### 4.1 Purpose

OpenAssetWatch should have one reusable inspection service for identifying and
redacting sensitive content in artifacts that enter or leave controlled
platform boundaries.

This is not a general-purpose endpoint DLP product. Its primary purpose is to
protect OpenAssetWatch evidence, diagnostics, generated artifacts, connector
payloads, and AI outputs.

### 4.2 Detection Pipeline

```text
Bounded Artifact or Text Chunk
          |
          v
Format-Safe Extraction
          |
          v
Pattern Candidates
          |
          v
Deterministic Validators
          |
          v
Context and Co-occurrence Scoring
          |
          v
Entropy / Secret Heuristics
          |
          v
Classification and Redaction Policy
          |
          v
Redacted Finding + Location + Provenance
```

### 4.3 Initial Detector Classes

Possible detector classes include:

- credentials and authentication tokens
- private-key material
- high-entropy secret candidates
- customer-defined sensitive patterns
- personal identifiers
- financial identifiers
- health-related identifiers
- internal infrastructure identifiers
- environment-specific protected values

Exact detector libraries and regulatory mappings remain separate implementation
choices.

### 4.4 Finding Contract

```json
{
  "sensitive_finding_id": "sensitive-123",
  "classification": "credential_candidate",
  "confidence": 0.91,
  "validation_state": "deterministically_validated",
  "source_artifact_id": "artifact-123",
  "location": {
    "section": "configuration",
    "line": 24,
    "column": 8,
    "byte_offset": 442
  },
  "display_value": "[REDACTED]",
  "original_retained": false,
  "detector_version": "sensitive-content.v1",
  "detected_at": ""
}
```

### 4.5 Location Preservation

Extraction adapters should preserve enough location metadata to explain where a
match came from without retaining unnecessary secret material.

Possible location fields:

- artifact ID
- file-relative path where policy permits
- report section
- record/field name
- line and column
- byte offset
- table and column identifier
- worksheet/section identifier
- message part or header name

### 4.6 Archive and Structured-Input Safety

If future artifact inspection supports archives or structured documents, it
must apply:

- compressed and uncompressed byte limits
- expansion-ratio limits
- recursion-depth limits
- file-count limits
- path traversal rejection
- symbolic-link rejection where applicable
- parser timeouts
- parser isolation for high-risk formats

### 4.7 Redaction Policy

Redaction should be destination-aware and support:

- full replacement
- partial masking
- hash-only reference
- drop field
- block artifact

The default for credentials, private keys, and authentication tokens should be
full removal from normal outputs.

---

## 5. Security Intelligence Watch

### 5.1 Gap

OpenAssetWatch has advisory synchronization and optional external intelligence
enrichment, but it also needs a distinct future capability for tracking current
security events and linking them to the user's known environment without
turning news or public commentary into authoritative findings.

### 5.2 Architecture

```text
Approved Intelligence Sources
          |
          v
Feed / API / Structured Publication Acquisition
          |
          v
Source Validation and Normalization
          |
          v
Duplicate Detection and Story Clustering
          |
          v
Entity Extraction
          |-- vulnerability identifiers
          |-- products and technologies
          |-- campaigns or threat themes
          |-- defensive recommendations
          `-- publication relationships
          |
          v
Environment Relevance Matching
          |
          v
Current Intelligence Candidate
          |
          +--> dashboard
          +--> digest
          +--> bounded notification
          `--> analyst investigation
```

### 5.3 Source Rules

Preferred acquisition order should be:

1. documented machine-readable feed or API
2. syndication feed
3. structured public dataset
4. bounded HTML extraction only when permitted and necessary

Each source must pass licensing, terms, privacy, attribution, rate-limit, and
retention review before production use.

### 5.4 Intelligence Event Contract

Suggested fields:

```text
intelligence_event_id
source_id
source_record_id
published_at
retrieved_at
headline
summary
content_hash
entity_refs
vulnerability_ids
affected_product_candidates
source_reliability
corroboration_count
story_cluster_id
asset_match_candidates
freshness_state
verification_state
license_profile_id
```

### 5.5 Story Clustering

Multiple publications describing the same underlying event should be grouped so
that repeated coverage does not inflate risk.

Clustering may use:

- exact or normalized vulnerability identifiers
- publication links
- canonical product identifiers
- title/content fingerprints
- time proximity
- deterministic entity overlap
- optional semantic similarity as a non-authoritative hint

One story cluster may contain many source records while remaining one
intelligence event for prioritization.

### 5.6 Authority Boundary

```text
Intelligence article or publication
            !=
Vulnerability applicability
            !=
Confirmed OpenAssetWatch finding
```

An intelligence event may:

- raise investigation priority
- trigger a bounded relevance check
- create a candidate enrichment record
- recommend operator review

It may not directly:

- confirm a vulnerable version
- create or merge an authoritative asset
- mark compromise
- close a finding
- execute remediation

### 5.7 Notifications

Notifications should require policy such as:

- verified environment match
- minimum confidence
- freshness
- severity or known-exploitation enrichment from a reviewed source
- source reliability
- duplicate suppression
- tenant/site scope

The notification must distinguish a current intelligence match from a confirmed
OpenAssetWatch finding.

---

## 6. Parser and Input Robustness Lab

### 6.1 Purpose

OpenAssetWatch should continuously test its own parsers and ingress contracts
against malformed, adversarial, truncated, oversized, and unusual input.

The goal is to discover reliability and security defects in OpenAssetWatch-owned
code before release. The lab is not an external-target vulnerability scanner
and must not generate exploit payloads or proof-of-compromise tooling.

### 6.2 Initial Targets

Suitable targets include:

- collector submissions
- sensor observation envelopes
- endpoint inventory contracts
- advisory catalogs and signed manifests
- component identifiers and version parsers
- connector event envelopes
- webhook and inbox parsers
- playbook definitions
- Skill Pack manifests
- capability/provider manifests
- AI structured-output schemas
- tool-call envelopes
- configuration files
- report and artifact importers
- future protocol decoders owned by the project

### 6.3 Pipeline

```text
Reviewed Seed Corpus
       |
       v
Bounded Mutation / Generation
       |
       v
Isolated OpenAssetWatch Parser
       |
       v
Observe
  |-- crash
  |-- hang
  |-- excessive resource use
  |-- invariant violation
  |-- inconsistent parse
  `-- unexpected acceptance
       |
       v
Failure Deduplication
       |
       v
Input Minimization
       |
       v
Root-Cause Review
       |
       v
Regression Fixture
       |
       v
CI / Nightly Robustness Corpus
```

### 6.4 Findings

A robustness finding should retain:

- parser/contract identifier and version
- failing input digest
- minimized fixture reference
- failure class
- exception or invariant code
- runtime and memory bounds
- reproducibility count
- affected versions
- remediation state
- regression-test reference

### 6.5 Safety Boundaries

- test only project-owned code or explicitly approved isolated fixtures
- no arbitrary external targets
- no network exploitation
- no shellcode or exploit generation
- no credential collection
- no production destructive testing
- no uncontrolled corpus growth
- no secret-bearing production payloads in the corpus
- isolated execution for risky parsers
- strict CPU, memory, file, and time limits

### 6.6 Release Gate

A newly reproducible crash, hang, parser escape, tenant-boundary violation, or
security-invariant failure in a supported input contract should block release
until fixed, explicitly risk-accepted, or the affected parser is disabled.

---

## 7. Adversarial Model Robustness Lab

### 7.1 Purpose

If OpenAssetWatch adds statistical or machine-learning models for future
behavioral baselines, classification assistance, ranking, or anomaly analysis,
those models should be tested against controlled adversarial and degraded-input
conditions before promotion.

This lab evaluates OpenAssetWatch-owned candidate models. It does not provide a
runtime capability for attacking third-party models.

### 7.2 Evaluation Classes

Future test classes may include:

- bounded feature perturbation
- missing features
- duplicated features or events
- conflicting evidence
- reordered evidence
- boundary-value manipulation
- out-of-distribution records
- mislabeled or poisoned training candidates
- temporal drift
- class imbalance
- transfer-style perturbations across approved candidate models
- uncertainty and abstention tests

### 7.3 Robustness Flow

```text
Versioned Evaluation Dataset
           |
           +--> Baseline Inputs
           |
           `--> Controlled Mutations
                    |
                    v
              Candidate Model
                    |
                    v
       Baseline vs Mutated Comparison
                    |
                    v
            Robustness Scorecard
                    |
                    v
              Promotion Gate
```

### 7.4 Abstention Rule

For security-critical classifications, instability or insufficient evidence
should prefer an explicit abstention outcome over a confident invented result.

Suggested states:

- `classified`
- `abstained_low_confidence`
- `abstained_out_of_distribution`
- `abstained_missing_features`
- `abstained_model_disagreement`
- `blocked_policy`

### 7.5 Evaluation Record

```json
{
  "test_id": "robustness-921",
  "model_digest": "sha256:...",
  "feature_contract": "asset-behavior.v2",
  "dataset_version": "robustness-corpus-3",
  "baseline_output": "network_camera",
  "mutated_output": "unknown",
  "expected_behavior": "abstain",
  "actual_behavior": "abstain",
  "result": "pass",
  "mutation_class": "missing_feature",
  "measured": true
}
```

### 7.6 Training-Data Eligibility

Training data should have explicit trust states.

Recommended default policy:

```text
Analyst-reviewed label
  -> eligible after provenance and quality review

Deterministic label
  -> eligible when the deterministic rule is within scope and provenance is valid

Model-generated or pseudo label
  -> evaluation-only by default

Unreviewed external label
  -> not training eligible
```

No production model should retrain directly from unreviewed model output or
unreviewed external data.

---

## 8. ML Feature and Score Provenance Contract

### 8.1 Gap

A single combined score hides which inputs, rules, models, versions, and
weights produced the value. Any future ML-assisted detector or ranker should
therefore emit an inspectable score envelope.

### 8.2 Required Provenance

Suggested fields:

```json
{
  "score_id": "score-123",
  "task_id": "task-456",
  "feature_contract": "network-behavior.v2",
  "feature_vector_digest": "sha256:...",
  "feature_completeness": 0.94,
  "rule_scores": {
    "behavior-rule-set": 0.74
  },
  "model_scores": {
    "model-a@sha256:...": 0.81,
    "model-b@sha256:...": 0.68
  },
  "aggregation_method": "weighted-v2",
  "combined_score": 0.77,
  "agreement_state": "partial",
  "abstention": false,
  "uncertainties": ["one expected feature unavailable"],
  "created_at": ""
}
```

### 8.3 Required Separation

OpenAssetWatch should keep these concepts separate:

- deterministic rule result
- model score
- ensemble/aggregate score
- confidence
- evidence quality
- severity
- reachability
- Operational Attention Score

A model score must not silently become severity, vulnerability status,
compromise status, or the Operational Attention Score.

### 8.4 Model Disagreement

When multiple models disagree, the platform should record:

- each raw model output
- model version/digest
- aggregation method
- disagreement magnitude
- final route
- whether human or deterministic arbitration was required

Major disagreement may trigger abstention or human review rather than averaging
away uncertainty.

---

## 9. Conditional Intelligence and Advisory Fetching

### 9.1 Purpose

Approved remote intelligence or advisory sources may support conditional
retrieval semantics that avoid repeatedly downloading unchanged content.

This is an optimization only. It must not weaken the existing signed-feed,
provenance, license, replay, downgrade, approval, or activation controls.

### 9.2 Flow

```text
Last Reviewed Source State
        |
        v
Conditional Fetch Metadata
        |
        v
Approved Remote Source
        |
        +--> unchanged -> record freshness check; keep last-known-good content
        |
        `--> changed ---> full bounded download
                           |
                           v
                    normal signature,
                    provenance, license,
                    schema, preview,
                    approval, activation
```

### 9.3 Rules

- conditional metadata is source-specific cache metadata, not trust evidence
- an unchanged response does not extend an expired signature or override local
  freshness policy unless the signed source contract permits it
- changed content always follows the complete verification lifecycle
- cache corruption or ambiguity falls back to full verification or fails closed
- cache keys must include source identity and relevant authorization scope
- cached content must retain digest, source version, and retrieval metadata
- no cache path may bypass revocation or downgrade policy

---

## 10. Relationship to Existing Architecture

This document extends rather than duplicates existing controls.

### AI Permission and Safe Output Architecture

`docs/architecture/ai-agent-permission-output-security.md` remains the canonical
source for:

- permission-path analysis
- trust-labeled context
- Safe Output Gate
- independent security-validation capacity
- protected control artifacts
- tool identity and drift controls

This document adds:

- invariant-versus-heuristic control classification
- monotonic taint
- request-scoped provenance fencing
- bounded transformed-secret egress inspection
- reusable sensitive-content inspection

### Agent Evaluation and Release Gates

`docs/architecture/agent-evaluation-and-release-gates.md` remains the canonical
evaluation and promotion framework. This document adds the specific Parser and
Input Robustness Lab and Adversarial Model Robustness Lab as future evaluation
families.

### External Intelligence

`docs/architecture/external-intelligence-enrichment-roadmap.md` remains the
canonical external-evidence expansion. The Security Intelligence Watch is a
separate current-events stream that reuses its source licensing, scope,
provenance, freshness, normalization, and non-authoritative evidence rules.

### Vulnerability Intelligence

`docs/SOFTWARE_AND_VULNERABILITY_INTELLIGENCE.md` and
`docs/TRUSTED_ADVISORY_FEEDS.md` remain authoritative for vulnerability
applicability and reviewed advisory synchronization. Conditional retrieval is
only a future transport optimization.

---

## 11. Phased Implementation Direction

### Phase 1 - Contracts and deterministic safety

- add invariant/heuristic control-class fields
- add monotonic taint to context contracts
- define sensitive-content finding schema
- define ML feature/score provenance schema
- define robustness-test result schema
- add negative tests proving heuristic controls cannot override invariant denial

### Phase 2 - Safe content inspection

- implement bounded sensitive-content inspection for generated artifacts
- add egress transform closure with strict resource limits
- integrate with Safe Output Gate
- add destination-aware redaction
- add regression fixtures for encoded or reformatted sensitive values

### Phase 3 - Security intelligence watch

- define reviewed source registry extensions
- implement one source-neutral feed interface
- add deduplication and story clustering
- add deterministic environment relevance matching
- add dashboard/digest candidate presentation
- keep notifications bounded and clearly non-authoritative

### Phase 4 - Parser robustness

- build isolated fuzz/robustness harness for project-owned parsers
- seed with synthetic and sanitized fixtures
- add crash/hang deduplication and fixture minimization
- make supported-contract invariant failures release-blocking

### Phase 5 - Model robustness

- only after a production-relevant ML capability exists
- define adversarial/degraded-input corpora for that task
- measure abstention, disagreement, calibration, and failure behavior
- require reproducible model/version/dataset provenance
- gate model promotion on approved thresholds

### Phase 6 - Transport optimization

- add conditional fetch support only to sources that explicitly support it
- prove no bypass of signature, provenance, replay, downgrade, approval, or
  revocation controls

---

## 12. Acceptance Criteria

The architecture should not be considered production-capable until:

- invariant and heuristic control outcomes are distinguishable in telemetry
- heuristic success cannot override invariant denial
- untrusted-data taint is derived and monotonic within a task
- sensitive-output inspection fails closed for protected external destinations
- encoded or reformatted protected values are covered by bounded tests
- every sensitive finding retains safe location and provenance metadata
- intelligence stories cannot create authoritative vulnerability findings
- story clustering prevents duplicate publication count from inflating risk
- parser robustness tests are isolated and resource bounded
- failing parser inputs can be minimized and retained as regression fixtures
- ML evaluation uses explicit model and dataset versions
- model disagreement and abstention remain visible
- training-data eligibility rejects unreviewed model/external labels by default
- conditional retrieval cannot bypass existing feed trust controls
- local-only operation remains functional without current-intelligence sources

---

## 13. Explicit Non-Goals

This architecture does not add or authorize:

- exploit generation
- shellcode generation
- proof-of-compromise generation
- autonomous penetration testing
- arbitrary external-target fuzzing
- unrestricted active scanning
- credential harvesting
- third-party model attack services
- model extraction against external systems
- general filesystem/database/network DLP crawling by default
- automatic dependency modification
- automatic retraining from unreviewed labels
- auto-blocking or remediation based solely on a model score
- news or public commentary as proof of compromise or vulnerability
- silent external data sharing

## Final Position

OpenAssetWatch should treat language models, statistical models, parsers,
external content, and generated artifacts as potentially fallible components
inside a deterministic security envelope.

The platform should prefer structural guarantees over attempts to infer an
attacker's intent, preserve provenance through every transformation, detect
sensitive egress independently of the model, continuously test its own input
boundaries, and require uncertainty to remain visible whenever evidence or
model behavior is incomplete.