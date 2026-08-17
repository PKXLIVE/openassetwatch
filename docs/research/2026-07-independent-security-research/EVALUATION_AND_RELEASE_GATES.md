# Evaluation, Benchmark Credibility, and Release Gates

## Status

Independent research input. Not an implementation commitment.

## Core conclusion

Credible product claims require three separations:

1. deterministic substrate correctness versus probabilistic or generative AI correctness;
2. benchmark or sandbox performance versus production outcomes; and
3. synthetic or self-consistency results versus real, independently labeled ground truth.

Probabilistic models should be trained on past data and tested on strictly later held-out data. Security evaluation should use repeated and adaptive attempts rather than one-shot testing. Every public benchmark claim should disclose datasets, model and prompt versions, scaffolding, hardware, costs, number of runs, variance, failures, and limitations.

## Substrate versus AI

### Deterministic substrate

Examples:

- asset discovery and deduplication;
- evidence normalization;
- stable identifier handling;
- CPE, purl, SBOM, and version-range matching;
- KEV membership;
- rule execution;
- permissions and tenant isolation;
- query, join, filter, and dashboard-plan validation;
- cost and cardinality enforcement;
- VEX propagation;
- correction and retraction handling; and
- audit logging.

Substrate tests require known-complete or human-labeled ground truth.

### Probabilistic or generative behavior

Examples:

- device classification;
- identity resolution;
- confidence scores;
- EPSS- or LEV-like probabilities;
- agent reasoning;
- evidence selection;
- citation faithfulness;
- recommendation drafting;
- natural-language-to-dashboard-plan translation; and
- chart selection.

These require held-out labeled data, calibration, repeated runs, visible failure sets, and drift monitoring.

## Asset discovery evaluation

Measure:

- discovery coverage against an independently established inventory;
- time to discovery;
- passive-only versus active-assisted coverage;
- managed versus unmanaged coverage;
- segment and site coverage;
- collector coverage;
- silent-device discovery;
- duplicate rate;
- stale-asset handling;
- disappearance and retirement handling;
- IoT and OT coverage; and
- safety incidents caused by discovery.

Do not define the denominator as only the assets the product can see. That makes coverage unfalsifiable.

## Asset identity evaluation

Report separately:

- device-class precision, recall, and F1;
- vendor, model, OS, software, and firmware accuracy;
- pairwise match precision and recall;
- cluster precision and recall;
- B-cubed precision, recall, and F1;
- false merge and false split rates;
- over-merge and under-merge rates;
- identity stability;
- time to correct;
- confidence calibration;
- human-review burden;
- accuracy under IP churn;
- accuracy under MAC randomization;
- clone and reimage handling;
- white-label performance;
- encrypted-traffic performance; and
- silent-device handling.

Do not report device-type accuracy as proof of instance-level identity accuracy.

## Vulnerability-correlation evaluation

Measure:

- CVE matching precision and recall;
- version-range correctness;
- CPE matching;
- purl and ecosystem matching;
- SBOM and firmware matching;
- false vulnerability assignments;
- missed vulnerabilities;
- unknown-version handling;
- VEX correctness;
- source freshness;
- correction and retraction propagation; and
- findings re-evaluated after identity change.

A product/version match is a hypothesis until affected version and advisory evidence are validated.

NVD CPE gaps must not be excluded from the denominator simply to improve precision.

## Risk-prioritization evaluation

Keep severity, probability, known exploitation, exposure, importance, confidence, urgency, and remediation value separate.

Recommended measures include:

- coverage: share of exploited vulnerabilities prioritized;
- efficiency: share of prioritized vulnerabilities that were exploited;
- effort: share of all vulnerabilities prioritized;
- precision at k;
- normalized discounted cumulative gain;
- KEV recall;
- time to prioritize;
- score stability and churn;
- explanation completeness;
- missing-data behavior;
- inter-rater agreement for qualitative SSVC inputs;
- choke-point value; and
- remediation-value accuracy.

For every probabilistic output, require:

- time-split held-out validation;
- reliability diagram;
- Brier score;
- ECE with bin count disclosed;
- a trivial baseline;
- drift monitoring; and
- recalibration or retirement if performance degrades.

## Agent evaluation

Measure:

- task correctness;
- evidence completeness;
- citation precision and recall;
- unsupported-claim rate;
- fabricated-finding rate;
- tool-selection and parameter accuracy;
- schema validity;
- permission compliance;
- tenant isolation;
- contradiction detection;
- escalation quality;
- false closure;
- human-review burden;
- repeatability across runs;
- pass-to-the-k reliability;
- latency;
- cost and token use;
- correction behavior;
- resilience to untrusted input; and
- utility under adversarial conditions.

Useful public benchmark families include tau-bench, AgentDojo, InjecAgent, Agent Security Bench, AgentHarm, WASP, SWE-bench, CyberSecEval, NYU CTF Bench, RAGTruth, ALCE, FActScore, and RAGAS. These are test inputs, not evidence of production performance.

## Dashboard evaluation

Measure:

- dashboard-plan validity;
- rendering success;
- metric faithfulness;
- filter correctness;
- join correctness;
- hallucinated fields;
- policy enforcement;
- cost and cardinality violations;
- cross-tenant leakage;
- sensitive-field exposure;
- chart appropriateness;
- misleading visualization rate;
- freshness display;
- provenance completeness;
- user task success;
- trust calibration;
- save and discard behavior;
- dashboard sprawl;
- latency; and
- cost.

A rendered dashboard is not necessarily a correct dashboard. Silent wrong numbers are release-blocking when they affect user decisions.

## Security testing

Test at minimum:

- direct and indirect prompt injection;
- malicious asset names and hostnames;
- poisoned logs and advisories;
- malicious feed records;
- tool metadata poisoning;
- untrusted connector and MCP behavior;
- SSRF and unsafe URL handling;
- data exfiltration;
- unauthorized queries;
- cross-tenant access;
- memory poisoning;
- audit bypass;
- excessive agency; and
- unsafe remediation advice.

Report attack success rate and normal-task utility under repeated and adaptive attempts. One-shot results are insufficient.

## Dataset strategy

Synthetic data is appropriate for:

- rare-class coverage;
- privacy-preserving substitutes;
- fault injection;
- adversarial testing;
- regression testing; and
- deterministic plumbing validation.

Synthetic results must be clearly labeled and must never be presented as field or production accuracy.

Dataset requirements:

- datasheet describing source, collection, license, limitations, and labeling;
- real versus synthetic designation;
- hidden held-out test partition;
- time-based split for predictive tasks;
- adversarial cases;
- privacy minimization;
- label-review process;
- inter-rater reliability; and
- contamination controls.

## Usability and operational simplicity

Evaluate:

- installation completion;
- time to first useful result;
- onboarding success;
- task completion;
- user comprehension;
- correct action selection;
- support burden;
- maintenance time;
- upgrade success;
- resource usage;
- offline operation;
- accessibility;
- false-positive tolerance;
- dashboard comprehension; and
- trust calibration.

Validated instruments may include System Usability Scale, NASA-TLX, trust-in-automation measures, task success, and time on task. Measure calibrated trust, not simply whether users say they trust the product.

## Comparator strategy

Compare against relevant categories using the same environment and ground truth:

- passive monitoring;
- active scanners;
- asset inventories;
- vulnerability scanners;
- CAASM and exposure platforms;
- risk-prioritization approaches;
- AI security assistants; and
- dashboard and BI systems.

Compare features, accuracy, coverage, cost, resource requirements, privacy, deployment complexity, and maintenance burden.

Always include simple baselines such as CVSS-only, prioritize-all-KEV, fixed templates, exact-key identity, and random ranking.

## Release blockers

The research supports blocking release for:

- any cross-tenant data leakage;
- any unauthorized field or dashboard access;
- any unsafe remediation recommendation on the defined safety suite;
- any autonomous irreversible or safety-impacting action;
- active OT behavior without deterministic validation and explicit approval;
- any AI write directly to authoritative facts;
- identity correction that fails to re-evaluate dependent findings;
- self-attested-only closure for findings that require independent verification;
- probabilistic confidence outside the pre-registered calibration tolerance;
- discovery, identity, or vulnerability matching below approved precision and recall floors;
- injection success above the approved threshold under adaptive attempts;
- a generated metric or join that changes a reported number without validation; and
- synthetic results represented as production performance.

## Public benchmark-reporting standard

Publish:

- dataset name, version, and description;
- datasheet;
- real or synthetic label;
- ground-truth method;
- model and version;
- prompt and policy version;
- tools and scaffolding;
- hardware;
- run count;
- temperature and sampling settings;
- cost and token use;
- mean, variance, and confidence interval;
- failures and counterexamples;
- known limitations;
- reproduction steps;
- regression history;
- contamination risk; and
- third-party validation status.

## Anti-gaming controls

- Hidden, rotated, time-split test sets.
- Multiple runs and pass-to-the-k reliability.
- Adaptive rather than one-shot testing.
- Trivial baselines.
- Full-population denominators.
- Separate substrate and AI tables.
- Separate synthetic and real tables.
- Visible failure examples.
- No self-consistency presented as accuracy.
- No exclusion of unknowns merely to improve precision.
- No never-expiring assets to inflate discovery coverage.
- No self-attested closure accepted as verified.

## Durable findings

- `EVAL-RES-001` — substrate and AI correctness must be reported separately.
- `EVAL-RES-002` — benchmark performance is not production performance.
- `EVAL-DATA-001` — probabilistic models require time-split held-out validation.
- `EVAL-DATA-002` — synthetic data must be labeled and cannot support production claims.
- `EVAL-CAL-001` — calibration requires reliability diagrams, Brier score, and disclosed ECE.
- `EVAL-SEC-001` — security requires repeated adaptive testing with utility under attack.
- `EVAL-GATE-001` — safety invariants should block release.
- `EVAL-REPORT-001` — public claims require full reproducibility metadata and visible failures.
- `EVAL-REPORT-002` — anti-gaming controls must be built into the evaluation program.
