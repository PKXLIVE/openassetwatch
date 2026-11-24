# AI Agent Supply Chain Security

- **Status:** Documentation-only architecture
- **Purpose:** Extend OpenAssetWatch provenance, integrity, review, and invalidation controls from model artifacts to the broader agent control and execution supply chain
- **Related:** `docs/MODEL_ARTIFACT_PROVENANCE.md`, `docs/architecture/ai-agent-permission-output-security.md`, `docs/architecture/skill-pack-contract.md`, `docs/SOURCE_LICENSING_REGISTRY.md`

## Core principle

```text
Natural-language control artifacts, tools, models, policies, and workflow packages can change agent behavior.
They require provenance and lifecycle controls comparable to code and security configuration.
```

An artifact being open source, readable, or previously approved is not sufficient evidence that its current bytes, publisher, schema, capabilities, or behavior remain approved.

## Existing foundation

OpenAssetWatch already has strong model-artifact provenance and qualification binding for local AI models. That design should remain canonical for model artifacts.

The remaining delta is to extend similar identity and invalidation principles to:

- Skill Packs;
- agent role definitions;
- prompts/instruction packages;
- policy bundles;
- tool and MCP manifests;
- tool-server packages;
- workflow definitions;
- sandbox profiles;
- output publisher configuration;
- retrieval corpora and knowledge bundles;
- evaluation datasets/fixtures;
- container images/runtime packages; and
- optional external security detectors.

## Supply-chain asset classes

### Models and model artifacts

Already governed by `MODEL_ARTIFACT_PROVENANCE.md` for local model provenance/qualification where configured.

### Skill Packs

Security-sensitive elements include:

- `skill.yaml`;
- `instructions.md`;
- input/output schemas;
- references;
- evaluation fixtures; and
- approved version/status.

A Skill Pack is not executable code in the initial runtime, but its instructions can materially influence model behavior and therefore require integrity/review.

### Agent roles

Role definitions influence routing, tools, evidence classes, budgets, and review requirements. They must be versioned and protected.

### Prompts and instruction templates

System/developer/task instructions are protected control artifacts. A textual change can alter behavior without source-code change.

### Policies and deterministic rule bundles

Policy/rule changes can alter enforcement and require the strongest review, test, and drift controls.

### Tools and MCP/tool servers

Tool identity includes implementation, schema, publisher, version, side-effect class, destinations, credential scope, and capabilities.

### Workflows

Workflow graphs may change delegation, tool order, approval sequence, or publication behavior.

### Retrieval/knowledge bundles

Corpus provenance, licensing, tenant scope, source integrity, and update history matter even when individual documents are untrusted data.

### Evaluation assets

Security tests and datasets can be poisoned or weakened. Evaluation bundles should be versioned, integrity-protected, and reviewed before they are allowed to satisfy release gates.

## Component registry integration

The existing AI Component Registry design should record each security-relevant component with:

- component ID/type;
- owner/maintainer;
- source/publisher;
- version;
- digest;
- schema digest where applicable;
- dependency/SBOM reference;
- license/reuse status;
- trust state;
- approved capability profile;
- tenant/deployment scope;
- review state/date;
- expiration/review deadline;
- active version;
- rollback version;
- runtime verification status; and
- revocation/quarantine state.

## Trust states

Suggested shared states:

- `candidate`
- `approved`
- `approved_with_restrictions`
- `unmanaged`
- `unknown`
- `expired`
- `quarantined`
- `revoked`
- `superseded`
- `requalification_required`

Not all component types need every state, but runtime policy must understand the difference between unknown, unapproved, revoked, and merely superseded.

## Canonical artifact identity

Display names are never enough.

Every protected artifact should have:

- stable artifact/component ID;
- artifact type;
- version;
- content digest;
- source/publisher identity;
- schema/capability digest when applicable;
- dependency manifest/SBOM digest when applicable;
- policy/review version; and
- activation state.

The model cannot assert these fields as trusted metadata.

## Skill Pack integrity

Before an approved Skill Pack can run, the future loader/coordinator should verify:

- approved Skill Pack ID/version;
- manifest digest;
- instruction digest;
- schema digests;
- referenced files confined to the approved package;
- no unexpected/unknown manifest fields;
- allowed tools/evidence/capabilities match approved policy;
- no executable script path unless a future separately approved runtime explicitly supports it;
- evaluation bundle/version is current; and
- package not revoked/expired/quarantined.

A changed instruction file requires re-evaluation even if the Skill Pack ID is unchanged.

## Instruction-file hygiene

Third-party or imported instruction files should be treated as untrusted control candidates.

The project should reject or quarantine unexpected control artifacts containing:

- hidden/invisible/bidirectional control characters not permitted by format;
- instructions to bypass product policy;
- embedded credentials/secrets;
- dynamic shell/download/install instructions;
- unapproved tool or network targets;
- permission-escalation claims;
- self-install/activation directions;
- unrelated external data destinations; or
- malformed schema/frontmatter intended to confuse parsers.

The original bytes/digest should remain available for forensic review when permitted.

## Tool/server integrity

Tool/server approval must bind to:

```text
publisher
integration_id
canonical_tool_id
version
implementation_digest
schema_digest
capabilities
side_effect_class
network_destinations
credential_scope
transport
policy_version
```

Security-relevant drift triggers disablement/re-review before further use.

See `AI_TOOL_AUTHORIZATION_MODEL.md`.

## Mandatory re-review triggers

Re-review should occur when any approved component changes:

- publisher/source;
- implementation/content digest;
- parameter/input/output schema;
- declared capability;
- side-effect class;
- network destination;
- credential scope;
- dependency set/SBOM materially;
- execution/runtime profile;
- instruction/prompt content;
- workflow graph;
- output publication behavior;
- security policy/rule binding; or
- required evaluation bundle.

A model cannot waive re-review.

## Signatures and attestations

Where the project controls publication, prefer cryptographic signatures/attestations in addition to hashes for security-sensitive release artifacts.

Hashes identify bytes; signatures/attestations can additionally bind publisher/release provenance.

The exact signing implementation should align with existing OpenAssetWatch release-security architecture rather than introduce a separate trust root.

## Dependency and SBOM requirements

Security-sensitive runtime packages should use:

- pinned/reviewed dependencies where practical;
- SBOM generation;
- vulnerability/license review;
- provenance/build evidence where available;
- known-source registries;
- reproducible or independently verifiable build metadata where feasible; and
- explicit update/rollback process.

No AI component gets an exemption from ordinary software supply-chain controls.

## Model/quantization/conversion lineage

The existing local model provenance contract remains authoritative. Any future model manager or agent runtime must consume its trust state rather than recreate a weaker model registry.

A qualified model artifact whose bound provenance changes must be requalified before approved Advisor/agent use according to current policy.

## Retrieval corpus integrity

A RAG corpus can be intentionally untrusted as data while still requiring trustworthy **corpus administration**.

Separate:

- document content trust;
- corpus membership/control trust;
- source provenance;
- tenant scope;
- ingestion approval; and
- index integrity.

A malicious document does not become trusted because the corpus index is signed. Likewise, a valid document should not enter a tenant's corpus through an unauthorized ingestion path.

## Evaluation supply chain

Security evaluation assets should be protected from silent weakening.

Record:

- evaluation bundle ID/version/digest;
- test-case count and categories;
- dataset/license metadata;
- expected release blockers;
- rule/policy/schema versions;
- generator/mutation configuration;
- approved exclusions; and
- reviewer/approval state.

A release report should name the exact bundle/version used.

## Update channels

Automatic remote pattern/rule/instruction updates are high-risk for an offline/local-first security product.

Preferred posture:

- explicit operator or release-managed update;
- signed/versioned bundle;
- integrity verification before activation;
- staged/review state;
- rollback; and
- no remote update server with permission to silently alter deterministic policy or Skill Pack instructions.

Optional detector intelligence may update more frequently, but detector updates cannot grant authorization or change core policy.

## External detector dependencies

An external scanner/classifier may be used only as defense-in-depth after:

- license review;
- dependency/supply-chain review;
- model/data provenance review if applicable;
- offline/network behavior review;
- false-positive/negative evaluation;
- resource impact measurement; and
- explicit policy defining failure behavior.

Detector verdicts remain signals, never action authorization.

## Quarantine

Quarantine a component when:

- digest/provenance mismatch;
- publisher/source changes unexpectedly;
- review expires;
- security advisory requires suspension;
- runtime behavior violates declared capability/destination;
- malicious/tampered package suspected;
- required evaluation fails; or
- security incident implicates the component.

Quarantine prevents new activation/use and triggers dependency/descendant review.

## Revocation and downstream invalidation

Revocation must propagate to affected runtime relationships.

Examples:

- revoked Skill Pack -> new tasks cannot select it; active tasks may be cancelled/quarantined according to consequence;
- revoked tool -> new requests denied; recent outputs reviewed if compromise suspected;
- revoked model artifact -> Advisor/agent route disabled according to provenance policy;
- revoked policy/workflow -> affected runs suspended pending revalidation;
- poisoned retrieval bundle -> dependent memory/hypotheses/artifacts marked for review.

## Rollback

Rollback activates a previously approved version for **new work**. It must not rewrite historical run records.

Existing investigations continue to record the exact component versions that actually ran.

## Runtime verification

At execution, critical components should be verified against approved identity before use.

Examples:

- Skill Pack instruction/schema digest;
- tool implementation/schema digest;
- model qualification/provenance state;
- policy/rule version;
- workflow graph version;
- publisher profile; and
- evaluation-gate version for action-capable deployments.

## Supply-chain telemetry

Suggested events:

- `ai.component.discovered`
- `ai.component.approved`
- `ai.component.drift_detected`
- `ai.component.quarantined`
- `ai.component.revoked`
- `ai.component.expired`
- `ai.skill.digest_mismatch`
- `ai.tool.digest_mismatch`
- `ai.tool.schema_drift`
- `ai.policy.integrity_failure`
- `ai.workflow.integrity_failure`
- `ai.eval.bundle_changed`
- `ai.supply_chain.activation_blocked`

## Reason codes

Candidate reason codes:

- `AI_COMPONENT_UNKNOWN`
- `AI_COMPONENT_UNAPPROVED`
- `AI_COMPONENT_REVOKED`
- `AI_COMPONENT_EXPIRED`
- `AI_COMPONENT_DIGEST_MISMATCH`
- `AI_COMPONENT_SCHEMA_DRIFT`
- `AI_COMPONENT_PUBLISHER_CHANGED`
- `AI_COMPONENT_CAPABILITY_DRIFT`
- `AI_COMPONENT_DESTINATION_DRIFT`
- `AI_COMPONENT_CREDENTIAL_SCOPE_DRIFT`
- `AI_SKILL_INSTRUCTION_DRIFT`
- `AI_POLICY_INTEGRITY_INVALID`
- `AI_SUPPLY_CHAIN_PROVENANCE_INVALID`
- `AI_REEVALUATION_REQUIRED`

## Evaluation

Required tests include:

- Skill Pack instructions changed with same version;
- schema changed after approval;
- tool publisher changes;
- tool destination expands;
- revoked component remains referenced by active config;
- malicious control artifact with hidden characters;
- model artifact provenance mismatch;
- evaluation bundle silently removes a blocker case;
- offline deployment cannot reach optional update source;
- rollback selects prior approved version without rewriting history;
- compromised component invalidates descendants; and
- model/tool metadata attempts to self-assert approved trust state.

## Hard release blockers

For security-sensitive agent capabilities:

- unknown/unapproved component loads on a privileged path;
- revoked component executes;
- security-relevant digest/schema/publisher drift executes without required re-review;
- invalid model provenance is accepted when policy requires binding;
- Skill Pack widens effective permissions through package change;
- policy/rule integrity failure is ignored;
- unsigned/unverified protected artifact is accepted when signature policy requires it; or
- evaluation evidence is treated as valid after its required bundle was materially weakened/unapproved.

## Build-versus-integrate principle

External research tools and scanners can inform tests or optional evaluation, but OpenAssetWatch should own the deterministic identity, authorization, trust, provenance, policy, and recovery contracts that define product security.

## Implementation sequence

1. Extend AI Component Registry schema/design with supply-chain fields.
2. Protect Skill Pack/version/digest before runtime loader implementation.
3. Reuse existing model-artifact provenance for local model routes.
4. Enforce tool identity/drift through Tool Gateway.
5. Protect policy/rule/workflow artifacts.
6. Add quarantine/revocation/rollback relationships.
7. Bind evaluation bundles to release evidence.
8. Add signatures/attestations where current project release architecture supports them.

No third-party component should become a runtime security boundary solely because it is open source or claims prompt/agent attack detection.