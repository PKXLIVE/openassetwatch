# Model Artifact Provenance and Qualification Binding

## Purpose

An artifact checksum proves only that a particular byte sequence has a stable
identity. It does not explain which checkpoint produced those bytes, which
converter or quantizer transformed them, which settings were used, which
runtime served them, or which qualification suite tested them. A model can load,
generate coherent text, and return valid JSON while still being unsuitable for
evidence-grounded Advisor work.

OpenAssetWatch therefore treats the local model supply chain as an explicit
sequence:

```text
source checkpoint
    -> conversion
    -> quantization or packaging
    -> model artifact
    -> inference runtime
    -> OpenAssetWatch qualification
    -> approved local Advisor use
```

OpenAssetWatch owns the contracts, policy, qualification binding, invalidation
state, and bounded status metadata. The operator continues to own and manage the
checkpoint, converter, quantizer, weights, and runtime outside OpenAssetWatch.

Read-only research into the unmerged experimental ROCmFPX PR #98 demonstrated
why this distinction matters: a converter correction could change generated
artifact semantics even when an earlier artifact still loaded. That research is
motivation only. It does not approve the pull request, set a supported runtime
commit, or establish support for any experimental model family.

## Versioned manifest

`oaw.model-artifact-manifest.v1` is a strict, provider-neutral JSON contract. It
contains these sections:

- `model_identity`: declared name, family, architecture, purpose, capabilities,
  upstream model identity, revision, and license
- `source_checkpoint`: immutable source revision, SHA-256 digest, format, size,
  license, and reviewed HTTPS reference
- `conversion`: converter name, version, exact commit, reviewed source,
  structured profile, input/output digests, and bounded timestamps
- `quantization`: quantizer name, version, exact commit, reviewed source,
  structured profile and type, optional importance-matrix digest, input/output
  digests, and bounded timestamps
- `artifact`: name, format, SHA-256 digest of the exact qualified bytes, size,
  split identity when applicable, optional parent digest, and creation time
- `runtime_compatibility`: provider protocol and optional runtime, backend,
  hardware, context, and memory compatibility observations
- `resource_observations`: optional measured, estimated, synthetic, or unknown
  conversion/quantization planning data
- `provenance_state` and a stable `created_at`

The models forbid unknown fields, bound strings and lists, reject non-finite or
negative measurements, require timezone-aware timestamps, and reject local
absolute paths and credential-bearing source URLs. Capabilities are declarations
in the manifest; a filename never proves a capability and actual Advisor
approval still depends on qualification.

### Provenance states

- `complete`: every required immutable source, converter, quantizer, artifact,
  and runtime identity is present and the lineage relationships validate.
- `partial`: the contract is structurally valid, but some lineage information
  is absent. It is not sufficient for manifest-bound Advisor approval.
- `unknown`: no trustworthy immutable lineage is asserted. It is not a claim
  that the artifact is malicious.
- `invalid`: the schema, digest, relationships, configured file, or evaluated
  trust input failed validation.
- `superseded`: the operator has deliberately replaced the artifact.
- `requalification-required`: a reviewed compatibility or correctness issue
  invalidated the previous qualification.

Resource observations are optional and never fabricate missing measurements.
They exist so a future Local Model Manager can preflight memory, temporary
storage, staging, and streaming requirements without turning estimates into
trust assertions.

## Canonical manifest digest

The `manifest_digest` is lowercase SHA-256 over UTF-8 canonical JSON with:

- the digest field itself excluded
- recursively stable object-key ordering
- compact separators and JSON finite-number rules
- timestamps normalized to UTC
- set-like capability and compatibility lists sorted and deduplicated
- artifact splits sorted by contiguous ordinal

Split artifacts also carry a separate SHA-256 digest over the ordered split
entries (`ordinal`, `name`, `digest`, and `size_bytes`). Identical semantic
content therefore has the same digest. Changing the source revision or digest,
converter commit, quantizer commit, artifact digest, runtime commit, or any other
manifest content changes the manifest digest.

The manifest digest is metadata identity, not a signature and not an artifact
hash. The artifact's own digest must identify the exact bytes tested by the
operator.

## Qualification binding

An optional `oaw.model-qualification-binding.v1` section in the existing local
qualification record binds approval to:

- artifact digest and manifest digest
- source checkpoint digest and revision
- converter and quantizer commits
- runtime commit
- qualification suite and fixture versions
- qualification completion time

When a manifest is configured, OpenAssetWatch requires complete provenance, an
approved qualification record, and an exact binding match. A change to any
bound identity or to the required suite/fixture version disables local Advisor
use until a new qualification is performed. Model output cannot assert or
override its own trust state.

The endpoint-only qualification harness accepts explicit provenance inputs:

```text
python scripts/qualify_local_ai.py \
  --base-url http://127.0.0.1:8080/v1 \
  --model operator-supplied-alias \
  --output operator-owned-qualification.json \
  --manifest operator-owned-manifest.json \
  --artifact-digest <lowercase-sha256> \
  --runtime-commit <exact-runtime-commit>
```

With `--manifest`, the artifact digest and runtime commit are mandatory and
must match before any endpoint request is sent. The harness does not discover or
hash model paths, download weights, launch or stop runtimes, convert or quantize
models, or delete artifacts.

## Artifact advisories and invalidation

`oaw.model-artifact-advisory.v1` describes a locally reviewed issue affecting an
exact source, converter, quantizer, runtime, artifact format, or qualification
suite identity. `oaw.model-artifact-advisory-registry.v1` is a bounded local
collection of those records.

The evaluator performs deterministic exact-string matching only. It does not
fetch advisories, inspect remote repositories, run Git, execute commands, or
modify model files. A matched advisory can be informational or require
requalification, reconversion, requantization, a runtime upgrade, or blocking
use. Reconversion, requantization, and runtime upgrades also invalidate the old
qualification. Severity and advisory state never become an OpenAssetWatch asset
finding or deterministic risk score.

No production advisory for experimental ROCmFPX PR #98 is included.

## Operator-owned configuration

The following variables are blank or compatibility-preserving by default:

```text
OPENASSETWATCH_AI_MODEL_MANIFEST=
OPENASSETWATCH_AI_REQUIRE_MODEL_MANIFEST=false
OPENASSETWATCH_AI_ARTIFACT_ADVISORIES=
```

`OPENASSETWATCH_AI_MODEL_MANIFEST` and
`OPENASSETWATCH_AI_ARTIFACT_ADVISORIES` refer to operator-owned local JSON files.
They are size-bounded, parsed with duplicate-key rejection, validated strictly,
and read only as regular non-symlink files. Paths and raw manifest content are
not exposed through provider status.

When `OPENASSETWATCH_AI_REQUIRE_MODEL_MANIFEST=true`, a missing, partial,
invalid, mismatched, or unbound manifest disables local Advisor use. Supplying a
manifest also opts into exact binding even when the policy flag is false;
configured invalid provenance always fails closed. An advisory registry without
a manifest cannot be evaluated and also fails closed.

The default demo provider and hosted external providers do not read or depend on
local artifact files. An unconfigured local provider retains the existing
compatibility behavior. A legacy approved qualification is reported as
`legacy-unbound`; it is never treated as a match for a configured manifest.

## Provider status and privacy

`GET /api/v1/ai/status` keeps these decisions separate:

- runtime `available`
- Advisor path `enabled`
- `qualification_state`
- `artifact_manifest_state`
- bounded artifact and manifest digests
- `provenance_state`
- `artifact_advisory_state` and match count
- `qualification_binding_state`

A runtime may be reachable while the Advisor path is disabled by incomplete
provenance, a mismatched binding, or an advisory. Status does not return local
paths, credentials, tokens, raw manifests, or arbitrary source URLs.

## Lifecycle and security boundaries

OpenAssetWatch does not automatically download, retain, convert, quantize,
launch, unload, or delete a model. It does not copy converter, quantizer, model,
or runtime source. Ordinary health checks read small metadata files only and do
not scan or hash large artifacts.

The longer-term direction remains one active generative model per bounded local
execution context, selected through provider-neutral routing. A future Local
Model Manager may add explicit operator workflows for registration, storage
planning, qualification history, advisory review, activation, rollback, and
safe retirement. It must preserve the same immutable identity, privacy,
read-only Advisor, tenant/site isolation, and human-control boundaries.

This contract does not require ROCmFPX, a GPU, or any model family. CPU-only and
other reviewed OpenAI-compatible local runtimes remain valid architectural
options.
