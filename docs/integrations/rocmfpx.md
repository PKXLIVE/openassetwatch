# Optional ROCmFPX Runtime Compatibility

## Compatibility target

ROCmFPX is an optional external inference implementation behind the existing
OpenAI-compatible provider. It is not part of OpenAssetWatch core architecture
and is not vendored or installed by OpenAssetWatch.

The read-only compatibility review used merged ROCmFPX `main` at:

```text
c49ebdbd5c9f01ec242369f9e7f7967855f80cba
2026-08-22T13:09:40-04:00
```

On the review date, `main` was exactly that commit; there were no merged changes
newer than the supplied reference. The merge identifies pull request 94,
`experimental/rocmi4-iu4`. Production identity must record the exact commit and
must not use only `main` or `latest`.

The following are upstream capabilities observed in merged source and
documentation, not OpenAssetWatch runtime measurements:

- `llama-server` exposes `/health`, `/v1/models`, and synchronous/streaming
  `/v1/chat/completions`
- chat completions accept JSON and JSON-schema response formats
- OpenAI-style native/generic function-call parsing is available, with
  model/template-dependent behavior
- `/props` reports server/model/template properties and capability metadata
- optional `/metrics` can expose request, queue, token, and throughput metrics
- agent-oriented ROCmFPX quant profiles aim to preserve JSON, tool, code, and
  chat coherency
- embedded MTP/NextN speculative decoding is supported for compatible models
  and remains model/workload dependent

OpenAssetWatch does not assume any of these optional capabilities. The
qualification harness measures the endpoint behavior it actually receives and
leaves undetected capabilities unavailable.

## Deployment relationship

```text
OpenAssetWatch backend
        |
        | bounded local HTTP, OpenAI-compatible
        v
ROCmFPX llama-server
        |
        +-- ROCm/HIP backend
        `-- Vulkan backend
```

Keep the application and runtime lifecycles separate. Bind a dedicated test or
single-host deployment to `127.0.0.1`. In Compose, use an isolated service
network and configure only the exact service hostname:

```text
OPENASSETWATCH_AI_PROVIDER=openai-compatible
OPENASSETWATCH_AI_EXTERNAL_ENABLED=false
OPENASSETWATCH_AI_BASE_URL=http://rocmfpx:8080/v1
OPENASSETWATCH_AI_MODEL=operator-supplied-alias
OPENASSETWATCH_AI_LOCAL_PROVIDER_HOSTS=rocmfpx
```

When the model artifact provenance policy is enabled, record the exact source
checkpoint revision/digest, converter commit, quantizer commit, resulting
artifact digest, and runtime commit in the provider-neutral manifest, then bind
qualification to those immutable values. Compatibility metadata or a successful
load does not authorize the runtime or artifact. See
[`MODEL_ARTIFACT_PROVENANCE.md`](../MODEL_ARTIFACT_PROVENANCE.md).

Do not expose the inference listener to the LAN. Do not give it database,
collector, agent, or admin credentials, and do not mount OpenAssetWatch storage
into it. OpenAssetWatch sends only bounded Advisor context and never calls
ROCmFPX model load/unload, shell, file, browsing, or arbitrary network tools.

## R9700 and backend safety

ROCmFPX merged build logic distinguishes both RDNA4 targets:

- `gfx1200`: Navi 44
- `gfx1201`: Navi 48, including AMD Radeon AI PRO R9700

The RDNA4 wrapper can fall back to `gfx1200` when detection is unavailable.
Therefore an R9700 build must explicitly record and verify `gfx1201`; a
`gfx1200` build is not an acceptable R9700 qualification target.

Before any live GPU validation on the approved R9700 host:

```text
r9700-health
```

If that command fails, stop. Do not install or upgrade ROCm, PyTorch, drivers,
firmware, or system Python; do not change BIOS settings or global
`HIP_VISIBLE_DEVICES`; and do not add an alternate ROCm stack. Target the R9700,
not another installed GPU. If the approved ROCm/HIP path is not cleanly
available, use the runtime's supported Vulkan path rather than altering the
machine to force HIP support.

No OpenAssetWatch performance claim should be derived from ROCmFPX upstream
benchmarks. Latency and throughput belong in a qualification result only when
measured on the stated pinned runtime, model, backend, and hardware.

## Safe later validation sequence

Use only an already-present, operator-approved model. Do not fetch a model to
complete validation.

1. Run `r9700-health` and stop if it fails.
2. Verify the intended device is the AI PRO R9700 and the pinned ROCmFPX build
   architecture is `gfx1201`.
3. Start the pinned `llama-server` bound to `127.0.0.1:<port>` with an explicit
   alias and the existing approved model path.
4. Run:

```powershell
python scripts/qualify_local_ai.py `
  --base-url http://127.0.0.1:<port>/v1 `
  --model <alias> `
  --output local-ai-qualification.json `
  --runtime-id rocmfpx-local-r9700 `
  --runtime-type ROCmFPX `
  --runtime-commit c49ebdbd5c9f01ec242369f9e7f7967855f80cba `
  --backend <ROCm-or-Vulkan> `
  --hardware-vendor AMD `
  --hardware-device-name "AMD Radeon AI PRO R9700" `
  --hardware-architecture gfx1201 `
  --manifest <operator-owned-manifest.json> `
  --artifact-digest <sha256-digest> `
  --quantization <quantization> `
  --quant-profile <profile> `
  --model-source <operator-recorded-source> `
  --model-license <license-or-unknown> `
  --declared-capability mtp
```

Include `--declared-capability mtp` only when the pinned runtime/model pairing
actually exposes and uses that capability; omit it otherwise. Declared
capabilities are provenance, not measured benchmark results.

5. Inspect the result and use it only if `advisor_approved` is `true`.
6. Stop the test server cleanly and confirm the listener and GPU allocation are
   gone. Do not retain an extra model without explicit operator approval.

The source, converter, quantizer, artifact, and runtime identities must be
recorded and bound separately from the ROCmFPX MIT runtime license.

## Validation status for this integration

```text
LIVE MODEL QUALIFICATION: NOT RUN
Reason: no operator-approved existing model path was supplied

R9700/GFX1201 LIVE VALIDATION: NOT RUN
Reason: no operator-approved existing model/runtime pairing was supplied

MODEL DOWNLOAD: NOT PERFORMED
```

All automated integration tests use mocks and fixtures. No ROCmFPX binary,
model, qualification output, or benchmark artifact belongs in the repository.
