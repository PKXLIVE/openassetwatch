# Local OpenAI-Compatible Inference

## Purpose and boundary

OpenAssetWatch can send a bounded AI Advisor request to an already-running
local OpenAI-compatible endpoint. The runtime is an implementation behind the
existing `OpenAICompatibleProvider`; it is not a collector, sensor, ingestion
path, evidence source, deterministic engine, tool gateway, or authorization
service.

```text
normalized evidence and deterministic findings
                    |
                    v
              AI Advisor
                    |
                    v
       OpenAICompatibleProvider
                    |
                    v
        local HTTP /v1 boundary
                    |
                    v
       operator-managed inference runtime
```

The runtime receives only the Advisor's bounded, projected evidence context.
It receives no database credentials, collector credentials, admin tokens,
storage access, raw collector submissions, arbitrary network tool, shell, or
write capability. Deterministic classification, findings/risk, and
vulnerability matching remain factual authorities. Model output is advisory,
read-only, tenant/site scoped by the context assembled before the provider
call, and rejected when it cites unknown evidence IDs.

OpenAssetWatch does not install, download, convert, start, stop, or delete a
model. The operator owns the runtime and model lifecycle.

## Local endpoint trust policy

Built-in local names remain:

- `localhost`
- `127.0.0.1`
- `::1`
- `host.docker.internal`

An exact container/service hostname can be added with:

```text
OPENASSETWATCH_AI_LOCAL_PROVIDER_HOSTS=approved-ai-service
```

The setting accepts comma-separated DNS hostnames and performs exact,
case-normalized matching. It does not support wildcards, suffix rules, CIDRs,
or IP addresses. Private, reserved, link-local, and metadata IP literals remain
blocked. Known metadata hostnames remain blocked even if configured. Provider
URLs cannot contain credentials, query strings, or fragments. Redirects are
not followed, and local requests bypass environment HTTP proxies so local
evidence is not accidentally forwarded to a proxy.

Before each local request, OpenAssetWatch resolves the exact trusted name into
a bounded address set. Every answer must be loopback or private; public,
link-local, multicast, unspecified, reserved, empty, oversized, and mixed-safe
answer sets fail closed. The transport connects to one validated address,
preserves the original HTTP Host and HTTPS certificate name, and verifies that
the connected peer matches the pinned address. This closes DNS rebinding and
time-of-check/time-of-use gaps without turning private address space into an
allowlist.

An unlisted name such as `approved-ai-service` is rejected over local HTTP. An
arbitrary `10.x`, `172.16-31.x`, or `192.168.x` address is also rejected. Trust
only the exact service name controlled by the deployment operator.

## Configuration

The deterministic provider remains the default. A local endpoint is opt-in:

```text
OPENASSETWATCH_AI_PROVIDER=openai-compatible
OPENASSETWATCH_AI_EXTERNAL_ENABLED=false
OPENASSETWATCH_AI_BASE_URL=http://host.docker.internal:8080/v1
OPENASSETWATCH_AI_MODEL=operator-supplied-alias
OPENASSETWATCH_AI_LOCAL_PROVIDER_HOSTS=
OPENASSETWATCH_AI_QUALIFICATION_RESULT=
```

For a Compose service, replace the base hostname and set the exact trust entry:

```text
OPENASSETWATCH_AI_BASE_URL=http://approved-ai-service:8080/v1
OPENASSETWATCH_AI_LOCAL_PROVIDER_HOSTS=approved-ai-service
```

Do not put API keys, real model paths, or qualification artifacts in tracked
configuration. `OPENASSETWATCH_AI_EXTERNAL_ENABLED` stays `false` for local
inference. A local API key, if the runtime requires one, belongs only in the
untracked runtime environment.

## Provider-neutral metadata

`backend/app/local_ai.py` defines `oaw.local-ai.v1` contracts for:

- runtime identity, version, commit, protocol, location, backend, and health
- model alias, digest, size, quantization, profile, source, and license
- generic hardware vendor, device, architecture, memory, and precision
- generic capabilities such as structured output, tool calling, streaming,
  MTP, MoE, and long context
- measured metrics when available, with unavailable values left `null`
- individual qualification tests, summary counts, and `advisor_approved`

GPU hardware is optional. CPU-only providers remain valid. No metric is
fabricated: the initial provider status returns unavailable metrics as `null`
rather than treating missing telemetry as zero.

`GET /api/v1/ai/status` can return the validated runtime metadata, current
health probe time, and qualification state. Set
`OPENASSETWATCH_AI_QUALIFICATION_RESULT` to an operator-owned result file to
connect the record to status. The file is bounded to 1 MB and must match the
configured base URL and model alias. Once this path is configured, an unreadable,
invalid, mismatched, rejected, or incomplete record disables local Advisor use.
If the path is absent, existing local-provider compatibility is preserved and
the status reports `not-configured`.

## Qualification harness

The harness tests an endpoint; it never accepts a model path and has no
download or server-launch option:

```powershell
python scripts/qualify_local_ai.py `
  --base-url http://127.0.0.1:8080/v1 `
  --model operator-supplied-alias `
  --output local-ai-qualification.json
```

For an exact container hostname, repeat `--trusted-local-host` as needed. Never
pass an API key on the command line; `--api-key-env` names an environment
variable containing an optional local key. `--declared-capability` can record
an operator-verified generic capability such as `mtp` or `moe`; measured
structured-output, tool-calling, and streaming gates override declarations.

Required gates cover:

- `/models` and `/chat/completions` connectivity
- deterministic arithmetic and concise formatting
- strict OpenAssetWatch-controlled JSON
- evidence, asset, finding, and CVE grounding
- hostile evidence/prompt-injection containment
- preservation of all deterministic authorities
- advisory-only output with no executed-action claim
- bounded response handling and fail-closed malformed/timeout behavior

The harness also probes `/health` where available. It tests streaming and one
read-only test tool when the endpoint exposes those capabilities. If a tool call
is detected, any unapproved name or arguments become a required failure. The
harness never executes the returned tool call.

`advisor_approved` is derived, not trusted from input. It becomes `true` only
when every baseline gate and every detected required capability gate passes.
Fast generation or coherent prose alone cannot approve a model.

## Pinning, storage, and removal

For a reproducible production record, supply a runtime version/commit, backend,
hardware architecture, model alias and digest, quantization/profile, source,
and model license when known. A runtime license and a model license are
independent; approval of one does not grant rights to use the other.

Keep one active generative model unless an operator explicitly approves
retaining another. To unload cleanly, stop the dedicated runtime process or
container and confirm its health endpoint is no longer reachable. If the
operator deliberately uses a runtime's model-router mode, use that runtime's
authenticated administrative unload procedure outside OpenAssetWatch.
OpenAssetWatch never invokes runtime load/unload endpoints. Remove an unused
model file only under the operator's storage policy and only after verifying it
is not referenced by another service or qualification record.

## Current limitations

- Qualification records are file-backed; there is not yet a tenant-scoped
  model registry or database migration.
- Setting a qualification path enables fail-closed enforcement. Deployments
  that leave it unset retain existing compatibility and must enforce their
  qualification policy operationally.
- Provider status does not scrape runtime metrics yet. Missing values remain
  unavailable rather than synthetic.
- OpenAssetWatch does not manage runtime processes, GPU allocation, or models.

See `docs/integrations/rocmfpx.md` for the optional ROCmFPX compatibility note.
