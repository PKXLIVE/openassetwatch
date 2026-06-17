# Internal Packages

Internal Go packages are implementation details for OpenAssetWatch commands.
They should stay defensive, passive-first, and evidence-oriented.

- `agent`: agent heartbeat/runtime helpers.
- `sensor`: passive sensor profile helpers.
- `collector`: local inventory assembly.
- `detector`: platform and local evidence detection.
- `network`: neighbor observation models and safe processing helpers.
- `config`: runtime config loading and quarantine-path refusal.
- `output`: output writers.
- `api`: API path/client constants.
- `auth`: secret reference types, not secret values.
- `audit`: audit event primitives.
- `storage`: storage interfaces.
- `updater`: update planning primitives.
- `installer`: service specification helpers.

Do not place offensive tooling, raw scanner wrappers, arbitrary command
execution, or credential handling in these packages.
