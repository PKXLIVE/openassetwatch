# Scripts

Reserved for repository maintenance and local validation scripts. Runtime
installers belong under `installers/`; production tool execution wrappers
should not be added here.

- `e2e/`: local development validation helpers. These must stay defensive,
  local-only, and explicit about any backend URL they contact.
- `release/`: local release artifact helpers. These may build local binaries
  into ignored `dist/` paths, create local TAR.GZ archives from existing dist
  artifacts, create local Debian package artifacts from existing Linux dist
  artifacts, validate generated Debian package artifacts, `/opt` layout,
  compatibility symlink, service-account metadata, scoped sudoers artifact
  content, systemd metadata, target-install service enablement, and
  config/identity-guarded service startup metadata without installing them,
  validate generated release artifacts, orchestrate the local release flow,
  stage a local
  proof-of-layout install tree under ignored `dist/` paths, create a local
  sandbox install proof under ignored `dist/` paths, remove only that local
  sandbox install proof, exercise local sandbox upgrade and rollback proofs,
  and generate metadata, but must not install software, build native
  installers, modify host services, modify host sudoers state, or execute
  package managers.
