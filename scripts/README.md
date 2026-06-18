# Scripts

Reserved for repository maintenance and local validation scripts. Runtime
installers belong under `installers/`; production tool execution wrappers
should not be added here.

- `e2e/`: local development validation helpers. These must stay defensive,
  local-only, and explicit about any backend URL they contact.
- `release/`: local release artifact helpers. These may build local binaries
  into ignored `dist/` paths, create local TAR.GZ archives from existing dist
  artifacts, validate generated release artifacts, orchestrate the local
  release flow, stage a local proof-of-layout install tree under ignored
  `dist/` paths, create a local sandbox install proof under ignored `dist/`
  paths, remove only that local sandbox install proof, and generate metadata,
  but must not install software, build native installers, modify services, or
  execute package managers.
