# Scripts

Reserved for repository maintenance and local validation scripts. Runtime
installers belong under `installers/`; production tool execution wrappers
should not be added here.

- `e2e/`: local development validation helpers. These must stay defensive,
  local-only, and explicit about any backend URL they contact.
- `release/`: local release artifact helpers. These may build local binaries
  into ignored `dist/` paths and generate metadata, but must not install
  software, build native installers, modify services, or execute package
  managers.
