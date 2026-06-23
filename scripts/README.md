# Scripts

Reserved for repository maintenance and local validation scripts. Runtime
installers belong under `installers/`; production tool execution wrappers
should not be added here.

- `e2e/`: local development validation helpers. These must stay defensive,
  local-only, and explicit about any backend URL they contact.
- `release/`: local release artifact helpers. These may build local binaries
  into ignored `dist/` paths, create local TAR.GZ archives from existing dist
  artifacts, create local Debian package artifacts from existing Linux dist
  artifacts, validate generated Debian package artifacts, create real RPM
  package artifacts from existing Linux dist artifacts when `rpmbuild` is
  available, validate generated RPM packages, staging trees, spec files,
  staged payloads, `/opt` layout, compatibility command paths, root-owned
  executable and libexec helper metadata,
  service-account metadata, scoped sudoers helper allowlist content, systemd
  metadata, target-install timer enablement, config/identity-guarded timer
  startup metadata, final-removal timer cleanup metadata, and conservative
  `LicenseRef-OpenAssetWatch-UNSPECIFIED` package license metadata while the
  repository lacks an authoritative license declaration, without installing
  them, stage Windows Program
  Files/ProgramData install layout proofs from existing Windows dist
  artifacts without creating services, validate staged Windows
  install layout proofs without creating services, scheduled tasks, registry
  entries, or MSI packages, build unsigned Windows MSI artifacts with the
  repo-pinned WiX Toolset local tool, validate Windows MSI checksum/manifest
  metadata, provide explicit Windows signing and verification hooks, provide
  explicit Windows service install and
  uninstall helpers with dry-run validation for administrator-controlled use,
  provide explicit Windows file install and uninstall helpers with dry-run
  validation for administrator-controlled file copy and cleanup, stage and
  validate macOS LaunchDaemon install layouts from existing Darwin artifacts,
  build unsigned macOS PKG artifacts with Apple packaging tools on macOS using
  numeric receipt versions, verify Darwin slice/universal architecture inputs,
  provide explicit macOS signing and notarization hooks that sign the embedded
  binary before pkgroot staging and regenerate final checksum/manifest metadata
  after notarization/stapling, support hosted signed-release workflows that
  import signing identities into a temporary keychain and materialize
  notarization API-key material only in runner temp storage, provide a safe
  macOS uninstaller with dry-run,
  root-precondition failure, no system-Python dependency, and data-preservation
  defaults, validate
  generated release artifacts, orchestrate the local release flow, stage a local
  proof-of-layout install tree under ignored `dist/` paths, create a local
  sandbox install proof under ignored `dist/` paths, remove only that local
  sandbox install proof, exercise local sandbox upgrade and rollback proofs,
  and generate metadata. Except for explicit administrator-controlled Windows
  helper execution and ignored local MSI artifact generation, these scripts
  must not install software, modify host services, modify host sudoers state,
  or execute package managers.
