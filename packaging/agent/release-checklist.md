# Agent Release Artifact Checklist

This checklist defines the future release artifact gates for OpenAssetWatch
agent packages. It is not an implementation and does not build, sign, install,
uninstall, upgrade, roll back, or publish anything.

## Build Inputs

- [ ] version is selected from an approved release channel
- [ ] source commit is reviewed and tagged according to release policy
- [ ] Go agent binary build is reproducible for each supported OS/architecture
- [ ] local `dist/` binary artifact generated with
      `scripts/release/build_agent_dist.ps1` where appropriate
- [ ] package manifest template is selected for the target OS
- [ ] no secrets are present in manifests, docs, config examples, or artifacts

## Binary Artifact Metadata

- [ ] artifact is written under ignored `dist/agent/<version>/<os>-<arch>/`
- [ ] artifact name is `oaw-agent` or `oaw-agent.exe` on Windows
- [ ] SHA256 checksum file is generated
- [ ] JSON manifest is generated
- [ ] manifest includes artifact name, version, OS, architecture,
      repo-relative path, SHA256, build timestamp, and git commit when
      available
- [ ] generated `dist/` artifacts are not committed
- [ ] local binary generation does not build installers or native packages

## TAR.GZ Package Metadata

- [ ] source artifact directory exists under
      `dist/agent/<version>/<os>-<arch>/`
- [ ] source artifact directory contains exactly one binary manifest
- [ ] source artifact checksum matches the binary manifest
- [ ] TAR.GZ package is written under ignored
      `dist/agent/<version>/packages/`
- [ ] package SHA256 checksum file is generated
- [ ] package manifest is generated
- [ ] package manifest includes package name, version, OS, architecture,
      package type, source artifact path, package path, SHA256, build
      timestamp, and git commit when available
- [ ] archive contains only the agent binary, binary checksum, binary manifest,
      and safe README notes
- [ ] archive does not include config files, identity files, enrollment tokens,
      credentials, logs, status files, service definitions, or generated
      secrets

## Release Validation

- [ ] `scripts/release/validate_agent_release.ps1` passes for the selected
      version
- [ ] validation output is JSON only
- [ ] binary artifact directories exist
- [ ] binary SHA256 checksum files match binaries and manifests
- [ ] binary manifests contain required fields
- [ ] package validation runs with `-IncludePackages` when TAR.GZ output is
      expected
- [ ] TAR.GZ package checksums match packages and manifests
- [ ] TAR.GZ package manifests contain required fields
- [ ] TAR.GZ archives do not contain config files, identity files, enrollment
      tokens, credentials, logs, status files, service definitions, or
      generated secrets
- [ ] generated `dist/` artifacts remain ignored and are not committed

## Local Install Staging

- [ ] `scripts/release/stage_agent_install.py` passes against the selected
      TAR.GZ package
- [ ] staging output is JSON only
- [ ] package file exists under `dist/agent/<version>/packages/`
- [ ] package SHA256 checksum matches the package manifest and checksum file
- [ ] package manifest contains required fields
- [ ] archive paths are safe and contain no forbidden entries
- [ ] staging output is written under ignored
      `dist/staging/agent/<version>/<os>-<arch>/`
- [ ] staged layout contains `binary/`, `config/`, `identity/`, `logs/`,
      `status/`, `service/`, and `package-metadata/`
- [ ] staged config and identity directories contain only placeholder README
      files, not real values
- [ ] staged logs and status directories contain only placeholder README files,
      not runtime state
- [ ] staged service directory contains only placeholder README files, not
      installed service definitions
- [ ] no files are written to Program Files, ProgramData, `/usr`, `/etc`,
      `/var`, `/Library`, service-manager paths, or package-manager metadata
      paths
- [ ] generated staging artifacts remain ignored and are not committed

## Local Sandbox Install Proof

- [ ] `scripts/release/install_agent_local.py` passes against the selected
      staged layout or TAR.GZ package
- [ ] install output is JSON only
- [ ] install output includes `ok`, `install_root`, `files`, `checks`,
      `warnings`, and `errors`
- [ ] default install output is written under ignored
      `dist/local-install/agent/<version>/<os>-<arch>/`
- [ ] explicit install roots outside the repository are refused
- [ ] local proof layout contains `binary/`, `config/`, `identity/`, `logs/`,
      `status/`, `service/`, and `package-metadata/`
- [ ] only safe files are copied: agent binary, checksum files, manifest files,
      README/install notes, and package metadata
- [ ] config and identity directories contain only placeholder README files,
      not real values
- [ ] logs and status directories contain only placeholder README files, not
      runtime state
- [ ] service directory contains only placeholder README files, not installed
      service definitions
- [ ] no files are written to Program Files, ProgramData, `/usr`, `/etc`,
      `/var`, `/Library`, service-manager paths, or package-manager metadata
      paths
- [ ] generated local install artifacts remain ignored and are not committed

## Local Sandbox Uninstall Proof

- [ ] `scripts/release/uninstall_agent_local.py` passes against the selected
      local sandbox install root
- [ ] uninstall output is JSON only
- [ ] uninstall output includes `ok`, `install_root`, `removed`, `checks`,
      `warnings`, and `errors`
- [ ] uninstall removes only roots under
      `dist/local-install/agent/<version>/<os>-<arch>/`
- [ ] uninstall roots outside the repository are refused
- [ ] paths that look like Program Files, ProgramData, `/usr`, `/etc`, `/var`,
      or `/Library` are refused
- [ ] expected package metadata is required by default
- [ ] `--force` allows removal of an incomplete repo-local sandbox install
      root only
- [ ] generated release packages under `dist/agent/<version>/packages/` remain
      in place
- [ ] config, identity, logs, and status outside the sandbox install root are
      not removed
- [ ] no services are unregistered, started, stopped, installed, or modified
- [ ] no package-manager or service-manager commands are executed

## Agent Installation Foundation Status

The current phase proves that OpenAssetWatch can build, package, validate, and
stage an agent release safely without modifying the host operating system.

Complete for this phase:

- [x] agent dist artifact generation
- [x] SHA256 checksum generation
- [x] binary manifest generation
- [x] TAR.GZ package creation
- [x] TAR.GZ checksum generation
- [x] package manifest generation
- [x] local release orchestration helper
- [x] release validation helper
- [x] local install-staging helper
- [x] proof install layout under ignored `dist/staging/`
- [x] local sandbox install helper
- [x] proof local install layout under ignored `dist/local-install/`

Future work:

- [ ] real OS installation
- [ ] writing to Program Files, ProgramData, `/usr`, `/etc`, `/var`, or
      `/Library`
- [ ] service installation
- [ ] daemon or service runtime
- [ ] scheduling
- [ ] `.deb` package build
- [ ] `.rpm` package build
- [ ] Windows MSI
- [ ] macOS signed/notarized package
- [ ] package-manager execution
- [ ] service-manager execution
- [ ] self-update
- [ ] licensing enforcement

## Local Release Orchestration

- [ ] `scripts/release/release_agent_local.ps1` passes for the selected
      version
- [ ] orchestration output is JSON only
- [ ] output includes `ok`, `version`, `artifacts`, `packages`, `checks`,
      `warnings`, and `errors`
- [ ] orchestration calls the build, TAR.GZ package, and release validation
      helpers rather than duplicating their logic
- [ ] generated artifacts remain under ignored `dist/` paths
- [ ] generated artifacts are not staged or committed
- [ ] orchestration does not build MSI, DEB, RPM, or PKG packages
- [ ] orchestration does not install software, modify the OS, write service
      definitions, execute package-manager commands, execute service-manager
      commands, contact network services, or store secrets

## Package Build

- [ ] package build planned for each target package type
- [ ] Windows MSI future package layout reviewed
- [ ] Linux `.deb` future package layout reviewed
- [ ] Linux `.rpm` future package layout reviewed
- [ ] Linux `.tar.gz` fallback layout reviewed
- [ ] macOS signed/notarized package layout reviewed
- [ ] package includes only approved binary and non-secret metadata
- [ ] package preserves config and identity during upgrade
- [ ] package does not delete config, identity, or logs by default

## Artifact Validation

- [ ] checksum generated for each artifact
- [ ] signature placeholder or signing workflow reference documented
- [ ] macOS notarization placeholder documented where applicable
- [ ] SBOM placeholder documented
- [ ] provenance attestation placeholder documented
- [ ] package metadata paths reviewed
- [ ] artifact names include OS, architecture, version, and package type

## Lifecycle Validation

- [ ] install validation planned
- [ ] uninstall validation planned
- [ ] upgrade validation planned
- [ ] rollback validation planned
- [ ] service definition review planned before service installation exists
- [ ] `oaw-agent doctor` validation planned after install or upgrade
- [ ] `oaw-agent status` validation planned after install or upgrade
- [ ] `oaw-agent check-in` validation planned where backend access is available

## Safety Gates

- [ ] no package-manager commands are executed by the running agent
- [ ] no service-manager commands are executed by planning commands
- [ ] no silent self-install behavior exists
- [ ] no silent self-upgrade behavior exists
- [ ] no scheduler or daemon behavior is introduced by package scaffolding
- [ ] no secrets are written to logs, config examples, identity examples, or
      package manifests
- [ ] no active scanning or offensive tooling is packaged
