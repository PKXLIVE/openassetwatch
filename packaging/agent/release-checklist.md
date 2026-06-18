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
