# Installers

Initial installer scaffolding was added for Linux, macOS, Windows, and Docker:

- `installers/linux/install.sh`
- `installers/linux/uninstall.sh`
- `installers/linux/status.sh`
- `installers/macos/install.sh`
- `installers/macos/uninstall.sh`
- `installers/macos/status.sh`
- `installers/windows/install.ps1`
- `installers/windows/uninstall.ps1`
- `installers/windows/status.ps1`
- `installers/docker/docker-compose.yml`
- `installers/docker/README.md`

## Current Scaffold State

These installers are service-shape scaffolds for local development and review.
They are not final production installers, they are not signed packages, and they
do not install offensive tools.

The Go build should produce the `oaw-agent`, `oaw-sensor`, `oaw-cli`,
`oaw-server`, `oaw-mcp-stdio`, and `oaw-test-config` binaries. Packaging tools
should wrap those signed Go binaries with platform-native service metadata,
config directory setup, and uninstall behavior.

The current scaffolds define:

- agent and sensor mode separation
- service name overrides
- config path overrides
- version display
- status commands
- least-privilege service defaults where practical
- no embedded secrets

## Deployment Identity And Enrollment

Signed binaries and native installers should remain generic where possible.
Tenant and deployment identity should be supplied by deployment config,
enrollment config, installer wrapper, MDM/RMM profile, or self-hosted
administrator-provided config.

Future installers should support:

- `site_id`: required environment/site/workspace boundary.
- `deployment_id`: unique GUID for the installer or deployment package. This is
  safe to log.
- `agent_id`: generated once per installed agent instance and persisted locally.
- `sensor_id`: generated once per installed sensor instance and persisted
  locally.
- optional `tenant_id` for hosted or multi-tenant control-plane enrollment.

Enrollment tokens, license keys, signing keys, and package signing material must
not be embedded in the repository or examples. Use secret references or
operator-provided placeholders only. Enrollment tokens are secrets and should
not be logged; `deployment_id` is not a secret.

Future installers should create or preserve a local identity file for
non-secret deployment identity, such as `site_id`, `deployment_id`, `agent_id`,
or `sensor_id`. This file must not contain enrollment tokens, license keys, API
keys, signing keys, or customer secrets. Enrollment token values should be
supplied through installer wrapper input, MDM/RMM secret delivery, CI/CD secret
references, or a self-hosted administrator-provided secret store.

Future default installed-agent identity locations should be:

- Windows: `%ProgramData%\OpenAssetWatch\Agent\identity\identity.json`
- Linux: `/etc/openassetwatch/agent/identity.json`
- macOS:
  `/Library/Application Support/OpenAssetWatch/Agent/identity/identity.json`

The current Go agent can explicitly initialize this non-secret file for local
development:

```powershell
go run ./cmd/oaw-agent identity init --site-id site-local --output identity.json
```

The command generates `agent_id` only for the local identity file. It preserves
a supplied `deployment_id` but does not fabricate one when it is omitted.

The first backend agent check-in endpoint is documented in
`docs/AGENT_CHECKIN.md`. It accepts identity and health metadata only; it does
not perform active network collection, execute commands, or enforce licensing.

## Requirements Covered

The scripts support:

- install, uninstall, and status commands
- `--version` display
- config path overrides
- service name overrides
- separate `agent` and `sensor` modes
- least-privilege service users where practical
- no offensive tool installation
- no secrets embedded in example configs

## Future Native Package Targets

The production release path should move from scripts to signed native packages:

- Windows: signed MSI.
- macOS: signed and notarized PKG.
- Linux: signed DEB and RPM.
- Docker: signed image with SBOM and provenance metadata.

Signing keys, certificates, notarization credentials, registry credentials, and
package repository credentials must only be referenced through CI/CD secret
names. Never commit signing material or raw secret values.

## Linux

The current Linux scaffold uses a systemd unit and defaults to:

- service name: `oaw-agent` or `oaw-sensor`
- config path: `/etc/openassetwatch/<mode>.json`
- binary path: `/usr/local/bin/oaw-<mode>`
- service user: `openassetwatch`

The future Linux release path should build signed DEB and RPM packages that
install the binary, config directory, service unit, logs/state directories, and
uninstall metadata.

## macOS

The current macOS scaffold uses a LaunchDaemon and defaults to:

- service label: `com.openassetwatch.agent` or `com.openassetwatch.sensor`
- config path: `/Library/Application Support/OpenAssetWatch/<mode>.json`
- binary path: `/usr/local/bin/oaw-<mode>`

The future macOS release path should build a signed and notarized PKG that
installs the binary, LaunchDaemon, config directory, logs/state directories, and
uninstall metadata.

## Windows

The current Windows scaffold uses a Windows service and defaults to:

- service name: `oaw-agent` or `oaw-sensor`
- config path: `%ProgramData%\OpenAssetWatch\<mode>.json`
- binary path: `%ProgramFiles%\OpenAssetWatch\oaw-<mode>.exe`
- service account: `NT AUTHORITY\LocalService`

The future Windows release path should build a signed MSI that installs the
binary, creates the Windows service, sets least-privilege defaults, writes no
secrets, and supports repair/uninstall flows.

## Docker

The Docker compose file is a future server packaging scaffold. It requires
`OAW_POSTGRES_PASSWORD` to be set outside the compose file and does not include
secrets or offensive tooling.

The future Docker path should publish signed images with SBOM and provenance
metadata. Image tags should point to immutable builds tied to source commits and
release versions.

## Related Docs

- `docs/SIGNED_RELEASES.md`
- `docs/RELEASE_PIPELINE.md`
