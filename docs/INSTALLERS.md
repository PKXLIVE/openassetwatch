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
