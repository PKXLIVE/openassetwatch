# OpenAssetWatch Agent macOS Deployment

This guide covers the production-oriented macOS agent package path. The macOS
agent is installed as a system LaunchDaemon and runs the existing portable
supervisor through:

```text
/Library/Application Support/OpenAssetWatch/Agent/bin/oaw-agent service run --config /Library/Application Support/OpenAssetWatch/Agent/config/config.json --identity-file /Library/Application Support/OpenAssetWatch/Agent/identity/identity.json --output-dir /Library/Application Support/OpenAssetWatch/Agent/state
```

The agent stays passive-first: it reads local interfaces, local route metadata,
and the local ARP cache. It does not scan networks, run remote commands, execute
arbitrary shells, rotate identity during install, or overwrite administrator
config.

## Supported Systems

- macOS package builds support Apple Silicon `arm64` and Intel `x86_64`.
- The normal distribution artifact is a universal package:
  `OpenAssetWatchAgent-<version>-macos-universal.pkg`.
- CI builds architecture-specific packages and a universal unsigned validation
  package. Release signing and notarization require Apple Developer credentials.
- Current CI exercises macOS 15 on Apple Silicon and Intel runners. Earlier
  macOS support claims must not be treated as tested until matching CI or
  release-validation evidence exists.
- macOS PKG receipt versions must be numeric with one to three dot-separated
  components. Prerelease and build suffixes are rejected for PKG builds to
  avoid mapping different release versions to the same installed receipt
  version.
- Local unsigned PR artifacts are validation artifacts only and are not
  release-ready.

## Installed Layout

| Item | Path |
| --- | --- |
| Binary | `/Library/Application Support/OpenAssetWatch/Agent/bin/oaw-agent` |
| Config | `/Library/Application Support/OpenAssetWatch/Agent/config/config.json` |
| Identity | `/Library/Application Support/OpenAssetWatch/Agent/identity/identity.json` |
| State | `/Library/Application Support/OpenAssetWatch/Agent/state` |
| Status | `/Library/Application Support/OpenAssetWatch/Agent/state/status.json` |
| Inventory | `/Library/Application Support/OpenAssetWatch/Agent/state/last-inventory.json` |
| Logs | `/Library/Logs/OpenAssetWatch/Agent` |
| LaunchDaemon | `/Library/LaunchDaemons/com.openassetwatch.agent.plist` |
| Install manifest | `/Library/Application Support/OpenAssetWatch/Agent/install-manifest.json` |

The package identifier and launchd label are both `com.openassetwatch.agent`.
The service account and group are `_openassetwatch`.

## Install

Interactive installation uses Installer.app by opening the signed package.
Command-line installation uses:

```bash
sudo installer -pkg OpenAssetWatchAgent-<version>-macos-universal.pkg -target /
```

The postinstall script creates or validates `_openassetwatch`, applies
ownership and modes, validates the plist with `plutil`, bootstraps the
LaunchDaemon, enables it, and kickstarts it. It does not perform backend
check-in itself and it succeeds when real config and identity files are not yet
provisioned; the daemon remains running in degraded retry state until ready.

## Provisioning

The package installs placeholder examples only:

```text
/Library/Application Support/OpenAssetWatch/Agent/config/config.example.json
/Library/Application Support/OpenAssetWatch/Agent/identity/identity.example.json
```

Create real files as administrator-controlled data:

```bash
sudo install -o root -g _openassetwatch -m 0640 config.json "/Library/Application Support/OpenAssetWatch/Agent/config/config.json"
sudo install -o root -g _openassetwatch -m 0640 identity.json "/Library/Application Support/OpenAssetWatch/Agent/identity/identity.json"
```

After provisioning, restart the daemon cycle:

```bash
sudo launchctl kickstart -k system/com.openassetwatch.agent
```

## Launchd Operations

Use modern launchctl verbs:

```bash
sudo launchctl print system/com.openassetwatch.agent
sudo launchctl bootout system /Library/LaunchDaemons/com.openassetwatch.agent.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.openassetwatch.agent.plist
sudo launchctl enable system/com.openassetwatch.agent
sudo launchctl kickstart -k system/com.openassetwatch.agent
```

Do not use deprecated `launchctl load` or `launchctl unload`.

The plist uses `ProgramArguments` as an array, `RunAtLoad=true`,
`KeepAlive=true`, `ThrottleInterval=60`, `ProcessType=Background`,
`ExitTimeOut=30`, `WorkingDirectory` set to the state directory, umask `"027"`,
and `UserName`/`GroupName` set to `_openassetwatch`. The daemon relies on the
internal supervisor for transient config, identity, DNS, backend, HTTP, and
collection failures; those transient failures must not exit the process.

## Status And Logs

Status and inventory:

```bash
sudo cat "/Library/Application Support/OpenAssetWatch/Agent/state/status.json"
sudo ls -l "/Library/Application Support/OpenAssetWatch/Agent/state/last-inventory.json"
```

Logs are written by the agent with bounded rotation under:

```text
/Library/Logs/OpenAssetWatch/Agent/oaw-agent.log
```

Logs must not contain config contents, identity contents, tokens, credentials,
passwords, API keys, authorization headers, request bodies, response bodies, or
private keys.

## Repair, Upgrade, Rollback

Reinstalling the same trusted package repairs package-managed files and
reapplies permissions without overwriting real config, identity, state, or logs.

Upgrade behavior:

- preinstall boots out the existing daemon;
- package-managed files are replaced;
- config, identity, state, and logs are preserved;
- postinstall reapplies safe permissions and bootstraps the daemon.

Downgrades are refused unless an administrator performs an explicit rollback
using a previous trusted signed package. Rollback preserves config and identity.
There is no automatic rollback and no self-update behavior.

## Uninstall

Use the explicit uninstaller:

```bash
sudo bash scripts/release/uninstall_agent_macos.sh
```

Defaults preserve config, identity, state, logs, and the service account.
Optional cleanup flags:

```bash
sudo bash scripts/release/uninstall_agent_macos.sh --remove-state --remove-logs
sudo bash scripts/release/uninstall_agent_macos.sh --purge
```

`--purge` is required before deleting config or identity. The uninstaller
refuses empty, parent, system, unrelated `/Library`, and symlink-escaped paths.

## Signing And Notarization

Unsigned local and PR artifacts are validation artifacts only. A signed but not
notarized artifact is useful for local signing validation, but it is not a
production release artifact. Production release packages must be signed,
notarized, stapled, and verified:

```bash
bash scripts/release/sign_notarize_agent_macos.sh \
  --version <numeric-version> \
  --arch-mode universal \
  --app-identity "Developer ID Application: Example" \
  --installer-identity "Developer ID Installer: Example" \
  --notary-profile openassetwatch
```

The signed release order is strict: build arm64/amd64 slices, assemble the
universal binary when requested, sign the final packaged binary with Developer
ID Application, verify hardened runtime, timestamp, and no `get-task-allow`,
stage that signed binary into the package root, build and sign the product PKG
with Developer ID Installer, submit to notarytool, require `Accepted`, download
the detailed notarization log, staple, validate the staple, rerun Gatekeeper
assessment, then regenerate final checksum and manifest metadata.

Verify release artifacts:

```bash
pkgutil --check-signature OpenAssetWatchAgent-<version>-macos-universal.pkg
python3 scripts/release/validate_agent_macos_install.py --version <numeric-version> --pkg dist/agent/<numeric-version>/packages/OpenAssetWatchAgent-<numeric-version>-macos-universal.pkg --require-signed-binary
spctl --assess --type install --verbose OpenAssetWatchAgent-<version>-macos-universal.pkg
xcrun stapler validate OpenAssetWatchAgent-<version>-macos-universal.pkg
```

Do not commit certificates, private keys, `.p12`, `.p8`, passwords, Apple IDs,
issuer IDs tied to credentials, or keychain files.

## MDM Notes

Jamf and other MDM tools should deploy the signed/notarized PKG as a system
package, then provision config and identity as administrator-controlled files.
macOS may display Background Items visibility for managed launchd services;
administrators should document that `com.openassetwatch.agent` is the expected
OpenAssetWatch LaunchDaemon.

## Troubleshooting

- `launchctl print system/com.openassetwatch.agent` shows launchd state.
- `status.json` reports degraded setup when config or identity is missing.
- Check `/Library/Logs/OpenAssetWatch/Agent/oaw-agent.log` for sanitized service
  start, stop, degraded, recovery, and fatal runtime messages.
- Verify backend connectivity from the host before blaming the daemon.
- Confirm ownership and modes if launchd reports permission errors.
- If the daemon appears to restart repeatedly, check that the binary path,
  plist `ProgramArguments`, service account, config, identity, and state/log
  permissions match this guide.
