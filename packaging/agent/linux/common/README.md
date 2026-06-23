# OpenAssetWatch Agent Linux Package Source

This directory contains the committed Linux package source used by the local
Debian, RPM, and tar.gz release helpers.

Version: `{{VERSION}}`

The Linux production runtime model is:

1. systemd timer
2. one-shot `oaw-agent.service`
3. `/opt/openassetwatch/agent/bin/oaw-agent run-once`
4. passive local inventory collection and submission

The package source is reviewable by design. Build helpers may render package
metadata and manifests under ignored `dist/`, but important service units,
helper scripts, sudoers rules, and maintainer script behavior should live in
this committed package tree.

The package does not create real `config.json` or `identity.json` values.
Administrators must provision those files explicitly.

Package-managed executables under `/opt/openassetwatch/agent/bin/` and
privileged helpers under `/usr/lib/openassetwatch/agent/libexec/` are
root-owned. Only state and log directories under `/var/lib/openassetwatch` and
`/var/log/openassetwatch` are service-owned by `openassetwatch`.

Systemd lifecycle operations are package-manager lifecycle operations, not
agent self-update behavior. They are guarded for active systemd hosts and must
fail visibly on real systemd errors rather than hiding failures with
unconditional `|| true`.

No authoritative repository license file is currently present. Linux package
metadata therefore uses `LicenseRef-OpenAssetWatch-UNSPECIFIED` where a package
format requires a license field, and public release remains blocked until the
project makes an explicit license decision.
