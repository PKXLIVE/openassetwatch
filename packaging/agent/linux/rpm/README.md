# OpenAssetWatch Agent RPM Package Source

This directory contains RPM package-owned source for `openassetwatch-agent`.

The RPM package is generated with standard `rpmbuild` tooling from the staged
build tree under ignored `dist/agent/<version>/rpm/`. The helper scripts do
not install or run the package on the build host.

The RPM package uses the same root-owned executable, root-owned helper, narrow
sudoers, service-account, and systemd timer model as the Debian package, with
RPM-family systemd unit paths under `/usr/lib/systemd/system/`.

The spec includes `%pre`, `%post`, `%preun`, and `%postun` lifecycle scriptlets.
They validate or create the non-interactive `openassetwatch` service principal,
enable `oaw-agent.timer`, restart the timer only when real config and identity
files exist, stop and disable the timer on final erase, distinguish upgrade
from erase, and preserve config, identity, state, logs, and the service
principal by default.

Install lifecycle CI currently exercises Rocky Linux 9 with systemd running as
PID 1. Other RPM-family distributions require separate lifecycle validation
before they are claimed as tested targets.
