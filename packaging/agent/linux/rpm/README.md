# OpenAssetWatch Agent RPM Package Source

This directory contains RPM package-owned source for `openassetwatch-agent`.

The RPM package is generated with standard `rpmbuild` tooling from the staged
build tree under ignored `dist/agent/<version>/rpm/`. The helper scripts do
not install or run the package on the build host.

The RPM package uses the same root-owned executable, root-owned helper, narrow
sudoers, service-account, and systemd timer model as the Debian package, with
RPM-family systemd unit paths under `/usr/lib/systemd/system/`.
