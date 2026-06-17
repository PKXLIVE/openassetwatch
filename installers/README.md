# Installers

This directory contains scaffold installers for early local testing and service
shape review.

- `linux/`: systemd shell scaffold for agent and sensor services.
- `macos/`: LaunchDaemon shell scaffold for agent and sensor services.
- `windows/`: PowerShell service scaffold for agent and sensor services.
- `docker/`: compose scaffold for future server packaging.

These files are not the final release packaging story. The future release path
is signed Windows MSI, signed and notarized macOS PKG, signed Linux DEB/RPM,
and signed Docker images with SBOM and provenance metadata.

Signing keys, certificates, notarization credentials, and registry credentials
must be referenced only through CI/CD secret names. Do not commit secret values.
