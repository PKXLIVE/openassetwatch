# Agent OS Package Mapping

This document maps operating systems to future OpenAssetWatch agent package
targets. It is documentation only and does not execute package-manager or
service-manager commands.

## Mapping

| Platform | Detection Input | Recommended Package |
| --- | --- | --- |
| Windows | `runtime.GOOS=windows` | signed MSI or enterprise deployment |
| Debian | `/etc/os-release` `ID=debian` or `ID_LIKE=debian` | `.deb` |
| Ubuntu | `/etc/os-release` `ID=ubuntu` or `ID_LIKE=debian` | `.deb` |
| RHEL | `/etc/os-release` `ID=rhel` or `ID_LIKE=rhel` | `.rpm` |
| Rocky Linux | `/etc/os-release` `ID=rocky` or `ID_LIKE=rhel` | `.rpm` |
| AlmaLinux | `/etc/os-release` `ID=almalinux` or `ID_LIKE=rhel` | `.rpm` |
| CentOS | `/etc/os-release` `ID=centos` or `ID_LIKE=rhel` | `.rpm` |
| Fedora | `/etc/os-release` `ID=fedora` or `ID_LIKE=fedora` | `.rpm` |
| SUSE/openSUSE | `/etc/os-release` `ID` or `ID_LIKE` includes `suse` or `opensuse` | `.rpm` |
| Unknown Linux | no supported `ID` or `ID_LIKE` match | `.tar.gz` or manual install |
| macOS | `runtime.GOOS=darwin` | signed and notarized package |

## Linux Detection Inputs

Future package selection should use read-only distribution detection:

- `/etc/os-release`
- `ID`
- `ID_LIKE`
- `VERSION_ID`

The running agent must not act as a package-manager wrapper. Package-manager
commands require explicit administrator action outside the agent runtime.

## Package Family Notes

- `.deb` packages are intended for Debian and Ubuntu families.
- `.rpm` packages are intended for RHEL, Rocky Linux, AlmaLinux, CentOS,
  Fedora, SUSE, and openSUSE families.
- `.tar.gz` packages are fallback artifacts for unsupported Linux
  distributions or manual install workflows.
- Windows package planning targets signed MSI and enterprise deployment tools.
- macOS package planning targets signed and notarized packages.
