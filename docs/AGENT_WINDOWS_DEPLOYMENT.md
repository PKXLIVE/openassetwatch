# OpenAssetWatch Agent Windows Deployment

This document describes the production-oriented Windows deployment path for the
OpenAssetWatch agent. The Windows service runtime uses the native Service
Control Manager and runs:

```text
C:\Program Files\OpenAssetWatch\Agent\bin\oaw-agent.exe service run --config C:\ProgramData\OpenAssetWatch\Agent\config\config.json --identity-file C:\ProgramData\OpenAssetWatch\Agent\identity\identity.json --output-dir C:\ProgramData\OpenAssetWatch\Agent\state
```

Task Scheduler is not used for the agent service.

## Supported Target

- operating system family: Windows Server and Windows desktop versions that
  support the standard Service Control Manager and LocalService account
- architecture: `windows/amd64`
- installer format: WiX Toolset MSI
- service name: `OpenAssetWatchAgent`
- display name: `OpenAssetWatch Agent`

## Installed Layout

- binary:
  `C:\Program Files\OpenAssetWatch\Agent\bin\oaw-agent.exe`
- config:
  `C:\ProgramData\OpenAssetWatch\Agent\config\config.json`
- identity:
  `C:\ProgramData\OpenAssetWatch\Agent\identity\identity.json`
- state:
  `C:\ProgramData\OpenAssetWatch\Agent\state`
- status:
  `C:\ProgramData\OpenAssetWatch\Agent\state\status.json`
- inventory:
  `C:\ProgramData\OpenAssetWatch\Agent\state\last-inventory.json`
- logs:
  `C:\ProgramData\OpenAssetWatch\Agent\logs`

The MSI installs only placeholder example config and identity files. Real
`config.json` and `identity.json` remain administrator-managed and are preserved
during repair, upgrade, and uninstall.

## Interactive Install

Build a Windows agent artifact and MSI from the repository:

```powershell
.\scripts\release\build_agent_dist.ps1 -Version 0.1.0 -TargetOS windows -TargetArch amd64
.\scripts\release\build_agent_msi.ps1 -Version 0.1.0 -TargetArch amd64
```

Install from an elevated PowerShell prompt:

```powershell
msiexec.exe /i .\dist\agent\0.1.0\packages\OpenAssetWatchAgent-0.1.0-windows-amd64.msi
```

## Silent Install

```powershell
msiexec.exe /i .\OpenAssetWatchAgent-0.1.0-windows-amd64.msi /qn /norestart /l*v oaw-agent-install.log
```

Unsigned local CI builds are validation artifacts only. Production releases
must sign `oaw-agent.exe` and the MSI before distribution.

## Provisioning

Create `config.json` and `identity.json` before relying on successful service
cycles. The service remains running in a degraded retry state if either file is
missing, but explicit `oaw-agent run-once` continues to fail closed.

```powershell
& "C:\Program Files\OpenAssetWatch\Agent\bin\oaw-agent.exe" config init `
  --server-url http://127.0.0.1:8000 `
  --site-id site-local `
  --output "C:\ProgramData\OpenAssetWatch\Agent\config\config.json"

& "C:\Program Files\OpenAssetWatch\Agent\bin\oaw-agent.exe" identity init `
  --site-id site-local `
  --output "C:\ProgramData\OpenAssetWatch\Agent\identity\identity.json"
```

## Service Operations

```powershell
Get-Service OpenAssetWatchAgent
Start-Service OpenAssetWatchAgent
Stop-Service OpenAssetWatchAgent
Restart-Service OpenAssetWatchAgent
sc.exe qc OpenAssetWatchAgent
```

The service runs as `NT AUTHORITY\LocalService`, reports SCM state, accepts Stop
and Shutdown controls, writes status atomically, and uses bounded retry/backoff
for transient backend or collection failures. The MSI uses the service-specific
SID `NT SERVICE\OpenAssetWatchAgent` for service ACLs where Windows Installer
authoring supports it, so writable state/log access is not granted broadly to
every LocalService-hosted service.

## Event Viewer

The MSI registers the `OpenAssetWatchAgent` Event Log source. Service startup,
stop, fatal errors, degraded transitions, and recovery events are written to the
Windows Application log when Event Log initialization succeeds. The service
falls back to stdout/stderr if Event Log setup is unavailable.

## Runtime Files

- status: `C:\ProgramData\OpenAssetWatch\Agent\state\status.json`
- last inventory:
  `C:\ProgramData\OpenAssetWatch\Agent\state\last-inventory.json`

Status output is sanitized and must not contain config contents, identity
contents, request bodies, response bodies, credentials, API keys, tokens,
passwords, private keys, or authorization headers.

## Repair And Upgrade

Use Windows Installer repair for file/table repair:

```powershell
msiexec.exe /fa .\OpenAssetWatchAgent-0.1.0-windows-amd64.msi /qn /norestart
```

Major upgrades use the stable MSI `UpgradeCode` and a new product version. The
MSI prevents unintended downgrade. Config, identity, state, and logs are
preserved across repair and upgrade.

## Rollback

Keep a previous signed MSI available. To roll back, uninstall the current MSI,
install the previous signed MSI, confirm the service is present, then review
`status.json` and backend check-in history.

## Uninstall

```powershell
msiexec.exe /x .\OpenAssetWatchAgent-0.1.0-windows-amd64.msi /qn /norestart
```

Uninstall removes the service entry and installed binary. It preserves real
config, identity, state, and logs unless an administrator explicitly removes
those paths afterward.

## Signature Verification

Use the signing helper with explicit certificate inputs for production release
signing and verification:

```powershell
.\scripts\release\sign_agent_windows.ps1 -Action VerifyExe -Path .\oaw-agent.exe
.\scripts\release\sign_agent_windows.ps1 -Action VerifyMsi -Path .\OpenAssetWatchAgent-0.1.0-windows-amd64.msi
```

## Enterprise Deployment Notes

The MSI supports silent install and standard Windows Installer repair,
upgrade, and uninstall flows. Enterprise deployment can use Intune, SCCM,
Group Policy software installation, or other MSI-capable deployment systems.
Administrators should provision `config.json` and `identity.json` before
expecting successful inventory submission.

## Troubleshooting

- SCM startup: use `sc.exe qc OpenAssetWatchAgent` and Event Viewer Application
  logs.
- permissions: confirm the `OpenAssetWatchAgent` service SID can read config
  and identity, execute the binary, and write state/log output.
- backend connectivity: review `status.json` for sanitized degraded error
  category/message and verify the configured Control Tower URL.
- service command: confirm the service ImagePath uses `service run`, not raw
  `run-once`.
