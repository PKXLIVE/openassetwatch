[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet("agent", "sensor")]
    [string]$Mode = "agent",
    [string]$ServiceName = "",
    [string]$ConfigPath = "",
    [string]$BinaryPath = "",
    [switch]$Version
)

$OawVersion = "0.1.0-foundation"
if ($Version) {
    Write-Output "OpenAssetWatch Windows installer $OawVersion"
    exit 0
}

if (-not $ServiceName) {
    $ServiceName = "oaw-$Mode"
}
if (-not $ConfigPath) {
    $ConfigPath = Join-Path $env:ProgramData "OpenAssetWatch\$Mode.json"
}
if (-not $BinaryPath) {
    $BinaryPath = Join-Path $env:ProgramFiles "OpenAssetWatch\oaw-$Mode.exe"
}

$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "install.ps1 must be run as Administrator to create a Windows service"
}

New-Item -ItemType Directory -Force -Path (Split-Path $ConfigPath) | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path $BinaryPath) | Out-Null

if (-not (Test-Path $BinaryPath)) {
    Write-Warning "$BinaryPath does not exist yet; service definition will be staged only"
}

$commandLine = "`"$BinaryPath`" --config `"$ConfigPath`""
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    if ($PSCmdlet.ShouldProcess($ServiceName, "Update OpenAssetWatch service")) {
        sc.exe config $ServiceName binPath= $commandLine obj= "NT AUTHORITY\LocalService" | Out-Null
    }
} else {
    if ($PSCmdlet.ShouldProcess($ServiceName, "Create OpenAssetWatch service")) {
        New-Service -Name $ServiceName -BinaryPathName $commandLine -DisplayName "OpenAssetWatch $Mode" -StartupType Automatic | Out-Null
        sc.exe config $ServiceName obj= "NT AUTHORITY\LocalService" | Out-Null
    }
}

Write-Output "Installed $ServiceName"
Write-Output "Mode: $Mode"
Write-Output "Config: $ConfigPath"
Write-Output "Version: $OawVersion"
