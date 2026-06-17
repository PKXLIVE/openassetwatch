[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet("agent", "sensor")]
    [string]$Mode = "agent",
    [string]$ServiceName = "",
    [switch]$PurgeConfig,
    [switch]$Version
)

$OawVersion = "0.1.0-foundation"
if ($Version) {
    Write-Output "OpenAssetWatch Windows uninstaller $OawVersion"
    exit 0
}

if (-not $ServiceName) {
    $ServiceName = "oaw-$Mode"
}

$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "uninstall.ps1 must be run as Administrator to remove a Windows service"
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($PSCmdlet.ShouldProcess($ServiceName, "Remove OpenAssetWatch service")) {
        if ($service.Status -ne "Stopped") {
            Stop-Service -Name $ServiceName -Force
        }
        sc.exe delete $ServiceName | Out-Null
    }
}

if ($PurgeConfig) {
    $configPath = Join-Path $env:ProgramData "OpenAssetWatch\$Mode.json"
    Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue
}

Write-Output "Uninstalled $ServiceName"
Write-Output "Config purged: $PurgeConfig"
Write-Output "Version: $OawVersion"
