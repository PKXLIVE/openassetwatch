param(
    [ValidateSet("agent", "sensor")]
    [string]$Mode = "agent",
    [string]$ServiceName = "",
    [switch]$Version
)

$OawVersion = "0.1.0-foundation"
if ($Version) {
    Write-Output "OpenAssetWatch Windows status $OawVersion"
    exit 0
}

if (-not $ServiceName) {
    $ServiceName = "oaw-$Mode"
}

Write-Output "Service: $ServiceName"
Write-Output "Mode: $Mode"
Write-Output "Version: $OawVersion"
Get-Service -Name $ServiceName -ErrorAction SilentlyContinue | Format-List *
