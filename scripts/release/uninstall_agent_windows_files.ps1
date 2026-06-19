# OpenAssetWatch Windows file uninstall helper.
#
# This helper removes only OpenAssetWatch agent files from explicit Windows
# install paths when run by an administrator. Use -DryRun for validation
# without modifying the host.

[CmdletBinding()]
param(
    [string]$ProgramFilesAgentRoot,

    [string]$ProgramDataAgentRoot,

    [string]$ServiceMetadata,

    [switch]$RemoveState,

    [switch]$RemoveLogs,

    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$ExpectedServiceName = "OpenAssetWatchAgent"
$ExpectedProgramFilesRoot = "C:\Program Files\OpenAssetWatch\Agent"
$ExpectedProgramDataRoot = "C:\ProgramData\OpenAssetWatch\Agent"
$SensitivePattern = "(?i)(credential|password|token|api[_-]?key|private[_-]?key|secret)"

$Report = [ordered]@{
    ok = $false
    dry_run = [bool]$DryRun
    program_files_root = ""
    programdata_root = ""
    service_metadata = ""
    admin = $false
    removed = @()
    actions = @()
    checks = @()
    warnings = @()
    errors = @()
}

function Add-Check {
    param(
        [string]$Name,
        [bool]$Ok,
        [string]$Message
    )
    $script:Report.checks += [ordered]@{
        name = $Name
        ok = $Ok
        message = $Message
    }
    if (-not $Ok -and -not [string]::IsNullOrWhiteSpace($Message)) {
        $script:Report.errors += $Message
    }
}

function Add-Action {
    param([string]$Message)
    $script:Report.actions += $Message
}

function Add-Warning {
    param([string]$Message)
    $script:Report.warnings += $Message
}

function Add-Removed {
    param([string]$PathValue)
    $script:Report.removed += $PathValue
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-OptionalPath {
    param(
        [string]$PathValue,
        [string]$Label
    )
    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        return ""
    }
    if (Test-Path -LiteralPath $PathValue) {
        return (Resolve-Path -LiteralPath $PathValue -ErrorAction Stop).ProviderPath
    }
    return [System.IO.Path]::GetFullPath($PathValue)
}

function Assert-SafeMetadataText {
    param([string]$PathValue)
    $text = Get-Content -Raw -LiteralPath $PathValue
    if ($text -match $SensitivePattern) {
        throw "Service metadata contains credential, password, token, API key, or secret markers."
    }
}

function Read-ServiceMetadata {
    param([string]$PathValue)
    $resolved = Resolve-Path -LiteralPath $PathValue -ErrorAction Stop
    Assert-SafeMetadataText -PathValue $resolved.ProviderPath
    $metadata = Get-Content -Raw -LiteralPath $resolved.ProviderPath | ConvertFrom-Json
    if ($metadata.service_name -ne $ExpectedServiceName) {
        throw "Service metadata service_name must be $ExpectedServiceName."
    }
    if ($metadata.executable_path -ne (Join-Path $ExpectedProgramFilesRoot "bin\oaw-agent.exe")) {
        throw "Service metadata executable_path does not match the approved Windows install path."
    }
    $script:Report.service_metadata = $resolved.ProviderPath
    return $metadata
}

function Assert-OpenAssetWatchRoot {
    param(
        [string]$PathValue,
        [string]$ExpectedRoot,
        [string]$Label
    )
    $fullPath = [System.IO.Path]::GetFullPath($PathValue).TrimEnd("\", "/")
    $expected = [System.IO.Path]::GetFullPath($ExpectedRoot).TrimEnd("\", "/")
    if (-not $fullPath.Equals($expected, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label must be the explicit OpenAssetWatch path $ExpectedRoot."
    }
}

function Remove-FileIfPresent {
    param(
        [string]$PathValue
    )
    if (Test-Path -LiteralPath $PathValue -PathType Leaf) {
        Remove-Item -LiteralPath $PathValue -Force
        Add-Removed $PathValue
    }
}

function Remove-DirectoryIfEmpty {
    param([string]$PathValue)
    if (-not (Test-Path -LiteralPath $PathValue -PathType Container)) {
        return
    }
    $child = Get-ChildItem -LiteralPath $PathValue -Force | Select-Object -First 1
    if ($null -eq $child) {
        Remove-Item -LiteralPath $PathValue -Force
        Add-Removed $PathValue
    } else {
        Add-Warning "Preserved non-empty directory $PathValue."
    }
}

function Remove-DirectoryTreeIfPresent {
    param([string]$PathValue)
    if (Test-Path -LiteralPath $PathValue -PathType Container) {
        Remove-Item -LiteralPath $PathValue -Recurse -Force
        Add-Removed $PathValue
    }
}

try {
    if (-not [string]::IsNullOrWhiteSpace($ServiceMetadata)) {
        Read-ServiceMetadata -PathValue $ServiceMetadata | Out-Null
        if ([string]::IsNullOrWhiteSpace($ProgramFilesAgentRoot)) {
            $ProgramFilesAgentRoot = $ExpectedProgramFilesRoot
        }
        if ([string]::IsNullOrWhiteSpace($ProgramDataAgentRoot)) {
            $ProgramDataAgentRoot = $ExpectedProgramDataRoot
        }
    }
    if ([string]::IsNullOrWhiteSpace($ProgramFilesAgentRoot) -and [string]::IsNullOrWhiteSpace($ServiceMetadata)) {
        throw "ProgramFilesAgentRoot or ServiceMetadata is required."
    }
    if ([string]::IsNullOrWhiteSpace($ProgramDataAgentRoot)) {
        $ProgramDataAgentRoot = $ExpectedProgramDataRoot
    }

    $programFilesRoot = Resolve-OptionalPath -PathValue $ProgramFilesAgentRoot -Label "ProgramFilesAgentRoot"
    $programDataRoot = Resolve-OptionalPath -PathValue $ProgramDataAgentRoot -Label "ProgramDataAgentRoot"
    Assert-OpenAssetWatchRoot -PathValue $programFilesRoot -ExpectedRoot $ExpectedProgramFilesRoot -Label "ProgramFilesAgentRoot"
    Assert-OpenAssetWatchRoot -PathValue $programDataRoot -ExpectedRoot $ExpectedProgramDataRoot -Label "ProgramDataAgentRoot"
    $Report.program_files_root = $programFilesRoot
    $Report.programdata_root = $programDataRoot

    $admin = Test-IsAdministrator
    $Report.admin = $admin
    if (-not $admin) {
        if ($DryRun) {
            Add-Warning "Administrator rights are required for real file uninstall; dry-run did not modify the host."
        } else {
            throw "Administrator rights are required to uninstall OpenAssetWatch files."
        }
    }
    Add-Check -Name "administrator check" -Ok ($admin -or [bool]$DryRun) -Message "Administrator check passed for the selected mode."

    $binary = Join-Path $programFilesRoot "bin\oaw-agent.exe"
    Add-Action "Remove $binary if present."
    Add-Action "Remove $programFilesRoot if it is safe and empty or contains only the agent binary path."
    Add-Action "Preserve ProgramData config and identity directories by default."
    Add-Action "Preserve ProgramData state unless -RemoveState is supplied."
    Add-Action "Preserve ProgramData logs unless -RemoveLogs is supplied."

    if ($RemoveState) {
        Add-Action "Remove ProgramData state directory because -RemoveState was supplied."
    }
    if ($RemoveLogs) {
        Add-Action "Remove ProgramData logs directory because -RemoveLogs was supplied."
    }

    Add-Check -Name "path safety" -Ok $true -Message "Removal paths are limited to OpenAssetWatch Program Files and ProgramData roots."

    if (-not $DryRun) {
        Remove-FileIfPresent -PathValue $binary
        $binRoot = Join-Path $programFilesRoot "bin"
        Remove-DirectoryIfEmpty -PathValue $binRoot
        Remove-DirectoryIfEmpty -PathValue $programFilesRoot

        if ($RemoveState) {
            Remove-DirectoryTreeIfPresent -PathValue (Join-Path $programDataRoot "state")
        }
        if ($RemoveLogs) {
            Remove-DirectoryTreeIfPresent -PathValue (Join-Path $programDataRoot "logs")
        }
    }
} catch {
    Add-Check -Name "windows file uninstall helper" -Ok $false -Message $_.Exception.Message
}

$Report.ok = ($Report.errors.Count -eq 0)
$Report | ConvertTo-Json -Depth 8
if ($Report.ok) {
    exit 0
}
exit 1
