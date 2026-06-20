# OpenAssetWatch Windows service uninstall helper.
#
# This helper removes only the Windows service entry when explicitly run by an
# administrator. Use -DryRun for validation without modifying the host.

[CmdletBinding()]
param(
    [string]$ServiceName,

    [string]$ServiceMetadata,

    [string]$InstallRoot,

    [switch]$Stop,

    [switch]$RemoveState,

    [int]$StopTimeoutSeconds = 30,

    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$ExpectedServiceName = "OpenAssetWatchAgent"
$SensitivePattern = "(?i)(credential|password|token|api[_-]?key|private[_-]?key|secret)"

$Report = [ordered]@{
    ok = $false
    dry_run = [bool]$DryRun
    service_name = ""
    install_root = ""
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
    $resolved = Resolve-Path -LiteralPath $PathValue -ErrorAction Stop
    return $resolved.ProviderPath
}

function Assert-SafeMetadataText {
    param([string]$PathValue)
    $text = Get-Content -Raw -LiteralPath $PathValue
    if ($text -match $SensitivePattern) {
        throw "Service metadata contains credential, password, token, API key, or secret markers."
    }
}

function Get-ServiceNameFromMetadata {
    param([string]$PathValue)
    Assert-SafeMetadataText -PathValue $PathValue
    $metadata = Get-Content -Raw -LiteralPath $PathValue | ConvertFrom-Json
    if ($metadata.service_name -ne $ExpectedServiceName) {
        throw "Service metadata service_name must be $ExpectedServiceName."
    }
    return [string]$metadata.service_name
}

function Assert-ValidServiceName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) {
        throw "ServiceName or ServiceMetadata is required."
    }
    if ($Name -ne $ExpectedServiceName) {
        throw "Invalid service name. Expected $ExpectedServiceName."
    }
}

function Assert-PathInside {
    param(
        [string]$Parent,
        [string]$Child
    )
    $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd("\", "/")
    $childFull = [System.IO.Path]::GetFullPath($Child)
    if ($childFull.Equals($parentFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        return
    }
    $prefix = $parentFull + [System.IO.Path]::DirectorySeparatorChar
    if (-not $childFull.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove state outside InstallRoot."
    }
}

function Assert-NotSystemInstallRoot {
    param([string]$PathValue)
    if ($PathValue -match "^[A-Za-z]:\\(Program Files|ProgramData)(\\|$)") {
        throw "RemoveState is for staged or test cleanup only and refuses Program Files or ProgramData roots."
    }
}

function Wait-ServiceState {
    param(
        [string]$Name,
        [string]$WantedStatus,
        [int]$TimeoutSeconds
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($WantedStatus -eq "Deleted") {
            if ($null -eq $service) {
                return $true
            }
        } elseif ($null -ne $service -and [string]$service.Status -eq $WantedStatus) {
            return $true
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    return $false
}

try {
    $metadataPath = Resolve-OptionalPath -PathValue $ServiceMetadata -Label "ServiceMetadata"
    if (-not [string]::IsNullOrWhiteSpace($metadataPath)) {
        $Report.service_metadata = $metadataPath
        $metadataServiceName = Get-ServiceNameFromMetadata -PathValue $metadataPath
        if ([string]::IsNullOrWhiteSpace($ServiceName)) {
            $ServiceName = $metadataServiceName
        } elseif ($ServiceName -ne $metadataServiceName) {
            throw "ServiceName does not match ServiceMetadata service_name."
        }
    }
    Assert-ValidServiceName -Name $ServiceName
    $Report.service_name = $ServiceName
    Add-Check -Name "service name" -Ok $true -Message "Service name is valid."

    $installRootPath = Resolve-OptionalPath -PathValue $InstallRoot -Label "InstallRoot"
    if (-not [string]::IsNullOrWhiteSpace($installRootPath)) {
        $Report.install_root = $installRootPath
    }

    $admin = Test-IsAdministrator
    $Report.admin = $admin
    if (-not $admin) {
        if ($DryRun) {
            Add-Warning "Administrator rights are required for real service removal; dry-run did not modify the host."
        } else {
            throw "Administrator rights are required to uninstall the Windows service."
        }
    }
    Add-Check -Name "administrator check" -Ok ($admin -or [bool]$DryRun) -Message "Administrator check passed for the selected mode."

    Add-Action "Remove service $ServiceName if it exists."
    if ($Stop) {
        Add-Action "Stop service $ServiceName before removal because -Stop was supplied."
    } else {
        Add-Action "Do not stop service automatically because -Stop was not supplied."
    }

    if (-not $DryRun) {
        $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            if ($Stop -and $existing.Status -ne "Stopped") {
                Stop-Service -Name $ServiceName -ErrorAction Stop
                if (-not (Wait-ServiceState -Name $ServiceName -WantedStatus "Stopped" -TimeoutSeconds $StopTimeoutSeconds)) {
                    throw "Timed out waiting for $ServiceName to stop."
                }
            }
            & sc.exe delete $ServiceName | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw "sc.exe delete failed for $ServiceName."
            }
            if (-not (Wait-ServiceState -Name $ServiceName -WantedStatus "Deleted" -TimeoutSeconds $StopTimeoutSeconds)) {
                throw "Timed out waiting for $ServiceName deletion to be observed."
            }
            Add-Removed "service:$ServiceName"
        } else {
            Add-Warning "Service $ServiceName does not exist."
        }
    }

    if ($RemoveState) {
        if ([string]::IsNullOrWhiteSpace($installRootPath)) {
            throw "InstallRoot is required with -RemoveState."
        }
        Assert-NotSystemInstallRoot -PathValue $installRootPath
        $statePath = Join-Path $installRootPath "ProgramData\OpenAssetWatch\Agent\state"
        Assert-PathInside -Parent $installRootPath -Child $statePath
        Add-Action "Remove staged/test state directory $statePath."
        if (-not $DryRun -and (Test-Path -LiteralPath $statePath)) {
            Remove-Item -LiteralPath $statePath -Recurse -Force
            Add-Removed $statePath
        }
    } else {
        Add-Action "Preserve config, identity, logs, and state because -RemoveState was not supplied."
    }
} catch {
    Add-Check -Name "windows service uninstall helper" -Ok $false -Message $_.Exception.Message
}

$Report.ok = ($Report.errors.Count -eq 0)
$Report | ConvertTo-Json -Depth 8
if ($Report.ok) {
    exit 0
}
exit 1
