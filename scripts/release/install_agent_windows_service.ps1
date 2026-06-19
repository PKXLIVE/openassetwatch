# OpenAssetWatch Windows service install helper.
#
# This helper creates only the Windows service entry when explicitly run by an
# administrator. Use -DryRun for validation without modifying the host.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$InstallRoot,

    [Parameter(Mandatory = $true)]
    [string]$ServiceMetadata,

    [switch]$Start,

    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$ExpectedServiceName = "OpenAssetWatchAgent"
$ExpectedDisplayName = "OpenAssetWatch Agent"
$ExpectedExecutablePath = "C:\Program Files\OpenAssetWatch\Agent\bin\oaw-agent.exe"
$ExpectedArguments = "run-once --config C:\ProgramData\OpenAssetWatch\Agent\config\config.json --identity-file C:\ProgramData\OpenAssetWatch\Agent\identity\identity.json --output-dir C:\ProgramData\OpenAssetWatch\Agent\state"
$SensitivePattern = "(?i)(credential|password|token|api[_-]?key|private[_-]?key|secret)"

$Report = [ordered]@{
    ok = $false
    dry_run = [bool]$DryRun
    service_name = ""
    install_root = ""
    service_metadata = ""
    admin = $false
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

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-RequiredPath {
    param(
        [string]$PathValue,
        [string]$Label
    )
    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        throw "$Label is required."
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

function Read-ServiceMetadata {
    param([string]$PathValue)
    Assert-SafeMetadataText -PathValue $PathValue
    $metadata = Get-Content -Raw -LiteralPath $PathValue | ConvertFrom-Json
    if ($metadata.service_name -ne $ExpectedServiceName) {
        throw "Service metadata service_name must be $ExpectedServiceName."
    }
    if ($metadata.display_name -ne $ExpectedDisplayName) {
        throw "Service metadata display_name must be $ExpectedDisplayName."
    }
    if ($metadata.executable_path -ne $ExpectedExecutablePath) {
        throw "Service metadata executable_path must be $ExpectedExecutablePath."
    }
    if ($metadata.arguments -ne $ExpectedArguments) {
        throw "Service metadata arguments do not match the approved run-once command."
    }
    if ($metadata.startup_type -ne "automatic") {
        throw "Service metadata startup_type must be automatic."
    }
    if ($metadata.service_account_recommendation -ne "LocalService") {
        throw "Service metadata service_account_recommendation must be LocalService."
    }
    if ($metadata.service_installed_by_this_helper -ne $false) {
        throw "Service metadata must show that staging did not install the service."
    }
    if ($metadata.scheduled_task_installed_by_this_helper -ne $false) {
        throw "Service metadata must show that staging did not install a scheduled task."
    }
    return $metadata
}

function Assert-ValidServiceName {
    param([string]$Name)
    if ($Name -ne $ExpectedServiceName) {
        throw "Invalid service name. Expected $ExpectedServiceName."
    }
}

try {
    $installRootPath = Resolve-RequiredPath -PathValue $InstallRoot -Label "InstallRoot"
    $metadataPath = Resolve-RequiredPath -PathValue $ServiceMetadata -Label "ServiceMetadata"
    $Report.install_root = $installRootPath
    $Report.service_metadata = $metadataPath

    $admin = Test-IsAdministrator
    $Report.admin = $admin
    if (-not $admin) {
        if ($DryRun) {
            Add-Warning "Administrator rights are required for real service installation; dry-run did not modify the host."
        } else {
            throw "Administrator rights are required to install the Windows service."
        }
    }
    Add-Check -Name "administrator check" -Ok ($admin -or [bool]$DryRun) -Message "Administrator check passed for the selected mode."

    $stagedExecutable = Join-Path $installRootPath "ProgramFiles\OpenAssetWatch\Agent\bin\oaw-agent.exe"
    $configDirectory = Join-Path $installRootPath "ProgramData\OpenAssetWatch\Agent\config"
    $identityDirectory = Join-Path $installRootPath "ProgramData\OpenAssetWatch\Agent\identity"

    if (-not (Test-Path -LiteralPath $stagedExecutable -PathType Leaf)) {
        throw "Staged oaw-agent.exe is missing under InstallRoot."
    }
    if (-not (Test-Path -LiteralPath $configDirectory -PathType Container)) {
        throw "Config directory is missing under InstallRoot."
    }
    if (-not (Test-Path -LiteralPath $identityDirectory -PathType Container)) {
        throw "Identity directory is missing under InstallRoot."
    }
    Add-Check -Name "staged layout" -Ok $true -Message "Staged executable, config directory, and identity directory exist."

    $metadata = Read-ServiceMetadata -PathValue $metadataPath
    Assert-ValidServiceName -Name $metadata.service_name
    $Report.service_name = $metadata.service_name
    Add-Check -Name "service metadata" -Ok $true -Message "Service metadata matches the approved OpenAssetWatch service model."

    if (-not $DryRun -and -not (Test-Path -LiteralPath $metadata.executable_path -PathType Leaf)) {
        throw "Production executable path from service metadata does not exist."
    }
    if ($DryRun) {
        Add-Warning "Dry-run validates staged layout and metadata only; it does not require the production executable path to exist."
    }

    $binaryPath = '"' + $metadata.executable_path + '" ' + $metadata.arguments
    Add-Action "Create service $($metadata.service_name) with automatic startup and LocalService account."
    if ($Start) {
        Add-Action "Start service $($metadata.service_name) after creation because -Start was supplied."
    } else {
        Add-Action "Do not start service automatically because -Start was not supplied."
    }

    if (-not $DryRun) {
        $existing = Get-Service -Name $metadata.service_name -ErrorAction SilentlyContinue
        if ($null -ne $existing) {
            throw "Service $($metadata.service_name) already exists."
        }
        & sc.exe create $metadata.service_name "binPath= $binaryPath" "start= auto" "DisplayName= $($metadata.display_name)" "obj= NT AUTHORITY\LocalService" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "sc.exe create failed for $($metadata.service_name)."
        }
        if ($Start) {
            Start-Service -Name $metadata.service_name -ErrorAction Stop
        }
    }
} catch {
    Add-Check -Name "windows service install helper" -Ok $false -Message $_.Exception.Message
}

$Report.ok = ($Report.errors.Count -eq 0)
$Report | ConvertTo-Json -Depth 8
if ($Report.ok) {
    exit 0
}
exit 1
