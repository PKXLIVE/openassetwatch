param(
    [string]$Version = "0.1.0-local",
    [string]$OutputDir = "dist",
    [string]$TargetOS = "",
    [string]$TargetArch = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:Checks = @()
$script:Warnings = @()
$script:Errors = @()

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Ok,
        [string]$Message = ""
    )

    $script:Checks += [ordered]@{
        name = $Name
        ok = $Ok
        message = $Message
    }

    if (-not $Ok -and -not [string]::IsNullOrWhiteSpace($Message)) {
        $script:Errors += $Message
    }
}

function Add-Warning {
    param([Parameter(Mandatory = $true)][string]$Message)
    $script:Warnings += $Message
}

function Invoke-JsonReleaseHelper {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $output = @(& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    $text = ($output | Out-String).Trim()

    if ([string]::IsNullOrWhiteSpace($text)) {
        Add-Check -Name $Name -Ok $false -Message "$Name produced no JSON output."
        return $null
    }

    try {
        $parsed = $text | ConvertFrom-Json
    }
    catch {
        Add-Check -Name $Name -Ok $false -Message "$Name produced malformed JSON output."
        return $null
    }

    if ($exitCode -ne 0) {
        Add-Check -Name $Name -Ok $false -Message "$Name failed."
        if ($parsed.PSObject.Properties.Name.Contains("errors")) {
            foreach ($errorItem in @($parsed.errors)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$errorItem)) {
                    $script:Errors += [string]$errorItem
                }
            }
        }
        return $parsed
    }

    Add-Check -Name $Name -Ok $true -Message "$Name completed."
    return $parsed
}

function Add-ValidationResults {
    param([Parameter(Mandatory = $true)]$ValidationResult)

    if ($ValidationResult.PSObject.Properties.Name.Contains("checks")) {
        foreach ($check in @($ValidationResult.checks)) {
            $script:Checks += $check
        }
    }
    if ($ValidationResult.PSObject.Properties.Name.Contains("warnings")) {
        foreach ($warning in @($ValidationResult.warnings)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$warning)) {
                $script:Warnings += [string]$warning
            }
        }
    }
    if ($ValidationResult.PSObject.Properties.Name.Contains("errors")) {
        foreach ($errorItem in @($ValidationResult.errors)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$errorItem)) {
                $script:Errors += [string]$errorItem
            }
        }
    }
}

function New-Summary {
    param(
        [string]$VersionValue,
        [object[]]$Artifacts,
        [object[]]$Packages
    )

    return [ordered]@{
        ok = ($script:Errors.Count -eq 0)
        version = $VersionValue
        artifacts = $Artifacts
        packages = $Packages
        checks = $script:Checks
        warnings = $script:Warnings
        errors = $script:Errors
    }
}

$artifacts = @()
$packages = @()

try {
    if ($Version -notmatch '^[A-Za-z0-9._+-]+$') {
        throw "Version may contain only letters, numbers, dot, underscore, plus, and hyphen."
    }

    $buildScript = Join-Path $PSScriptRoot "build_agent_dist.ps1"
    $packageScript = Join-Path $PSScriptRoot "package_agent_targz.ps1"
    $validateScript = Join-Path $PSScriptRoot "validate_agent_release.ps1"

    foreach ($scriptPath in @($buildScript, $packageScript, $validateScript)) {
        if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
            throw "Required helper script not found: $scriptPath"
        }
    }

    $buildArgs = @("-Version", $Version, "-OutputDir", $OutputDir)
    if (-not [string]::IsNullOrWhiteSpace($TargetOS)) {
        $buildArgs += @("-TargetOS", $TargetOS)
    }
    if (-not [string]::IsNullOrWhiteSpace($TargetArch)) {
        $buildArgs += @("-TargetArch", $TargetArch)
    }

    $buildResult = Invoke-JsonReleaseHelper -Name "build dist artifact" -ScriptPath $buildScript -Arguments $buildArgs
    if ($null -ne $buildResult -and $script:Errors.Count -eq 0) {
        $artifacts += [ordered]@{
            artifact = [string]$buildResult.artifact
            checksum = [string]$buildResult.checksum
            manifest = [string]$buildResult.manifest
        }

        $artifactDir = Split-Path -Parent ([string]$buildResult.artifact)
        $packageResult = Invoke-JsonReleaseHelper -Name "package targz artifact" -ScriptPath $packageScript -Arguments @("-ArtifactDir", $artifactDir, "-DistDir", $OutputDir)
        if ($null -ne $packageResult -and $script:Errors.Count -eq 0) {
            $packages += [ordered]@{
                package = [string]$packageResult.package
                checksum = [string]$packageResult.checksum
                manifest = [string]$packageResult.manifest
            }

            $validationResult = Invoke-JsonReleaseHelper -Name "validate release artifacts" -ScriptPath $validateScript -Arguments @("-Version", $Version, "-DistRoot", $OutputDir, "-IncludePackages")
            if ($null -ne $validationResult) {
                Add-ValidationResults -ValidationResult $validationResult
            }
        }
    }
}
catch {
    Add-Check -Name "local release orchestration" -Ok $false -Message $_.Exception.Message
}

$summary = New-Summary -VersionValue $Version -Artifacts $artifacts -Packages $packages
$summary | ConvertTo-Json -Depth 8

if ($script:Errors.Count -gt 0) {
    exit 1
}
