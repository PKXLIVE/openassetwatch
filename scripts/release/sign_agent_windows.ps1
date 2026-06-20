param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("SignExe", "VerifyExe", "SignMsi", "VerifyMsi")]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$CertificateThumbprint = "",

    [string]$PfxPath = "",

    [string]$PfxPasswordEnv = "",

    [string]$TimestampUrl = "http://timestamp.digicert.com",

    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SensitivePattern = "(?i)(credential|password|token|api[_-]?key|private[_-]?key|secret)"
$Report = [ordered]@{
    ok = $false
    action = $Action
    path = ""
    dry_run = [bool]$DryRun
    command = "signtool.exe"
    arguments = @()
    warnings = @()
    errors = @()
}

function Add-Warning {
    param([string]$Message)
    $script:Report.warnings += $Message
}

function Add-Error {
    param([string]$Message)
    $script:Report.errors += $Message
}

function Sanitize-Arguments {
    param([string[]]$Arguments)
    return @($Arguments | ForEach-Object { ([string]$_) -replace $SensitivePattern, "[redacted]" })
}

function Resolve-InputPath {
    param([string]$PathValue)
    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        throw "Path is required."
    }
    $resolved = Resolve-Path -LiteralPath $PathValue -ErrorAction Stop
    return $resolved.ProviderPath
}

function Get-SignTool {
    $tool = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($null -eq $tool) {
        throw "signtool.exe was not found on PATH. Install the Windows SDK or run on a signing runner."
    }
    return $tool.Source
}

try {
    $resolvedPath = Resolve-InputPath -PathValue $Path
    $Report.path = $resolvedPath

    $arguments = @()
    switch ($Action) {
        "SignExe" {
            if ([string]::IsNullOrWhiteSpace($CertificateThumbprint) -and [string]::IsNullOrWhiteSpace($PfxPath)) {
                throw "Signing requires CertificateThumbprint or PfxPath."
            }
            $arguments = @("sign", "/fd", "SHA256", "/tr", $TimestampUrl, "/td", "SHA256")
            if (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
                $arguments += @("/sha1", $CertificateThumbprint)
            }
            else {
                if ([string]::IsNullOrWhiteSpace($PfxPasswordEnv) -or [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($PfxPasswordEnv))) {
                    throw "PfxPasswordEnv must name an environment variable containing the PFX password."
                }
                $arguments += @("/f", (Resolve-InputPath -PathValue $PfxPath), "/p", "[redacted]")
            }
            $arguments += $resolvedPath
        }
        "SignMsi" {
            if ([string]::IsNullOrWhiteSpace($CertificateThumbprint) -and [string]::IsNullOrWhiteSpace($PfxPath)) {
                throw "Signing requires CertificateThumbprint or PfxPath."
            }
            $arguments = @("sign", "/fd", "SHA256", "/tr", $TimestampUrl, "/td", "SHA256")
            if (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
                $arguments += @("/sha1", $CertificateThumbprint)
            }
            else {
                if ([string]::IsNullOrWhiteSpace($PfxPasswordEnv) -or [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($PfxPasswordEnv))) {
                    throw "PfxPasswordEnv must name an environment variable containing the PFX password."
                }
                $arguments += @("/f", (Resolve-InputPath -PathValue $PfxPath), "/p", "[redacted]")
            }
            $arguments += $resolvedPath
        }
        "VerifyExe" {
            $arguments = @("verify", "/pa", "/v", $resolvedPath)
        }
        "VerifyMsi" {
            $arguments = @("verify", "/pa", "/v", $resolvedPath)
        }
    }

    $Report.arguments = Sanitize-Arguments -Arguments $arguments
    if ($DryRun) {
        Add-Warning "Dry-run only; no signature was applied or verified."
    }
    else {
        $signtool = Get-SignTool
        $realArguments = @($arguments | ForEach-Object {
            if ($_ -eq "[redacted]") {
                [Environment]::GetEnvironmentVariable($PfxPasswordEnv)
            }
            else {
                $_
            }
        })
        & $signtool @realArguments | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "signtool.exe failed for $Action."
        }
    }
}
catch {
    Add-Error -Message $_.Exception.Message
}

$Report.ok = ($Report.errors.Count -eq 0)
$Report | ConvertTo-Json -Depth 6
if ($Report.ok) {
    exit 0
}
exit 1
