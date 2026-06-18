param(
    [string]$Version = "0.1.0-local",
    [string]$OutputDir = "dist",
    [string]$TargetOS = "",
    [string]$TargetArch = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Get-RepoRoot {
    $fallbackRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\.."))
    try {
        $gitRoot = (& git rev-parse --show-toplevel 2>$null)
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($gitRoot)) {
            return [System.IO.Path]::GetFullPath($gitRoot.Trim())
        }
    }
    catch {
        return $fallbackRoot
    }
    return $fallbackRoot
}

function Resolve-RepoPath {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$PathValue
    )

    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        throw "Path value cannot be empty."
    }

    if ([System.IO.Path]::IsPathRooted($PathValue)) {
        $fullPath = [System.IO.Path]::GetFullPath($PathValue)
    }
    else {
        $fullPath = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot $PathValue))
    }

    $comparison = [System.StringComparison]::OrdinalIgnoreCase
    $rootWithSeparator = $RepoRoot.TrimEnd([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)) + [System.IO.Path]::DirectorySeparatorChar
    if (-not ($fullPath.Equals($RepoRoot, $comparison) -or $fullPath.StartsWith($rootWithSeparator, $comparison))) {
        throw "OutputDir must resolve inside the repository."
    }

    return $fullPath
}

function Convert-ToRepoRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$PathValue
    )

    $rootUri = [System.Uri]::new($RepoRoot.TrimEnd([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)) + [System.IO.Path]::DirectorySeparatorChar)
    $pathUri = [System.Uri]::new($PathValue)
    $relative = [System.Uri]::UnescapeDataString($rootUri.MakeRelativeUri($pathUri).ToString())
    return $relative
}

function Invoke-GoEnv {
    param([Parameter(Mandatory = $true)][string]$Name)

    $value = (& go env $Name)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($value)) {
        throw "Unable to resolve $Name from go env."
    }
    return $value.Trim()
}

function Test-InAllowedSet {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string[]]$Allowed
    )

    if ($Allowed -notcontains $Value) {
        throw "$Name must be one of: $($Allowed -join ', ')."
    }
}

if ($Version -notmatch '^[A-Za-z0-9._+-]+$') {
    throw "Version may contain only letters, numbers, dot, underscore, plus, and hyphen."
}

$repoRoot = Get-RepoRoot
$outputRoot = Resolve-RepoPath -RepoRoot $repoRoot -PathValue $OutputDir

if ([string]::IsNullOrWhiteSpace($TargetOS)) {
    $TargetOS = Invoke-GoEnv -Name "GOHOSTOS"
}
if ([string]::IsNullOrWhiteSpace($TargetArch)) {
    $TargetArch = Invoke-GoEnv -Name "GOHOSTARCH"
}

Test-InAllowedSet -Name "TargetOS" -Value $TargetOS -Allowed @("windows", "linux", "darwin")
Test-InAllowedSet -Name "TargetArch" -Value $TargetArch -Allowed @("amd64", "arm64")

$gitCommit = "unknown"
try {
    $commit = (& git rev-parse --short=12 HEAD 2>$null)
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($commit)) {
        $gitCommit = $commit.Trim()
    }
}
catch {
    $gitCommit = "unknown"
}

$targetName = "$TargetOS-$TargetArch"
$artifactName = "oaw-agent"
if ($TargetOS -eq "windows") {
    $artifactName = "oaw-agent.exe"
}

$targetDir = Join-Path (Join-Path (Join-Path $outputRoot "agent") $Version) $targetName
New-Item -ItemType Directory -Force -Path $targetDir | Out-Null

$artifactPath = Join-Path $targetDir $artifactName
$checksumPath = Join-Path $targetDir "$artifactName.sha256"
$manifestPath = Join-Path $targetDir "$artifactName.manifest.json"

$oldGOOS = $env:GOOS
$oldGOARCH = $env:GOARCH
$oldCGO = $env:CGO_ENABLED
try {
    $env:GOOS = $TargetOS
    $env:GOARCH = $TargetArch
    $env:CGO_ENABLED = "0"

    $ldflags = "-s -w -X github.com/openassetwatch/openassetwatch/pkg/version.Number=$Version -X github.com/openassetwatch/openassetwatch/pkg/version.Commit=$gitCommit"
    & go build -trimpath -mod=readonly -ldflags $ldflags -o $artifactPath ./cmd/oaw-agent
    if ($LASTEXITCODE -ne 0) {
        throw "go build failed for $TargetOS/$TargetArch."
    }
}
finally {
    $env:GOOS = $oldGOOS
    $env:GOARCH = $oldGOARCH
    $env:CGO_ENABLED = $oldCGO
}

$sha256 = (Get-FileHash -Algorithm SHA256 -Path $artifactPath).Hash.ToLowerInvariant()
Set-Content -Path $checksumPath -Value "$sha256  $artifactName" -Encoding ascii

$buildTimestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$manifest = [ordered]@{
    artifact_name = $artifactName
    artifact_type = "oaw-agent-binary"
    version = $Version
    os = $TargetOS
    arch = $TargetArch
    path = Convert-ToRepoRelativePath -RepoRoot $repoRoot -PathValue $artifactPath
    sha256 = $sha256
    build_timestamp = $buildTimestamp
    git_commit = $gitCommit
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -Path $manifestPath -Encoding utf8

$summary = [ordered]@{
    status = "built"
    artifact = Convert-ToRepoRelativePath -RepoRoot $repoRoot -PathValue $artifactPath
    checksum = Convert-ToRepoRelativePath -RepoRoot $repoRoot -PathValue $checksumPath
    manifest = Convert-ToRepoRelativePath -RepoRoot $repoRoot -PathValue $manifestPath
}
$summary | ConvertTo-Json -Depth 4
