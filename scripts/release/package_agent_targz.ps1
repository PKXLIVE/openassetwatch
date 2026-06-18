param(
    [Parameter(Mandatory = $true)][string]$ArtifactDir,
    [string]$DistDir = "dist"
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
        throw "Path must resolve inside the repository."
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
    return [System.Uri]::UnescapeDataString($rootUri.MakeRelativeUri($pathUri).ToString())
}

function Assert-ChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Child,
        [Parameter(Mandatory = $true)][string]$Message
    )

    $comparison = [System.StringComparison]::OrdinalIgnoreCase
    $parentWithSeparator = $Parent.TrimEnd([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)) + [System.IO.Path]::DirectorySeparatorChar
    if (-not ($Child.Equals($Parent, $comparison) -or $Child.StartsWith($parentWithSeparator, $comparison))) {
        throw $Message
    }
}

function Get-GitCommit {
    try {
        $commit = (& git rev-parse --short=12 HEAD 2>$null)
        if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($commit)) {
            return $commit.Trim()
        }
    }
    catch {
        return "unknown"
    }
    return "unknown"
}

function Test-NoForbiddenSourceFiles {
    param([Parameter(Mandatory = $true)][string]$PathValue)

    $forbidden = @(
        "config.json",
        "identity.json",
        "status.json",
        "*.log",
        "*.pem",
        "*.key",
        "*token*",
        "*secret*",
        "*credential*",
        "*password*"
    )

    foreach ($pattern in $forbidden) {
        $matches = @(Get-ChildItem -LiteralPath $PathValue -File -Filter $pattern -ErrorAction SilentlyContinue)
        if ($matches.Count -gt 0) {
            throw "ArtifactDir contains forbidden file pattern '$pattern'."
        }
    }
}

$repoRoot = Get-RepoRoot
$artifactRoot = Resolve-RepoPath -RepoRoot $repoRoot -PathValue $ArtifactDir
$distRoot = Resolve-RepoPath -RepoRoot $repoRoot -PathValue $DistDir

if (-not (Test-Path -LiteralPath $artifactRoot -PathType Container)) {
    throw "ArtifactDir does not exist or is not a directory."
}

Test-NoForbiddenSourceFiles -PathValue $artifactRoot

$binaryManifestFiles = @(Get-ChildItem -LiteralPath $artifactRoot -File -Filter "*.manifest.json")
if ($binaryManifestFiles.Count -ne 1) {
    throw "ArtifactDir must contain exactly one binary manifest (*.manifest.json)."
}

$binaryManifestPath = $binaryManifestFiles[0].FullName
$binaryManifest = Get-Content -Raw -LiteralPath $binaryManifestPath | ConvertFrom-Json

$requiredManifestFields = @("artifact_name", "version", "os", "arch", "path", "sha256", "git_commit")
foreach ($field in $requiredManifestFields) {
    if (-not $binaryManifest.PSObject.Properties.Name.Contains($field) -or [string]::IsNullOrWhiteSpace([string]$binaryManifest.$field)) {
        throw "Binary manifest is missing required field '$field'."
    }
}
if ($binaryManifest.PSObject.Properties.Name.Contains("artifact_type") -and [string]$binaryManifest.artifact_type -ne "oaw-agent-binary") {
    throw "Binary manifest artifact_type must be oaw-agent-binary."
}

$sourceArtifactPath = Resolve-RepoPath -RepoRoot $repoRoot -PathValue ([string]$binaryManifest.path)
Assert-ChildPath -Parent $artifactRoot -Child $sourceArtifactPath -Message "Binary manifest path must point inside ArtifactDir."

if (-not (Test-Path -LiteralPath $sourceArtifactPath -PathType Leaf)) {
    throw "Source artifact from binary manifest was not found."
}

$sourceChecksumPath = Join-Path $artifactRoot "$($binaryManifest.artifact_name).sha256"
if (-not (Test-Path -LiteralPath $sourceChecksumPath -PathType Leaf)) {
    throw "Source artifact checksum file was not found."
}

$expectedArtifactHash = ([string]$binaryManifest.sha256).ToLowerInvariant()
$actualArtifactHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceArtifactPath).Hash.ToLowerInvariant()
if ($expectedArtifactHash -ne $actualArtifactHash) {
    throw "Source artifact checksum does not match binary manifest."
}

$version = [string]$binaryManifest.version
$targetOS = [string]$binaryManifest.os
$targetArch = [string]$binaryManifest.arch
if ($version -notmatch '^[A-Za-z0-9._+-]+$') {
    throw "Version may contain only letters, numbers, dot, underscore, plus, and hyphen."
}
if ($targetOS -notmatch '^[A-Za-z0-9._+-]+$' -or $targetArch -notmatch '^[A-Za-z0-9._+-]+$') {
    throw "OS and architecture values must be simple identifier strings."
}

$packageName = "openassetwatch-agent-$version-$targetOS-$targetArch.tar.gz"
$packageDir = Join-Path (Join-Path (Join-Path $distRoot "agent") $version) "packages"
New-Item -ItemType Directory -Force -Path $packageDir | Out-Null

$packagePath = Join-Path $packageDir $packageName
$packageChecksumPath = Join-Path $packageDir "$packageName.sha256"
$packageManifestPath = Join-Path $packageDir "$packageName.manifest.json"

$stagingRoot = Join-Path $packageDir ".staging-$version-$targetOS-$targetArch"
$archiveRootName = "openassetwatch-agent-$version-$targetOS-$targetArch"
$archiveRoot = Join-Path $stagingRoot $archiveRootName

if (Test-Path -LiteralPath $stagingRoot) {
    Assert-ChildPath -Parent $packageDir -Child $stagingRoot -Message "Refusing to clean staging outside package directory."
    Remove-Item -LiteralPath $stagingRoot -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $archiveRoot | Out-Null
Copy-Item -LiteralPath $sourceArtifactPath -Destination (Join-Path $archiveRoot $binaryManifest.artifact_name)
Copy-Item -LiteralPath $sourceChecksumPath -Destination (Join-Path $archiveRoot (Split-Path $sourceChecksumPath -Leaf))
Copy-Item -LiteralPath $binaryManifestPath -Destination (Join-Path $archiveRoot (Split-Path $binaryManifestPath -Leaf))

$notes = @(
    "# OpenAssetWatch Agent TAR.GZ Package Notes",
    "",
    "This archive contains only the OpenAssetWatch agent binary, binary checksum,",
    "and binary manifest from an existing local dist artifact.",
    "",
    "This archive does not include config files, identity files, enrollment tokens,",
    "credentials, logs, status files, service definitions, installer scripts, or",
    "package-manager instructions.",
    "",
    "Verify checksums and follow administrator-approved deployment procedures before",
    "using this artifact."
)
Set-Content -LiteralPath (Join-Path $archiveRoot "README.md") -Value $notes -Encoding utf8

$tarCommand = Get-Command tar -ErrorAction Stop
$tarPath = $tarCommand.Source
if ($tarCommand.PSObject.Properties.Name.Contains("Path") -and -not [string]::IsNullOrWhiteSpace($tarCommand.Path)) {
    $tarPath = $tarCommand.Path
}
Push-Location $stagingRoot
try {
    & $tarPath -czf $packagePath $archiveRootName
    if ($LASTEXITCODE -ne 0) {
        throw "tar.gz archive creation failed."
    }
}
finally {
    Pop-Location
}

$packageHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $packagePath).Hash.ToLowerInvariant()
Set-Content -LiteralPath $packageChecksumPath -Value "$packageHash  $packageName" -Encoding ascii

$buildTimestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$packageManifest = [ordered]@{
    package_name = $packageName
    version = $version
    os = $targetOS
    arch = $targetArch
    package_type = "tar.gz"
    source_artifact_path = Convert-ToRepoRelativePath -RepoRoot $repoRoot -PathValue $sourceArtifactPath
    source_checksum_path = Convert-ToRepoRelativePath -RepoRoot $repoRoot -PathValue $sourceChecksumPath
    source_manifest_path = Convert-ToRepoRelativePath -RepoRoot $repoRoot -PathValue $binaryManifestPath
    package_path = Convert-ToRepoRelativePath -RepoRoot $repoRoot -PathValue $packagePath
    sha256 = $packageHash
    build_timestamp = $buildTimestamp
    git_commit = Get-GitCommit
    contents = @(
        [string]$binaryManifest.artifact_name,
        [string](Split-Path $sourceChecksumPath -Leaf),
        [string](Split-Path $binaryManifestPath -Leaf),
        "README.md"
    )
}
$packageManifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $packageManifestPath -Encoding utf8

Remove-Item -LiteralPath $stagingRoot -Recurse -Force

$summary = [ordered]@{
    status = "packaged"
    package = Convert-ToRepoRelativePath -RepoRoot $repoRoot -PathValue $packagePath
    checksum = Convert-ToRepoRelativePath -RepoRoot $repoRoot -PathValue $packageChecksumPath
    manifest = Convert-ToRepoRelativePath -RepoRoot $repoRoot -PathValue $packageManifestPath
}
$summary | ConvertTo-Json -Depth 4
