param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$DistRoot = "dist",
    [switch]$IncludePackages
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

function Test-ChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Child
    )

    $comparison = [System.StringComparison]::OrdinalIgnoreCase
    $parentWithSeparator = $Parent.TrimEnd([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)) + [System.IO.Path]::DirectorySeparatorChar
    return ($Child.Equals($Parent, $comparison) -or $Child.StartsWith($parentWithSeparator, $comparison))
}

function Test-ManifestFields {
    param(
        [Parameter(Mandatory = $true)]$Manifest,
        [Parameter(Mandatory = $true)][string[]]$Fields,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $missing = @()
    foreach ($field in $Fields) {
        if (-not $Manifest.PSObject.Properties.Name.Contains($field)) {
            $missing += $field
            continue
        }
        if ([string]::IsNullOrWhiteSpace([string]$Manifest.$field)) {
            $missing += $field
        }
    }

    if ($missing.Count -gt 0) {
        Add-Check -Name "$Context manifest fields" -Ok $false -Message "$Context manifest missing fields: $($missing -join ', ')"
        return $false
    }

    Add-Check -Name "$Context manifest fields" -Ok $true -Message "$Context manifest fields are present."
    return $true
}

function Test-ChecksumFile {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$ChecksumPath,
        [Parameter(Mandatory = $true)][string]$ExpectedHash,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $FilePath).Hash.ToLowerInvariant()
    $manifestHash = $ExpectedHash.ToLowerInvariant()
    $checksumText = (Get-Content -LiteralPath $ChecksumPath -TotalCount 1)
    $checksumHash = (([string]$checksumText) -split '\s+')[0].ToLowerInvariant()

    if ($actualHash -ne $manifestHash) {
        Add-Check -Name "$Context manifest checksum" -Ok $false -Message "$Context SHA256 does not match manifest."
        return $false
    }
    Add-Check -Name "$Context manifest checksum" -Ok $true -Message "$Context SHA256 matches manifest."

    if ($actualHash -ne $checksumHash) {
        Add-Check -Name "$Context checksum file" -Ok $false -Message "$Context SHA256 does not match checksum file."
        return $false
    }
    Add-Check -Name "$Context checksum file" -Ok $true -Message "$Context SHA256 matches checksum file."
    return $true
}

function Test-ForbiddenArchiveContent {
    param(
        [Parameter(Mandatory = $true)][string]$PackagePath,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $tarCommand = Get-Command tar -ErrorAction SilentlyContinue
    if ($null -eq $tarCommand) {
        Add-Check -Name "$Context archive listing" -Ok $false -Message "tar command is required to validate TAR.GZ archive contents."
        return
    }

    $tarPath = $tarCommand.Source
    if ($tarCommand.PSObject.Properties.Name.Contains("Path") -and -not [string]::IsNullOrWhiteSpace($tarCommand.Path)) {
        $tarPath = $tarCommand.Path
    }

    $tarArgs = @("-tzf", $PackagePath)
    if ($PackagePath -match '^[A-Za-z]:[\\/]') {
        $tarHelp = ""
        try {
            $tarHelp = (& $tarPath --help 2>&1 | Out-String)
        }
        catch {
            $tarHelp = ""
        }
        if ($tarHelp -match '--force-local') {
            $tarArgs = @("--force-local", "-tzf", $PackagePath)
        }
    }

    $listing = @(& $tarPath @tarArgs 2>&1)
    if ($LASTEXITCODE -ne 0) {
        Add-Check -Name "$Context archive listing" -Ok $false -Message "$Context archive could not be listed."
        return
    }

    Add-Check -Name "$Context archive listing" -Ok $true -Message "$Context archive can be listed."
    $forbidden = @($listing | Where-Object {
        $_ -match '(config\.json|identity\.json|status\.json|\.log$|token|secret|credential|password|\.pem$|\.key$|\.service$|\.plist$)'
    })

    if ($forbidden.Count -gt 0) {
        Add-Check -Name "$Context forbidden archive content" -Ok $false -Message "$Context archive contains forbidden entries: $($forbidden -join ', ')"
        return
    }

    Add-Check -Name "$Context forbidden archive content" -Ok $true -Message "$Context archive contains no forbidden entries."
}

function Test-BinaryArtifactDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$ArtifactDir,
        [Parameter(Mandatory = $true)][string]$Version
    )

    $relativeArtifactDir = Convert-ToRepoRelativePath -RepoRoot $RepoRoot -PathValue $ArtifactDir
    Add-Check -Name "dist artifact directory exists: $relativeArtifactDir" -Ok (Test-Path -LiteralPath $ArtifactDir -PathType Container) -Message "Artifact directory checked."

    $manifestFiles = @(Get-ChildItem -LiteralPath $ArtifactDir -File -Filter "*.manifest.json" -ErrorAction SilentlyContinue)
    if ($manifestFiles.Count -ne 1) {
        Add-Check -Name "binary manifest exists: $relativeArtifactDir" -Ok $false -Message "$relativeArtifactDir must contain exactly one binary manifest."
        return
    }
    Add-Check -Name "binary manifest exists: $relativeArtifactDir" -Ok $true -Message "$relativeArtifactDir contains one binary manifest."

    try {
        $manifest = Get-Content -Raw -LiteralPath $manifestFiles[0].FullName | ConvertFrom-Json
    }
    catch {
        Add-Check -Name "binary manifest parses: $relativeArtifactDir" -Ok $false -Message "$relativeArtifactDir binary manifest is malformed JSON."
        return
    }
    Add-Check -Name "binary manifest parses: $relativeArtifactDir" -Ok $true -Message "$relativeArtifactDir binary manifest parses."

    $required = @("artifact_name", "version", "os", "arch", "path", "sha256", "build_timestamp", "git_commit")
    if (-not (Test-ManifestFields -Manifest $manifest -Fields $required -Context "binary $relativeArtifactDir")) {
        return
    }

    if ([string]$manifest.version -ne $Version) {
        Add-Check -Name "binary manifest version: $relativeArtifactDir" -Ok $false -Message "$relativeArtifactDir binary manifest version does not match requested version."
        return
    }
    Add-Check -Name "binary manifest version: $relativeArtifactDir" -Ok $true -Message "$relativeArtifactDir binary manifest version matches."

    $artifactPath = Resolve-RepoPath -RepoRoot $RepoRoot -PathValue ([string]$manifest.path)
    if (-not (Test-ChildPath -Parent $ArtifactDir -Child $artifactPath)) {
        Add-Check -Name "binary path containment: $relativeArtifactDir" -Ok $false -Message "$relativeArtifactDir binary path is outside artifact directory."
        return
    }
    Add-Check -Name "binary path containment: $relativeArtifactDir" -Ok $true -Message "$relativeArtifactDir binary path is inside artifact directory."

    if (-not (Test-Path -LiteralPath $artifactPath -PathType Leaf)) {
        Add-Check -Name "agent binary exists: $relativeArtifactDir" -Ok $false -Message "$relativeArtifactDir agent binary is missing."
        return
    }
    Add-Check -Name "agent binary exists: $relativeArtifactDir" -Ok $true -Message "$relativeArtifactDir agent binary exists."

    $checksumPath = Join-Path $ArtifactDir "$($manifest.artifact_name).sha256"
    if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
        Add-Check -Name "binary checksum exists: $relativeArtifactDir" -Ok $false -Message "$relativeArtifactDir binary checksum file is missing."
        return
    }
    Add-Check -Name "binary checksum exists: $relativeArtifactDir" -Ok $true -Message "$relativeArtifactDir binary checksum exists."

    [void](Test-ChecksumFile -FilePath $artifactPath -ChecksumPath $checksumPath -ExpectedHash ([string]$manifest.sha256) -Context "binary $relativeArtifactDir")
}

function Test-ReleaseArtifactDirectoryName {
    param([Parameter(Mandatory = $true)][string]$Name)

    return $Name -match '^(linux|windows|darwin)-[A-Za-z0-9]+$'
}

function Test-PackageManifest {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$PackageManifestPath,
        [Parameter(Mandatory = $true)][string]$Version
    )

    $relativeManifest = Convert-ToRepoRelativePath -RepoRoot $RepoRoot -PathValue $PackageManifestPath
    try {
        $manifest = Get-Content -Raw -LiteralPath $PackageManifestPath | ConvertFrom-Json
    }
    catch {
        Add-Check -Name "package manifest parses: $relativeManifest" -Ok $false -Message "$relativeManifest package manifest is malformed JSON."
        return
    }
    Add-Check -Name "package manifest parses: $relativeManifest" -Ok $true -Message "$relativeManifest package manifest parses."

    $required = @("package_name", "version", "os", "arch", "package_type", "source_artifact_path", "package_path", "sha256", "build_timestamp", "git_commit")
    if (-not (Test-ManifestFields -Manifest $manifest -Fields $required -Context "package $relativeManifest")) {
        return
    }

    if ([string]$manifest.version -ne $Version -or [string]$manifest.package_type -ne "tar.gz") {
        Add-Check -Name "package identity: $relativeManifest" -Ok $false -Message "$relativeManifest package identity does not match requested version and tar.gz type."
        return
    }
    Add-Check -Name "package identity: $relativeManifest" -Ok $true -Message "$relativeManifest package identity matches."

    $packagePath = Resolve-RepoPath -RepoRoot $RepoRoot -PathValue ([string]$manifest.package_path)
    if (-not (Test-Path -LiteralPath $packagePath -PathType Leaf)) {
        Add-Check -Name "package exists: $relativeManifest" -Ok $false -Message "$relativeManifest package file is missing."
        return
    }
    Add-Check -Name "package exists: $relativeManifest" -Ok $true -Message "$relativeManifest package file exists."

    $checksumPath = "$packagePath.sha256"
    if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
        Add-Check -Name "package checksum exists: $relativeManifest" -Ok $false -Message "$relativeManifest package checksum file is missing."
        return
    }
    Add-Check -Name "package checksum exists: $relativeManifest" -Ok $true -Message "$relativeManifest package checksum file exists."

    [void](Test-ChecksumFile -FilePath $packagePath -ChecksumPath $checksumPath -ExpectedHash ([string]$manifest.sha256) -Context "package $relativeManifest")
    Test-ForbiddenArchiveContent -PackagePath $packagePath -Context "package $relativeManifest"
}

try {
    if ($Version -notmatch '^[A-Za-z0-9._+-]+$') {
        throw "Version may contain only letters, numbers, dot, underscore, plus, and hyphen."
    }

    $repoRoot = Get-RepoRoot
    $distRootPath = Resolve-RepoPath -RepoRoot $repoRoot -PathValue $DistRoot
    $releaseRoot = Join-Path (Join-Path $distRootPath "agent") $Version

    $releaseRootExists = Test-Path -LiteralPath $releaseRoot -PathType Container
    $releaseRootMessage = "Release root exists."
    if (-not $releaseRootExists) {
        $releaseRootMessage = "Release root not found under dist/agent/$Version."
    }
    Add-Check -Name "release root exists" -Ok $releaseRootExists -Message $releaseRootMessage
    if (Test-Path -LiteralPath $releaseRoot -PathType Container) {
        $artifactDirs = @(Get-ChildItem -LiteralPath $releaseRoot -Directory -ErrorAction SilentlyContinue | Where-Object {
            Test-ReleaseArtifactDirectoryName -Name $_.Name
        })
        if ($artifactDirs.Count -eq 0) {
            Add-Check -Name "dist artifact directories exist" -Ok $false -Message "No dist artifact directories found under dist/agent/$Version."
        }
        else {
            Add-Check -Name "dist artifact directories exist" -Ok $true -Message "$($artifactDirs.Count) dist artifact directorie(s) found."
            foreach ($dir in $artifactDirs) {
                Test-BinaryArtifactDirectory -RepoRoot $repoRoot -ArtifactDir $dir.FullName -Version $Version
            }
        }

        if ($IncludePackages) {
            $packageDir = Join-Path $releaseRoot "packages"
            $packageDirExists = Test-Path -LiteralPath $packageDir -PathType Container
            $packageDirMessage = "Package directory exists."
            if (-not $packageDirExists) {
                $packageDirMessage = "Package directory not found under dist/agent/$Version/packages."
            }
            Add-Check -Name "package directory exists" -Ok $packageDirExists -Message $packageDirMessage
            if ($packageDirExists) {
                $packageManifestFiles = @(Get-ChildItem -LiteralPath $packageDir -File -Filter "*.tar.gz.manifest.json" -ErrorAction SilentlyContinue)
                if ($packageManifestFiles.Count -eq 0) {
                    Add-Check -Name "package manifests exist" -Ok $false -Message "No TAR.GZ package manifests found under dist/agent/$Version/packages."
                }
                else {
                    Add-Check -Name "package manifests exist" -Ok $true -Message "$($packageManifestFiles.Count) package manifest(s) found."
                    foreach ($manifestPath in $packageManifestFiles) {
                        Test-PackageManifest -RepoRoot $repoRoot -PackageManifestPath $manifestPath.FullName -Version $Version
                    }
                }
            }
        }
        else {
            Add-Warning "Package validation skipped because -IncludePackages was not supplied."
        }
    }
}
catch {
    Add-Check -Name "validation script execution" -Ok $false -Message $_.Exception.Message
}

$summary = [ordered]@{
    ok = ($script:Errors.Count -eq 0)
    checks = $script:Checks
    warnings = $script:Warnings
    errors = $script:Errors
}

$summary | ConvertTo-Json -Depth 8
if ($script:Errors.Count -gt 0) {
    exit 1
}
