param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [string]$TargetArch = "amd64",

    [string]$AgentArtifactInput = "",

    [string]$OutputDir = "dist",

    [string]$Python = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$WixToolVersion = "6.0.2"
$WixUtilExtension = "WixToolset.Util.wixext/6.0.2"
$TargetOS = "windows"
$ArtifactName = "oaw-agent.exe"
$PackageName = "OpenAssetWatchAgent"

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
    $pathUri = [System.Uri]::new([System.IO.Path]::GetFullPath($PathValue))
    return [System.Uri]::UnescapeDataString($rootUri.MakeRelativeUri($pathUri).ToString())
}

function Convert-ToMsiVersion {
    param([Parameter(Mandatory = $true)][string]$ReleaseVersion)
    if ($ReleaseVersion -notmatch '^(\d+)\.(\d+)\.(\d+)') {
        throw "Version must begin with a Windows Installer compatible major.minor.patch value."
    }
    $parts = @([int]$Matches[1], [int]$Matches[2], [int]$Matches[3])
    if ($parts[0] -lt 0 -or $parts[0] -gt 255) {
        throw "MSI major version must be between 0 and 255."
    }
    if ($parts[1] -lt 0 -or $parts[1] -gt 255) {
        throw "MSI minor version must be between 0 and 255."
    }
    if ($parts[2] -lt 0 -or $parts[2] -gt 65535) {
        throw "MSI build version must be between 0 and 65535."
    }
    return "$($parts[0]).$($parts[1]).$($parts[2])"
}

function Invoke-Tool {
    param([string[]]$Arguments)
    & $Arguments[0] @($Arguments | Select-Object -Skip 1)
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $($Arguments -join ' ')"
    }
}

function Invoke-PythonScript {
    param([string[]]$Arguments)
    if (-not [string]::IsNullOrWhiteSpace($Python)) {
        & $Python @Arguments | Out-Null
        return $LASTEXITCODE
    }
    if (-not [string]::IsNullOrWhiteSpace($env:OAW_PYTHON)) {
        & $env:OAW_PYTHON @Arguments | Out-Null
        return $LASTEXITCODE
    }
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($null -ne $python) {
        & $python.Source @Arguments | Out-Null
        return $LASTEXITCODE
    }
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($null -ne $py) {
        & $py.Source -3 @Arguments | Out-Null
        return $LASTEXITCODE
    }
    throw "Python is required to stage the Windows install layout."
}

if ($Version -notmatch '^[A-Za-z0-9._+-]+$') {
    throw "Version may contain only letters, numbers, dot, underscore, plus, and hyphen."
}
if ($TargetArch -ne "amd64") {
    throw "Only windows/amd64 MSI builds are currently supported."
}

$repoRoot = Get-RepoRoot
$outputRoot = Resolve-RepoPath -RepoRoot $repoRoot -PathValue $OutputDir
$msiVersion = Convert-ToMsiVersion -ReleaseVersion $Version

$artifactDir = Join-Path (Join-Path (Join-Path $outputRoot "agent") $Version) "$TargetOS-$TargetArch"
if (-not [string]::IsNullOrWhiteSpace($AgentArtifactInput)) {
    $artifactDir = Resolve-RepoPath -RepoRoot $repoRoot -PathValue $AgentArtifactInput
}
if (-not (Test-Path -LiteralPath $artifactDir -PathType Container)) {
    throw "Windows agent artifact directory does not exist: $(Convert-ToRepoRelativePath -RepoRoot $repoRoot -PathValue $artifactDir)"
}

$artifactPath = Join-Path $artifactDir $ArtifactName
$artifactChecksumPath = Join-Path $artifactDir "$ArtifactName.sha256"
$artifactManifestPath = Join-Path $artifactDir "$ArtifactName.manifest.json"
foreach ($path in @($artifactPath, $artifactChecksumPath, $artifactManifestPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required Windows artifact input is missing: $(Convert-ToRepoRelativePath -RepoRoot $repoRoot -PathValue $path)"
    }
}

$stageScript = Join-Path $PSScriptRoot "stage_agent_windows_install.py"
$stageArguments = @($stageScript, "--version", $Version, "--output-dir", $outputRoot)
if (-not [string]::IsNullOrWhiteSpace($AgentArtifactInput)) {
    $stageArguments += @("--artifact-dir", $artifactDir)
}
$stageExitCode = Invoke-PythonScript -Arguments $stageArguments
if ($stageExitCode -ne 0) {
    throw "Windows install staging failed."
}

$windowsInstallRoot = Join-Path (Join-Path (Join-Path $outputRoot "agent") $Version) "windows-install"
$packagesDir = Join-Path (Join-Path (Join-Path $outputRoot "agent") $Version) "packages"
$intermediateDir = Join-Path (Join-Path (Join-Path $outputRoot "agent") $Version) "msi-obj"
New-Item -ItemType Directory -Force -Path $packagesDir | Out-Null
New-Item -ItemType Directory -Force -Path $intermediateDir | Out-Null

$msiName = "$PackageName-$Version-windows-$TargetArch.msi"
$msiPath = Join-Path $packagesDir $msiName
$checksumPath = Join-Path $packagesDir "$msiName.sha256"
$manifestPath = Join-Path $packagesDir "$msiName.manifest.json"
$wxsPath = Join-Path $repoRoot "packaging\agent\windows\OpenAssetWatchAgent.wxs"

Invoke-Tool -Arguments @("dotnet", "tool", "restore")
Invoke-Tool -Arguments @("dotnet", "tool", "run", "wix", "--", "extension", "add", $WixUtilExtension)
Invoke-Tool -Arguments @(
    "dotnet", "tool", "run", "wix", "--",
    "build",
    $wxsPath,
    "-ext", $WixUtilExtension,
    "-arch", "x64",
    "-d", "SourceDir=$windowsInstallRoot",
    "-d", "ReleaseVersion=$Version",
    "-d", "MsiVersion=$msiVersion",
    "-d", "TargetArch=$TargetArch",
    "-intermediatefolder", $intermediateDir,
    "-out", $msiPath
)

if (-not (Test-Path -LiteralPath $msiPath -PathType Leaf)) {
    throw "MSI build did not produce the expected artifact."
}

$sha256 = (Get-FileHash -Algorithm SHA256 -Path $msiPath).Hash.ToLowerInvariant()
Set-Content -Path $checksumPath -Value "$sha256  $msiName" -Encoding ascii

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

$manifest = [ordered]@{
    package_name = "openassetwatch-agent"
    artifact_name = $msiName
    package_type = "msi"
    package_license = "Apache-2.0"
    version = $Version
    msi_version = $msiVersion
    os = "windows"
    arch = $TargetArch
    wix_tool_version = $WixToolVersion
    wix_util_extension = $WixUtilExtension
    source_artifact = Convert-ToRepoRelativePath -RepoRoot $repoRoot -PathValue $artifactPath
    windows_install_root = Convert-ToRepoRelativePath -RepoRoot $repoRoot -PathValue $windowsInstallRoot
    package_path = Convert-ToRepoRelativePath -RepoRoot $repoRoot -PathValue $msiPath
    sha256 = $sha256
    checksum = Convert-ToRepoRelativePath -RepoRoot $repoRoot -PathValue $checksumPath
    git_commit = $gitCommit
    generated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    signing = [ordered]@{
        signed = $false
        note = "Local CI builds are unsigned. Production release builds must sign the executable and MSI."
    }
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -Path $manifestPath -Encoding utf8

$summary = [ordered]@{
    ok = $true
    version = $Version
    msi = Convert-ToRepoRelativePath -RepoRoot $repoRoot -PathValue $msiPath
    checksum = Convert-ToRepoRelativePath -RepoRoot $repoRoot -PathValue $checksumPath
    manifest = Convert-ToRepoRelativePath -RepoRoot $repoRoot -PathValue $manifestPath
}
$summary | ConvertTo-Json -Depth 6
