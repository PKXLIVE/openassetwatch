param(
    [Parameter(Mandatory = $true)]
    [string]$ServerUrl,

    [string]$SiteId = "site-local",

    [switch]$KeepTemp
)

$ErrorActionPreference = "Stop"

function Resolve-LocalServerUrl {
    param([string]$Value)

    try {
        $uri = [System.Uri]::new($Value)
    } catch {
        throw "ServerUrl must be an absolute local HTTP URL."
    }

    if ($uri.Scheme -notin @("http", "https")) {
        throw "ServerUrl must use http or https."
    }

    $localHosts = @("localhost", "127.0.0.1", "::1", "[::1]")
    if ($localHosts -notcontains $uri.Host) {
        throw "ServerUrl must point to a local backend such as http://localhost:8000."
    }

    if ($uri.Query -or $uri.Fragment) {
        throw "ServerUrl must not include query parameters or fragments."
    }

    if ($uri.UserInfo) {
        throw "ServerUrl must not include credentials."
    }

    return $uri
}

function Join-OawEndpoint {
    param(
        [System.Uri]$BaseUri,
        [string]$Path
    )

    $base = $BaseUri.AbsoluteUri.TrimEnd("/")
    return "$base/$($Path.TrimStart('/'))"
}

function Resolve-GoCommand {
    $go = Get-Command go -ErrorAction SilentlyContinue
    if ($go) {
        return $go.Source
    }

    $windowsGo = Join-Path $env:ProgramFiles "Go\bin\go.exe"
    if (Test-Path $windowsGo) {
        return $windowsGo
    }

    throw "Go is not available on PATH and was not found at the standard Windows install path."
}

$serverUri = Resolve-LocalServerUrl -Value $ServerUrl
$goCommand = Resolve-GoCommand
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "oaw-e2e-$([System.Guid]::NewGuid().ToString('N'))"
$inventoryPath = Join-Path $tempDir "inventory.json"
$pushedLocation = $false

New-Item -ItemType Directory -Path $tempDir | Out-Null

try {
    Push-Location $repoRoot
    $pushedLocation = $true

    $healthUrl = Join-OawEndpoint -BaseUri $serverUri -Path "/health"
    try {
        Invoke-WebRequest -Method Get -Uri $healthUrl -TimeoutSec 5 -UseBasicParsing | Out-Null
    } catch {
        throw "Backend is not reachable at $healthUrl. Start the local backend before running this helper."
    }

    & $goCommand run ./cmd/oaw-agent collect --once --site-id $SiteId --output $inventoryPath
    if ($LASTEXITCODE -ne 0) {
        throw "Local collection failed."
    }

    if (-not (Test-Path $inventoryPath)) {
        throw "Local collection did not create the expected inventory JSON file."
    }

    $submitOutput = & $goCommand run ./cmd/oaw-agent submit --file $inventoryPath --server-url $ServerUrl 2>&1
    $submitExit = $LASTEXITCODE
    if ($submitExit -ne 0) {
        throw "Submit failed. $submitOutput"
    }

    if ($submitOutput -notmatch "HTTP 2\d\d") {
        throw "Submit did not report an accepted HTTP response. $submitOutput"
    }

    Write-Host "Local collect and submit E2E passed for site_id '$SiteId'."
    Write-Host $submitOutput
    if ($KeepTemp) {
        Write-Host "Inventory JSON retained at $inventoryPath"
    }
} finally {
    if ($pushedLocation) {
        Pop-Location
    }
    if (-not $KeepTemp -and (Test-Path $tempDir)) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force
    }
}
