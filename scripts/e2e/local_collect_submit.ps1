param(
    [Parameter(Mandatory = $true)]
    [string]$ServerUrl,

    [string]$SiteId = "site-local",

    [switch]$IncludeCheckIn,

    [switch]$UseConfig,

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
$configPath = Join-Path $tempDir "config.json"
$identityPath = Join-Path $tempDir "identity.json"
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

    if ($UseConfig) {
        $configOutput = & $goCommand run ./cmd/oaw-agent config init --server-url $ServerUrl --site-id $SiteId --output $configPath 2>&1
        $configExit = $LASTEXITCODE
        if ($configExit -ne 0) {
            throw "Agent config initialization failed. $configOutput"
        }

        if (-not (Test-Path $configPath)) {
            throw "Agent config initialization did not create the expected config JSON file."
        }
    }

    if ($IncludeCheckIn) {
        $identityOutput = & $goCommand run ./cmd/oaw-agent identity init --site-id $SiteId --output $identityPath 2>&1
        $identityExit = $LASTEXITCODE
        if ($identityExit -ne 0) {
            throw "Identity initialization failed. $identityOutput"
        }

        if (-not (Test-Path $identityPath)) {
            throw "Identity initialization did not create the expected identity JSON file."
        }

        if ($UseConfig) {
            $checkInOutput = & $goCommand run ./cmd/oaw-agent check-in --identity-file $identityPath --config $configPath 2>&1
        } else {
            $checkInOutput = & $goCommand run ./cmd/oaw-agent check-in --identity-file $identityPath --server-url $ServerUrl 2>&1
        }
        $checkInExit = $LASTEXITCODE
        if ($checkInExit -ne 0) {
            throw "Agent check-in failed. $checkInOutput"
        }

        if ($checkInOutput -notmatch "HTTP 2\d\d") {
            throw "Agent check-in did not report an accepted HTTP response. $checkInOutput"
        }

        if ($UseConfig) {
            & $goCommand run ./cmd/oaw-agent collect --once --identity-file $identityPath --config $configPath --output $inventoryPath
        } else {
            & $goCommand run ./cmd/oaw-agent collect --once --identity-file $identityPath --output $inventoryPath
        }
    } elseif ($UseConfig) {
        & $goCommand run ./cmd/oaw-agent collect --once --config $configPath --output $inventoryPath
    } else {
        & $goCommand run ./cmd/oaw-agent collect --once --site-id $SiteId --output $inventoryPath
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Local collection failed."
    }

    if (-not (Test-Path $inventoryPath)) {
        throw "Local collection did not create the expected inventory JSON file."
    }

    if ($UseConfig) {
        $submitOutput = & $goCommand run ./cmd/oaw-agent submit --file $inventoryPath --config $configPath 2>&1
    } else {
        $submitOutput = & $goCommand run ./cmd/oaw-agent submit --file $inventoryPath --server-url $ServerUrl 2>&1
    }
    $submitExit = $LASTEXITCODE
    if ($submitExit -ne 0) {
        throw "Submit failed. $submitOutput"
    }

    if ($submitOutput -notmatch "HTTP 2\d\d") {
        throw "Submit did not report an accepted HTTP response. $submitOutput"
    }

    if ($IncludeCheckIn) {
        if ($UseConfig) {
            Write-Host "Local config, identity, check-in, collect, and submit E2E passed for site_id '$SiteId'."
        } else {
            Write-Host "Local identity, check-in, collect, and submit E2E passed for site_id '$SiteId'."
        }
        Write-Host $checkInOutput
    } elseif ($UseConfig) {
        Write-Host "Local config, collect, and submit E2E passed for site_id '$SiteId'."
    } else {
        Write-Host "Local collect and submit E2E passed for site_id '$SiteId'."
    }
    Write-Host $submitOutput
    if ($KeepTemp) {
        if ($UseConfig) {
            Write-Host "Config JSON retained at $configPath"
        }
        if ($IncludeCheckIn) {
            Write-Host "Identity JSON retained at $identityPath"
        }
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
