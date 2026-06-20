# OpenAssetWatch Windows file install helper.
#
# This helper copies files from a staged Windows install layout into real
# Windows install paths only when explicitly run by an administrator. Use
# -DryRun for validation without modifying the host.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$WindowsInstallRoot,

    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$ProgramFilesAgentRoot = "C:\Program Files\OpenAssetWatch\Agent"
$ProgramFilesBinRoot = Join-Path $ProgramFilesAgentRoot "bin"
$ProgramFilesBinary = Join-Path $ProgramFilesBinRoot "oaw-agent.exe"
$ProgramDataAgentRoot = "C:\ProgramData\OpenAssetWatch\Agent"
$ProgramDataConfigRoot = Join-Path $ProgramDataAgentRoot "config"
$ProgramDataIdentityRoot = Join-Path $ProgramDataAgentRoot "identity"
$ProgramDataStateRoot = Join-Path $ProgramDataAgentRoot "state"
$ProgramDataLogsRoot = Join-Path $ProgramDataAgentRoot "logs"
$ExpectedServiceName = "OpenAssetWatchAgent"
$ExpectedServiceExecutable = $ProgramFilesBinary
$SensitivePattern = "(?i)(credential|password|token|api[_-]?key|private[_-]?key|secret)"

$Report = [ordered]@{
    ok = $false
    dry_run = [bool]$DryRun
    windows_install_root = ""
    program_files_binary = $ProgramFilesBinary
    programdata_root = $ProgramDataAgentRoot
    actions = @()
    acl_expectations = @()
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

function Add-AclExpectation {
    param([string]$Message)
    $script:Report.acl_expectations += $Message
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

function Assert-SafeJsonText {
    param(
        [string]$PathValue,
        [string]$Label
    )
    $text = Get-Content -Raw -LiteralPath $PathValue
    if ($text -match $SensitivePattern) {
        throw "$Label contains credential, password, token, API key, or secret markers."
    }
}

function Assert-StagedLayout {
    param([string]$Root)
    $paths = [ordered]@{
        binary = Join-Path $Root "ProgramFiles\OpenAssetWatch\Agent\bin\oaw-agent.exe"
        config_example = Join-Path $Root "ProgramData\OpenAssetWatch\Agent\config\config.example.json"
        identity_example = Join-Path $Root "ProgramData\OpenAssetWatch\Agent\identity\identity.example.json"
        state_dir = Join-Path $Root "ProgramData\OpenAssetWatch\Agent\state"
        logs_dir = Join-Path $Root "ProgramData\OpenAssetWatch\Agent\logs"
        service_metadata = Join-Path $Root "service\oaw-agent-service.json"
        manifest = Join-Path $Root "windows-install-manifest.json"
    }
    foreach ($name in $paths.Keys) {
        $path = $paths[$name]
        if ($name -in @("state_dir", "logs_dir")) {
            if (-not (Test-Path -LiteralPath $path -PathType Container)) {
                throw "Staged $name is missing."
            }
        } elseif (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Staged $name is missing."
        }
    }
    Assert-SafeJsonText -PathValue $paths.service_metadata -Label "Service metadata"
    Assert-SafeJsonText -PathValue $paths.manifest -Label "Windows install manifest"
    $metadata = Get-Content -Raw -LiteralPath $paths.service_metadata | ConvertFrom-Json
    if ($metadata.service_name -ne $ExpectedServiceName) {
        throw "Service metadata service_name must be $ExpectedServiceName."
    }
    if ($metadata.executable_path -ne $ExpectedServiceExecutable) {
        throw "Service metadata executable_path must be $ExpectedServiceExecutable."
    }
    if ([string]$metadata.arguments -notmatch "^service run ") {
        throw "Service metadata arguments must use service run."
    }
    return $paths
}

function Assert-ExampleJson {
    param(
        [string]$ConfigExample,
        [string]$IdentityExample
    )
    $config = Get-Content -Raw -LiteralPath $ConfigExample | ConvertFrom-Json
    if ($null -ne $config.PSObject.Properties["config_json"]) {
        throw "Config example must not create real config.json values."
    }
    if ($config.server_url -notmatch "\.example\.invalid$") {
        throw "Config example must use example.invalid."
    }
    $identity = Get-Content -Raw -LiteralPath $IdentityExample | ConvertFrom-Json
    if ($null -ne $identity.PSObject.Properties["identity_json"]) {
        throw "Identity example must not create real identity.json values."
    }
    foreach ($field in @("agent_id", "deployment_id", "created_at", "updated_at")) {
        if (-not ([string]$identity.$field).StartsWith("replace-with-")) {
            throw "Identity example $field must be an explicit placeholder."
        }
    }
}

function Assert-NoRealConfigOverwrite {
    $realConfig = Join-Path $ProgramDataConfigRoot "config.json"
    $realIdentity = Join-Path $ProgramDataIdentityRoot "identity.json"
    if (Test-Path -LiteralPath $realConfig) {
        Add-Warning "Existing config.json will be preserved."
    }
    if (Test-Path -LiteralPath $realIdentity) {
        Add-Warning "Existing identity.json will be preserved."
    }
}

function New-AccessRule {
    param(
        [string]$Identity,
        [System.Security.AccessControl.FileSystemRights]$Rights,
        [System.Security.AccessControl.InheritanceFlags]$Inheritance,
        [System.Security.AccessControl.PropagationFlags]$Propagation
    )
    return New-Object System.Security.AccessControl.FileSystemAccessRule(
        $Identity,
        $Rights,
        $Inheritance,
        $Propagation,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
}

function Set-DirectoryAcl {
    param(
        [string]$PathValue,
        [bool]$LocalServiceCanWrite
    )
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $inherit = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $propagation = [System.Security.AccessControl.PropagationFlags]::None
    $acl.AddAccessRule((New-AccessRule -Identity "BUILTIN\Administrators" -Rights "FullControl" -Inheritance $inherit -Propagation $propagation))
    $acl.AddAccessRule((New-AccessRule -Identity "NT AUTHORITY\SYSTEM" -Rights "FullControl" -Inheritance $inherit -Propagation $propagation))
    if ($LocalServiceCanWrite) {
        $acl.AddAccessRule((New-AccessRule -Identity "NT AUTHORITY\LOCAL SERVICE" -Rights "Modify" -Inheritance $inherit -Propagation $propagation))
    } else {
        $acl.AddAccessRule((New-AccessRule -Identity "NT AUTHORITY\LOCAL SERVICE" -Rights "ReadAndExecute" -Inheritance $inherit -Propagation $propagation))
    }
    Set-Acl -LiteralPath $PathValue -AclObject $acl
}

try {
    $rootPath = Resolve-RequiredPath -PathValue $WindowsInstallRoot -Label "WindowsInstallRoot"
    $Report.windows_install_root = $rootPath

    $admin = Test-IsAdministrator
    if (-not $admin) {
        if ($DryRun) {
            Add-Warning "Administrator rights are required for real file installation; dry-run did not modify the host."
        } else {
            throw "Administrator rights are required to install OpenAssetWatch files."
        }
    }
    Add-Check -Name "administrator check" -Ok ($admin -or [bool]$DryRun) -Message "Administrator check passed for the selected mode."

    $staged = Assert-StagedLayout -Root $rootPath
    Assert-ExampleJson -ConfigExample $staged.config_example -IdentityExample $staged.identity_example
    Add-Check -Name "staged layout" -Ok $true -Message "Staged binary, examples, service metadata, and manifest exist."

    Assert-NoRealConfigOverwrite
    Add-Action "Create $ProgramFilesBinRoot."
    Add-Action "Copy staged oaw-agent.exe to $ProgramFilesBinary."
    Add-Action "Create ProgramData config, identity, state, and logs directories."
    Add-Action "Copy config.example.json and identity.example.json only."
    Add-Action "Preserve config.json and identity.json if present."

    Add-AclExpectation "Program Files agent directory is not writable by LocalService."
    Add-AclExpectation "Program Files agent binary is readable and executable by LocalService."
    Add-AclExpectation "ProgramData config and identity directories are administrator-controlled."
    Add-AclExpectation "LocalService has read access to config and identity examples."
    Add-AclExpectation "ProgramData state and logs allow LocalService write access."
    Add-AclExpectation "Administrators and SYSTEM retain full control."
    Add-AclExpectation "No broad Everyone or Users write access is granted."

    if (-not $DryRun) {
        New-Item -ItemType Directory -Force -Path $ProgramFilesBinRoot | Out-Null
        Copy-Item -LiteralPath $staged.binary -Destination $ProgramFilesBinary -Force

        foreach ($dir in @($ProgramDataConfigRoot, $ProgramDataIdentityRoot, $ProgramDataStateRoot, $ProgramDataLogsRoot)) {
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
        }

        Copy-Item -LiteralPath $staged.config_example -Destination (Join-Path $ProgramDataConfigRoot "config.example.json") -Force
        Copy-Item -LiteralPath $staged.identity_example -Destination (Join-Path $ProgramDataIdentityRoot "identity.example.json") -Force

        Set-DirectoryAcl -PathValue $ProgramFilesAgentRoot -LocalServiceCanWrite $false
        Set-DirectoryAcl -PathValue $ProgramDataConfigRoot -LocalServiceCanWrite $false
        Set-DirectoryAcl -PathValue $ProgramDataIdentityRoot -LocalServiceCanWrite $false
        Set-DirectoryAcl -PathValue $ProgramDataStateRoot -LocalServiceCanWrite $true
        Set-DirectoryAcl -PathValue $ProgramDataLogsRoot -LocalServiceCanWrite $true
    }
} catch {
    Add-Check -Name "windows file install helper" -Ok $false -Message $_.Exception.Message
}

$Report.ok = ($Report.errors.Count -eq 0)
$Report | ConvertTo-Json -Depth 8
if ($Report.ok) {
    exit 0
}
exit 1
