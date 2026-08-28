param(
    [Parameter(Mandatory = $true)]
    [string]$Msi
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$ExpectedServiceSid = "S-1-5-80-630466807-4251148593-2853048944-3410275790-4186592652"
$ExpectedSddl = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;$ExpectedServiceSid)"

function Get-RecordValues {
    param(
        [Parameter(Mandatory = $true)]$Database,
        [Parameter(Mandatory = $true)][string]$Query,
        [Parameter(Mandatory = $true)][string[]]$FieldTypes
    )

    $view = $Database.OpenView($Query)
    try {
        $null = $view.Execute()
        $record = $view.Fetch()
        if ($null -eq $record) {
            throw "Expected MSI table row is missing."
        }
        $values = [System.Collections.Generic.List[object]]::new()
        for ($index = 0; $index -lt $FieldTypes.Count; $index++) {
            if ($FieldTypes[$index] -eq "integer") {
                $values.Add($record.IntegerData($index + 1))
            }
            else {
                $values.Add($record.StringData($index + 1))
            }
        }
        return [pscustomobject]@{ Values = $values.ToArray() }
    }
    finally {
        $null = $view.Close()
    }
}

$stage = "input"
try {
    $msiPath = (Resolve-Path -LiteralPath $Msi).Path
    if ([System.IO.Path]::GetExtension($msiPath) -ne ".msi") {
        throw "MSI table validation requires an MSI artifact."
    }

    $stage = "open_database"
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.OpenDatabase($msiPath, 0)

    $stage = "custom_action"
    $customAction = Get-RecordValues -Database $database -Query (
        'SELECT `Action`,`Type`,`Source`,`Target` FROM `CustomAction` ' +
        'WHERE `Action`=''RepairPrivateStateAcl'''
    ) -FieldTypes @("string", "integer", "string", "string")
	$action = $customAction.Values[0]
    $stage = "custom_action_type"
    $actionType = [int]$customAction.Values[1]
	$actionSource = $customAction.Values[2]
	$actionTarget = $customAction.Values[3]

	$stage = "repair_sequence"
    $repairSequenceRecord = Get-RecordValues -Database $database -Query (
        'SELECT `Condition`,`Sequence` FROM `InstallExecuteSequence` ' +
        'WHERE `Action`=''RepairPrivateStateAcl'''
    ) -FieldTypes @("string", "integer")
    $repairCondition = $repairSequenceRecord.Values[0]
    $stage = "repair_sequence_value"
    $repairSequence = [int]$repairSequenceRecord.Values[1]

    $stage = "secure_objects_sequence"
    $secureObjectsSequenceRecord = Get-RecordValues -Database $database -Query (
        'SELECT `Sequence` FROM `InstallExecuteSequence` ' +
        'WHERE `Action`=''Wix4SchedSecureObjects_X64'''
    ) -FieldTypes @("integer")
    $stage = "secure_objects_sequence_value"
    $secureObjectsSequence = [int]$secureObjectsSequenceRecord.Values[0]

    $stage = "service_sequence"
    $startSequenceRecord = Get-RecordValues -Database $database -Query (
        'SELECT `Sequence` FROM `InstallExecuteSequence` WHERE `Action`=''StartServices'''
    ) -FieldTypes @("integer")
    $stage = "service_sequence_value"
    $startSequence = [int]$startSequenceRecord.Values[0]

	$stage = "credential_directory"
    $directoryRecord = Get-RecordValues -Database $database -Query (
        'SELECT `Directory` FROM `Directory` WHERE `Directory`=''AgentCredentialDir'''
    ) -FieldTypes @("string")
    $credentialDirectory = $directoryRecord.Values[0]

    $stage = "credential_acl"
    $aclRecord = Get-RecordValues -Database $database -Query (
        'SELECT `LockObject`,`Table`,`SDDLText` FROM `MsiLockPermissionsEx` ' +
        'WHERE `LockObject`=''AgentCredentialDir'''
    ) -FieldTypes @("string", "string", "string")
    $aclObject = $aclRecord.Values[0]
    $aclTable = $aclRecord.Values[1]
    $aclSddl = $aclRecord.Values[2]

    $stage = "credential_create_folder"
    $createFolderRecord = Get-RecordValues -Database $database -Query (
        'SELECT `Directory_`,`Component_` FROM `CreateFolder` ' +
        'WHERE `Directory_`=''AgentCredentialDir'''
    ) -FieldTypes @("string", "string")
    $createFolderDirectory = $createFolderRecord.Values[0]
    $createFolderComponent = $createFolderRecord.Values[1]

    $stage = "credential_component"
    $componentRecord = Get-RecordValues -Database $database -Query (
        'SELECT `Component`,`Directory_` FROM `Component` ' +
        'WHERE `Component`=''AgentCredentialDirectoryComponent'''
    ) -FieldTypes @("string", "string")
    $credentialComponent = $componentRecord.Values[0]
    $componentDirectory = $componentRecord.Values[1]

    $stage = "evaluate"
    $checks = [ordered]@{
        custom_action = $action -eq "RepairPrivateStateAcl"
        argument_free_command = $actionTarget -eq "repair-private-state-acl"
        installed_agent_source = $actionSource -eq "AgentExe"
        deferred = ($actionType -band 0x400) -ne 0
        no_impersonation = ($actionType -band 0x800) -ne 0
        failure_checked = ($actionType -band 0xC0) -eq 0
        repair_condition = $repairCondition -eq 'NOT (REMOVE~="ALL")'
        repair_after_protected_acl = $repairSequence -gt $secureObjectsSequence
        repair_before_service_start = $repairSequence -lt $startSequence
        credential_directory = $credentialDirectory -eq "AgentCredentialDir"
        credential_acl_object = $aclObject -eq "AgentCredentialDir"
        protected_exact_acl = $aclSddl -eq $ExpectedSddl
        credential_create_folder_acl = $aclTable -eq "CreateFolder"
        credential_create_folder = (
            $createFolderDirectory -eq "AgentCredentialDir" -and
            $createFolderComponent -eq "AgentCredentialDirectoryComponent"
        )
        credential_component_binding = (
            $credentialComponent -eq "AgentCredentialDirectoryComponent" -and
            $componentDirectory -eq "AgentCredentialDir"
        )
    }
    $failed = @($checks.GetEnumerator() | Where-Object { -not $_.Value })
    if ($failed.Count -ne 0) {
        [ordered]@{
            ok = $false
            checks = $checks
            error = "Compiled MSI credential-security table validation failed."
        } | ConvertTo-Json -Depth 4
        exit 1
    }

    [ordered]@{
        ok = $true
        checks = $checks
    } | ConvertTo-Json -Depth 4
}
catch {
    [ordered]@{
        ok = $false
        stage = $stage
        exception_type = $_.Exception.GetType().Name
        error_id = $_.FullyQualifiedErrorId
        error = "Compiled MSI credential-security table validation failed."
    } | ConvertTo-Json -Depth 3
    exit 1
}
