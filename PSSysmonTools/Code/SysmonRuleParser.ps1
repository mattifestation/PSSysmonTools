function ConvertFrom-SysmonBinaryConfiguration {
<#
.SYNOPSIS

Parses a binary Sysmon configuration.

.DESCRIPTION

ConvertFrom-SysmonBinaryConfiguration parses a binary Sysmon configuration. The configuration is typically stored in the registry at the following path: HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters\Rules

ConvertFrom-SysmonBinaryConfiguration currently only supports the following schema versions: 3.30, 3.40

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

.PARAMETER RuleBytes

Specifies the raw bytes of a Sysmon configuration from the registry.

.EXAMPLE

[Byte[]] $RuleBytes = Get-ItemPropertyValue -Path HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters -Name Rules
ConvertFrom-SysmonBinaryConfiguration -RuleBytes $RuleBytes

.OUTPUTS

Sysmon.EventGroup

Outputs one or more groupings of Sysmon rules.

.NOTES

ConvertFrom-SysmonBinaryConfiguration is designed to serve as a helper function for Get-SysmonConfiguration.
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [Byte[]]
        [ValidateNotNullOrEmpty()]
        $RuleBytes
    )

    #region Define byte to string mappings. This may change across verions.
    $SupportedSchemaVersions = @(
        [Version] '3.30.0.0',
        [Version] '3.40.0.0',
        [Version] '4.00.0.0'
    )

    $EventConditionMapping = @{
        0 = 'Is'
        1 = 'IsNot'
        2 = 'Contains'
        3 = 'Excludes'
        4 = 'BeginWith'
        5 = 'EndWith'
        6 = 'LessThan'
        7 = 'MoreThan'
        8 = 'Image'
    }

    # The following value to string mappings were all pulled from
    # IDA and will require manual validation with with each new
    # Sysmon and schema version. Here's hoping they don't change often!
    $ProcessCreateMapping = @{
        0 = 'UtcTime'
        1 = 'ProcessGuid'
        2 = 'ProcessId'
        3 = 'Image'
        4 = 'CommandLine'
        5 = 'CurrentDirectory'
        6 = 'User'
        7 = 'LogonGuid'
        8 = 'LogonId'
        9 = 'TerminalSessionId'
        10 = 'IntegrityLevel'
        11 = 'Hashes'
        12 = 'ParentProcessGuid'
        13 = 'ParentProcessId'
        14 = 'ParentImage'
        15 = 'ParentCommandLine'
    }

    $ProcessCreateMapping_4_00 = @{
        0 = 'UtcTime'
        1 = 'ProcessGuid'
        2 = 'ProcessId'
        3 = 'Image'
        4 = 'FileVersion'
        5 = 'Description'
        6 = 'Product'
        7 = 'Company'
        8 = 'CommandLine'
        9 = 'CurrentDirectory'
        10 = 'User'
        11 = 'LogonGuid'
        12 = 'LogonId'
        13 = 'TerminalSessionId'
        14 = 'IntegrityLevel'
        15 = 'Hashes'
        16 = 'ParentProcessGuid'
        17 = 'ParentProcessId'
        18 = 'ParentImage'
        19 = 'ParentCommandLine'
    }

    $FileCreateTimeMapping = @{
        0 = 'UtcTime'
        1 = 'ProcessGuid'
        2 = 'ProcessId'
        3 = 'Image'
        4 = 'TargetFilename'
        5 = 'CreationUtcTime'
        6 = 'PreviousCreationUtcTime'
    }

    $NetworkConnectMapping = @{
        0 = 'UtcTime'
        1 = 'ProcessGuid'
        2 = 'ProcessId'
        3 = 'Image'
        4 = 'User'
        5 = 'Protocol'
        6 = 'Initiated'
        7 = 'SourceIsIpv6'
        8 = 'SourceIp'
        9 = 'SourceHostname'
        10 = 'SourcePort'
        11 = 'SourcePortName'
        12 = 'DestinationIsIpv6'
        13 = 'DestinationIp'
        14 = 'DestinationHostname'
        15 = 'DestinationPort'
        16 = 'DestinationPortName'
    }

    $SysmonServiceStateChangeMapping = @{
        0 = 'UtcTime'
        1 = 'State'
        2 = 'Version'
        3 = 'SchemaVersion'
    }

    $ProcessTerminateMapping = @{
        0 = 'UtcTime'
        1 = 'ProcessGuid'
        2 = 'ProcessId'
        3 = 'Image'
    }

    $DriverLoadMapping = @{
        0 = 'UtcTime'
        1 = 'ImageLoaded'
        2 = 'Hashes'
        3 = 'Signed'
        4 = 'Signature'
        5 = 'SignatureStatus'
    }

    $ImageLoadMapping = @{
        0 = 'UtcTime'
        1 = 'ProcessGuid'
        2 = 'ProcessId'
        3 = 'Image'
        4 = 'ImageLoaded'
        5 = 'Hashes'
        6 = 'Signed'
        7 = 'Signature'
        8 = 'SignatureStatus'
    }

    $ImageLoadMapping_4_00 = @{
        0 = 'UtcTime'
        1 = 'ProcessGuid'
        2 = 'ProcessId'
        3 = 'Image'
        4 = 'ImageLoaded'
        5 = 'FileVersion'
        6 = 'Description'
        7 = 'Product'
        8 = 'Company'
        9 = 'Hashes'
        10 = 'Signed'
        11 = 'Signature'
        12 = 'SignatureStatus'
    }

    $CreateRemoteThreadMapping = @{
        0 = 'UtcTime'
        1 = 'SourceProcessGuid'
        2 = 'SourceProcessId'
        3 = 'SourceImage'
        4 = 'TargetProcessGuid'
        5 = 'TargetProcessId'
        6 = 'TargetImage'
        7 = 'NewThreadId'
        8 = 'StartAddress'
        9 = 'StartModule'
        10 = 'StartFunction'
    }

    $RawAccessReadMapping = @{
        0 = 'UtcTime'
        1 = 'ProcessGuid'
        2 = 'ProcessId'
        3 = 'Image'
        4 = 'Device'
    }

    $ProcessAccessMapping = @{
        0 = 'UtcTime'
        1 = 'SourceProcessGUID'
        2 = 'SourceProcessId'
        3 = 'SourceThreadId'
        4 = 'SourceImage'
        5 = 'TargetProcessGUID'
        6 = 'TargetProcessId'
        7 = 'TargetImage'
        8 = 'GrantedAccess'
        9 = 'CallTrace'
    }

    $FileCreateMapping = @{
        0 = 'UtcTime'
        1 = 'ProcessGuid'
        2 = 'ProcessId'
        3 = 'Image'
        4 = 'TargetFilename'
        5 = 'CreationUtcTime'
    }

    $RegistryEventCreateKeyMapping = @{
        0 = 'EventType'
        1 = 'UtcTime'
        2 = 'ProcessGuid'
        3 = 'ProcessId'
        4 = 'Image'
        5 = 'TargetObject'
    }

    $RegistryEventSetValueMapping = @{
        0 = 'EventType'
        1 = 'UtcTime'
        2 = 'ProcessGuid'
        3 = 'ProcessId'
        4 = 'Image'
        5 = 'TargetObject'
        6 = 'Details'
    }

    $RegistryEventDeleteKeyMapping = @{
        0 = 'EventType'
        1 = 'UtcTime'
        2 = 'ProcessGuid'
        3 = 'ProcessId'
        4 = 'Image'
        5 = 'TargetObject'
        6 = 'NewName'
    }

    $FileCreateStreamHashMapping = @{
        0 = 'UtcTime'
        1 = 'ProcessGuid'
        2 = 'ProcessId'
        3 = 'Image'
        4 = 'TargetFilename'
        5 = 'CreationUtcTime'
        6 = 'Hash'
    }

    $SysmonConfigurationChangeMapping = @{
        0 = 'UtcTime'
        1 = 'Configuration'
        2 = 'ConfigurationFileHash'
    }

    $PipeEventCreatedMapping = @{
        0 = 'UtcTime'
        1 = 'ProcessGuid'
        2 = 'ProcessId'
        3 = 'PipeName'
        4 = 'Image'
    }

    $PipeEventConnectedMapping = @{
        0 = 'UtcTime'
        1 = 'ProcessGuid'
        2 = 'ProcessId'
        3 = 'PipeName'
        4 = 'Image'
    }

    $WmiEventFilterMapping = @{
        0 = 'EventType'
        1 = 'UtcTime'
        2 = 'Operation'
        3 = 'User'
        4 = 'EventNamespace'
        5 = 'Name'
        6 = 'Query'
    }

    $WmiEventConsumerMapping = @{
        0 = 'EventType'
        1 = 'UtcTime'
        2 = 'Operation'
        3 = 'User'
        4 = 'Name'
        5 = 'Type'
        6 = 'Destination'
    }

    $WmiEventConsumerToFilterMapping = @{
        0 = 'EventType'
        1 = 'UtcTime'
        2 = 'Operation'
        3 = 'User'
        4 = 'Consumer'
        5 = 'Filter'
    }

    $EventTypeMapping = @{
        1  = @('ProcessCreate', $ProcessCreateMapping)
        2  = @('FileCreateTime', $FileCreateTimeMapping)
        3  = @('NetworkConnect', $NetworkConnectMapping)
        # SysmonServiceStateChange is not actually present in the schema. It is here for the sake of completeness.
        4  = @('SysmonServiceStateChange', $SysmonServiceStateChangeMapping)
        5  = @('ProcessTerminate', $ProcessTerminateMapping)
        6  = @('DriverLoad', $DriverLoadMapping)
        7  = @('ImageLoad', $ImageLoadMapping)
        8  = @('CreateRemoteThread', $CreateRemoteThreadMapping)
        9  = @('RawAccessRead', $RawAccessReadMapping)
        10 = @('ProcessAccess', $ProcessAccessMapping)
        11 = @('FileCreate', $FileCreateMapping)
        12 = @('RegistryEventCreateKey', $RegistryEventCreateKeyMapping)
        13 = @('RegistryEventSetValue', $RegistryEventSetValueMapping)
        14 = @('RegistryEventDeleteKey', $RegistryEventDeleteKeyMapping)
        15 = @('FileCreateStreamHash', $FileCreateStreamHashMapping)
        # SysmonConfigurationChange is not actually present in the schema. It is here for the sake of completeness.
        16 = @('SysmonConfigurationChange', $SysmonConfigurationChangeMapping)
        17 = @('PipeEventCreated', $PipeEventCreatedMapping)
        18 = @('PipeEventConnected', $PipeEventConnectedMapping)
        19 = @('WmiEventFilter', $WmiEventFilterMapping)
        20 = @('WmiEventConsumer', $WmiEventConsumerMapping)
        21 = @('WmiEventConsumerToFilter', $WmiEventConsumerToFilterMapping)
    }
    #endregion

    $RuleMemoryStream = New-Object -TypeName System.IO.MemoryStream -ArgumentList @(,$RuleBytes)

    $RuleReader = New-Object -TypeName System.IO.BinaryReader -ArgumentList $RuleMemoryStream

    # I'm noting here for the record that parsing could be slightly more robust to account for malformed
    # rule blobs. I'm writing this in my spare time so I likely won't put too much work into increased
    # parsing robustness.

    if ($RuleBytes.Count -lt 16) {
        $RuleReader.Dispose()
        $RuleMemoryStream.Dispose()
        throw 'Insufficient length to contain a Sysmon rule header.'
    }

    # This value should be either 0 or 1. 1 should be expected for a current Sysmon config.
    # A value of 1 indicates that offset 8 will contain the file offset to the first rule grouping.
    # A value of 0 should indicate that offset 8 will be the start of the first rule grouping.
    # Currently, I am just going to check that the value is 1 and throw an exception if it's not.
    $HeaderValue0 = $RuleReader.ReadUInt16()

    if ($HeaderValue0 -ne 1) {
        $RuleReader.Dispose()
        $RuleMemoryStream.Dispose()
        throw "Incorrect header value at offset 0x00. Expected: 1. Actual: $HeaderValue0"
    }

    # This value is expected to be 1. Any other value will indicate the presence of a "registry rule version"
    # that is incompatible with the current Sysmon schema version. A value other than 1 likely indicates the
    # presence of an old version of Sysmon. Any value besides 1 will not be supported in this script.
    $HeaderValue1 = $RuleReader.ReadUInt16()

    if ($HeaderValue1 -ne 1) {
        $RuleReader.Dispose()
        $RuleMemoryStream.Dispose()
        throw "Incorrect header value at offset 0x02. Expected: 1. Actual: $HeaderValue1"
    }

    $RuleGroupCount = $RuleReader.ReadUInt32()
    $RuleGroupBeginOffset = $RuleReader.ReadUInt32()

    $SchemaVersionMinor = $RuleReader.ReadUInt16()
    $SchemaVersionMajor = $RuleReader.ReadUInt16()

    $SchemaVersion = New-Object -TypeName System.Version -ArgumentList $SchemaVersionMajor, $SchemaVersionMinor, 0, 0

    Write-Verbose "Obtained the following schema version: $($SchemaVersion.ToString(2))"

    if (-not ($SupportedSchemaVersions -contains $SchemaVersion)) {
        $RuleReader.Dispose()
        $RuleMemoryStream.Dispose()
        throw "Unsupported schema version: $($SchemaVersion.ToString(2)). Schema version must be at least $($MinimumSupportedSchemaVersion.ToString(2))"
    }

    #region Perform offset updates depending upon the schema version here
    # This logic should be the first candidate for refactoring should the schema change drastically in the future.
    switch ($SchemaVersion.ToString(2)) {
        '4.0' {
            Write-Verbose 'Using schema version 4.00 updated offsets.'
            # ProcessCreate and ImageLoad values changed
            $EventTypeMapping[1][1] = $ProcessCreateMapping_4_00
            $EventTypeMapping[7][1] = $ImageLoadMapping_4_00
        }
    }
    #endregion

    $null = $RuleReader.BaseStream.Seek($RuleGroupBeginOffset, 'Begin')

    $EventCollection = for ($i = 0; $i -lt $RuleGroupCount; $i++) {
        $EventTypeValue = $RuleReader.ReadInt32()
        $EventType = $EventTypeMapping[$EventTypeValue][0]
        $EventTypeRuleTypes = $EventTypeMapping[$EventTypeValue][1]
        $OnMatchValue = $RuleReader.ReadInt32()

        $OnMatch = $null

        switch ($OnMatchValue) {
            0 { $OnMatch = 'Exclude' }
            1 { $OnMatch = 'Include' }
            default { $OnMatch = '?' }
        }

        $NextEventTypeOffset = $RuleReader.ReadInt32()
        $RuleCount = $RuleReader.ReadInt32()
        [PSObject[]] $Rules = New-Object -TypeName PSObject[]($RuleCount)

        # Parse individual rules here
        for ($j = 0; $j -lt $RuleCount; $j++) {
            $RuleType = $EventTypeRuleTypes[$RuleReader.ReadInt32()]
            $Filter = $EventConditionMapping[$RuleReader.ReadInt32()]
            $NextRuleOffset = $RuleReader.ReadInt32()
            $RuleTextLength = $RuleReader.ReadInt32()
            $RuleTextBytes = $RuleReader.ReadBytes($RuleTextLength)
            $RuleText = [Text.Encoding]::Unicode.GetString($RuleTextBytes).TrimEnd("`0")

            $Rules[$j] = [PSCustomObject] @{
                PSTypeName = 'Sysmon.Rule'
                RuleType = $RuleType
                Filter = $Filter
                RuleText = $RuleText
            }

            $null = $RuleReader.BaseStream.Seek($NextRuleOffset, 'Begin')
        }

        [PSCustomObject] @{
            PSTypeName = 'Sysmon.EventGroup'
            EventType = $EventType
            OnMatch = $OnMatch
            Rules = $Rules
        }

        $null = $RuleReader.BaseStream.Seek($NextEventTypeOffset, 'Begin')
    }

    $RuleReader.Dispose()
    $RuleMemoryStream.Dispose()

    # Calculate the hash of the binary rule blob
    $SHA256Hasher = New-Object -TypeName System.Security.Cryptography.SHA256CryptoServiceProvider
    $ConfigBlobSHA256Hash = ($SHA256Hasher.ComputeHash($RuleBytes) | ForEach-Object { $_.ToString('X2') }) -join ''

    [PSCustomObject] @{
        PSTypeName = 'Sysmon.EventCollection'
        SchemaVersion = $SchemaVersion
        ConfigBlobSHA256Hash = $ConfigBlobSHA256Hash
        Events = $EventCollection
    }
}

function Get-SysmonConfiguration {
<#
.SYNOPSIS

Parses a Sysmon driver configuration from the registry. Output is nearly identical to that of "sysmon.exe -c" but without the requirement to run sysmon.exe.

.DESCRIPTION

Get-SysmonConfiguration parses a Sysmon configuration from the registry without the need to run "sysmon.exe -c". This function is designed to enable Sysmon configuration auditing at scale as well as reconnaissance for red teamers. 

Get-SysmonConfiguration has been tested with the following Sysmon versions: 6.20

Due to the admin-only ACL set on the Sysmon driver registry key, Get-SysmonConfiguration will typically need to run in an elevated context. Because the user-mode service and driver names can be changed, Get-SysmonConfiguration will locate the service and driver regardless of their names.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

Required Dependencies: ConvertFrom-SysmonBinaryConfiguration

.PARAMETER MatchExeOutput

Mirrors the text output of "sysmon.exe -c". This parameter was implemented primarily to enable testing scenarios - i.e. to ensure that the output matches that of the version of Sysmon (or schema) being tested against.

.EXAMPLE

Get-SysmonConfiguration

.EXAMPLE

Get-SysmonConfiguration -MatchExeOutput

.OUTPUTS

Sysmon.Configuration

Outputs a fully parsed Sysmon configuration including the hash of the registry rule blob for auditing purposes.

System.String

Outputs mirrored output from "sysmon.exe -c".

.NOTES

Get-SysmonConfiguration will have to be manually validated for each new Sysmon and configuration schema version. Please report all bugs and indiscrepencies with new versions by supplying the following information:

1) The Sysmon config XML that's generating the error (only schema versions 3.30 and later).
2) The version of Sysmon being used (only 6.20 and later).
#>

    [OutputType('Sysmon.Configuration', ParameterSetName = 'PSOutput')]
    [OutputType([String], ParameterSetName = 'ExeOutput')]
    [CmdletBinding(DefaultParameterSetName = 'PSOutput')]
    param (
        [Parameter(ParameterSetName = 'ExeOutput')]
        [Switch]
        $MatchExeOutput
    )

    # Find the Sysmon driver based solely off the presence of the "Rules" value.
    # This is being done because the user can optionally specify a driver name other than the default: SysmonDrv
    $ServiceParameters = Get-ChildItem -Path HKLM:\SYSTEM\CurrentControlSet\Services -Recurse -Include 'Parameters' -ErrorAction SilentlyContinue
    $DriverParameters = $ServiceParameters | Where-Object { $_.Property -contains 'Rules' }

    if (-not $DriverParameters) {
        Write-Error 'Unable to locate a Sysmon driver. Either it is not installed or you do not have permissions to read the driver configuration in the registry.'
        return
    }

    $FoundSysmonMatch = $False
    $SysmonDriverName = $null
    $SysmonServiceName = $null
    $SysmonDriverParams = $null

    # Just in case there is more than one instance where there is a "Rules" value, correlate it with the user-mode service to confirm.
    $DriverParameters | ForEach-Object {
        $CandidateDriverName = $_.PSParentPath.Split('\')[-1]
        $CandidateDriverParams = $_

        $CandidateUserModeServices = $ServiceParameters | Where-Object { $_.Property -contains 'DriverName' }

        if (-not $CandidateUserModeServices) {
            Write-Error 'Unable to locate a user-mode Sysmon service.'
            return
        }

        $CandidateUserModeServices | ForEach-Object {
            $CandidateServiceName = $_.PSParentPath.Split('\')[-1]
            $DriverName = ($_ | Get-ItemProperty).DriverName

            # We have a matching user-mode Sysmon service and Sysmon driver.
            if ($DriverName -eq $CandidateDriverName) {
                $FoundSysmonMatch = $True
                $SysmonDriverName = $CandidateDriverName
                $SysmonServiceName = $CandidateServiceName
                $SysmonDriverParams = $CandidateDriverParams | Get-ItemProperty
            }
        }
    }

    if ($FoundSysmonMatch) {
        # HKLM\SYSTEM\CurrentControlSet\Services\<SYSMON_DRIVER_NAME>\Parameters
        $RuleBytes = $SysmonDriverParams.Rules                        # REG_BINARY
        $Options = $SysmonDriverParams.Options                        # REG_DWORD
        $HashingAlgorithmValue = $SysmonDriverParams.HashingAlgorithm # REG_DWORD
        $ProcessAccessMasks = $SysmonDriverParams.ProcessAccessMasks  # REG_BINARY - No larger than size: 0x28 (0x28 / 4 == 10: unique masks to interpret alongside ProcessAccessNames)
        $ProcessAccessNames = $SysmonDriverParams.ProcessAccessNames  # REG_MULTI_SZ - Can have no more than 10 entries
        $CheckRevocation = $SysmonDriverParams.CheckRevocation        # REG_BINARY of size: 1 byte

        # The high-order bit of HashingAlgorithm must be set to 1 (i.e. 0x80000000)
        $HashingAlgorithms = if ($HashingAlgorithmValue) {
            if ($HashingAlgorithmValue -band 1) { 'SHA1' }
            if ($HashingAlgorithmValue -band 2) { 'MD5' }
            if ($HashingAlgorithmValue -band 4) { 'SHA256' }
            if ($HashingAlgorithmValue -band 8) { 'IMPHASH' }
        }

        $NetworkConnection = $False
        if ($Options -band 1) { $NetworkConnection = $True }

        $ImageLoading = $False
        if ($Options -band 2) { $ImageLoading = $True }

        $CRLChecking = $False
        if (($CheckRevocation.Count -gt 0) -and ($CheckRevocation[0] -eq 1)) { $CRLChecking = $True }

        # Parse the binary rules blob.
        $Rules = ConvertFrom-SysmonBinaryConfiguration -RuleBytes $RuleBytes

        $ProcessAccess = $False
        if ($Rules.Events.EventType -contains 'ProcessAccess') { $ProcessAccess = $True }

        # Process ProcessAccessNames and ProcessAccessMasks.
        # The code path to actually use these appears to be a dead one now.
        # I'm only parsing this to mirror Sysmon 6.20 supporting parsing.
        $ProcessAccessList = New-Object -TypeName PSObject[]($ProcessAccessNames.Count)
        for ($i = 0; $i -lt $ProcessAccessNames.Count; $i++) {
            $ProcessAccessList[$i] = [PSCustomObject] @{
                ProcessName = $ProcessAccessNames[$i]
                AccessMask = [BitConverter]::ToInt32($ProcessAccessMasks, $i * 4)
            }
        }

        $Properties = [Ordered] @{
            PSTypeName = 'Sysmon.Configuration'
            ServiceName = $SysmonServiceName
            DriverName = $SysmonDriverName
            HashingAlgorithms = $HashingAlgorithms
            NetworkConnectionEnabled = $NetworkConnection
            ImageLoadingEnabled = $ImageLoading
            CRLCheckingEnabled = $CRLChecking
            ProcessAccessEnabled = $ProcessAccess
            ProcessAccess = $ProcessAccessList
            SchemaVersion = $Rules.SchemaVersion.ToString(2)
            ConfigBlobSHA256Hash = $Rules.ConfigBlobSHA256Hash
            Rules = $Rules.Events
        }

        # Don't print the ProcessAccess property if it's not populated. With Sysmon 6.20, this
        # should never be present anyway unless there's a stale artifact from an older version.
        if ($ProcessAccessList.Count -eq 0) { $Properties.Remove('ProcessAccess') }

        if ($MatchExeOutput) {
        
            $NetworkConnectionString = if ($NetworkConnection) { 'enabled' } else { 'disabled' }
            $ImageLoadingString = if ($ImageLoading) { 'enabled' } else { 'disabled' }
            $CRLCheckingString = if ($CRLChecking) { 'enabled' } else { 'disabled' }
            $ProcessAccessString = if ($ProcessAccess) { 'enabled' } else { 'disabled' }
            if ($ProcessAccessList) {
                $ProcessAccessString = ($ProcessAccessList | ForEach-Object { "`"$($_.ProcessName)`":0x$($_.AccessMask.ToString('x'))" }) -join ','
            }

            $AllRuleText = $Rules.Events | ForEach-Object {
                # Dumb hacks to format output to the original "sysmon.exe -c" output
                $EventType = $_.EventType
                if ($EventType.StartsWith('RegistryEvent')) { $EventType = 'RegistryEvent' }
                if ($EventType.StartsWith('WmiEvent')) { $EventType = 'WmiEvent' }
                if ($EventType.StartsWith('PipeEvent')) { $EventType = 'PipeEvent' }

                $RuleText = $_.Rules | ForEach-Object {
                    $FilterText = switch ($_.Filter) {
                        'Is' { 'is' }
                        'IsNot' { 'is not' }
                        'Contains' { 'contains' }
                        'Excludes' { 'excludes' }
                        'BeginWith' { 'begin with' }
                        'EndWith' { 'end with' }
                        'LessThan' { 'less than' }
                        'MoreThan' { 'more than' }
                        'Image' { 'image' }
                    }

                    "`t{0,-30} filter: {1,-12} value: '{2}'" -f $_.RuleType, $FilterText, $_.RuleText
                }

                $RuleSet =  @"
 - {0,-34} onmatch: {1}
{2}
"@ -f $EventType,
      $_.OnMatch.ToLower(),
      ($RuleText | Out-String).TrimEnd("`r`n")

                $RuleSet.TrimEnd("`r`n")
            }


            $ConfigOutput = @"
Current configuration:
{0,-34}{1}
{2,-34}{3}
{4,-34}{5}
{6,-34}{7}
{8,-34}{9}
{10,-34}{11}
{12,-34}{13}

Rule configuration (version {14}):
{15}
"@ -f ' - Service name:',
      $SysmonServiceName,
      ' - Driver name:',
      $SysmonDriverName,
      ' - HashingAlgorithms:',
      ($HashingAlgorithms -join ','),
      ' - Network connection:',
      $NetworkConnectionString,
      ' - Image loading:',
      $ImageLoadingString,
      ' - CRL checking:',
      $CRLCheckingString,
      ' - Process Access:',
      $ProcessAccessString,
      "$($Rules.SchemaVersion.Major).$($Rules.SchemaVersion.Minor.ToString().PadRight(2, '0'))",
      ($AllRuleText | Out-String).TrimEnd("`r`n")

            $ConfigOutput
        } else {
            [PSCustomObject] $Properties
        }
    } else {
        Write-Error 'Unable to locate a Sysmon driver and user-mode service.'
    }
}

function ConvertTo-SysmonXMLConfiguration {
<#
.SYNOPSIS

Recovers a Sysmon XML configuration from a binary configuration.

.DESCRIPTION

ConvertTo-SysmonXMLConfiguration takes the parsed output from Get-SysmonConfiguration and converts it to an XML configuration. This function is useful for recovering lost Sysmon configurations or for performing reconnaisance.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

Required Dependencies: Get-SysmonConfiguration
                       GeneratedCode.ps1

.PARAMETER Configuration

Specifies the parsed Sysmon configuration output from Get-SysmonConfiguration.

.EXAMPLE

Get-SysmonConfiguration | ConvertTo-SysmonXMLConfiguration

.EXAMPLE

$Configuration = Get-SysmonConfiguration
ConvertTo-SysmonXMLConfiguration -Configuration $Configuration

.INPUTS

Sysmon.Configuration

ConvertTo-SysmonXMLConfiguration accepts a single result from Get-SysmonConfiguration over the pipeline. Note: it will not accept input from Get-SysmonConfiguration when "-MatchExeOutput" is specified.

.OUTPUTS

System.String

Outputs a Sysmon XML configuration document.
#>

    [OutputType([String])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [PSTypeName('Sysmon.Configuration')]
        $Configuration
    )

    $SchemaVersion = $Configuration.SchemaVersion

    # Get the parsing code for the respective schema.
    # Code injection note: an attacker would be able to influence the schema version used. That would only influence what
    #  non-injectible source code was supplied to Add-Type, however. $ConfigurationSchemaSource variables should always be
    #  constant variables with script (i.e. module) scope.
    $SchemaSource = Get-Variable -Name "SysmonConfigSchemaSource_$($SchemaVersion.Replace('.', '_'))" -Scope Script -ValueOnly
    
    # Compile the parsing code
    Add-Type -TypeDefinition $SchemaSource -ReferencedAssemblies 'System.Xml' -ErrorAction Stop

    $NamespaceName = "Sysmon_$($SchemaVersion.Replace('.', '_'))"

    # Create a base "Sysmon" object. This serves as the root node that will eventually be serialized to XML.
    $Sysmon = New-Object -TypeName "$NamespaceName.Sysmon"

    $Sysmon.schemaversion = $Configuration.SchemaVersion

    if ($Configuration.CRLCheckingEnabled) { $Sysmon.CheckRevocation = New-Object -TypeName "$NamespaceName.SysmonCheckRevocation" }

    # The hashing algorithms need to be lower case in the XML config.
    $Sysmon.HashAlgorithms = ($Configuration.HashingAlgorithms | ForEach-Object { $_.ToLower() }) -join ','

    $ProcessAccessString = ($Configuration.ProcessAccess | ForEach-Object { "$($_.ProcessName):0x$($_.AccessMask.ToString('x'))" }) -join ','
    if ($ProcessAccessString) { $Sysmon.ProcessAccessConfig = $ProcessAccessString }

    # Do not consider redundant event types. A well-formed binary Sysmon rule blob will have
    # identical RegistryEvent, PipeEvent, and WmiEvent rule entries as of config schema version 3.4[0]
    $EventTypesToExclude = @(
        'RegistryEventSetValue',
        'RegistryEventDeleteKey',
        'PipeEventConnected',
        'WmiEventConsumer',
        'WmiEventConsumerToFilter'
    )

    # Group rules by their respective event types - a requirement for
    # setting properties properly in the SysmonEventFiltering instance.
    $EventGrouping = $Configuration.Rules |
        Where-Object { -not ($EventTypesToExclude -contains $_.EventType) } |
            Group-Object -Property EventType

    # A configuration can technically not have any EventFiltering rules.
    if ($EventGrouping) {
        $Sysmon.EventFiltering = New-Object -TypeName "$NamespaceName.SysmonEventFiltering"

        foreach ($Event in $EventGrouping) {
            # The name of the event - e.g. ProcessCreate, FileCreate, etc.
            $EventName = $Event.Name

            # Normalize these event names.
            # Have a mentioned that I hate that these aren't unique names in Sysmon?
            switch ($EventName) {
                'RegistryEventCreateKey' { $EventName = 'RegistryEvent' }
                'PipeEventCreated' { $EventName = 'PipeEvent' }
                'WmiEventFilter' { $EventName = 'WmiEvent' }
            }

            if ($Event.Count -gt 2) {
                Write-Error "There is more than two $EventName entries. This should not be possible."
                return
            }

            if (($Event.Count -eq 2) -and ($Event.Group[0].OnMatch -eq $Event.Group[1].OnMatch)) {
                Write-Error "The `"onmatch`" attribute values for the $EventName rules are not `"include`" and `"exclude`". This should not be possible."
                return
            }

            $Events = foreach ($RuleSet in $Event.Group) {
                # The dynamic typing that follows relies upon naming consistency in the schema serialization source code.
                $EventInstance = New-Object -TypeName "$NamespaceName.SysmonEventFiltering$EventName" -Property @{
                    onmatch = $RuleSet.OnMatch.ToLower()
                }

                $RuleDefs = @{}

                foreach ($Rule in $RuleSet.Rules) {
                    $PropertyName = $Rule.RuleType
                    # Since each property can be of a unique type, resolve it accordingly.
                    $PropertyTypeName = ("$NamespaceName.SysmonEventFiltering$EventName" -as [Type]).GetProperty($PropertyName).PropertyType.FullName.TrimEnd('[]')

                    if (-not $RuleDefs.ContainsKey($PropertyName)) {
                        $RuleDefs[$PropertyName] = New-Object -TypeName "Collections.ObjectModel.Collection``1[$PropertyTypeName]"
                    }

                    $RuleInstance = New-Object -TypeName $PropertyTypeName
                    # This needs to be lower case in the XML config.
                    $RuleInstance.condition = $Rule.Filter.ToLower()
                    # An exception is thrown here if the value has a space and it is being cast to an enum type.
                    # Currently, "Protected Process" is the only instance. I'll need to refactor this if more instances arise.
                    if ($Rule.RuleText -eq 'Protected Process') { $RuleInstance.Value = 'ProtectedProcess' } else { $RuleInstance.Value = $Rule.RuleText }

                    $RuleDefs[$PropertyName].Add($RuleInstance)
                }

                # Set the collected rule properties accordingly.
                foreach ($PropertyName in $RuleDefs.Keys) {
                    $EventInstance."$PropertyName" = $RuleDefs[$PropertyName]
                }

                $EventInstance
            }

            $EventPropertyName = $Events[0].GetType().Name.Substring('SysmonEventFiltering'.Length)
            $Sysmon.EventFiltering."$EventPropertyName" = $Events
        }
    }

    $XmlWriter = $null

    try {
        $XmlWriterSetting = New-Object -TypeName Xml.XmlWriterSettings
        # A Sysmon XML config is not expected to have an XML declaration line.
        $XmlWriterSetting.OmitXmlDeclaration = $True
        $XmlWriterSetting.Indent = $True
        # Use two spaces in place of a tab character.
        $XmlWriterSetting.IndentChars = '  '
        # Normalize newlines to CRLF.
        $XmlWriterSetting.NewLineHandling = [Xml.NewLineHandling]::Replace

        $XMlStringBuilder = New-Object -TypeName Text.StringBuilder

        $XmlWriter = [Xml.XmlWriter]::Create($XMlStringBuilder, $XmlWriterSetting)

        $XmlSerializer = New-Object -TypeName Xml.Serialization.XmlSerializer -ArgumentList ("$NamespaceName.Sysmon" -as [Type]), ''
        # This will strip any additional "xmlns" attributes from the root Sysmon element.
        $EmptyNamespaces = New-Object -TypeName Xml.Serialization.XmlSerializerNamespaces
        $EmptyNamespaces.Add('', '')

        $XmlSerializer.Serialize($XmlWriter, $Sysmon, $EmptyNamespaces)
    } catch {
        Write-Error $_
    } finally {
        if ($XmlWriter) { $XmlWriter.Close() }
    }

    $XMlStringBuilder.ToString()
}