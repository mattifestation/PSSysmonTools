$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\.."
$ModuleManifest = "$ModuleRoot\PSSysmonTools.psd1"

Remove-Module [P]SSysmonTools
Import-Module $ModuleManifest -Force -ErrorAction Stop

# Insert check to ensure that these tests are running elevated
$IsRunningElevated = (New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsRunningElevated) {
    throw 'PSSysmonTools tests must run from an elevated PowerShell prompt.'
}

$BinToSchemaVerMapping = @{
    '6.20' = '3.40'
    '7.00' = '4.0'
}

$SysmonBinPath = Join-Path -Path $ModuleRoot -ChildPath 'Tests\SupportedSysmonBinaries'
$SysmonBins = Get-ChildItem "$SysmonBinPath\Sysmon_*.exe"

$SampleConfigPath = Join-Path -Path $ModuleRoot -ChildPath 'Tests\SampleConfigs'
$SampleConfigs = Get-ChildItem "$SampleConfigPath\*.xml"

$StdoutPath = Join-Path -Path $env:TEMP -ChildPath 'stdout.txt'

# Delete any existing stdout.txt files.
Remove-Item -Path $StdoutPath -Force -ErrorAction SilentlyContinue

function Test-SysmonInstalled {
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

    [PSCustomObject] @{
        SysmonInstalled = $FoundSysmonMatch
        ServiceName = $SysmonServiceName
        DriverName = $SysmonDriverName
    }
}

$SysmonInstallStatus = Test-SysmonInstalled

# Before running any tests, ensure that Sysmon is not installed
if ($SysmonInstallStatus.SysmonInstalled) {
    throw @"
A Sysmon service and driver was found. You must manually uninstall the Sysmon service and driver before proceeding with these tests.
Service name: $($SysmonInstallStatus.ServiceName)
Driver name: $($SysmonInstallStatus.DriverName)
"@
}

Describe 'Test-SysmonConfiguration' {
    Context 'parameter validation' {
        It 'should accept -Path' {
            { Test-SysmonConfiguration -Path $SampleConfigs[0].FullName } | Should Not Throw

            $ValidationResult = Test-SysmonConfiguration -Path $SampleConfigs[0].FullName

            $ValidationResult | Should Not BeNullOrEmpty
            $ValidationResult.PSObject.TypeNames[0] | Should BeExactly 'Sysmon.XMLValidationResult'
        }

        It 'should accept pipeline input' {
            { $SampleConfigs | Test-SysmonConfiguration } | Should Not Throw
        }
    }

    Context 'expected behavior' {
        foreach ($SampleConfig in $SampleConfigs) {
            It "should have expected output for the following config: $($SampleConfig.FullName)" {
                $ValidationResult = Test-SysmonConfiguration -Path $SampleConfig.FullName

                $ExpectedVersion = ($SampleConfig.FullName.Split('_')[1..2]) -join '.'

                $ValidationResult.Validated | Should Be $True
                $ValidationResult.SchemaVersion | Should BeExactly $ExpectedVersion
                $ValidationResult.Path | Should BeExactly $SampleConfig.FullName
            }
        }

        It 'should throw an exception upon attempting to parse non XML' {
            { Get-ChildItem "$SampleConfigPath\README.txt" | Test-SysmonConfiguration -ErrorAction Stop } | Should Throw
        }
    }
}

# First validate if an existing instance of Sysmon is installed
$SysmonBins | ForEach-Object {
    $CurrentSysmonVersion = $_.VersionInfo.FileVersion
    $SysmonPath = $_.FullName

    $SchemaVersion = $BinToSchemaVerMapping[$CurrentSysmonVersion]
    $CurrentConfig = $SampleConfigs | ? { $_.Name -eq "Sysmon_$($SchemaVersion.Replace('.', '_'))_Autogenerated.xml" }

    Describe "Sysmon $CurrentSysmonVersion Tests" {
        Context 'service installation' {
            It 'should not have an already installed service/driver' {
                # This would indicate that the last service installation failed to uninstall properly.
                # throw an exception in this case as testing cannot continue under this condition.
                $SysmonInstallStatus = Test-SysmonInstalled

                $SysmonInstallStatus.SysmonInstalled | Should Be $False
            }

            It "should install the service with an autogenerated test schema ($($CurrentConfig.Name))" {
                Start-Process -FilePath $SysmonPath -ArgumentList ('-NoLogo', '-i', $CurrentConfig.FullName) -Wait -RedirectStandardOutput $StdoutPath -NoNewWindow
            
                $StdoutResult = Get-Content $StdoutPath

                Remove-Item -Path $StdoutPath -Force -ErrorAction SilentlyContinue

                $StdoutResult[2] -match 'is already registered' | Should Be $False
                $StdoutResult[2] -match 'installed.' | Should Be $True
                $StdoutResult[3] -match 'installed.' | Should Be $True
            }
        }

        Describe 'Get-SysmonConfiguration' {
            Context 'parameter validation' {
                It 'should accept no arguments' {
                    { Get-SysmonConfiguration } | Should Not Throw

                    $Config = Get-SysmonConfiguration

                    $Config | Should Not BeNullOrEmpty
                    $Config.PSObject.TypeNames[0] | Should BeExactly 'Sysmon.Configuration'
                }

                It 'should accept -MatchExeOutput' {
                    { Get-SysmonConfiguration } | Should Not Throw

                    $Config = Get-SysmonConfiguration -MatchExeOutput

                    $Config | Should Not BeNullOrEmpty
                    $Config -is [String] | Should Be $True
                }
            }

            Context 'expected behavior' {
                It 'match XML config values' {
                    $Config = Get-SysmonConfiguration

                    $Config.ServiceName | Should Not BeNullOrEmpty
                    $Config.DriverName | Should Not BeNullOrEmpty
                    $Config.HashingAlgorithms | Should Not BeNullOrEmpty
                    $Config.NetworkConnectionEnabled | Should Be $True
                    $Config.ImageLoadingEnabled | Should Be $True
                    $Config.CRLCheckingEnabled | Should Be $True
                    $Config.ProcessAccessEnabled | Should Be $True
                    $Config.ProcessAccess | Should Not BeNullOrEmpty
                    $Config.SchemaVersion | Should BeExactly $SchemaVersion
                    $Config.ConfigBlobSHA256Hash | Should Not BeNullOrEmpty
                    $Config.Rules | Should Not BeNullOrEmpty
                }

                # This is the primary way in which all populated properties of Get-SysmonConfiguration are validated against sysmon.exe
                # This test is a little time-consuming because "sysmon.exe -c" takes a while to complete.
                It 'should match the output of "sysmon.exe -c" when -MatchExeOutput is supplied' {
                    Start-Process -FilePath $SysmonPath -ArgumentList ('-NoLogo', '-c') -Wait -RedirectStandardOutput $StdoutPath -NoNewWindow
            
                    $StdoutResult = Get-Content -Path $StdoutPath -Raw

                    Remove-Item -Path $StdoutPath -Force -ErrorAction SilentlyContinue

                    $OutputPath = Join-Path -Path $env:TEMP -ChildPath Result.txt

                    # Save the output to a file and then read the contents back. This will make string comparison easier.
                    Get-SysmonConfiguration -MatchExeOutput | Out-File -FilePath $OutputPath -Encoding ascii
                    $ConfigText = Get-Content -Path $OutputPath -Raw

                    Remove-Item -Path $OutputPath -Force -ErrorAction SilentlyContinue

                    $StdoutResult | Should Not BeNullOrEmpty
                    $ConfigText | Should Not BeNullOrEmpty
                    $ConfigText | Should BeExactly $StdoutResult
                }
            }
        }

        Describe 'ConvertTo-SysmonXMLConfiguration' {
            Context 'parameter validation' {
                It 'should accept -Configuration' {
                    { Get-SysmonConfiguration | ConvertTo-SysmonXMLConfiguration } | Should Not Throw

                    $XMLConfig = Get-SysmonConfiguration | ConvertTo-SysmonXMLConfiguration

                    $XMLConfig | Should Not BeNullOrEmpty
                    $XMLConfig -is [String] | Should Be $True
                }
            }

            Context 'expected behavior' {
                It 'should output valid, parsable XML' {
                    $XMLConfig = Get-SysmonConfiguration | ConvertTo-SysmonXMLConfiguration

                    ([XML] $XMLConfig) -is [System.Xml.XmlDocument] | Should Be $True
                }

                It 'should validate against its respective configuration schema' {
                    $OutputPath = Join-Path -Path $env:TEMP -ChildPath Result.xml

                    Get-SysmonConfiguration | ConvertTo-SysmonXMLConfiguration | Out-File -FilePath $OutputPath -Encoding ascii

                    $ValidationResult = Test-SysmonConfiguration -Path $OutputPath

                    Remove-Item -Path $OutputPath -Force -ErrorAction SilentlyContinue

                    $ValidationResult.Validated | Should Be $True
                    $ValidationResult.SchemaVersion | Should BeExactly $SchemaVersion
                }

                # The autogenerated test was originally the output of ConvertTo-SysmonXMLConfiguration
                # I should validate the the recovered XML is identical to the original XML
                It 'should be identical to the original XML configuration' {
                    $OutputPath = Join-Path -Path $env:TEMP -ChildPath Result.txt

                    Get-SysmonConfiguration | ConvertTo-SysmonXMLConfiguration | Out-File -FilePath $OutputPath -Encoding ascii
                    
                    $RecoveredXMLText = Get-Content -Path $OutputPath -Raw

                    Remove-Item -Path $OutputPath -Force -ErrorAction SilentlyContinue

                    $OriginalXMlText = Get-Content -Path $CurrentConfig -Raw

                    $RecoveredXMLText | Should BeExactly $OriginalXMlText
                }
            }
        }

        Describe 'Merge-SysmonXMLConfiguration' {
            Context 'parameter validation' {
                It 'should accept -Configuration' {
                    { Merge-SysmonXMLConfiguration -ReferencePolicyPath $CurrentConfig.FullName -PolicyToMergePath $CurrentConfig.FullName } | Should Not Throw

                    $MergedXMLConfig = Merge-SysmonXMLConfiguration -ReferencePolicyPath $CurrentConfig.FullName -PolicyToMergePath $CurrentConfig.FullName

                    $MergedXMLConfig | Should Not BeNullOrEmpty
                    $MergedXMLConfig -is [String] | Should Be $True
                    $MergedXMLConfig.Substring(0,25) | Should BeExactly '<!-- Merged Sysmon policy'
                }

                It 'should accept -ExcludeMergeComments' {
                    $MergedXMLConfig = Merge-SysmonXMLConfiguration -ReferencePolicyPath $CurrentConfig.FullName -PolicyToMergePath $CurrentConfig.FullName -ExcludeMergeComments

                    $MergedXMLConfig | Should Not BeNullOrEmpty
                    $MergedXMLConfig -is [String] | Should Be $True
                    $MergedXMLConfig.Substring(0,25) -ne '<!-- Merged Sysmon policy' | Should Be $True
                }
            }

            Context 'expected behavior' {
                It 'should validate as a proper Sysmon configuration' {
                    $OutputPath = Join-Path -Path $env:TEMP -ChildPath Result.txt

                    Merge-SysmonXMLConfiguration -ReferencePolicyPath $CurrentConfig.FullName -PolicyToMergePath $CurrentConfig.FullName | Out-File -FilePath $OutputPath -Encoding ascii

                    $ValidationResult = Test-SysmonConfiguration -Path $OutputPath

                    Remove-Item -Path $OutputPath -Force -ErrorAction SilentlyContinue

                    $ValidationResult.Validated | Should Be $True
                    $ValidationResult.SchemaVersion | Should BeExactly $SchemaVersion
                }
            }
        }

        Context 'service uninstallation' {
            It 'should uninstall the service' {
                Start-Process -FilePath $SysmonPath -ArgumentList ('-NoLogo', '-u') -Wait -RedirectStandardOutput $StdoutPath -NoNewWindow
            
                $StdoutResult = Get-Content $StdoutPath

                Remove-Item -Path $StdoutPath -Force -ErrorAction SilentlyContinue

                $StdoutResult[0] -match 'Sysmon is not installed on this computer.' | Should Be $False
                # The user-mode service should be removed
                $StdoutResult[2] -match 'removed.' | Should Be $True
                # The driver should be removed
                $StdoutResult[5] -match 'removed.' | Should Be $True
            }
        }
    }
}
