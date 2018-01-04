function Merge-SysmonXMLConfiguration {
<#
.SYNOPSIS

Merges one or more Sysmon XML configurations.

.DESCRIPTION

Merge-SysmonXMLConfiguration merges one or more Sysmon XML configurations into a reference policy. Having to merge Sysmon configurations allows you to maintain sets of smaller configs and then selectively merge them based on the specific environment/goals.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

Required Dependencies: Test-SysmonConfiguration
                       GeneratedCode.ps1

.PARAMETER ReferencePolicyPath

Specifies a Sysmon XML configuration into which all other policies will be merged.

.PARAMETER PolicyToMergePath

Specifies one or more Sysmon XML configurations to merge into the reference policy.

.PARAMETER ExcludeMergeComments

Specifies that merge comments should be excluded from the resulting XML.

.EXAMPLE

Merge-SysmonXMLConfiguration -ReferencePolicyPath MasterPolicy.xml -PolicyToMergePath ('policy1.xml', 'policy2.xml')

.EXAMPLE

$PoliciesToMerge = ls .\sysmon_configs\*.xml
Merge-SysmonXMLConfiguration -ReferencePolicyPath MasterPolicy.xml -PolicyToMergePath $PoliciesToMerge

.EXAMPLE

ls .\sysmon_configs\*.xml | Merge-SysmonXMLConfiguration -ReferencePolicyPath MasterPolicy.xml

.INPUTS

System.IO.FileInfo, System.String

Accepts one or more Sysmon confguration XML files over the pipeline.

.OUTPUTS

System.String

Outputs a String consisting of the merged policy.
#>

    [OutputType([System.String])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [String]
        $ReferencePolicyPath,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('FullName')]
        [String[]]
        $PolicyToMergePath,

        [Switch]
        $ExcludeMergeComments
    )

    BEGIN {
        $ReferencePolicyFullPath = Resolve-Path -Path $ReferencePolicyPath

        Write-Verbose "Validating the reference policy XML against the Sysmon rule schema: $ReferencePolicyFullPath"
        $ReferencePolicyValidationResult = Test-SysmonConfiguration -Path $ReferencePolicyFullPath -ErrorAction Stop

        if (-not ($Script:SupportedSchemaVersions -contains $ReferencePolicyValidationResult.SchemaVersion)) {
            Write-Error "The reference policy XML ($ReferencePolicyFullPath) has an unsupported schema version: $($ReferencePolicyValidationResult.SchemaVersion). Supported schema versions are: $($Script:SupportedSchemaVersions -join ', ')"
            return
        }

        # Get the parsing code for the respective schema.
        # Code injection note: an attacker would be able to influence the schema version used. That would only influence what
        #  non-injectible source code was supplied to Add-Type, however. $ConfigurationSchemaSource variables should always be
        #  constant variables with script (i.e. module) scope.
        $SchemaSource = Get-Variable -Name "SysmonConfigSchemaSource_$($ReferencePolicyValidationResult.SchemaVersion.Replace('.', '_'))" -Scope Script -ValueOnly
    
        # Compile the parsing code
        Add-Type -TypeDefinition $SchemaSource -ReferencedAssemblies 'System.Xml' -ErrorAction Stop

        $NamespaceName = "Sysmon_$($ReferencePolicyValidationResult.SchemaVersion.Replace('.', '_'))"

        # This will be used to deserialize all of the XML configs and to serialize the merged config.
        $XmlSerializer = New-Object -TypeName Xml.Serialization.XmlSerializer -ArgumentList ("$NamespaceName.Sysmon" -as [Type]), ''

        $XMLReader = New-Object -TypeName Xml.XmlTextReader -ArgumentList $ReferencePolicyFullPath

        $ReferenceSysmon = $XmlSerializer.Deserialize($XMLReader) -as "$NamespaceName.Sysmon"

        $XMLReader.Close()

        # Collect each property name implemented by the SysmonEventFiltering type - e.g. ProcessCreate, RegistryEvent, etc.
        $EventFilteringProperties = ("$NamespaceName.SysmonEventFiltering" -as [Type]).GetProperties().Name

        # Sysmon objects will be deserialized for each XML policy.
        $SysmonList = New-Object -TypeName "Collections.ObjectModel.Collection``1[$NamespaceName.Sysmon]"

        # It's possible that there is no EnvetFiltering instance in the reference policy - e.g. if merging with a blank policy.
        if ($null -eq $ReferenceSysmon.EventFiltering) { $ReferenceSysmon.EventFiltering = New-Object -TypeName "$NamespaceName.SysmonEventFiltering" }

        $SysmonList.Add($ReferenceSysmon)

        $CommentList = New-Object -TypeName "Collections.ObjectModel.Collection``1[System.String]"
        $LongestPathLength = $ReferencePolicyFullPath.Path.Length
    }

    PROCESS {
        # Deserialize each XML policy supplied via the -PolicyToMergePath parameter.
        foreach ($Policy in $PolicyToMergePath) {
            $PolicyFullPath = Resolve-Path $Policy

            if ($PolicyFullPath.Path.Length -gt $LongestPathLength) { $LongestPathLength = $PolicyFullPath.Path.Length }
            $CommentList.Add("    * $PolicyFullPath")

            # Each policy must pass XSD validation.
            Write-Verbose "Validating the following policy XML against the Sysmon rule schema: $PolicyFullPath"
            $ValidationResult = Test-SysmonConfiguration -Path $PolicyFullPath -ErrorAction Stop

            if ($ValidationResult.SchemaVersion -ne $ReferencePolicyValidationResult.SchemaVersion) {
                Write-Error "The schema version of $PolicyFullPath ($($ValidationResult.SchemaVersion)) does not match that of the reference configuration: $ReferencePolicyFullPath ($($ReferencePolicyValidationResult.SchemaVersion))"
                return
            }

            if ($ValidationResult.Validated) {
                $XMLReader = New-Object -TypeName Xml.XmlTextReader -ArgumentList $PolicyFullPath

                $SysmonList.Add(($XmlSerializer.Deserialize($XMLReader) -as "$NamespaceName.Sysmon"))

                $XMLReader.Close()
            }
        }
    }

    END {
        # Iterate over each event type - e.g. ProcessCreate, RegistryEvent, etc.
        foreach ($EventFilteringProperty in $EventFilteringProperties) {
            Write-Verbose "Iterating over $EventFilteringProperty events."

            # Group the "include" and "exclude" events of similar types together
            $EventGrouping = $SysmonList.EventFiltering."$EventFilteringProperty" | Group-Object -Property onmatch

            # Collect each property name implemented by each respective event type - e.g. UtcTime, Image, TargetObject, etc.
            $RulePropertyNames = ("$NamespaceName.SysmonEventFiltering$EventFilteringProperty" -as [Type]).GetProperties().Name |
                Where-Object { $_ -ne 'onmatch' }

            $Events = foreach ($Event in $EventGrouping) {
                # For example, imagine we are just going over ProcessCreate "include" rules here.
                # Here, we will need to collect all the rules for each property of the ProcessCreate event type.

                # i.e. "include" or "exclude"
                $OnMatchVal = $Event.Name

                # e.g. create a new instance of a ProcessCreate object.
                # This is where we will add the collected rules
                $EventInstance = New-Object -TypeName "$NamespaceName.SysmonEventFiltering$EventFilteringProperty"
                $EventInstance.onmatch = $OnMatchVal

                foreach ($RulePropertyName in $RulePropertyNames) {
                    # Rules will be collected here. Their uniqueness will be determined
                    # (i.e. de-duped) by using the result of GetHashCode() as the key.
                    $UniqueRuleTable = @{}

                    # This will be an array of rules of the same type corresponding to the current event type.
                    $Event.Group."$RulePropertyName" | Where-Object { $null -ne $_ } | ForEach-Object {
                        $RuleHashCode = "$($_.condition)$($_.Value)".GetHashCode()

                        if (-not $UniqueRuleTable.ContainsKey($RuleHashCode)) { $UniqueRuleTable[$RuleHashCode] = $_ }
                    }

                    $UniqueRules = foreach ($Key in $UniqueRuleTable.Keys) { $UniqueRuleTable[$Key] }

                    # So now we have a set of unique rules for a given rule type
                    # e.g. this is the set of all unique TargetObject rules for a RegistryEvent "include" instance.
                    $EventInstance."$RulePropertyName" = $UniqueRules
                }

                $EventInstance
            }

            # Ensure the event groups are typed properly.
            $Events = $Events -as "$NamespaceName.SysmonEventFiltering$EventFilteringProperty[]"
            
            $ReferenceSysmon.EventFiltering."$EventFilteringProperty" = $Events
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

            if (-not $ExcludeMergeComments) {
                $AdditionalPadLen = 6
                $PaddedFormatString = " {0,-$($LongestPathLength + $AdditionalPadLen)} "
                $XmlWriter.WriteComment($PaddedFormatString -f 'Merged Sysmon policy')
                $XmlWriter.WriteComment($PaddedFormatString -f ('=' * ($LongestPathLength + $AdditionalPadLen)))
                $XmlWriter.WriteComment($PaddedFormatString -f '  Reference policy:')
                $XmlWriter.WriteComment($PaddedFormatString -f "    * $ReferencePolicyFullPath")
                $XmlWriter.WriteComment($PaddedFormatString -f '  Merged policies:')
                foreach ($String in $CommentList) { $XmlWriter.WriteComment($PaddedFormatString -f $String) }
                $XmlWriter.WriteComment($PaddedFormatString -f ('=' * ($LongestPathLength + $AdditionalPadLen)))
            }

            # This will strip any additional "xmlns" attributes from the root Sysmon element.
            $EmptyNamespaces = New-Object -TypeName Xml.Serialization.XmlSerializerNamespaces
            $EmptyNamespaces.Add('', '')

            $XmlSerializer.Serialize($XmlWriter, $ReferenceSysmon, $EmptyNamespaces)
        } catch {
            Write-Error $_
        } finally {
            if ($XmlWriter) { $XmlWriter.Close() }
        }

        $XMlStringBuilder.ToString()
    }
}
