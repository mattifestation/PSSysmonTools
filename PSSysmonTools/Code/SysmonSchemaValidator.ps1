filter Test-SysmonConfiguration {
<#
.SYNOPSIS

Validates a Sysmon configuration.

.DESCRIPTION

Test-SysmonConfiguration validates a Sysmon configuration XML document against its respective XML schema (present in the "Schemas" directory).

The XML schemas and Test-SysmonConfiguration are designed to validate configurations without the need of Sysmon. Additionally, as of Sysmon 6.20, Sysmon does not expose a configuration schema publicly. There is a DTD schema embedded in the binary but the schema itself doesn't validate due to repeating RegistryEvent and WmiEvent elements. DTD schemas are also not nearly expressive enough nor do they permit code generation with xsd.exe.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause

Required Dependencies: the XSDs in the "Schemas" directory.

.PARAMETER Path

Specifies the path to a Sysmon configuration XML.

.EXAMPLE

Test-SysmonConfiguration -Path sysmonconfig.xml

.OUTPUTS

Sysmon.XMLValidationResult

Outputs an object consisting of the results of the schema validation.
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        [Alias('FullName')]
        [ValidateNotNullOrEmpty()]
        $Path
    )

    $FullPath = Resolve-Path $Path

    $FileContents = Get-Content -Path $FullPath

    Write-Verbose "Attempting to parse the following file: $FullPath"

    if ($FileContents) {
        try {
            # First, attempt to extract the schemaversion attribute so that
            # the XML can be validated against the correct Sysmon XSD.
            $XMLContent = [Xml] $FileContents
            $SchemaVersion = $XMLContent.Sysmon.schemaversion

            if (-not $SchemaVersion) {
                Write-Error 'A "schemaversion" attribute value was not present in the specified XML.'
                return
            }

            switch ($SchemaVersion) {
                # Oddly, Sysmon interprets ".4" as ".40". It also ignores leading numbers after the second digit.
                '3.40' {
                    $XSDPath = "$Script:ModuleBase\Schemas\SysmonConfigurationSchema_3_40.xsd"
                }

                '3.4' {
                    $XSDPath = "$Script:ModuleBase\Schemas\SysmonConfigurationSchema_3_40.xsd"
                    # Since Sysmon normalizes the schema version to 3.40, we'll do it here as well.
                    $SchemaVersion = '3.40'
                }

                '4.00' {
                    $XSDPath = "$Script:ModuleBase\Schemas\SysmonConfigurationSchema_4_00.xsd"
                }

                '4.0' {
                    $XSDPath = "$Script:ModuleBase\Schemas\SysmonConfigurationSchema_4_00.xsd"
                    $SchemaVersion = '4.00'
                }

                default {
                    Write-Error "Schema version $SchemaVersion is not supported."
                    return
                }
            }

            $SchemaVersion = ([Version] $SchemaVersion).ToString(2)

            Write-Verbose "Using the following schema version: $SchemaVersion"
            Write-Verbose "Using the following XSD: $XSDPath"

            # At this point, the XML can be validated against its respective schema.

            $SysmonConfigNamespace = 'urn:schemas-specterops.io:SysmonConfiguration'

            $XMLSettings = New-Object -TypeName Xml.XmlReaderSettings
            $XMLSettings.CheckCharacters = $True
            $XMLSettings.CloseInput = $True
            $XMLSettings.IgnoreWhitespace = $True
            $XMLSettings.NameTable = New-Object -TypeName Xml.NameTable
            $XMLNamespaceManager = New-Object -TypeName Xml.XmlNamespaceManager -ArgumentList $XMLSettings.NameTable
            
            # Since the namespace is not supplied in a Sysmon config, it needs to be specified here.
            $XMLNamespaceManager.AddNamespace([String]::Empty, $SysmonConfigNamespace)
            $XMLParserContext = New-Object -TypeName Xml.XmlParserContext -ArgumentList $XMLSettings.NameTable, $XMLNamespaceManager, $null, ([Xml.XmlSpace]::Default)
            
            $XMLSettings.ValidationType = [Xml.ValidationType]::Schema
            $null = $XMLSettings.Schemas.Add($SysmonConfigNamespace, $XSDPath)
            $XMLSettings.ValidationFlags = $XMLSettings.ValidationFlags -bor [Xml.Schema.XmlSchemaValidationFlags]::ReportValidationWarnings

            # Raise a "XMLValidationError" event consisting of error/warning context in the event of a failed validation
            $null = Register-ObjectEvent -InputObject $XMLSettings -EventName ValidationEventHandler -SourceIdentifier XMLValidator -Action {
                param($sender, [Xml.Schema.ValidationEventArgs] $e)

                New-Event -SourceIdentifier XMLValidationError -MessageData $e
            }

            $XMLReader = [Xml.XmlReader]::Create($FullPath.Path, $XMLSettings, $XMLParserContext)

            # Recursively read each element of the supplied XML. An validation errors will trigger the scriptblock above.
            while ($XMLReader.Read()) { }

            $XMLReader.Close()
            Unregister-Event -SourceIdentifier XMLValidator

            $ValidationSucceeded = $True

            # If there were any errors or warnings, surface them accordingly.
            Get-Event -SourceIdentifier XMLValidationError -ErrorAction SilentlyContinue | ForEach-Object {
                $ValidationEvent = $_

                # Surfacing the validation error as a PowerShell error will
                # allow the user to decide how to handle the error via -ErrorAction
                switch ($ValidationEvent.MessageData.Severity) {
                    'Warning' { Write-Warning $ValidationEvent.MessageData.Message; $ValidationSucceeded = $False }
                    'Error'   { Write-Error   $ValidationEvent.MessageData.Message; $ValidationSucceeded = $False }
                }

                # Remove the event upon processing it.
                $ValidationEvent | Remove-Event
            }

            [PSCustomObject] @{
                PSTypeName = 'Sysmon.XMLValidationResult'
                Validated = $ValidationSucceeded
                SchemaVersion = $SchemaVersion
                Path = $FullPath.Path
            }
        } catch {
            Write-Error $_
            return
        }
    }
}
