Get-ChildItem "$PSScriptRoot\Code\*" -Include '*.ps1' | ForEach-Object { . $_.FullName }

Set-Variable -Name ModuleBase -Option Constant -Scope Script -Value $PSScriptRoot
Set-Variable -Name SupportedSchemaVersions -Option Constant -Scope Script -Value @(
    '3.40',
    '4.0'
)
