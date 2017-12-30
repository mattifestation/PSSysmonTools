Get-ChildItem "$PSScriptRoot\Code\*" -Include '*.ps1' | ForEach-Object { . $_.FullName }

$Script:ModuleBase = $PSScriptRoot
