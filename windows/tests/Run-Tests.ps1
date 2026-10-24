# Runs the unit tests locally:  powershell -ExecutionPolicy Bypass -File windows\tests\Run-Tests.ps1
if (-not (Get-Module -ListAvailable Pester | Where-Object { $_.Version -ge '5.0' })) { Install-Module Pester -MinimumVersion 5.5 -Force -Scope CurrentUser }
Import-Module Pester -MinimumVersion 5.0
$cfg = New-PesterConfiguration; $cfg.Run.Path = $PSScriptRoot; $cfg.Output.Verbosity = 'Detailed'
Invoke-Pester -Configuration $cfg
