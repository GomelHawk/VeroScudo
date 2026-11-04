# VeroScudo core, part 40: logging and the armed state.
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.

# ---------------------------------------------------------------- logging & state
function Write-VeroLog {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Message, [string]$Action = 'core')
    $p = Get-VeroPath
    if (-not (Test-Path $p.State)) { New-Item -ItemType Directory -Path $p.State -Force | Out-Null }
    if ((Test-Path $p.Log) -and (Get-Item $p.Log).Length -gt 2MB) { Move-Item $p.Log "$($p.Log).1" -Force }
    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $Action, $Message
    Add-Content -Path $p.Log -Value $line -Encoding UTF8
    Write-Host $line
}
function Test-VeroArmed { Test-Path (Get-VeroPath).ArmedFlag }
function Set-VeroArmed {
    [CmdletBinding()] param([Parameter(Mandatory)][bool]$Value, [string]$Action = 'core')
    $p = Get-VeroPath
    if ($Value -and -not (Test-Path $p.ArmedFlag)) { New-Item -ItemType File -Path $p.ArmedFlag -Force | Out-Null; Write-VeroLog 'ARMED' $Action }
    if (-not $Value -and (Test-Path $p.ArmedFlag)) { Remove-Item $p.ArmedFlag -Force; Write-VeroLog 'DISARMED' $Action }
}
function Set-VeroActiveProfile {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Name, [string]$Action = 'core')
    $p = Get-VeroPath
    $null = Get-VeroConfig -Active $Name                                  # validates the name against config.json
    $cur = if (Test-Path $p.ActiveProfile) { (Get-Content $p.ActiveProfile -Raw).Trim() } else { '' }
    if ($cur -ne $Name) { Set-Content -Path $p.ActiveProfile -Value $Name -Encoding UTF8; Write-VeroLog "active profile -> '$Name'" $Action }
}
