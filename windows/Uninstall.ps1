#Requires -RunAsAdministrator
<# Removes tasks, firewall changes, the Wi-Fi fix, shortcuts and the program. Keeps config + credential unless -Purge. #>
param([string]$InstallDir = "$env:ProgramFiles\VeroScudo", [switch]$Purge)
$ErrorActionPreference = 'Continue'
$trays = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*VeroScudoTray.ps1*' })
foreach ($t in $trays) { Stop-Process -Id $t.ProcessId -Force -ErrorAction SilentlyContinue }
if ($trays) { Wait-Process -Id $trays.ProcessId -Timeout 10 -ErrorAction SilentlyContinue }   # the tray holds its images open
Get-ScheduledTask -TaskPath '\VeroScudo\' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
# put the firewall back as it was before VeroScudo (saved on first arm), not to a blanket default
$core = Join-Path $PSScriptRoot 'VeroScudo.Core.psm1'
if (Test-Path $core) { Import-Module $core -Force; Disable-VeroKillSwitch -Action uninstall }
else {
    Set-NetFirewallProfile -All -DefaultOutboundAction NotConfigured
    Get-NetFirewallRule -Group VeroScudo -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Remove-NetFirewallHyperVRule -Name VeroScudo-WSL -ErrorAction SilentlyContinue
}
Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WcmSvc' -Name EnableBadStateTracking -ErrorAction SilentlyContinue
$d = [Environment]::GetFolderPath('Desktop')
Remove-Item "$d\VeroScudo On.lnk", "$d\VeroScudo Off.lnk" -Force -ErrorAction SilentlyContinue
$state = Join-Path $env:ProgramData 'VeroScudo\state'
Remove-Item "$state\armed.flag", "$state\reconnect.lock", "$state\fw-original.json" -Force -ErrorAction SilentlyContinue   # a reinstall saves a fresh original
if ($Purge) {
    Remove-Item (Join-Path $env:ProgramData 'VeroScudo') -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $env:LOCALAPPDATA 'VeroScudo') -Recurse -Force -ErrorAction SilentlyContinue
}
if ($InstallDir -ne $PSScriptRoot) { Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host "tasks left: $(@(Get-ScheduledTask -TaskPath '\VeroScudo\' -ErrorAction SilentlyContinue).Count); outbound: $((Get-NetFirewallProfile | ForEach-Object DefaultOutboundAction) -join ','); rules: $(@(Get-NetFirewallRule -Group VeroScudo -ErrorAction SilentlyContinue).Count)"
Write-Host 'UNINSTALL OK'
