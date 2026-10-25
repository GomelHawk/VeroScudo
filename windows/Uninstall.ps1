#Requires -RunAsAdministrator
<# Removes tasks, the WFP filters (and any 1.0.x firewall changes), the Wi-Fi fix, shortcuts and the program.
   Keeps config + credentials unless -Purge. #>
param([string]$InstallDir = "$env:ProgramFiles\VeroScudo", [switch]$Purge)
$ErrorActionPreference = 'Continue'
# stop the watchdog loop and the tray first: a running watchdog would re-apply the kill-switch
Get-ScheduledTask -TaskPath '\VeroScudo\' -ErrorAction SilentlyContinue | Stop-ScheduledTask -ErrorAction SilentlyContinue
$procs = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match 'VeroScudo(Tray)?\.ps1' -and $_.ProcessId -ne $PID })
foreach ($t in $procs) { Stop-Process -Id $t.ProcessId -Force -ErrorAction SilentlyContinue }
if ($procs) { Wait-Process -Id $procs.ProcessId -Timeout 10 -ErrorAction SilentlyContinue }
Get-ScheduledTask -TaskPath '\VeroScudo\' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
$core = Join-Path $PSScriptRoot 'VeroScudo.Core.psm1'
$state = Join-Path $env:ProgramData 'VeroScudo\state'
Remove-Item "$state\armed.flag" -Force -ErrorAction SilentlyContinue          # a reinstall must not start armed
if (Test-Path $core) {
    Import-Module $core -Force
    Disable-VeroKillSwitch -Action uninstall
    try { [VeroScudo.Wfp]::Remove() } catch { Write-Warning "WFP provider not removed: $($_.Exception.Message)" }
} else {
    Set-NetFirewallProfile -All -DefaultOutboundAction NotConfigured
    Get-NetFirewallRule -Group VeroScudo -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Remove-NetFirewallHyperVRule -Name VeroScudo-WSL -ErrorAction SilentlyContinue
}
Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WcmSvc' -Name EnableBadStateTracking -ErrorAction SilentlyContinue
$d = [Environment]::GetFolderPath('Desktop')
Remove-Item "$d\VeroScudo On.lnk", "$d\VeroScudo Off.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "$state\reconnect.lock", "$state\wfp.json", "$state\emergency.flag" -Force -ErrorAction SilentlyContinue
if ($Purge) {
    foreach ($d in (Join-Path $env:ProgramData 'VeroScudo'), (Join-Path $env:LOCALAPPDATA 'VeroScudo')) {
        if ($env:ProgramData -and $env:LOCALAPPDATA -and (Split-Path $d -Leaf) -eq 'VeroScudo') { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
# only ever a folder named VeroScudo that holds our module - never whatever path was passed in
$dirOk = $InstallDir -and (Split-Path $InstallDir -Leaf) -eq 'VeroScudo' -and (Test-Path -LiteralPath (Join-Path $InstallDir 'VeroScudo.Core.psm1'))
if ($InstallDir -ne $PSScriptRoot -and $dirOk) { Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue }
elseif (-not $dirOk) { Write-Warning "not removing '$InstallDir': it does not look like a VeroScudo install folder" }
$filters = try { [VeroScudo.Wfp]::Count() } catch { '?' }
Write-Host "tasks left: $(@(Get-ScheduledTask -TaskPath '\VeroScudo\' -ErrorAction SilentlyContinue).Count); WFP filters: $filters; outbound: $((Get-NetFirewallProfile | ForEach-Object DefaultOutboundAction) -join ',')"
Write-Host 'UNINSTALL OK'
