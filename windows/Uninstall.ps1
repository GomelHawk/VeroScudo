#Requires -RunAsAdministrator
<# Removes tasks, the WFP filters (and any 1.0.x firewall changes), the Wi-Fi fix, shortcuts and the program.
   Keeps config + credentials unless -Purge. #>
param([string]$InstallDir = '', [switch]$Purge)
# Modules auto-load from $env:PSModulePath, whose first entry is the user's writable Documents\WindowsPowerShell\Modules: a
# module planted there (VpnClient, ScheduledTasks ...) would run with this process's rights - and the guard tasks run elevated.
# System folders only, before anything else is loaded (-NoProfile does not cover this).
$env:PSModulePath = "$PSHOME\Modules;" + (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'WindowsPowerShell\Modules')
# system folders from the OS and HKLM, never from environment variables (this runs elevated with your environment)
function Get-SysFolder([string]$Name, [string]$Key) {
    $drive = [IO.Path]::GetPathRoot([Environment]::SystemDirectory).TrimEnd('\')
    $rk = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Key)
    $v = if ($rk) { [string]$rk.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
    if ($rk) { $rk.Close() }
    if (-not $v) { throw "cannot read $Name from HKLM\$Key" }
    $v -replace '(?i)%SystemDrive%', $drive
}
$ProgramFilesDir = Get-SysFolder 'ProgramFilesDir' 'SOFTWARE\Microsoft\Windows\CurrentVersion'
$ProgramDataDir = Get-SysFolder 'ProgramData' 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
if (-not $InstallDir) { $InstallDir = Join-Path $ProgramFilesDir 'VeroScudo' }
$ErrorActionPreference = 'Continue'
# stop the watchdog loop and the tray first: a running watchdog would re-apply the kill-switch
Get-ScheduledTask -TaskPath '\VeroScudo\' -ErrorAction SilentlyContinue | Stop-ScheduledTask -ErrorAction SilentlyContinue
$procs = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match 'VeroScudo(Tray)?\.ps1' -and $_.ProcessId -ne $PID })
foreach ($t in $procs) { Stop-Process -Id $t.ProcessId -Force -ErrorAction SilentlyContinue }
if ($procs) { Wait-Process -Id $procs.ProcessId -Timeout 10 -ErrorAction SilentlyContinue }
Get-ScheduledTask -TaskPath '\VeroScudo\' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
$core = Join-Path $PSScriptRoot 'VeroScudo.Core.psm1'
$state = Join-Path $ProgramDataDir 'VeroScudo\state'
Remove-Item "$state\armed.flag" -Force -ErrorAction SilentlyContinue          # a reinstall must not start armed
if (Test-Path $core) {
    Import-Module $core -Force
    # an OpenVPN started by VeroScudo would otherwise keep running without its runner
    try { foreach ($pr in @((Get-VeroConfig).Profiles | Where-Object Type -eq 'openvpn')) { Stop-VeroOpenVpn -ProfileName $pr.Profile } } catch { Write-Warning "OpenVPN not stopped: $($_.Exception.Message)" }
    # the 'VeroScudo OpenVPN' adapter the installer / runner created (only that one, by its exact name)
    try { Remove-VeroOpenVpnAdapter -Action 'uninstall' } catch { Write-Warning "OpenVPN adapter not removed: $($_.Exception.Message)" }
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
Remove-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath('Programs')) 'VeroScudo.lnk') -Force -ErrorAction SilentlyContinue   # Start menu entry (one file)
Remove-Item "$state\reconnect.lock", "$state\wfp.json", "$state\emergency.flag" -Force -ErrorAction SilentlyContinue
if ($Purge) {
    foreach ($d in (Join-Path $ProgramDataDir 'VeroScudo'), (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'VeroScudo')) {
        if ($ProgramDataDir -and (Split-Path $d -Leaf) -eq 'VeroScudo' -and (Test-Path -LiteralPath $d -PathType Container)) { Remove-Item -LiteralPath $d -Recurse -Force }   # errors shown, never silenced
    }
}
# only ever a folder named VeroScudo that holds our module - never whatever path was passed in
$dirOk = $InstallDir -and (Split-Path $InstallDir -Leaf) -eq 'VeroScudo' -and (Test-Path -LiteralPath (Join-Path $InstallDir 'VeroScudo.Core.psm1'))
if ($InstallDir -ne $PSScriptRoot -and $dirOk) { Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue }
elseif (-not $dirOk) { Write-Warning "not removing '$InstallDir': it does not look like a VeroScudo install folder" }
$filters = try { [VeroScudo.Wfp]::Count() } catch { '?' }
Write-Host "tasks left: $(@(Get-ScheduledTask -TaskPath '\VeroScudo\' -ErrorAction SilentlyContinue).Count); WFP filters: $filters; outbound: $((Get-NetFirewallProfile | ForEach-Object DefaultOutboundAction) -join ',')"
Write-Host 'UNINSTALL OK'
