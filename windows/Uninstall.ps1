#Requires -RunAsAdministrator
<# Removes tasks, the WFP filters (and any 1.0.x firewall changes), the Wi-Fi fix, shortcuts and the program (when run
   from another folder than the program's own - a script cannot remove the folder it runs from, and says so).
   Keeps the config and state unless -Purge. Your own folder with the stored passwords is never removed from here: the
   script names it for you to delete. #>
param([string]$InstallDir = '', [switch]$Purge)
# Modules auto-load from $env:PSModulePath, whose first entry is the user's writable Documents\WindowsPowerShell\Modules: a
# module planted there (VpnClient, ScheduledTasks ...) would run with this process's rights - and the guard tasks run elevated.
# System folders only, before anything else is loaded (-NoProfile does not cover this).
$env:PSModulePath = "$PSHOME\Modules;" + [IO.Path]::Combine([Environment]::GetFolderPath('ProgramFiles'), 'WindowsPowerShell\Modules')   # no cmdlet before the pin is in force
# the signed-in user's shortcuts are removed below: with over-the-shoulder UAC this session is another account - refuse, like Install.ps1
$console = [string](Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName
$me = [Security.Principal.WindowsIdentity]::GetCurrent().Name            # the account this session really runs as, not what its environment says
if ($console -and $console -ne $me) { throw "signed in as '$console', but this elevated session runs as '$me' - run Uninstall.ps1 from the signed-in administrator account." }
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
    Remove-NetFirewallHyperVRule -Name VeroScudo-WSL-Block -ErrorAction SilentlyContinue
    Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object { [string]$_.Comment -eq 'VeroScudo: the VPN server while the tunnel is down' } |
        ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction SilentlyContinue }
}
Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WcmSvc' -Name EnableBadStateTracking -ErrorAction SilentlyContinue
$d = [Environment]::GetFolderPath('Desktop')
Remove-Item "$d\VeroScudo On.lnk", "$d\VeroScudo Off.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath('Programs')) 'VeroScudo.lnk') -Force -ErrorAction SilentlyContinue   # Start menu entry (one file)
Remove-Item "$state\reconnect.lock", "$state\wfp.json", "$state\emergency.flag" -Force -ErrorAction SilentlyContinue
function Remove-VeroTreeNoFollow([string]$Path) {
    <# Removes a folder of VeroScudo's with what is in it - and never anything a link in it points to. The user's own
       VeroScudo folder is among those removed here, as administrator: a junction placed in it (or in its place) is removed
       as the link it is, its target is not entered. File by file, no recursive delete command. #>
    $di = New-Object IO.DirectoryInfo $Path
    if (-not $di.Exists) { return }
    if ($di.Attributes -band [IO.FileAttributes]::ReparsePoint) { $di.Delete(); return }     # the link itself, never its target
    foreach ($f in $di.GetFiles()) { $f.Attributes = [IO.FileAttributes]::Normal; $f.Delete() }
    foreach ($s in $di.GetDirectories()) { Remove-VeroTreeNoFollow $s.FullName }
    $di.Delete()
}
if ($Purge) {
    $d = Join-Path $ProgramDataDir 'VeroScudo'
    if ($ProgramDataDir -and (Split-Path $d -Leaf) -eq 'VeroScudo' -and (Test-Path -LiteralPath $d -PathType Container)) { Remove-VeroTreeNoFollow $d }   # errors shown, never silenced
    # Your own folder (stored passwords, tray settings) is NOT removed from here: this script runs as administrator, and a
    # folder its owner can change at any moment is no place for an administrator's delete. It is yours to remove.
    $own = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'VeroScudo'
    if (Test-Path -LiteralPath $own) { Write-Host "Your own VeroScudo folder holds the stored VPN passwords (readable by your account only) and the tray's settings. Delete it yourself if you want them gone: $own" }
}
# only ever a folder named VeroScudo that holds our module - never whatever path was passed in
$dirOk = $InstallDir -and (Split-Path $InstallDir -Leaf) -eq 'VeroScudo' -and (Test-Path -LiteralPath (Join-Path $InstallDir 'VeroScudo.Core.psm1'))
# ... and only one that is the administrators' own all the way up: a folder its user can change while it is being removed
# is no place for an administrator's delete (a copy of the files unpacked somewhere is removed by hand)
$dirSafe = $dirOk -and (Get-Command Test-VeroAdminOnlyPath -ErrorAction SilentlyContinue) -and -not (Test-VeroAdminOnlyPath (Join-Path $InstallDir 'VeroScudo.Core.psm1')) -and
           (Test-VeroAdminOnlyRules -Contents @((Get-Acl -LiteralPath $InstallDir).Access | ForEach-Object { $_ }))
if ($dirOk -and -not $dirSafe) { Write-Warning "not removing '$InstallDir': others than administrators can change it or a folder above it. Delete it yourself." }
elseif ($InstallDir -ne $PSScriptRoot -and $dirOk) { try { Remove-VeroTreeNoFollow $InstallDir } catch { Write-Warning "'$InstallDir' not removed completely: $($_.Exception.Message)" } }
elseif (-not $dirOk) { Write-Warning "not removing '$InstallDir': it does not look like a VeroScudo install folder" }
elseif ($InstallDir -eq $PSScriptRoot) { Write-Host "The program folder is the one this script runs from and cannot remove itself. Delete it yourself: $InstallDir" }
$filters = try { [VeroScudo.Wfp]::Count() } catch { '?' }
Write-Host "tasks left: $(@(Get-ScheduledTask -TaskPath '\VeroScudo\' -ErrorAction SilentlyContinue).Count); WFP filters: $filters; outbound: $((Get-NetFirewallProfile | ForEach-Object DefaultOutboundAction) -join ',')"
Write-Host 'UNINSTALL OK'
