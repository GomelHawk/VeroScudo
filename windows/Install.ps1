#Requires -RunAsAdministrator
<#
  VeroScudo installer (Windows). Run from an elevated PowerShell:
    .\Install.ps1 -ProfileName "MyVPN" -Server vpn.example.com -UserName jdoe        # first install
    .\Install.ps1                                                                 # re-install / upgrade, keeps config
  Copies the program to $InstallDir, writes %ProgramData%\VeroScudo\config.json (unless present),
  registers the scheduled tasks, the tray autostart and two Desktop shortcuts, applies the Wi-Fi fix.
  Idempotent. The VPN password is NOT asked here: each user runs Set-VpnCredential.ps1 once.
#>
param(
    [string]$ProfileName, [string]$Server, [string]$UserName, [int]$Port = 443,
    [string]$InstallDir = "$env:ProgramFiles\VeroScudo",
    [switch]$NoTray, [switch]$NoShortcuts
)
$ErrorActionPreference = 'Stop'
$Src = $PSScriptRoot
Import-Module (Join-Path $Src 'VeroScudo.Core.psm1') -Force
$p = Get-VeroPath
New-Item -ItemType Directory -Path $InstallDir, $p.Home, $p.State -Force | Out-Null

# --- config
if (-not (Test-Path $p.Config)) {
    if (-not $ProfileName -or -not $Server -or -not $UserName) {
        $profiles = @(Get-VpnConnection -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
        Write-Host "Windows VPN profiles found: $($profiles -join ', ')"
        if (-not $ProfileName) { $ProfileName = Read-Host 'VPN profile name (exactly as in Windows Settings)' }
        if (-not $Server)   { $Server   = Read-Host 'VPN server host name' }
        if (-not $UserName) { $UserName = Read-Host 'VPN username' }
    }
    $cfg = Get-Content (Join-Path $Src 'config.example.json') -Raw | ConvertFrom-Json
    $cfg.vpn.profile = $ProfileName; $cfg.vpn.server = $Server; $cfg.vpn.username = $UserName; $cfg.vpn.port = $Port
    $cfg | ConvertTo-Json -Depth 5 | Set-Content $p.Config -Encoding UTF8
    Write-Host "config written: $($p.Config)"
}
$config = Get-VeroConfig
if (-not (Get-VpnConnection -Name $config.Profile -ErrorAction SilentlyContinue)) {
    Write-Warning "No Windows VPN profile named '$($config.Profile)' exists for this user. Create it in Settings > VPN first."
}

# --- program files
# a running tray keeps the old code in memory and locks its images; the tray task is restarted at the end
$trays = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" | Where-Object { $_.CommandLine -match 'VeroScudoTray\.ps1' })
foreach ($t in $trays) { Stop-Process -Id $t.ProcessId -Force -ErrorAction SilentlyContinue }
if ($trays) { Wait-Process -Id $trays.ProcessId -Timeout 10 -ErrorAction SilentlyContinue; Write-Host "stopped $($trays.Count) running tray(s)" }
foreach ($f in 'VeroScudo.Core.psm1', 'VeroScudo.ps1', 'VeroScudoTray.ps1', 'run.vbs', 'Set-VpnCredential.ps1', 'Uninstall.ps1', 'config.example.json') {
    Copy-Item (Join-Path $Src $f) (Join-Path $InstallDir $f) -Force
}
$iconsSrc = @((Join-Path $Src 'icons'), (Join-Path (Split-Path $Src -Parent) 'assets\icons')) | Where-Object { Test-Path $_ } | Select-Object -First 1   # release zip layout, then repo layout
$iconsDst = Join-Path $InstallDir 'icons'
if ($iconsSrc) {
    # copy the contents: copying the folder onto an existing icons\ would nest it as icons\icons (remove any such leftover)
    Remove-Item (Join-Path $iconsDst 'icons') -Recurse -Force -ErrorAction SilentlyContinue
    New-Item $iconsDst -ItemType Directory -Force | Out-Null
    Copy-Item (Join-Path $iconsSrc '*') $iconsDst -Recurse -Force
} else { Write-Warning 'icons folder not found - tray will use a generic icon' }
Write-Host "program copied to $InstallDir"

# --- Wi-Fi recovery fix (see docs/ARCHITECTURE.md)
if ($config.WifiRecoveryFix) {
    if (-not (Test-Path 'HKLM:\SOFTWARE\Microsoft\WcmSvc')) { New-Item 'HKLM:\SOFTWARE\Microsoft\WcmSvc' | Out-Null }
    Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WcmSvc' -Name EnableBadStateTracking -Value 0 -Type DWord
    Write-Host 'Wi-Fi recovery fix applied (WcmSvc EnableBadStateTracking=0)'
}

# --- scheduled tasks
$Folder    = '\VeroScudo\'
$user      = "$env:USERDOMAIN\$env:USERNAME"
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) `
                -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden
function Act([string]$a) { New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\wscript.exe" -Argument "//B //Nologo `"$InstallDir\run.vbs`" $a" }
function EventTrigger([string]$query) {
    $t = New-CimInstance -CimClass (Get-CimClass MSFT_TaskEventTrigger root/Microsoft/Windows/TaskScheduler) -ClientOnly
    $t.Subscription = $query; $t.Enabled = $true; $t
}
$prof = $config.Profile -replace "'", "&apos;"
$connected  = EventTrigger "<QueryList><Query Id=`"0`" Path=`"System`"><Select Path=`"System`">*[System[Provider[@Name='RasMan'] and EventID=20267]] and *[EventData[Data='$prof']]</Select></Query></QueryList>"
$terminated = EventTrigger "<QueryList><Query Id=`"0`" Path=`"Application`"><Select Path=`"Application`">*[System[Provider[@Name='RasClient'] and EventID=20226]] and *[EventData[Data='$prof']]</Select></Query></QueryList>"
$every5min  = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)
$atLogon    = New-ScheduledTaskTrigger -AtLogOn -User $user
$tasks = @(
    @{ Name = 'Connected';  Action = (Act 'arm');      Trigger = @($connected);           Desc = 'VPN connected -> arm kill-switch' }
    @{ Name = 'Terminated'; Action = (Act 'on-event'); Trigger = @($terminated);          Desc = 'VPN terminated -> user hung up: disarm / else: reconnect' }
    @{ Name = 'Watchdog';   Action = (Act 'watchdog'); Trigger = @($every5min, $atLogon); Desc = 'self-heal every 5 min and at logon' }
    @{ Name = 'On';         Action = (Act 'on');       Trigger = @();                     Desc = 'manual: arm + connect' }
    @{ Name = 'Off';        Action = (Act 'off');      Trigger = @();                     Desc = 'manual: disarm + disconnect' }
)
if (-not $NoTray) {
    $trayAction = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\wscript.exe" -Argument "//B //Nologo `"$InstallDir\run.vbs`" tray"
    $tasks += @{ Name = 'Tray'; Action = $trayAction; Trigger = @((New-ScheduledTaskTrigger -AtLogOn -User $user)); Desc = 'tray icon at sign-in' }
}
foreach ($t in $tasks) {
    $args_ = @{ TaskName = $t.Name; TaskPath = $Folder; Action = $t.Action; Principal = $principal; Settings = $settings; Description = $t.Desc; Force = $true }
    if ($t.Trigger.Count -gt 0) { $args_.Trigger = $t.Trigger }
    Register-ScheduledTask @args_ | Out-Null
    Write-Host "task registered: $Folder$($t.Name)"
}

# --- shortcuts
if (-not $NoShortcuts) {
    $desktop = [Environment]::GetFolderPath('Desktop'); $shell = New-Object -ComObject WScript.Shell
    foreach ($s in @(@{ N = 'VeroScudo On'; T = 'On'; I = "$InstallDir\icons\png\protected.ico" }, @{ N = 'VeroScudo Off'; T = 'Off'; I = "$InstallDir\icons\png\off.ico" })) {
        $lnk = $shell.CreateShortcut((Join-Path $desktop "$($s.N).lnk"))
        $lnk.TargetPath = "$env:SystemRoot\System32\schtasks.exe"; $lnk.Arguments = "/run /tn `"$Folder$($s.T)`""
        $lnk.WindowStyle = 7; if (Test-Path $s.I) { $lnk.IconLocation = $s.I }; $lnk.Save()
        Write-Host "shortcut: $($s.N)"
    }
}
if (-not $NoTray) { schtasks /run /tn "$Folder`Tray" | Out-Null }
Write-Host ''
Write-Host "INSTALL OK.  Next: each user runs  powershell -ExecutionPolicy Bypass -File `"$InstallDir\Set-VpnCredential.ps1`""
Write-Host '            then connects the VPN (Settings, or the "VeroScudo On" shortcut).'
