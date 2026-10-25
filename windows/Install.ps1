#Requires -RunAsAdministrator
<#
  VeroScudo installer (Windows). Run from an elevated 64-bit PowerShell:
    .\Install.ps1 -ProfileName "MyVPN" -Server vpn.example.com -UserName jdoe        # first install
    .\Install.ps1 -ProfileName "Backup" -Server vpn2.example.com -UserName jdoe      # add another VPN profile
    .\Install.ps1                                                                 # re-install / upgrade, keeps config
  Self-tests the WFP interface first (nothing is changed when that fails), copies the program to $InstallDir, compiles the
  native helper, writes %ProgramData%\VeroScudo\config.json (unless present) and locks that folder down to administrators,
  registers the scheduled tasks, the tray autostart and two Desktop shortcuts, applies the Wi-Fi fix and migrates a 1.0.x
  Windows-Firewall kill-switch to WFP filters. Idempotent. The VPN password is NOT asked here: each user stores it once
  (tray Settings, or Set-VpnCredential.ps1).
#>
param(
    [string]$ProfileName, [string]$Server, [string]$UserName, [int]$Port = 443,
    [string]$InstallDir = "$env:ProgramFiles\VeroScudo",
    [switch]$NoTray, [switch]$NoShortcuts
)
$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitProcess) { throw 'Run Install.ps1 from 64-bit PowerShell (C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe).' }
$Src = $PSScriptRoot
Import-Module (Join-Path $Src 'VeroScudo.Core.psm1') -Force

# --- self-test before touching anything: the kill-switch is built from these WFP layer/field ids
Test-VeroNative | Out-Null
Write-Host 'WFP self-test OK'

$p = Get-VeroPath
New-Item -ItemType Directory -Path $InstallDir, $p.Home, $p.State -Force | Out-Null

# --- state folder: administrators and SYSTEM only; users may read (the tray shows state and log)
# Without this, ProgramData's default ACL lets any user create files in it (and own them).
& icacls.exe $p.Home /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
& icacls.exe "$($p.Home)\*" /reset /T /C /Q | Out-Null
& icacls.exe $p.Home /setowner '*S-1-5-32-544' /T /C /Q | Out-Null
Write-Host "locked down: $($p.Home) (Administrators/SYSTEM full, Users read)"

# --- config
if (-not (Test-Path $p.Config)) {
    if (-not $ProfileName -or -not $Server -or -not $UserName) {
        $profiles = @(Get-VpnConnection -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
        Write-Host "Windows VPN profiles found: $($profiles -join ', ')"
        if (-not $ProfileName) { $ProfileName = Read-Host 'VPN profile name (exactly as in Windows Settings)' }
        if (-not $Server)   { $Server   = Read-Host 'VPN server host name' }
        if (-not $UserName) { $UserName = Read-Host 'VPN username' }
    }
    $json = @{ profiles = @(@{ profile = $ProfileName; server = $Server; port = $Port; username = $UserName }); activeProfile = $ProfileName
               retrySeconds = 10; vm = 'auto'; wifiRecoveryFix = $true; updateCheck = $true; lanAllow = @() } | ConvertTo-Json -Depth 5
    Save-VeroConfig -Json $json | Out-Null
    Write-Host "config written: $($p.Config)"
} else {
    $raw = Get-Content $p.Config -Raw
    $cfg = Get-VeroConfig -Raw $raw
    $obj = $raw | ConvertFrom-Json
    if ($ProfileName -and @($cfg.Profiles | ForEach-Object Profile) -notcontains $ProfileName) {
        if (-not $Server -or -not $UserName) { throw 'Adding a profile needs -Server and -UserName too.' }
        $cfg.Profiles = @($cfg.Profiles) + [pscustomobject]@{ Profile = $ProfileName; Server = $Server; Port = $Port; Username = $UserName; ServerIps = @() }
        Save-VeroConfig -Json (ConvertTo-VeroConfigJson $cfg) | Out-Null
        Write-Host "profile added: $ProfileName"
    } elseif ($obj.PSObject.Properties['vpn']) {
        Save-VeroConfig -Json (ConvertTo-VeroConfigJson $cfg) | Out-Null        # 1.0 single-profile file -> profiles list
        Write-Host 'config converted to the profiles format'
    }
}
$config = Get-VeroConfig
foreach ($pr in $config.Profiles) {
    if (-not (Get-VpnConnection -Name $pr.Profile -ErrorAction SilentlyContinue)) {
        Write-Warning "No Windows VPN profile named '$($pr.Profile)' exists for this user. Create it in Settings > VPN first."
    }
}

# --- stop what runs the old code (the tray holds its images open, the watchdog loop holds the module)
$Folder = '\VeroScudo\'
Get-ScheduledTask -TaskPath $Folder -ErrorAction SilentlyContinue | Stop-ScheduledTask -ErrorAction SilentlyContinue
$old = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" | Where-Object { $_.CommandLine -match 'VeroScudo(Tray)?\.ps1' -and $_.ProcessId -ne $PID })
foreach ($t in $old) { Stop-Process -Id $t.ProcessId -Force -ErrorAction SilentlyContinue }
if ($old) { Wait-Process -Id $old.ProcessId -Timeout 10 -ErrorAction SilentlyContinue; Write-Host "stopped $($old.Count) running VeroScudo process(es)" }

# --- program files
foreach ($f in 'VeroScudo.Core.psm1', 'VeroScudo.Native.cs', 'VeroScudo.ps1', 'VeroScudoTray.ps1', 'run.vbs', 'Set-VpnCredential.ps1', 'Uninstall.ps1', 'config.example.json') {
    Copy-Item (Join-Path $Src $f) (Join-Path $InstallDir $f) -Force
}
# compile the native helper once (a child process: this session already loaded the same types from source)
$dll = Join-Path $InstallDir 'VeroScudo.Native.dll'
Remove-Item $dll -Force -ErrorAction SilentlyContinue
$compile = "Add-Type -TypeDefinition ([IO.File]::ReadAllText('$InstallDir\VeroScudo.Native.cs')) -Language CSharp -OutputAssembly '$dll' -OutputType Library"
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command $compile
if (-not (Test-Path $dll)) { throw "native helper was not compiled: $dll" }
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

# --- kill-switch engine: WFP filters replace the 1.0.x Windows Firewall rules. Fail-closed order: new filters first.
if (Test-VeroArmed) {
    Sync-VeroKillSwitch -Config $config -Action install -Force
    Write-Host 'armed: WFP kill-switch applied'
}
Remove-VeroLegacyFirewall -Action install

# --- scheduled tasks
$user      = "$env:USERDOMAIN\$env:USERNAME"
$guard     = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$limited   = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited      # the tray needs no admin rights
$settings  = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) `
                -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden
function Act([string]$a) { New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\wscript.exe" -Argument "//B //Nologo `"$InstallDir\run.vbs`" $a" }
function EventTrigger([string]$query) {
    $t = New-CimInstance -CimClass (Get-CimClass MSFT_TaskEventTrigger root/Microsoft/Windows/TaskScheduler) -ClientOnly
    $t.Subscription = $query; $t.Enabled = $true; $t
}
# any VPN: the guard itself decides from the event which profile it was (several profiles can be configured)
$connected  = EventTrigger "<QueryList><Query Id=`"0`" Path=`"System`"><Select Path=`"System`">*[System[Provider[@Name='RasMan'] and EventID=20267]]</Select></Query></QueryList>"
$terminated = EventTrigger "<QueryList><Query Id=`"0`" Path=`"Application`"><Select Path=`"Application`">*[System[Provider[@Name='RasClient'] and EventID=20226]]</Select></Query></QueryList>"
$everyMin   = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
$atLogon    = New-ScheduledTaskTrigger -AtLogOn -User $user
$tasks = @(
    @{ Name = 'Connected';  Action = (Act 'arm');      Trigger = @($connected);          P = $guard; Desc = 'VPN connected -> arm kill-switch' }
    @{ Name = 'Terminated'; Action = (Act 'on-event'); Trigger = @($terminated);         P = $guard; Desc = 'VPN terminated -> user hung up: disarm / else: reconnect' }
    @{ Name = 'Watchdog';   Action = (Act 'watchdog'); Trigger = @($everyMin, $atLogon); P = $guard; Desc = 'keeps the kill-switch exact every 15 s; restarted within a minute if it stops' }
    @{ Name = 'On';         Action = (Act 'on');       Trigger = @();                    P = $guard; Desc = 'manual: arm + connect' }
    @{ Name = 'Off';        Action = (Act 'off');      Trigger = @();                    P = $guard; Desc = 'manual: disarm + disconnect' }
    @{ Name = 'Switch';     Action = (Act 'switch');   Trigger = @();                    P = $guard; Desc = 'switch the VPN profile requested by the tray' }
)
if (-not $NoTray) {
    $trayAction = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\wscript.exe" -Argument "//B //Nologo `"$InstallDir\run.vbs`" tray"
    $tasks += @{ Name = 'Tray'; Action = $trayAction; Trigger = @((New-ScheduledTaskTrigger -AtLogOn -User $user)); P = $limited; Desc = 'tray icon at sign-in' }
}
foreach ($t in $tasks) {
    $args_ = @{ TaskName = $t.Name; TaskPath = $Folder; Action = $t.Action; Principal = $t.P; Settings = $settings; Description = $t.Desc; Force = $true }
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
schtasks /run /tn "$Folder`Watchdog" | Out-Null
if (-not $NoTray) { schtasks /run /tn "$Folder`Tray" | Out-Null }
Write-Host ''
Write-Host "INSTALL OK ($(Get-VeroVersion)).  Next: store the VPN password once per profile - tray > Settings, or"
Write-Host "            powershell -ExecutionPolicy Bypass -File `"$InstallDir\Set-VpnCredential.ps1`""
Write-Host '            then connect the VPN (Settings, or the "VeroScudo On" shortcut).'
