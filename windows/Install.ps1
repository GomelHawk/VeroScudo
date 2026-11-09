#Requires -RunAsAdministrator
<#
  VeroScudo installer (Windows). Run from an elevated 64-bit PowerShell:
    .\Install.ps1 -ProfileName "MyVPN" -Server vpn.example.com -UserName jdoe        # first install
    .\Install.ps1 -ProfileName "Backup" -Server vpn2.example.com -UserName jdoe      # add another VPN profile
    .\Install.ps1 -ProfileName "Reserve" -Type openvpn -OpenVpnConfig C:\path\reserve.ovpn -UserName jdoe   # OpenVPN profile
    .\Install.ps1 -ProfileName "wg-home" -Type wireguard -WireGuardConfig C:\path\wg-home.conf           # WireGuard tunnel
    .\Install.ps1                                                                 # re-install / upgrade, keeps config
  Self-tests the WFP interface first (nothing is changed when that fails), copies the program to $InstallDir, compiles the
  native helper, writes %ProgramData%\VeroScudo\config.json (unless present) and locks that folder down to administrators,
  registers the scheduled tasks, the tray autostart, two Desktop shortcuts and a Start menu entry for the tray, applies the Wi-Fi fix and migrates a 1.0.x
  Windows-Firewall kill-switch to WFP filters. Idempotent. The VPN password is NOT asked here: each user stores it once
  (tray Settings, or Set-VpnCredential.ps1).
#>
param(
    [string]$ProfileName, [string]$Server, [string]$UserName, [int]$Port = 0,
    [ValidateSet('ras', 'openvpn', 'wireguard', 'hiddify')][string]$Type = 'ras',
    [string]$OpenVpnConfig,          # openvpn: the .ovpn to import (checked, key files inlined, stored admin-only)
    [string]$WireGuardConfig,        # wireguard: optional .conf to read the endpoint from and check (the tunnel itself lives in the WireGuard app)
    [switch]$Dco,                    # openvpn: keep the kernel data channel (the server permit is then not tied to openvpn.exe)
    [string]$InstallDir = '',     # default: <Program Files>\VeroScudo, resolved from the OS (never %ProgramFiles%)
    [switch]$NoTray, [switch]$NoShortcuts
)
$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitProcess) { throw 'Run Install.ps1 from 64-bit PowerShell (C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe).' }
# Modules auto-load from $env:PSModulePath, whose first entry is the user's writable Documents\WindowsPowerShell\Modules: a
# module planted there (VpnClient, ScheduledTasks ...) would run with this process's rights - and the guard tasks run elevated.
# System folders only, before anything else is loaded (-NoProfile does not cover this).
$env:PSModulePath = "$PSHOME\Modules;" + (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'WindowsPowerShell\Modules')
$Src = $PSScriptRoot
Import-Module (Join-Path $Src 'VeroScudo.Core.psm1') -Force
# system folders from the OS: this runs elevated with YOUR environment, where any program you run can plant %ProgramFiles%
$Sys = Get-VeroSystemDir System
if (-not $InstallDir) { $InstallDir = Join-Path (Get-VeroSystemDir ProgramFiles) 'VeroScudo' }

# --- self-test before touching anything: the kill-switch is built from these WFP layer/field ids
Test-VeroNative | Out-Null
Write-Host 'WFP self-test OK'
# a custom -InstallDir: the elevated tasks run VeroScudo from it, so no folder above it may let a user rename or replace it
$weak = Test-VeroAdminOnlyPath $InstallDir
if ($weak) { throw "refusing -InstallDir '$InstallDir': '$weak' lets non-administrators rename or replace folders in it, and the elevated tasks run VeroScudo from there. Use a folder under $(Get-VeroSystemDir ProgramFiles)." }

$p = Get-VeroPath
New-Item -ItemType Directory -Path $InstallDir, $p.Home, $p.State -Force | Out-Null

# --- program folder: administrators and SYSTEM write, everyone else reads. Program Files gives that by default; a custom
# -InstallDir inherits whatever its parent allows - and the elevated tasks run run.vbs / VeroScudo.ps1 from here.
& icacls.exe $InstallDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
& icacls.exe $InstallDir /setowner '*S-1-5-32-544' /T /C /Q | Out-Null

# --- state folder: administrators and SYSTEM only; users may read (the tray shows state and log)
# Without this, ProgramData's default ACL lets any user create files in it (and own them).
& icacls.exe $p.Home /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
# reset everything below to the folder's rules - except the OpenVPN folder, which keeps its own stricter ones (private keys)
foreach ($child in @(Get-ChildItem -LiteralPath $p.Home -Force | Where-Object { $_.FullName -ne $p.OpenVpnDir })) { & icacls.exe $child.FullName /reset /T /C /Q | Out-Null }
& icacls.exe $p.Home /setowner '*S-1-5-32-544' /T /C /Q | Out-Null
$null = Protect-VeroOpenVpnDir
# the reset above gave state\locks the folder's "Users: read" - enough to open a lock file and hold it: administrators only again
$null = Get-VeroLockDir
Write-Host "locked down: $($p.Home) (Administrators/SYSTEM full, Users read; openvpn\ and state\locks\ Administrators/SYSTEM only)"

function New-ProfileEntry([string]$Name, [string]$Kind, [string]$Srv, [int]$Prt, [string]$User, [string]$Ovpn, [string]$WgConf, [bool]$KeepDco) {
    <# One new profile from the command line, per type. OpenVPN: imports the .ovpn first (throws on a refused config). #>
    if ($Kind -eq 'openvpn') {
        if (-not $Ovpn) { throw 'An OpenVPN profile needs -OpenVpnConfig <file.ovpn>.' }
        $r = Import-VeroOpenVpnProfile -ProfileName $Name -Source $Ovpn
        foreach ($w in $r.Warnings) { Write-Warning $w }
        if ($r.Auth -and -not $User) { $User = Read-Host 'VPN username for this OpenVPN profile' }
        return [pscustomobject]@{ Profile = $Name; Type = 'openvpn'; Server = ''; Port = 1194; Username = $User; ServerIps = @(); Auth = $r.Auth; Dco = $KeepDco }
    }
    if ($Kind -eq 'hiddify') {                                              # VPN mode of the Hiddify app: nothing to import, it keeps its servers
        if (-not (Get-VeroHiddifyDir)) { throw 'Hiddify is not installed (Program Files\Hiddify\Hiddify.exe not found).' }
        return [pscustomobject]@{ Profile = $Name; Type = 'hiddify'; Server = ''; Port = 443; Username = ''; ServerIps = @(); Auth = $false; Dco = $false }
    }
    if ($Kind -eq 'wireguard') {
        if ($WgConf) {
            $r = Test-VeroWireGuardConf -Text ([IO.File]::ReadAllText($WgConf))
            if ($r.Errors.Count -gt 0) { throw ("WireGuard config refused: {0}" -f ($r.Errors -join '; ')) }
            foreach ($w in $r.Warnings) { Write-Warning $w }
            if (-not $Srv) { $Srv = $r.Server }; if (-not $Prt) { $Prt = $r.Port }
        }
        if (-not $Srv) { throw 'A WireGuard profile needs -Server (its endpoint) or -WireGuardConfig <file.conf>.' }
        if (-not $Prt) { $Prt = 51820 }
        return [pscustomobject]@{ Profile = $Name; Type = 'wireguard'; Server = $Srv; Port = $Prt; Username = ''; ServerIps = @(); Auth = $false; Dco = $false }
    }
    # Windows VPN: imported from the Windows profile - server, port, protocol and sign-in come from there
    $w = Get-VeroWindowsVpn -Name $Name
    if ($w) {
        $e = ConvertTo-VeroRasEntry -Vpn $w -UserName $(if ($User) { $User } else { Get-VeroRasSavedUser -Name $Name -AllUsers $w.AllUsers })
        if ($Srv) { $e.Server = $Srv }; if ($Prt) { $e.Port = $Prt }
        Write-Host ("imported from Windows: '{0}' - {1}" -f $Name, (Get-VeroRasDescription -TunnelType $w.TunnelType -Password $w.Password -AllUsers $w.AllUsers))
        if ($e.Auth -and -not $e.Username) { $e.Username = Read-Host "VPN username for '$Name'" }
        return $e
    }
    if (-not $Srv -or -not $User) { throw "No Windows VPN profile named '$Name' - create it in Settings > VPN first (or give -Server and -UserName)." }
    [pscustomobject]@{ Profile = $Name; Type = 'ras'; Server = $Srv; Port = $(if ($Prt) { $Prt } else { 443 }); Username = $User; ServerIps = @(); Auth = $true; Dco = $false }
}
# --- config
if (-not (Test-Path $p.Config)) {
    if ($Type -eq 'ras' -and -not $ProfileName) {
        $profiles = @(Get-VeroWindowsVpn | ForEach-Object Name)
        Write-Host "Windows VPN profiles found: $($profiles -join ', ')"
        $ProfileName = Read-Host 'VPN profile name (exactly as in Windows Settings)'
    }
    if (-not $ProfileName) { $ProfileName = Read-Host 'Profile name' }
    $entry = New-ProfileEntry -Name $ProfileName -Kind $Type -Srv $Server -Prt $Port -User $UserName -Ovpn $OpenVpnConfig -WgConf $WireGuardConfig -KeepDco $Dco.IsPresent
    $json = [ordered]@{ profiles = @(ConvertTo-VeroProfileObject $entry); activeProfile = $ProfileName
               retrySeconds = 10; vm = $true; wifiRecoveryFix = $true; updateCheck = $true; lanAllow = @() } | ConvertTo-Json -Depth 5
    Save-VeroConfig -Json $json | Out-Null
    Write-Host "config written: $($p.Config)"
} else {
    $raw = Get-Content $p.Config -Raw
    $cfg = Get-VeroConfig -Raw $raw
    $obj = $raw | ConvertFrom-Json
    if ($ProfileName -and @($cfg.Profiles | ForEach-Object Profile) -notcontains $ProfileName) {
        $cfg.Profiles = @($cfg.Profiles) + (New-ProfileEntry -Name $ProfileName -Kind $Type -Srv $Server -Prt $Port -User $UserName -Ovpn $OpenVpnConfig -WgConf $WireGuardConfig -KeepDco $Dco.IsPresent)
        Save-VeroConfig -Json (ConvertTo-VeroConfigJson $cfg) | Out-Null
        Write-Host "profile added: $ProfileName ($(Get-VeroTypeLabel $Type))"
    } elseif ($ProfileName -and $Type -eq 'openvpn' -and $OpenVpnConfig) {
        $r = Import-VeroOpenVpnProfile -ProfileName $ProfileName -Source $OpenVpnConfig              # re-import an updated .ovpn
        foreach ($w in $r.Warnings) { Write-Warning $w }
        Write-Host "OpenVPN config re-imported: $ProfileName"
    } elseif ($obj.PSObject.Properties['vpn']) {
        Save-VeroConfig -Json (ConvertTo-VeroConfigJson $cfg) | Out-Null        # 1.0 single-profile file -> profiles list
        Write-Host 'config converted to the profiles format'
    }
}
$config = Get-VeroConfig
foreach ($pr in $config.Profiles) {
    switch ($pr.Type) {
        'openvpn' {
            if (-not (Get-VeroOpenVpnExe)) { Write-Warning "OpenVPN profile '$($pr.Profile)': openvpn.exe not found - install OpenVPN (community edition)." }
            elseif (-not $pr.Dco) {
                if (Initialize-VeroOpenVpnAdapter -Action 'install') { Write-Host "OpenVPN adapter: 'VeroScudo OpenVPN' (used only by VeroScudo's OpenVPN profiles)" }
                else { Write-Warning "OpenVPN profile '$($pr.Profile)': no 'VeroScudo OpenVPN' adapter could be created - OpenVPN will use any free TAP adapter (see the log)." }
            }
            if (-not (Test-Path (Get-VeroPath -VpnProfile $pr.Profile).OvpnConfig)) { Write-Warning "OpenVPN profile '$($pr.Profile)' is not imported - run Install.ps1 -ProfileName '$($pr.Profile)' -Type openvpn -OpenVpnConfig <file>." }
        }
        'wireguard' {
            if (-not (Test-Path (Join-Path (Get-VeroSystemDir ProgramFiles) "WireGuard\Data\Configurations\$($pr.Profile).conf.dpapi"))) {
                Write-Warning "WireGuard profile '$($pr.Profile)': no such tunnel in the WireGuard app - import it there under exactly this name."
            }
        }
        default {
            if (-not (Get-VeroWindowsVpn -Name $pr.Profile)) {
                Write-Warning "No Windows VPN profile named '$($pr.Profile)' exists for this user. Create it in Settings > VPN first."
            }
        }
    }
    $n = Get-VeroSwitchNotice -Type $pr.Type -ProfileName $pr.Profile
    if ($n) { Write-Host "NOTE: $n" }
}

# --- stop what runs the old code (the tray holds its images open, the watchdog loop holds the module)
$Folder = '\VeroScudo\'
Get-ScheduledTask -TaskPath $Folder -ErrorAction SilentlyContinue | Stop-ScheduledTask -ErrorAction SilentlyContinue
$old = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" | Where-Object { $_.CommandLine -match 'VeroScudo(Tray)?\.ps1' -and $_.ProcessId -ne $PID })
foreach ($t in $old) { Stop-Process -Id $t.ProcessId -Force -ErrorAction SilentlyContinue }
if ($old) { Wait-Process -Id $old.ProcessId -Timeout 10 -ErrorAction SilentlyContinue; Write-Host "stopped $($old.Count) running VeroScudo process(es)" }

# --- the native helper must be replaceable: a PowerShell window that ran VeroScudo.ps1 from the install folder keeps the
# old DLL loaded (and locked) until it is closed. Checked BEFORE anything is copied, so a failed install changes nothing.
$oldDll = Join-Path $InstallDir 'VeroScudo.Native.dll'
if (Test-Path -LiteralPath $oldDll) {
    $locked = $true
    for ($i = 0; $i -lt 15 -and $locked; $i++) {                            # processes stopped just above need a moment to exit
        try { $fs = [IO.File]::Open($oldDll, 'Open', 'ReadWrite', 'None'); $fs.Close(); $locked = $false } catch { Start-Sleep -Seconds 1 }
    }
    if ($locked) {
        $mine = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { try { $_.Location -eq $oldDll } catch { $false } }
        $holders = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { try { @($_.Modules | Where-Object FileName -eq $oldDll).Count -gt 0 } catch { $false } })
        $ps = @(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe' OR Name = 'pwsh.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.ProcessId -ne $PID })
        $who = if ($mine) { 'THIS PowerShell window (it ran VeroScudo from the install folder)' }
               elseif ($holders) { ($holders | ForEach-Object { "$($_.ProcessName) (PID $($_.Id))" }) -join ', ' }
               elseif ($ps) { 'another process - probably one of these PowerShell windows: ' + (($ps | ForEach-Object { "PID $($_.ProcessId)" }) -join ', ') }
               else { 'another process' }
        throw "The installed native helper is in use by $who. Close that PowerShell window (or run Install.ps1 from a fresh one) and try again - nothing was changed."
    }
}

# --- program files
foreach ($f in 'VeroScudo.Core.psm1', 'VeroScudo.Tray.psm1', 'VeroScudo.Native.cs', 'VeroScudo.Tray.cs', 'VeroScudo.ps1', 'VeroScudoTray.ps1', 'run.vbs', 'Set-VpnCredential.ps1', 'Uninstall.ps1', 'config.example.json') {
    Copy-Item (Join-Path $Src $f) (Join-Path $InstallDir $f) -Force
}
# the module's parts (Core\*.ps1): the module lists the files it loads, so copy exactly those
New-Item -ItemType Directory -Path (Join-Path $InstallDir 'Core') -Force | Out-Null
foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $Src 'Core') -Filter '*.ps1' | ForEach-Object Name)) {
    Copy-Item (Join-Path $Src "Core\$f") (Join-Path $InstallDir "Core\$f") -Force
}
# compile the native helper once (a child process: this session already loaded the same types from source)
$dll = Join-Path $InstallDir 'VeroScudo.Native.dll'
$compileStart = Get-Date
if (Test-Path -LiteralPath $dll) { Remove-Item -LiteralPath $dll -Force }   # no SilentlyContinue: a locked old DLL must stop the install
$q = { param($s) $s -replace "'", "''" }                                                   # a quote in a path must not end the string
$compile = "Add-Type -TypeDefinition ([IO.File]::ReadAllText('$(& $q "$InstallDir\VeroScudo.Native.cs")')) -Language CSharp -OutputAssembly '$(& $q $dll)' -OutputType Library"
& "$Sys\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command $compile
# a DLL that is not brand new is the OLD one: never report INSTALL OK with a helper that does not match the scripts
if (-not (Test-Path -LiteralPath $dll) -or (Get-Item -LiteralPath $dll).LastWriteTime -lt $compileStart.AddSeconds(-2)) { throw "native helper was not compiled: $dll" }
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

# --- scheduled tasks: for the signed-in user, who must be the account that elevated. With over-the-shoulder UAC (a standard
# user typing an administrator's password) this session runs as that administrator: the tasks, the tray, the shortcuts and
# the DPAPI credential would belong to two different accounts, and the real user would get no redial and no tray. The guard
# tasks run elevated, so the signed-in user has to be an administrator in the first place.
$user      = "$env:USERDOMAIN\$env:USERNAME"
$console   = [string](Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).UserName
if ($console -and $console -ne $user) {
    throw "signed in as '$console', but this elevated session runs as '$user'. VeroScudo's tasks and tray must belong to the signed-in user, and the guard tasks need an administrator account: sign in as an administrator (or make '$console' one) and run Install.ps1 again."
}
$guard     = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$limited   = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited      # the tray needs no admin rights
$settings  = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) `
                -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Hidden
function Act([string]$a) { New-ScheduledTaskAction -Execute "$Sys\wscript.exe" -Argument "//B //Nologo `"$InstallDir\run.vbs`" $a" }
function EventTrigger([string]$query) {
    $t = New-CimInstance -CimClass (Get-CimClass MSFT_TaskEventTrigger root/Microsoft/Windows/TaskScheduler) -ClientOnly
    $t.Subscription = $query; $t.Enabled = $true; $t
}
# any VPN: the guard itself decides from the event which profile it was (several profiles can be configured)
$connected  = EventTrigger "<QueryList><Query Id=`"0`" Path=`"System`"><Select Path=`"System`">*[System[Provider[@Name='RasMan'] and EventID=20267]]</Select></Query></QueryList>"
# IKEv2 connects log only RasClient 20225 (Application log): a second trigger; the guard checks the tunnel is really up
$connectedIke = EventTrigger "<QueryList><Query Id=`"0`" Path=`"Application`"><Select Path=`"Application`">*[System[Provider[@Name='RasClient'] and EventID=20225]]</Select></Query></QueryList>"
$terminated = EventTrigger "<QueryList><Query Id=`"0`" Path=`"Application`"><Select Path=`"Application`">*[System[Provider[@Name='RasClient'] and EventID=20226]]</Select></Query></QueryList>"
# the network itself dropped (Wi-Fi off, cable out): logged at once - unlike a dead VPN, which RAS reports seconds after the
# network is back. Blocks Hyper-V Default Switch VMs right away (Invoke-VeroActionNetDown).
$netDown    = EventTrigger "<QueryList><Query Id=`"0`" Path=`"Microsoft-Windows-NetworkProfile/Operational`"><Select Path=`"Microsoft-Windows-NetworkProfile/Operational`">*[System[EventID=10001]]</Select></Query></QueryList>"
$everyMin   = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
$atLogon    = New-ScheduledTaskTrigger -AtLogOn -User $user
$tasks = @(
    @{ Name = 'Connected';  Action = (Act 'arm');      Trigger = @($connected, $connectedIke);          P = $guard; Desc = 'VPN connected -> arm kill-switch' }
    @{ Name = 'Terminated'; Action = (Act 'on-event'); Trigger = @($terminated);         P = $guard; Desc = 'VPN terminated -> user hung up: disarm / else: reconnect' }
    @{ Name = 'NetDown';    Action = (Act 'netdown');  Trigger = @($netDown);            P = $guard; Desc = 'network disconnected -> block Hyper-V VMs until the tunnel works again' }
    @{ Name = 'Watchdog';   Action = (Act 'watchdog'); Trigger = @($everyMin, $atLogon); P = $guard; Desc = 'keeps the kill-switch exact every 15 s; restarted within a minute if it stops' }
    @{ Name = 'On';         Action = (Act 'on');       Trigger = @();                    P = $guard; Desc = 'manual: arm + connect' }
    @{ Name = 'OnDisconnect'; Action = (Act 'on-disconnect'); Trigger = @();             P = $guard; Desc = 'tray: end the other connected VPNs (you chose it), then arm + connect' }
    @{ Name = 'OnForce';    Action = (Act 'on-force'); Trigger = @();                    P = $guard; Desc = 'tray: arm + connect although another VPN is connected (you chose it)' }
    @{ Name = 'Off';        Action = (Act 'off');      Trigger = @();                    P = $guard; Desc = 'manual: disarm + disconnect' }
    @{ Name = 'Switch';     Action = (Act 'switch');   Trigger = @();                    P = $guard; Desc = 'switch the VPN profile requested by the tray' }
    @{ Name = 'Reconnect';  Action = (Act 'reconnect'); Trigger = @();                   P = $guard; Desc = 'manual: block, hang up, redial; traffic again once the tunnel is back' }
    @{ Name = 'OpenVPN';    Action = (Act 'openvpn');  Trigger = @();                    P = $guard; Desc = 'runs openvpn.exe for an OpenVPN profile while VeroScudo is on (started by the guard)' }
)
if (-not $NoTray) {
    $trayAction = New-ScheduledTaskAction -Execute "$Sys\wscript.exe" -Argument "//B //Nologo `"$InstallDir\run.vbs`" tray"
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
        $lnk.TargetPath = "$Sys\schtasks.exe"; $lnk.Arguments = "/run /tn `"$Folder$($s.T)`""
        $lnk.WindowStyle = 7; if (Test-Path $s.I) { $lnk.IconLocation = $s.I }; $lnk.Save()
        Write-Host "shortcut: $($s.N)"
    }
    # Start menu entry for the tray: the only way back after "Exit tray" short of signing out. It runs the Tray task,
    # so the tray starts exactly as at sign-in; a second start while it runs exits quietly (single-instance mutex).
    if (-not $NoTray) {
        $lnk = $shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Programs')) 'VeroScudo.lnk'))
        $lnk.TargetPath = "$Sys\schtasks.exe"; $lnk.Arguments = "/run /tn `"$($Folder)Tray`""
        $lnk.WindowStyle = 7; $lnk.Description = 'Show the VeroScudo tray icon'
        if (Test-Path "$InstallDir\icons\app\app.ico") { $lnk.IconLocation = "$InstallDir\icons\app\app.ico" }; $lnk.Save()
        Write-Host 'shortcut: Start menu > VeroScudo (tray)'
    }
}
schtasks /run /tn "$Folder`Watchdog" | Out-Null
if (-not $NoTray) { schtasks /run /tn "$Folder`Tray" | Out-Null }
Write-Host ''
Write-Host "INSTALL OK ($(Get-VeroVersion)).  Next: store the VPN password once per profile - tray > Settings, or"
Write-Host "            powershell -ExecutionPolicy Bypass -File `"$InstallDir\Set-VpnCredential.ps1`""
Write-Host '            then connect the VPN (Settings, or the "VeroScudo On" shortcut).'
