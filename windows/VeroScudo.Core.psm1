#Requires -Version 5.1
<#
  VeroScudo - Master the switch.          https://github.com/GomelHawk/VeroScudo
  Windows core module. See docs/ARCHITECTURE.md for the contract this implements and docs/SECURITY.md for the threat model.

  Pure functions (unit-tested): Get-VeroConfig, Get-VeroDecision, Get-VeroFilterSpec, Get-VeroPath, Test-VeroCidr,
  Test-VeroReleaseUrl, Test-VeroNewerVersion, Get-VeroRasVerdict, the profile-type checks (Test-VeroOpenVpnConf,
  Test-VeroWireGuardConf), the OpenVPN management parser and the WireGuard health / transition rules.
  Everything else talks to Windows (WFP, RAS, OpenVPN, WireGuard, event log, Hyper-V firewall) and is exercised by tests-local/.

  Profile types (docs/ARCHITECTURE.md, "Profile types"): 'ras' = the Windows built-in VPN client (default, stable),
  'openvpn' = an openvpn.exe that VeroScudo starts and owns through its management interface, 'wireguard' = a tunnel
  service of the WireGuard for Windows app.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Version      = '1.3.0'
$script:LegacyGroup  = 'VeroScudo'                                       # Windows Firewall rule group of 1.0.x (migrated away)
$script:VmRule       = 'VeroScudo-WSL'
$script:WslCreator   = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'          # Hyper-V firewall VM creator id of WSL
# System folders come from the OS, never from environment variables: the guard runs elevated, and a non-admin process can
# plant %ProgramFiles%, %ProgramData% or %SystemRoot% in HKCU\Environment (the SilentCleanup-style UAC bypass).
function Get-VeroSystemDir {
    [CmdletBinding()] param([ValidateSet('System', 'ProgramFiles', 'ProgramData')][string]$Kind)
    $sys = [Environment]::SystemDirectory                                   # GetSystemDirectory(): not the environment
    if (-not $sys) { $sys = 'C:\Windows\System32' }                        # (non-Windows dev harness only)
    if ($Kind -eq 'System') { return $sys }
    $drive = try { [IO.Path]::GetPathRoot($sys).TrimEnd('\') } catch { 'C:' }
    $key, $name = if ($Kind -eq 'ProgramFiles') { 'SOFTWARE\Microsoft\Windows\CurrentVersion', 'ProgramFilesDir' } else { 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList', 'ProgramData' }
    try {
        $rk = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($key)
        if ($rk) {
            $v = [string]$rk.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames); $rk.Close()
            if ($v) { return ($v -replace '(?i)%SystemDrive%', $drive) }
        }
    } catch { Write-Verbose "registry: $($_.Exception.Message)" }
    if ($Kind -eq 'ProgramFiles') { $drive + '\Program Files' } else { $drive + '\ProgramData' }
}
# exactly the spelling of 1.2.1 (C:\WINDOWS\System32\svchost.exe), which is live-verified - only the root comes from the OS now
$script:Svchost      = ((Get-VeroSystemDir System) -replace '\\[^\\]+$', '') + '\System32\svchost.exe'
$script:Rasdial      = (Get-VeroSystemDir System) + '\rasdial.exe'            # elevated callers: never resolved by name
$script:Schtasks     = (Get-VeroSystemDir System) + '\schtasks.exe'
$script:HomeOverride = $null                                            # tests only (Set-VeroHome); never read from the environment
$script:UserOverride = $null                                            # tests only (Set-VeroHome -UserDir)
$script:ReleasePrefix = 'https://github.com/GomelHawk/VeroScudo/releases/'
$script:Types        = @('ras', 'openvpn', 'wireguard')
$script:WgStaleSeconds = 180                                            # WireGuard re-handshakes every 2 min on a live link
$script:WgGraceSeconds = 30                                             # a just-started tunnel has not handshaken yet

# ---------------------------------------------------------------- native helpers (WFP, RasDial, LUIDs)
function Import-VeroNative {
    if ('VeroScudo.Wfp' -as [type]) { return }
    $dll = Join-Path $PSScriptRoot 'VeroScudo.Native.dll'
    try {
        # loaded from its BYTES, not as a file: Smart App Control refuses to map the locally compiled, unsigned DLL as an
        # image (Code Integrity 3077, seen live 2026-11-03), while an assembly loaded from memory is not checked that way -
        # the same way the tray's own Add-Type helpers load. It also leaves the file unlocked, so a reinstall can replace it.
        # The file sits in Program Files (administrators only), so its bytes are as trusted as the file was.
        if (Test-Path $dll) { [void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes($dll)) }
        else { Add-Type -TypeDefinition (Get-Content (Join-Path $PSScriptRoot 'VeroScudo.Native.cs') -Raw) -Language CSharp }
        if (-not ('VeroScudo.Wfp' -as [type])) { throw "native helper loaded, but its types are missing: $dll" }
    } catch { $script:NativeLoadFailed = $true; throw }                    # see "the native helper blocked by Windows"
}
# ---------------------------------------------------------------- the native helper blocked by Windows (Smart App Control)
# A process that failed to load VeroScudo.Native.dll keeps failing for its whole life (.NET remembers the failed load), so
# the long-running watchdog exits on such a failure and is started fresh by its task - with a growing wait, so a one-off
# block heals in about a minute and a lasting one is retried every 10 minutes without filling the log.
$script:NativeLoadFailed = $false
function Get-VeroNativeRetrySeconds {
    <# Pure: wait before the next try after the Nth failed load in a row: 1, 5, then 10 minutes. #>
    [CmdletBinding()] param([int]$Count)
    if ($Count -le 1) { 60 } elseif ($Count -eq 2) { 300 } else { 600 }
}
function Get-VeroNativeBlocked {
    $f = (Get-VeroPath).NativeBlocked
    if (Test-Path $f) { try { return (Get-Content $f -Raw | ConvertFrom-Json) } catch { Write-Verbose 'native-blocked unreadable' } }
    $null
}
function Set-VeroNativeBlocked {
    [CmdletBinding()] param([string]$Message, [string]$Action = 'core', [switch]$FromTask)
    # -FromTask (On, Off, events...): recorded for the tray, but neither counted nor delaying the watchdog's next try
    $old = Get-VeroNativeBlocked
    $count = if ($FromTask) { $(if ($old) { [int]$old.Count } else { 0 }) } elseif ($old) { [int]$old.Count + 1 } else { 1 }
    $wait = if ($FromTask) { 0 } else { Get-VeroNativeRetrySeconds $count }
    $now = Get-Date
    @{ First = $(if ($old) { [string]$old.First } else { $now.ToString('o') }); Last = $now.ToString('o'); Count = $count
       Next = $(if ($FromTask -and $old) { [string]$old.Next } else { $now.AddSeconds($wait).ToString('o') }); Message = $Message } | ConvertTo-Json | Set-Content (Get-VeroPath).NativeBlocked
    Write-VeroLog ("ERROR: Windows blocked VeroScudo's native helper (Smart App Control or App Control: {0}). The kill-switch filters stay in place; self-repair and automatic redial are paused - next try at {1:HH:mm} (failure {2} in a row)." -f $Message, $now.AddSeconds($wait), $count) $Action
}
function Clear-VeroNativeBlocked {
    [CmdletBinding()] param([string]$Action = 'core')
    $f = (Get-VeroPath).NativeBlocked
    if (Test-Path $f) { Remove-Item $f -Force; Write-VeroLog 'native helper loads again - self-repair and automatic redial are back' $Action }
}
function Test-VeroNativeRetryDue {
    <# Pure apart from the clock: may a fresh watchdog try again now? #>
    [CmdletBinding()] param($Blocked, [datetime]$Now = (Get-Date))
    if (-not $Blocked -or -not [string]$Blocked.Next) { return $true }
    $Now -ge [datetime]::Parse([string]$Blocked.Next, $null, [Globalization.DateTimeStyles]::RoundtripKind)
}


# ---------------------------------------------------------------- paths & config
function Set-VeroHome {
    <# Points the state/config home somewhere else - for tests. Deliberately NOT an environment variable: the guard runs
       elevated, and a value a non-admin process can plant (HKCU\Environment) must never redirect it. #>
    [CmdletBinding()] param([string]$Path, [string]$UserDir)
    $script:HomeOverride = $Path
    $script:UserOverride = $UserDir
}

function Get-VeroSafeName([string]$Name) {
    $clean = ($Name -replace '[^A-Za-z0-9_.-]', '_')
    $sha = [Security.Cryptography.SHA256]::Create()
    $hash = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Name))[0..3] | ForEach-Object { $_.ToString('x2') })
    '{0}-{1}' -f $clean.Substring(0, [Math]::Min(40, $clean.Length)), $hash
}

function Get-VeroPath {
    [CmdletBinding()] param([string]$VpnProfile)
    $home_ = if ($script:HomeOverride) { $script:HomeOverride } else { ((Get-VeroSystemDir ProgramData) + '\VeroScudo') }
    $state = Join-Path $home_ 'state'
    $user  = if ($script:UserOverride) { $script:UserOverride } else { Join-Path $env:LOCALAPPDATA 'VeroScudo' }
    $p = [pscustomobject]@{
        Home          = $home_
        Config        = Join-Path $home_ 'config.json'
        State         = $state
        ArmedFlag     = Join-Path $state 'armed.flag'
        ActiveProfile = Join-Path $state 'active-profile'
        Lock          = Join-Path $state 'reconnect.lock'
        WfpState      = Join-Path $state 'wfp.json'
        Emergency     = Join-Path $state 'emergency.flag'
        FwBackup      = Join-Path $state 'fw-original.json'
        VmBackup      = Join-Path $state 'vm-original.json'
        Log           = Join-Path $state 'veroscudo.log'
        Renew         = Join-Path $state 'renew.json'
        Conflicts     = Join-Path $state 'conflicts.json'
        NativeBlocked = Join-Path $state 'native-blocked.json'             # Windows refused to load VeroScudo.Native.dll
        OffAt         = Join-Path $state 'off-at.txt'                      # when you last pressed Off
        CrlWindow     = Join-Path $state 'crl-window.json'                 # SSTP revocation check: TCP 80 briefly allowed
        RasCoId       = Join-Path $state 'ras-coid.json'                   # connection id of the connect VeroScudo saw (System log)
        OnRefused     = Join-Path $state 'on-refused.json'                 # On refused: another VPN is connected (the tray says so)
        Foreign       = Join-Path $state 'foreign.json'                    # a VPN that is not a VeroScudo profile connected while armed
        OpenVpnDir    = Join-Path $home_ 'openvpn'
        UserDir       = $user
        SwitchRequest = Join-Path $user 'switch.request'
        UpdateFile    = Join-Path $user 'update.json'
        LegacyCred    = Join-Path $user 'cred.xml'
        Cred          = $null
        ServerIp      = $null
        KeyPass       = $null; Otp = $null; AuthFail = $null; TunnelCache = $null; EndpointCache = $null
        OvpnConfig    = $null; OvpnStatus = $null; OvpnStop = $null; OvpnLog = $null; OvpnPw = $null
    }
    if ($VpnProfile) {
        $safe = Get-VeroSafeName $VpnProfile
        $p.Cred = Join-Path $user "cred-$safe.xml"
        $p.KeyPass = Join-Path $user "keypass-$safe.xml"                  # OpenVPN private-key passphrase (optional)
        $p.Otp = Join-Path $user "otp-$safe.txt"                          # one-time code typed into the tray, read once by the runner
        $p.ServerIp = Join-Path $state "server-$safe.ip"
        $p.EndpointCache = Join-Path $state "server-$safe.json"           # OpenVPN: host -> addresses, for every 'remote'
        $p.AuthFail = Join-Path $state "authfail-$safe.flag"
        $p.TunnelCache = Join-Path $state "tunnel-$safe.json"             # WireGuard health, written elevated, read by the tray
        $p.OvpnConfig = Join-Path (Join-Path $home_ 'openvpn') "$safe.ovpn"   # admin-only copy made at import
        $p.OvpnStatus = Join-Path $state "ovpn-$safe.json"
        $p.OvpnStop = Join-Path $state "ovpn-$safe.stop"
        $p.OvpnLog = Join-Path (Join-Path $home_ 'openvpn') "$safe.log"     # administrators only (it names servers and users)
        $p.OvpnPw = Join-Path $state "ovpn-$safe.pw"
    }
    $p
}

function Test-VeroCidr {
    <# A single address or CIDR that is narrow enough to be a LAN, never "everything". Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    $ip = $Value; $prefix = $null
    if ($Value -match '^([^/]+)/(\d{1,3})$') { $ip = $Matches[1]; $prefix = [int]$Matches[2] }
    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$addr)) { return $false }
    if ($ip -notmatch '^[0-9a-fA-F:.]+$') { return $false }                  # TryParse also accepts "1" or "0x1"
    $v4 = $addr.AddressFamily -eq 'InterNetwork'
    if ($v4 -and $ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $false }
    if ($null -eq $prefix) { $prefix = if ($v4) { 32 } else { 128 } }
    if ($v4) { return ($prefix -ge 8 -and $prefix -le 32) }
    return ($prefix -ge 16 -and $prefix -le 128)
}

function Test-VeroHost([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 253) { return $false }
    if ($Value -match '^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$') { return $true }
    $a = $null; return [System.Net.IPAddress]::TryParse($Value, [ref]$a)
}

function Get-VeroConfig {
    <# Reads config.json, applies defaults, validates every value, resolves the active profile.
       -Raw accepts JSON text (tests); -Active overrides the selection (tests, switch). #>
    [CmdletBinding()] param([string]$Path, [string]$Raw, [string]$Active)
    $paths = Get-VeroPath
    if (-not $Raw) {
        if (-not $Path) { $Path = $paths.Config }
        if (-not (Test-Path $Path)) { throw "VeroScudo config not found: $Path (run Install.ps1)" }
        $Raw = Get-Content $Path -Raw
    }
    $j = $Raw | ConvertFrom-Json
    function Get-Prop($o, $n) { if ($null -ne $o -and $o.PSObject.Properties[$n]) { $o.$n } else { $null } }

    # profiles: the 1.0 single "vpn" object is still accepted
    $rawProfiles = @(if (Get-Prop $j 'profiles') { $j.profiles } elseif (Get-Prop $j 'vpn') { $j.vpn })
    if ($rawProfiles.Count -eq 0) { throw 'config.json: vpn.profile is required (add a "profiles" list)' }
    $profiles = foreach ($p in $rawProfiles) {
        $name = [string](Get-Prop $p 'profile')
        if (-not $name) { throw 'config.json: vpn.profile is required' }
        if ($name.Length -gt 256 -or $name -match '[\x00-\x1f"*?\[\]<>|&]') { throw "config.json: invalid VPN profile name '$name'" }
        $type = ([string](Get-Prop $p 'type')).ToLowerInvariant()
        if (-not $type) { $type = 'ras' }
        if ($script:Types -notcontains $type) { throw "config.json: type must be 'ras', 'openvpn' or 'wireguard' (profile '$name')" }
        # WireGuard names its tunnel service after the tunnel: the same rule as the WireGuard app (and safe on a command line)
        if ($type -eq 'wireguard' -and $name -notmatch '^[A-Za-z0-9_=+.-]{1,32}$') { throw "config.json: a WireGuard tunnel name is 1-32 of A-Z a-z 0-9 _ = + . - (profile '$name')" }
        $server = [string](Get-Prop $p 'server')
        if (-not $server -and $type -ne 'openvpn') { throw "config.json: vpn.server is required (profile '$name')" }   # OpenVPN: the 'remote' lines
        if ($server -and -not (Test-VeroHost $server)) { throw "config.json: invalid server '$server' (profile '$name')" }
        $user = [string](Get-Prop $p 'username')
        $authSet = $null -ne (Get-Prop $p 'auth')
        if (-not $user -and $type -eq 'ras' -and -not ($authSet -and -not [bool]$p.auth)) { throw "config.json: vpn.username is required (profile '$name')" }
        if ($user.Length -gt 256 -or $user -match '[\x00-\x1f"]') { throw "config.json: invalid username (profile '$name')" }
        $defPort = switch ($type) { 'wireguard' { 51820 } 'openvpn' { 1194 } default { 443 } }
        $port = if ($null -ne (Get-Prop $p 'port')) { [int]$p.port } else { $defPort }
        if ($port -lt 1 -or $port -gt 65535) { throw "config.json: port must be 1-65535 (profile '$name')" }
        $pinned = @(Get-Prop $p 'serverIps' | Where-Object { $_ })
        foreach ($ip in $pinned) { $a = $null; if (-not [System.Net.IPAddress]::TryParse([string]$ip, [ref]$a)) { throw "config.json: invalid serverIps entry '$ip' (profile '$name')" } }
        $dco = [bool](Get-Prop $p 'dco')                                    # OpenVPN: keep the kernel data channel (no program-scoped permit)
        $auth = if ($null -ne (Get-Prop $p 'auth')) { [bool]$p.auth } else { $type -ne 'wireguard' }   # OpenVPN: the .ovpn asks for a password
        [pscustomobject]@{ Profile = $name; Type = $type; Server = $server; Port = $port; Username = $user; ServerIps = @($pinned | ForEach-Object { [string]$_ })
                           Dco = ($type -eq 'openvpn' -and $dco); Auth = ($type -ne 'wireguard' -and $auth) }
    }
    $profiles = @($profiles)
    $dupes = @($profiles | Group-Object Profile | Where-Object Count -gt 1)
    if ($dupes) { throw "config.json: profile '$($dupes[0].Name)' is listed twice" }

    $vm = if ($null -ne $j.PSObject.Properties['vm']) { $j.vm } else { 'auto' }
    if ($vm -is [string] -and $vm -ne 'auto') { throw "config.json: vm must be 'auto', true or false" }
    $retry = if ($j.PSObject.Properties['retrySeconds']) { [int]$j.retrySeconds } else { 10 }
    if ($retry -lt 3 -or $retry -gt 3600) { throw 'config.json: retrySeconds must be 3-3600' }
    $lan = @(if ($j.PSObject.Properties['lanAllow']) { $j.lanAllow } else { @() }) | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ }
    foreach ($c in $lan) { if (-not (Test-VeroCidr $c)) { throw "config.json: lanAllow '$c' is not a LAN range (IPv4 /8 or narrower, IPv6 /16 or narrower)" } }

    # active profile: explicit > runtime selection (state, written by the guard) > configured default > first
    $names = @($profiles | ForEach-Object Profile)
    $default = [string](Get-Prop $j 'activeProfile')
    if ($default -and $names -notcontains $default) { throw "config.json: activeProfile '$default' is not in profiles" }
    $selected = $null
    if ($Active) {
        if ($names -notcontains $Active) { throw "unknown VPN profile '$Active' (configured: $($names -join ', '))" }
        $selected = $Active
    } elseif (Test-Path $paths.ActiveProfile) {
        $s = (Get-Content $paths.ActiveProfile -Raw -ErrorAction SilentlyContinue)
        if ($s) { $s = $s.Trim() }
        if ($s -and $names -contains $s) { $selected = $s }
    }
    if (-not $selected) { $selected = if ($default) { $default } else { $names[0] } }
    $act = $profiles | Where-Object Profile -eq $selected | Select-Object -First 1

    [pscustomobject]@{
        Profiles        = $profiles
        DefaultProfile  = if ($default) { $default } else { $names[0] }
        Profile         = $act.Profile
        Type            = $act.Type
        Dco             = $act.Dco
        Auth            = $act.Auth
        Server          = $act.Server
        Port            = $act.Port
        Username        = $act.Username
        ServerIps       = $act.ServerIps
        RetrySeconds    = $retry
        Vm              = $vm
        WifiRecoveryFix = if ($j.PSObject.Properties['wifiRecoveryFix']) { [bool]$j.wifiRecoveryFix } else { $true }
        LanAllow        = @($lan)
        UpdateCheck     = if ($j.PSObject.Properties['updateCheck']) { [bool]$j.updateCheck } else { $true }
    }
}

function ConvertTo-VeroConfigJson {
    <# The canonical on-disk form of a config object (profiles list). #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config)
    [ordered]@{
        profiles        = @($Config.Profiles | ForEach-Object { ConvertTo-VeroProfileObject $_ })
        activeProfile   = $Config.DefaultProfile
        retrySeconds    = $Config.RetrySeconds
        vm              = $Config.Vm
        wifiRecoveryFix = $Config.WifiRecoveryFix
        updateCheck     = $Config.UpdateCheck
        lanAllow        = @($Config.LanAllow)
    } | ConvertTo-Json -Depth 6
}

function ConvertTo-VeroProfileObject {
    <# One profile entry in its on-disk form (shared by the installer, the tray and Save-VeroConfig). #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Entry)
    $type = if ($Entry.PSObject.Properties['Type'] -and $Entry.Type) { [string]$Entry.Type } else { 'ras' }
    $o = [ordered]@{ profile = $Entry.Profile }
    if ($type -ne 'ras') { $o.type = $type }
    if ($Entry.Server) { $o.server = $Entry.Server }
    if ($type -ne 'openvpn') { $o.port = $Entry.Port }
    if ($Entry.Username) { $o.username = $Entry.Username }
    if (@($Entry.ServerIps | Where-Object { $_ }).Count -gt 0) { $o.serverIps = @($Entry.ServerIps) }
    if ($type -eq 'ras' -and $Entry.PSObject.Properties['Auth'] -and -not $Entry.Auth) { $o.auth = $false }     # certificate sign-in
    if ($type -eq 'openvpn') {
        $o.auth = if ($Entry.PSObject.Properties['Auth']) { [bool]$Entry.Auth } else { $true }
        if ($Entry.PSObject.Properties['Dco'] -and $Entry.Dco) { $o.dco = $true }
    }
    $o
}

function Get-VeroTypeLabel {
    <# Human name of a profile type, as the tray and the log show it. #>
    [CmdletBinding()] param([string]$Type)
    switch ($Type) { 'openvpn' { 'OpenVPN' } 'wireguard' { 'WireGuard' } default { 'Windows VPN' } }
}

function Get-VeroSwitchNotice {
    <# The notice shown on every switch to a reserve type (tray balloon, command line, log). $null for the built-in client. Pure. #>
    [CmdletBinding()] param([string]$Type, [string]$ProfileName)
    switch ($Type) {
        'openvpn'   { "'$ProfileName' is an OpenVPN profile. VeroScudo controls this connection: don't connect or disconnect it from OpenVPN GUI - use VeroScudo's On, Off and Reconnect." }
        'wireguard' { "'$ProfileName' is a WireGuard profile. A dead WireGuard link is noticed after 1-3 minutes, not seconds; you stay blocked until it reconnects. Prefer a Windows VPN profile when you can." }
        default     { $null }
    }
}

function Get-VeroProfileType {
    <# The type of a configured profile; 'ras' for anything not configured (or no config yet). #>
    [CmdletBinding()] param([string]$ProfileName)
    try {
        $e = @((Get-VeroConfig).Profiles | Where-Object Profile -eq $ProfileName) | Select-Object -First 1
        if ($e) { return [string]$e.Type }
    } catch { Write-Verbose "config: $($_.Exception.Message)" }
    'ras'
}

$script:Elevated = $null
function Test-VeroElevated {
    if ($null -eq $script:Elevated) {
        try { $script:Elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
        catch { $script:Elevated = $false }
    }
    $script:Elevated
}

function Save-VeroConfig {
    <# Validates JSON text with the same rules as Get-VeroConfig and writes it atomically (admin). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Json)
    $cfg = Get-VeroConfig -Raw $Json
    $p = Get-VeroPath
    $tmp = "$($p.Config).new"
    ConvertTo-VeroConfigJson $cfg | Set-Content -Path $tmp -Encoding UTF8
    Move-Item $tmp $p.Config -Force
    $cfg
}

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

# ---------------------------------------------------------------- VPN status & events
function Get-VeroNic {
    <# .NET interface list: ~ms, where the equivalent CIM cmdlets cost hundreds of ms - this runs every 15 s. #>
    [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
}
function Get-VeroTunnelNic([string]$ProfileName) {
    Get-VeroNic | Where-Object { $_.Name -eq $ProfileName -and [string]$_.NetworkInterfaceType -eq 'Ppp' -and [string]$_.OperationalStatus -eq 'Up' } | Select-Object -First 1
}

function Test-VeroVpnConnected {
    <# Is the profile's tunnel really carrying traffic? RAS: the adapter / RAS says connected. OpenVPN: the daemon reported
       CONNECTED and that tunnel address sits on an up tunnel adapter. WireGuard: the service runs and the last handshake is
       fresh (a dead WireGuard link keeps its adapter up, so the adapter alone proves nothing). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName, [string]$Type)
    if (-not $Type) { $Type = Get-VeroProfileType $ProfileName }
    if ($Type -eq 'openvpn') { return [bool](Get-VeroOpenVpnNic $ProfileName) }
    if ($Type -eq 'wireguard') { return ((Get-VeroWgHealthNow $ProfileName) -eq 'up') }
    if (Get-VeroTunnelNic $ProfileName) { return $true }                  # fast path: the RAS adapter is up
    $c = Get-VpnConnection -Name $ProfileName -ErrorAction SilentlyContinue
    if (-not $c) { $c = Get-VpnConnection -Name $ProfileName -AllUserConnection -ErrorAction SilentlyContinue }
    if ($c) { return $c.ConnectionStatus -eq 'Connected' }
    return ((& $script:Rasdial) -join ' ') -match ('\b' + [regex]::Escape($ProfileName) + '\b')
}

function Get-VeroRasVerdict {
    <# Pure. From 20226 records {Profile; CoId; Code; Time} picks the newest and flags a conflict: RAS writes exactly one
       termination per connection (CoID), so two with different codes mean one of them was forged. #>
    [CmdletBinding()] param([object[]]$Records)
    $recs = @($Records | Where-Object { $_ })
    if ($recs.Count -eq 0) { return $null }
    $newest = $recs | Sort-Object Time -Descending | Select-Object -First 1
    $codes = @($recs | Where-Object CoId -eq $newest.CoId | ForEach-Object { [int64]$_.Code } | Select-Object -Unique)
    [pscustomobject]@{ Profile = $newest.Profile; CoId = $newest.CoId; Code = [int64]$newest.Code; Conflict = ($codes.Count -gt 1); Time = $newest.Time }
}

function Get-VeroRasTermination {
    [CmdletBinding()] param([int]$WithinMinutes = 2)
    $recs = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'RasClient'; Id = 20226
                                              StartTime = (Get-Date).AddMinutes(-60) } -ErrorAction SilentlyContinue |
        Where-Object { $_.Properties.Count -ge 4 } |
        ForEach-Object { [pscustomobject]@{ Profile = [string]$_.Properties[2].Value; CoId = [string]$_.Properties[0].Value; Code = $_.Properties[3].Value; Time = $_.TimeCreated } }
    $recent = @($recs | Where-Object Time -ge (Get-Date).AddMinutes(-$WithinMinutes))
    if ($recent.Count -eq 0) { return $null }
    $newest = $recent | Sort-Object Time -Descending | Select-Object -First 1
    Get-VeroRasVerdict -Records @($recs | Where-Object CoId -eq $newest.CoId)    # conflict check over the last hour
}

function Get-VeroRasConnected {
    <# Profile name of the newest "connected" event: RasMan 20267 (System log - not writable by ordinary users), else
       RasClient 20225 (Application log): an IKEv2 connect logs ONLY that one (seen live 2026-11-03). The Application log is
       user-writable, so the caller arms only when that profile really is connected - a forged record can at most turn
       VeroScudo on (the strict direction), never off. -Names: the configured profiles (to find the name in a 20225). #>
    [CmdletBinding()] param([int]$WithinMinutes = 2, [string[]]$Names = @())
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'RasMan'; Id = 20267
                                            StartTime = (Get-Date).AddMinutes(-$WithinMinutes) } -MaxEvents 1 -ErrorAction SilentlyContinue
    $r = Get-VeroRasClientConnect -WithinMinutes $WithinMinutes -Names $Names | Select-Object -First 1
    # the NEWER of the two: after a switch the System log still holds the old profile's connect (seen live 2026-11-03:
    # SSTP CorporateVPN in RasMan, then IKEv2 PrivateVPN only in RasClient - the old one was taken, the new one ignored)
    $rm = if ($ev -and $ev.Properties.Count -ge 3) { [pscustomobject]@{ Profile = [string]$ev.Properties[2].Value; Time = $ev.TimeCreated } } else { $null }
    if ($rm -and $r) { return $(if ($r.Time -gt $rm.Time) { $r.Profile } else { $rm.Profile }) }
    if ($rm) { return $rm.Profile }
    if ($r) { return $r.Profile }
    $null
}

function Get-VeroRasClientConnect {
    <# RasClient 20225 "connected" records (newest first) whose connection name is one of -Names: @{ Profile; CoId; Time }. #>
    [CmdletBinding()] param([int]$WithinMinutes = 60, [string[]]$Names = @())
    $evs = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'RasClient'; Id = 20225
                                               StartTime = (Get-Date).AddMinutes(-$WithinMinutes) } -MaxEvents 20 -ErrorAction SilentlyContinue)
    foreach ($e in $evs) {
        $vals = @($e.Properties | ForEach-Object { [string]$_.Value })
        $name = $vals | Where-Object { $Names -contains $_ } | Select-Object -First 1
        $coid = $vals | Where-Object { $_ -match '^\{[0-9A-Fa-f-]{36}\}$' } | Select-Object -First 1
        if ($name) { [pscustomobject]@{ Profile = $name; CoId = [string]$coid; Time = $e.TimeCreated } }
    }
}

function Get-VeroRasConnectedRecord {
    <# The newest RasMan "connected" (20267, System log - ordinary users cannot write it) for a profile, with its connection id
       (CoID). No time limit: it is the connection a later termination must belong to. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName, [switch]$AllowApplicationLog)
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'RasMan'; Id = 20267 } -MaxEvents 50 -ErrorAction SilentlyContinue |
          Where-Object { $_.Properties.Count -ge 3 -and [string]$_.Properties[2].Value -eq $ProfileName } | Select-Object -First 1
    $rm = if ($ev) { [pscustomobject]@{ Profile = $ProfileName; CoId = [string]$ev.Properties[0].Value; Time = $ev.TimeCreated } } else { $null }
    if (-not $AllowApplicationLog) { return $rm }
    # at arm only: IKEv2 has no RasMan record - take the RasClient 20225 of THIS connect (newer than any RasMan one)
    $rc = Get-VeroRasClientConnect -WithinMinutes 5 -Names @($ProfileName) | Where-Object { $_.CoId } | Select-Object -First 1
    if ($rc -and (-not $rm -or $rc.Time -gt $rm.Time)) { return $rc }
    $rm
}

function Get-VeroExpectedCoId {
    <# The connection ids a "you hung up" may name: the one recorded at arm AND the newest System-log connect of the profile -
       both are trusted sources (two connects within a second can leave the record one connection behind). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    $ids = @()
    $f = (Get-VeroPath).RasCoId
    if (Test-Path $f) { try { $j = Get-Content $f -Raw | ConvertFrom-Json; if ([string]$j.Profile -eq $ProfileName -and [string]$j.CoId) { $ids += [string]$j.CoId } } catch { Write-Verbose 'ras-coid unreadable' } }
    $r = Get-VeroRasConnectedRecord -ProfileName $ProfileName
    if ($r -and $r.CoId) { $ids += [string]$r.CoId }
    @($ids | Select-Object -Unique)
}

$script:LastDialCode = 0
function Test-VeroRecentOff {
    <# True for 30 s after your Off: a redial that was already running can still connect then - that is not you connecting. #>
    $f = (Get-VeroPath).OffAt
    if (-not (Test-Path $f)) { return $false }
    try { ((Get-Date) - [datetime]::Parse((Get-Content $f -Raw).Trim(), $null, [Globalization.DateTimeStyles]::RoundtripKind)).TotalSeconds -lt 30 } catch { $false }
}

function Save-VeroRasCoId {
    <# Records the connection id of the profile's newest connect (anti-forgery for a later "you hung up"). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    Start-Sleep -Milliseconds 500                                             # RAS writes the connect record right after it connects
    $rec = Get-VeroRasConnectedRecord -ProfileName $ProfileName -AllowApplicationLog
    if ($rec) { @{ Profile = $rec.Profile; CoId = $rec.CoId; Time = (Get-Date).ToString('o') } | ConvertTo-Json | Set-Content (Get-VeroPath).RasCoId }
}

function Invoke-VeroArmConnected {
    <# A Windows VPN profile connected by hand (any protocol): arm for it - the same steps from the Connected task and from the
       watchdog's own check, so the outcome never depends on which events a protocol logs. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'arm')
    $p = Get-VeroPath
    # an SSTP tunnel may still be checking its server certificate's revocation when the filters arrive
    if ((Get-VeroConfigType $Config) -eq 'ras' -and (Get-VeroTunnelType $Config.Profile) -in 'Sstp', 'Automatic') {
        Open-VeroCrlWindow -Action $Action -Reason 'SSTP tunnel just connected (revocation check may still run)'
    }
    # remember WHICH connection this is: a later "you hung up" must name the same connection id (anti-forgery)
    $rec = Get-VeroRasConnectedRecord -ProfileName $Config.Profile -AllowApplicationLog
    if ($rec) { @{ Profile = $rec.Profile; CoId = $rec.CoId; Time = (Get-Date).ToString('o') } | ConvertTo-Json | Set-Content $p.RasCoId }
    Update-VeroServerIpBeforeArm -Config $Config -Action $Action
    Set-VeroArmed $true $Action; Sync-VeroKillSwitch -Config $Config -Action $Action
}

function Update-VeroServerIpBeforeArm {
    <# Look the server name up NOW, while no filters are in force yet (not armed): the kill-switch then allows the address the
       tunnel really uses. A server that moved (seen live 2026-11-03: vpn.corp.example.com changed address, the cache still had
       the old one - the tunnel was cut 5 s after arming and every redial was refused) is picked up before it can bite. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core')
    if ((Test-VeroArmed) -or @($Config.ServerIps).Count -gt 0) { return }
    $before = @(Resolve-VeroServerIp -Config $Config -CacheOnly)
    $now = @(if ((Get-VeroConfigType $Config) -eq 'ras') { Resolve-VeroServerIp -Config $Config } else { Resolve-VeroEndpoint -Config $Config | ForEach-Object Ip })
    if (($now -join ',') -ne ($before -join ',')) { Write-VeroLog ("server '{0}' resolves to {1} now (cached: {2})" -f $Config.Server, ($now -join ','), $(if ($before) { $before -join ',' } else { 'none' })) $Action }
}

$script:RasSeen = @{}
function Update-VeroRasWatch {
    <# Watchdog: a configured Windows VPN profile that BECAME connected since the last pass (15 s) while it is not the armed,
       active one arms VeroScudo for it - for every protocol, whatever Windows logged (IKEv2 writes no RasMan 20267; a type may
       write neither event). Edges only: the first look after start changes nothing, and our own Off (disarm, then hang up)
       is a falling edge. True when it armed. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'watchdog')
    $up = @(Get-VeroNic | Where-Object { [string]$_.NetworkInterfaceType -eq 'Ppp' -and [string]$_.OperationalStatus -eq 'Up' } | ForEach-Object Name)
    $armedNow = $false
    foreach ($pr in @($Config.Profiles | Where-Object Type -eq 'ras')) {
        $cur = $up -contains $pr.Profile
        $prev = $script:RasSeen[$pr.Profile]
        $script:RasSeen[$pr.Profile] = $cur
        if ($null -eq $prev -or $prev -or -not $cur -or $armedNow) { continue }
        if ((Test-VeroArmed) -and $pr.Profile -eq $Config.Profile) { continue }      # already protected by it
        if (Test-VeroRecentOff) { continue }                                         # a redial finishing just after your Off
        if (Test-VeroLockAlive) { continue }                                         # our own redial / switch is running
        Write-VeroLog "Windows VPN '$($pr.Profile)' connected - kill-switch on for it (decision source: watchdog saw the tunnel come up)" $Action
        if ($pr.Profile -ne $Config.Profile) { Set-VeroActiveProfile -Name $pr.Profile -Action $Action }
        Invoke-VeroArmConnected -Config (Get-VeroConfig) -Action $Action
        $armedNow = $true
    }
    $armedNow
}

function Get-VeroRasCode {
    <# Reason code of the newest RasClient event (20226 terminated / 20227 dial failed) for this profile. -1 if none. #>
    [CmdletBinding()] param([Parameter(Mandatory)][int]$EventId, [Parameter(Mandatory)][string]$ProfileName, [int]$WithinMinutes = 5)
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'RasClient'; Id = $EventId
                                           StartTime = (Get-Date).AddMinutes(-$WithinMinutes) } -ErrorAction SilentlyContinue |
          Where-Object { $_.Properties.Count -ge 4 -and $_.Properties[2].Value -eq $ProfileName } |
          Sort-Object TimeCreated -Descending | Select-Object -First 1
    if ($ev) { return [int64]$ev.Properties[3].Value }
    return -1
}

function Get-VeroDecision {
    <# The one judgement the guard makes. 631 = "the user disconnected" (Windows RAS). #>
    [CmdletBinding()] param([Parameter(Mandatory)][int64]$ReasonCode, [Parameter(Mandatory)][bool]$Armed)
    if ($ReasonCode -eq 631) { return 'disarm' }
    if ($Armed) { return 'reconnect' }
    return 'none'
}

# ---------------------------------------------------------------- the kill-switch: WFP filter set
function Get-VeroFilterSpec {
    <# The allow-list (docs/ARCHITECTURE.md) as WFP filters. Pure: returns VeroScudo.FilterSpec[] for [VeroScudo.Wfp]::Apply.
       Every permit is scoped (interface, address, port or program); one catch-all BLOCK per layer catches the rest.
       DNS and certificate-revocation fetches are allowed ONLY while the tunnel is down (needed to redial) - while it is
       up, name resolution goes through the tunnel like everything else (no DNS leak to the local network). #>
    [CmdletBinding()] param(
        [Parameter(Mandatory)]$Config,
        [string[]]$ServerIps = @(),
        [uint64]$TunnelLuid = 0,
        [uint64]$WslLuid = 0,
        [string[]]$DnsServers = @(),
        [string]$TunnelType = 'Automatic',
        [string]$Svchost = $script:Svchost,
        [object[]]$Endpoints = $null,          # OpenVPN / WireGuard: @{ Ip; Proto (6|17); Port } - replaces the RAS ports above
        [string]$EndpointApp = '',             # OpenVPN without DCO: only openvpn.exe may reach them; '' = kernel socket (no program)
        [bool]$CrlWindow = $false              # SSTP only: a dial just failed on the certificate revocation check (see Open-VeroCrlWindow)
    )
    Import-VeroNative
    $C4 = [VeroScudo.Layer]::ConnectV4; $C6 = [VeroScudo.Layer]::ConnectV6
    $R4 = [VeroScudo.Layer]::RecvAcceptV4; $R6 = [VeroScudo.Layer]::RecvAcceptV6
    $specs = New-Object 'System.Collections.Generic.List[VeroScudo.FilterSpec]'
    $permit = [byte]8
    function New-Spec([string]$name, [guid]$layer, [bool]$allow, [byte]$weight) {
        $s = New-Object VeroScudo.FilterSpec($name, $layer, $allow, $weight); $specs.Add($s); $s
    }
    function Split-Family([string[]]$list) {
        $v4 = @(); $v6 = @()
        foreach ($a in $list) { if ($a -match ':') { $v6 += $a } else { $v4 += $a } }
        , @($v4, $v6)
    }

    foreach ($l in $C4, $C6, $R4, $R6) { $null = (New-Spec 'loopback' $l $true $permit).Loopback() }
    if ($TunnelLuid) { foreach ($l in $C4, $C6, $R4, $R6) { $null = (New-Spec 'VPN tunnel' $l $true $permit).Interface($TunnelLuid) } }
    if ($WslLuid)    { foreach ($l in $C4, $C6, $R4, $R6) { $null = (New-Spec 'WSL switch' $l $true $permit).Interface($WslLuid) } }

    # the VPN server: only the protocol/ports of the profile's tunnel type; TCP/UDP only from svchost (SstpSvc, IKEEXT, RasMan)
    if ($null -ne $Endpoints) { $ServerIps = @() }                          # reserve types: their own endpoints below
    $fam = Split-Family $ServerIps
    # IKEv2 data: Windows hands each packet of the tunnel to the firewall as an IP-in-IP flow to the server (protocol 4,
    # protocol 41 for IPv6 inside) before IPsec encrypts it. Without these the tunnel connects and carries nothing (seen live
    # 2026-11-03: 614 drops of protocol 4 to the server in a few seconds, every IKEv2 profile dead while armed).
    $ipInIp = @(@{ P = 4; Ports = @(); App = $false }, @{ P = 41; Ports = @(); App = $false })
    $parts = switch ($TunnelType) {
        'Sstp'  { @(@{ P = 6; Ports = @($Config.Port); App = $true }) }
        'Ikev2' { @(@{ P = 17; Ports = @(500, 4500); App = $false }, @{ P = 50; Ports = @(); App = $false }) + $ipInIp }
        'L2tp'  { @(@{ P = 17; Ports = @(500, 4500, 1701); App = $false }, @{ P = 50; Ports = @(); App = $false }) }
        'Pptp'  { @(@{ P = 6; Ports = @(1723); App = $false }, @{ P = 47; Ports = @(); App = $false }) }
        default { @(@{ P = 6; Ports = @($Config.Port); App = $true }, @{ P = 6; Ports = @(1723); App = $false },
                    @{ P = 17; Ports = @(500, 4500, 1701); App = $false }, @{ P = 50; Ports = @(); App = $false }, @{ P = 47; Ports = @(); App = $false }) + $ipInIp }
    }
    foreach ($pair in @(@($C4, $fam[0]), @($C6, $fam[1]))) {
        $layer = $pair[0]; $ips = @($pair[1])
        if ($ips.Count -eq 0) { continue }
        foreach ($pt in $parts) {
            $s = New-Spec "VPN server proto $($pt.P)" $layer $true $permit
            $null = $s.Protocol([byte]$pt.P)
            foreach ($port in $pt.Ports) { $null = $s.RemotePort([uint16]$port) }
            foreach ($ip in $ips) { $null = $s.Remote($ip) }
            if ($pt.App) { $null = $s.App($Svchost) }
        }
    }

    # OpenVPN / WireGuard: each server address only on its own protocol and port (one permit per protocol/port pair)
    if ($null -ne $Endpoints) {
        $groups = @($Endpoints | Where-Object { $_ -and $_.Ip } | Group-Object { '{0}/{1}' -f $_.Proto, $_.Port } | Sort-Object Name)
        foreach ($g in $groups) {
            $first = $g.Group[0]
            $ips = Split-Family @($g.Group | ForEach-Object { [string]$_.Ip } | Select-Object -Unique | Sort-Object)
            foreach ($pair in @(@($C4, $ips[0]), @($C6, $ips[1]))) {
                $layer = $pair[0]; $list = @($pair[1])
                if ($list.Count -eq 0) { continue }
                $s = (New-Spec "VPN server proto $($first.Proto)" $layer $true $permit).Protocol([byte]$first.Proto).RemotePort([uint16]$first.Port)
                foreach ($ip in $list) { $null = $s.Remote($ip) }
                if ($EndpointApp) { $null = $s.App($EndpointApp) }
            }
        }
    }

    # link maintenance: DHCP / DHCPv6 leases, IPv6 neighbour discovery on the link only
    foreach ($l in $C4, $R4) { $null = (New-Spec 'DHCP' $l $true $permit).Protocol(17).LocalPort(68).RemotePort(67).App($Svchost) }   # the DHCP client service only
    foreach ($l in $C6, $R6) { $null = (New-Spec 'DHCPv6' $l $true $permit).Protocol(17).LocalPort(546).RemotePort(547).App($Svchost) }
    foreach ($l in $C6, $R6) {
        $s = (New-Spec 'NDP' $l $true $permit).Protocol(58)
        foreach ($t in 133..137) { $null = $s.IcmpType([uint16]$t) }
        $null = $s.Remote('fe80::/10').Remote('ff02::/16')
    }

    if (-not $TunnelLuid) {
        # redial needs to resolve the server name: only through Windows' DNS client (svchost), only to the resolvers the
        # network handed out. No resolver known yet (link coming up) = no DNS permit at all, never "port 53 anywhere".
        $dns = Split-Family $DnsServers
        foreach ($pair in @(@($C4, $dns[0]), @($C6, $dns[1]))) {
            $layer = $pair[0]; $srv = @($pair[1])
            if ($srv.Count -eq 0) { continue }
            $s = (New-Spec 'DNS (redial)' $layer $true $permit).Protocol(17).Protocol(6).RemotePort(53).App($Svchost)
            foreach ($ip in $srv) { $null = $s.Remote($ip) }
        }
        # SSTP's certificate revocation check (HTTP to the CA's CRL/OCSP servers, anywhere): NOT open by default - BITS,
        # Delivery Optimization and WPAD share svchost.exe, so a standing "svchost may use TCP 80" permit is a side door.
        # Opened only for a short window after a dial failed on exactly that check (Open-VeroCrlWindow), SSTP profiles only.
        if ($CrlWindow -and $null -eq $Endpoints -and $TunnelType -in 'Sstp', 'Automatic') {
            foreach ($l in $C4, $C6) { $null = (New-Spec 'CRL (redial window)' $l $true $permit).Protocol(6).RemotePort(80).App($Svchost) }
        }
    }

    $lan = Split-Family $Config.LanAllow
    foreach ($c in $lan[0]) { foreach ($l in $C4, $R4) { $null = (New-Spec "LAN $c" $l $true $permit).Remote($c) } }
    foreach ($c in $lan[1]) { foreach ($l in $C6, $R6) { $null = (New-Spec "LAN $c" $l $true $permit).Remote($c) } }

    foreach ($l in $C4, $C6, $R4, $R6) { $null = New-Spec 'block everything else' $l $false 0 }
    , $specs.ToArray()
}

function Get-VeroSpecFingerprint([object[]]$Specs) {
    $text = ($Specs | ForEach-Object { $_.ToString() }) -join "`n"
    $sha = [Security.Cryptography.SHA256]::Create()
    -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) | ForEach-Object { $_.ToString('x2') })
}

function Resolve-VeroServerIp {
    <# Pinned serverIps win. Otherwise resolve and merge with the cache (newest first, at most 8): a VPN host that moves
       keeps working, and a lookup that fails while blocked still leaves the last known addresses.
       -CacheOnly: no lookup at all (the filters must never wait for DNS - see Sync-VeroKillSwitch). #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [switch]$CacheOnly)
    if (@($Config.ServerIps).Count -gt 0) { return @($Config.ServerIps) }
    $p = Get-VeroPath -VpnProfile $Config.Profile
    # [string]: Get-Content tags each line with its file path, and ConvertTo-Json would write those tags into wfp.json
    $cached = @(if (Test-Path $p.ServerIp) { Get-Content $p.ServerIp | Where-Object { $_ } | ForEach-Object { [string]$_ } })
    if ($CacheOnly) { return $cached }
    $fresh = @()
    try {
        $fresh = @([System.Net.Dns]::GetHostAddresses($Config.Server) | Where-Object { $_.AddressFamily -in 'InterNetwork', 'InterNetworkV6' -and -not $_.IsIPv6LinkLocal } |
                   ForEach-Object { $_.IPAddressToString })
    } catch { Write-Verbose "DNS lookup of $($Config.Server) failed: $($_.Exception.Message)" }
    $all = @(@($fresh) + @($cached) | Where-Object { $_ } | Select-Object -Unique | Select-Object -First 8)
    if ($all.Count -gt 0 -and (($all -join ',') -ne ($cached -join ','))) { Set-Content -Path $p.ServerIp -Value $all }
    return $all
}

function Get-VeroTunnelLuid {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName, [string]$Type)
    Import-VeroNative
    if (-not $Type) { $Type = Get-VeroProfileType $ProfileName }
    if ($Type -ne 'ras') {
        # only a tunnel adapter that is carrying the tunnel right now; never a physical NIC
        # WireGuard: allowed while its service runs, even before the first handshake - app traffic is what starts a handshake
        # when no keepalive is set; a dead tunnel only loses that traffic (its routes point into it), it never leaks
        $nic = if ($Type -eq 'openvpn') { Get-VeroOpenVpnNic $ProfileName } elseif ((Get-VeroWgState $ProfileName) -eq 'running') { Get-VeroWgNic $ProfileName }
        if ($nic) { return [VeroScudo.Iface]::LuidFromGuid([guid]$nic.Id) }
        return [uint64]0
    }
    $nic = Get-VeroTunnelNic $ProfileName
    if ($nic) { return [VeroScudo.Iface]::LuidFromGuid([guid]$nic.Id) }
    if (-not (Test-VeroVpnConnected $ProfileName)) { return [uint64]0 }
    $if = Get-NetIPInterface -InterfaceAlias $ProfileName -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $if) { return [uint64]0 }
    [VeroScudo.Iface]::LuidFromIndex([uint32]$if.ifIndex)
}

function Get-VeroWslLuid {
    $a = Get-VeroNic | Where-Object { $_.Name -like 'vEthernet (WSL*' -and [string]$_.OperationalStatus -eq 'Up' } | Select-Object -First 1
    if ($a) { Import-VeroNative; [VeroScudo.Iface]::LuidFromGuid([guid]$a.Id) } else { [uint64]0 }
}

function Get-VeroDnsServer {
    <# Resolvers of the physical links that are up (not the tunnel, not WSL): the only DNS destinations while blocked. #>
    [CmdletBinding()] param([string]$ProfileName)
    @(Get-VeroNic | Where-Object { [string]$_.OperationalStatus -eq 'Up' -and [string]$_.NetworkInterfaceType -notin 'Ppp', 'Loopback', 'Tunnel' -and
                                   $_.Name -notlike 'vEthernet*' -and $_.Name -ne $ProfileName -and -not (Test-VeroTunnelAdapter $_) } |
        ForEach-Object { $_.GetIPProperties().DnsAddresses } | ForEach-Object { ($_.ToString() -split '%')[0] } |
        Where-Object { $_ -and $_ -notlike 'fec0:0:0:ffff::*' } | Select-Object -Unique | Sort-Object)
}

function Get-VeroWindowsVpn {
    <# The Windows VPN profiles of this user AND those created for all users (IT, admin, rasphone "anyone's use"), with what
       VeroScudo needs from them: server, protocol (tunnel type) and whether they sign in with a password. #>
    [CmdletBinding()] param([string]$Name)
    $all = @(@(Get-VpnConnection -ErrorAction SilentlyContinue) + @(Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue)) | Where-Object { $_ }
    $seen = @{}
    foreach ($c in $all) {
        if ($seen.ContainsKey($c.Name) -or ($Name -and $c.Name -ne $Name)) { continue }
        $seen[$c.Name] = $true
        $xml = if ($c.PSObject.Properties['EapConfigXmlStream'] -and $c.EapConfigXmlStream) { [string]$c.EapConfigXmlStream.OuterXml } else { '' }
        [pscustomobject]@{
            Name       = [string]$c.Name
            Server     = [string]$c.ServerAddress
            TunnelType = if ($c.TunnelType) { [string]$c.TunnelType } else { 'Automatic' }
            Password   = Test-VeroRasPassword -AuthMethods @($c.AuthenticationMethod | ForEach-Object { [string]$_ }) -EapXml $xml
            AllUsers   = [bool]($c.PSObject.Properties['AllUserConnection'] -and $c.AllUserConnection)
            Connected  = [string]$c.ConnectionStatus -eq 'Connected'
        }
    }
}

function Split-VeroServerAddress {
    <# Pure: a Windows VPN server address -> @{ Host; Port } ("vpn.example.com", "vpn.example.com:4443", "[2001:db8::1]:443",
       "https://vpn.example.com/"). Port 0 = none given. #>
    [CmdletBinding()] param([AllowEmptyString()][string]$Address)
    $a = ([string]$Address).Trim() -replace '^[a-zA-Z][a-zA-Z0-9+.-]*://', '' -replace '/.*$', ''
    if ($a -match '^\[([0-9a-fA-F:.]+)\](:(\d{1,5}))?$') { return [pscustomobject]@{ Host = $Matches[1]; Port = $(if ($Matches[3]) { [int]$Matches[3] } else { 0 }) } }
    if ($a -match '^([^:]+):(\d{1,5})$') { return [pscustomobject]@{ Host = $Matches[1]; Port = [int]$Matches[2] } }
    [pscustomobject]@{ Host = $a; Port = 0 }
}

function ConvertTo-VeroRasEntry {
    <# Pure: a Windows VPN profile (Get-VeroWindowsVpn) -> a VeroScudo profile entry with the right settings for its type.
       SSTP / Automatic use the port from the server address (else 443); IKEv2, L2TP and PPTP have fixed ports. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Vpn, [string]$UserName = '')
    $sa = Split-VeroServerAddress $Vpn.Server
    $port = if ($sa.Port -ge 1 -and $sa.Port -le 65535) { $sa.Port } else { 443 }
    [pscustomobject]@{ Profile = $Vpn.Name; Type = 'ras'; Server = $sa.Host; Port = $port; Username = $(if ($Vpn.Password) { $UserName } else { '' })
                       ServerIps = @(); Auth = [bool]$Vpn.Password; Dco = $false; ImportFrom = $null; TunnelType = $Vpn.TunnelType }
}

function Get-VeroRasSavedUser {
    <# The username Windows saved for that VPN profile ('' if none; the password is never read). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Name, [bool]$AllUsers = $false)
    try { Import-VeroNative; return [VeroScudo.Ras]::SavedUserName($Name, $AllUsers) } catch { Write-Verbose "saved user: $($_.Exception.Message)" }
    ''
}

function Test-VeroRasPassword {
    <# Pure: does a Windows VPN profile sign in with a username and password? Not with a machine certificate, nor with EAP-TLS
       (smart card / user certificate, EAP type 13). #>
    [CmdletBinding()] param([string[]]$AuthMethods = @(), [string]$EapXml = '')
    if ($AuthMethods -contains 'MachineCertificate') { return $false }
    if ($AuthMethods -contains 'Eap' -and $EapXml -match '<(\w+:)?Type>\s*13\s*</(\w+:)?Type>') { return $false }
    $true
}

function Get-VeroRasDescription {
    <# Pure: one line for the profile editor - what VeroScudo found in the Windows profile. #>
    [CmdletBinding()] param([string]$TunnelType, [bool]$Password = $true, [bool]$AllUsers = $false)
    $proto = switch ($TunnelType) { 'Ikev2' { 'IKEv2 (UDP 500/4500)' } 'Sstp' { 'SSTP (TCP, port below)' } 'L2tp' { 'L2TP/IPsec with certificate or pre-shared key (UDP 500/4500/1701)' } 'Pptp' { 'PPTP (TCP 1723 + GRE)' } default { 'Automatic (all built-in protocols allowed; SSTP on the port below)' } }
    $sign = if ($Password) { 'username + password (store it with Set password...)' } else { 'certificate - no password needed' }
    "Protocol: $proto. Sign-in: $sign.$(if ($AllUsers) { ' Profile for all users.' })"
}

$script:TunnelTypes = @{}
function Get-VeroTunnelType([string]$ProfileName) {
    if (-not $script:TunnelTypes.ContainsKey($ProfileName)) {             # cached per process: the watchdog loop is long-lived
        $c = Get-VpnConnection -Name $ProfileName -ErrorAction SilentlyContinue
        if (-not $c) { $c = Get-VpnConnection -Name $ProfileName -AllUserConnection -ErrorAction SilentlyContinue }   # created for all users
        if (-not $c) { return 'Automatic' }
        $script:TunnelTypes[$ProfileName] = if ($c.TunnelType) { [string]$c.TunnelType } else { 'Automatic' }
    }
    $script:TunnelTypes[$ProfileName]
}

$script:HyperVFw = $null
function Test-VeroHyperVFirewall {
    <# Does this Windows have the Hyper-V firewall (Windows 11 22H2+)? Every Hyper-V firewall call is gated by this. #>
    if ($null -eq $script:HyperVFw) {
        $script:HyperVFw = [bool]((Get-Command Get-NetFirewallHyperVVMCreator, Get-NetFirewallHyperVRule, Set-NetFirewallHyperVVMSetting -ErrorAction SilentlyContinue | Measure-Object).Count -ge 3)
    }
    $script:HyperVFw
}
function Test-VeroVmWanted {
    [CmdletBinding()] param([Parameter(Mandatory)]$Config)
    if ($Config.Vm -eq $false) { return $false }
    if (-not (Test-VeroHyperVFirewall)) {
        # no Hyper-V firewall (older Windows): WSL/VM traffic cannot be controlled - say so instead of silently skipping it
        if (Get-VeroNic | Where-Object { $_.Name -like 'vEthernet*' -and [string]$_.OperationalStatus -eq 'Up' }) {
            if (-not $script:VmWarned) { Write-VeroLog 'WARNING: virtual machines / WSL are present but this Windows has no Hyper-V firewall - their traffic is NOT covered by the kill-switch' 'core'; $script:VmWarned = $true }
        }
        return $false
    }
    if ($Config.Vm -eq 'auto') { return [bool](Get-NetFirewallHyperVVMCreator -ErrorAction SilentlyContinue | Where-Object VMCreatorId -eq $script:WslCreator) }
    return [bool]$Config.Vm
}
$script:VmWarned = $false

function Set-VeroVmAccess {
    <# WSL traffic is NAT-forwarded, so the host's WFP filters do not see it; the Hyper-V firewall does. While armed the WSL
       VM's default outbound is Block, and our allow rule is enabled only while the tunnel is up. #>
    [CmdletBinding()] param([Parameter(Mandatory)][bool]$Allow, [string]$Action = 'core')
    if (-not (Test-VeroHyperVFirewall)) { return }
    $p = Get-VeroPath
    if (-not (Test-Path $p.VmBackup)) {
        $vs = Get-NetFirewallHyperVVMSetting -PolicyStore PersistentStore -Name $script:WslCreator -ErrorAction SilentlyContinue
        $orig = if ($vs) { [string]$vs.DefaultOutboundAction } else { 'NotConfigured' }
        # Block is VeroScudo's own value (a leftover of an earlier arm), never a real original: WSL would have no network at all
        if ($orig -eq 'Block') { $orig = 'NotConfigured' }
        @{ DefaultOutboundAction = $orig } | ConvertTo-Json | Set-Content $p.VmBackup
    }
    $cur = Get-NetFirewallHyperVVMSetting -PolicyStore PersistentStore -Name $script:WslCreator -ErrorAction SilentlyContinue
    if (-not $cur -or [string]$cur.DefaultOutboundAction -ne 'Block') {
        Set-NetFirewallHyperVVMSetting -Name $script:WslCreator -DefaultOutboundAction Block
        Write-VeroLog 'WSL default outbound -> Block' $Action
    }
    $r = Get-NetFirewallHyperVRule -Name $script:VmRule -ErrorAction SilentlyContinue
    if (-not $r) {
        New-NetFirewallHyperVRule -Name $script:VmRule -DisplayName 'VeroScudo - WSL outbound' -Direction Outbound -Action Allow -VMCreatorId $script:WslCreator -Enabled False | Out-Null
        $r = Get-NetFirewallHyperVRule -Name $script:VmRule
        Write-VeroLog 'Hyper-V rule created: WSL outbound' $Action
    }
    $want = if ($Allow) { 'True' } else { 'False' }
    if ([string]$r.Enabled -ne $want) {
        Set-NetFirewallHyperVRule -Name $script:VmRule -Enabled $want
        Write-VeroLog "WSL outbound -> $(if ($Allow) { 'allowed' } else { 'blocked' })" $Action
    }
}
function Restore-VeroVmAccess {
    $p = Get-VeroPath
    if (-not (Test-VeroHyperVFirewall)) { Remove-Item $p.VmBackup -Force -ErrorAction SilentlyContinue; return }   # nothing was ever changed
    $r = Get-NetFirewallHyperVRule -Name $script:VmRule -ErrorAction SilentlyContinue
    if ($r) { Remove-NetFirewallHyperVRule -Name $script:VmRule }
    if (Test-Path $p.VmBackup) {
        $orig = [string](Get-Content $p.VmBackup -Raw | ConvertFrom-Json).DefaultOutboundAction
        # a saved Block came from VeroScudo itself (seen live: WSL stayed offline whenever VeroScudo was off)
        if (-not $orig -or $orig -eq 'Block') { $orig = 'NotConfigured' }
        try {
            Set-NetFirewallHyperVVMSetting -Name $script:WslCreator -DefaultOutboundAction $orig
            Remove-Item $p.VmBackup -Force                                   # only once it is really restored
        } catch { Write-VeroLog "ERROR: WSL default outbound not restored ($orig): $($_.Exception.Message) - will retry" 'core' }
    }
}

function Enable-VeroEmergencyBlock {
    <# Fail closed: when the WFP filters cannot be applied, block with the Windows Firewall profile default instead. Weaker
       (allow rules still pass) but never open. The next successful sync removes it. #>
    [CmdletBinding()] param([string]$Action = 'core')
    $p = Get-VeroPath
    if (-not (Test-Path $p.FwBackup)) { Get-NetFirewallProfile | Select-Object Name, DefaultOutboundAction | ConvertTo-Json | Set-Content -Path $p.FwBackup }
    Set-NetFirewallProfile -All -DefaultOutboundAction Block
    New-Item -ItemType File -Path $p.Emergency -Force | Out-Null
    Write-VeroLog 'EMERGENCY: WFP unavailable - Windows Firewall default outbound set to Block' $Action
}

function Remove-VeroLegacyFirewall {
    <# Undoes what 1.0.x (Windows Firewall rules + profile default) and the emergency block changed. #>
    [CmdletBinding()] param([string]$Action = 'core')
    # order matters: restore the default outbound action FIRST. Removing the old allow rules while the default is still
    # Block blocks everything for a moment, and Windows re-checks open connections on every firewall change - that cut
    # the VPN's own connection (RAS 829) during the 1.0 -> 1.1 upgrade.
    $p = Get-VeroPath
    if (Test-Path $p.FwBackup) {
        foreach ($pr in (Get-Content $p.FwBackup -Raw | ConvertFrom-Json)) {
            $v = [string]$pr.DefaultOutboundAction
            if ($v -match '^\d+$') { $v = @{ '0' = 'NotConfigured'; '2' = 'Allow'; '4' = 'Block' }[$v] }
            if (-not $v) { $v = 'NotConfigured' }
            Set-NetFirewallProfile -Name $pr.Name -DefaultOutboundAction $v
        }
        Remove-Item $p.FwBackup -Force
        Write-VeroLog 'Windows Firewall default outbound restored' $Action
    }
    $rules = @(Get-NetFirewallRule -Group $script:LegacyGroup -ErrorAction SilentlyContinue)
    if ($rules) { Remove-NetFirewallRule -Group $script:LegacyGroup; Write-VeroLog "removed $($rules.Count) Windows Firewall rule(s) of the old kill-switch" $Action }
    Remove-Item $p.Emergency -Force -ErrorAction SilentlyContinue
}

# thin wrappers: the only places that touch the WFP engine (mockable in tests)
function Set-VeroWfpFilter([object[]]$Specs) { Import-VeroNative; [VeroScudo.Wfp]::Apply([VeroScudo.FilterSpec[]]$Specs) }
function Get-VeroWfpCount { Import-VeroNative; [VeroScudo.Wfp]::Count() }
function Clear-VeroWfpFilter { Import-VeroNative; [VeroScudo.Wfp]::Clear() }

function Get-VeroConfigType($Config) {
    <# The active profile's type; configs built by older callers (or tests) without a Type are the built-in client. #>
    if ($Config.PSObject.Properties['Type'] -and $Config.Type) { [string]$Config.Type } else { 'ras' }
}

function Resolve-VeroEndpoint {
    <# OpenVPN / WireGuard server endpoints @{ Ip; Proto; Port } for the allow-list. WireGuard: the configured endpoint (plus
       the address the tunnel really uses, learned while it runs). OpenVPN: every 'remote' of the imported .ovpn.
       Same cache rules as Resolve-VeroServerIp: newest first, at most 8 per host, -CacheOnly never waits for DNS. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [switch]$CacheOnly)
    $type = Get-VeroConfigType $Config
    if ($type -eq 'wireguard') {
        $ips = @(Resolve-VeroServerIp -Config $Config -CacheOnly:$CacheOnly)
        return @($ips | ForEach-Object { [pscustomobject]@{ Ip = [string]$_; Proto = 17; Port = [int]$Config.Port } })
    }
    $p = Get-VeroPath -VpnProfile $Config.Profile
    $remotes = @(Get-VeroOpenVpnRemote -ProfileName $Config.Profile)
    $cache = @{}
    if (Test-Path $p.EndpointCache) { try { (Get-Content $p.EndpointCache -Raw | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $cache[$_.Name] = @($_.Value) } } catch { Write-Verbose 'endpoint cache unreadable' } }
    $changed = $false
    $out = foreach ($r in $remotes) {
        $a = $null
        $ips = if ([System.Net.IPAddress]::TryParse($r.Host, [ref]$a)) { @($r.Host) } else {
            $cached = @($cache[$r.Host] | Where-Object { $_ })
            if ($CacheOnly) { $cached } else {
                $fresh = @()
                try { $fresh = @([System.Net.Dns]::GetHostAddresses($r.Host) | Where-Object { $_.AddressFamily -in 'InterNetwork', 'InterNetworkV6' -and -not $_.IsIPv6LinkLocal } | ForEach-Object { $_.IPAddressToString }) }
                catch { Write-Verbose "DNS lookup of $($r.Host) failed: $($_.Exception.Message)" }
                $all = @(@($fresh) + @($cached) | Where-Object { $_ } | Select-Object -Unique | Select-Object -First 8)
                if (($all -join ',') -ne ($cached -join ',')) { $cache[$r.Host] = $all; $changed = $true }
                $all
            }
        }
        foreach ($ip in $ips) { [pscustomobject]@{ Ip = [string]$ip; Proto = $(if ($r.Proto -eq 'tcp') { 6 } else { 17 }); Port = [int]$r.Port } }
    }
    if ($changed) { $cache | ConvertTo-Json -Depth 3 | Set-Content $p.EndpointCache }
    @($out)
}

function Get-VeroAppliedState {
    $p = Get-VeroPath
    if (-not (Test-Path $p.WfpState)) { return $null }
    try { Get-Content $p.WfpState -Raw | ConvertFrom-Json } catch { $null }
}

function Sync-VeroKillSwitch {
    <# Computes the filter set for the current situation and applies it when it differs from what is in force (or when
       filters went missing). Atomic: one WFP transaction replaces the previous set. Re-run every 15 s by the watchdog, so a
       recreated WSL adapter, a new tunnel interface or a moved VPN server are picked up without a manual toggle.
       The filters are applied with the cached server addresses first and the name is re-resolved only afterwards, while the
       tunnel is up: a lookup made before the switch would hang on the filters still in force (seen live: 23 s after a drop,
       12 s after a reconnect, all traffic blocked meanwhile). One sync at a time (watchdog and event tasks run in parallel). #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core', [switch]$Force, [switch]$NoRefresh, [switch]$ForceDown)
    # -ForceDown: apply the set without the tunnel even while it is still up (Reconnect: block first, then hang up)
    $again = Invoke-VeroLocked { param($c, $a, $f, $n, $d) Sync-VeroKillSwitchCore -Config $c -Action $a -Force:$f -NoRefresh:$n -ForceDown:$d } -Arguments @($Config, $Action, $Force.IsPresent, $NoRefresh.IsPresent, $ForceDown.IsPresent)
    if ($again -and -not $ForceDown) { Sync-VeroKillSwitch -Config $Config -Action $Action -NoRefresh }
}

function Invoke-VeroLocked([scriptblock]$Script, [object[]]$Arguments = @()) {
    <# Applying and removing filters never overlap (watchdog, event tasks and On/Off run in parallel processes). Seen live:
       a slow disarm finished after a re-arm had applied its filters and left an armed machine without any. #>
    $mutex = New-Object System.Threading.Mutex($false, 'Local\VeroScudo-Sync')
    $owned = $false
    try {
        try { $owned = $mutex.WaitOne(60000) } catch [System.Threading.AbandonedMutexException] { $owned = $true }
        & $Script @Arguments                       # values passed explicitly, not read from the caller's scope
    } finally {
        if ($owned) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

function Sync-VeroKillSwitchCore {
    <# Returns $true when a fresh lookup found different server addresses (the caller re-syncs once). #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core', [switch]$Force, [switch]$NoRefresh, [switch]$ForceDown)
    $p = Get-VeroPath
    $type = Get-VeroConfigType $Config
    if (-not $ForceDown) {                                                 # a Reconnect is hanging up: keep its tunnel blocked meanwhile
        $mk = Get-VeroRenewMarker
        if ($mk -and [string]$mk.Profile -eq $Config.Profile -and -not [string]$mk.HungUp) {
            try { if (((Get-Date) - [datetime]::Parse([string]$mk.Start, $null, [Globalization.DateTimeStyles]::RoundtripKind)).TotalSeconds -lt 30) { $ForceDown = [switch]$true } } catch { Write-Verbose 'renew marker' }
        }
    }
    $tun = if ($ForceDown) { [uint64]0 } else { Get-VeroTunnelLuid $Config.Profile -Type $type }
    $eps = $null; $app = ''
    if ($type -eq 'ras') {
        $ips = @(Resolve-VeroServerIp -Config $Config -CacheOnly)
        if ($ips.Count -eq 0) { $ips = @(Resolve-VeroServerIp -Config $Config) }                   # first run: nothing cached yet
        if ($ips.Count -eq 0) { Write-VeroLog "WARNING: cannot resolve $($Config.Server) and no cached IP - redial cannot reach it" $Action }
    } else {
        $eps = @(Resolve-VeroEndpoint -Config $Config -CacheOnly)
        if ($eps.Count -eq 0) { $eps = @(Resolve-VeroEndpoint -Config $Config) }
        if ($eps.Count -eq 0) { Write-VeroLog "WARNING: no address known for the $(Get-VeroTypeLabel $type) server of '$($Config.Profile)' - redial cannot reach it" $Action }
        $ips = @($eps | ForEach-Object { [string]$_.Ip } | Select-Object -Unique)
        if ($type -eq 'openvpn' -and -not $Config.Dco) {
            $app = Get-VeroOpenVpnExe
            if (-not $app) { $eps = @() }                                   # never a program-less permit by accident: nothing to allow
        }
    }
    $vm = Test-VeroVmWanted $Config
    $wsl = if ($vm) { Get-VeroWslLuid } else { [uint64]0 }
    $dns = @(if (-not $tun) { Get-VeroDnsServer -ProfileName $Config.Profile })    # @(if ...): an if yielding an empty list is $null
    $rasType = if ($type -eq 'ras') { Get-VeroTunnelType $Config.Profile } else { 'Automatic' }
    $crl = ($type -eq 'ras') -and (Test-VeroCrlWindow)
    $noDns = (-not $tun) -and @($dns).Count -eq 0
    if ($noDns -and -not $script:NoDnsLogged) { Write-VeroLog 'no DNS server known for the network yet - no DNS permit (redial uses cached server addresses)' $Action }
    $script:NoDnsLogged = $noDns                                              # once per change, not every 15 s
    $specs = Get-VeroFilterSpec -Config $Config -ServerIps $ips -TunnelLuid $tun -WslLuid $wsl -DnsServers $dns -TunnelType $rasType -Endpoints $eps -EndpointApp $app -CrlWindow $crl
    $fp = Get-VeroSpecFingerprint $specs
    $prev = Get-VeroAppliedState
    $present = Get-VeroWfpCount
    $applied = $false
    if ($Force -or -not $prev -or $prev.Fingerprint -ne $fp -or $present -ne $specs.Count -or (Test-Path $p.Emergency)) {
        $applied = $true
        try {
            Set-VeroWfpFilter $specs
        } catch {
            Write-VeroLog "ERROR: WFP apply failed: $($_.Exception.Message)" $Action
            Enable-VeroEmergencyBlock -Action $Action
            throw
        }
        @{ Fingerprint = $fp; Count = $specs.Count; Profile = $Config.Profile; Type = $type; Tunnel = [string]$tun; Wsl = [string]$wsl; Servers = $ips; Time = (Get-Date).ToString('o') } |
            ConvertTo-Json | Set-Content $p.WfpState
        $why = if (-not $prev) { 'armed' } elseif ($present -ne $prev.Count) { "filters missing ($present of $($prev.Count))" } else { 'changed' }
        Write-VeroLog ("kill-switch {0}: {1} filters, profile '{2}' ({7}), tunnel {3}, wsl {4}, server {5}, dns {6}" -f $why, $specs.Count, $Config.Profile,
            $(if ($tun) { 'up' } elseif ($ForceDown) { 'BLOCKED for reconnect' } else { 'DOWN' }), $(if ($wsl) { 'bound' } else { '-' }), ($ips -join ','),
            $(if ($tun) { 'tunnel only' } else { ($dns -join ',') }), (Get-VeroTypeLabel $type)) $Action
        if (Test-Path $p.Emergency) { Remove-VeroLegacyFirewall -Action $Action }
    }
    # the Hyper-V firewall queries are slow (~0.4 s): only when something changed, else every ~5 min as a tamper check
    $script:SyncCount++
    if ($vm -and ($applied -or $script:VmAllowed -ne [bool]$tun -or $script:SyncCount % 20 -eq 0)) {
        Set-VeroVmAccess -Allow ([bool]$tun) -Action $Action
        $script:VmAllowed = [bool]$tun
    }
    # refresh the server addresses only now - through the tunnel, after the filters let it through
    if ($tun -and -not $NoRefresh -and @($Config.ServerIps).Count -eq 0) {
        if ($type -eq 'ras') {
            $fresh = @(Resolve-VeroServerIp -Config $Config)
            return (($fresh -join ',') -ne ($ips -join ','))
        }
        $fresh = @(Resolve-VeroEndpoint -Config $Config | ForEach-Object { [string]$_.Ip } | Select-Object -Unique)
        return (($fresh -join ',') -ne ($ips -join ','))
    }
    $false
}
$script:SyncCount = 0
$script:NoDnsLogged = $false
$script:VmAllowed = $null

function Disable-VeroKillSwitch {
    [CmdletBinding()] param([string]$Action = 'core')
    Invoke-VeroLocked {
        param($a)
        # re-checked under the lock: if something armed again meanwhile (On pressed right after a hang-up), its filters stay
        if (Test-VeroArmed) { Write-VeroLog 'armed again meanwhile - kill-switch kept' $a; return }
        Clear-VeroWfpFilter
        Remove-Item (Get-VeroPath).WfpState -Force -ErrorAction SilentlyContinue
        Remove-VeroLegacyFirewall -Action $a
        Restore-VeroVmAccess
        Write-VeroLog 'kill-switch OFF (filters removed)' $a
    } -Arguments @($Action)
}

function Test-VeroKillSwitchPresent {
    # anything VeroScudo changed and has not yet undone, incl. a WSL setting whose restore failed (retried by the watchdog)
    ((Get-VeroWfpCount) -gt 0) -or (Test-Path (Get-VeroPath).Emergency) -or (Test-Path (Get-VeroPath).VmBackup) -or
        [bool](Get-NetFirewallRule -Group $script:LegacyGroup -ErrorAction SilentlyContinue)
}

function Test-VeroNative {
    <# Elevated self-test (Install.ps1): every layer/condition GUID the filters use must be known to this Windows' WFP. #>
    Import-VeroNative
    $missing = @()
    foreach ($l in 'ConnectV4', 'ConnectV6', 'RecvAcceptV4', 'RecvAcceptV6') {
        $fields = [VeroScudo.Wfp]::LayerFields([VeroScudo.Layer]::$l)
        foreach ($n in 'Flags', 'LocalInterface', 'RemoteAddress', 'Protocol', 'RemotePort', 'LocalPort', 'AppId') {
            if ($fields -notcontains [VeroScudo.Field]::$n) { $missing += "$l/$n" }
        }
    }
    if ($missing) { throw "WFP self-test failed - unknown field(s): $($missing -join ', ')" }
    $true
}

# ---------------------------------------------------------------- dialing
function Get-VeroCredential {
    [CmdletBinding()] param([Parameter(Mandatory)]$Config)
    $p = Get-VeroPath -VpnProfile $Config.Profile
    foreach ($f in $p.Cred, $p.LegacyCred) {
        if (-not (Test-Path $f)) { continue }
        try { $c = Import-Clixml $f } catch { continue }
        if ($f -eq $p.Cred -or $c.UserName -eq $Config.Username) { return $c }    # the 1.0 single credential, if it is for this user
    }
    $null
}
function Get-VeroKeyPassphrase {
    <# OpenVPN: the private-key passphrase, stored like the password (DPAPI, this Windows account only). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    $f = (Get-VeroPath -VpnProfile $ProfileName).KeyPass
    if (Test-Path $f) { try { return (Import-Clixml $f) } catch { Write-Verbose 'key passphrase unreadable' } }
    $null
}

$script:EventSettleSeconds = 3              # on-event waits this long before reading the termination records (tests: 0)
$script:RasAuthCodes = @(691)              # "the user name and password combination is not recognized"
# SSTP could not check the server certificate's revocation (CRL/OCSP offline): CRYPT_E_REVOCATION_OFFLINE / _NO_REVOCATION_CHECK
# + WSAEACCES (0x8007271D): seen live 2026-11-03 - with no TCP 80 permit, SSTP's revocation fetch is refused by the filters
# and RasDial returns "access forbidden" instead of a revocation code
$script:RasRevocationCodes = @(-2146885613, -2146885614, 0x80092013, 0x80092012, -2147014883, 10013)
function Open-VeroCrlWindow {
    <# Allow svchost TCP 80 for 2 minutes so SSTP can fetch the CRL: after a dial failed on the revocation check, and right
       after an SSTP tunnel came up (it may still be checking when the filters arrive - seen live: RAS 829 ~5 s after arm). #>
    [CmdletBinding()] param([string]$Action = 'core', [string]$Reason = 'SSTP could not check the server certificate revocation')
    @{ Until = (Get-Date).AddMinutes(2).ToString('o') } | ConvertTo-Json | Set-Content (Get-VeroPath).CrlWindow
    Write-VeroLog "$Reason - HTTP (TCP 80) from Windows services allowed for 2 minutes so it can" $Action
}
function Test-VeroCrlWindow {
    $f = (Get-VeroPath).CrlWindow
    if (-not (Test-Path $f)) { return $false }
    try { return ((Get-Date) -lt [datetime]::Parse([string](Get-Content $f -Raw | ConvertFrom-Json).Until, $null, [Globalization.DateTimeStyles]::RoundtripKind)) } catch { return $false }
}
function Invoke-VeroDial {
    <# One connection attempt for the active profile's type.
       RAS: RasDial API with the DPAPI-stored credential - the password never appears on a command line (process lists, EDR,
       event 4688); without a stored credential, rasdial uses whatever the phonebook entry has. A rejected password stops the
       automatic redial (Set-VeroAuthFailed): retrying it every few seconds can lock the account on the VPN server. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core')
    switch (Get-VeroConfigType $Config) {
        'openvpn'   { Invoke-VeroOpenVpnDial -Config $Config -Action $Action; return }
        'wireguard' { Invoke-VeroWgDial -Config $Config -Action $Action; return }
    }
    $cred = Get-VeroCredential -Config $Config
    if ($cred) {
        Import-VeroNative
        $code = [VeroScudo.Ras]::Dial($Config.Profile, $cred.UserName, $cred.Password)
        if ($code -ne 0) { Write-Verbose "RasDial: $code" }
        $script:LastDialCode = $code
    } else {
        Write-VeroLog "WARNING: no stored credential for '$($Config.Profile)' (tray Settings or Set-VpnCredential.ps1) - dialing without password" $Action
        & $script:Rasdial $Config.Profile 2>&1 | Out-Null
        $code = $LASTEXITCODE
        $script:LastDialCode = $code
    }
    if ($script:RasAuthCodes -contains [int64]$code) { Set-VeroAuthFailed -ProfileName $Config.Profile -Reason "RAS error $code" -Action $Action }
    # ONLY the RasDial result decides - never the Application log (RasClient 20227): ordinary users can write that log, and
    # a forged "revocation offline" record would keep svchost's HTTP open for as long as the redial runs
    if ($script:RasRevocationCodes -contains [int64]$code -and -not (Test-VeroCrlWindow)) {
        Open-VeroCrlWindow -Action $Action
        Sync-VeroKillSwitch -Config $Config -Action $Action                # the next attempt can reach the CRL
    }
}

function Invoke-VeroHangUp {
    <# Ends the profile's tunnel the way its own client does. Callers that must not be read as "the user hung up" (switch,
       Reconnect) protect themselves first: a switch makes the new profile active, Reconnect writes the renew marker. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName, [string]$Type)
    if (-not $Type) { $Type = Get-VeroProfileType $ProfileName }
    switch ($Type) {
        'openvpn'   { Stop-VeroOpenVpn -ProfileName $ProfileName }
        'wireguard' { Invoke-VeroWgHangUp -ProfileName $ProfileName }
        default     { & $script:Rasdial $ProfileName /disconnect 2>&1 | Out-Null }
    }
}

# ---------------------------------------------------------------- rejected password: stop redialing until it is changed
function Set-VeroAuthFailed {
    <# -Which Key: the private-key passphrase was rejected (only a newer passphrase lifts the pause); else the password.
       Always rewritten: its time must be newer than the password that was just rejected. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName, [string]$Reason = '', [string]$Action = 'core', [ValidateSet('Auth', 'Key')][string]$Which = 'Auth')
    $p = Get-VeroPath -VpnProfile $ProfileName
    $first = -not (Test-Path $p.AuthFail)
    Set-Content -Path $p.AuthFail -Value ("{0} {1:o} {2}" -f $Which, (Get-Date), $Reason) -Encoding UTF8
    if ($first) {
        Write-VeroLog "PASSWORD REJECTED for '$ProfileName' ($Reason) - automatic redial paused so the account is not locked; traffic stays blocked. Store the right password (tray Settings), then Turn on or Reconnect." $Action
    }
}
function Clear-VeroAuthFailed {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName, [string]$Action = 'core')
    $p = Get-VeroPath -VpnProfile $ProfileName
    if (Test-Path $p.AuthFail) { Remove-Item $p.AuthFail -Force; Write-VeroLog "password pause for '$ProfileName' lifted" $Action }
}
function Test-VeroAuthBlocked {
    <# True while the profile's password was rejected and no newer password (or key passphrase) has been stored since. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    $p = Get-VeroPath -VpnProfile $ProfileName
    if (-not (Test-Path $p.AuthFail)) { return $false }
    $flag = (Get-Item $p.AuthFail).LastWriteTimeUtc
    $which = (([string](Get-Content $p.AuthFail -Raw -ErrorAction SilentlyContinue)) -split '\s+')[0]
    $f = if ($which -eq 'Key') { $p.KeyPass } else { $p.Cred }
    if ($f -and (Test-Path $f) -and (Get-Item $f).LastWriteTimeUtc -gt $flag) { return $false }
    $true
}

# ---------------------------------------------------------------- Reconnect (user): our own hang-up is not "you hung up"
function Set-VeroRenewMarker {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName, [switch]$HungUp)
    $p = Get-VeroPath
    $m = @{ Profile = $ProfileName; Start = (Get-Date).ToString('o'); HungUp = '' }
    if ($HungUp -and (Test-Path $p.Renew)) { try { $old = Get-Content $p.Renew -Raw | ConvertFrom-Json; $m.Start = [string]$old.Start } catch { Write-Verbose 'renew marker unreadable' } }
    if ($HungUp) { $m.HungUp = (Get-Date).ToString('o') }
    $m | ConvertTo-Json | Set-Content $p.Renew
}
function Test-VeroRenewHangUp {
    <# Pure rule: is a termination record at $EventTime our own hang-up for Reconnect? Only for that profile, only between the
       marker's start and 30 s after the hang-up finished, and never for a marker older than 5 minutes. #>
    [CmdletBinding()] param($Marker, [string]$ProfileName, [datetime]$EventTime, [datetime]$Now = (Get-Date))
    if (-not $Marker -or [string]$Marker.Profile -ne $ProfileName) { return $false }
    $start = [datetime]::Parse([string]$Marker.Start, $null, [Globalization.DateTimeStyles]::RoundtripKind)
    if (($Now - $start).TotalMinutes -gt 5) { return $false }
    $end = if ([string]$Marker.HungUp) { [datetime]::Parse([string]$Marker.HungUp, $null, [Globalization.DateTimeStyles]::RoundtripKind).AddSeconds(30) } else { $Now }
    ($EventTime -ge $start.AddSeconds(-1) -and $EventTime -le $end)
}
function Get-VeroRenewMarker {
    $p = Get-VeroPath
    if (Test-Path $p.Renew) { try { return (Get-Content $p.Renew -Raw | ConvertFrom-Json) } catch { Write-Verbose 'renew marker unreadable' } }
    $null
}

function Test-VeroLockAlive {
    $p = Get-VeroPath
    if (-not (Test-Path $p.Lock)) { return $false }
    $lockPid = Get-Content $p.Lock -ErrorAction SilentlyContinue | Select-Object -First 1
    # the lock survives a crash or reboot and Windows reuses PIDs: alive only if that PID is still a PowerShell
    # process that was already running when the lock was written
    $proc = if ($lockPid) { Get-Process -Id $lockPid -ErrorAction SilentlyContinue }
    $started = try { $proc.StartTime } catch { $null }
    if ($proc -and $proc.ProcessName -in 'powershell', 'pwsh' -and $started -and $started -le (Get-Item $p.Lock).LastWriteTime) { return $true }
    Remove-Item $p.Lock -Force -ErrorAction SilentlyContinue
    return $false
}

function Enter-VeroLock {
    <# Atomic: CreateNew fails when another loop holds the lock, so two processes can never both redial. #>
    $p = Get-VeroPath
    for ($i = 0; $i -lt 2; $i++) {
        try {
            $fs = [IO.File]::Open($p.Lock, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
            $b = [Text.Encoding]::ASCII.GetBytes([string]$PID); $fs.Write($b, 0, $b.Length); $fs.Close()
            return $true
        } catch [IO.IOException] {
            if (Test-VeroLockAlive) { return $false }                       # alive: someone else redials; stale: removed, retry
        }
    }
    $false
}

function Invoke-VeroReconnect {
    <# Blocked + redial forever, until the tunnel is up or the user turns the VPN off. Follows a profile switch: the
       config (and so the active profile) is re-read on every attempt.
       -Renew (the user's Reconnect): first block - the kill-switch is applied without the tunnel while it is still up -,
       then hang up, then the normal loop; traffic flows again only once the new tunnel is up. All of it under the
       reconnect lock, so the watchdog never reads our own hang-up as a failure or as the user turning the VPN off. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core', [switch]$Renew)
    if (-not (Enter-VeroLock)) { Write-VeroLog $(if ($Renew) { 'reconnect requested, but a reconnect is already running - it continues' } else { 'reconnect loop already running' }) $Action; return }
    $p = Get-VeroPath
    $attempt = 0
    $pausedLogged = $false
    $switchTo = $null
    try {
        if ($Renew) {
            $type = Get-VeroConfigType $Config
            Write-VeroLog "RECONNECT requested by you: traffic blocked, hanging up '$($Config.Profile)' ($(Get-VeroTypeLabel $type)), redialing" $Action
            Set-VeroRenewMarker -ProfileName $Config.Profile
            Sync-VeroKillSwitch -Config $Config -Action $Action -ForceDown -Force
            Invoke-VeroHangUp -ProfileName $Config.Profile -Type $type
            $t = Get-Date
            while ((Test-VeroVpnConnected $Config.Profile -Type $type) -and ((Get-Date) - $t).TotalSeconds -lt 15) { Start-Sleep -Milliseconds 500 }
            Set-VeroRenewMarker -ProfileName $Config.Profile -HungUp
            if (Test-VeroVpnConnected $Config.Profile -Type $type) { Write-VeroLog "WARNING: '$($Config.Profile)' did not hang up within 15 s - keeping it" $Action }
        }
        while ((Test-VeroArmed) -and -not (Test-VeroVpnConnected $Config.Profile)) {
            # you picked another profile while this one is being redialed: yours wins (seen live: the tray's switch to WireGuard
            # was dropped because this loop kept the Switch task busy redialing OpenVPN)
            if (Get-VeroPendingSwitch) {
                $want = Read-VeroSwitchRequest                                   # taken by this loop (the Switch task may take it first: then it switches)
                if ($want -and $want -ne $Config.Profile -and @((Get-VeroConfig).Profiles | ForEach-Object Profile) -contains $want) {
                    Write-VeroLog "you chose '$want' while '$($Config.Profile)' was being redialed - switching to it" $Action
                    $switchTo = $want; break
                }
            }
            $attempt++
            Sync-VeroKillSwitch -Config $Config -Action $Action
            if (Test-VeroAuthBlocked $Config.Profile) {
                if (-not $pausedLogged) { Write-VeroLog "redial paused: the password for '$($Config.Profile)' was rejected - store the right one (tray Settings); still blocked" $Action; $pausedLogged = $true }
                Start-Sleep -Seconds $Config.RetrySeconds
                $Config = Get-VeroConfig
                continue
            }
            Invoke-VeroDial -Config $Config -Action $Action
            if (Test-VeroVpnConnected $Config.Profile) {
                Write-VeroLog "reconnected '$($Config.Profile)' after $attempt attempt(s)" $Action
                if ((Get-VeroConfigType $Config) -eq 'ras') { Save-VeroRasCoId -ProfileName $Config.Profile }   # its "you hung up" must match it
                break
            }
            Write-VeroLog "attempt $attempt failed ($(Get-VeroDialFailure $Config))" $Action
            # the server may have moved: look it up again (the redial's DNS permit is in force while down) and let the new
            # address through before the next attempt - the cache alone would refuse it forever
            if (@($Config.ServerIps).Count -eq 0 -and (Get-VeroConfigType $Config) -eq 'ras') {
                $cached = @(Resolve-VeroServerIp -Config $Config -CacheOnly)
                $fresh = @(Resolve-VeroServerIp -Config $Config)
                if (($fresh -join ',') -ne ($cached -join ',')) {
                    Write-VeroLog ("server '{0}' now resolves to {1} - allowed for the next attempt" -f $Config.Server, ($fresh -join ',')) $Action
                    Sync-VeroKillSwitch -Config $Config -Action $Action
                }
            }
            Start-Sleep -Seconds $Config.RetrySeconds
            $Config = Get-VeroConfig
        }
        if (-not (Test-VeroArmed)) { Write-VeroLog 'disarmed during reconnect - stopping' $Action }
    } finally {
        Remove-Item $p.Lock -Force -ErrorAction SilentlyContinue
    }
    if ($switchTo) { Invoke-VeroSwitch -Name $switchTo -Action $Action; return }       # after the lock is released: the switch redials itself
    if ((Test-VeroArmed) -and (Test-VeroVpnConnected $Config.Profile)) { Sync-VeroKillSwitch -Config $Config -Action $Action }
    elseif ($attempt -gt 0 -and -not (Test-VeroArmed) -and (Test-VeroVpnConnected $Config.Profile)) {
        # you pressed Off while this loop was dialing and the dial still connected: Off means disconnected
        Invoke-VeroHangUp $Config.Profile (Get-VeroConfigType $Config)
        Write-VeroLog "you turned VeroScudo off while it was redialing - hung up the tunnel that connected afterwards" $Action
    }
}

function Get-VeroDialFailure($Config) {
    <# One line for the log: why the last attempt did not bring the tunnel up. #>
    switch (Get-VeroConfigType $Config) {
        'openvpn'   { $s = Get-VeroOpenVpnStatus $Config.Profile; if ($s) { "OpenVPN $($s.State)$(if ($s.Reason) { ': ' + $s.Reason })" } else { 'OpenVPN not started' } }
        'wireguard' { "WireGuard $(Get-VeroWgState $Config.Profile), handshake $(Get-VeroWgHealthNow $Config.Profile)" }
        default     { $ev = Get-VeroRasCode -EventId 20227 -Profile $Config.Profile; "RasDial $($script:LastDialCode)$(if ($ev -ne -1) { ', RAS ' + $ev })" }
    }
}

function Invoke-VeroCheck {
    <# One watchdog pass: armed -> filters exactly as they should be (+ redial when down); disarmed -> nothing left behind. #>
    [CmdletBinding()] param([string]$Action = 'watchdog')
    $cfg = Get-VeroConfig
    $script:CheckCount++
    try { if (Update-VeroRasWatch -Config $cfg -Action $Action) { $cfg = Get-VeroConfig } } catch { Write-VeroLog "ERROR: Windows VPN watch: $($_.Exception.Message)" $Action }
    if (@($cfg.Profiles | Where-Object Type -eq 'wireguard').Count -gt 0) {
        try { if (Update-VeroWgWatch -Config $cfg -Action $Action) { $cfg = Get-VeroConfig } } catch { Write-VeroLog "ERROR: WireGuard watch: $($_.Exception.Message)" $Action }
    }
    # about once a minute: other VPNs / kill-switches - every pass (15 s) while one is reported, so the tray's warning goes
    # away soon after you stop the other VPN (seen live: it stayed up to a minute after WireGuard was turned off)
    if (-not (Test-VeroLockAlive) -and (Get-VeroPendingSwitch -MinAgeSeconds 5)) {
        $want = Read-VeroSwitchRequest
        if ($want -and @($cfg.Profiles | ForEach-Object Profile) -contains $want) {
            Write-VeroLog "switch to '$want' was not picked up by the Switch task - switching now" $Action
            Invoke-VeroSwitch -Name $want -Action $Action
            $cfg = Get-VeroConfig
        }
    }
    if ($script:CheckCount % 4 -eq 1 -or @(Get-VeroConflictList).Count -gt 0) {
        try { Update-VeroConflict -Config $cfg -Action $Action } catch { Write-Verbose "conflict check: $($_.Exception.Message)" }
    }
    if (Test-VeroArmed) {
        Sync-VeroKillSwitch -Config $cfg -Action $Action
        if (-not (Test-VeroVpnConnected $cfg.Profile) -and -not (Test-VeroLockAlive)) { Invoke-VeroReconnect -Config $cfg -Action $Action }
    } elseif (Test-VeroKillSwitchPresent) {
        Write-VeroLog 'disarmed but kill-switch still present - removing' $Action
        Disable-VeroKillSwitch -Action $Action
    }
}
$script:CheckCount = 0

function Invoke-VeroSwitch {
    <# Switch the active VPN profile. While armed the machine stays blocked the whole time: the old tunnel stops being
       allowed before it is hung up, and nothing is allowed out until the new one is up. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Name, [string]$Action = 'switch')
    $old = Get-VeroConfig
    $new = Get-VeroConfig -Active $Name
    if ($old.Profile -eq $new.Profile) {
        Write-VeroLog "profile '$Name' is already active" $Action
        if ((Test-VeroArmed) -and -not (Test-VeroVpnConnected $new.Profile)) { Invoke-VeroReconnect -Config $new -Action $Action }
        return
    }
    Set-VeroActiveProfile -Name $Name -Action $Action                    # first: the old profile's 631 is then ignored
    $notice = Get-VeroSwitchNotice -Type $new.Type -ProfileName $Name
    if ($notice) { Write-VeroLog "NOTICE: $notice" $Action }
    $oldType = Get-VeroConfigType $old
    if (Test-VeroArmed) {
        Sync-VeroKillSwitch -Config $new -Action $Action
        # ALWAYS hang the old tunnel up and wait until it is really gone before dialing the new one: once blocked it can look
        # "not connected" while RAS still holds it (and its routes) - the new dial then fails until RAS gives up on it
        # (seen live 2026-11-03: CorporateVPN -> PrivateVPN, IKEv2 attempts failed for ~1 minute until RAS logged 829)
        Invoke-VeroHangUp $old.Profile $oldType
        $t = Get-Date
        while ((Test-VeroVpnConnected $old.Profile -Type $oldType) -and ((Get-Date) - $t).TotalSeconds -lt 15) { Start-Sleep -Milliseconds 500 }
        Write-VeroLog "hung up '$($old.Profile)'" $Action
        Invoke-VeroReconnect -Config $new -Action $Action
    } elseif (Test-VeroVpnConnected $old.Profile -Type $oldType) {
        Invoke-VeroHangUp $old.Profile $oldType
        Write-VeroLog "hung up '$($old.Profile)' (VPN is off - '$Name' is selected for the next turn on)" $Action
    }
}

function Get-VeroPendingSwitch {
    <# The profile the tray asked to switch to, without consuming the request; $null when none (or it is no profile). #>
    [CmdletBinding()] param([double]$MinAgeSeconds = 0)
    $f = (Get-VeroPath).SwitchRequest
    if (-not (Test-Path $f)) { return $null }
    if ($MinAgeSeconds -gt 0 -and ((Get-Date) - (Get-Item $f).LastWriteTime).TotalSeconds -lt $MinAgeSeconds) { return $null }
    $n = (Get-Content $f -Raw -ErrorAction SilentlyContinue)
    if ($n) { $n.Trim() } else { $null }
}

function Read-VeroSwitchRequest {
    <# The tray (unelevated) asks for a switch by writing a profile name to the user's own folder; only names that exist in
       the admin-owned config.json are honoured. #>
    $p = Get-VeroPath
    if (-not (Test-Path $p.SwitchRequest)) { return $null }
    $name = (Get-Content $p.SwitchRequest -Raw -ErrorAction SilentlyContinue)
    Remove-Item $p.SwitchRequest -Force -ErrorAction SilentlyContinue
    if ($name) { $name.Trim() } else { $null }
}

# ---------------------------------------------------------------- reserve types: shared helpers
function Test-VeroNeedsPassword($Config) {
    switch (Get-VeroConfigType $Config) { 'wireguard' { $false } default { [bool]$Config.Auth } }   # ras: false = certificate sign-in
}

function Test-VeroTunnelAdapter($Nic) {
    <# A virtual tunnel adapter (TAP, Wintun, OpenVPN DCO, WireGuard, RAS) - never a physical NIC. #>
    if (-not $Nic) { return $false }
    if ([string]$Nic.Description -match 'Teredo|ISATAP|6to4|IP-HTTPS|IPHTTPS|Microsoft Kernel Debug') { return $false }   # Windows' own tunnels
    if ([string]$Nic.NetworkInterfaceType -in 'Ppp', 'Tunnel') { return $true }
    [string]$Nic.Description -match 'TAP-Windows|Wintun|WireGuard|OpenVPN|Data Channel Offload|ovpn-dco|TAP-|sing-box|Hiddify|NordLynx|PrivateVPN'
}

function Write-VeroSecretFile {
    <# A file only Administrators and SYSTEM can read (the state folder lets users read). Created empty, locked down, then filled. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Text)
    Set-Content -Path $Path -Value '' -Encoding ASCII
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $id = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'Allow')))
    }
    Set-Acl -Path $Path -AclObject $acl
    [IO.File]::WriteAllText($Path, $Text, (New-Object Text.UTF8Encoding($false)))
}

function Protect-VeroOpenVpnDir {
    <# %ProgramData%\VeroScudo\openvpn holds imported configs (often with private keys): Administrators and SYSTEM only. #>
    $d = (Get-VeroPath).OpenVpnDir
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $id = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -Path $d -AclObject $acl
    $d
}

# ---------------------------------------------------------------- OpenVPN: config check and import
# ALLOW-list of client options. VeroScudo runs openvpn.exe as administrator, so an imported config may only use options
# known not to run programs, load modules (plugin, pkcs11-providers, providers, engine), write files or redirect control
# (management, config, log, proxies). Anything else - also an option spelled with quotes or escapes - is refused.
$script:OvpnAllowed = @('client', 'tls-client', 'pull', 'dev', 'dev-type', 'proto', 'remote', 'remote-random', 'remote-random-hostname',
    'resolv-retry', 'nobind', 'persist-key', 'persist-tun', 'persist-remote-ip', 'port', 'rport', 'lport', 'float',
    'ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2', 'key-direction', 'extra-certs', 'crl-verify', 'secret', 'dh', 'pkcs12',
    'peer-fingerprint', 'cipher', 'data-ciphers', 'data-ciphers-fallback', 'ncp-ciphers', 'ncp-disable', 'auth', 'tls-version-min',
    'tls-version-max', 'tls-cipher', 'tls-ciphersuites', 'tls-cert-profile', 'tls-groups', 'ecdh-curve', 'remote-cert-tls', 'ns-cert-type',
    'remote-cert-ku', 'remote-cert-eku', 'verify-x509-name', 'x509-username-field', 'tls-timeout', 'hand-window', 'tran-window', 'reneg-sec',
    'reneg-bytes', 'reneg-pkts', 'comp-lzo', 'compress', 'allow-compression', 'comp-noadapt', 'verb', 'mute', 'mute-replay-warnings',
    'replay-window', 'auth-user-pass', 'auth-nocache', 'auth-retry', 'auth-token-user', 'static-challenge', 'redirect-gateway',
    'redirect-private', 'route', 'route-ipv6', 'route-nopull', 'route-delay', 'route-method', 'route-metric', 'route-gateway',
    'route-ipv6-gateway', 'max-routes', 'pull-filter', 'dhcp-option', 'block-outside-dns', 'register-dns', 'ip-win32', 'tap-sleep',
    'dhcp-renew', 'dhcp-release', 'windows-driver', 'disable-dco', 'topology', 'tun-ipv6', 'ifconfig', 'ifconfig-ipv6', 'ifconfig-nowarn',
    'ping', 'ping-restart', 'ping-exit', 'ping-timer-rem', 'keepalive', 'inactive', 'explicit-exit-notify', 'connect-retry',
    'connect-retry-max', 'connect-timeout', 'server-poll-timeout', 'sndbuf', 'rcvbuf', 'fragment', 'mssfix', 'tun-mtu', 'tun-mtu-extra',
    'link-mtu', 'mtu-disc', 'push-peer-info', 'setenv', 'key-method', 'auth-nocache', 'socket-flags', 'bind', 'script-security',
    'remap-usr1', 'single-session', 'tls-exit', 'nice', 'fast-io', 'txqueuelen', 'mark', 'opt-verify', 'auth-token')
$script:OvpnInline = @('ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2', 'extra-certs', 'crl-verify', 'secret', 'dh', 'pkcs12', 'peer-fingerprint')

function Test-VeroOpenVpnConf {
    <# Checks an .ovpn and returns @{ Errors; Warnings; Remotes; Auth; StaticChallenge; Text }. Text is the config with every
       referenced key/cert file inlined (what the import stores). Pure apart from -ReadFile (reads those files; tests pass a fake).
       Reads blocks the way OpenVPN does: an inline block ends at the first line that STARTS with </tag>. #>
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [string]$BaseDir = '', [scriptblock]$ReadFile)
    if (-not $ReadFile) { $ReadFile = { param($f) [IO.File]::ReadAllBytes($f) } }
    $errors = New-Object System.Collections.Generic.List[string]
    $warn = New-Object System.Collections.Generic.List[string]
    $remotes = New-Object System.Collections.Generic.List[object]
    $out = New-Object System.Text.StringBuilder
    $g = @{ Proto = 'udp'; Port = 1194 }                                    # global defaults
    $c = $null                                                              # the current <connection> block's own proto/port
    $auth = $false; $sc = $false; $redirect = $false; $dns = $false; $pull = $false
    $inBlock = $null
    $toPort = { param($v) if ($v -match '^\d{1,5}$' -and [int]$v -ge 1 -and [int]$v -le 65535) { [int]$v } else { -1 } }
    foreach ($raw in ($Text -split "`r?`n")) {
        $line = $raw.Trim()
        if ($inBlock) {                                                     # inline <ca>...</ca> etc: copied as is
            if ($line.StartsWith("</$inBlock>")) {
                if ($line -ne "</$inBlock>") { $errors.Add("text after </$inBlock> on the same line") }
                $inBlock = $null
            } elseif ($line.StartsWith('<')) { $errors.Add("a tag line inside <$inBlock>: '$line'") }
            [void]$out.AppendLine($raw)
            continue
        }
        if ($line -eq '<connection>') { if ($c) { $errors.Add('nested <connection>') }; $c = @{ Proto = $null; Port = $null }; [void]$out.AppendLine($raw); continue }
        if ($line -eq '</connection>') { $c = $null; [void]$out.AppendLine($raw); continue }
        if ($line -match '^<([a-z0-9-]+)>$') {
            if ($script:OvpnInline -notcontains $Matches[1]) { $errors.Add("inline <$($Matches[1])> is not allowed"); continue }
            $inBlock = $Matches[1]; [void]$out.AppendLine($raw); continue
        }
        if ($line.StartsWith('<')) { $errors.Add("unexpected tag line '$line'"); continue }
        if (-not $line -or $line -match '^[#;]') { [void]$out.AppendLine($raw); continue }
        $tok = @($line -split '\s+' | Where-Object { $_ })
        $first = $tok[0]
        if ($first.StartsWith('--')) { $first = $first.Substring(2) }
        if ($first -cnotmatch '^[a-z0-9-]+$') { $errors.Add("'$($tok[0])' is not allowed: option names must be plain (no quotes, escapes or capitals)"); continue }
        $d = $first
        $arg = @($tok | Select-Object -Skip 1)
        if ($script:OvpnAllowed -notcontains $d) { $errors.Add("'$d' is not allowed: VeroScudo runs OpenVPN as administrator and accepts only known client options (remove the line)"); continue }
        if ($d -eq 'script-security' -and -not ($arg.Count -gt 0 -and $arg[0] -in '0', '1')) { $errors.Add("'script-security $($arg -join ' ')' would let the config run programs as administrator (remove the line)"); continue }
        if ($d -eq 'setenv' -and $arg.Count -gt 0 -and $arg[0] -eq 'opt') { $errors.Add("'setenv opt' would hide unknown options (remove the line)"); continue }
        $skip = $false                                                      # NB: 'continue' inside a switch would not skip this line
        switch ($d) {
            'proto' { if ($arg.Count) { $v = if ($arg[0] -like 'tcp*') { 'tcp' } else { 'udp' }; if ($c) { $c.Proto = $v } else { $g.Proto = $v } } }
            { $_ -in 'port', 'rport' } {
                $v = if ($arg.Count) { & $toPort $arg[0] } else { -1 }
                if ($v -lt 0) { $errors.Add("'$d' needs a port 1-65535"); break }
                if ($c) { $c.Port = $v } else { $g.Port = $v }
            }
            'remote' {
                if ($arg.Count -lt 1) { $errors.Add("'remote' without a server"); break }
                $pt = 0
                if ($arg.Count -ge 2) { $pt = & $toPort $arg[1]; if ($pt -lt 0) { $errors.Add("remote '$($arg[0])': port must be 1-65535"); break } }
                $r = [pscustomobject]@{ Host = $arg[0]; Port = $pt; Proto = $(if ($arg.Count -ge 3) { if ($arg[2] -like 'tcp*') { 'tcp' } else { 'udp' } } else { '' }); Block = $c }
                if (-not (Test-VeroHost $r.Host)) { $errors.Add("invalid remote '$($r.Host)'") } else { $remotes.Add($r) }
            }
            'auth-user-pass' {
                $auth = $true
                if ($arg.Count -gt 0) { $warn.Add("'auth-user-pass $($arg[0])' keeps the password in a plain file. VeroScudo ignores that file and uses the password stored in VeroScudo (tray Settings) - delete the file.") }
                [void]$out.AppendLine('auth-user-pass'); $skip = $true
            }
            'static-challenge' { $sc = $true; $warn.Add('This config asks for a one-time code (static-challenge). Every connect, also an automatic redial, waits for you to type the code in the tray.') }
            'redirect-gateway' { $redirect = $true }
            'pull' { $pull = $true }
            'client' { $pull = $true }
            'dhcp-option' { if ($arg.Count -ge 2 -and $arg[0] -eq 'DNS') { $dns = $true } }
        }
        if ($skip) { continue }
        if ($script:OvpnInline -contains $d -and $arg.Count -ge 1 -and $arg[0] -ne '[inline]') {
            if ($d -eq 'crl-verify' -and $arg.Count -ge 2 -and $arg[1] -eq 'dir') { $errors.Add("'crl-verify ... dir' cannot be imported - use a CRL file"); continue }
            $file = $arg[0]
            $full = if ([IO.Path]::IsPathRooted($file) -or -not $BaseDir) { $file } else { [IO.Path]::Combine($BaseDir, $file) }   # no drive check: pure
            try { $bytes = & $ReadFile $full } catch { $errors.Add("'$d $file': file not found or unreadable"); continue }
            $body = if ($d -eq 'pkcs12') { [Convert]::ToBase64String($bytes) } else { ([Text.Encoding]::UTF8.GetString($bytes)).Trim() }
            # a key file must not be able to close its block early and smuggle options in
            if (@($body -split "`r?`n" | Where-Object { $_.Trim().StartsWith('<') }).Count -gt 0) { $errors.Add("'$d $file' contains a tag line ('<...>') - not a plain key/cert file"); continue }
            [void]$out.AppendLine("<$d>"); [void]$out.AppendLine($body); [void]$out.AppendLine("</$d>")
            if ($d -eq 'tls-auth' -and $arg.Count -ge 2) { [void]$out.AppendLine("key-direction $($arg[1])") }
            continue
        }
        [void]$out.AppendLine($raw)
    }
    if ($inBlock) { $errors.Add("inline block <$inBlock> is not closed") }
    if ($c) { $errors.Add('<connection> is not closed') }
    # a remote's own proto/port, else its <connection> block's, else the global one
    $resolved = @(foreach ($r in $remotes) {
        $bp = if ($r.Block) { $r.Block.Port } else { $null }; $bq = if ($r.Block) { $r.Block.Proto } else { $null }
        [pscustomobject]@{ Host = $r.Host; Port = $(if ($r.Port) { $r.Port } elseif ($bp) { $bp } else { $g.Port }); Proto = $(if ($r.Proto) { $r.Proto } elseif ($bq) { $bq } else { $g.Proto }) } })
    if ($resolved.Count -eq 0) { $errors.Add("no 'remote' line - VeroScudo needs the server to allow it through the kill-switch") }
    if ($resolved.Count -gt 16) { $errors.Add('more than 16 remote servers - keep the ones you use') }
    if (-not $redirect) {
        if ($pull) { $warn.Add("No 'redirect-gateway' in the file: fine if the server pushes it. If it does not (split tunnel), everything outside the tunnel stays blocked while VeroScudo is on.") }
        else { $warn.Add("No 'redirect-gateway': only the tunnel's own routes work; everything else stays blocked while VeroScudo is on.") }
    }
    if (-not $dns -and -not $pull) { $warn.Add("No DNS server for the tunnel ('dhcp-option DNS'): names may not resolve while VeroScudo blocks the local network's DNS.") }
    [pscustomobject]@{ Errors = @($errors); Warnings = @($warn); Remotes = $resolved; Auth = $auth; StaticChallenge = $sc; Text = $out.ToString() }
}

function Import-VeroOpenVpnProfile {
    <# Elevated: checks the user's .ovpn once more, inlines its key files and stores the result as the admin-only copy that
       openvpn.exe will run. Returns the check result (warnings). Throws on any error - nothing is written then. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName, [Parameter(Mandatory)][string]$Source)
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { throw "OpenVPN config not found: $Source" }
    $text = [IO.File]::ReadAllText($Source)                                # read once: what is checked is what is stored
    $r = Test-VeroOpenVpnConf -Text $text -BaseDir (Split-Path -Parent $Source)
    if ($r.Errors.Count -gt 0) { throw ("OpenVPN config '{0}' refused: {1}" -f $Source, ($r.Errors -join '; ')) }
    # what is stored is checked once more as a whole (inlined key files included)
    $again = Test-VeroOpenVpnConf -Text $r.Text -ReadFile { param($x) throw "unexpected file reference $x" }
    if ($again.Errors.Count -gt 0) { throw ("OpenVPN config '{0}' refused after inlining: {1}" -f $Source, ($again.Errors -join '; ')) }
    $null = Protect-VeroOpenVpnDir
    $dst = (Get-VeroPath -VpnProfile $ProfileName).OvpnConfig
    [IO.File]::WriteAllText($dst, $r.Text, (New-Object Text.UTF8Encoding($false)))
    Write-VeroLog "OpenVPN profile '$ProfileName' imported from $Source ($($r.Remotes.Count) server(s); password: $($r.Auth))" 'import'
    $r
}

function Get-VeroOpenVpnRemote {
    <# The 'remote' servers of an imported profile (admin copy). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    $f = (Get-VeroPath -VpnProfile $ProfileName).OvpnConfig
    if (-not (Test-Path $f)) { return @() }
    @((Test-VeroOpenVpnConf -Text ([IO.File]::ReadAllText($f)) -ReadFile { param($x) $null = $x; [byte[]]@() }).Remotes)
}

$script:OvpnExe = $null
# VeroScudo's own TAP adapter for OpenVPN profiles (without DCO OpenVPN otherwise takes ANY free TAP adapter - seen live:
# the one the PrivateVPN app installed and named "PrivateVPN", which also clashes when that app runs at the same time).
$script:OvpnAdapter = 'VeroScudo OpenVPN'
$script:OvpnAdapterNoted = $false
function Get-VeroTapctl {
    <# tapctl.exe, shipped next to openvpn.exe by the OpenVPN community installer. #>
    $exe = Get-VeroOpenVpnExe
    if (-not $exe) { return '' }
    $t = Join-Path (Split-Path $exe -Parent) 'tapctl.exe'
    if (Test-Path -LiteralPath $t -PathType Leaf) { $t } else { '' }
}
function Test-VeroOpenVpnAdapter { [bool](Get-VeroNic | Where-Object { [string]$_.Name -eq $script:OvpnAdapter } | Select-Object -First 1) }
function Initialize-VeroOpenVpnAdapter {
    <# Makes sure the 'VeroScudo OpenVPN' adapter exists (elevated: installer, OpenVPN runner). True when OpenVPN can be
       pinned to it; false = OpenVPN keeps choosing a free TAP adapter itself (said once per process, in the log). #>
    [CmdletBinding()] param([string]$Action = 'core')
    if (Test-VeroOpenVpnAdapter) { return $true }
    $t = Get-VeroTapctl
    $why = ''
    if (-not $t) { $why = 'tapctl.exe not found next to openvpn.exe' }
    else {
        $out = & $t create --hwid 'root\tap0901' --name $script:OvpnAdapter 2>&1
        $code = $LASTEXITCODE
        $deadline = (Get-Date).AddSeconds(5)
        while (-not (Test-VeroOpenVpnAdapter) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }
        if (Test-VeroOpenVpnAdapter) { Write-VeroLog "created network adapter '$($script:OvpnAdapter)' for VeroScudo's OpenVPN profiles" $Action; return $true }
        $why = "tapctl create failed (exit $code): $((@($out) | ForEach-Object { [string]$_ }) -join ' ') - is the TAP-Windows driver installed?"
    }
    if (-not $script:OvpnAdapterNoted) { Write-VeroLog "NOTE: no '$($script:OvpnAdapter)' adapter ($why) - OpenVPN uses any free TAP adapter" $Action; $script:OvpnAdapterNoted = $true }
    $false
}
function Remove-VeroOpenVpnAdapter {
    <# Uninstall: removes the adapter VeroScudo created (only that one, by its exact name). #>
    [CmdletBinding()] param([string]$Action = 'uninstall')
    if (-not (Test-VeroOpenVpnAdapter)) { return }
    $t = Get-VeroTapctl
    if (-not $t) { Write-VeroLog "WARNING: '$($script:OvpnAdapter)' adapter left in place - tapctl.exe not found (remove it in Device Manager)" $Action; return }
    $out = & $t delete $script:OvpnAdapter 2>&1
    if ($LASTEXITCODE -eq 0) { Write-VeroLog "removed network adapter '$($script:OvpnAdapter)'" $Action }
    else { Write-VeroLog "WARNING: could not remove the '$($script:OvpnAdapter)' adapter: $((@($out) | ForEach-Object { [string]$_ }) -join ' ')" $Action }
}

function Get-VeroOpenVpnExe {
    <# openvpn.exe of the OpenVPN community installer (HKLM, administrators only), else its default location. #>
    if ($script:OvpnExe) { return $script:OvpnExe }
    $cand = @()
    try { $k = Get-ItemProperty 'HKLM:\SOFTWARE\OpenVPN' -ErrorAction Stop; if ($k.PSObject.Properties['exe_path']) { $cand += [string]$k.exe_path } } catch { Write-Verbose 'no OpenVPN registry key' }
    $cand += (Join-Path (Get-VeroSystemDir ProgramFiles) 'OpenVPN\bin\openvpn.exe')
    foreach ($c in $cand) { if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) { $script:OvpnExe = $c; return $c } }
    ''
}

function Get-VeroOpenVpnVersion([string]$Exe) {
    try { $v = (& $Exe --version 2>&1 | Select-Object -First 1) -join ''; if ($v -match 'OpenVPN (\d+\.\d+(\.\d+)?)') { return [version]$Matches[1] } } catch { Write-Verbose 'openvpn --version failed' }
    [version]'0.0'
}

function Get-VeroOpenVpnArgs {
    <# The openvpn.exe command line. Pure. The user's file is used as is; VeroScudo's own options come after it so they win:
       management on localhost with a one-time password, hold until we release, passwords asked over the management
       connection (never a file), no user scripts, our log, and no DCO unless the profile allows it (then the permit can be
       tied to openvpn.exe). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ConfigPath, [Parameter(Mandatory)][int]$Port, [Parameter(Mandatory)][string]$PwFile,
                            [Parameter(Mandatory)][string]$LogPath, [version]$Version = [version]'2.6', [bool]$Dco = $false, [bool]$Auth = $true,
                            [string]$DevNode = '')
    $q = { param($x) '"' + ($x -replace '"', '') + '"' }
    $a = @('--config', (& $q $ConfigPath), '--management', '127.0.0.1', $Port, (& $q $PwFile), '--management-hold', '--management-query-passwords',
           '--auth-retry', 'interact', '--auth-nocache', '--script-security', '1', '--log', (& $q $LogPath), '--verb', '3')
    if ($Auth) { $a += '--auth-user-pass' }                                 # overrides any file named in the config
    if (-not $Dco -and $Version -ge [version]'2.6') { $a += '--disable-dco' }
    if ($DevNode -and -not $Dco) { $a += @('--dev-node', (& $q $DevNode)) }  # VeroScudo's own TAP adapter, never another app's
    $a -join ' '
}

function ConvertFrom-VeroMgmtLine {
    <# One line of the OpenVPN management interface -> what it means. Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Line)
    $r = [ordered]@{ Kind = 'other'; State = ''; Reason = ''; LocalIp = ''; Which = ''; Challenge = ''; Dynamic = $false }
    if ($Line -match '^>STATE:\d*,([A-Z_]+),([^,]*),([^,]*)') {
        $r.Kind = 'state'; $r.State = $Matches[1]; $r.Reason = $Matches[2]; $r.LocalIp = $Matches[3]
    } elseif ($Line -match "^>PASSWORD:Need '([^']+)'(.*)$") {
        $r.Kind = 'need'; $r.Which = $Matches[1]
        if ($Matches[2] -match 'SC:\d+,(.*)$') { $r.Challenge = $Matches[1].Trim(); if (-not $r.Challenge) { $r.Challenge = 'one-time code' } }
    } elseif ($Line -match "^>PASSWORD:Verification Failed: '([^']+)'(.*)$") {
        $r.Kind = 'failed'; $r.Which = $Matches[1]; $r.Dynamic = ($Matches[2] -match 'CRV1:')
    } elseif ($Line -match '^>HOLD:') { $r.Kind = 'hold' }
    elseif ($Line -match '^>FATAL:(.*)$') { $r.Kind = 'fatal'; $r.Reason = $Matches[1] }
    elseif ($Line -match '^ERROR:(.*)$') { $r.Kind = 'error'; $r.Reason = $Matches[1].Trim() }
    [pscustomobject]$r
}

function Format-VeroMgmtValue {
    <# A value for a management command: quoted, backslash and double quote escaped. Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    if ($Value -match '[\r\n]') { throw 'line breaks are not allowed in a credential' }
    '"' + ($Value -replace '\\', '\\' -replace '"', '\"') + '"'
}

function Get-VeroStaticChallengeResponse {
    <# OpenVPN static-challenge password: SCRV1:<base64 password>:<base64 response>. Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Password, [Parameter(Mandatory)][AllowEmptyString()][string]$Response)
    'SCRV1:{0}:{1}' -f [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Password)), [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Response))
}

# ---------------------------------------------------------------- OpenVPN: runner status (state folder, written elevated)
function Get-VeroOpenVpnStatus([string]$ProfileName) {
    $f = (Get-VeroPath -VpnProfile $ProfileName).OvpnStatus
    if (Test-Path $f) { try { return (Get-Content $f -Raw | ConvertFrom-Json) } catch { Write-Verbose 'openvpn status unreadable' } }
    $null
}
function Set-VeroOpenVpnStatus([string]$ProfileName, [hashtable]$Fields) {
    $p = Get-VeroPath -VpnProfile $ProfileName
    $cur = [ordered]@{ State = ''; Reason = ''; LocalIp = ''; RunnerPid = 0; OvpnPid = 0; Challenge = ''; Time = '' }
    $old = Get-VeroOpenVpnStatus $ProfileName
    if ($old) { foreach ($k in @($cur.Keys)) { if ($old.PSObject.Properties[$k]) { $cur[$k] = $old.$k } } }
    foreach ($k in $Fields.Keys) { $cur[$k] = $Fields[$k] }
    $cur.Time = (Get-Date).ToString('o')
    $tmp = "$($p.OvpnStatus).new"
    $cur | ConvertTo-Json | Set-Content $tmp
    Move-Item $tmp $p.OvpnStatus -Force
}

function Get-VeroOpenVpnNic([string]$ProfileName) {
    <# The tunnel adapter that carries the address OpenVPN reported on CONNECTED - only a tunnel adapter, never a physical NIC. #>
    $s = Get-VeroOpenVpnStatus $ProfileName
    if (-not $s -or [string]$s.State -ne 'CONNECTED' -or -not [string]$s.LocalIp) { return $null }
    $ip = [string]$s.LocalIp
    Get-VeroNic | Where-Object { [string]$_.OperationalStatus -eq 'Up' -and (Test-VeroTunnelAdapter $_) -and
                                 (@($_.GetIPProperties().UnicastAddresses | ForEach-Object { $_.Address.ToString() }) -contains $ip) } | Select-Object -First 1
}

function Test-VeroOpenVpnRunnerAlive {
    $m = $null
    try { if ([System.Threading.Mutex]::TryOpenExisting('Local\VeroScudo-OpenVPN', [ref]$m)) { $m.Dispose(); return $true } } catch { Write-Verbose 'mutex check failed' }
    $false
}

function Invoke-VeroOpenVpnDial {
    <# Makes sure the OpenVPN runner (a long-running elevated task) is up, then waits up to 30 s for CONNECTED. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core')
    $p = Get-VeroPath -VpnProfile $Config.Profile
    if (-not (Test-Path $p.OvpnConfig)) { Write-VeroLog "ERROR: OpenVPN profile '$($Config.Profile)' is not imported (tray Settings, or Install.ps1 -OpenVpnConfig)" $Action; return }
    if (-not (Get-VeroOpenVpnExe)) { Write-VeroLog 'ERROR: openvpn.exe not found - install OpenVPN (community edition, openvpn.net/community)' $Action; return }
    if (-not (Test-VeroOpenVpnRunnerAlive)) {
        Remove-Item $p.OvpnStop -Force -ErrorAction SilentlyContinue
        Set-VeroOpenVpnStatus $Config.Profile @{ State = 'STARTING'; Reason = ''; LocalIp = ''; Challenge = '' }   # not the last run's result
        Write-VeroLog "starting OpenVPN for '$($Config.Profile)'" $Action
        & $script:Schtasks /run /tn '\VeroScudo\OpenVPN' 2>&1 | Out-Null
    }
    $t = Get-Date
    while (((Get-Date) - $t).TotalSeconds -lt 30) {
        Start-Sleep -Seconds 1
        if (Test-VeroVpnConnected $Config.Profile -Type 'openvpn') { return }
        if (Get-VeroPendingSwitch) { return }                                # you chose another profile: the loop switches
        $s = Get-VeroOpenVpnStatus $Config.Profile
        if ($s -and [string]$s.State -in 'AUTH_FAILED', 'NO_PASSWORD', 'NEED_OTP') { return }
    }
}

function Stop-VeroOpenVpn {
    <# Asks the runner to stop OpenVPN (it sends SIGTERM over the management connection); kills a leftover process only
       when it really is that openvpn.exe. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    $p = Get-VeroPath -VpnProfile $ProfileName
    Set-Content -Path $p.OvpnStop -Value (Get-Date).ToString('o')
    $t = Get-Date
    while ((Test-VeroOpenVpnRunnerAlive) -and ((Get-Date) - $t).TotalSeconds -lt 15) { Start-Sleep -Milliseconds 500 }   # gone, so a redial starts a fresh one
    Stop-VeroOpenVpnOrphan -ProfileName $ProfileName
}

function Stop-VeroOpenVpnOrphan([string]$ProfileName) {
    $s = Get-VeroOpenVpnStatus $ProfileName
    if (-not $s -or -not $s.OvpnPid) { return }
    $proc = Get-Process -Id ([int]$s.OvpnPid) -ErrorAction SilentlyContinue
    $started = try { $proc.StartTime } catch { $null }
    $when = try { [datetime]::Parse([string]$s.Time, $null, [Globalization.DateTimeStyles]::RoundtripKind) } catch { Get-Date }
    if ($proc -and $proc.ProcessName -eq 'openvpn' -and $started -and $started -le $when) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Write-VeroLog "stopped a leftover openvpn.exe (PID $($proc.Id)) of '$ProfileName'" 'openvpn'
    }
}

# ---------------------------------------------------------------- OpenVPN: the runner (elevated task \VeroScudo\OpenVPN)
function Get-VeroFreePort {
    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $l.Start(); $port = $l.LocalEndpoint.Port; $l.Stop(); $port
}
function New-VeroSecret {
    $b = New-Object byte[] 24
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create(); $rng.GetBytes($b); $rng.Dispose()
    [Convert]::ToBase64String($b) -replace '[+/=]', 'x'
}

function Send-VeroMgmt($M, [string]$Command) {
    $b = [Text.Encoding]::UTF8.GetBytes($Command + "`n")
    $M.Stream.Write($b, 0, $b.Length); $M.Stream.Flush()
}

function Read-VeroMgmt($M, [int]$TimeoutMs = 1000) {
    <# Complete lines that arrived within the timeout; $null once the connection closed. #>
    $sock = $M.Client.Client
    if ($sock.Poll($TimeoutMs * 1000, [System.Net.Sockets.SelectMode]::SelectRead)) {
        if ($sock.Available -eq 0) { return $null }
        $buf = New-Object byte[] 8192
        $n = $M.Stream.Read($buf, 0, $buf.Length)
        if ($n -le 0) { return $null }
        [void]$M.Pending.Append([Text.Encoding]::UTF8.GetString($buf, 0, $n))
    }
    $text = $M.Pending.ToString()
    $i = $text.LastIndexOf("`n")
    if ($i -lt 0) { return , @() }
    $M.Pending.Length = 0; [void]$M.Pending.Append($text.Substring($i + 1))
    , @($text.Substring(0, $i) -split "`n" | ForEach-Object { $_.TrimEnd("`r") } | Where-Object { $_ })
}

function Connect-VeroMgmt([int]$Port, [string]$Password, $Process) {
    <# Connects to the management port (OpenVPN opens it a moment after start) and logs in with the one-time password. #>
    $t = Get-Date
    while (((Get-Date) - $t).TotalSeconds -lt 15 -and -not $Process.HasExited) {
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $c.Connect([System.Net.IPAddress]::Loopback, $Port)
            $m = [pscustomobject]@{ Client = $c; Stream = $c.GetStream(); Pending = (New-Object System.Text.StringBuilder) }
            $t2 = Get-Date
            while (((Get-Date) - $t2).TotalSeconds -lt 5) {
                $null = Read-VeroMgmt $m 500
                if ($m.Pending.ToString() -match 'ENTER PASSWORD:') { $m.Pending.Length = 0; Send-VeroMgmt $m $Password; return $m }
            }
            $c.Close()
        } catch { Start-Sleep -Milliseconds 300 }
    }
    $null
}

function Get-VeroOpenVpnStopReason([string]$ProfileName) {
    $p = Get-VeroPath -VpnProfile $ProfileName
    if (Test-Path $p.OvpnStop) { return 'stop requested' }
    if (-not (Test-VeroArmed)) { return 'VPN turned off' }
    $c = Get-VeroConfig
    if ($c.Profile -ne $ProfileName) { return "profile switched to '$($c.Profile)'" }
    $null
}

function Invoke-VeroOpenVpnSession {
    <# One openvpn.exe run, driven through its management connection. Returns why it ended:
       'stopped' (VeroScudo asked), 'exited' (OpenVPN ended on its own - a failure), 'auth-failed', 'no-password', 'otp' or 'setup'. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'openvpn')
    $name = $Config.Profile
    $p = Get-VeroPath -VpnProfile $name
    $exe = Get-VeroOpenVpnExe
    if (-not $exe -or -not (Test-Path $p.OvpnConfig)) { Write-VeroLog "ERROR: OpenVPN not installed or '$name' not imported" $Action; return 'setup' }
    $cred = if ($Config.Auth) { Get-VeroCredential -Config $Config } else { $null }
    if ($Config.Auth -and -not $cred) { Set-VeroOpenVpnStatus $name @{ State = 'NO_PASSWORD'; Reason = 'no stored password' }; Write-VeroLog "ERROR: no stored password for '$name' (tray Settings)" $Action; return 'no-password' }
    $port = Get-VeroFreePort; $secret = New-VeroSecret
    Write-VeroSecretFile -Path $p.OvpnPw -Text $secret
    $dev = if (-not $Config.Dco -and (Initialize-VeroOpenVpnAdapter -Action $Action)) { $script:OvpnAdapter } else { '' }
    $argLine = Get-VeroOpenVpnArgs -ConfigPath $p.OvpnConfig -Port $port -PwFile $p.OvpnPw -LogPath $p.OvpnLog -Version (Get-VeroOpenVpnVersion $exe) -Dco $Config.Dco -Auth $Config.Auth -DevNode $dev
    # the previous run's log is kept (OpenVPN rewrites its log on every start - a failed start's log was lost that way)
    if (Test-Path $p.OvpnLog) { Move-Item -LiteralPath $p.OvpnLog -Destination ($p.OvpnLog -replace '\.log$', '.prev.log') -Force -ErrorAction SilentlyContinue }
    $proc = Start-Process -FilePath $exe -ArgumentList $argLine -WindowStyle Hidden -PassThru
    Set-VeroOpenVpnStatus $name @{ State = 'STARTING'; Reason = ''; LocalIp = ''; RunnerPid = $PID; OvpnPid = $proc.Id; Challenge = '' }
    $result = 'exited'; $reason = ''; $m = $null; $stopping = $null; $deadline = $null
    # what OpenVPN said last (never what VeroScudo sent - that holds the credentials): logged when a start makes no progress
    $trace = New-Object System.Collections.Generic.Queue[string]
    $progress = Get-Date; $curState = 'STARTING'; $waitingOtp = $false
    try {
        $m = Connect-VeroMgmt -Port $port -Password $secret -Process $proc
        Remove-Item $p.OvpnPw -Force -ErrorAction SilentlyContinue
        if (-not $m) { $reason = 'management interface did not answer' }
        else { Send-VeroMgmt $m 'state on'; Send-VeroMgmt $m 'hold release' }
        while ($m) {
            if (-not $stopping) {
                $stopping = Get-VeroOpenVpnStopReason $name
                if ($stopping) { Write-VeroLog "stopping OpenVPN '$name' ($stopping)" $Action; Send-VeroMgmt $m 'signal SIGTERM'; $deadline = (Get-Date).AddSeconds(10); $result = 'stopped'; $reason = $stopping }
            } elseif ((Get-Date) -gt $deadline) { break }
            $lines = Read-VeroMgmt $m 1000
            if ($null -eq $lines) { break }
            # no progress for 45 s before CONNECTED (no new state, no password asked): restart it instead of waiting for ever
            # (seen live twice: a start sat in STARTING, OpenVPN never asked for the password; the next start took 7 s)
            if (-not $stopping -and -not $waitingOtp -and $curState -ne 'CONNECTED' -and ((Get-Date) - $progress).TotalSeconds -gt 45) {
                Write-VeroLog ("OpenVPN '{0}' made no progress for 45 s (state {1}) - restarting it. Last from OpenVPN: {2}" -f $name, $curState, ((@($trace) | Select-Object -Last 8) -join ' | ')) $Action
                Send-VeroMgmt $m 'signal SIGTERM'; $stopping = 'no progress for 45 s'; $deadline = (Get-Date).AddSeconds(10); $reason = $stopping
            }
            foreach ($line in $lines) {
                if ($line -notmatch '^>PASSWORD:Verification|^>BYTECOUNT') { $trace.Enqueue($line); while ($trace.Count -gt 30) { $null = $trace.Dequeue() } }
                $e = ConvertFrom-VeroMgmtLine $line
                if ($e.Kind -in 'state', 'need', 'hold') { $progress = Get-Date; if ($e.Kind -eq 'state') { $curState = $e.State } }
                switch ($e.Kind) {
                    'hold' { Send-VeroMgmt $m 'hold release' }
                    'state' {
                        Set-VeroOpenVpnStatus $name @{ State = $e.State; Reason = $e.Reason; LocalIp = $(if ($e.State -eq 'CONNECTED') { $e.LocalIp } else { '' }) }
                        if ($e.State -in 'CONNECTED', 'RECONNECTING', 'EXITING') {
                            Write-VeroLog "OpenVPN '$name': $($e.State)$(if ($e.Reason) { ' (' + $e.Reason + ')' })" $Action
                            if ($e.State -eq 'EXITING' -and -not $stopping) { $reason = $e.Reason }
                            if (Test-VeroArmed) { Sync-VeroKillSwitch -Config (Get-VeroConfig) -Action $Action }
                        }
                    }
                    'need' {
                        if ($stopping) { break }                            # never re-send a just-rejected password
                        if ($e.Which -eq 'Auth') {
                            if (-not $cred) { $result = 'no-password'; $reason = 'the server asks for a password - none stored'; Send-VeroMgmt $m 'signal SIGTERM'; $stopping = $reason; $deadline = (Get-Date).AddSeconds(10); break }
                            $pw = $cred.GetNetworkCredential().Password
                            if ($e.Challenge) {
                                $waitingOtp = $true
                                $otp = Wait-VeroOtp -ProfileName $name -Challenge $e.Challenge -Action $Action
                                $waitingOtp = $false; $progress = Get-Date
                                if ($null -eq $otp) { $result = 'otp'; $reason = 'no one-time code entered'; Send-VeroMgmt $m 'signal SIGTERM'; $stopping = $reason; $deadline = (Get-Date).AddSeconds(10); break }
                                $pw = Get-VeroStaticChallengeResponse -Password $pw -Response $otp
                            }
                            Send-VeroMgmt $m ('username "Auth" ' + (Format-VeroMgmtValue $cred.UserName))
                            Send-VeroMgmt $m ('password "Auth" ' + (Format-VeroMgmtValue $pw))
                            $pw = $null
                        } elseif ($e.Which -eq 'Private Key') {
                            $kp = Get-VeroKeyPassphrase -ProfileName $name
                            if (-not $kp) { $result = 'no-password'; $reason = 'the private key needs a passphrase - none stored'; Send-VeroMgmt $m 'signal SIGTERM'; $stopping = $reason; $deadline = (Get-Date).AddSeconds(10); break }
                            Send-VeroMgmt $m ('password "Private Key" ' + (Format-VeroMgmtValue $kp.GetNetworkCredential().Password))
                        } else {
                            $result = 'setup'; $reason = "OpenVPN asks for '$($e.Which)', which VeroScudo cannot answer"; Send-VeroMgmt $m 'signal SIGTERM'; $stopping = $reason; $deadline = (Get-Date).AddSeconds(10)
                        }
                    }
                    'failed' {
                        $result = 'auth-failed'
                        $reason = if ($e.Dynamic) { 'the server asks for a dynamic challenge (CRV1), which VeroScudo cannot answer' } else { "$($e.Which) rejected by the server" }
                        Set-VeroAuthFailed -ProfileName $name -Reason "OpenVPN: $reason" -Action $Action -Which $(if ($e.Which -eq 'Private Key') { 'Key' } else { 'Auth' })
                        Send-VeroMgmt $m 'signal SIGTERM'; $stopping = $reason; $deadline = (Get-Date).AddSeconds(10)
                    }
                    'fatal' { Write-VeroLog "OpenVPN '$name' FATAL: $($e.Reason)" $Action; $reason = $e.Reason }
                    'error' { Write-VeroLog "OpenVPN '$name' management: $($e.Reason)" $Action }
                }
            }
        }
    } finally {
        if ($m) { try { $m.Client.Close() } catch { Write-Verbose 'close failed' } }
        if (-not $proc.HasExited) { if (-not $proc.WaitForExit(5000)) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } }
        Remove-Item $p.OvpnPw -Force -ErrorAction SilentlyContinue
        $final = switch ($result) { 'auth-failed' { 'AUTH_FAILED' } 'no-password' { 'NO_PASSWORD' } 'otp' { 'NEED_OTP' } default { 'EXITED' } }
        Set-VeroOpenVpnStatus $name @{ State = $final; Reason = $reason; LocalIp = ''; OvpnPid = 0; Challenge = '' }
        if (Test-VeroArmed) { try { Sync-VeroKillSwitch -Config (Get-VeroConfig) -Action $Action } catch { Write-VeroLog "ERROR: sync after OpenVPN exit: $($_.Exception.Message)" $Action } }
    }
    Write-VeroLog ("OpenVPN '{0}' ended: {1}{2} (decision source: {3})" -f $name, $result, $(if ($reason) { " - $reason" }),
        $(if ($result -eq 'stopped') { "VeroScudo's own stop" } else { 'OpenVPN exited on its own = failure, stays blocked' })) $Action
    $result
}

function Wait-VeroOtp {
    <# Static challenge: the tray shows the question, the user types the code; it arrives as a file in the user's folder.
       Waits up to 2 minutes; $null when no code came (or VeroScudo was turned off meanwhile). #>
    [CmdletBinding()] param([string]$ProfileName, [string]$Challenge, [string]$Action = 'openvpn')
    $p = Get-VeroPath -VpnProfile $ProfileName
    Remove-Item $p.Otp -Force -ErrorAction SilentlyContinue
    Set-VeroOpenVpnStatus $ProfileName @{ State = 'NEED_OTP'; Challenge = $Challenge }
    Write-VeroLog "OpenVPN '$ProfileName' asks for a one-time code - type it in the tray" $Action
    $t = Get-Date
    while (((Get-Date) - $t).TotalSeconds -lt 120) {
        if (Test-Path $p.Otp) {
            $code = (Get-Content $p.Otp -Raw -ErrorAction SilentlyContinue); Remove-Item $p.Otp -Force -ErrorAction SilentlyContinue
            Set-VeroOpenVpnStatus $ProfileName @{ State = 'AUTH'; Challenge = '' }
            if ($code) { return $code.Trim() }
        }
        if (Get-VeroOpenVpnStopReason $ProfileName) { break }
        Start-Sleep -Milliseconds 500
    }
    $null
}

function Invoke-VeroOpenVpnRunner {
    <# The long-running elevated runner (scheduled task \VeroScudo\OpenVPN, one per session). Runs openvpn.exe for the active
       profile while VeroScudo is on; an OpenVPN that ends on its own is a failure: restarted every retrySeconds. Ends when
       VeroScudo is turned off, another profile type becomes active, a password is rejected or VeroScudo asks it to stop. #>
    [CmdletBinding()] param([string]$Action = 'openvpn')
    $mutex = New-Object System.Threading.Mutex($false, 'Local\VeroScudo-OpenVPN')
    $mine = $false
    try { $mine = $mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $mine = $true }
    if (-not $mine) { $mutex.Dispose(); return }
    try {
        $cfg = Get-VeroConfig
        foreach ($pr in @($cfg.Profiles | Where-Object Type -eq 'openvpn')) { Stop-VeroOpenVpnOrphan -ProfileName $pr.Profile }
        while ($true) {
            $cfg = Get-VeroConfig
            if ((Get-VeroConfigType $cfg) -ne 'openvpn' -or -not (Test-VeroArmed)) { break }
            $p = Get-VeroPath -VpnProfile $cfg.Profile
            if (Test-Path $p.OvpnStop) { Remove-Item $p.OvpnStop -Force -ErrorAction SilentlyContinue; break }
            if (Test-VeroAuthBlocked $cfg.Profile) { break }
            $r = Invoke-VeroOpenVpnSession -Config $cfg -Action $Action
            if ($r -ne 'exited') { Remove-Item $p.OvpnStop -Force -ErrorAction SilentlyContinue; break }
            Start-Sleep -Seconds $cfg.RetrySeconds
        }
    } finally { $mutex.ReleaseMutex(); $mutex.Dispose() }
}

# ---------------------------------------------------------------- WireGuard (the WireGuard for Windows app's tunnel services)
function Get-VeroWgDir { Join-Path (Get-VeroSystemDir ProgramFiles) 'WireGuard' }
function Get-VeroWgServiceName([string]$Name) { 'WireGuardTunnel$' + $Name }
function Get-VeroWgState {
    <# 'running', 'stopped' (installed, not running: crashed or stopped in services.msc) or 'missing' (not installed:
       deactivated in the WireGuard app, or never activated). Readable without admin rights. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    $s = Get-Service -Name (Get-VeroWgServiceName $ProfileName) -ErrorAction SilentlyContinue
    if (-not $s) { return 'missing' }
    if ([string]$s.Status -eq 'Running') { 'running' } else { 'stopped' }
}
function Get-VeroWgNic([string]$ProfileName) {
    Get-VeroNic | Where-Object { $_.Name -eq $ProfileName -and [string]$_.Description -like 'WireGuard*' -and [string]$_.OperationalStatus -eq 'Up' } | Select-Object -First 1
}

function Get-VeroWgHealth {
    <# Pure. 'up' = a handshake within the last 3 minutes (a live WireGuard link re-handshakes every 2); 'starting' = service
       started less than 30 s ago and no fresh handshake yet; 'stale' = running but silent (dead link: its adapter stays up);
       'down' = service not running. #>
    [CmdletBinding()] param([string]$ServiceState, [int64[]]$Handshakes = @(), [int64]$Now, [double]$ServiceAgeSeconds = 1e9,
                            [int]$StaleSeconds = $script:WgStaleSeconds, [int]$GraceSeconds = $script:WgGraceSeconds)
    if ($ServiceState -ne 'running') { return 'down' }
    $last = [int64]0
    foreach ($h in $Handshakes) { if ($h -gt $last) { $last = $h } }
    if ($last -gt 0 -and ($Now - $last) -le $StaleSeconds) { return 'up' }
    if ($ServiceAgeSeconds -lt $GraceSeconds) { return 'starting' }
    'stale'
}

function Get-VeroWgTransition {
    <# Pure. What a change of a WireGuard tunnel service between two watchdog passes means:
       'arm'    - it started (activated in the WireGuard app) while not already the armed, active profile: like connecting a
                  Windows VPN by hand, it arms VeroScudo and becomes the active profile;
       'disarm' - the active profile's service was REMOVED (deactivated in the WireGuard app) while armed and VeroScudo was
                  not reconnecting it itself: the user's Off;
       'none'   - anything else (a crash or a stop leaves the service installed: that is a failure, the redial handles it). #>
    [CmdletBinding()] param([string]$Previous, [string]$Current, [bool]$Armed, [bool]$Active, [bool]$LockAlive)
    if (-not $Previous -or $Previous -eq $Current -or $LockAlive) { return 'none' }
    if ($Current -eq 'running' -and -not ($Armed -and $Active)) { return 'arm' }
    if ($Previous -eq 'running' -and $Current -eq 'missing' -and $Armed -and $Active) { return 'disarm' }
    'none'
}

$script:WgSeen = @{}
function Update-VeroWgWatch {
    <# Watchdog pass for WireGuard profiles: service start/removal by the WireGuard app (Get-VeroWgTransition). True when it
       changed the state. Only the long-running watchdog keeps the previous observation, so only it sees the edges.
       Every 'arm' is handled before any 'disarm', and each decision re-reads the armed flag and the active profile: switching
       tunnels in the WireGuard app (B activated, A removed in one pass) must end armed on B, never disarmed. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'watchdog')
    $changed = $false
    $seen = @(foreach ($pr in @($Config.Profiles | Where-Object Type -eq 'wireguard')) {
        $cur = Get-VeroWgState $pr.Profile
        $prev = $script:WgSeen[$pr.Profile]
        $script:WgSeen[$pr.Profile] = $cur
        [pscustomobject]@{ Name = $pr.Profile; Prev = $prev; Cur = $cur }
    })
    $started = @($seen | Where-Object { $_.Cur -eq 'running' -and $_.Prev -and $_.Prev -ne 'running' })
    foreach ($x in $started) {
        $d = Get-VeroWgTransition -Previous $x.Prev -Current $x.Cur -Armed (Test-VeroArmed) -Active ($x.Name -eq (Get-VeroConfig).Profile) -LockAlive (Test-VeroLockAlive)
        if ($d -ne 'arm') { continue }
        Write-VeroLog "WireGuard tunnel '$($x.Name)' was activated outside VeroScudo - it becomes the active profile, kill-switch on (decision source: WireGuard service started)" $Action
        Set-VeroActiveProfile -Name $x.Name -Action $Action
        Set-VeroArmed $true $Action
        Sync-VeroKillSwitch -Config (Get-VeroConfig) -Action $Action
        $changed = $true
    }
    foreach ($x in @($seen | Where-Object { $started -notcontains $_ })) {
        $active = (Get-VeroConfig).Profile
        $d = Get-VeroWgTransition -Previous $x.Prev -Current $x.Cur -Armed (Test-VeroArmed) -Active ($x.Name -eq $active) -LockAlive (Test-VeroLockAlive)
        if ($d -eq 'disarm') {
            Write-VeroLog "WireGuard tunnel '$($x.Name)' was deactivated in the WireGuard app - treated as your Off (decision source: WireGuard service removed, not by VeroScudo)" $Action
            Set-VeroArmed $false $Action
            Disable-VeroKillSwitch -Action $Action
            $changed = $true
        } elseif ($x.Prev -eq 'running' -and $x.Cur -eq 'stopped' -and $x.Name -eq $active -and (Test-VeroArmed)) {
            Write-VeroLog "WireGuard service of '$($x.Name)' stopped but is still installed (crash or services.msc) - a failure: stays blocked, redials" $Action
        }
    }
    $changed
}

function Get-VeroWgServiceAge([string]$ProfileName) {
    try {
        $svc = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f ((Get-VeroWgServiceName $ProfileName) -replace "'", "''")) -ErrorAction Stop
        if ($svc -and $svc.ProcessId) { return ((Get-Date) - (Get-Process -Id $svc.ProcessId -ErrorAction Stop).StartTime).TotalSeconds }
    } catch { Write-Verbose "service age: $($_.Exception.Message)" }
    1e9
}

function Get-VeroWgHealthNow {
    <# Elevated: asks wg.exe for the handshakes (and learns the endpoint the tunnel really uses), caches the result for the
       tray. Not elevated (tray): the cached result if recent, else just "the service runs". #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    $p = Get-VeroPath -VpnProfile $ProfileName
    $state = Get-VeroWgState $ProfileName
    if ($state -ne 'running') { return 'down' }
    if (-not (Test-VeroElevated)) {
        try {
            $c = Get-Content $p.TunnelCache -Raw -ErrorAction Stop | ConvertFrom-Json
            if (((Get-Date) - [datetime]::Parse([string]$c.Time, $null, [Globalization.DateTimeStyles]::RoundtripKind)).TotalSeconds -lt 60) { return [string]$c.Health }
        } catch { Write-Verbose 'no recent WireGuard health' }
        return 'up'
    }
    $wg = Join-Path (Get-VeroWgDir) 'wg.exe'
    $hs = @()
    $ErrorActionPreference = 'Continue'                                    # (local) PS 5.1 turns native stderr into errors under Stop
    try {
        $hs = @(& $wg show $ProfileName latest-handshakes 2>$null | ForEach-Object { $f = ($_ -split '\s+'); if ($f.Count -ge 2) { [int64]$f[1] } })
        $eps = @(& $wg show $ProfileName endpoints 2>$null | ForEach-Object { $f = ($_ -split '\s+'); if ($f.Count -ge 2 -and $f[1] -match '^\[?([0-9a-fA-F:.]+)\]?:\d+$') { $Matches[1] } })
        if ($eps.Count -gt 0) { Add-VeroServerIpCache -ProfileName $ProfileName -Ips $eps }
    } catch { Write-Verbose "wg show failed: $($_.Exception.Message)" }
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $h = Get-VeroWgHealth -ServiceState $state -Handshakes $hs -Now $now -ServiceAgeSeconds 0                  # 0: 'up' or not, cheaply
    if ($h -ne 'up') { $h = Get-VeroWgHealth -ServiceState $state -Handshakes $hs -Now $now -ServiceAgeSeconds (Get-VeroWgServiceAge $ProfileName) }
    try { @{ Health = $h; Time = (Get-Date).ToString('o') } | ConvertTo-Json | Set-Content $p.TunnelCache } catch { Write-Verbose 'tunnel cache not writable' }
    $h
}

function Add-VeroServerIpCache([string]$ProfileName, [string[]]$Ips) {
    <# The address a WireGuard tunnel really talks to goes to the front of the server cache (the kill-switch then allows it). #>
    $p = Get-VeroPath -VpnProfile $ProfileName
    # [string]: Get-Content tags each line with its file path, and ConvertTo-Json would write those tags into wfp.json
    $cached = @(if (Test-Path $p.ServerIp) { Get-Content $p.ServerIp | Where-Object { $_ } | ForEach-Object { [string]$_ } })
    $all = @(@($Ips) + $cached | Where-Object { $_ } | Select-Object -Unique | Select-Object -First 8)
    if (($all -join ',') -ne ($cached -join ',')) { Set-Content -Path $p.ServerIp -Value $all }
}

function Invoke-VeroWgDial {
    <# Starts the tunnel service (installs it from the WireGuard app's stored config when it is not installed). A running
       tunnel without a fresh handshake is restarted: that also looks the server name up again. Waits up to 15 s. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core')
    $name = $Config.Profile
    $exe = Join-Path (Get-VeroWgDir) 'wireguard.exe'
    if (-not (Test-Path $exe)) { Write-VeroLog 'ERROR: WireGuard for Windows is not installed (wireguard.com/install)' $Action; return }
    $state = Get-VeroWgState $name
    if ($state -eq 'running') {
        $h = Get-VeroWgHealthNow $name
        if ($h -eq 'starting') { Start-Sleep -Seconds 5; return }
        if ($h -eq 'up') { return }
        Write-VeroLog "WireGuard '$name': no handshake for over $($script:WgStaleSeconds / 60) minutes - restarting the tunnel" $Action
        Invoke-VeroWgHangUp -ProfileName $name
        Sync-VeroKillSwitch -Config $Config -Action $Action                 # tunnel gone: the redial's DNS permit is back for the endpoint name
        $state = Get-VeroWgState $name
    }
    if ($state -eq 'stopped') {
        Start-Service -Name (Get-VeroWgServiceName $name) -ErrorAction SilentlyContinue
    } else {
        $conf = Join-Path (Get-VeroWgDir) "Data\Configurations\$name.conf.dpapi"
        if (-not (Test-Path $conf)) { Write-VeroLog "ERROR: WireGuard tunnel '$name' not found - import it in the WireGuard app first" $Action; return }
        Start-Process -FilePath $exe -ArgumentList ('/installtunnelservice "{0}"' -f $conf) -WindowStyle Hidden -Wait
    }
    $t = Get-Date
    while (((Get-Date) - $t).TotalSeconds -lt 15) { Start-Sleep -Seconds 1; if ((Get-VeroWgHealthNow $name) -eq 'up') { return }; if (Get-VeroPendingSwitch) { return } }
}

function Invoke-VeroWgHangUp {
    <# Deactivates the tunnel exactly like the WireGuard app does (removes its service), so the app shows it inactive too. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    if ((Get-VeroWgState $ProfileName) -eq 'missing') { return }
    $exe = Join-Path (Get-VeroWgDir) 'wireguard.exe'
    Start-Process -FilePath $exe -ArgumentList ('/uninstalltunnelservice {0}' -f $ProfileName) -WindowStyle Hidden -Wait
    $t = Get-Date
    while ((Get-VeroWgState $ProfileName) -ne 'missing' -and ((Get-Date) - $t).TotalSeconds -lt 10) { Start-Sleep -Milliseconds 500 }
}

function Test-VeroWireGuardConf {
    <# Checks a WireGuard .conf before it is added: returns @{ Errors; Warnings; Server; Port }. Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $errors = New-Object System.Collections.Generic.List[string]
    $warn = New-Object System.Collections.Generic.List[string]
    $section = ''; $peers = @(); $cur = $null; $dns = $false
    foreach ($raw in ($Text -split "`r?`n")) {
        $line = ($raw -replace '#.*$', '').Trim()
        if (-not $line) { continue }
        if ($line -match '^\[(\w+)\]$') {
            $section = $Matches[1].ToLowerInvariant()
            if ($section -eq 'peer') { $cur = @{ Endpoint = ''; Allowed = @(); Keepalive = 0 }; $peers += $cur }
            continue
        }
        if ($line -notmatch '^([A-Za-z]+)\s*=\s*(.*)$') { continue }
        $k = $Matches[1].ToLowerInvariant(); $v = $Matches[2].Trim()
        if ($section -eq 'interface' -and $k -eq 'dns' -and $v) { $dns = $true }
        if ($section -eq 'peer' -and $cur) {
            switch ($k) {
                'endpoint' { $cur.Endpoint = $v }
                'allowedips' { $cur.Allowed += @($v -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
                'persistentkeepalive' { $cur.Keepalive = [int]($v -replace '[^0-9]', '0') }
            }
        }
    }
    $server = ''; $port = 0
    $withEndpoint = @($peers | Where-Object { $_.Endpoint })
    if ($withEndpoint.Count -eq 0) { $errors.Add('no peer with an Endpoint - VeroScudo needs the server address for the kill-switch') }
    elseif ($withEndpoint.Count -gt 1) { $warn.Add('more than one peer has an Endpoint: VeroScudo allows only the first one through the kill-switch') }
    if ($withEndpoint.Count -ge 1) {
        $ep = $withEndpoint[0]
        if ($ep.Endpoint -match '^\[([0-9a-fA-F:.]+)\]:(\d+)$' -or $ep.Endpoint -match '^([^:\[\]]+):(\d+)$') { $server = $Matches[1]; $port = [int]$Matches[2] }
        else { $errors.Add("cannot read the Endpoint '$($ep.Endpoint)' (host:port)") }
        if ($server -and -not (Test-VeroHost $server)) { $errors.Add("invalid Endpoint host '$server'") }
        if ($ep.Keepalive -le 0) { $warn.Add('PersistentKeepalive is not set: VeroScudo judges a WireGuard link by its handshakes, so an idle tunnel would look dead and be restarted. Add "PersistentKeepalive = 25" to the [Peer].') }
        $all = @($peers | ForEach-Object { $_.Allowed })
        if ($all -notcontains '0.0.0.0/0') { $warn.Add('AllowedIPs does not contain 0.0.0.0/0 (split tunnel): while VeroScudo is on, everything outside the tunnel stays blocked.') }
    }
    if (-not $dns) { $warn.Add('No DNS in [Interface]: names may not resolve while VeroScudo blocks the local network''s DNS.') }
    [pscustomobject]@{ Errors = @($errors); Warnings = @($warn); Server = $server; Port = $port }
}

# ---------------------------------------------------------------- conflicts: other VPNs and kill-switches next to VeroScudo
$script:KillSwitchWords = 'WireGuard|OpenVPN|PrivateVPN|Hiddify|sing-box|NordVPN|ExpressVPN|Mullvad|Proton|Surfshark|Private Internet Access|CyberGhost|Windscribe|IVPN|Astrill|Cloudflare WARP'
function Get-VeroConflict {
    <# Read-only: what else is tunnelling or filtering next to VeroScudo. Each item is one human-readable line. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config)
    $type = Get-VeroConfigType $Config
    $items = New-Object System.Collections.Generic.List[string]
    # 1. every other connected VPN (Windows VPN, WireGuard, openvpn.exe, vendor apps' adapters)
    foreach ($f in @(Get-VeroForeignVpn -Config $Config)) { $items.Add((Format-VeroForeignVpn $f) + ' - VeroScudo blocks its traffic while it is on') }
    # 2. our OpenVPN configs also present in OpenVPN GUI / the OpenVPN service folders (same servers)
    $ovpnProfiles = @($Config.Profiles | Where-Object Type -eq 'openvpn')
    if ($ovpnProfiles.Count -gt 0) {
        $dirs = @()
        try { $u = Get-ItemProperty 'HKCU:\Software\OpenVPN-GUI' -ErrorAction Stop; if ($u.PSObject.Properties['config_dir']) { $dirs += [Environment]::ExpandEnvironmentVariables([string]$u.config_dir) } } catch { Write-Verbose 'no OpenVPN-GUI key' }
        $dirs += (Join-Path $env:USERPROFILE 'OpenVPN\config')
        $auto = Join-Path (Get-VeroSystemDir ProgramFiles) 'OpenVPN\config-auto'
        try { $k = Get-ItemProperty 'HKLM:\SOFTWARE\OpenVPN' -ErrorAction Stop; if ($k.PSObject.Properties['config_dir']) { $dirs += [string]$k.config_dir }; if ($k.PSObject.Properties['autostart_config_dir']) { $auto = [string]$k.autostart_config_dir } } catch { Write-Verbose 'no OpenVPN key' }
        $dirs += (Join-Path (Get-VeroSystemDir ProgramFiles) 'OpenVPN\config')
        foreach ($pr in $ovpnProfiles) {
            $mine = @(Get-VeroOpenVpnRemote -ProfileName $pr.Profile | ForEach-Object { '{0}:{1}' -f $_.Host, $_.Port }) | Sort-Object
            if ($mine.Count -eq 0) { continue }
            foreach ($d in @($dirs + $auto | Select-Object -Unique)) {
                if (-not $d -or -not (Test-Path -LiteralPath $d)) { continue }
                # the folder and its direct subfolders only, never through junctions/links: these folders belong to the user,
                # and a junction to C:\ must not turn this admin-run check into a disk scan every minute
                $where = @($d) + @(Get-ChildItem -LiteralPath $d -Directory -ErrorAction SilentlyContinue | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | Select-Object -First 20 | ForEach-Object FullName)
                $files = @(foreach ($w in $where) { Get-ChildItem -LiteralPath $w -Filter '*.ovpn' -File -ErrorAction SilentlyContinue | Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } })
                foreach ($f in @($files | Select-Object -First 50)) {
                    $theirs = @((Test-VeroOpenVpnConf -Text ([IO.File]::ReadAllText($f.FullName)) -ReadFile { param($x) $null = $x; [byte[]]@() }).Remotes | ForEach-Object { '{0}:{1}' -f $_.Host, $_.Port }) | Sort-Object
                    if ($theirs.Count -gt 0 -and (@($theirs | Where-Object { $mine -contains $_ }).Count -gt 0)) {
                        $where = if ($d -eq $auto) { 'the OpenVPN service starts it by itself' } else { "OpenVPN GUI lists it - don't connect it there" }
                        $items.Add("'$($f.Name)' has the same server as '$($pr.Profile)': $where")
                    }
                }
            }
        }
    }
    # 5. other apps' kill-switch filter layers (WFP providers)
    try {
        Import-VeroNative
        foreach ($i in @(Select-VeroForeignWfp -Type $type -Providers @([VeroScudo.Wfp]::Providers()) -SubLayers @([VeroScudo.Wfp]::SubLayers()))) { $items.Add($i) }
    } catch { Write-Verbose "WFP providers: $($_.Exception.Message)" }
    @($items | Select-Object -Unique)
}

function Select-VeroForeignWfp {
    <# Pure. Other apps' WFP kill-switch layers worth a warning. Providers: names; SubLayers: "weight|name". The active
       profile's own client (WireGuard app, OpenVPN) is not "another app" - its layer is expected while its tunnel runs. #>
    [CmdletBinding()] param([string]$Type, [string[]]$Providers = @(), [string[]]$SubLayers = @())
    $own = switch ($Type) { 'wireguard' { 'WireGuard' } 'openvpn' { 'OpenVPN' } default { $null } }
    foreach ($n in $Providers) {
        if ($n -notmatch $script:KillSwitchWords) { continue }
        if ($own -and $n -match $own) { continue }
        "another app's filter layer is installed: '$n'"
    }
    # a sublayer with the same top weight as ours: WFP evaluates equal weights in no defined order, so its hard permits
    # could be seen before our block
    foreach ($sl in $SubLayers) {
        $parts = $sl -split '\|', 2
        if ($parts.Count -lt 2 -or [int]$parts[0] -lt 0xFFFF) { continue }
        if ($own -and $parts[1] -match $own) { continue }
        "another filter layer has the same top priority as VeroScudo's: '$($parts[1])' - its rules may win"
    }
}

function Get-VeroForeignVpn {
    <# Every VPN that is connected right now and is NOT the active profile's tunnel: another Windows VPN, a WireGuard tunnel,
       an openvpn.exe VeroScudo did not start, or a vendor app's tunnel adapter. Read-only, works without admin rights (the
       tray asks before Turn on). @{ Name; Kind ('ras'|'wireguard'|'openvpn'|'app'); Configured; CanDisconnect; Id }. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config)
    $type = Get-VeroConfigType $Config
    $names = @($Config.Profiles | ForEach-Object Profile)
    $out = New-Object System.Collections.Generic.List[object]
    $rasUp = @(Get-VeroWindowsVpn | Where-Object { $_.Connected })
    foreach ($v in $rasUp) {
        if ($type -eq 'ras' -and $v.Name -eq $Config.Profile) { continue }
        $out.Add([pscustomobject]@{ Name = $v.Name; Kind = 'ras'; Configured = ($names -contains $v.Name); CanDisconnect = $true; Id = $v.Name })
    }
    $wgUp = @(Get-Service -Name 'WireGuardTunnel$*' -ErrorAction SilentlyContinue | Where-Object { [string]$_.Status -eq 'Running' } | ForEach-Object { $_.Name.Substring(16) })
    foreach ($n in $wgUp) {
        if ($type -eq 'wireguard' -and $n -eq $Config.Profile) { continue }
        $out.Add([pscustomobject]@{ Name = $n; Kind = 'wireguard'; Configured = ($names -contains $n); CanDisconnect = $true; Id = $n })
    }
    $ours = @(foreach ($pr in @($Config.Profiles | Where-Object Type -eq 'openvpn')) { $st = Get-VeroOpenVpnStatus $pr.Profile; if ($st -and $st.OvpnPid) { [int]$st.OvpnPid } })
    $ovpnForeign = @(Get-Process -Name openvpn -ErrorAction SilentlyContinue | Where-Object { $ours -notcontains $_.Id })
    foreach ($proc in $ovpnForeign) { $out.Add([pscustomobject]@{ Name = "OpenVPN (PID $($proc.Id))"; Kind = 'openvpn'; Configured = $false; CanDisconnect = $true; Id = [string]$proc.Id }) }
    # vendor apps: a tunnel adapter that is up and belongs to none of the above (and is not ours)
    $ownRunner = ($type -eq 'openvpn') -and (Test-VeroOpenVpnRunnerAlive)
    # VeroScudo's own OpenVPN tunnels, by the adapter that holds the address OpenVPN reported: the runner's lock above is
    # per session and invisible to the tray (seen live: the tray listed VeroScudo's own TAP adapter as "a VPN app")
    $ownNics = @(foreach ($pr in @($Config.Profiles | Where-Object Type -eq 'openvpn')) { $n = Get-VeroOpenVpnNic $pr.Profile; if ($n) { [string]$n.Id } })
    foreach ($nic in @(Get-VeroNic | Where-Object { [string]$_.OperationalStatus -eq 'Up' -and (Test-VeroTunnelAdapter $_) })) {
        if ([string]$nic.NetworkInterfaceType -eq 'Ppp') { continue }                                       # Windows VPN: listed by name above
        if ($ownNics -contains [string]$nic.Id) { continue }
        if ([string]$nic.Description -like 'WireGuard*' -and ($wgUp -contains $nic.Name -or ($type -eq 'wireguard' -and $nic.Name -eq $Config.Profile))) { continue }
        $isOvpnAdapter = [string]$nic.Description -match 'TAP-Windows|Wintun|OpenVPN|Data Channel Offload|ovpn-dco'
        if ($isOvpnAdapter -and ($ownRunner -or $ovpnForeign.Count -gt 0)) { continue }
        $out.Add([pscustomobject]@{ Name = "$($nic.Name) ($($nic.Description))"; Kind = 'app'; Configured = $false; CanDisconnect = $false; Id = [string]$nic.Name })
    }
    $out.ToArray()                                                          # callers wrap it in @()
}

function Format-VeroForeignVpn($F) {
    <# One line for the log, the tray and the status window. Pure. #>
    switch ($F.Kind) {
        'ras'       { "Windows VPN '$($F.Name)' is connected$(if ($F.Configured) { ' (another VeroScudo profile)' } else { ' (not a VeroScudo profile)' })" }
        'wireguard' { "WireGuard tunnel '$($F.Name)' is active$(if ($F.Configured) { ' (another VeroScudo profile)' } else { ' (not a VeroScudo profile)' })" }
        'openvpn'   { "$($F.Name) runs outside VeroScudo (OpenVPN GUI or the OpenVPN service)" }
        default     { "a VPN app's tunnel is up: $($F.Name) - VeroScudo cannot disconnect it, close that app" }
    }
}

function Disconnect-VeroForeignVpn {
    <# Only on your choice (tray "Disconnect ... and turn on", -DisconnectOthers): ends every other connected VPN it can,
       each the way its own client does. Returns the ones it could not end (vendor apps). #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'on')
    $left = New-Object System.Collections.Generic.List[object]
    foreach ($f in @(Get-VeroForeignVpn -Config $Config)) {
        if (-not $f.CanDisconnect) { $left.Add($f); continue }             # a VPN app's own tunnel (NB: not inside the switch)
        switch ($f.Kind) {
            'ras'       { & $script:Rasdial $f.Id /disconnect 2>&1 | Out-Null }
            'wireguard' { Invoke-VeroWgHangUp -ProfileName $f.Id }
            'openvpn'   {
                $gui = Join-Path (Get-VeroSystemDir ProgramFiles) 'OpenVPN\bin\openvpn-gui.exe'
                if ((Get-Process -Name 'openvpn-gui' -ErrorAction SilentlyContinue) -and (Test-Path $gui)) { Start-Process -FilePath $gui -ArgumentList '--command disconnect_all' -WindowStyle Hidden; Start-Sleep -Seconds 3 }
                $proc = Get-Process -Id ([int]$f.Id) -ErrorAction SilentlyContinue
                if ($proc -and $proc.ProcessName -eq 'openvpn') { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
            }
        }
        Write-VeroLog "disconnected: $(Format-VeroForeignVpn $f) - you chose it (Disconnect and turn on)" $Action
    }
    $left.ToArray()
}

function Update-VeroConflict {
    <# Watchdog: refreshes state\conflicts.json (the tray shows it) and logs when the list changes. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'watchdog')
    $items = @(Get-VeroConflict -Config $Config)
    $p = Get-VeroPath
    $old = @(Get-VeroConflictList)
    if (($old -join "`n") -ne ($items -join "`n")) {
        if ($items.Count -gt 0) { Write-VeroLog ("ATTENTION: {0}" -f ($items -join ' | ')) $Action } else { Write-VeroLog 'no other VPN or kill-switch next to VeroScudo any more' $Action }
    }
    @{ Time = (Get-Date).ToString('o'); Items = $items } | ConvertTo-Json -Depth 3 | Set-Content $p.Conflicts
}

function Get-VeroConflictList {
    $f = (Get-VeroPath).Conflicts
    if (Test-Path $f) { try { return @((Get-Content $f -Raw | ConvertFrom-Json).Items | Where-Object { $_ }) } catch { Write-Verbose 'conflicts unreadable' } }
    @()
}

# ---------------------------------------------------------------- actions & status
function Get-VeroStatus {
    [CmdletBinding()] param($Config)
    if (-not $Config) { $Config = Get-VeroConfig }
    $p = Get-VeroPath -VpnProfile $Config.Profile
    $r = if (Test-VeroHyperVFirewall) { Get-NetFirewallHyperVRule -Name $script:VmRule -ErrorAction SilentlyContinue } else { $null }
    $type = Get-VeroConfigType $Config
    $armed = Test-VeroArmed; $up = Test-VeroVpnConnected $Config.Profile -Type $type
    $applied = Get-VeroAppliedState
    $filters = try { Get-VeroWfpCount } catch { 'n/a (needs admin)' }
    $detail = switch ($type) {
        'openvpn'   { $s = Get-VeroOpenVpnStatus $Config.Profile; if ($s) { "$($s.State)$(if ($s.Reason) { ' (' + $s.Reason + ')' })" } else { 'not started' } }
        'wireguard' { "service $(Get-VeroWgState $Config.Profile), handshake $(Get-VeroWgHealthNow $Config.Profile)" }
        default     { '-' }
    }
    [pscustomobject]@{
        Version    = $script:Version
        Profile    = $Config.Profile
        Type       = Get-VeroTypeLabel $type
        Profiles   = (@($Config.Profiles | ForEach-Object { '{0} ({1})' -f $_.Profile, (Get-VeroTypeLabel $_.Type) }) -join ', ')
        Armed      = $armed
        Connected  = $up
        State      = if (-not $armed) { 'off' } elseif ($up) { 'protected' } else { 'blocked' }
        Client     = $detail
        Credential = if (Test-VeroNeedsPassword $Config) { [bool](Get-VeroCredential -Config $Config) } else { 'not needed' }
        PwRejected = Test-VeroAuthBlocked $Config.Profile
        Conflicts  = (@(Get-VeroConflictList) -join ' | ')
        Helper     = $(if ($nb = Get-VeroNativeBlocked) { "BLOCKED by Windows since $($nb.First) ($($nb.Count) failures), next try $($nb.Next)" } else { 'ok' })
        Filters    = $filters
        Applied    = if ($applied) { $applied.Time } else { '-' }
        Server     = "$(if ($type -eq 'openvpn') { (@(try { Get-VeroOpenVpnRemote -ProfileName $Config.Profile } catch { @() }) | ForEach-Object { '{0}:{1}/{2}' -f $_.Host, $_.Port, $_.Proto }) -join ' ' } else { $Config.Server }) -> $(if ($applied -and $applied.PSObject.Properties['Servers']) { @($applied.Servers | ForEach-Object { if ($_ -is [string]) { $_ } else { [string]$_.value } }) -join ', ' } else { (@(Resolve-VeroServerIp -Config $Config -CacheOnly) -join ', ') })"
        Emergency  = Test-Path $p.Emergency
        Vm         = if (-not $r) { 'not managed' } elseif ([string]$r.Enabled -eq 'True') { 'allowed' } else { 'blocked' }
        Reconnect  = Test-VeroLockAlive
        Log        = $p.Log
    }
}

function Invoke-VeroAction {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][ValidateSet('arm', 'disarm', 'on', 'on-disconnect', 'on-force', 'off', 'on-event', 'reconnect', 'watchdog', 'check', 'switch', 'status', 'openvpn')][string]$Action,
        $Config,
        [string]$VpnProfile
    )
    if (-not $Config) { $Config = Get-VeroConfig }
    $p = Get-VeroPath
    if (-not (Test-Path $p.State)) { New-Item -ItemType Directory -Path $p.State -Force | Out-Null }
    switch ($Action) {
        'arm' {
            # a VPN connected (RasMan, System log): a configured profile becomes the active one; anything else is ignored
            $names = @($Config.Profiles | ForEach-Object Profile)
            if (Test-VeroRecentOff) { Write-VeroLog 'connect right after your Off (a redial that was already running) - not armed' $Action; return }
            $c = Get-VeroRasConnected -Names $names
            # the Connected task also fires on RasClient 20225 (user-writable log): arm only for a tunnel that is really up
            $who = if ($c -and $names -contains $c) { $c } else { $Config.Profile }
            if (($names -contains $who) -and -not (Test-VeroVpnConnected $who -Type 'ras')) {
                if (-not ($c -and $names -notcontains $c)) { Write-VeroLog "connect record for '$who', but it is not connected - ignored" $Action; return }
            }
            if ($c -and $c -ne $Config.Profile) {
                if (@($Config.Profiles | ForEach-Object Profile) -notcontains $c) {
                    if (Test-VeroArmed) {                                       # tell the user (tray) - its traffic goes nowhere
                        Write-VeroLog "WARNING: VPN '$c' connected, but it is not a VeroScudo profile - its traffic is blocked. Disconnect it, or import it in Settings." $Action
                        @{ Name = $c; Time = (Get-Date).ToString('o') } | ConvertTo-Json | Set-Content $p.Foreign
                    } else { Write-VeroLog "VPN '$c' connected - not a configured profile, VeroScudo is off: ignored" $Action }
                    return
                }
                Set-VeroActiveProfile -Name $c -Action $Action
                $Config = Get-VeroConfig
            }
            Invoke-VeroArmConnected -Config $Config -Action $Action
        }
        'disarm' { Set-VeroArmed $false $Action; Disable-VeroKillSwitch -Action $Action }
        { $_ -in 'on', 'on-disconnect', 'on-force' } {
                   # another VPN is connected: plain 'on' (shortcut, script) refuses and says so - the tray asks you first and
                   # then runs 'on-disconnect' (ends them, your choice) or 'on-force' (turn on anyway, their traffic is blocked)
                   $foreign = @(Get-VeroForeignVpn -Config $Config)
                   if ($foreign.Count -gt 0 -and $Action -eq 'on') {
                       $what = ($foreign | ForEach-Object { Format-VeroForeignVpn $_ }) -join '; '
                       if (-not (Test-VeroArmed)) {
                           Write-VeroLog "NOT turned on: $what. Use Turn VPN on in the tray to choose, or -DisconnectOthers / -Force." $Action
                           @{ Time = (Get-Date).ToString('o'); Items = @($foreign | ForEach-Object { Format-VeroForeignVpn $_ }) } | ConvertTo-Json -Depth 3 | Set-Content $p.OnRefused
                           return
                       }
                       Write-VeroLog "WARNING: already on, next to: $what - their traffic is blocked" $Action   # already on: On just redials
                   }
                   if ($Action -eq 'on-disconnect' -and $foreign.Count -gt 0) {
                       $left = @(Disconnect-VeroForeignVpn -Config $Config -Action $Action)
                       foreach ($f in $left) { Write-VeroLog "WARNING: $(Format-VeroForeignVpn $f)" $Action }
                   }
                   if ($Action -eq 'on-force' -and $foreign.Count -gt 0) { Write-VeroLog ("turned on anyway (your choice) next to: {0} - their traffic is blocked" -f (($foreign | ForEach-Object Name) -join ', ')) $Action }
                   Clear-VeroAuthFailed -ProfileName $Config.Profile -Action $Action           # you asked: one more try with the stored password
                   Update-VeroServerIpBeforeArm -Config $Config -Action $Action
                   Set-VeroArmed $true $Action; Sync-VeroKillSwitch -Config $Config -Action $Action
                   $notice = Get-VeroSwitchNotice -Type (Get-VeroConfigType $Config) -ProfileName $Config.Profile
                   if ($notice) { Write-VeroLog "NOTICE: $notice" $Action }
                   if (-not (Test-VeroVpnConnected $Config.Profile)) { Invoke-VeroReconnect -Config $Config -Action $Action } }
        'off'    { Set-Content -Path $p.OffAt -Value (Get-Date).ToString('o')             # for 30 s nothing re-arms by itself (see Test-VeroRecentOff)
                   Set-VeroArmed $false $Action; Disable-VeroKillSwitch -Action $Action
                   Remove-Item $p.Renew -Force -ErrorAction SilentlyContinue
                   $type = Get-VeroConfigType $Config
                   # OpenVPN runs only under VeroScudo: always stop it (also mid-connect); the others only when connected
                   if ($type -eq 'openvpn' -or (Test-VeroVpnConnected $Config.Profile -Type $type)) {
                       Invoke-VeroHangUp $Config.Profile $type; Write-VeroLog "disconnected '$($Config.Profile)' by user (off; source: VeroScudo Off)" $Action } }
        'on-event' {
            # let RAS write all its records first: a forged 631 raced in right after a real failure must meet the real
            # record (same connection: conflict) - and a 631 for any other connection id than the one we saw connect is refused
            if ($script:EventSettleSeconds -gt 0) { Start-Sleep -Seconds $script:EventSettleSeconds }
            $t = Get-VeroRasTermination
            if (-not $t) { Write-VeroLog 'VPN terminated, but no recent RAS record - running a check' $Action; Invoke-VeroCheck -Action $Action; return }
            Write-VeroLog "VPN '$($t.Profile)' terminated, RAS code $($t.Code)" $Action
            if ($t.Profile -ne $Config.Profile) { Write-VeroLog "not the active profile '$($Config.Profile)' - ignored" $Action; return }
            if ((Get-VeroConfigType $Config) -ne 'ras') { Write-VeroLog "'$($Config.Profile)' is not a Windows VPN profile - RAS events do not apply, ignored" $Action; return }
            if (Test-VeroVpnConnected $Config.Profile) { Write-VeroLog "'$($Config.Profile)' is still connected - stale or forged event, ignored" $Action; return }
            $code = $t.Code
            if ($t.Conflict) { Write-VeroLog 'conflicting termination records for one connection (forged?) - treated as a failure' $Action; $code = 0 }
            $when = if ($t.PSObject.Properties['Time']) { $t.Time } else { $null }
            $own = ($code -eq 631 -and $when -and (Test-VeroRenewHangUp -Marker (Get-VeroRenewMarker) -ProfileName $t.Profile -EventTime $when))
            if ($own) { Write-VeroLog "631 comes from VeroScudo's own hang-up for Reconnect - not your Off; stays armed" $Action; $code = 0 }
            if ($code -eq 631) {
                $want = @(Get-VeroExpectedCoId -ProfileName $t.Profile)
                if ($want -notcontains [string]$t.CoId) {
                    Write-VeroLog ("'you hung up' record names connection {0}, but VeroScudo saw {1} connect - forged or stale, treated as a failure" -f $t.CoId, $(if ($want) { $want -join ' / ' } else { 'none' })) $Action
                    $code = 0
                }
            }
            Write-VeroLog ("decision source: RAS reason code {0} -> {1}" -f $code, $(if ($code -eq 631) { 'you hung up' } else { 'link failure' })) $Action
            switch (Get-VeroDecision -ReasonCode $code -Armed (Test-VeroArmed)) {
                'disarm'    { Set-VeroArmed $false $Action; Disable-VeroKillSwitch -Action $Action }
                'reconnect' { Invoke-VeroReconnect -Config $Config -Action $Action }
            }
        }
        'reconnect' {
            # the user's Reconnect: block, hang up, redial; normal traffic again only once the new tunnel is up
            if (-not (Test-VeroArmed)) { Write-VeroLog 'Reconnect: the VPN is off - use Turn on' $Action; return }
            Clear-VeroAuthFailed -ProfileName $Config.Profile -Action $Action
            Invoke-VeroReconnect -Config $Config -Action $Action -Renew
        }
        'openvpn'   { Invoke-VeroOpenVpnRunner -Action $Action }
        'check'     { Invoke-VeroCheck -Action $Action }
        'watchdog'  {
            # long-running, exactly one per session: the task re-triggers every minute so a crashed loop is back within a minute,
            # and every extra start exits here at once (the launcher returning early once let one loop pile up per minute)
            $single = New-Object System.Threading.Mutex($false, 'Local\VeroScudo-Watchdog')
            $mine = $false
            try { $mine = $single.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $mine = $true }
            if (-not $mine) { $single.Dispose(); return }
            try {
                if (-not (Test-VeroNativeRetryDue (Get-VeroNativeBlocked))) { return }      # helper blocked: not yet time to retry
                while ($true) {
                    try {
                        Invoke-VeroCheck -Action $Action
                        Clear-VeroNativeBlocked -Action $Action                    # every good pass (a cheap Test-Path): also clears a short task's record
                    } catch {
                        if ($script:NativeLoadFailed) { Set-VeroNativeBlocked -Message $_.Exception.Message -Action $Action; break }   # exit: a fresh process retries
                        Write-VeroLog "ERROR: $($_.Exception.Message)" $Action
                    }
                    Start-Sleep -Seconds 15
                }
            } finally { $single.ReleaseMutex(); $single.Dispose() }
        }
        'switch' {
            $name = if ($VpnProfile) { $VpnProfile } else { Read-VeroSwitchRequest }
            if (-not $name) { Write-VeroLog 'switch requested without a profile name - ignored' $Action; return }
            if (@($Config.Profiles | ForEach-Object Profile) -notcontains $name) { Write-VeroLog "switch to unknown profile '$name' - ignored" $Action; return }
            Invoke-VeroSwitch -Name $name -Action $Action
        }
        'status' {
            $s = Get-VeroStatus -Config $Config
            $s.PSObject.Properties | ForEach-Object { '{0,-11}: {1}' -f $_.Name, $_.Value }
            $n = Get-VeroSwitchNotice -Type (Get-VeroConfigType $Config) -ProfileName $Config.Profile
            if ($n) { "notice     : $n" }
            if (Test-Path $p.Log) { '--- last log lines'; Get-Content $p.Log -Tail 8 }
        }
    }
}

function Get-VeroVersion { $script:Version }

function Test-VeroNewerVersion {
    <# True when a release tag (v1.2.3) is newer than the running version. Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Tag, [string]$Current = $script:Version)
    $t = $Tag.Trim() -replace '^[vV]', ''
    if ($t -notmatch '^\d+(\.\d+){1,3}$') { return $false }
    return ([version]$t -gt [version]$Current)
}

function Test-VeroReleaseUrl {
    <# Only this project's GitHub release pages may be opened from an update notice. Pure. #>
    [CmdletBinding()] param([AllowEmptyString()][string]$Url)
    if (-not $Url) { return $false }
    $u = $null
    if (-not [Uri]::TryCreate($Url, 'Absolute', [ref]$u)) { return $false }
    return ($u.Scheme -eq 'https' -and $u.Host -eq 'github.com' -and $u.AbsoluteUri.StartsWith($script:ReleasePrefix, [StringComparison]::Ordinal) -and -not $u.UserInfo)
}

function Get-VeroLatestRelease {
    <# GitHub "latest release" lookup; $null on any failure. Only call while traffic is allowed (never while blocked). #>
    [CmdletBinding()] param([string]$Repo = 'GomelHawk/VeroScudo', [int]$TimeoutSec = 10)
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $r = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -TimeoutSec $TimeoutSec -UseBasicParsing `
                -Headers @{ 'User-Agent' = "VeroScudo/$script:Version"; Accept = 'application/vnd.github+json' }
        if ($r.tag_name -and (Test-VeroReleaseUrl ([string]$r.html_url))) { return [pscustomobject]@{ Tag = [string]$r.tag_name; Url = [string]$r.html_url; Name = [string]$r.name } }
    } catch { Write-Verbose "update check failed: $($_.Exception.Message)" }
    return $null
}

Export-ModuleMember -Function Get-VeroPendingSwitch, Initialize-VeroOpenVpnAdapter, Remove-VeroOpenVpnAdapter, Test-VeroOpenVpnAdapter, Get-VeroTapctl, Select-VeroForeignWfp, Get-VeroRasConnected, Save-VeroRasCoId, Test-VeroRecentOff, Update-VeroServerIpBeforeArm, Invoke-VeroArmConnected, Update-VeroRasWatch, Get-VeroRasClientConnect, Get-VeroRasConnectedRecord, Get-VeroExpectedCoId, Open-VeroCrlWindow, Test-VeroCrlWindow, Get-VeroSystemDir, Get-VeroNativeRetrySeconds, Get-VeroNativeBlocked, Set-VeroNativeBlocked, Clear-VeroNativeBlocked, Test-VeroNativeRetryDue, Get-VeroForeignVpn, Format-VeroForeignVpn, Disconnect-VeroForeignVpn, Split-VeroServerAddress, ConvertTo-VeroRasEntry, Get-VeroRasSavedUser, Get-VeroWindowsVpn, Test-VeroRasPassword, Get-VeroRasDescription, ConvertTo-VeroProfileObject, Get-VeroTypeLabel, Get-VeroSwitchNotice, Get-VeroProfileType, Test-VeroElevated,
    Test-VeroNeedsPassword, Test-VeroTunnelAdapter, Protect-VeroOpenVpnDir, Test-VeroOpenVpnConf, Import-VeroOpenVpnProfile, Get-VeroOpenVpnRemote,
    Get-VeroOpenVpnExe, Get-VeroOpenVpnArgs, ConvertFrom-VeroMgmtLine, Format-VeroMgmtValue, Get-VeroStaticChallengeResponse, Get-VeroOpenVpnStatus,
    Get-VeroOpenVpnNic, Test-VeroOpenVpnRunnerAlive, Invoke-VeroOpenVpnDial, Stop-VeroOpenVpn, Invoke-VeroOpenVpnSession, Invoke-VeroOpenVpnRunner,
    Get-VeroWgState, Get-VeroWgHealth, Get-VeroWgTransition, Update-VeroWgWatch, Get-VeroWgHealthNow, Invoke-VeroWgDial, Invoke-VeroWgHangUp,
    Test-VeroWireGuardConf, Get-VeroConflict, Update-VeroConflict, Get-VeroConflictList, Get-VeroKeyPassphrase, Set-VeroAuthFailed, Clear-VeroAuthFailed,
    Test-VeroAuthBlocked, Set-VeroRenewMarker, Test-VeroRenewHangUp, Get-VeroRenewMarker, Resolve-VeroEndpoint, Invoke-VeroHangUp,
    Get-VeroVersion, Test-VeroNewerVersion, Test-VeroReleaseUrl, Get-VeroLatestRelease, Set-VeroHome, Get-VeroPath,
    Get-VeroConfig, ConvertTo-VeroConfigJson, Save-VeroConfig, Test-VeroCidr, Write-VeroLog, Test-VeroArmed, Set-VeroArmed, Set-VeroActiveProfile,
    Test-VeroVpnConnected, Get-VeroRasCode, Get-VeroRasVerdict, Get-VeroRasTermination, Get-VeroDecision, Resolve-VeroServerIp,
    Get-VeroFilterSpec, Get-VeroTunnelLuid, Get-VeroDnsServer, Get-VeroWslLuid, Test-VeroVmWanted, Sync-VeroKillSwitch, Disable-VeroKillSwitch,
    Remove-VeroLegacyFirewall, Test-VeroKillSwitchPresent, Test-VeroNative, Import-VeroNative, Set-VeroVmAccess, Restore-VeroVmAccess,
    Get-VeroCredential, Invoke-VeroDial, Enter-VeroLock, Set-VeroWfpFilter, Get-VeroWfpCount, Clear-VeroWfpFilter, Invoke-VeroReconnect, Invoke-VeroCheck, Invoke-VeroSwitch, Get-VeroStatus, Invoke-VeroAction
