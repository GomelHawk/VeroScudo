# VeroScudo core, part 30: paths and config.json.
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.

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
        $th = Get-VeroTypeHandler $type
        $defPort = $th.DefaultPort
        $port = if ($null -ne (Get-Prop $p 'port')) { [int]$p.port } else { $defPort }
        if ($port -lt 1 -or $port -gt 65535) { throw "config.json: port must be 1-65535 (profile '$name')" }
        $pinned = @(Get-Prop $p 'serverIps' | Where-Object { $_ })
        foreach ($ip in $pinned) { $a = $null; if (-not [System.Net.IPAddress]::TryParse([string]$ip, [ref]$a)) { throw "config.json: invalid serverIps entry '$ip' (profile '$name')" } }
        $dco = [bool](Get-Prop $p 'dco')                                    # OpenVPN: keep the kernel data channel (no program-scoped permit)
        $auth = if ($null -ne (Get-Prop $p 'auth')) { [bool]$p.auth } else { $th.PasswordCapable }   # OpenVPN: the .ovpn asks for a password
        [pscustomobject]@{ Profile = $name; Type = $type; Server = $server; Port = $port; Username = $user; ServerIps = @($pinned | ForEach-Object { [string]$_ })
                           Dco = ($th.HasDco -and $dco); Auth = ($th.PasswordCapable -and $auth) }
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
    (Get-VeroTypeHandler $Type).Label
}

function Get-VeroSwitchNotice {
    <# The notice shown on every switch to a reserve type (tray balloon, command line, log). $null for the built-in client. Pure. #>
    [CmdletBinding()] param([string]$Type, [string]$ProfileName)
    & (Get-VeroTypeHandler $Type).SwitchNotice $ProfileName
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
