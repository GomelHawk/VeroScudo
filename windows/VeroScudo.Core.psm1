#Requires -Version 5.1
<#
  VeroScudo - Master the switch.          https://github.com/GomelHawk/VeroScudo
  Windows core module. See docs/ARCHITECTURE.md for the contract this implements and docs/SECURITY.md for the threat model.

  Pure functions (unit-tested): Get-VeroConfig, Get-VeroDecision, Get-VeroFilterSpec, Get-VeroPath, Test-VeroCidr,
  Test-VeroReleaseUrl, Test-VeroNewerVersion, Get-VeroRasVerdict.
  Everything else talks to Windows (WFP, RAS, event log, Hyper-V firewall) and is exercised by tests-local/.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Version      = '1.1.0'
$script:LegacyGroup  = 'VeroScudo'                                       # Windows Firewall rule group of 1.0.x (migrated away)
$script:VmRule       = 'VeroScudo-WSL'
$script:WslCreator   = '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'          # Hyper-V firewall VM creator id of WSL
$script:Svchost      = "$env:SystemRoot\System32\svchost.exe"
$script:HomeOverride = $null                                            # tests only (Set-VeroHome); never read from the environment
$script:ReleasePrefix = 'https://github.com/GomelHawk/VeroScudo/releases/'

# ---------------------------------------------------------------- native helpers (WFP, RasDial, LUIDs)
function Import-VeroNative {
    if ('VeroScudo.Wfp' -as [type]) { return }
    $dll = Join-Path $PSScriptRoot 'VeroScudo.Native.dll'
    if (Test-Path $dll) { Add-Type -Path $dll }
    else { Add-Type -TypeDefinition (Get-Content (Join-Path $PSScriptRoot 'VeroScudo.Native.cs') -Raw) -Language CSharp }
}

# ---------------------------------------------------------------- paths & config
function Set-VeroHome {
    <# Points the state/config home somewhere else - for tests. Deliberately NOT an environment variable: the guard runs
       elevated, and a value a non-admin process can plant (HKCU\Environment) must never redirect it. #>
    [CmdletBinding()] param([string]$Path)
    $script:HomeOverride = $Path
}

function Get-VeroSafeName([string]$Name) {
    $clean = ($Name -replace '[^A-Za-z0-9_.-]', '_')
    $sha = [Security.Cryptography.SHA256]::Create()
    $hash = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Name))[0..3] | ForEach-Object { $_.ToString('x2') })
    '{0}-{1}' -f $clean.Substring(0, [Math]::Min(40, $clean.Length)), $hash
}

function Get-VeroPath {
    [CmdletBinding()] param([string]$VpnProfile)
    $home_ = if ($script:HomeOverride) { $script:HomeOverride } else { Join-Path $env:ProgramData 'VeroScudo' }
    $state = Join-Path $home_ 'state'
    $user  = Join-Path $env:LOCALAPPDATA 'VeroScudo'
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
        UserDir       = $user
        SwitchRequest = Join-Path $user 'switch.request'
        UpdateFile    = Join-Path $user 'update.json'
        LegacyCred    = Join-Path $user 'cred.xml'
        Cred          = $null
        ServerIp      = $null
    }
    if ($VpnProfile) {
        $safe = Get-VeroSafeName $VpnProfile
        $p.Cred = Join-Path $user "cred-$safe.xml"
        $p.ServerIp = Join-Path $state "server-$safe.ip"
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
        $server = [string](Get-Prop $p 'server')
        if (-not $server) { throw "config.json: vpn.server is required (profile '$name')" }
        if (-not (Test-VeroHost $server)) { throw "config.json: invalid server '$server' (profile '$name')" }
        $user = [string](Get-Prop $p 'username')
        if (-not $user) { throw "config.json: vpn.username is required (profile '$name')" }
        if ($user.Length -gt 256 -or $user -match '[\x00-\x1f"]') { throw "config.json: invalid username (profile '$name')" }
        $port = if ($null -ne (Get-Prop $p 'port')) { [int]$p.port } else { 443 }
        if ($port -lt 1 -or $port -gt 65535) { throw "config.json: port must be 1-65535 (profile '$name')" }
        $pinned = @(Get-Prop $p 'serverIps' | Where-Object { $_ })
        foreach ($ip in $pinned) { $a = $null; if (-not [System.Net.IPAddress]::TryParse([string]$ip, [ref]$a)) { throw "config.json: invalid serverIps entry '$ip' (profile '$name')" } }
        [pscustomobject]@{ Profile = $name; Server = $server; Port = $port; Username = $user; ServerIps = @($pinned | ForEach-Object { [string]$_ }) }
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
        profiles        = @($Config.Profiles | ForEach-Object {
            $o = [ordered]@{ profile = $_.Profile; server = $_.Server; port = $_.Port; username = $_.Username }
            if (@($_.ServerIps).Count -gt 0) { $o.serverIps = @($_.ServerIps) }
            $o })
        activeProfile   = $Config.DefaultProfile
        retrySeconds    = $Config.RetrySeconds
        vm              = $Config.Vm
        wifiRecoveryFix = $Config.WifiRecoveryFix
        updateCheck     = $Config.UpdateCheck
        lanAllow        = @($Config.LanAllow)
    } | ConvertTo-Json -Depth 6
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
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    if (Get-VeroTunnelNic $ProfileName) { return $true }                  # fast path: the RAS adapter is up
    $c = Get-VpnConnection -Name $ProfileName -ErrorAction SilentlyContinue
    if ($c) { return $c.ConnectionStatus -eq 'Connected' }
    return ((rasdial.exe) -join ' ') -match ('\b' + [regex]::Escape($ProfileName) + '\b')
}

function Get-VeroRasVerdict {
    <# Pure. From 20226 records {Profile; CoId; Code; Time} picks the newest and flags a conflict: RAS writes exactly one
       termination per connection (CoID), so two with different codes mean one of them was forged. #>
    [CmdletBinding()] param([object[]]$Records)
    $recs = @($Records | Where-Object { $_ })
    if ($recs.Count -eq 0) { return $null }
    $newest = $recs | Sort-Object Time -Descending | Select-Object -First 1
    $codes = @($recs | Where-Object CoId -eq $newest.CoId | ForEach-Object { [int64]$_.Code } | Select-Object -Unique)
    [pscustomobject]@{ Profile = $newest.Profile; CoId = $newest.CoId; Code = [int64]$newest.Code; Conflict = ($codes.Count -gt 1) }
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
    <# Profile name of the newest RasMan "connected" event (System log - not writable by ordinary users). #>
    [CmdletBinding()] param([int]$WithinMinutes = 2)
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'RasMan'; Id = 20267
                                            StartTime = (Get-Date).AddMinutes(-$WithinMinutes) } -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($ev -and $ev.Properties.Count -ge 3) { return [string]$ev.Properties[2].Value }
    $null
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
        [string]$Svchost = $script:Svchost
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
    $fam = Split-Family $ServerIps
    $parts = switch ($TunnelType) {
        'Sstp'  { @(@{ P = 6; Ports = @($Config.Port); App = $true }) }
        'Ikev2' { @(@{ P = 17; Ports = @(500, 4500); App = $false }, @{ P = 50; Ports = @(); App = $false }) }
        'L2tp'  { @(@{ P = 17; Ports = @(500, 4500, 1701); App = $false }, @{ P = 50; Ports = @(); App = $false }) }
        'Pptp'  { @(@{ P = 6; Ports = @(1723); App = $false }, @{ P = 47; Ports = @(); App = $false }) }
        default { @(@{ P = 6; Ports = @($Config.Port); App = $true }, @{ P = 6; Ports = @(1723); App = $false },
                    @{ P = 17; Ports = @(500, 4500, 1701); App = $false }, @{ P = 50; Ports = @(); App = $false }, @{ P = 47; Ports = @(); App = $false }) }
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

    # link maintenance: DHCP / DHCPv6 leases, IPv6 neighbour discovery on the link only
    foreach ($l in $C4, $R4) { $null = (New-Spec 'DHCP' $l $true $permit).Protocol(17).LocalPort(68).RemotePort(67) }
    foreach ($l in $C6, $R6) { $null = (New-Spec 'DHCPv6' $l $true $permit).Protocol(17).LocalPort(546).RemotePort(547) }
    foreach ($l in $C6, $R6) {
        $s = (New-Spec 'NDP' $l $true $permit).Protocol(58)
        foreach ($t in 133..137) { $null = $s.IcmpType([uint16]$t) }
        $null = $s.Remote('fe80::/10').Remote('ff02::/16')
    }

    if (-not $TunnelLuid) {
        # redial needs to resolve the server name and SSTP checks certificate revocation; both only through Windows' own
        # services (svchost), DNS only to the resolvers the network handed out
        $dns = Split-Family $DnsServers
        $known = (@($DnsServers | Where-Object { $_ }).Count -gt 0)            # $null-safe: no resolver known yet (link still coming up)
        foreach ($pair in @(@($C4, $dns[0]), @($C6, $dns[1]))) {
            $layer = $pair[0]; $srv = @($pair[1])
            if ($known -and $srv.Count -eq 0) { continue }
            $s = (New-Spec 'DNS (redial)' $layer $true $permit).Protocol(17).Protocol(6).RemotePort(53).App($Svchost)
            foreach ($ip in $srv) { $null = $s.Remote($ip) }
        }
        foreach ($l in $C4, $C6) { $null = (New-Spec 'CRL (redial)' $l $true $permit).Protocol(6).RemotePort(80).App($Svchost) }
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
    $cached = @(if (Test-Path $p.ServerIp) { Get-Content $p.ServerIp | Where-Object { $_ } })
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
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    Import-VeroNative
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
                                   $_.Name -notlike 'vEthernet*' -and $_.Name -ne $ProfileName } |
        ForEach-Object { $_.GetIPProperties().DnsAddresses } | ForEach-Object { ($_.ToString() -split '%')[0] } |
        Where-Object { $_ -and $_ -notlike 'fec0:0:0:ffff::*' } | Select-Object -Unique | Sort-Object)
}

$script:TunnelTypes = @{}
function Get-VeroTunnelType([string]$ProfileName) {
    if (-not $script:TunnelTypes.ContainsKey($ProfileName)) {             # cached per process: the watchdog loop is long-lived
        $c = Get-VpnConnection -Name $ProfileName -ErrorAction SilentlyContinue
        if (-not $c) { return 'Automatic' }
        $script:TunnelTypes[$ProfileName] = if ($c.TunnelType) { [string]$c.TunnelType } else { 'Automatic' }
    }
    $script:TunnelTypes[$ProfileName]
}

function Test-VeroVmWanted {
    [CmdletBinding()] param([Parameter(Mandatory)]$Config)
    if ($Config.Vm -eq 'auto') { return [bool](Get-NetFirewallHyperVVMCreator -ErrorAction SilentlyContinue | Where-Object VMCreatorId -eq $script:WslCreator) }
    return [bool]$Config.Vm
}

function Set-VeroVmAccess {
    <# WSL traffic is NAT-forwarded, so the host's WFP filters do not see it; the Hyper-V firewall does. While armed the WSL
       VM's default outbound is Block, and our allow rule is enabled only while the tunnel is up. #>
    [CmdletBinding()] param([Parameter(Mandatory)][bool]$Allow, [string]$Action = 'core')
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
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core', [switch]$Force, [switch]$NoRefresh)
    $again = Invoke-VeroLocked { Sync-VeroKillSwitchCore -Config $Config -Action $Action -Force:$Force -NoRefresh:$NoRefresh }
    if ($again) { Sync-VeroKillSwitch -Config $Config -Action $Action -NoRefresh }
}

function Invoke-VeroLocked([scriptblock]$Script) {
    <# Applying and removing filters never overlap (watchdog, event tasks and On/Off run in parallel processes). Seen live:
       a slow disarm finished after a re-arm had applied its filters and left an armed machine without any. #>
    $mutex = New-Object System.Threading.Mutex($false, 'Local\VeroScudo-Sync')
    $owned = $false
    try {
        try { $owned = $mutex.WaitOne(60000) } catch [System.Threading.AbandonedMutexException] { $owned = $true }
        & $Script
    } finally {
        if ($owned) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

function Sync-VeroKillSwitchCore {
    <# Returns $true when a fresh lookup found different server addresses (the caller re-syncs once). #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core', [switch]$Force, [switch]$NoRefresh)
    $p = Get-VeroPath
    $tun = Get-VeroTunnelLuid $Config.Profile
    $ips = @(Resolve-VeroServerIp -Config $Config -CacheOnly)
    if ($ips.Count -eq 0) { $ips = @(Resolve-VeroServerIp -Config $Config) }                   # first run: nothing cached yet
    if ($ips.Count -eq 0) { Write-VeroLog "WARNING: cannot resolve $($Config.Server) and no cached IP - redial cannot reach it" $Action }
    $vm = Test-VeroVmWanted $Config
    $wsl = if ($vm) { Get-VeroWslLuid } else { [uint64]0 }
    $dns = @(if (-not $tun) { Get-VeroDnsServer -ProfileName $Config.Profile })    # @(if ...): an if yielding an empty list is $null
    $specs = Get-VeroFilterSpec -Config $Config -ServerIps $ips -TunnelLuid $tun -WslLuid $wsl -DnsServers $dns -TunnelType (Get-VeroTunnelType $Config.Profile)
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
        @{ Fingerprint = $fp; Count = $specs.Count; Profile = $Config.Profile; Tunnel = [string]$tun; Wsl = [string]$wsl; Servers = $ips; Time = (Get-Date).ToString('o') } |
            ConvertTo-Json | Set-Content $p.WfpState
        $why = if (-not $prev) { 'armed' } elseif ($present -ne $prev.Count) { "filters missing ($present of $($prev.Count))" } else { 'changed' }
        Write-VeroLog ("kill-switch {0}: {1} filters, profile '{2}', tunnel {3}, wsl {4}, server {5}, dns {6}" -f $why, $specs.Count, $Config.Profile,
            $(if ($tun) { 'up' } else { 'DOWN' }), $(if ($wsl) { 'bound' } else { '-' }), ($ips -join ','), $(if ($tun) { 'tunnel only' } else { ($dns -join ',') })) $Action
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
        $fresh = @(Resolve-VeroServerIp -Config $Config)
        return (($fresh -join ',') -ne ($ips -join ','))
    }
    $false
}
$script:SyncCount = 0
$script:VmAllowed = $null

function Disable-VeroKillSwitch {
    [CmdletBinding()] param([string]$Action = 'core')
    Invoke-VeroLocked {
        # re-checked under the lock: if something armed again meanwhile (On pressed right after a hang-up), its filters stay
        if (Test-VeroArmed) { Write-VeroLog 'armed again meanwhile - kill-switch kept' $Action; return }
        Clear-VeroWfpFilter
        Remove-Item (Get-VeroPath).WfpState -Force -ErrorAction SilentlyContinue
        Remove-VeroLegacyFirewall -Action $Action
        Restore-VeroVmAccess
        Write-VeroLog 'kill-switch OFF (filters removed)' $Action
    }
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
function Invoke-VeroDial {
    <# RasDial API with the DPAPI-stored credential: the password never appears on a command line (process lists, EDR,
       event 4688). Without a stored credential, rasdial uses whatever the phonebook entry has. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core')
    $cred = Get-VeroCredential -Config $Config
    if ($cred) {
        Import-VeroNative
        $code = [VeroScudo.Ras]::Dial($Config.Profile, $cred.UserName, $cred.Password)
        if ($code -ne 0) { Write-Verbose "RasDial: $code" }
    } else {
        Write-VeroLog "WARNING: no stored credential for '$($Config.Profile)' (tray Settings or Set-VpnCredential.ps1) - dialing without password" $Action
        rasdial.exe $Config.Profile 2>&1 | Out-Null
    }
}
function Invoke-VeroHangUp([string]$ProfileName) { rasdial.exe $ProfileName /disconnect 2>&1 | Out-Null }

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
       config (and so the active profile) is re-read on every attempt. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core')
    if (-not (Enter-VeroLock)) { Write-VeroLog 'reconnect loop already running' $Action; return }
    $p = Get-VeroPath
    $attempt = 0
    try {
        while ((Test-VeroArmed) -and -not (Test-VeroVpnConnected $Config.Profile)) {
            $attempt++
            Sync-VeroKillSwitch -Config $Config -Action $Action
            Invoke-VeroDial -Config $Config -Action $Action
            if (Test-VeroVpnConnected $Config.Profile) { Write-VeroLog "reconnected '$($Config.Profile)' after $attempt attempt(s)" $Action; break }
            Write-VeroLog "attempt $attempt failed (RAS $(Get-VeroRasCode -EventId 20227 -Profile $Config.Profile))" $Action
            Start-Sleep -Seconds $Config.RetrySeconds
            $Config = Get-VeroConfig
        }
        if (-not (Test-VeroArmed)) { Write-VeroLog 'disarmed during reconnect - stopping' $Action }
    } finally {
        Remove-Item $p.Lock -Force -ErrorAction SilentlyContinue
    }
    if ((Test-VeroArmed) -and (Test-VeroVpnConnected $Config.Profile)) { Sync-VeroKillSwitch -Config $Config -Action $Action }
}

function Invoke-VeroCheck {
    <# One watchdog pass: armed -> filters exactly as they should be (+ redial when down); disarmed -> nothing left behind. #>
    [CmdletBinding()] param([string]$Action = 'watchdog')
    $cfg = Get-VeroConfig
    if (Test-VeroArmed) {
        Sync-VeroKillSwitch -Config $cfg -Action $Action
        if (-not (Test-VeroVpnConnected $cfg.Profile) -and -not (Test-VeroLockAlive)) { Invoke-VeroReconnect -Config $cfg -Action $Action }
    } elseif (Test-VeroKillSwitchPresent) {
        Write-VeroLog 'disarmed but kill-switch still present - removing' $Action
        Disable-VeroKillSwitch -Action $Action
    }
}

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
    if (Test-VeroArmed) {
        Sync-VeroKillSwitch -Config $new -Action $Action
        if (Test-VeroVpnConnected $old.Profile) { Invoke-VeroHangUp $old.Profile; Write-VeroLog "hung up '$($old.Profile)'" $Action }
        Invoke-VeroReconnect -Config $new -Action $Action
    } elseif (Test-VeroVpnConnected $old.Profile) {
        Invoke-VeroHangUp $old.Profile
        Write-VeroLog "hung up '$($old.Profile)' (VPN is off - '$Name' is selected for the next turn on)" $Action
    }
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

# ---------------------------------------------------------------- actions & status
function Get-VeroStatus {
    [CmdletBinding()] param($Config)
    if (-not $Config) { $Config = Get-VeroConfig }
    $p = Get-VeroPath -VpnProfile $Config.Profile
    $r = Get-NetFirewallHyperVRule -Name $script:VmRule -ErrorAction SilentlyContinue
    $armed = Test-VeroArmed; $up = Test-VeroVpnConnected $Config.Profile
    $applied = Get-VeroAppliedState
    $filters = try { Get-VeroWfpCount } catch { 'n/a (needs admin)' }
    [pscustomobject]@{
        Version    = $script:Version
        Profile    = $Config.Profile
        Profiles   = (@($Config.Profiles | ForEach-Object Profile) -join ', ')
        Armed      = $armed
        Connected  = $up
        State      = if (-not $armed) { 'off' } elseif ($up) { 'protected' } else { 'blocked' }
        Credential = [bool](Get-VeroCredential -Config $Config)
        Filters    = $filters
        Applied    = if ($applied) { $applied.Time } else { '-' }
        Emergency  = Test-Path $p.Emergency
        Vm         = if (-not $r) { 'not managed' } elseif ([string]$r.Enabled -eq 'True') { 'allowed' } else { 'blocked' }
        Reconnect  = Test-VeroLockAlive
        Log        = $p.Log
    }
}

function Invoke-VeroAction {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][ValidateSet('arm', 'disarm', 'on', 'off', 'on-event', 'reconnect', 'watchdog', 'check', 'switch', 'status')][string]$Action,
        $Config,
        [string]$VpnProfile
    )
    if (-not $Config) { $Config = Get-VeroConfig }
    $p = Get-VeroPath
    if (-not (Test-Path $p.State)) { New-Item -ItemType Directory -Path $p.State -Force | Out-Null }
    switch ($Action) {
        'arm' {
            # a VPN connected (RasMan, System log): a configured profile becomes the active one; anything else is ignored
            $c = Get-VeroRasConnected
            if ($c -and $c -ne $Config.Profile) {
                if (@($Config.Profiles | ForEach-Object Profile) -notcontains $c) { Write-VeroLog "VPN '$c' connected - not a configured profile, ignored" $Action; return }
                Set-VeroActiveProfile -Name $c -Action $Action
                $Config = Get-VeroConfig
            }
            Set-VeroArmed $true $Action; Sync-VeroKillSwitch -Config $Config -Action $Action
        }
        'disarm' { Set-VeroArmed $false $Action; Disable-VeroKillSwitch -Action $Action }
        'on'     { Set-VeroArmed $true $Action; Sync-VeroKillSwitch -Config $Config -Action $Action
                   if (-not (Test-VeroVpnConnected $Config.Profile)) { Invoke-VeroReconnect -Config $Config -Action $Action } }
        'off'    { Set-VeroArmed $false $Action; Disable-VeroKillSwitch -Action $Action
                   if (Test-VeroVpnConnected $Config.Profile) { Invoke-VeroHangUp $Config.Profile; Write-VeroLog "disconnected '$($Config.Profile)' by user (off)" $Action } }
        'on-event' {
            $t = Get-VeroRasTermination
            if (-not $t) { Write-VeroLog 'VPN terminated, but no recent RAS record - running a check' $Action; Invoke-VeroCheck -Action $Action; return }
            Write-VeroLog "VPN '$($t.Profile)' terminated, RAS code $($t.Code)" $Action
            if ($t.Profile -ne $Config.Profile) { Write-VeroLog "not the active profile '$($Config.Profile)' - ignored" $Action; return }
            if (Test-VeroVpnConnected $Config.Profile) { Write-VeroLog "'$($Config.Profile)' is still connected - stale or forged event, ignored" $Action; return }
            $code = $t.Code
            if ($t.Conflict) { Write-VeroLog 'conflicting termination records for one connection (forged?) - treated as a failure' $Action; $code = 0 }
            switch (Get-VeroDecision -ReasonCode $code -Armed (Test-VeroArmed)) {
                'disarm'    { Set-VeroArmed $false $Action; Disable-VeroKillSwitch -Action $Action }
                'reconnect' { Invoke-VeroReconnect -Config $Config -Action $Action }
            }
        }
        'reconnect' { if (Test-VeroArmed) { Invoke-VeroReconnect -Config $Config -Action $Action } }
        'check'     { Invoke-VeroCheck -Action $Action }
        'watchdog'  {
            # long-running, exactly one per session: the task re-triggers every minute so a crashed loop is back within a minute,
            # and every extra start exits here at once (the launcher returning early once let one loop pile up per minute)
            $single = New-Object System.Threading.Mutex($false, 'Local\VeroScudo-Watchdog')
            $mine = $false
            try { $mine = $single.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $mine = $true }
            if (-not $mine) { $single.Dispose(); return }
            try {
                while ($true) {
                    try { Invoke-VeroCheck -Action $Action } catch { Write-VeroLog "ERROR: $($_.Exception.Message)" $Action }
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

Export-ModuleMember -Function Get-VeroVersion, Test-VeroNewerVersion, Test-VeroReleaseUrl, Get-VeroLatestRelease, Set-VeroHome, Get-VeroPath,
    Get-VeroConfig, ConvertTo-VeroConfigJson, Save-VeroConfig, Test-VeroCidr, Write-VeroLog, Test-VeroArmed, Set-VeroArmed, Set-VeroActiveProfile,
    Test-VeroVpnConnected, Get-VeroRasCode, Get-VeroRasVerdict, Get-VeroRasTermination, Get-VeroDecision, Resolve-VeroServerIp,
    Get-VeroFilterSpec, Get-VeroTunnelLuid, Get-VeroDnsServer, Get-VeroWslLuid, Test-VeroVmWanted, Sync-VeroKillSwitch, Disable-VeroKillSwitch,
    Remove-VeroLegacyFirewall, Test-VeroKillSwitchPresent, Test-VeroNative, Import-VeroNative, Set-VeroVmAccess, Restore-VeroVmAccess,
    Get-VeroCredential, Invoke-VeroDial, Enter-VeroLock, Set-VeroWfpFilter, Get-VeroWfpCount, Clear-VeroWfpFilter, Invoke-VeroReconnect, Invoke-VeroCheck, Invoke-VeroSwitch, Get-VeroStatus, Invoke-VeroAction
