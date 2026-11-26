# VeroScudo core, part 60: the kill-switch: WFP filter set, sync, VM path, emergency block.
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.

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
        [uint64]$SwitchLuid = 0,               # the Hyper-V Default Switch's host adapter (its VMs' DHCP and DNS), 0 = none
        [string[]]$DnsServers = @(),
        [string]$TunnelType = 'Automatic',
        [string]$Svchost = $script:Svchost,
        [object[]]$Endpoints = $null,          # OpenVPN / WireGuard: @{ Ip; Proto (6|17); Port } - replaces the RAS ports above
        [string]$EndpointApp = '',             # OpenVPN without DCO: only openvpn.exe may reach them; '' = kernel socket (no program)
        [bool]$CrlWindow = $false,             # SSTP only: a dial just failed on the certificate revocation check (see Open-VeroCrlWindow)
        [string]$PermitKind = '',              # 'server': ServerIps on the tunnel type's ports (built-in client) | 'endpoints': Endpoints (OpenVPN, WireGuard) | 'program': ProgramApps to anywhere (Hiddify)
        [string[]]$ProgramApps = @()           # 'program': the client's executables (full paths in an administrators-only folder)
    )
    Import-VeroNative
    if (-not $PermitKind) { $PermitKind = if ($null -ne $Endpoints) { 'endpoints' } else { 'server' } }   # older callers and tests
    if ($PermitKind -notin 'server', 'endpoints', 'program') { throw "PermitKind must be 'server', 'endpoints' or 'program'" }
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
    # Hyper-V Default Switch: Windows itself is its VMs' DHCP server and DNS proxy (ICS). An internal switch - this adapter
    # never reaches a network outside this PC. VMs protected: only while the tunnel is up (the DNS proxy then resolves through
    # the tunnel; while blocked the VMs get nothing). Not protected (vm=false): always - VeroScudo leaves them alone.
    if ($SwitchLuid -and ($TunnelLuid -or -not $Config.Vm)) { foreach ($l in $C4, $C6, $R4, $R6) { $null = (New-Spec 'Default Switch (VM DHCP/DNS)' $l $true $permit).Interface($SwitchLuid) } }

    # the VPN server: only the protocol/ports of the profile's tunnel type. SSTP's TCP only from svchost (SstpSvc). The
    # ports of IKEv2, L2TP and PPTP only for traffic sent as Local System or by an elevated administrator (Sys) - Windows'
    # IKE service, its tunnel drivers and whatever they send on behalf of the elevated guard's dial - never an ordinary
    # program of the signed-in user. The port-less protocols (ESP, GRE, IP-in-IP) stay by address: ordinary programs
    # cannot send them.
    if ($PermitKind -in 'endpoints', 'program') { $ServerIps = @() }        # reserve types: their own permits below
    $fam = Split-Family $ServerIps
    # IKEv2 data: Windows hands each packet of the tunnel to the firewall as an IP-in-IP flow to the server (protocol 4,
    # protocol 41 for IPv6 inside) before IPsec encrypts it. Without these the tunnel connects and carries nothing
    # (hundreds of protocol-4 drops to the server within seconds, every IKEv2 profile dead while armed).
    $ipInIp = @(@{ P = 4; Ports = @(); App = $false }, @{ P = 41; Ports = @(); App = $false })
    $parts = switch ($TunnelType) {
        'Sstp'  { @(@{ P = 6; Ports = @($Config.Port); App = $true }) }
        'Ikev2' { @(@{ P = 17; Ports = @(500, 4500); App = $false; Sys = $true }, @{ P = 50; Ports = @(); App = $false }) + $ipInIp }
        'L2tp'  { @(@{ P = 17; Ports = @(500, 4500, 1701); App = $false; Sys = $true }, @{ P = 50; Ports = @(); App = $false }) }
        'Pptp'  { @(@{ P = 6; Ports = @(1723); App = $false; Sys = $true }, @{ P = 47; Ports = @(); App = $false }) }
        default { @(@{ P = 6; Ports = @($Config.Port); App = $true }, @{ P = 6; Ports = @(1723); App = $false; Sys = $true },
                    @{ P = 17; Ports = @(500, 4500, 1701); App = $false; Sys = $true }, @{ P = 50; Ports = @(); App = $false }, @{ P = 47; Ports = @(); App = $false }) + $ipInIp }
    }
    foreach ($pair in @(@($C4, $fam[0]), @($C6, $fam[1]))) {
        $layer = $pair[0]; $ips = @($pair[1])
        if ($ips.Count -eq 0) { continue }
        foreach ($pt in $parts) {
            $s = New-Spec "VPN server proto $($pt.P)" $layer $true $permit
            $null = $s.Protocol([byte]$pt.P)
            foreach ($port in $pt.Ports) { $null = $s.RemotePort([uint16]$port) }
            foreach ($ip in @($ips | Sort-Object)) { $null = $s.Remote((ConvertTo-VeroRuleAddress $ip)) }      # sorted: a name whose answers rotate gives the same set
            if ($pt.App) { $null = $s.App($Svchost) }
            if ($pt.ContainsKey('Sys') -and $pt.Sys) { $null = $s.Privileged() }
        }
    }

    # OpenVPN / WireGuard: each server address only on its own protocol and port (one permit per protocol/port pair)
    if ($PermitKind -eq 'endpoints') {
        $groups = @(@($Endpoints) | Where-Object { $_ -and $_.Ip } | Group-Object { '{0}/{1}' -f $_.Proto, $_.Port } | Sort-Object Name)
        foreach ($g in $groups) {
            $first = $g.Group[0]
            $ips = Split-Family @($g.Group | ForEach-Object { [string]$_.Ip } | Select-Object -Unique | Sort-Object)
            foreach ($pair in @(@($C4, $ips[0]), @($C6, $ips[1]))) {
                $layer = $pair[0]; $list = @($pair[1])
                if ($list.Count -eq 0) { continue }
                $s = (New-Spec "VPN server proto $($first.Proto)" $layer $true $permit).Protocol([byte]$first.Proto).RemotePort([uint16]$first.Port)
                foreach ($ip in $list) { $null = $s.Remote((ConvertTo-VeroRuleAddress $ip)) }
                if ($EndpointApp) { $null = $s.App($EndpointApp) }
            }
        }
    }

    # Hiddify: its own programs may reach anything (its servers are many, change with each subscription and use TCP and
    # UDP); outbound only - nothing may connect in to them. No program known: nothing at all (never a program-less permit).
    if ($PermitKind -eq 'program') {
        foreach ($app in @($ProgramApps | Where-Object { $_ })) {
            # elevated only (VPN mode runs elevated): the same program started by anyone else stays blocked
            foreach ($l in $C4, $C6) { $null = (New-Spec "VPN app $([IO.Path]::GetFileName($app))" $l $true $permit).App($app).Privileged() }
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
            foreach ($ip in $srv) { $null = $s.Remote((ConvertTo-VeroRuleAddress $ip)) }
        }
        # SSTP's certificate revocation check (HTTP to the CA's CRL/OCSP servers, anywhere): NOT open by default - BITS,
        # Delivery Optimization and WPAD share svchost.exe, so a standing "svchost may use TCP 80" permit is a side door.
        # Opened only for a short window after a dial failed on exactly that check (Open-VeroCrlWindow), SSTP profiles only.
        if ($CrlWindow -and $PermitKind -eq 'server' -and $TunnelType -in 'Sstp', 'Automatic') {
            foreach ($l in $C4, $C6) { $null = (New-Spec 'CRL (redial window)' $l $true $permit).Protocol(6).RemotePort(80).App($Svchost) }
        }
    }

    $lan = Split-Family $Config.LanAllow
    foreach ($c in $lan[0]) { foreach ($l in $C4, $R4) { $null = (New-Spec "LAN $c" $l $true $permit).Remote((ConvertTo-VeroRuleAddress $c -Range)) } }
    foreach ($c in $lan[1]) { foreach ($l in $C6, $R6) { $null = (New-Spec "LAN $c" $l $true $permit).Remote((ConvertTo-VeroRuleAddress $c -Range)) } }

    foreach ($l in $C4, $C6, $R4, $R6) { $null = New-Spec 'block everything else' $l $false 0 }
    , $specs.ToArray()
}

function Get-VeroSpecFingerprint([object[]]$Specs) {
    $text = ($Specs | ForEach-Object { $_.ToString() }) -join "`n"
    $sha = [Security.Cryptography.SHA256]::Create()
    -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)) | ForEach-Object { $_.ToString('x2') })
}

function Test-VeroUsableServerIp {
    <# An address a VPN server can really have: not link-local, loopback, unspecified, multicast, or a fake-DNS answer of
       sing-box / Hiddify (198.18.0.0/15, fc00::/18). Private ranges stay allowed - a company VPN server can sit in the
       local network. Pure (= usable_server_ip on Linux/macOS). #>
    [CmdletBinding()] param([string]$Address)
    if ($Address -match '/' -or -not (Test-VeroCidr $Address)) { return $false }   # a plain address (Test-VeroCidr says what that is)
    $a = [System.Net.IPAddress]::Parse($Address)
    $b = $a.GetAddressBytes()
    if ($a.AddressFamily -eq 'InterNetwork') {
        if ($b[0] -eq 127 -or $b[0] -eq 0 -or $b[0] -ge 224 -or ($b[0] -eq 169 -and $b[1] -eq 254)) { return $false }
        if ($b[0] -eq 198 -and ($b[1] -eq 18 -or $b[1] -eq 19)) { return $false }
        return $true
    }
    if ($a.IsIPv6LinkLocal -or $a.IsIPv6Multicast -or $a.Equals([System.Net.IPAddress]::IPv6Loopback) -or $a.Equals([System.Net.IPAddress]::IPv6Any)) { return $false }
    -not ($b[0] -eq 0xfc -and $b[1] -eq 0 -and ($b[2] -band 0xc0) -eq 0)
}

function Get-VeroHostAddress([string]$Name) {
    <# The addresses of $Name: the answer of the redial's DNS window when it gave one (Invoke-VeroDnsFirst - no second lookup,
       which would wait for a DNS that is closed again), else a lookup through Windows' DNS client. #>
    if ($script:DnsFresh -and $script:DnsFresh.Count -gt 0) { return @($script:DnsFresh[$Name] | Where-Object { $_ }) }   # no answer: none
    @([System.Net.Dns]::GetHostAddresses($Name) | Where-Object { $_.AddressFamily -in 'InterNetwork', 'InterNetworkV6' } | ForEach-Object { $_.IPAddressToString })
}

function Resolve-VeroServerIp {
    <# Pinned serverIps win. Otherwise resolve and merge with the cache (newest first, at most 8): a VPN host that moves
       keeps working, and a lookup that fails while blocked still leaves the last known addresses.
       -CacheOnly: no lookup at all (the filters must never wait for DNS - see Sync-VeroKillSwitch). #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [switch]$CacheOnly)
    if (@($Config.ServerIps).Count -gt 0) { return @($Config.ServerIps) }
    $p = Get-VeroPath -VpnProfile $Config.Profile
    # [string]: Get-Content tags each line with its file path, and ConvertTo-Json would write those tags into wfp.json
    $cached = @(if (Test-Path $p.ServerIp) { Get-Content $p.ServerIp | Where-Object { $_ } | ForEach-Object { [string]$_ } | Where-Object { Test-VeroUsableServerIp $_ } })
    if ($CacheOnly) { return $cached }
    $fresh = @()
    try {
        $fresh = @(Get-VeroHostAddress $Config.Server | Where-Object { Test-VeroUsableServerIp $_ })
    } catch { Write-Verbose "DNS lookup of $($Config.Server) failed: $($_.Exception.Message)" }
    $all = @(@($fresh) + @($cached) | Where-Object { $_ } | Select-Object -Unique | Select-Object -First 8)
    if ($all.Count -gt 0 -and (($all -join ',') -ne ($cached -join ','))) { Write-VeroStateFile -Path $p.ServerIp -Text ($all -join "`r`n") }
    return $all
}

function Get-VeroTunnelLuid {
    <# The LUID of the interface carrying the profile's tunnel right now, 0 when it is down. Only a tunnel adapter, never a
       physical NIC (each type's handler decides what counts as "carrying"). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName, [string]$Type)
    Import-VeroNative
    if (-not $Type) { $Type = Get-VeroProfileType $ProfileName }
    [uint64](& (Get-VeroTypeHandler $Type).TunnelLuid $ProfileName)
}
function Get-VeroRasTunnelLuid {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    $nic = Get-VeroTunnelNic $ProfileName
    if ($nic) { return [VeroScudo.Iface]::LuidFromGuid([guid]$nic.Id) }
    if (-not (Test-VeroVpnConnected $ProfileName)) { return [uint64]0 }
    $if = Get-NetIPInterface -InterfaceAlias $ProfileName -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $if) { return [uint64]0 }
    [VeroScudo.Iface]::LuidFromIndex([uint32]$if.ifIndex)
}

function Get-VeroSwitchLuid {
    <# The Hyper-V Default Switch's host adapter, 0 when there is none (Hyper-V off) or it is down. By its fixed name: the
       same in every Windows language. #>
    $a = Get-VeroNic | Where-Object { $_.Name -eq 'vEthernet (Default Switch)' -and [string]$_.OperationalStatus -eq 'Up' } | Select-Object -First 1
    if ($a) { Import-VeroNative; [VeroScudo.Iface]::LuidFromGuid([guid]$a.Id) } else { [uint64]0 }
}

function Get-VeroWslLuid {
    # WSL's own adapter sits on an internal switch: no default gateway. A switch merely named "WSL..." but bridged to a network
    # card (external) carries that card's gateway - its adapter is the way out to the network and is never allowed
    $a = Get-VeroNic | Where-Object { $_.Name -like 'vEthernet (WSL*' -and [string]$_.OperationalStatus -eq 'Up' -and
        @($_.GetIPProperties().GatewayAddresses | Where-Object { -not $_.Address.Equals([Net.IPAddress]::Any) -and -not $_.Address.Equals([Net.IPAddress]::IPv6Any) }).Count -eq 0 } | Select-Object -First 1
    if ($a) { Import-VeroNative; [VeroScudo.Iface]::LuidFromGuid([guid]$a.Id) } else { [uint64]0 }
}

function Get-VeroDnsServer {
    <# Resolvers of the physical links that are up (not the tunnel, not WSL): the only DNS destinations while blocked. #>
    [CmdletBinding()] param([string]$ProfileName)
    @(Get-VeroNic | Where-Object { [string]$_.OperationalStatus -eq 'Up' -and [string]$_.NetworkInterfaceType -notin 'Ppp', 'Loopback', 'Tunnel' -and
                                   $_.Name -notlike 'vEthernet*' -and $_.Name -ne $ProfileName -and -not (Test-VeroTunnelAdapter $_) } |
        ForEach-Object { $_.GetIPProperties().DnsAddresses } | ForEach-Object { ($_.ToString() -split '%')[0] } |
        Where-Object { $_ -and $_ -notlike 'fec0:0:0:ffff::*' -and $_ -notmatch '/' -and (Test-VeroCidr $_) } | Select-Object -Unique | Sort-Object)   # plain addresses only: one that is not would stop the whole filter set
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
    if (-not $Config.Vm) { return $false }                                  # Settings: VMs and containers not protected
    if (-not (Test-VeroHyperVFirewall)) {
        # no Hyper-V firewall (older Windows): WSL/VM traffic cannot be controlled - say so instead of silently skipping it
        if (Get-VeroNic | Where-Object { $_.Name -like 'vEthernet*' -and [string]$_.OperationalStatus -eq 'Up' }) {
            if (-not $script:VmWarned) { Write-VeroLog 'WARNING: virtual machines / WSL are present but this Windows has no Hyper-V firewall - their traffic is NOT covered by the kill-switch' 'core'; $script:VmWarned = $true }
        }
        return $false
    }
    # a query that fails must not read as "no WSL" while VeroScudo holds WSL's setting changed: the block would be skipped
    try { $creators = @(Get-NetFirewallHyperVVMCreator -ErrorAction Stop) } catch { return (Test-Path -LiteralPath (Get-VeroPath).VmBackup) }
    [bool]($creators | Where-Object VMCreatorId -eq $script:WslCreator)   # WSL is there
}
$script:VmWarned = $false

function Lock-VeroWslNow {
    <# The fastest block of WSL: one switch of a ready block rule (created on the first arm, off while the tunnel is up). A
       block rule beats the allow rule at once; the rest of the drop handling follows. #>
    [CmdletBinding()] param()
    if (-not (Test-VeroHyperVFirewall)) { return }
    try { Set-NetFirewallHyperVRule -Name $script:VmBlockRule -Enabled True -ErrorAction Stop }
    catch { New-NetFirewallHyperVRule -Name $script:VmBlockRule -DisplayName 'VeroScudo - WSL blocked (VPN down)' -Direction Outbound -Action Block -VMCreatorId $script:WslCreator -Enabled True | Out-Null }
}

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
        Write-VeroStateFile -Path $p.VmBackup -Text (@{ DefaultOutboundAction = $orig } | ConvertTo-Json)
    }
    # blocking: the block rule first - it beats the allow rule at once; only when it is not on already (this runs every 15 s)
    if (-not $Allow) {
        $b = Get-NetFirewallHyperVRule -Name $script:VmBlockRule -ErrorAction SilentlyContinue
        if (-not $b -or [string]$b.Enabled -ne 'True') { Lock-VeroWslNow; Write-VeroLog 'WSL block rule -> on' $Action }
    }
    # the allow rule first, the default Block after it: turning on while the tunnel is up never leaves WSL a moment without
    # network (the other order - Block, then 1 s later allowed - could hang a connection open in WSL at that moment)
    $want = if ($Allow) { 'True' } else { 'False' }
    $r = Get-NetFirewallHyperVRule -Name $script:VmRule -ErrorAction SilentlyContinue
    if (-not $r) {
        New-NetFirewallHyperVRule -Name $script:VmRule -DisplayName 'VeroScudo - WSL outbound' -Direction Outbound -Action Allow -VMCreatorId $script:WslCreator -Enabled $want | Out-Null
        Write-VeroLog "Hyper-V rule created: WSL outbound ($(if ($Allow) { 'allowed' } else { 'blocked' }))" $Action
    } elseif ([string]$r.Enabled -ne $want) {
        Set-NetFirewallHyperVRule -Name $script:VmRule -Enabled $want
        Write-VeroLog "WSL outbound -> $(if ($Allow) { 'allowed' } else { 'blocked' })" $Action
    }
    $cur = Get-NetFirewallHyperVVMSetting -PolicyStore PersistentStore -Name $script:WslCreator -ErrorAction SilentlyContinue
    if (-not $cur -or [string]$cur.DefaultOutboundAction -ne 'Block') {
        Set-NetFirewallHyperVVMSetting -Name $script:WslCreator -DefaultOutboundAction Block
        Write-VeroLog 'WSL default outbound -> Block' $Action
    }
    # allowing: the block rule off last (after the allow rule is on); it stays ready for the next drop - created off if missing
    if ($Allow) {
        $b = Get-NetFirewallHyperVRule -Name $script:VmBlockRule -ErrorAction SilentlyContinue
        if (-not $b) { New-NetFirewallHyperVRule -Name $script:VmBlockRule -DisplayName 'VeroScudo - WSL blocked (VPN down)' -Direction Outbound -Action Block -VMCreatorId $script:WslCreator -Enabled False | Out-Null }
        elseif ([string]$b.Enabled -ne 'False') { Set-NetFirewallHyperVRule -Name $script:VmBlockRule -Enabled False }
    }
}
function Restore-VeroVmAccess {
    $p = Get-VeroPath
    if (-not (Test-VeroHyperVFirewall)) { Remove-Item $p.VmBackup -Force -ErrorAction SilentlyContinue; return }   # nothing was ever changed
    # the block rule goes first and always: Off must never leave WSL blocked, whatever happens to the rest
    if (Get-NetFirewallHyperVRule -Name $script:VmBlockRule -ErrorAction SilentlyContinue) {
        try { Remove-NetFirewallHyperVRule -Name $script:VmBlockRule } catch { Write-VeroLog "ERROR: WSL block rule not removed: $($_.Exception.Message) - will retry" 'core' }
    }
    # the default first, the allow rule after it: Off never leaves WSL a moment without network; a default that could not be
    # restored keeps the rule (WSL keeps its network) and is retried
    $restored = $true
    if (Test-Path $p.VmBackup) {
        $orig = [string](Get-Content $p.VmBackup -Raw | ConvertFrom-Json).DefaultOutboundAction
        # a saved Block came from VeroScudo itself (restoring it would leave WSL offline whenever VeroScudo is off)
        if (-not $orig -or $orig -eq 'Block') { $orig = 'NotConfigured' }
        try {
            Set-NetFirewallHyperVVMSetting -Name $script:WslCreator -DefaultOutboundAction $orig
            Remove-Item $p.VmBackup -Force                                   # only once it is really restored
        } catch { $restored = $false; Write-VeroLog "ERROR: WSL default outbound not restored ($orig): $($_.Exception.Message) - will retry" 'core' }
    }
    $r = Get-NetFirewallHyperVRule -Name $script:VmRule -ErrorAction SilentlyContinue
    if ($r -and $restored) { Remove-NetFirewallHyperVRule -Name $script:VmRule }
}

function Set-VeroFailClosed {
    <# A sync that could not work out or apply the filters, on an armed machine: never left as it happened to be.
       No filter in force: the emergency block (set again also when it is noted already - a policy refresh may have undone
       it). In every case the VMs and WSL get the blocked side - the state of the tunnel is not known here - and the note
       of the applied filters goes, so the next sync that works applies everything and gives them their way back.
       Each step on its own: one that fails is logged and the next still runs. Never throws. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core', [string]$Why = '')
    if (-not (Test-VeroArmed)) { return }
    $p = Get-VeroPath
    $have = try { Get-VeroWfpCount } catch { 0 }
    if ($have -eq 0) {
        try {
            if (-not (Test-Path $p.Emergency)) { Write-VeroLog "ERROR: $Why" $Action; Enable-VeroEmergencyBlock -Action $Action }
            elseif (@(Get-NetFirewallProfile | Where-Object { [string]$_.Enabled -notin 'True', '1' -or [string]$_.DefaultOutboundAction -notin 'Block', '4' }).Count -gt 0) {
                Set-NetFirewallProfile -All -Enabled True -DefaultOutboundAction Block
            }
        } catch { Write-VeroLog "ERROR: emergency block failed too - NOT PROTECTED: $($_.Exception.Message)" $Action }
    } elseif ($Why) { Write-VeroLog "ERROR: $Why - the filters in force stay" $Action }
    if ($Config.Vm) {
        try { $null = Set-VeroVmBlock -Block $true -Action $Action; $script:AclBlocked = $true } catch { Write-VeroLog "ERROR: Hyper-V VMs could not be blocked: $($_.Exception.Message)" $Action }
        try { if (Test-VeroVmWanted -Config $Config) { Set-VeroVmAccess -Allow $false -Action $Action; $script:VmAllowed = $false } }
        catch { Write-VeroLog "ERROR: WSL could not be blocked: $($_.Exception.Message)" $Action }
    }
    try { if (Test-Path -LiteralPath $p.WfpState) { Remove-Item -LiteralPath $p.WfpState -Force } } catch { Write-Verbose 'applied-filters note kept' }
}

$script:EmergencyUnnoted = $false     # this process set the emergency block and could write neither its flag nor the note of the old settings

function Enable-VeroEmergencyBlock {
    <# Fail closed: when the WFP filters cannot be applied, block with the Windows Firewall profile default instead. Weaker
       (allow rules still pass) but never open. The next successful sync removes it. #>
    [CmdletBinding()] param([string]$Action = 'core')
    $p = Get-VeroPath
    # the note of how the firewall was, for the way back - the block does not wait on it. Never taken once the block is
    # in force: it would note the block itself as "how the firewall was"
    if (-not (Test-Path $p.FwBackup) -and -not (Test-Path $p.Emergency) -and -not $script:EmergencyUnnoted) {
        try { Write-VeroStateFile -Path $p.FwBackup -Text (Get-NetFirewallProfile | Select-Object Name, DefaultOutboundAction, Enabled | ConvertTo-Json) }
        catch { Write-VeroLog "WARNING: the firewall's settings could not be noted ($($_.Exception.Message)) - they are not restored automatically afterwards" $Action }
    }
    # the flag first: with it there, every later pass sets the block again. A flag that cannot be written does not stop the block
    try { New-Item -ItemType File -Path $p.Emergency -Force | Out-Null } catch { Write-VeroLog "WARNING: the emergency block could not be noted ($($_.Exception.Message))" $Action }
    Set-NetFirewallProfile -All -Enabled True -DefaultOutboundAction Block     # a profile that is switched off blocks nothing
    if (-not (Test-Path $p.Emergency) -and -not (Test-Path $p.FwBackup)) { $script:EmergencyUnnoted = $true }
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
            # a profile that was switched off before the emergency block is switched off again (a backup from before 1.4 has no such note)
            if ($pr.PSObject.Properties['Enabled'] -and [string]$pr.Enabled -in '0', 'False') { Set-NetFirewallProfile -Name $pr.Name -Enabled False }
        }
        if (Test-Path $p.Emergency) { Remove-Item $p.Emergency -Force }       # before the note: a flag left behind alone would read as "block without a note" next time
        Remove-Item $p.FwBackup -Force
        Write-VeroLog 'Windows Firewall default outbound restored' $Action
    } elseif ((Test-Path $p.Emergency) -or $script:EmergencyUnnoted) {
        # the emergency block was set without a note of how the firewall was (the note could not be written): the block
        # itself still goes - back to Windows' own default; profiles that had been switched off stay switched on
        Set-NetFirewallProfile -All -DefaultOutboundAction NotConfigured
        Write-VeroLog 'emergency block lifted - Windows Firewall default outbound back to its default (the earlier settings had not been noted; check them if you had changed them)' $Action
    }
    $rules = @(Get-NetFirewallRule -Group $script:LegacyGroup -ErrorAction SilentlyContinue)
    if ($rules) { Remove-NetFirewallRule -Group $script:LegacyGroup; Write-VeroLog "removed $($rules.Count) Windows Firewall rule(s) of the old kill-switch" $Action }
    Remove-Item $p.Emergency -Force -ErrorAction SilentlyContinue
    $script:EmergencyUnnoted = $false
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
        $literal = (Test-VeroCidr ([string]$r.Host)) -and [string]$r.Host -notmatch '/'
        $ips = if ($literal) { @($r.Host | Where-Object { Test-VeroUsableServerIp ([string]$_) }) } else {
            $cached = @($cache[$r.Host] | Where-Object { $_ -and (Test-VeroUsableServerIp ([string]$_)) })
            if ($CacheOnly) { $cached } else {
                $fresh = @()
                try { $fresh = @(Get-VeroHostAddress ([string]$r.Host) | Where-Object { Test-VeroUsableServerIp $_ }) }
                catch { Write-Verbose "DNS lookup of $($r.Host) failed: $($_.Exception.Message)" }
                $all = @(@($fresh) + @($cached) | Where-Object { $_ } | Select-Object -Unique | Select-Object -First 8)
                if (($all -join ',') -ne ($cached -join ',')) { $cache[$r.Host] = $all; $changed = $true }
                $all
            }
        }
        foreach ($ip in $ips) { [pscustomobject]@{ Ip = [string]$ip; Proto = $(if ($r.Proto -eq 'tcp') { 6 } else { 17 }); Port = [int]$r.Port } }
    }
    if ($changed) { Write-VeroStateFile -Path $p.EndpointCache -Text ($cache | ConvertTo-Json -Depth 3) }
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
       tunnel is up: a lookup made before the switch would hang on the filters still in force (23 s after a drop,
       12 s after a reconnect, all traffic blocked meanwhile). One sync at a time (watchdog and event tasks run in parallel). #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core', [switch]$Force, [switch]$NoRefresh, [switch]$ForceDown)
    # -ForceDown: apply the set without the tunnel even while it is still up (Reconnect: block first, then hang up)
    $due = Invoke-VeroLocked { param($c, $a, $f, $n, $d) Sync-VeroKillSwitchCore -Config $c -Action $a -Force:$f -NoRefresh:$n -ForceDown:$d } -Arguments @($Config, $Action, $Force.IsPresent, $NoRefresh.IsPresent, $ForceDown.IsPresent)
    # the server lookup after the lock is released: it can hang for many seconds, and Off must never wait for it
    if ($due -and $due.PSObject.Properties['Ips'] -and -not $ForceDown) {
        $fresh = @(& (Get-VeroTypeHandler (Get-VeroConfigType $Config)).ResolveIps $Config)
        if (($fresh -join ',') -ne (@($due.Ips) -join ',')) { Sync-VeroKillSwitch -Config $Config -Action $Action -NoRefresh }
    }
}

function Invoke-VeroLocked([scriptblock]$Script, [object[]]$Arguments = @()) {
    <# Applying and removing filters never overlap (watchdog, event tasks and On/Off run in parallel processes). Otherwise
       a slow disarm can finish after a re-arm applied its filters and leave an armed machine without any. #>
    # after a minute without the lock: ahead anyway - Off must work even while another process is stuck in a sync - and said so
    $held = Enter-VeroSingleton -Name 'sync' -WaitMs 60000
    if (-not $held) { Write-VeroLog 'WARNING: another VeroScudo process has held the filter lock for a minute - going ahead without it' 'core' }
    try {
        & $Script @Arguments                       # values passed explicitly, not read from the caller's scope
    } finally {
        if ($held) { $held.Dispose() }
    }
}

function Get-VeroSyncPlan {
    <# What the kill-switch must look like right now: the tunnel (0 = blocked), the addresses this type's client may reach,
       DNS while down, the VM path - and the filter specs built from them. The lookups it names are the only side effects. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core', [switch]$ForceDown)
    $type = Get-VeroConfigType $Config
    $th = Get-VeroTypeHandler $type
    if (-not $ForceDown) {                                                 # a Reconnect is hanging up: keep its tunnel blocked meanwhile
        $mk = Get-VeroRenewMarker
        if ($mk -and [string]$mk.Profile -eq $Config.Profile -and -not [string]$mk.HungUp) {
            try { if (((Get-Date) - [datetime]::Parse([string]$mk.Start, $null, [Globalization.DateTimeStyles]::RoundtripKind)).TotalSeconds -lt 30) { $ForceDown = [switch]$true } } catch { Write-Verbose 'renew marker' }
        }
    }
    $tun = if ($ForceDown) { [uint64]0 } else { Get-VeroTunnelLuid $Config.Profile -Type $type }
    $srv = & $th.ServerPermit $Config $Action                             # what the filters may let this type's client reach
    $ips = @($srv.Ips); $eps = $srv.Endpoints; $app = [string]$srv.App
    $apps = @(if ($srv.ContainsKey('Apps')) { $srv.Apps })
    $vm = Test-VeroVmWanted $Config
    $wsl = if ($vm) { Get-VeroWslLuid } else { [uint64]0 }
    $sw = Get-VeroSwitchLuid                                               # Get-VeroFilterSpec decides when it is open
    # DNS while down: a type VeroScudo dials gets it only for the redial's own lookup of its server, right before each
    # dial (Invoke-VeroDnsFirst) - the names of the sites you visit stay inside. Hiddify (not dialed): none - its
    # programs may reach any address and its core asks its own DNS servers
    # the SSTP revocation window (Open-VeroCrlWindow) needs DNS too: the CRL/OCSP servers are known by name
    $wantDns = (-not $tun) -and ($script:DnsWindow -or [bool](& $th.CrlWindow))
    $dns = @(if ($wantDns) { Get-VeroDnsServer -ProfileName $Config.Profile })    # @(if ...): an if yielding an empty list is $null
    $rasType = & $th.RasTunnelType $Config.Profile                        # the built-in client's protocol (its ports); 'Automatic' for the others
    $crl = [bool](& $th.CrlWindow)
    $noDns = $wantDns -and @($dns).Count -eq 0
    if ($noDns -and -not $script:NoDnsLogged) { Write-VeroLog 'no DNS server known for the network yet - no DNS permit (redial uses cached server addresses)' $Action }
    $script:NoDnsLogged = $noDns                                              # once per change, not every 15 s
    $specs = Get-VeroFilterSpec -Config $Config -ServerIps $ips -TunnelLuid $tun -WslLuid $wsl -SwitchLuid $sw -DnsServers $dns -TunnelType $rasType -Endpoints $eps -EndpointApp $app -CrlWindow $crl -PermitKind $srv.Kind -ProgramApps $apps
    @{ Type = $type; Handler = $th; ForceDown = [bool]$ForceDown; Tunnel = $tun; Ips = @($ips); Dns = @($dns); Vm = $vm; Wsl = $wsl; Switch = $sw; Specs = @($specs) }
}

function Sync-VeroKillSwitchCore {
    <# Applies the plan when it differs from what is in force (or -Force), logs it, toggles the VM path, refreshes the
       server addresses through the tunnel. Returns $true when a fresh lookup found different server addresses (the
       caller re-syncs once). #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core', [switch]$Force, [switch]$NoRefresh, [switch]$ForceDown)
    $p = Get-VeroPath
    # under the lock: turned off since the caller looked? Then no filters - they would stay until the next watchdog pass
    if (-not (Test-VeroArmed)) { return $false }
    try {
        $plan = Get-VeroSyncPlan -Config $Config -Action $Action -ForceDown:$ForceDown
        $type = $plan.Type; $ForceDown = $plan.ForceDown; $tun = $plan.Tunnel
        $ips = @($plan.Ips); $dns = @($plan.Dns); $vm = $plan.Vm; $wsl = $plan.Wsl; $sw = $plan.Switch; $specs = @($plan.Specs)
        $fp = Get-VeroSpecFingerprint $specs
        $prev = Get-VeroAppliedState
        $present = Get-VeroWfpCount
    } catch {
        # the filters could not even be worked out (the native helper does not load, an adapter cannot be read ...): an
        # armed machine with no filter in force gets the emergency block, like a failed apply below
        Set-VeroFailClosed -Config $Config -Action $Action -Why "the filters could not be worked out: $($_.Exception.Message)"
        throw
    }
    $applied = $false
    if ($Force -or -not $prev -or $prev.Fingerprint -ne $fp -or $present -ne $specs.Count -or (Test-Path $p.Emergency)) {
        $applied = $true
        try {
            Set-VeroWfpFilter $specs
        } catch {
            Set-VeroFailClosed -Config $Config -Action $Action -Why "WFP apply failed: $($_.Exception.Message)"
            throw
        }
        # a blocked set (a drop, a Reconnect, a switch): the connection check starts its rating over from here, however short
        # the gap - its own rounds every 10-100 s can miss a Reconnect of a few seconds (otherwise "unstable" 1 s after one)
        if (-not $tun) { try { Write-VeroStateFile -Path $p.LastDown -Text ([string](Get-VeroEpoch)) } catch { Write-Verbose 'last-down not written' } }
        # the note of what is in force (for the next pass, status and the tray). The steps below - the VMs and WSL - never
        # depend on it: a file somebody holds open at this moment must not leave them as they were
        try { Write-VeroStateFile -Path $p.WfpState -Text (@{ Fingerprint = $fp; Count = $specs.Count; Profile = $Config.Profile; Type = $type; Tunnel = [string]$tun; Wsl = [string]$wsl; Switch = [string]$sw; Servers = $ips; Time = (Get-Date).ToString('o') } | ConvertTo-Json) }
        catch { Write-VeroLog "WARNING: the note of the applied filters could not be written ($($_.Exception.Message)) - they are applied again on the next pass" $Action }
        $why = if (-not $prev) { 'armed' } elseif ($present -ne $prev.Count) { "filters missing ($present of $($prev.Count))" } else { 'changed' }
        Write-VeroLog ("kill-switch {0}: {1} filters, profile '{2}' ({7}), tunnel {3}, wsl {4}, default switch {8}, server {5}, dns {6}" -f $why, $specs.Count, $Config.Profile,
            $(if ($tun) { 'up' } elseif ($ForceDown) { 'BLOCKED for reconnect' } else { 'DOWN' }), $(if ($wsl) { 'bound' } else { '-' }), ($ips -join ','),
            $(if ($tun) { 'tunnel only' } else { ($dns -join ',') }), (Get-VeroTypeLabel $type), $(if ($sw -and ($tun -or -not $Config.Vm)) { 'open' } else { '-' })) $Action   # as the filters have it
    }
    $liftEmergency = $applied -and ((Test-Path $p.Emergency) -or (Test-Path $p.FwBackup) -or $script:EmergencyUnnoted)   # lifted below, after the VM and WSL steps (the note of the old settings alone tells of a block too)
    # Hyper-V Default Switch VMs: their traffic never reaches these filters (62-HyperVAcl.ps1). Protected: port ACLs while
    # the tunnel is down - right after the filters, before the slower WSL step (after it they would come 3 s later).
    # On every change; while blocked also every sync, so a VM created meanwhile is covered. Not protected: none at all.
    # fix B: after Windows logged "network disconnected" (NetDown task) they stay blocked until the tunnel is proven: a new
    # tunnel (a redial), or traffic through it - RAS reports a dead tunnel only seconds after the network is back
    $suspect = try { Get-VeroNetSuspect } catch { Write-VeroLog "ERROR: the note of the network drop cannot be read ($($_.Exception.Message)) - Hyper-V VMs stay blocked for now" $Action; $true }
    if ($suspect -and $suspect -isnot [bool] -and $tun) {
        # a failure in this look (an adapter that just went away, a note that cannot be removed) leaves the VMs blocked
        # for this pass - it never skips the steps below
        try {
            if ([string]$tun -ne [string]$suspect.Tunnel -or (Test-VeroTunnelCarries -Luid $tun)) {
                Clear-VeroNetSuspect; $suspect = $null
                Write-VeroLog 'the tunnel carries traffic again - Hyper-V VMs through the tunnel' $Action
            }
        } catch { Write-VeroLog "ERROR: could not tell whether the tunnel carries traffic again ($($_.Exception.Message)) - Hyper-V VMs stay blocked for now" $Action }
    }
    # WSL / Default Switch VMs: the internet routed to nowhere while the tunnel is down (62-HyperVAcl.ps1), and right
    # after a drop the watchdog saw while RAS still says "connected" (the note of the drop, at most 30 s: RAS tells within
    # ~20 s) - gone once the tunnel is proven (above: the proof is sent from the tunnel's own address, past these routes).
    # Before the route check below: a tunnel that is back must find them gone, or it would look like a split tunnel. Not
    # for a type VeroScudo does not dial (Hiddify reaches its servers itself), not during the revocation window
    $holeDrop = (-not $tun) -or ($suspect -and $suspect -isnot [bool] -and (Test-VeroNetSuspectFresh $suspect))
    $holeWant = $holeDrop -and [bool]$Config.Vm -and ([bool]$wsl -or [bool]$sw) -and [bool]$plan.Handler.Dials -and -not [bool](& $plan.Handler.CrlWindow) -and @($ips).Count -gt 0
    try { Sync-VeroBlackhole -Want $holeWant -ServerIps $ips -Dns $dns -Action $Action } catch { Write-VeroLog "ERROR: routes for WSL and VMs: $($_.Exception.Message) - tried again on the next pass" $Action }
    # a split-tunnel profile: the VMs and WSL stay blocked even while it is up (they would reach the rest past the tunnel);
    # not asked while a drop is unproven - they are blocked anyway, and the routes above would look like a split tunnel
    $full = if ($tun -and $Config.Vm -and -not $suspect) { Test-VeroTunnelHoldsDefault -Luid $tun } else { $true }
    if (-not $full -and -not $script:SplitLogged) { Write-VeroLog "the route to the internet does not lead into the tunnel of '$($Config.Profile)' (a split-tunnel profile, or the network is changing) - VMs and WSL stay blocked" $Action }
    $script:SplitLogged = -not $full
    # the tunnel that holds the route to the internet, for the watchdog's 1-second look (Test-VeroRouteLeft): only a full
    # tunnel that carries traffic - a split tunnel or a drop not yet proven over is never watched
    $script:WatchLuid = if ($tun -and $full -and -not $suspect -and $Config.Vm) { [uint64]$tun } else { [uint64]0 }
    $aclWant = ((-not [bool]$tun) -or [bool]$suspect -or -not $full) -and [bool]$Config.Vm
    # the record on disk too: the NetDown task blocks the VMs in its own process, so this one may not know they are blocked
    if ($applied -or $script:AclBlocked -ne $aclWant -or $aclWant -or (Test-Path -LiteralPath $p.VmAcl)) {
        try { $null = Set-VeroVmBlock -Block $aclWant -Action $Action; $script:AclBlocked = $aclWant }
        catch { Write-VeroLog "ERROR: Hyper-V port ACLs: $($_.Exception.Message)" $Action }
    }
    # the Hyper-V firewall queries are slow (~0.4 s): only when something changed, else every ~5 min as a tamper check
    $script:SyncCount++
    # what this long-lived process remembers about the Windows VPN entries is looked up again now and then: an entry changed
    # from SSTP to IKEv2 would otherwise keep its old ports here while every short task computes the new ones
    if ($script:SyncCount % 20 -eq 0) { $script:TunnelTypes = @{} }
    $wslAllow = [bool]$tun -and -not [bool]$suspect -and $full             # like the VMs: blocked after a drop until proven, and with a split tunnel
    if ($vm -and ($applied -or $script:VmAllowed -ne $wslAllow -or $script:SyncCount % 20 -eq 0)) {
        try { Set-VeroVmAccess -Allow $wslAllow -Action $Action; $script:VmAllowed = $wslAllow }
        catch { Write-VeroLog "ERROR: WSL (Hyper-V firewall): $($_.Exception.Message) - tried again on the next pass" $Action; $script:VmAllowed = $null }
    }
    # the VPN server's name answered locally while the tunnel is down (NRPT) - nothing is asked of Windows unless it changes
    try { Sync-VeroNrpt -Config $Config -TunnelLuid ([uint64]$tun) -Action $Action } catch { Write-VeroLog "ERROR: NRPT: $($_.Exception.Message) - tried again on the next pass" $Action }
    # the emergency block of an earlier failure goes last: the real filters and the VM / WSL steps are in force by now
    if ($liftEmergency) { try { Remove-VeroLegacyFirewall -Action $Action } catch { Write-VeroLog "ERROR: the emergency block could not be lifted ($($_.Exception.Message)) - tried again on the next pass" $Action } }
    # the server addresses are refreshed only now - through the tunnel, after the filters let it through - by the caller,
    # outside the lock: here only what is in force
    if ($tun -and -not $NoRefresh -and @($Config.ServerIps).Count -eq 0) { return [pscustomobject]@{ Ips = @($ips) } }
    $false
}
$script:SyncCount = 0
$script:NoDnsLogged = $false
$script:VmAllowed = $null
$script:SplitLogged = $false
$script:AclBlocked = $null

function Disable-VeroKillSwitch {
    [CmdletBinding()] param([string]$Action = 'core')
    Invoke-VeroLocked {
        param($a)
        # re-checked under the lock: if something armed again meanwhile (On pressed right after a hang-up), its filters stay
        if (Test-VeroArmed) { Write-VeroLog 'armed again meanwhile - kill-switch kept' $a; return }
        Clear-VeroWfpFilter
        Remove-Item (Get-VeroPath).WfpState -Force -ErrorAction SilentlyContinue
        # each step on its own: one that fails must not keep the later ones from running (the routes to nowhere left in
        # place would leave the PC without internet after Off)
        try { Remove-VeroLegacyFirewall -Action $a } catch { Write-VeroLog "ERROR: old firewall rules not removed: $($_.Exception.Message) - will retry" $a }
        try { Restore-VeroVmAccess } catch { Write-VeroLog "ERROR: WSL access not restored: $($_.Exception.Message) - will retry" $a }
        try { Clear-VeroNetSuspect } catch { Write-VeroLog "ERROR: network note not removed: $($_.Exception.Message)" $a }
        try { $null = Set-VeroVmBlock -Block $false -Action $a } catch { Write-VeroLog "ERROR: Hyper-V port ACLs not removed: $($_.Exception.Message) - will retry" $a }
        $script:AclBlocked = $null
        try { Remove-VeroNrpt -Action $a } catch { Write-VeroLog "ERROR: NRPT rules not removed: $($_.Exception.Message) - will retry" $a }
        try { Remove-VeroBlackhole -Action $a } catch { Write-VeroLog "ERROR: routes for WSL and VMs not removed: $($_.Exception.Message) - will retry" $a }
        Write-VeroLog 'kill-switch OFF (filters removed)' $a
    } -Arguments @($Action)
}

function Test-VeroKillSwitchPresent {
    # anything VeroScudo changed and has not yet undone, incl. a WSL setting whose restore failed (retried by the watchdog)
    ((Get-VeroWfpCount) -gt 0) -or (Test-Path (Get-VeroPath).Emergency) -or (Test-Path (Get-VeroPath).VmBackup) -or (Test-Path (Get-VeroPath).VmAcl) -or
        (Test-Path (Get-VeroPath).Blackhole) -or (Test-Path (Get-VeroPath).Nrpt) -or
        [bool](Get-NetFirewallRule -Group $script:LegacyGroup -ErrorAction SilentlyContinue)
}

function Test-VeroNative {
    <# Elevated self-test (Install.ps1): every layer/condition GUID the filters use must be known to this Windows' WFP. #>
    Import-VeroNative
    $missing = @()
    foreach ($l in 'ConnectV4', 'ConnectV6', 'RecvAcceptV4', 'RecvAcceptV6') {
        $fields = [VeroScudo.Wfp]::LayerFields([VeroScudo.Layer]::$l)
        foreach ($n in 'Flags', 'LocalInterface', 'RemoteAddress', 'Protocol', 'RemotePort', 'LocalPort', 'AppId', 'UserId') {
            if ($fields -notcontains [VeroScudo.Field]::$n) { $missing += "$l/$n" }
        }
    }
    if ($missing) { throw "WFP self-test failed - unknown field(s): $($missing -join ', ')" }
    # and one filter of every shape the guard builds, offered to WFP inside a transaction that is rolled back: a condition
    # this Windows does not take is found here, before anything is changed
    $probe = foreach ($l in [VeroScudo.Layer]::ConnectV4, [VeroScudo.Layer]::ConnectV6) {
        $s = New-Object VeroScudo.FilterSpec('self-test', $l, $true, [byte]8)
        $null = $s.Protocol([byte]17).RemotePort([uint16]500).Remote($(if ($l -eq [VeroScudo.Layer]::ConnectV4) { '203.0.113.5' } else { '2001:db8::5' })).Privileged()
        $s
        $t = New-Object VeroScudo.FilterSpec('self-test', $l, $true, [byte]8)
        $null = $t.Protocol([byte]6).RemotePort([uint16]443).App($script:Svchost)
        $t
    }
    try { [VeroScudo.Wfp]::Validate([VeroScudo.FilterSpec[]]@($probe)) } catch { throw "WFP self-test failed - a filter was refused: $($_.Exception.Message)" }
    $true
}
