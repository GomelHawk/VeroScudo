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
        [string[]]$DnsServers = @(),
        [string]$TunnelType = 'Automatic',
        [string]$Svchost = $script:Svchost,
        [object[]]$Endpoints = $null,          # OpenVPN / WireGuard: @{ Ip; Proto (6|17); Port } - replaces the RAS ports above
        [string]$EndpointApp = '',             # OpenVPN without DCO: only openvpn.exe may reach them; '' = kernel socket (no program)
        [bool]$CrlWindow = $false,             # SSTP only: a dial just failed on the certificate revocation check (see Open-VeroCrlWindow)
        [string]$PermitKind = ''               # 'server': ServerIps on the tunnel type's ports (built-in client) | 'endpoints': Endpoints (OpenVPN, WireGuard)
    )
    Import-VeroNative
    if (-not $PermitKind) { $PermitKind = if ($null -ne $Endpoints) { 'endpoints' } else { 'server' } }   # older callers and tests
    if ($PermitKind -notin 'server', 'endpoints') { throw "PermitKind must be 'server' or 'endpoints'" }
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
    if ($PermitKind -eq 'endpoints') { $ServerIps = @() }                   # reserve types: their own endpoints below
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
    if ($PermitKind -eq 'endpoints') {
        $groups = @(@($Endpoints) | Where-Object { $_ -and $_.Ip } | Group-Object { '{0}/{1}' -f $_.Proto, $_.Port } | Sort-Object Name)
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
        if ($CrlWindow -and $PermitKind -eq 'server' -and $TunnelType -in 'Sstp', 'Automatic') {
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
    $vm = Test-VeroVmWanted $Config
    $wsl = if ($vm) { Get-VeroWslLuid } else { [uint64]0 }
    $dns = @(if (-not $tun) { Get-VeroDnsServer -ProfileName $Config.Profile })    # @(if ...): an if yielding an empty list is $null
    $rasType = & $th.RasTunnelType $Config.Profile                        # the built-in client's protocol (its ports); 'Automatic' for the others
    $crl = [bool](& $th.CrlWindow)
    $noDns = (-not $tun) -and @($dns).Count -eq 0
    if ($noDns -and -not $script:NoDnsLogged) { Write-VeroLog 'no DNS server known for the network yet - no DNS permit (redial uses cached server addresses)' $Action }
    $script:NoDnsLogged = $noDns                                              # once per change, not every 15 s
    $specs = Get-VeroFilterSpec -Config $Config -ServerIps $ips -TunnelLuid $tun -WslLuid $wsl -DnsServers $dns -TunnelType $rasType -Endpoints $eps -EndpointApp $app -CrlWindow $crl -PermitKind $srv.Kind
    @{ Type = $type; Handler = $th; ForceDown = [bool]$ForceDown; Tunnel = $tun; Ips = @($ips); Dns = @($dns); Vm = $vm; Wsl = $wsl; Specs = @($specs) }
}

function Sync-VeroKillSwitchCore {
    <# Applies the plan when it differs from what is in force (or -Force), logs it, toggles the VM path, refreshes the
       server addresses through the tunnel. Returns $true when a fresh lookup found different server addresses (the
       caller re-syncs once). #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core', [switch]$Force, [switch]$NoRefresh, [switch]$ForceDown)
    $p = Get-VeroPath
    $plan = Get-VeroSyncPlan -Config $Config -Action $Action -ForceDown:$ForceDown
    $type = $plan.Type; $th = $plan.Handler; $ForceDown = $plan.ForceDown; $tun = $plan.Tunnel
    $ips = @($plan.Ips); $dns = @($plan.Dns); $vm = $plan.Vm; $wsl = $plan.Wsl; $specs = @($plan.Specs)
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
        $fresh = @(& $th.ResolveIps $Config)
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
