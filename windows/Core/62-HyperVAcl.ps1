# VeroScudo core, part 62: Hyper-V Default Switch VMs - port ACLs while blocked.
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.
#
# Windows translates a Default Switch VM's traffic inside the Hyper-V virtual switch, below the host's IP stack: none of
# the WFP filters see it, and while the tunnel is down it leaves through the normal network. The
# virtual switch enforces port ACLs on each VM's port before that translation, so while armed and blocked every VM on the
# Default Switch gets: outbound deny everything, allow the switch's own subnet (Windows is its DHCP server and DNS proxy),
# broadcast and IPv6 link-local/multicast. While the tunnel is up the rules are removed (the VM's traffic then follows
# Windows' routes into the tunnel). VeroScudo records exactly the rules it added (state\vm-acl.json) and removes only those:
# a port ACL the user set is never touched. All VMs on the switch, running or not - an ACL is part of the VM's settings,
# so a VM started during an outage is blocked from its first packet.

$script:SwitchName = 'Default Switch'
$script:HyperVTools = $null
$script:AclToolsWarned = $false

function Test-VeroHyperVTools {
    <# The Hyper-V PowerShell module (Hyper-V management tools) is there. Cached. #>
    if ($null -eq $script:HyperVTools) {
        $script:HyperVTools = [bool]((Get-Command -Module Hyper-V -Name Get-VMNetworkAdapter, Get-VMNetworkAdapterAcl, Add-VMNetworkAdapterAcl, Remove-VMNetworkAdapterAcl -ErrorAction SilentlyContinue | Measure-Object).Count -ge 4)
    }
    $script:HyperVTools
}

function ConvertTo-VeroNetworkPrefix {
    <# '172.20.152.1', 20 -> '172.20.144.0/20' (IPv4). Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Address, [Parameter(Mandatory)][int]$PrefixLength)
    $b = ([System.Net.IPAddress]::Parse($Address)).GetAddressBytes()
    [Array]::Reverse($b)
    $n = [BitConverter]::ToUInt32($b, 0)
    $all = [uint64]4294967295                                           # not 0xFFFFFFFF: PowerShell reads that as -1
    $mask = if ($PrefixLength -le 0) { [uint32]0 } else { [uint32](($all -shl (32 - $PrefixLength)) -band $all) }
    $net = [BitConverter]::GetBytes([uint32]($n -band $mask))
    [Array]::Reverse($net)
    '{0}/{1}' -f ([System.Net.IPAddress]::new($net)).ToString(), $PrefixLength
}

function Get-VeroVmAclRule {
    <# The port ACLs of a blocked Default Switch VM: [@{ Remote; Action }], all outbound. The most specific address wins in
       Hyper-V, so the allows punch holes into the denies. $Subnet: the switch's own network ('' = unknown: no hole for it). Pure. #>
    [CmdletBinding()] param([string]$Subnet)
    $r = @(
        @{ Remote = '0.0.0.0/0'; Action = 'Deny' }
        @{ Remote = '::/0'; Action = 'Deny' }
        @{ Remote = '255.255.255.255'; Action = 'Allow' }             # DHCP discover (Hyper-V stores a host address without /32)
        @{ Remote = 'fe80::/10'; Action = 'Allow' }                   # IPv6 link-local (neighbour discovery)
        @{ Remote = 'ff00::/8'; Action = 'Allow' }                    # IPv6 multicast (neighbour discovery)
    )
    if ($Subnet) { $r += @{ Remote = $Subnet; Action = 'Allow' } }     # Windows: DHCP server and DNS proxy of the switch
    $r
}

function Format-VeroAclAddress([string]$Remote) {
    <# One form for comparing: Hyper-V stores a host address without its /32 (/128) and may prefix 'Remote '. Pure. #>
    ([string]$Remote).Trim() -replace '^Remote\s+', '' -replace '/32$', '' -replace '/128$', ''
}
function Get-VeroAclRemote($Acl) {
    <# The remote address of a port ACL as Hyper-V reports it (property name differs between Windows versions). #>
    foreach ($n in 'RemoteAddress', 'RemoteIPAddress', 'Address') { if ($Acl.PSObject.Properties[$n] -and [string]$Acl.$n) { return [string]$Acl.$n } }
    ''
}
function Find-VeroVmAcl($Adapter, [string]$Remote, [string]$Action, [object[]]$Present) {
    <# The adapter's outbound port ACLs with this address and action, in Hyper-V's own form. -Present: the adapter's ACLs
       already fetched (one Hyper-V call per VM instead of one per rule). #>
    if ($null -eq $Present) { $Present = @(Get-VeroVmAdapterAcl $Adapter) }
    @($Present | Where-Object { [string]$_.Direction -eq 'Outbound' -and [string]$_.Action -eq $Action -and (Format-VeroAclAddress (Get-VeroAclRemote $_)) -eq (Format-VeroAclAddress $Remote) })
}

# thin wrappers around the Hyper-V module (module-qualified: VMware PowerCLI has a Get-VM of its own); mocked in the tests
function Get-VeroAllVmAdapter { @(Hyper-V\Get-VMNetworkAdapter -VMName * -ErrorAction SilentlyContinue) }
function Get-VeroSwitchVmAdapter { @(Get-VeroAllVmAdapter | Where-Object { [string]$_.SwitchName -eq $script:SwitchName }) }
function Get-VeroVmAdapterAcl($Adapter) { @(Hyper-V\Get-VMNetworkAdapterAcl -VMNetworkAdapter $Adapter -ErrorAction SilentlyContinue) }
function Add-VeroVmAdapterAcl($Adapter, [string]$Remote, [string]$Action) { Hyper-V\Add-VMNetworkAdapterAcl -VMNetworkAdapter $Adapter -RemoteIPAddress $Remote -Direction Outbound -Action $Action -ErrorAction Stop }
function Remove-VeroVmAdapterAcl($Adapter, [string]$Remote, [string]$Action) { Hyper-V\Remove-VMNetworkAdapterAcl -VMNetworkAdapter $Adapter -RemoteIPAddress $Remote -Direction Outbound -Action $Action -ErrorAction Stop }

function Get-VeroSwitchSubnet {
    <# The Default Switch's IPv4 network, from its host adapter ('' when there is none). #>
    $a = Get-NetIPAddress -InterfaceAlias "vEthernet ($script:SwitchName)" -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($a) { ConvertTo-VeroNetworkPrefix -Address $a.IPAddress -PrefixLength $a.PrefixLength } else { '' }
}

function Get-VeroVmAclState {
    $p = (Get-VeroPath).VmAcl
    if (-not (Test-Path -LiteralPath $p)) { return @() }
    # ConvertFrom-Json (PowerShell 5.1) emits a JSON array as ONE object: assign it first, then enumerate the variable
    try { $j = [IO.File]::ReadAllText($p) | ConvertFrom-Json; @($j | ForEach-Object { $_ } | Where-Object { $_ }) }
    catch { Write-VeroLog "WARNING: the record of the Hyper-V port rules VeroScudo added cannot be read ($($_.Exception.Message)) - rules it added earlier may stay on the VMs' adapters (remove them with Remove-VMNetworkAdapterAcl)" 'core'; @() }
}
function Save-VeroVmAclState([object[]]$Entries) {
    $p = (Get-VeroPath).VmAcl
    if (@($Entries).Count -eq 0) { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }; return }
    Write-VeroStateFile -Path $p -Text (ConvertTo-Json -InputObject @($Entries) -Depth 3)   # whole or not at all: it records the rules to remove later
}

function Set-VeroVmBlock {
    <# Block (deny rules on every Default Switch VM) or unblock (remove exactly what VeroScudo added). Idempotent: run
       again while blocked it covers VMs created or attached since. Never throws: a failure is logged and retried on the
       next sync - the WFP kill-switch must not depend on it. Returns the number of VMs it covers while blocked. #>
    [CmdletBinding()] param([Parameter(Mandatory)][bool]$Block, [string]$Action = 'core')
    $have = @(Get-VeroVmAclState)
    if (-not $Block) {
        if ($have.Count -eq 0) { return 0 }
        if (-not (Test-VeroHyperVTools)) { return 0 }
        $adapters = @(Get-VeroAllVmAdapter)                              # also VMs moved to another switch since: their rules go too
        $left = New-Object System.Collections.Generic.List[object]
        foreach ($e in $have) {
            $a = $adapters | Where-Object { [string]$_.Id -eq [string]$e.AdapterId } | Select-Object -First 1
            if (-not $a) { continue }                                  # the VM or its adapter is gone: nothing left to remove
            try {
                # removed in the form Hyper-V stored it ('255.255.255.255/32' does not match its '255.255.255.255'
                # and the rule would stay), then checked
                foreach ($m in @(Find-VeroVmAcl $a ([string]$e.Remote) ([string]$e.Action))) { Remove-VeroVmAdapterAcl $a (Format-VeroAclAddress (Get-VeroAclRemote $m)) ([string]$e.Action) }
                if (@(Find-VeroVmAcl $a ([string]$e.Remote) ([string]$e.Action)).Count -gt 0) { throw 'still there after removal' }
            } catch { $left.Add($e); Write-VeroLog "ERROR: port ACL $($e.Remote) $($e.Action) on VM '$($e.VMName)' not removed: $($_.Exception.Message) - will retry" $Action }
        }
        Save-VeroVmAclState $left.ToArray()
        if ($left.Count -eq 0) { Write-VeroLog "Hyper-V VMs on the $($script:SwitchName): port ACLs removed (traffic through the tunnel)" $Action }
        return 0
    }
    if (-not (Test-VeroHyperVTools)) {
        if (-not $script:AclToolsWarned -and (Get-VeroNic | Where-Object { $_.Name -eq "vEthernet ($script:SwitchName)" })) {
            Write-VeroLog "WARNING: the Hyper-V $($script:SwitchName) is there but the Hyper-V PowerShell tools are not - its VMs are NOT covered while blocked" $Action
            $script:AclToolsWarned = $true
        }
        return 0
    }
    $adapters = @(Get-VeroSwitchVmAdapter)
    if ($adapters.Count -eq 0) { return 0 }
    $rules = @(Get-VeroVmAclRule -Subnet (Get-VeroSwitchSubnet))
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($e in $have) { $list.Add($e) }
    $added = 0
    foreach ($a in $adapters) {
        $present = @(Get-VeroVmAdapterAcl $a)
        foreach ($r in $rules) {
            $ours = @($have | Where-Object { [string]$_.AdapterId -eq [string]$a.Id -and [string]$_.Remote -eq $r.Remote -and [string]$_.Action -eq $r.Action }).Count -gt 0
            $there = @(Find-VeroVmAcl $a $r.Remote $r.Action -Present $present).Count -gt 0
            if ($there) { continue }                                   # ours already, or the user's own: leave it as it is
            try {
                Add-VeroVmAdapterAcl $a $r.Remote $r.Action
                if (-not $ours) { $list.Add([pscustomobject]@{ VMName = [string]$a.VMName; AdapterId = [string]$a.Id; Remote = $r.Remote; Action = $r.Action }) }
                $added++
            } catch { Write-VeroLog "ERROR: port ACL $($r.Remote) $($r.Action) on VM '$($a.VMName)' not set: $($_.Exception.Message)" $Action }
        }
    }
    Save-VeroVmAclState $list.ToArray()
    if ($added -gt 0) { Write-VeroLog ("Hyper-V VMs on the {0}: blocked by port ACLs ({1})" -f $script:SwitchName, ((@($adapters | ForEach-Object { [string]$_.VMName }) | Select-Object -Unique) -join ', ')) $Action }
    $adapters.Count
}

# ---------------------------------------------------------------- fix B: the network dropped
# Windows reports a dead VPN late: after a Wi-Fi drop RAS said so ~4 s after the Wi-Fi was back, and until then the
# Default Switch VMs left through the ISP. Windows logs the drop itself at once (NetworkProfile
# 10001, the \VeroScudo\NetDown task): the VMs are blocked right then, and stay blocked until the tunnel is proven to carry
# traffic again - a new tunnel (a redial), or a check through it. Windows itself needs none of this: WFP lets it out only
# through the tunnel interface anyway.

function Get-VeroNetSuspect {
    $p = (Get-VeroPath).NetSuspect
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    try { [IO.File]::ReadAllText($p) | ConvertFrom-Json } catch { [pscustomobject]@{ Time = ''; Tunnel = '' } }
}
function Test-VeroNetSuspectFresh($Suspect, [int]$Seconds = 30, [datetime]$Now = (Get-Date)) {
    <# The note of a drop is at most -Seconds old (an unreadable time: not fresh). Pure. #>
    try { $age = ($Now - [datetime]::Parse([string]$Suspect.Time, $null, [Globalization.DateTimeStyles]::RoundtripKind)).TotalSeconds } catch { return $false }
    $age -ge -5 -and $age -le $Seconds
}
function Clear-VeroNetSuspect {
    $p = (Get-VeroPath).NetSuspect
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
}

function Test-VeroDnsVia([System.Net.IPAddress]$Source, [System.Net.IPAddress]$Server, [int]$TimeoutMs = 2000) {
    <# One DNS question (the root's NS) from $Source to $Server: any answer means the path carries traffic. #>
    $u = $null
    try {
        $u = New-Object System.Net.Sockets.UdpClient (New-Object System.Net.IPEndPoint($Source, 0))
        $u.Client.ReceiveTimeout = $TimeoutMs
        [byte[]]$q = 0x56, 0x53, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01
        $null = $u.Send($q, $q.Length, (New-Object System.Net.IPEndPoint($Server, 53)))
        $from = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $r = $u.Receive([ref]$from)
        return ($r.Length -ge 12 -and $r[0] -eq 0x56 -and $r[1] -eq 0x53)
    } catch { return $false } finally { if ($u) { $u.Close() } }
}
function Test-VeroTcpVia([System.Net.IPAddress]$Source, [string]$Remote, [int]$Port, [int]$TimeoutMs = 3000) {
    $c = $null
    try {
        $c = New-Object System.Net.Sockets.TcpClient (New-Object System.Net.IPEndPoint($Source, 0))
        $t = $c.ConnectAsync($Remote, $Port)
        return ($t.Wait($TimeoutMs) -and $c.Connected)
    } catch { return $false } finally { if ($c) { $c.Close() } }
}

function Test-VeroTunnelCarries {
    <# Does the tunnel with this LUID really carry traffic? Sent from the tunnel's own address (so it can only go through
       it): a DNS question to the tunnel's DNS servers, else a TCP connection to 1.1.1.1:443. #>
    [CmdletBinding()] param([Parameter(Mandatory)][uint64]$Luid)
    Import-VeroNative
    $nic = Get-VeroNic | Where-Object { try { [VeroScudo.Iface]::LuidFromGuid([guid]$_.Id) -eq $Luid } catch { $false } } | Select-Object -First 1
    if (-not $nic) { return $false }
    $ipp = $nic.GetIPProperties()
    $src = @($ipp.UnicastAddresses | ForEach-Object { $_.Address } | Where-Object { [string]$_.AddressFamily -eq 'InterNetwork' }) | Select-Object -First 1
    if (-not $src) { return $false }
    foreach ($d in @($ipp.DnsAddresses | Where-Object { [string]$_.AddressFamily -eq 'InterNetwork' })) { if (Test-VeroDnsVia -Source $src -Server $d) { return $true } }
    Test-VeroTcpVia -Source $src -Remote '1.1.1.1' -Port 443
}

function Test-VeroTunnelHoldsDefault {
    <# Does the route to the internet lead into the tunnel? VMs and WSL follow Windows' routing table: with a split-tunnel
       profile everything outside its routes would leave past the tunnel. Unknown (lookup failed): $true - as before. #>
    [CmdletBinding()] param([Parameter(Mandatory)][uint64]$Luid)
    try {
        Import-VeroNative
        $nic = Get-VeroNic | Where-Object { try { [VeroScudo.Iface]::LuidFromGuid([guid]$_.Id) -eq $Luid } catch { $false } } | Select-Object -First 1
        if (-not $nic) { return $true }
        $idx = $nic.GetIPProperties().GetIPv4Properties().Index
        $r = @(Find-NetRoute -RemoteIPAddress '1.1.1.1' -ErrorAction Stop | Where-Object { $_.PSObject.Properties['DestinationPrefix'] }) | Select-Object -First 1
        if (-not $r) { return $true }
        [int]$r.InterfaceIndex -eq [int]$idx
    } catch { $true }
}

$script:WatchLuid = [uint64]0                                                # nothing watched until a sync proves a tunnel

function Get-VeroBestLuid { [VeroScudo.Iface]::BestLuid('1.1.1.1') }     # the interface the internet route uses now (tests replace it)

function Test-VeroRouteLeft {
    <# The watchdog's 1-second look: the tunnel it last saw holding the route to the internet ($script:WatchLuid, set by the
       sync) no longer does - the route leads elsewhere or nowhere. A drop, also while RAS still says "connected" (it says
       so up to ~20 s late). One system call; never for a split tunnel (not watched). #>
    if (-not $script:WatchLuid) { return $false }
    $best = try { [uint64](Get-VeroBestLuid) } catch { return $false }
    $best -ne $script:WatchLuid
}

function Invoke-VeroNetChange {
    <# The watchdog saw the route leave the tunnel, or heard Windows change an address with the tunnel gone: armed and VMs
       protected -> the drop handling now (Invoke-VeroActionNetDown), not ~3 s later when Windows logs "network
       disconnected". Once per drop: an open note of the drop (net-suspect) means it was handled. #>
    [CmdletBinding()] param([string]$Action = 'watchdog')
    if (-not (Test-VeroArmed) -or (Get-VeroNetSuspect)) { return }
    $c = try { Get-VeroConfig } catch { $null }
    if (-not $c -or -not $c.Vm) { return }
    $left = Test-VeroRouteLeft
    if (-not $left) {
        $tun = try { Get-VeroTunnelLuid $c.Profile -Type (Get-VeroConfigType $c) } catch { [uint64]1 }    # unknown: not a drop
        if ($tun) { return }
    }
    $script:WatchLuid = [uint64]0                                            # once: the sync watches again when the tunnel is proven
    Write-VeroLog $(if ($left) { 'the route to the internet left the tunnel - WSL and VMs blocked at once' } else { 'the tunnel is gone (Windows changed an address) - WSL and VMs blocked at once' }) $Action
    Invoke-VeroActionNetDown -Config $c -Action $Action
}

function Invoke-VeroActionNetDown {
    <# \VeroScudo\NetDown (Windows logged "network disconnected"): while armed and VMs are protected, block the Default
       Switch VMs now and remember why - the sync keeps them blocked until the tunnel is proven again. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'netdown')
    if (-not (Test-VeroArmed) -or -not $Config.Vm) { return }
    Invoke-VeroLocked {
        param($c, $a)
        if (-not (Test-VeroArmed)) { return }
        # open connections of WSL and the VMs must not follow the route onto the physical adapter: first, before the firewall
        # calls that take a second, also while RAS still says "connected" (the sync keeps them while this drop is unproven,
        # at most 30 s, or the tunnel is down). A WSL or Default Switch adapter is up: .NET list, ~ms
        if (Get-VeroNic | Where-Object { $_.Name -like 'vEthernet*' -and [string]$_.OperationalStatus -eq 'Up' }) {
            try {
                $th = Get-VeroTypeHandler (Get-VeroConfigType $c); $st = Get-VeroAppliedState
                if ($th.Dials -and -not (& $th.CrlWindow) -and $st -and @($st.Servers).Count) { Sync-VeroBlackhole -Want $true -ServerIps @($st.Servers) -Action $a }
            } catch { Write-VeroLog "ERROR: routes for WSL and VMs: $($_.Exception.Message)" $a }
        }
        $tun = try { Get-VeroTunnelLuid $c.Profile -Type (Get-VeroConfigType $c) } catch { [uint64]0 }
        if (-not (Get-VeroNetSuspect)) { Write-VeroLog 'network disconnected - Hyper-V VMs blocked until the tunnel is proven to work again' $a }
        # WSL first: one switch of its ready block rule (the VMs' port ACLs take seconds); then the VMs; then the note of why
        $wsl = Test-VeroVmWanted -Config $c
        try { if ($wsl) { Lock-VeroWslNow } } catch { Write-VeroLog "ERROR: WSL could not be blocked: $($_.Exception.Message)" $a }
        $null = Set-VeroVmBlock -Block $true -Action $a
        try { if ($wsl) { Set-VeroVmAccess -Allow $false -Action $a } } catch { Write-VeroLog "ERROR: WSL could not be blocked: $($_.Exception.Message)" $a }
        try { Write-VeroStateFile -Path (Get-VeroPath).NetSuspect -Text (@{ Time = (Get-Date).ToString('o'); Tunnel = [string]$tun } | ConvertTo-Json) }
        catch { Write-VeroLog "WARNING: the note of the network drop could not be written ($($_.Exception.Message))" $a }
        $script:AclBlocked = $true
    } -Arguments @($Config, $Action)
}

# --- The internet routed to nowhere while the tunnel is down (WSL and the Default Switch VMs) ---------------------------
# Their traffic is NAT-forwarded by Windows: the host's WFP filters never see it, and the Hyper-V firewall lets a connection
# that was open before the drop go on - it follows the route to the internet onto the physical adapter (tens of seconds
# after a drop). While VeroScudo is on and the tunnel is down, routes on the loopback adapter that are more specific than
# the default route take everything there - except the VPN server (the redial), the networks the adapters are on (LAN,
# WSL's own subnet) and, while the redial's DNS window is open, the network's DNS servers. IPv4 only: that NAT forwards
# IPv4 only. Active store only (a reboot clears them), metric [VeroScudo.Route]::Marker; removed as soon as the tunnel is
# up, and by Off and uninstall.

function ConvertTo-VeroPrefixBits([string]$Text) {
    $ip, $len = $Text.Split('/')
    $a = [System.Net.IPAddress]::Parse($ip)
    $b = $a.GetAddressBytes()
    $max = $b.Length * 8
    $l = if ($null -ne $len) { [int]$len } else { $max }
    if ($l -lt 0 -or $l -gt $max) { throw "bad prefix length: $Text" }
    @{ Bytes = $b; Len = $l; Max = $max }
}

function Get-VeroBlackholePrefix {
    <# The prefixes that cover all of IPv4 and IPv6 (from /1) except the -Exclude prefixes and addresses - the fewest that do:
       each excluded prefix splits the one around it into one piece per bit. Pure. #>
    [CmdletBinding()] param([string[]]$Exclude = @())
    $bit = { param($b, $i) ($b[$i -shr 3] -shr (7 - ($i -band 7))) -band 1 }
    $cut = { param($b, $d, $flip)                                        # the first $d bits of $b, bit $d-1 flipped when $flip
        $o = [byte[]]$b.Clone()
        for ($i = $d; $i -lt $o.Length * 8; $i++) { $o[$i -shr 3] = $o[$i -shr 3] -band (-bnot (1 -shl (7 - ($i -band 7)))) -band 0xFF }
        if ($flip) { $j = $d - 1; $o[$j -shr 3] = $o[$j -shr 3] -bxor (1 -shl (7 - ($j -band 7))) }
        , $o }
    $starts = @{ 4 = @('0.0.0.0/1', '128.0.0.0/1'); 16 = @('::/1', '8000::/1') }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($size in 4, 16) {
        $list = New-Object System.Collections.ArrayList
        foreach ($s in $starts[$size]) { [void]$list.Add((ConvertTo-VeroPrefixBits $s)) }
        foreach ($e in @($Exclude | Where-Object { $_ } | ForEach-Object { ConvertTo-VeroPrefixBits $_ } | Where-Object { $_.Bytes.Length -eq $size })) {
            $next = New-Object System.Collections.ArrayList
            foreach ($p in $list) {
                $n = [Math]::Min($p.Len, $e.Len); $same = $true
                for ($i = 0; $i -lt $n; $i++) { if ((& $bit $p.Bytes $i) -ne (& $bit $e.Bytes $i)) { $same = $false; break } }
                if (-not $same) { [void]$next.Add($p); continue }                   # apart
                if ($e.Len -le $p.Len) { continue }                                  # the piece lies inside the excluded prefix
                for ($d = $p.Len + 1; $d -le $e.Len; $d++) { [void]$next.Add(@{ Bytes = (& $cut $e.Bytes $d $true); Len = $d; Max = $p.Max }) }
            }
            $list = $next
        }
        foreach ($p in $list) { $out.Add(('{0}/{1}' -f ([System.Net.IPAddress]::new([byte[]]$p.Bytes)), $p.Len)) }
    }
    , $out.ToArray()
}

function Get-VeroRouteTable { Import-VeroNative; [VeroScudo.Route]::Read() }
function Add-VeroRoute([uint32]$IfIndex, [string]$Prefix, [int]$Length) { Import-VeroNative; [VeroScudo.Route]::Add($IfIndex, $Prefix, $Length) }
function Remove-VeroRoute([uint32]$IfIndex, [string]$Prefix, [int]$Length) { Import-VeroNative; [VeroScudo.Route]::Delete($IfIndex, $Prefix, $Length) }

function Get-VeroIfIndex([uint64]$Luid) {
    <# The IPv4 interface index of the adapter with this LUID, 0 when there is none. .NET list, ~ms. #>
    Import-VeroNative
    $nic = Get-VeroNic | Where-Object { try { [VeroScudo.Iface]::LuidFromGuid([guid]$_.Id) -eq $Luid } catch { $false } } | Select-Object -First 1
    if (-not $nic) { return [uint32]0 }
    try { [uint32]$nic.GetIPProperties().GetIPv4Properties().Index } catch { [uint32]0 }
}

function Test-VeroTunnelOwnsDefault {
    <# With the routes under the tunnel in place every route check says "the tunnel": then the tunnel's own routes tell a full
       tunnel (0.0.0.0/0, or 0.0.0.0/1 + 128.0.0.0/1) from a split one. -Table: Get-VeroRouteTable lines. #>
    [CmdletBinding()] param([string[]]$Table = @(), [uint32]$TunnelIndex)
    Import-VeroNative                                                       # for the marker metric
    foreach ($line in $Table) {
        $f = $line.Split('|')
        if ($f.Count -lt 4 -or [uint32]$f[0] -ne $TunnelIndex -or [int]$f[3] -eq [VeroScudo.Route]::Marker) { continue }
        if ($f[1] -eq '0.0.0.0/0' -or $f[1] -eq '0.0.0.0/1') { return $true }
    }
    $false
}

function Get-VeroBlackholeExclude {
    <# What must keep its normal route: the VPN server addresses, the -Dns servers (only while the redial's DNS window is
       open), and every network an adapter is on (its on-link routes: the LAN, WSL's subnet; not loopback, nothing wider
       than /4 or /8). -Table: Get-VeroRouteTable lines. Pure. #>
    [CmdletBinding()] param([string[]]$ServerIps = @(), [string[]]$Dns = @(), [string[]]$Table = @(), [uint32[]]$Loopback = @())
    $ex = New-Object System.Collections.Generic.List[string]
    foreach ($a in @($ServerIps) + @($Dns)) { $ip = $null; if ($a -and [System.Net.IPAddress]::TryParse([string]$a, [ref]$ip)) { $ex.Add($ip.ToString()) } }
    foreach ($line in $Table) {
        $f = $line.Split('|')
        if ($f.Count -lt 4 -or [uint32]$f[0] -in $Loopback) { continue }
        if ($f[2] -ne '0.0.0.0' -and $f[2] -ne '::') { continue }             # on-link only
        $len = [int]$f[1].Split('/')[1]
        if ($len -lt $(if ($f[1].Contains(':')) { 8 } else { 4 })) { continue }
        $ex.Add($f[1])
    }
    , @($ex | Select-Object -Unique)
}

function Get-VeroBlackholeRecord {
    $p = (Get-VeroPath).Blackhole
    if (-not (Test-Path -LiteralPath $p)) { return @() }
    try { $j = Get-Content -LiteralPath $p -Raw | ConvertFrom-Json; return @($j | ForEach-Object { [string]$_ }) } catch { return @() }   # $j first: PowerShell 5.1 passes a JSON list on as one object
}

function Sync-VeroBlackhole {
    <# -Want: the routes to nowhere, all but the excluded; otherwise none. Only what changed is asked of Windows; a route
       Windows (or security software) refuses is logged once - WSL is then protected as before (the Hyper-V firewall). #>
    # -TunnelIndex: the tunnel is up - the same routes on the tunnel too (its interface metric is far lower than the loopback
    # adapter's, so they win): the routes to nowhere wait underneath, and when the tunnel goes its routes go with it - a drop
    # finds the way out closed already, nothing has to react first
    [CmdletBinding()] param([Parameter(Mandatory)][bool]$Want, [string[]]$ServerIps = @(), [string[]]$Dns = @(), [uint32]$TunnelIndex = 0, [string]$Action = 'core')
    $have = @(Get-VeroBlackholeRecord)
    if (-not $Want -and $have.Count -eq 0) { return }
    $lo4 = [uint32][System.Net.NetworkInformation.NetworkInterface]::LoopbackInterfaceIndex
    $wantSet = @{}
    if ($Want) {
        $ex = Get-VeroBlackholeExclude -ServerIps $ServerIps -Dns $Dns -Table @(Get-VeroRouteTable) -Loopback @($lo4)
        foreach ($p in (Get-VeroBlackholePrefix -Exclude $ex)) {
            if ($p.Contains(':')) { continue }
            $wantSet["$lo4|$p"] = $true
            if ($TunnelIndex) { $wantSet["$TunnelIndex|$p"] = $true }
        }
    }
    $keep = New-Object System.Collections.Generic.List[string]
    $failed = $null; $changed = $false
    foreach ($r in $have) {
        if ($wantSet.ContainsKey($r)) { $keep.Add($r); continue }
        $f = $r.Split('|'); $pp = $f[1].Split('/')
        $e = Remove-VeroRoute -IfIndex ([uint32]$f[0]) -Prefix $pp[0] -Length ([int]$pp[1])
        # one on a tunnel that is gone went with it (whatever the error says): only the loopback adapter's are kept to retry
        if ($e -ne 0 -and $e -ne 1168 -and [uint32]$f[0] -eq $lo4) { $keep.Add($r); $failed = "removing $($f[1]): error $e" } else { $changed = $true }
    }
    foreach ($k in $wantSet.Keys) {
        if ($keep.Contains($k)) { continue }
        $f = $k.Split('|'); $pp = $f[1].Split('/')
        $e = Add-VeroRoute -IfIndex ([uint32]$f[0]) -Prefix $pp[0] -Length ([int]$pp[1])
        if ($e -eq 0 -or $e -eq 5010) { $keep.Add($k); $changed = $true } elseif (-not $failed) { $failed = "adding $($f[1]): error $e" }
    }
    if ($changed) {
        Write-VeroStateFile -Path (Get-VeroPath).Blackhole -Text (ConvertTo-Json -InputObject @($keep) -Compress)
        Write-VeroLog $(if ($TunnelIndex -and $keep.Count) { "WSL and VMs: routes to nowhere ready under the tunnel - a drop finds the way out closed ($($keep.Count) routes)" }
                        elseif ($keep.Count) { "WSL and VMs: the internet routed to nowhere while the tunnel is down ($($keep.Count) routes; the VPN server and the local networks excepted)" } else { 'routes to nowhere removed - the tunnel is up' }) $Action
    }
    if ($failed -and $script:BlackholeSaid -ne $failed) { Write-VeroLog "WARNING: Windows refused a route for WSL and VMs ($failed) - they stay protected by the Hyper-V firewall only" $Action }
    $script:BlackholeSaid = $failed
}
$script:BlackholeSaid = $null

function Remove-VeroBlackhole {
    <# Off and uninstall: every route VeroScudo recorded, and any other on the loopback adapter with its metric (a record lost in a crash). #>
    [CmdletBinding()] param([string]$Action = 'core')
    Sync-VeroBlackhole -Want $false -Action $Action
    $lo = @([uint32][System.Net.NetworkInformation.NetworkInterface]::LoopbackInterfaceIndex, [uint32][System.Net.NetworkInformation.NetworkInterface]::IPv6LoopbackInterfaceIndex)
    foreach ($line in @(Get-VeroRouteTable)) {
        $f = $line.Split('|')
        if ($f.Count -lt 4 -or [uint32]$f[0] -notin $lo -or [int]$f[3] -ne [VeroScudo.Route]::Marker) { continue }
        if ($f[1] -like '127.*' -or $f[1] -eq '::1/128') { continue }
        $pp = $f[1].Split('/'); $null = Remove-VeroRoute -IfIndex ([uint32]$f[0]) -Prefix $pp[0] -Length ([int]$pp[1])
    }
    $p = (Get-VeroPath).Blackhole
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
}
