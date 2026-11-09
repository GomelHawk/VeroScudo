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
    try { $j = [IO.File]::ReadAllText($p) | ConvertFrom-Json; @($j | ForEach-Object { $_ } | Where-Object { $_ }) } catch { @() }
}
function Save-VeroVmAclState([object[]]$Entries) {
    $p = (Get-VeroPath).VmAcl
    if (@($Entries).Count -eq 0) { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }; return }
    [IO.File]::WriteAllText($p, (ConvertTo-Json -InputObject @($Entries) -Depth 3))
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

function Invoke-VeroActionNetDown {
    <# \VeroScudo\NetDown (Windows logged "network disconnected"): while armed and VMs are protected, block the Default
       Switch VMs now and remember why - the sync keeps them blocked until the tunnel is proven again. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'netdown')
    if (-not (Test-VeroArmed) -or -not $Config.Vm) { return }
    Invoke-VeroLocked {
        param($c, $a)
        if (-not (Test-VeroArmed)) { return }
        $tun = try { Get-VeroTunnelLuid $c.Profile -Type (Get-VeroConfigType $c) } catch { [uint64]0 }
        if (-not (Get-VeroNetSuspect)) { Write-VeroLog 'network disconnected - Hyper-V VMs blocked until the tunnel is proven to work again' $a }
        [IO.File]::WriteAllText((Get-VeroPath).NetSuspect, (@{ Time = (Get-Date).ToString('o'); Tunnel = [string]$tun } | ConvertTo-Json))
        $null = Set-VeroVmBlock -Block $true -Action $a
        $script:AclBlocked = $true
    } -Arguments @($Config, $Action)
}
