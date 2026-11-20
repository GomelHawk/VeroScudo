# Pester 5 unit tests for VeroScudo.Core: the filter set, its sync, the VM / WSL / Hyper-V steps and the server addresses.
# Pure parts directly; WFP / RAS / firewall calls are mocked (Core.TestSetup.ps1).
BeforeAll { . (Join-Path $PSScriptRoot 'Core.TestSetup.ps1') }
AfterAll { Remove-TestDir; Set-VeroHome $null }

Describe 'Get-VeroFilterSpec (the allow-list)' {
    BeforeAll {
        $script:cfg = Get-VeroConfig -Raw $script:cfgJson
        $script:down = Get-VeroFilterSpec -Config $script:cfg -ServerIps @('203.0.113.5') -DnsServers @('192.168.1.1') -TunnelType 'Sstp'
        $script:up = Get-VeroFilterSpec -Config $script:cfg -ServerIps @('203.0.113.5') -TunnelLuid 6473924464345088 -WslLuid 42 -TunnelType 'Sstp'
    }
    It 'ends every one of the four layers with a catch-all block' {
        foreach ($l in [VeroScudo.Layer]::ConnectV4, [VeroScudo.Layer]::ConnectV6, [VeroScudo.Layer]::RecvAcceptV4, [VeroScudo.Layer]::RecvAcceptV6) {
            @($script:down | Where-Object { $_.Layer -eq $l -and -not $_.Permit }).Count | Should -Be 1
        }
    }
    It 'gives the catch-all block the lowest weight and every permit a higher one' {
        foreach ($s in $script:up) { if ($s.Permit) { $s.Weight | Should -BeGreaterThan 0 } else { $s.Weight | Should -Be 0 } }
    }
    It 'scopes every permit to an address, an interface or loopback - a port plus a program is not a scope' {
        foreach ($t in (Get-SpecText ($script:up + $script:down))) {
            $parts = $t -split '\|'
            if ($parts[2] -ne 'permit') { continue }
            $parts[4] | Should -Not -BeNullOrEmpty -Because "permit '$($parts[0])' must have conditions"
            if ($parts[0] -in 'DHCP', 'DHCPv6') { $parts[4] | Should -Match "$($script:F.App)=.*svchost\.exe" -Because 'DHCP: the DHCP client service only'; continue }
            ($parts[4] -match $script:F.Addr -or $parts[4] -match $script:F.If -or $parts[4] -match $script:F.Flags) | Should -BeTrue -Because "permit '$($parts[0])' needs an address, interface or loopback: $($parts[4])"
        }
    }
    It 'opens TCP 80 for the SSTP revocation check only in its short window, and only for SSTP' {
        @(Get-SpecText $script:down | Where-Object { $_ -like 'CRL*' }).Count | Should -Be 0
        @(Get-SpecText (Get-VeroFilterSpec -Config $script:cfg -ServerIps @('203.0.113.5') -DnsServers @('192.168.1.1') -TunnelType 'Sstp' -CrlWindow $true) | Where-Object { $_ -like 'CRL*' }).Count | Should -Be 2
        @(Get-SpecText (Get-VeroFilterSpec -Config $script:cfg -ServerIps @('203.0.113.5') -TunnelType 'Ikev2' -CrlWindow $true) | Where-Object { $_ -like 'CRL*' }).Count | Should -Be 0
        @(Get-SpecText (Get-VeroFilterSpec -Config $script:cfg -ServerIps @('203.0.113.5') -TunnelLuid 9 -TunnelType 'Sstp' -CrlWindow $true) | Where-Object { $_ -like 'CRL*' }).Count | Should -Be 0
    }
    It 'allows the tunnel and WSL only by their interface, and only when known' {
        @(Get-SpecText $script:up | Where-Object { $_ -like 'VPN tunnel|*' -and $_ -like "*$($script:F.If)=luid:6473924464345088*" }).Count | Should -Be 4
        @(Get-SpecText $script:up | Where-Object { $_ -like 'WSL switch|*' }).Count | Should -Be 4
        @(Get-SpecText $script:down | Where-Object { $_ -like 'VPN tunnel|*' -or $_ -like 'WSL switch|*' }).Count | Should -Be 0
    }
    It 'allows the SSTP server only on TCP 443 from svchost to the resolved address' {
        $s = @(Get-SpecText $script:down | Where-Object { $_ -like 'VPN server*' })
        $s.Count | Should -Be 1
        $s[0] | Should -Match "$($script:F.Proto)=6"; $s[0] | Should -Match "$($script:F.RPort)=443"
        $s[0] | Should -Match "$($script:F.Addr)=203\.0\.113\.5"; $s[0] | Should -Match "$($script:F.App)=.*svchost\.exe"
    }
    It 'has no server permit when nothing resolved (never a wildcard)' {
        @(Get-SpecText (Get-VeroFilterSpec -Config $script:cfg -ServerIps @() -TunnelType 'Sstp') | Where-Object { $_ -like 'VPN server*' }).Count | Should -Be 0
    }
    It 'allows DNS only while the tunnel is down - no DNS leak while protected' {
        @(Get-SpecText $script:down | Where-Object { $_ -like 'DNS*' }).Count | Should -BeGreaterThan 0
        @(Get-SpecText $script:up | Where-Object { $_ -like 'DNS*' -or $_ -like 'CRL*' }).Count | Should -Be 0
    }
    It 'restricts DNS to svchost and to the network-provided resolvers' {
        $dns = @(Get-SpecText $script:down | Where-Object { $_ -like 'DNS*' })
        $dns.Count | Should -Be 1                                 # IPv4 resolver only -> no IPv6 DNS permit
        $dns[0] | Should -Match "$($script:F.App)=.*svchost\.exe"; $dns[0] | Should -Match "$($script:F.Addr)=192\.168\.1\.1"; $dns[0] | Should -Match "$($script:F.RPort)=53"
    }
    It 'has no DNS permit at all when no resolver is known (never port 53 to anywhere)' {
        @(Get-SpecText (Get-VeroFilterSpec -Config $script:cfg -ServerIps @('203.0.113.5') -TunnelType 'Sstp') | Where-Object { $_ -like 'DNS*' }).Count | Should -Be 0
    }
    It 'uses the IKEv2 ports for an IKEv2 profile' {
        $s = (Get-SpecText (Get-VeroFilterSpec -Config $script:cfg -ServerIps @('203.0.113.5') -TunnelType 'Ikev2') | Where-Object { $_ -like 'VPN server*' }) -join "`n"
        $s | Should -Match "$($script:F.RPort)=500"; $s | Should -Match "$($script:F.RPort)=4500"; $s | Should -Match "$($script:F.Proto)=50"
        $s | Should -Not -Match "$($script:F.RPort)=443"
    }
    It 'lets the IKEv2 tunnel data through (IP-in-IP to the server)' {
        # Windows shows each packet of an IKEv2 tunnel to the firewall as protocol 4 (41 for IPv6 inside) to the server
        $s = (Get-SpecText (Get-VeroFilterSpec -Config $script:cfg -ServerIps @('203.0.113.5') -TunnelType 'Ikev2') | Where-Object { $_ -like 'VPN server*' }) -join "`n"
        $s | Should -Match "$($script:F.Proto)=4\b"; $s | Should -Match "$($script:F.Proto)=41\b"
        $a = (Get-SpecText (Get-VeroFilterSpec -Config $script:cfg -ServerIps @('203.0.113.5') -TunnelType 'Automatic') | Where-Object { $_ -like 'VPN server*' }) -join "`n"
        $a | Should -Match "$($script:F.Proto)=4\b"
        foreach ($t in 'Sstp', 'L2tp', 'Pptp') {
            $o = (Get-SpecText (Get-VeroFilterSpec -Config $script:cfg -ServerIps @('203.0.113.5') -TunnelType $t) | Where-Object { $_ -like 'VPN server*' }) -join "`n"
            $o | Should -Not -Match "$($script:F.Proto)=4\b"
        }
    }
    It 'puts LAN ranges into their own address family, both directions' {
        $c2 = Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"s","username":"u"},"lanAllow":["192.168.1.0/24","fd00::/64"]}'
        $t = Get-VeroFilterSpec -Config $c2 -ServerIps @('203.0.113.5')
        @($t | Where-Object { $_.Name -eq 'LAN 192.168.1.0/24' -and $_.Layer -in [VeroScudo.Layer]::ConnectV4, [VeroScudo.Layer]::RecvAcceptV4 }).Count | Should -Be 2
        @($t | Where-Object { $_.Name -eq 'LAN fd00::/64' -and $_.Layer -in [VeroScudo.Layer]::ConnectV6, [VeroScudo.Layer]::RecvAcceptV6 }).Count | Should -Be 2
    }
    It 'stays far below the filter-key capacity' { $script:up.Count | Should -BeLessThan ([VeroScudo.Wfp]::MaxFilters / 4) }
    It 'is deterministic (same input -> same fingerprint)' {
        $a = Get-SpecText (Get-VeroFilterSpec -Config $script:cfg -ServerIps @('203.0.113.5') -TunnelType 'Sstp')
        $b = Get-SpecText (Get-VeroFilterSpec -Config $script:cfg -ServerIps @('203.0.113.5') -TunnelType 'Sstp')
        ($a -join "`n") | Should -Be ($b -join "`n")
    }
}

Describe 'Get-VeroFilterSpec: the Hyper-V Default Switch (its VMs get DHCP and DNS from Windows)' {
    BeforeAll {
        $script:cfgF = Get-VeroConfig -Raw $script:cfgJson
        $script:fDown = Get-VeroFilterSpec -Config $script:cfgF -ServerIps @('203.0.113.5') -SwitchLuid 77 -TunnelType 'Sstp'
        $script:fUp = Get-VeroFilterSpec -Config $script:cfgF -ServerIps @('203.0.113.5') -TunnelLuid 6473924464345088 -SwitchLuid 77 -TunnelType 'Sstp'
    }
    It 'opens the Default Switch adapter only while the tunnel is up, by its interface' {
        @(Get-SpecText $script:fDown | Where-Object { $_ -like 'Default Switch*' }).Count | Should -Be 0
        $d = @(Get-SpecText $script:fUp | Where-Object { $_ -like 'Default Switch*' })
        $d.Count | Should -Be 4
        foreach ($t in $d) { $t | Should -BeLike "*$($script:F.If)=luid:77*" }
    }
    It 'adds no other layer: forwarded VM traffic is not something WFP sees here' {
        $layers = @([VeroScudo.Layer]::ConnectV4, [VeroScudo.Layer]::ConnectV6, [VeroScudo.Layer]::RecvAcceptV4, [VeroScudo.Layer]::RecvAcceptV6)
        foreach ($x in $script:fUp) { $layers | Should -Contain $x.Layer }
    }
}

Describe 'Hyper-V Default Switch VMs: port ACLs while blocked (62-HyperVAcl.ps1, a fake Hyper-V ACL store)' {
    BeforeAll {
        $script:vmA = [pscustomobject]@{ VMName = 'VeroTest-Ubuntu'; Id = 'Microsoft:A\1'; SwitchName = 'Default Switch' }
        $script:vmB = [pscustomobject]@{ VMName = 'Bridged'; Id = 'Microsoft:B\1'; SwitchName = 'External' }
    }
    BeforeEach {
        # what the virtual switch holds: like real Hyper-V, a host address is stored without its /32
        $script:store = New-Object System.Collections.ArrayList
        Mock -ModuleName VeroScudo.Core Test-VeroHyperVTools { $true }
        Mock -ModuleName VeroScudo.Core Get-VeroSwitchSubnet { '172.20.144.0/20' }
        Mock -ModuleName VeroScudo.Core Get-VeroAllVmAdapter { $script:vmA; $script:vmB }
        Mock -ModuleName VeroScudo.Core Get-VeroVmAdapterAcl { @($script:store | Where-Object { $_.AdapterId -eq $Adapter.Id }) }
        Mock -ModuleName VeroScudo.Core Add-VeroVmAdapterAcl { [void]$script:store.Add([pscustomobject]@{ AdapterId = $Adapter.Id; RemoteAddress = ($Remote -replace '/32$', ''); Action = $Action; Direction = 'Outbound' }) }
        Mock -ModuleName VeroScudo.Core Remove-VeroVmAdapterAcl {
            $hit = @($script:store | Where-Object { $_.AdapterId -eq $Adapter.Id -and $_.RemoteAddress -eq $Remote -and $_.Action -eq $Action })
            foreach ($h in $hit) { $script:store.Remove($h) }                 # an address in another form matches nothing - like Hyper-V
        }
    }
    AfterEach { Remove-TestFile @((Get-VeroPath).VmAcl) }
    It 'computes the switch network from the host address' {
        ConvertTo-VeroNetworkPrefix -Address '172.20.152.1' -PrefixLength 20 | Should -Be '172.20.144.0/20'
        ConvertTo-VeroNetworkPrefix -Address '192.168.137.1' -PrefixLength 24 | Should -Be '192.168.137.0/24'
    }
    It 'denies everything first and opens only the switch, broadcast and IPv6 link-local/multicast' {
        $r = @(Get-VeroVmAclRule -Subnet '172.20.144.0/20')
        $r[0].Remote | Should -Be '0.0.0.0/0'; $r[0].Action | Should -Be 'Deny'
        @($r | Where-Object Action -eq 'Deny' | ForEach-Object Remote) | Should -Be @('0.0.0.0/0', '::/0')
        @($r | Where-Object Action -eq 'Allow' | ForEach-Object Remote) | Sort-Object | Should -Be (@('172.20.144.0/20', '255.255.255.255', 'fe80::/10', 'ff00::/8') | Sort-Object)
    }
    It 'blocks every VM on the Default Switch, none elsewhere, and records what it added' {
        Set-VeroVmBlock -Block $true | Should -Be 1
        @($script:store | Where-Object AdapterId -eq 'Microsoft:A\1').Count | Should -Be 6
        @($script:store | Where-Object AdapterId -eq 'Microsoft:B\1').Count | Should -Be 0
        $j = Get-Content (Get-VeroPath).VmAcl -Raw | ConvertFrom-Json; @($j | ForEach-Object { $_ }).Count | Should -Be 6
    }
    It 'adds nothing twice (it runs every sync while blocked)' {
        Set-VeroVmBlock -Block $true | Out-Null
        Set-VeroVmBlock -Block $true | Out-Null
        $script:store.Count | Should -Be 6
    }
    It 'unblocking removes every rule it added - also the broadcast one Hyper-V stores without /32' {
        Set-VeroVmBlock -Block $true | Out-Null
        Set-VeroVmBlock -Block $false | Out-Null
        $script:store.Count | Should -Be 0
        Test-Path (Get-VeroPath).VmAcl | Should -BeFalse
    }
    It 'a rule the user set is neither recorded nor removed' {
        [void]$script:store.Add([pscustomobject]@{ AdapterId = 'Microsoft:A\1'; RemoteAddress = '0.0.0.0/0'; Action = 'Deny'; Direction = 'Outbound' })
        Set-VeroVmBlock -Block $true | Out-Null
        $script:store.Count | Should -Be 6                                  # 5 added + the user's own
        Set-VeroVmBlock -Block $false | Out-Null
        @($script:store | ForEach-Object RemoteAddress) | Should -Be @('0.0.0.0/0')
    }
    It 'keeps what it could not remove, to retry' {
        Set-VeroVmBlock -Block $true | Out-Null
        Mock -ModuleName VeroScudo.Core Remove-VeroVmAdapterAcl { throw 'busy' } -ParameterFilter { $Remote -eq '::/0' }
        Set-VeroVmBlock -Block $false | Out-Null
        $j = Get-Content (Get-VeroPath).VmAcl -Raw | ConvertFrom-Json; @($j | ForEach-Object { $_.Remote }) | Should -Be @('::/0')
    }
    It 'without the Hyper-V tools it changes nothing' {
        Mock -ModuleName VeroScudo.Core Test-VeroHyperVTools { $false }
        Set-VeroVmBlock -Block $true | Should -Be 0
        $script:store.Count | Should -Be 0
    }
}

Describe 'fix B: the network dropped - Hyper-V VMs stay blocked until the tunnel is proven (mocked)' {
    BeforeAll {
        $script:cfgB = Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"vpn.example.com","username":"u"},"vm":true}'
        $script:cfgBoff = Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"vpn.example.com","username":"u"},"vm":false}'
        Mock -ModuleName VeroScudo.Core Resolve-VeroServerIp { '203.0.113.5' }
        Mock -ModuleName VeroScudo.Core Get-VeroDnsServer { @('192.168.1.1') }
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelType { 'Sstp' }
        Mock -ModuleName VeroScudo.Core Set-VeroWfpFilter { }
        Mock -ModuleName VeroScudo.Core Get-VeroWfpCount { 0 }
        Mock -ModuleName VeroScudo.Core Remove-VeroLegacyFirewall { }
        Mock -ModuleName VeroScudo.Core Test-VeroVmWanted { $false }            # WSL: not this test's subject
    }
    BeforeEach {
        Mock -ModuleName VeroScudo.Core Set-VeroVmBlock { 1 }
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelLuid { [uint64]555 }
        Mock -ModuleName VeroScudo.Core Test-VeroTunnelCarries { $false }
        Mock -ModuleName VeroScudo.Core Test-VeroArmed { $true }
        Remove-TestFile @((Get-VeroPath).NetSuspect, (Get-VeroPath).WfpState)
    }
    AfterAll { Remove-TestFile @((Get-VeroPath).NetSuspect, (Get-VeroPath).WfpState) }
    It 'netdown blocks the VMs at once and remembers the tunnel it saw' {
        Invoke-VeroAction -Action netdown -Config $script:cfgB
        Should -Invoke -ModuleName VeroScudo.Core Set-VeroVmBlock -Times 1 -Exactly -ParameterFilter { $Block -eq $true }
        (Get-Content (Get-VeroPath).NetSuspect -Raw | ConvertFrom-Json).Tunnel | Should -Be '555'
    }
    It 'netdown does nothing while off, or when VMs are not protected' {
        Mock -ModuleName VeroScudo.Core Test-VeroArmed { $false }
        Invoke-VeroAction -Action netdown -Config $script:cfgB
        Mock -ModuleName VeroScudo.Core Test-VeroArmed { $true }
        Invoke-VeroAction -Action netdown -Config $script:cfgBoff
        Should -Invoke -ModuleName VeroScudo.Core Set-VeroVmBlock -Times 0 -Exactly
        Test-Path (Get-VeroPath).NetSuspect | Should -BeFalse
    }
    It 'the same tunnel that does not carry traffic (RAS has not noticed yet): VMs stay blocked' {
        Invoke-VeroAction -Action netdown -Config $script:cfgB
        Sync-VeroKillSwitch -Config $script:cfgB -Action test -NoRefresh
        Should -Invoke -ModuleName VeroScudo.Core Set-VeroVmBlock -Times 0 -Exactly -ParameterFilter { $Block -eq $false }
        Test-Path (Get-VeroPath).NetSuspect | Should -BeTrue
    }
    It 'the tunnel carries traffic again: VMs back through it' {
        Invoke-VeroAction -Action netdown -Config $script:cfgB
        Mock -ModuleName VeroScudo.Core Test-VeroTunnelCarries { $true }
        Sync-VeroKillSwitch -Config $script:cfgB -Action test -NoRefresh
        Should -Invoke -ModuleName VeroScudo.Core Set-VeroVmBlock -Times 1 -Exactly -ParameterFilter { $Block -eq $false }
        Test-Path (Get-VeroPath).NetSuspect | Should -BeFalse
    }
    It 'a split-tunnel profile: VMs stay blocked although the tunnel is up and carries traffic' {
        Mock -ModuleName VeroScudo.Core Test-VeroTunnelHoldsDefault { $false }
        Sync-VeroKillSwitch -Config $script:cfgB -Action test -NoRefresh
        Should -Invoke -ModuleName VeroScudo.Core Set-VeroVmBlock -Times 0 -Exactly -ParameterFilter { $Block -eq $false }
        Should -Invoke -ModuleName VeroScudo.Core Set-VeroVmBlock -ParameterFilter { $Block -eq $true }
    }
    It 'a new tunnel (a redial) counts as proven without a check' {
        Invoke-VeroAction -Action netdown -Config $script:cfgB
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelLuid { [uint64]777 }
        Sync-VeroKillSwitch -Config $script:cfgB -Action test -NoRefresh
        Should -Invoke -ModuleName VeroScudo.Core Test-VeroTunnelCarries -Times 0 -Exactly
        Test-Path (Get-VeroPath).NetSuspect | Should -BeFalse
    }
    It 'Off clears it' {
        Invoke-VeroAction -Action netdown -Config $script:cfgB
        Mock -ModuleName VeroScudo.Core Test-VeroArmed { $false }
        Disable-VeroKillSwitch -Action test
        Test-Path (Get-VeroPath).NetSuspect | Should -BeFalse
    }
}

Describe 'native layout' {
    It 'marshals FWPM_FILTER0 exactly like the x64 headers' {
        [VeroScudo.Native]::Layout() | Should -Be 'filter=200 cond=40 value=16 sublayer=72 provider=64 | layerKey=64 weight=96 num=112 action=128 context=152 filterId=176 eff=184'
    }
    It 'derives distinct, stable filter keys' {
        [VeroScudo.Wfp]::FilterKey(0) | Should -Not -Be ([VeroScudo.Wfp]::FilterKey(1))
        [VeroScudo.Wfp]::FilterKey(5) | Should -Be ([VeroScudo.Wfp]::FilterKey(5))
    }
}

Describe 'Sync-VeroKillSwitch (mocked WFP)' {
    AfterAll { Set-VeroArmed $false 'test' }
    BeforeAll {
        Set-VeroArmed $true 'test'                                           # filters are only ever applied to an armed machine
        $script:cfgS = Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"vpn.example.com","username":"u"},"vm":false}'
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelLuid { [uint64]0 }
        Mock -ModuleName VeroScudo.Core Resolve-VeroServerIp { '203.0.113.5' }        # ONE address -> a plain string, not an array
        Mock -ModuleName VeroScudo.Core Get-VeroDnsServer { @('192.168.1.1') }
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelType { 'Sstp' }
        Mock -ModuleName VeroScudo.Core Set-VeroWfpFilter { }
        Mock -ModuleName VeroScudo.Core Remove-VeroLegacyFirewall { }
    }
    BeforeEach { Remove-TestFile (Get-VeroPath).WfpState, (Get-VeroPath).Emergency }
    It 'applies the filter set when nothing is applied yet' {
        Mock -ModuleName VeroScudo.Core Get-VeroWfpCount { 0 }
        Sync-VeroKillSwitch -Config $script:cfgS -Action test
        Should -Invoke -ModuleName VeroScudo.Core Set-VeroWfpFilter -Times 1 -Exactly
        (Get-Content (Get-VeroPath).WfpState -Raw | ConvertFrom-Json).Count | Should -BeGreaterThan 0
    }
    It 'does nothing when the same set is already in force' {
        Mock -ModuleName VeroScudo.Core Get-VeroWfpCount { 0 }
        Sync-VeroKillSwitch -Config $script:cfgS -Action test
        $n = (Get-Content (Get-VeroPath).WfpState -Raw | ConvertFrom-Json).Count
        Mock -ModuleName VeroScudo.Core Get-VeroWfpCount { $n }.GetNewClosure()
        Sync-VeroKillSwitch -Config $script:cfgS -Action test
        Should -Invoke -ModuleName VeroScudo.Core Set-VeroWfpFilter -Times 1 -Exactly
    }
    It 're-applies when filters went missing' {
        Mock -ModuleName VeroScudo.Core Get-VeroWfpCount { 0 }
        Sync-VeroKillSwitch -Config $script:cfgS -Action test
        Sync-VeroKillSwitch -Config $script:cfgS -Action test
        Should -Invoke -ModuleName VeroScudo.Core Set-VeroWfpFilter -Times 2 -Exactly
    }
    It 're-applies when the tunnel interface changes (new LUID after a reconnect or reboot)' {
        Mock -ModuleName VeroScudo.Core Get-VeroWfpCount { 0 }
        Sync-VeroKillSwitch -Config $script:cfgS -Action test
        $n = (Get-Content (Get-VeroPath).WfpState -Raw | ConvertFrom-Json).Count
        Mock -ModuleName VeroScudo.Core Get-VeroWfpCount { $n }.GetNewClosure()
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelLuid { [uint64]123 }
        Sync-VeroKillSwitch -Config $script:cfgS -Action test
        Should -Invoke -ModuleName VeroScudo.Core Set-VeroWfpFilter -Times 2 -Exactly
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelLuid { [uint64]0 }
    }
    It 'fails closed: a WFP error turns on the firewall emergency block and is rethrown' {
        Mock -ModuleName VeroScudo.Core Get-VeroWfpCount { 0 }
        Mock -ModuleName VeroScudo.Core Set-VeroWfpFilter { throw 'BFE down' }
        Mock -ModuleName VeroScudo.Core Get-NetFirewallProfile { @([pscustomobject]@{ Name = 'Public'; DefaultOutboundAction = 'NotConfigured' }) }
        Mock -ModuleName VeroScudo.Core Set-NetFirewallProfile { }
        { Sync-VeroKillSwitch -Config $script:cfgS -Action test } | Should -Throw '*BFE down*'
        Should -Invoke -ModuleName VeroScudo.Core Set-NetFirewallProfile -Times 1 -Exactly -ParameterFilter { $DefaultOutboundAction -eq 'Block' }
        Test-Path (Get-VeroPath).Emergency | Should -BeTrue
        Mock -ModuleName VeroScudo.Core Set-VeroWfpFilter { }
        Remove-TestFile (Get-VeroPath).Emergency, (Get-VeroPath).FwBackup        # no leftover state for the next block
    }
}

Describe 'Sync-VeroKillSwitch never waits for DNS before applying' {
    AfterAll { Set-VeroArmed $false 'test' }
    BeforeAll {
        Set-VeroArmed $true 'test'                                           # filters are only ever applied to an armed machine
        $script:cfgD = Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"vpn.example.com","username":"u"},"vm":false}'
        Mock -ModuleName VeroScudo.Core Get-VeroDnsServer { @() }
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelType { 'Sstp' }
        Mock -ModuleName VeroScudo.Core Get-VeroWfpCount { 0 }
        $script:order = New-Object System.Collections.ArrayList
        Mock -ModuleName VeroScudo.Core Set-VeroWfpFilter { [void]$script:order.Add('apply') }
        Mock -ModuleName VeroScudo.Core Resolve-VeroServerIp { [void]$script:order.Add($(if ($CacheOnly) { 'cache' } else { 'lookup' })); '203.0.113.5' }
    }
    BeforeEach { $script:order.Clear(); Remove-TestFile (Get-VeroPath).WfpState, (Get-VeroPath).Emergency, (Get-VeroPath).FwBackup }
    It 'tunnel down: applies from the cache and does not look the name up at all' {
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelLuid { [uint64]0 }
        Sync-VeroKillSwitch -Config $script:cfgD -Action test
        @($script:order) | Should -Be @('cache', 'apply')
    }
    It 'tunnel down with no DNS server known yet (link coming up) still applies' {
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelLuid { [uint64]0 }
        Mock -ModuleName VeroScudo.Core Get-VeroDnsServer { }
        { Sync-VeroKillSwitch -Config $script:cfgD -Action test } | Should -Not -Throw
        @($script:order) | Should -Contain 'apply'
    }
    It 'tunnel up: applies first, looks the name up afterwards' {
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelLuid { [uint64]77 }
        Sync-VeroKillSwitch -Config $script:cfgD -Action test
        @($script:order) | Should -Be @('cache', 'apply', 'lookup')
    }
}

Describe 'Remove-VeroLegacyFirewall (1.0 migration)' {
    It 'restores the default outbound action BEFORE removing the old allow rules (else the VPN connection is cut)' {
        $script:steps = New-Object System.Collections.ArrayList
        '[{"Name":"Public","DefaultOutboundAction":0}]' | Set-Content (Get-VeroPath).FwBackup
        Mock -ModuleName VeroScudo.Core Set-NetFirewallProfile { [void]$script:steps.Add("default:$DefaultOutboundAction") }
        Mock -ModuleName VeroScudo.Core Get-NetFirewallRule { @([pscustomobject]@{ Name = 'old' }) }
        Mock -ModuleName VeroScudo.Core Remove-NetFirewallRule { [void]$script:steps.Add("remove-rules:$Group") }
        Remove-VeroLegacyFirewall -Action test
        @($script:steps) | Should -Be @('default:NotConfigured', 'remove-rules:VeroScudo')
    }
}

Describe 'Disable-VeroKillSwitch vs a parallel re-arm' {
    AfterEach { Set-VeroArmed $false 'test' }
    It 'keeps the filters when the machine was armed again before the removal ran' {
        Set-VeroArmed $true 'test'
        Disable-VeroKillSwitch -Action test
        Should -Invoke -ModuleName VeroScudo.Core Clear-VeroWfpFilter -Times 0 -Exactly
    }
    It 'removes the filters when disarmed' {
        Disable-VeroKillSwitch -Action test
        Should -Invoke -ModuleName VeroScudo.Core Clear-VeroWfpFilter -Times 1 -Exactly
    }
}

Describe 'WSL at a drop: a ready block rule, switched on first (mocked Hyper-V firewall)' {
    BeforeAll {
        # the fake Hyper-V firewall's table: one test-only global (a mock body sees its parameters only in its own scope, so
        # no closure), emptied between tests, removed after this block
        $global:VeroTestHv = @{ Rules = @{}; Steps = (New-Object System.Collections.ArrayList) }
        Mock -ModuleName VeroScudo.Core Test-VeroHyperVFirewall { $true }
        Mock -ModuleName VeroScudo.Core Get-NetFirewallHyperVVMSetting { [pscustomobject]@{ DefaultOutboundAction = 'Block' } }
        Mock -ModuleName VeroScudo.Core Get-NetFirewallHyperVRule { if ($Name -and $global:VeroTestHv.Rules.ContainsKey([string]$Name)) { [pscustomobject]@{ Name = [string]$Name; Enabled = $global:VeroTestHv.Rules[[string]$Name] } } }
        Mock -ModuleName VeroScudo.Core Set-NetFirewallHyperVRule { [void]$global:VeroTestHv.Steps.Add("$Name=$Enabled"); $global:VeroTestHv.Rules[[string]$Name] = [string]$Enabled }
        Mock -ModuleName VeroScudo.Core New-NetFirewallHyperVRule { [void]$global:VeroTestHv.Steps.Add("new $Name $Action=$Enabled"); $global:VeroTestHv.Rules[[string]$Name] = [string]$Enabled }
        Mock -ModuleName VeroScudo.Core Remove-NetFirewallHyperVRule { [void]$global:VeroTestHv.Steps.Add("remove $Name") }
    }
    BeforeEach {
        $global:VeroTestHv.Steps.Clear(); $global:VeroTestHv.Rules.Clear()
        $global:VeroTestHv.Rules['VeroScudo-WSL'] = 'True'; $global:VeroTestHv.Rules['VeroScudo-WSL-Block'] = 'False'
        '{"DefaultOutboundAction":"NotConfigured"}' | Set-Content (Get-VeroPath).VmBackup
    }
    AfterAll { Remove-TestFile (Get-VeroPath).VmBackup; Remove-Variable -Name VeroTestHv -Scope Global -ErrorAction SilentlyContinue }
    It 'blocking: the block rule goes on BEFORE the allow rule goes off' {
        Set-VeroVmAccess -Allow $false -Action test
        @($global:VeroTestHv.Steps) | Should -Be @('VeroScudo-WSL-Block=True', 'VeroScudo-WSL=False')
    }
    It 'blocking again (every watchdog pass): nothing is switched' {
        $global:VeroTestHv.Rules['VeroScudo-WSL-Block'] = 'True'; $global:VeroTestHv.Rules['VeroScudo-WSL'] = 'False'
        Set-VeroVmAccess -Allow $false -Action test
        $global:VeroTestHv.Steps.Count | Should -Be 0
    }
    It 'allowing: the allow rule goes on BEFORE the block rule goes off; the block rule stays ready' {
        $global:VeroTestHv.Rules['VeroScudo-WSL-Block'] = 'True'; $global:VeroTestHv.Rules['VeroScudo-WSL'] = 'False'
        Set-VeroVmAccess -Allow $true -Action test
        @($global:VeroTestHv.Steps) | Should -Be @('VeroScudo-WSL=True', 'VeroScudo-WSL-Block=False')
    }
    It 'allowing on a machine without the block rule yet: it is created, switched off' {
        $global:VeroTestHv.Rules.Remove('VeroScudo-WSL-Block')
        Set-VeroVmAccess -Allow $true -Action test
        @($global:VeroTestHv.Steps) | Should -Contain 'new VeroScudo-WSL-Block Block=False'
    }
    It 'Off: the block rule is removed first, whatever happens to the rest (WSL never stays blocked while off)' {
        Mock -ModuleName VeroScudo.Core Set-NetFirewallHyperVVMSetting { throw 'access denied' }
        Restore-VeroVmAccess
        @($global:VeroTestHv.Steps)[0] | Should -Be 'remove VeroScudo-WSL-Block'
    }
    It 'the drop handling switches WSL off before it touches the VMs' {
        $script:order = New-Object System.Collections.ArrayList
        Mock -ModuleName VeroScudo.Core Lock-VeroWslNow { [void]$script:order.Add('wsl') }
        Mock -ModuleName VeroScudo.Core Set-VeroVmBlock { [void]$script:order.Add('vms'); 1 }
        Mock -ModuleName VeroScudo.Core Set-VeroVmAccess { }
        Mock -ModuleName VeroScudo.Core Test-VeroVmWanted { $true }
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelLuid { [uint64]0 }
        $c = Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"vpn.example.com","username":"u"},"vm":true}'
        Set-VeroArmed $true 'test'
        try { & (Get-Module VeroScudo.Core) { Invoke-VeroActionNetDown -Config $args[0] -Action test } $c }
        finally { Set-VeroArmed $false 'test'; Remove-TestFile (Get-VeroPath).NetSuspect }
        @($script:order) | Should -Be @('wsl', 'vms')
    }
}

Describe 'Invoke-VeroNetChange (the watchdog heard an address change)' {
    BeforeEach {
        Mock -ModuleName VeroScudo.Core Invoke-VeroActionNetDown { }
        Mock -ModuleName VeroScudo.Core Get-VeroConfig { Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"vpn.example.com","username":"u"},"vm":true}' } -ParameterFilter { -not $Raw }
        Mock -ModuleName VeroScudo.Core Get-VeroNetSuspect { $null }
        Mock -ModuleName VeroScudo.Core Test-VeroArmed { $true }
    }
    It 'the tunnel is gone: the drop handling runs at once' {
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelLuid { [uint64]0 }
        Invoke-VeroNetChange -Action test
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroActionNetDown -Times 1 -Exactly
    }
    It 'the route left the tunnel while RAS still says connected: the drop handling runs at once, and once' {
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelLuid { [uint64]77 }
        Mock -ModuleName VeroScudo.Core Get-VeroBestLuid { [uint64]5 }                 # the route goes to the Wi-Fi now
        InModuleScope VeroScudo.Core { $script:WatchLuid = [uint64]77 }
        Test-VeroRouteLeft | Should -BeTrue
        Invoke-VeroNetChange -Action test
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroActionNetDown -Times 1 -Exactly
        Test-VeroRouteLeft | Should -BeFalse                                            # not watched until the sync proves it again
    }
    It 'a split tunnel (never watched) is not a drop' {
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelLuid { [uint64]77 }
        Mock -ModuleName VeroScudo.Core Get-VeroBestLuid { [uint64]5 }
        InModuleScope VeroScudo.Core { $script:WatchLuid = [uint64]0 }
        Invoke-VeroNetChange -Action test
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroActionNetDown -Times 0 -Exactly
    }
    It 'the tunnel is still there (another address changed): nothing' {
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelLuid { [uint64]77 }
        Mock -ModuleName VeroScudo.Core Get-VeroBestLuid { [uint64]77 }
        InModuleScope VeroScudo.Core { $script:WatchLuid = [uint64]77 }
        Invoke-VeroNetChange -Action test
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroActionNetDown -Times 0 -Exactly
    }
    It 'off, or the drop already handled: nothing' {
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelLuid { [uint64]0 }
        Mock -ModuleName VeroScudo.Core Get-VeroNetSuspect { [pscustomobject]@{ Time = 'x'; Tunnel = '77' } }
        Invoke-VeroNetChange -Action test
        Mock -ModuleName VeroScudo.Core Get-VeroNetSuspect { $null }
        Mock -ModuleName VeroScudo.Core Test-VeroArmed { $false }
        Invoke-VeroNetChange -Action test
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroActionNetDown -Times 0 -Exactly
    }
}

Describe 'WSL setting restore' {
    It 'never restores VeroScudo''s own Block as the "original" (WSL would stay offline while off)' {
        '{"DefaultOutboundAction":"Block"}' | Set-Content (Get-VeroPath).VmBackup
        Restore-VeroVmAccess
        Should -Invoke -ModuleName VeroScudo.Core Set-NetFirewallHyperVVMSetting -Times 1 -Exactly -ParameterFilter { $DefaultOutboundAction -eq 'NotConfigured' }
        Test-Path (Get-VeroPath).VmBackup | Should -BeFalse
    }
    It 'keeps the backup when the restore fails, so it is retried' {
        '{"DefaultOutboundAction":"Allow"}' | Set-Content (Get-VeroPath).VmBackup
        Mock -ModuleName VeroScudo.Core Set-NetFirewallHyperVVMSetting { throw 'access denied' }
        Restore-VeroVmAccess
        Test-Path (Get-VeroPath).VmBackup | Should -BeTrue
        Remove-TestFile (Get-VeroPath).VmBackup
    }
}

Describe 'CRL window from the RasDial result only; a 631 by connection id; no Hyper-V cmdlets without Hyper-V' {
    It 'a forged 20227 in the Application log cannot open the CRL window (only the RasDial result decides)' {
        Set-VeroHome $script:TestHomeDir -UserDir (Join-Path $script:TestHomeDir 'user')
        Remove-TestFile (Get-VeroPath).CrlWindow
        Mock -ModuleName VeroScudo.Core Get-VeroRasCode { -2146885613 }
        Mock -ModuleName VeroScudo.Core Get-VeroCredential { $null }
        Mock -ModuleName VeroScudo.Core Sync-VeroKillSwitch { }
        InModuleScope VeroScudo.Core { $script:Rasdial = 'Write-Output' }        # a dial that does nothing, on any OS
        try { Invoke-VeroDial -Config (Get-VeroConfig -Raw '{"vpn":{"profile":"Work","server":"s","username":"u"}}') -Action test } catch { Write-Verbose 'no rasdial here' }
        Test-VeroCrlWindow | Should -BeFalse
        Should -Invoke -ModuleName VeroScudo.Core Get-VeroRasCode -Times 0 -Exactly
        InModuleScope VeroScudo.Core { $script:Rasdial = (Get-VeroSystemDir System) + '\rasdial.exe' }
        Set-VeroHome $script:TestHomeDir
    }
    It 'accepts a 631 for the recorded OR the newest System-log connection id' {
        Mock -ModuleName VeroScudo.Core Get-VeroRasConnectedRecord { [pscustomobject]@{ Profile = 'Work'; CoId = 'SECOND' } }
        @{ Profile = 'Work'; CoId = 'FIRST' } | ConvertTo-Json | Set-Content (Get-VeroPath).RasCoId
        $ids = @(Get-VeroExpectedCoId -ProfileName 'Work')
        $ids | Should -Contain 'FIRST'; $ids | Should -Contain 'SECOND'
        Remove-TestFile (Get-VeroPath).RasCoId
    }
    It 'never calls a Hyper-V firewall cmdlet on a Windows without it (Off and Status keep working)' {
        InModuleScope VeroScudo.Core { $script:HyperVFw = $false }
        Mock -ModuleName VeroScudo.Core Get-NetFirewallHyperVRule { throw 'not on this Windows' }
        Mock -ModuleName VeroScudo.Core Set-NetFirewallHyperVVMSetting { throw 'not on this Windows' }
        { Restore-VeroVmAccess } | Should -Not -Throw
        { Set-VeroVmAccess -Allow $true -Action test } | Should -Not -Throw
        InModuleScope VeroScudo.Core { $script:HyperVFw = $null }
    }
}

Describe 'a VPN server that moved: fresh lookup before arming and after a failed redial' {
    BeforeAll { $script:cfgM = Get-VeroConfig -Raw '{"profiles":[{"profile":"CorporateVPN","server":"vpn.corp.example.com","username":"u"}]}' }
    AfterEach { Set-VeroArmed $false 'test'; Remove-TestFile (Get-VeroPath).Lock }
    It 'looks the server up before arming (no filters yet), not only from the cache' {
        Mock -ModuleName VeroScudo.Core Resolve-VeroServerIp { if ($CacheOnly) { '203.0.113.10' } else { '203.0.113.20', '203.0.113.10' } }
        Update-VeroServerIpBeforeArm -Config $script:cfgM -Action test
        Should -Invoke -ModuleName VeroScudo.Core Resolve-VeroServerIp -ParameterFilter { -not $CacheOnly } -Times 1 -Exactly
    }
    It 'does not look up while already armed (the filters are in force)' {
        Set-VeroArmed $true 'test'
        Mock -ModuleName VeroScudo.Core Resolve-VeroServerIp { '203.0.113.10' }
        Update-VeroServerIpBeforeArm -Config $script:cfgM -Action test
        Should -Invoke -ModuleName VeroScudo.Core Resolve-VeroServerIp -Times 0 -Exactly
    }
    It 'redialing: a new address is looked up right before the dial and allowed for it' {
        Set-VeroArmed $true 'test'
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $false }
        Mock -ModuleName VeroScudo.Core Invoke-VeroDial { }
        Mock -ModuleName VeroScudo.Core Get-VeroDialFailure { 'RAS -2147014883' }
        Mock -ModuleName VeroScudo.Core Sync-VeroKillSwitch { }
        Mock -ModuleName VeroScudo.Core Test-VeroAuthBlocked { $false }
        Mock -ModuleName VeroScudo.Core Resolve-VeroServerIp { if ($CacheOnly) { '203.0.113.10' } else { '203.0.113.20', '203.0.113.10' } }
        $cm = $script:cfgM
        Mock -ModuleName VeroScudo.Core Get-VeroConfig { $cm }.GetNewClosure()
        Mock -ModuleName VeroScudo.Core Start-Sleep { Set-VeroArmed $false 'test' }
        Mock -ModuleName VeroScudo.Core Start-VeroDnsLookup { [System.Threading.Tasks.Task]::FromResult([System.Net.IPAddress[]]@([System.Net.IPAddress]::Parse('203.0.113.20'))) }
        Invoke-VeroReconnect -Config $script:cfgM -Action test
        # the attempt's sync and the re-sync with the new address - answered from the cache, DNS never opened - before the dial
        Should -Invoke -ModuleName VeroScudo.Core Sync-VeroKillSwitch -Times 2 -Exactly
        Should -Invoke -ModuleName VeroScudo.Core Resolve-VeroServerIp -ParameterFilter { -not $CacheOnly } -Times 1 -Exactly
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroDial -Times 1 -Exactly
    }
}

Describe 'Resolve-VeroServerIp cache returns plain strings' {
    It 'returns plain strings, so wfp.json and the status list the addresses themselves' {
        $f = Join-Path $TestDrive 'server.ip'
        Set-Content -Path $f -Value '203.0.113.10', '203.0.113.20'
        $c = Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"vpn.example.com","username":"u"}}'
        Mock -ModuleName VeroScudo.Core Get-VeroPath { [pscustomobject]@{ ServerIp = $f } }
        $r = @(Resolve-VeroServerIp -Config $c -CacheOnly)
        $r | Should -Be @('203.0.113.10', '203.0.113.20')
        (ConvertTo-Json -InputObject $r -Compress) | Should -Be '["203.0.113.10","203.0.113.20"]'
    }
}

Describe 'Select-VeroForeignWfp (other apps kill-switch layers)' {
    BeforeAll {
        $script:prov = @('WireGuard', 'Microsoft Windows WFP Built-in TCP Templates provider.', 'OpenVPN')
        $script:subs = @('65535|WireGuard filters', '65535|OpenVPN', '4096|Some low layer')
    }
    It 'warns about every VPN layer while a Windows VPN profile is active' {
        $r = @(Select-VeroForeignWfp -Type 'ras' -Providers $script:prov -SubLayers $script:subs)
        @($r | Where-Object { $_ -match 'WireGuard' }).Count | Should -Be 2
        @($r | Where-Object { $_ -match 'OpenVPN' }).Count | Should -Be 2
        @($r | Where-Object { $_ -match 'Built-in|low layer' }).Count | Should -Be 0
    }
    It "does not flag the active WireGuard profile's own layer (it would stay in Attention all the time)" {
        $r = @(Select-VeroForeignWfp -Type 'wireguard' -Providers $script:prov -SubLayers $script:subs)
        @($r | Where-Object { $_ -match 'WireGuard' }).Count | Should -Be 0
        @($r | Where-Object { $_ -match 'OpenVPN' }).Count | Should -Be 2
    }
    It "does not flag the active OpenVPN profile's own layer" {
        $r = @(Select-VeroForeignWfp -Type 'openvpn' -Providers $script:prov -SubLayers $script:subs)
        @($r | Where-Object { $_ -match 'OpenVPN' }).Count | Should -Be 0
        @($r | Where-Object { $_ -match 'WireGuard' }).Count | Should -Be 2
    }
}

Describe 'Get-VeroFilterSpec: the permit kind is explicit' {
    BeforeAll { $script:cfgK = Get-VeroConfig -Raw '{"profiles":[{"profile":"wg","type":"wireguard","server":"wg.example.com","port":51820}]}' }
    It 'endpoints kind: no server-port permits even with addresses given; server kind: no endpoint permits' {
        $t = Get-SpecText (Get-VeroFilterSpec -Config $script:cfgK -ServerIps @('203.0.113.5') -Endpoints @() -PermitKind 'endpoints')
        @($t | Where-Object { $_ -like 'VPN server*' }).Count | Should -Be 0
        $eps = @([pscustomobject]@{ Ip = '203.0.113.5'; Proto = 17; Port = 51820 })
        $t = Get-SpecText (Get-VeroFilterSpec -Config $script:cfgK -Endpoints $eps -PermitKind 'server')
        @($t | Where-Object { $_ -like 'VPN server proto*' }).Count | Should -Be 0
    }
    It 'without the kind, $null endpoints mean server and a list means endpoints (older callers)' {
        $eps = @([pscustomobject]@{ Ip = '203.0.113.5'; Proto = 17; Port = 51820 })
        @((Get-SpecText (Get-VeroFilterSpec -Config $script:cfgK -Endpoints $eps)) | Where-Object { $_ -like 'VPN server proto 17*' }).Count | Should -BeGreaterThan 0
        { Get-VeroFilterSpec -Config $script:cfgK -PermitKind 'both' } | Should -Throw
    }
    It 'the permits the handlers build carry their kind' {
        (Get-VeroTypeHandler 'ras').ServerPermit | Should -Not -BeNullOrEmpty
        Mock -ModuleName VeroScudo.Core Resolve-VeroServerIp { @('203.0.113.5') }
        Mock -ModuleName VeroScudo.Core Resolve-VeroEndpoint { @([pscustomobject]@{ Ip = '203.0.113.6'; Proto = 17; Port = 51820 }) }
        (& (Get-Module VeroScudo.Core) { param($c) Get-VeroRasServerPermit -Config $c } (Get-VeroConfig -Raw $script:cfgJson)).Kind | Should -Be 'server'
        (& (Get-Module VeroScudo.Core) { param($c) Get-VeroEndpointPermit -Config $c } $script:cfgK).Kind | Should -Be 'endpoints'
    }
}

Describe 'Get-VeroStatusServer: what the profile names -> what the filters allow' {
    It 'reads both the 1.2 object form and the 1.3 string form of wfp.json' {
        $cfg = Get-VeroConfig -Raw $script:cfgJson
        Get-VeroStatusServer -Config $cfg -Applied ([pscustomobject]@{ Servers = @('203.0.113.5', '203.0.113.6') }) | Should -Be 'vpn.example.com -> 203.0.113.5, 203.0.113.6'
        Get-VeroStatusServer -Config $cfg -Applied ([pscustomobject]@{ Servers = @([pscustomobject]@{ value = '203.0.113.7' }) }) | Should -Be 'vpn.example.com -> 203.0.113.7'
    }
}

Describe 'Server addresses: never a fake-DNS answer or loopback' {
    It 'is the same rule as usable_server_ip on Linux/macOS' {
        foreach ($bad in '198.18.0.81', '198.19.255.1', 'fc00::44', '127.0.0.1', '::1', '0.0.0.0', 'fe80::1', '224.0.0.1', 'x') { Test-VeroUsableServerIp $bad | Should -BeFalse -Because $bad }
        foreach ($good in '203.0.113.5', '185.72.199.130', '10.0.0.5', '192.168.1.10', '2001:db8::1', 'fd00::5') { Test-VeroUsableServerIp $good | Should -BeTrue -Because $good }
    }
}

Describe 'an armed machine is never left without a filter' {
    It 'falls back to the emergency block when the filters cannot even be worked out' {
        Mock -ModuleName VeroScudo.Core Get-VeroSyncPlan { throw 'adapter list unreadable' }
        Mock -ModuleName VeroScudo.Core Get-VeroWfpCount { 0 }
        Mock -ModuleName VeroScudo.Core Enable-VeroEmergencyBlock { }
        $cfg = Get-VeroConfig -Raw $script:cfgJson
        Set-VeroArmed $true 'test'
        { & (Get-Module VeroScudo.Core) { param($c) Sync-VeroKillSwitchCore -Config $c -Action test } $cfg } | Should -Throw '*adapter list unreadable*'
        Should -Invoke -ModuleName VeroScudo.Core Enable-VeroEmergencyBlock -Times 1 -Exactly
        Set-VeroArmed $false 'test'
    }
    It 'applies nothing at all to a machine that is not armed (Off landed since the caller looked)' {
        Mock -ModuleName VeroScudo.Core Get-VeroSyncPlan { throw 'must not be asked' }
        Mock -ModuleName VeroScudo.Core Set-VeroWfpFilter { }
        $cfg = Get-VeroConfig -Raw $script:cfgJson
        Set-VeroArmed $false 'test'
        & (Get-Module VeroScudo.Core) { param($c) Sync-VeroKillSwitchCore -Config $c -Action test } $cfg | Should -BeFalse
        Should -Invoke -ModuleName VeroScudo.Core Set-VeroWfpFilter -Times 0 -Exactly
    }
    It 'arms although the lookup before it fails' {
        Mock -ModuleName VeroScudo.Core Update-VeroServerIpBeforeArm { throw 'file in use' }
        Mock -ModuleName VeroScudo.Core Sync-VeroKillSwitch { }
        $cfg = Get-VeroConfig -Raw $script:cfgJson
        & (Get-Module VeroScudo.Core) { param($c) Enter-VeroArmed -Config $c -Action test } $cfg
        Test-VeroArmed | Should -BeTrue
        Should -Invoke -ModuleName VeroScudo.Core Sync-VeroKillSwitch -Times 1 -Exactly
        Set-VeroArmed $false 'test'
    }
    It 'a log file that cannot be rotated or written stops nothing' {
        $log = (Get-VeroPath).Log
        $fs = [IO.File]::Open($log, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try { { Write-VeroLog 'held' 'test' } | Should -Not -Throw } finally { $fs.Dispose() }
    }
}

Describe 'ConvertTo-VeroRuleAddress: the last check before a filter' {
    It 'passes <v>' -ForEach @(@{ v = '203.0.113.5' }, @{ v = '2001:db8::1' }, @{ v = 'fe80::1' }) { & (Get-Module VeroScudo.Core) { param($x) ConvertTo-VeroRuleAddress $x } $v | Should -Be $v }
    It 'passes the range <v> only when a range is asked for' -ForEach @(@{ v = '192.168.1.0/24' }, @{ v = 'fd00::/16' }) {
        & (Get-Module VeroScudo.Core) { param($x) ConvertTo-VeroRuleAddress $x -Range } $v | Should -Be $v
        { & (Get-Module VeroScudo.Core) { param($x) ConvertTo-VeroRuleAddress $x } $v } | Should -Throw
    }
    It 'refuses <v>' -ForEach @(@{ v = '1' }, @{ v = '10.1' }, @{ v = 'fe80::1%5' }, @{ v = "203.0.113.5`n" }, @{ v = 'vpn.example.com' }, @{ v = '' }, @{ v = '0x7f.1' }) {
        { & (Get-Module VeroScudo.Core) { param($x) ConvertTo-VeroRuleAddress $x } $v } | Should -Throw
    }
}

Describe 'a sync that fails never leaves the VMs and WSL as they happened to be' {
    BeforeAll {
        $script:cfgF = Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"vpn.example.com","username":"u"},"vm":true}'
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelLuid { [uint64]0 }
        Mock -ModuleName VeroScudo.Core Resolve-VeroServerIp { @('203.0.113.5') }
        Mock -ModuleName VeroScudo.Core Get-VeroDnsServer { @() }
        Mock -ModuleName VeroScudo.Core Get-VeroWslLuid { [uint64]0 }
        Mock -ModuleName VeroScudo.Core Set-VeroVmBlock { 0 }
        Mock -ModuleName VeroScudo.Core Set-VeroVmAccess { }
        Mock -ModuleName VeroScudo.Core Test-VeroVmWanted { $true }
        Mock -ModuleName VeroScudo.Core Enable-VeroEmergencyBlock { }
    }
    BeforeEach { Set-VeroArmed $true 'test' }
    AfterEach { Set-VeroArmed $false 'test'; Remove-TestFile (Get-VeroPath).WfpState }
    It 'when the filters cannot be applied: emergency block, and the VMs and WSL blocked' {
        Mock -ModuleName VeroScudo.Core Set-VeroWfpFilter { throw 'BFE down' }
        Mock -ModuleName VeroScudo.Core Get-VeroWfpCount { 0 }
        { & (Get-Module VeroScudo.Core) { param($c) Sync-VeroKillSwitchCore -Config $c -Action test } $script:cfgF } | Should -Throw '*BFE down*'
        Should -Invoke -ModuleName VeroScudo.Core Enable-VeroEmergencyBlock -Times 1 -Exactly
        Should -Invoke -ModuleName VeroScudo.Core Set-VeroVmBlock -Times 1 -Exactly -ParameterFilter { $Block -eq $true }
        Should -Invoke -ModuleName VeroScudo.Core Set-VeroVmAccess -Times 1 -Exactly -ParameterFilter { $Allow -eq $false }
    }
    It 'with filters still in force: they stay, no emergency block, the VMs and WSL blocked all the same' {
        Mock -ModuleName VeroScudo.Core Get-VeroSyncPlan { throw 'adapter list unreadable' }
        Mock -ModuleName VeroScudo.Core Get-VeroWfpCount { 12 }
        { & (Get-Module VeroScudo.Core) { param($c) Sync-VeroKillSwitchCore -Config $c -Action test } $script:cfgF } | Should -Throw
        Should -Invoke -ModuleName VeroScudo.Core Enable-VeroEmergencyBlock -Times 0 -Exactly
        Should -Invoke -ModuleName VeroScudo.Core Set-VeroVmBlock -Times 1 -Exactly -ParameterFilter { $Block -eq $true }
        Should -Invoke -ModuleName VeroScudo.Core Set-VeroVmAccess -Times 1 -Exactly -ParameterFilter { $Allow -eq $false }
    }
    It 'one step that fails does not stop the next, and the note of the applied filters goes' {
        Mock -ModuleName VeroScudo.Core Get-VeroWfpCount { 12 }
        Mock -ModuleName VeroScudo.Core Set-VeroVmBlock { throw 'no Hyper-V' }
        Set-Content -Path (Get-VeroPath).WfpState -Value '{}'
        { & (Get-Module VeroScudo.Core) { param($c) Set-VeroFailClosed -Config $c -Action test -Why 'x' } $script:cfgF } | Should -Not -Throw
        Should -Invoke -ModuleName VeroScudo.Core Set-VeroVmAccess -Times 1 -Exactly
        Test-Path (Get-VeroPath).WfpState | Should -BeFalse
    }
    It 'does nothing on a machine that is not armed' {
        Set-VeroArmed $false 'test'
        & (Get-Module VeroScudo.Core) { param($c) Set-VeroFailClosed -Config $c -Action test -Why 'x' } $script:cfgF
        Should -Invoke -ModuleName VeroScudo.Core Set-VeroVmBlock -Times 0 -Exactly
    }
}

Describe 'the emergency block is always lifted again' {
    It 'also when the firewall''s old settings could not be noted: back to the default, and the flag goes' {
        Mock -ModuleName VeroScudo.Core Get-NetFirewallRule { }
        $p = Get-VeroPath
        Remove-TestFile $p.FwBackup
        Set-Content -Path $p.Emergency -Value ''
        & (Get-Module VeroScudo.Core) { Remove-VeroLegacyFirewall -Action test }
        Should -Invoke -ModuleName VeroScudo.Core Set-NetFirewallProfile -Times 1 -Exactly -ParameterFilter { $All -and [string]$DefaultOutboundAction -eq 'NotConfigured' }
        Test-Path $p.Emergency | Should -BeFalse
    }
    It 'a block that cannot note the old settings is set all the same' {
        Mock -ModuleName VeroScudo.Core Write-VeroStateFile { throw 'file in use' }
        $p = Get-VeroPath
        Remove-TestFile $p.FwBackup, $p.Emergency
        & (Get-Module VeroScudo.Core) { Enable-VeroEmergencyBlock -Action test }
        Should -Invoke -ModuleName VeroScudo.Core Set-NetFirewallProfile -Times 1 -Exactly -ParameterFilter { [string]$DefaultOutboundAction -eq 'Block' }
        Test-Path $p.Emergency | Should -BeTrue
        Remove-TestFile $p.Emergency
    }
    It 'the block in force is never noted as the firewall''s old settings' {
        Mock -ModuleName VeroScudo.Core Write-VeroStateFile { }
        $p = Get-VeroPath
        Remove-TestFile $p.FwBackup
        Set-Content -Path $p.Emergency -Value ''
        & (Get-Module VeroScudo.Core) { Enable-VeroEmergencyBlock -Action test }
        Should -Invoke -ModuleName VeroScudo.Core Write-VeroStateFile -Times 0 -Exactly
        Remove-TestFile $p.Emergency
    }
    It 'a block set with neither its flag nor the note is remembered, not noted later, and lifted' {
        Mock -ModuleName VeroScudo.Core Get-NetFirewallRule { }
        Mock -ModuleName VeroScudo.Core Write-VeroStateFile { throw 'file in use' }
        Mock -ModuleName VeroScudo.Core New-Item { throw 'no room' }
        $p = Get-VeroPath
        Remove-TestFile $p.FwBackup, $p.Emergency
        & (Get-Module VeroScudo.Core) { Enable-VeroEmergencyBlock -Action test }
        & (Get-Module VeroScudo.Core) { $script:EmergencyUnnoted } | Should -BeTrue
        & (Get-Module VeroScudo.Core) { Enable-VeroEmergencyBlock -Action test }
        Should -Invoke -ModuleName VeroScudo.Core Write-VeroStateFile -Times 1 -Exactly          # the first call only
        & (Get-Module VeroScudo.Core) { Remove-VeroLegacyFirewall -Action test }
        Should -Invoke -ModuleName VeroScudo.Core Set-NetFirewallProfile -Times 1 -Exactly -ParameterFilter { $All -and [string]$DefaultOutboundAction -eq 'NotConfigured' }
        & (Get-Module VeroScudo.Core) { $script:EmergencyUnnoted } | Should -BeFalse
    }
}

Describe 'the resolvers allowed while blocked' {
    It 'are plain addresses only: one the filters would refuse is left out instead of stopping the whole filter set' {
        $nic = [pscustomobject]@{ Name = 'Ethernet'; Description = 'Example Ethernet'; NetworkInterfaceType = 'Ethernet'; OperationalStatus = 'Up'; Id = [guid]::NewGuid().ToString() }
        $nic | Add-Member -MemberType ScriptMethod -Name GetIPProperties -Value {
            [pscustomobject]@{ DnsAddresses = @('192.168.1.1', '::ffff:192.0.2.53', 'fe80::1%12', 'fec0:0:0:ffff::1', '192.168.1.1', '2001:db8::53') | ForEach-Object { [ipaddress]$_ } } }
        $script:dnsNic = $nic
        Mock -ModuleName VeroScudo.Core Get-VeroNic { $script:dnsNic }
        $got = & (Get-Module VeroScudo.Core) { Get-VeroDnsServer -ProfileName 'X' }
        $got | Should -Be @('192.168.1.1', '2001:db8::53', 'fe80::1')
    }
}

Describe 'the machine''s variables for a program the guard starts' {
    It 'are read as stored: a %NAME% in a value is not filled in from this process''s environment' {
        $m = & (Get-Module VeroScudo.Core) { Get-VeroMachineVariable }
        $m | Should -BeOfType [hashtable]
        [string]$m['windir'] | Should -Be '%SystemRoot%'
    }
}

Describe 'the VPN server''s ports are for Windows itself, not for any program' {
    BeforeAll { $script:cfgP = Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"vpn.example.com","username":"u"}}'; $script:sys = 'af043a0a=SYSTEM+ADMINS' }
    It '<type>: every server permit with a port is limited to Local System or an elevated administrator (or to svchost for SSTP); port-less protocols are by address' -ForEach @(
        @{ type = 'Ikev2' }, @{ type = 'L2tp' }, @{ type = 'Pptp' }, @{ type = 'Automatic' }, @{ type = 'Sstp' }
    ) {
        $srv = @(Get-SpecText (Get-VeroFilterSpec -Config $script:cfgP -ServerIps @('203.0.113.5', '2001:db8::5') -TunnelType $type) | Where-Object { $_ -like 'VPN server proto*' })
        $srv.Count | Should -BeGreaterThan 0
        foreach ($line in $srv) {
            $hasPort = $line -match ($script:F.RPort + '=')
            $scoped = ($line -match [regex]::Escape($script:sys)) -or ($line -match ($script:F.App + '='))
            if ($hasPort) { $scoped | Should -BeTrue -Because $line } else { $line | Should -Not -Match ([regex]::Escape($script:sys)) }
        }
    }
    It 'IKEv2: UDP 500 and 4500 to the server, for Local System and elevated administrators only' {
        $srv = @(Get-SpecText (Get-VeroFilterSpec -Config $script:cfgP -ServerIps @('203.0.113.5') -TunnelType 'Ikev2') | Where-Object { $_ -like 'VPN server proto 17*' })
        $srv.Count | Should -Be 1
        $srv[0] | Should -Match ($script:F.RPort + '=500'); $srv[0] | Should -Match ($script:F.RPort + '=4500'); $srv[0] | Should -Match ([regex]::Escape($script:sys))
    }
    It 'Windows accepts every filter shape the guard builds (asked inside a transaction that is rolled back; needs administrator rights)' {
        if (-not (Test-VeroElevated)) { Set-ItResult -Skipped -Because 'not elevated: WFP takes no question from a standard process (CI runs this)'; return }
        $before = [VeroScudo.Wfp]::Count()
        foreach ($type in 'Sstp', 'Ikev2', 'L2tp', 'Pptp', 'Automatic') {
            $specs = Get-VeroFilterSpec -Config $script:cfgP -ServerIps @('203.0.113.5', '2001:db8::5') -DnsServers @('192.168.1.1') -TunnelType $type
            { [VeroScudo.Wfp]::Validate([VeroScudo.FilterSpec[]]@($specs)) } | Should -Not -Throw -Because $type
        }
        [VeroScudo.Wfp]::Count() | Should -Be $before                         # nothing was left behind
    }
}

Describe 'DNS while blocked: only the redial''s own lookup of the server, right before each dial (mocked)' {
    AfterAll { Set-VeroArmed $false 'test' }
    BeforeAll {
        Set-VeroArmed $true 'test'
        $script:cfgN = Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"vpn.example.com","username":"u"},"vm":false}'
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelLuid { [uint64]0 }
        Mock -ModuleName VeroScudo.Core Resolve-VeroServerIp { '203.0.113.5' }
        Mock -ModuleName VeroScudo.Core Get-VeroDnsServer { @('192.168.1.1') }
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelType { 'Sstp' }
    }
    AfterEach { InModuleScope VeroScudo.Core { $script:DnsWindow = $false; $script:DnsFresh = @{} } }
    It 'blocked: no DNS permit for a type VeroScudo dials' {
        $plan = & (Get-Module VeroScudo.Core) { Get-VeroSyncPlan -Config $args[0] -Action test } $script:cfgN
        @(Get-SpecText $plan.Specs | Where-Object { $_ -like 'DNS*' }).Count | Should -Be 0
    }
    It 'blocked, inside the redial''s DNS window: the DNS client may ask the network''s resolvers' {
        InModuleScope VeroScudo.Core { $script:DnsWindow = $true }
        $plan = & (Get-Module VeroScudo.Core) { Get-VeroSyncPlan -Config $args[0] -Action test } $script:cfgN
        @(Get-SpecText $plan.Specs | Where-Object { $_ -like 'DNS (redial)*' }).Count | Should -BeGreaterThan 0
    }
    It 'the names a dial looks up: the server''s name, none for an address or pinned addresses' {
        Get-VeroDialName -Config $script:cfgN | Should -Be 'vpn.example.com'
        @(Get-VeroDialName -Config (Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"203.0.113.5","username":"u"}}')).Count | Should -Be 0
        @(Get-VeroDialName -Config (Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"vpn.example.com","username":"u","serverIps":["203.0.113.5"]}}')).Count | Should -Be 0
    }
    It 'no answer from the cache: opens DNS for the lookup and closes it before the dial - also when no answer comes in time' {
        $script:seen = New-Object System.Collections.ArrayList
        Mock -ModuleName VeroScudo.Core Sync-VeroKillSwitch { [void]$script:seen.Add("sync window=$(& (Get-Module VeroScudo.Core) { $script:DnsWindow })") }
        Mock -ModuleName VeroScudo.Core Start-VeroDnsLookup { [void]$script:seen.Add('lookup'); (New-Object System.Threading.Tasks.TaskCompletionSource[System.Net.IPAddress[]]).Task }   # never answers
        InModuleScope VeroScudo.Core { $script:DnsFirstSeconds = 1 }
        Invoke-VeroDnsFirst -Config $script:cfgN -Action test
        InModuleScope VeroScudo.Core { $script:DnsFirstSeconds = 3 }
        @($script:seen) | Should -Be @('lookup', 'sync window=True', 'lookup', 'sync window=False')   # the cache first, DNS closed
        InModuleScope VeroScudo.Core { $script:DnsWindow } | Should -BeFalse
    }
    It 'an answer goes into the cache without a second lookup, and the new address is allowed for the dial' {
        $script:seen = New-Object System.Collections.ArrayList
        Mock -ModuleName VeroScudo.Core Sync-VeroKillSwitch { [void]$script:seen.Add('sync') }
        Mock -ModuleName VeroScudo.Core Start-VeroDnsLookup { [System.Threading.Tasks.Task]::FromResult([System.Net.IPAddress[]]@([System.Net.IPAddress]::Parse('203.0.113.77'))) }
        Mock -ModuleName VeroScudo.Core Resolve-VeroServerIp { [void]$script:seen.Add("resolve " + ((& (Get-Module VeroScudo.Core) { Get-VeroHostAddress 'vpn.example.com' }) -join ',')) }
        Invoke-VeroDnsFirst -Config $script:cfgN -Action test
        @($script:seen) | Should -Be @('resolve 203.0.113.77', 'sync')          # answered from the cache: DNS never opened
    }
}


Describe 'the VPN server''s name answered locally while the tunnel is down (NRPT + local DNS answer, mocked)' {
    BeforeAll {
        $script:cfgL = Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"vpn.example.com","username":"u"},"vm":false}'
        function New-Query([string]$n, [int]$t) {
            $b = New-Object System.Collections.Generic.List[byte]; $b.AddRange([byte[]](0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            foreach ($l in $n.Split('.')) { $b.Add([byte]$l.Length); $b.AddRange([Text.Encoding]::ASCII.GetBytes($l)) }
            $b.AddRange([byte[]](0, 0, $t, 0, 1)); , $b.ToArray()
        }
        $script:map = New-Object 'System.Collections.Generic.Dictionary[string,string[]]' ([StringComparer]::OrdinalIgnoreCase)
        $script:map['vpn.example.com'] = [string[]]@('203.0.113.5', '2001:db8::5')
    }
    BeforeEach {
        $global:VeroTestNrpt = New-Object System.Collections.ArrayList
        Mock -ModuleName VeroScudo.Core Add-DnsClientNrptRule { [void]$global:VeroTestNrpt.Add("add $Namespace -> $NameServers"); [pscustomobject]@{ Name = '{guid-1}' } }
        Mock -ModuleName VeroScudo.Core Remove-DnsClientNrptRule { [void]$global:VeroTestNrpt.Add("remove $Name") }
        Mock -ModuleName VeroScudo.Core Resolve-VeroServerIp { '203.0.113.5' } -ParameterFilter { $CacheOnly }
        Mock -ModuleName VeroScudo.Core Get-VeroLocalDnsAddress { '127.0.0.53' }
        Mock -ModuleName VeroScudo.Core Test-VeroArmed { $true }
        Remove-TestFile (Get-VeroPath).Nrpt
    }
    AfterAll { Remove-TestFile (Get-VeroPath).Nrpt, (Get-VeroPath).LocalDns; Remove-Variable -Name VeroTestNrpt -Scope Global -ErrorAction SilentlyContinue }
    It 'the local answer: A and AAAA of the server''s name (any case), REFUSED for every other name, nothing for garbage' {
        $r = [VeroScudo.LocalDns]::Answer((New-Query 'VPN.Example.com' 1), $script:map)
        ($r[3] -band 15) | Should -Be 0; $r[7] | Should -Be 1; ($r[-4..-1] -join '.') | Should -Be '203.0.113.5'
        ([VeroScudo.LocalDns]::Answer((New-Query 'vpn.example.com' 28), $script:map))[7] | Should -Be 1
        $o = [VeroScudo.LocalDns]::Answer((New-Query 'news.example.org' 1), $script:map); ($o[3] -band 15) | Should -Be 5; $o[7] | Should -Be 0
        [VeroScudo.LocalDns]::Answer([byte[]](1, 2, 3), $script:map) | Should -BeNullOrEmpty
        [VeroScudo.LocalDns]::Start([string[]]@('203.0.113.9')) | Should -BeFalse              # never anything but loopback
    }
    It 'the answer map: the server''s name with its cached addresses; none for a server given as an address' {
        $m = Get-VeroDnsAnswerMap -Config $script:cfgL
        @($m.Keys) | Should -Be @('vpn.example.com'); @($m['vpn.example.com']) | Should -Be @('203.0.113.5')
        (Get-VeroDnsAnswerMap -Config (Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"203.0.113.5","username":"u"}}')).Count | Should -Be 0
    }
    It 'tunnel down: one rule for the server''s name -> the local answer, recorded; the next pass asks Windows nothing' {
        Sync-VeroNrpt -Config $script:cfgL -TunnelLuid 0 -Action test
        @($global:VeroTestNrpt) | Should -Be @('add vpn.example.com -> 127.0.0.53')
        $global:VeroTestNrpt.Clear()
        Sync-VeroNrpt -Config $script:cfgL -TunnelLuid 0 -Action test
        $global:VeroTestNrpt.Count | Should -Be 0
    }
    It 'tunnel up: the recorded rule goes (lookups through the tunnel keep the addresses fresh)' {
        Sync-VeroNrpt -Config $script:cfgL -TunnelLuid 0 -Action test
        $global:VeroTestNrpt.Clear()
        Sync-VeroNrpt -Config $script:cfgL -TunnelLuid 77 -Action test
        @($global:VeroTestNrpt) | Should -Be @('remove {guid-1}')
        Test-Path (Get-VeroPath).Nrpt | Should -BeTrue
        @(& (Get-Module VeroScudo.Core) { Get-VeroNrptRecord }).Count | Should -Be 0
    }
    It 'no local answer running (watchdog down): no rule - the redial falls back to its DNS window' {
        Mock -ModuleName VeroScudo.Core Get-VeroLocalDnsAddress { $null }
        Sync-VeroNrpt -Config $script:cfgL -TunnelLuid 0 -Action test
        $global:VeroTestNrpt.Count | Should -Be 0
    }
    It 'a rule Windows refuses (security software): said once, not recorded' {
        Mock -ModuleName VeroScudo.Core Add-DnsClientNrptRule { throw 'access denied' }
        Mock -ModuleName VeroScudo.Core Write-VeroLog { }
        Sync-VeroNrpt -Config $script:cfgL -TunnelLuid 0 -Action test
        Sync-VeroNrpt -Config $script:cfgL -TunnelLuid 0 -Action test
        Should -Invoke -ModuleName VeroScudo.Core Write-VeroLog -Times 1 -Exactly -ParameterFilter { $Message -like 'WARNING: Windows refused the NRPT rule*' }
        Test-Path (Get-VeroPath).Nrpt | Should -BeFalse
    }
    It 'Off: the recorded rule and any rule with VeroScudo''s comment are removed, the record goes' {
        Sync-VeroNrpt -Config $script:cfgL -TunnelLuid 0 -Action test
        Mock -ModuleName VeroScudo.Core Get-DnsClientNrptRule { @([pscustomobject]@{ Name = '{orphan}'; Comment = 'VeroScudo: the VPN server while the tunnel is down' }, [pscustomobject]@{ Name = '{users-own}'; Comment = 'something else' }) }
        $global:VeroTestNrpt.Clear()
        Remove-VeroNrpt -Action test
        @($global:VeroTestNrpt) | Should -Be @('remove {guid-1}', 'remove {orphan}')                  # never the user's own rule
        Test-Path (Get-VeroPath).Nrpt | Should -BeFalse
    }
}

Describe 'the note that the local DNS answer runs' {
    It 'the note that the local answer runs counts for 60 s only' {
        $p = (Get-VeroPath).LocalDns
        @{ Address = '127.0.0.53'; Time = (Get-Date).ToString('o') } | ConvertTo-Json | Set-Content $p
        & (Get-Module VeroScudo.Core) { Get-VeroLocalDnsAddress } | Should -Be '127.0.0.53'
        @{ Address = '127.0.0.53'; Time = (Get-Date).AddMinutes(-5).ToString('o') } | ConvertTo-Json | Set-Content $p
        & (Get-Module VeroScudo.Core) { Get-VeroLocalDnsAddress } | Should -BeNullOrEmpty
        @{ Address = '10.0.0.1'; Time = (Get-Date).ToString('o') } | ConvertTo-Json | Set-Content $p
        & (Get-Module VeroScudo.Core) { Get-VeroLocalDnsAddress } | Should -BeNullOrEmpty         # never a non-loopback address
    }
}
