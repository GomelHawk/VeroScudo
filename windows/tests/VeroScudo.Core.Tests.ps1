# Pester 5 unit tests for VeroScudo.Core.psm1. Pure parts directly; WFP / RAS / firewall calls are mocked.
BeforeAll {
    # an installed copy loaded in the same session (e.g. after running VeroScudo.ps1 there) makes Pester's mocks ambiguous:
    # unload every copy from this session (memory only - no files are touched), then load the one under test
    Get-Module VeroScudo.Core | Remove-Module -Force
    Import-Module (Join-Path $PSScriptRoot '..\VeroScudo.Core.psm1') -Force
    # SAFETY: everything these tests write or delete must live in a fresh temp folder. A failed setup once left the
    # cleanup pointing at the user's profile (`$script:Home` is `$HOME`), so: never a name that can collide with an
    # automatic variable, refuse to run unless the module's home really is that folder, delete only through Remove-TestDir.
    $script:TestHomeDir = Join-Path ([IO.Path]::GetTempPath()) ("veroscudo-test-" + [guid]::NewGuid())
    function Test-IsTestDir([string]$Path) {
        if (-not $Path -or -not $script:TestHomeDir) { return $false }
        $sep = [IO.Path]::DirectorySeparatorChar                            # '\' on Windows (CI); '/' only in a WSL dev harness
        $full = [IO.Path]::GetFullPath($Path).TrimEnd($sep)
        $root = [IO.Path]::GetFullPath($script:TestHomeDir).TrimEnd($sep)
        ($root -like ([IO.Path]::GetTempPath().TrimEnd($sep) + $sep + 'veroscudo-test-*')) -and ($full -eq $root -or $full.StartsWith($root + $sep, [StringComparison]::OrdinalIgnoreCase))
    }
    function Remove-TestDir { if (Test-IsTestDir $script:TestHomeDir) { Remove-Item -LiteralPath $script:TestHomeDir -Recurse -Force -ErrorAction SilentlyContinue } }
    function Remove-TestFile([string[]]$Paths) { foreach ($f in $Paths) { if (Test-IsTestDir $f) { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue } else { throw "test tried to delete outside its temp folder: $f" } } }
    Set-VeroHome $script:TestHomeDir
    if (-not (Test-IsTestDir (Get-VeroPath).Home)) { throw "SAFETY: module home is '$((Get-VeroPath).Home)', not the test folder - refusing to run" }
    New-Item -ItemType Directory -Path (Get-VeroPath).State -Force | Out-Null
    $script:cfgJson = '{"vpn":{"profile":"MyVPN","server":"vpn.example.com","port":443,"username":"jdoe"},"retrySeconds":7,"vm":"auto","wifiRecoveryFix":true,"lanAllow":[]}'
    $script:multiJson = '{"profiles":[{"profile":"Work","server":"vpn.example.com","username":"jdoe"},{"profile":"Backup","server":"vpn2.example.com","port":8443,"username":"jdoe2"}],"activeProfile":"Work"}'
    Import-VeroNative
    # field-key prefixes as FilterSpec.ToString() prints them
    $script:F = @{ Flags = '632ce23b'; If = '4cd62a49'; Addr = 'b235ae9a'; Proto = '3971ef2b'; RPort = 'c35a604d'; LPort = '0c1ba1af'; App = 'd78e1e87' }
    function Get-SpecText($specs) { @($specs | ForEach-Object { $_.ToString() }) }

    # SAFETY: nothing in this file may reach the real firewall, WFP, Hyper-V firewall or VPN. File-wide no-op mocks for every
    # command that changes the system; a test that needs a behaviour overrides one of them in its own block.
    foreach ($cmd in 'Set-NetFirewallProfile', 'New-NetFirewallRule', 'Set-NetFirewallRule', 'Remove-NetFirewallRule',
                     'Set-NetFirewallHyperVVMSetting', 'New-NetFirewallHyperVRule', 'Set-NetFirewallHyperVRule', 'Remove-NetFirewallHyperVRule',
                     'Set-VeroWfpFilter', 'Clear-VeroWfpFilter', 'Invoke-VeroDial', 'Invoke-VeroHangUp') {
        Mock -ModuleName VeroScudo.Core $cmd { }
    }
    # "nothing found" = no output at all, like the real cmdlets (an explicit $null would be piped on as a value)
    Mock -ModuleName VeroScudo.Core Get-NetFirewallRule { }
    Mock -ModuleName VeroScudo.Core Get-NetFirewallHyperVRule { }
    Mock -ModuleName VeroScudo.Core Get-NetFirewallHyperVVMSetting { }
    Mock -ModuleName VeroScudo.Core Get-NetFirewallHyperVVMCreator { }
    Mock -ModuleName VeroScudo.Core Get-NetFirewallProfile { @([pscustomobject]@{ Name = 'Public'; DefaultOutboundAction = 'NotConfigured' }) }
    Mock -ModuleName VeroScudo.Core Get-VeroWfpCount { 0 }
}
AfterAll { Remove-TestDir; Set-VeroHome $null }

Describe 'Get-VeroConfig' {
    AfterEach { Remove-TestFile (Get-VeroPath).ActiveProfile }
    It 'reads the 1.0 single-profile format and applies defaults' {
        $c = Get-VeroConfig -Raw $script:cfgJson
        $c.Profile | Should -Be 'MyVPN'; $c.Port | Should -Be 443; $c.RetrySeconds | Should -Be 7
        $c.Vm | Should -Be 'auto'; $c.WifiRecoveryFix | Should -BeTrue; $c.LanAllow.Count | Should -Be 0
        @($c.Profiles).Count | Should -Be 1
    }
    It 'defaults port, retry, vm and updateCheck when omitted' {
        $c = Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"s","username":"u"}}'
        $c.Port | Should -Be 443; $c.RetrySeconds | Should -Be 10; $c.Vm | Should -Be 'auto'; $c.UpdateCheck | Should -BeTrue
    }
    It 'reads several profiles and picks the configured default' {
        $c = Get-VeroConfig -Raw $script:multiJson
        @($c.Profiles).Count | Should -Be 2
        $c.Profile | Should -Be 'Work'; $c.Server | Should -Be 'vpn.example.com'
    }
    It 'selects another profile with -Active' {
        $c = Get-VeroConfig -Raw $script:multiJson -Active 'Backup'
        $c.Profile | Should -Be 'Backup'; $c.Port | Should -Be 8443; $c.Username | Should -Be 'jdoe2'
        $c.DefaultProfile | Should -Be 'Work'
    }
    It 'follows the runtime selection written by the guard, and ignores an unknown one' {
        Set-Content (Get-VeroPath).ActiveProfile 'Backup'
        (Get-VeroConfig -Raw $script:multiJson).Profile | Should -Be 'Backup'
        Set-Content (Get-VeroPath).ActiveProfile 'Planted'
        (Get-VeroConfig -Raw $script:multiJson).Profile | Should -Be 'Work'
    }
    It 'rejects an unknown -Active profile' { { Get-VeroConfig -Raw $script:multiJson -Active 'Nope' } | Should -Throw '*unknown VPN profile*' }
    It 'rejects a duplicate profile' { { Get-VeroConfig -Raw '{"profiles":[{"profile":"A","server":"s","username":"u"},{"profile":"A","server":"t","username":"u"}]}' } | Should -Throw '*listed twice*' }
    It 'rejects a missing profile name' { { Get-VeroConfig -Raw '{"vpn":{"server":"s","username":"u"}}' } | Should -Throw '*vpn.profile*' }
    It 'rejects an invalid vm value' { { Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"s","username":"u"},"vm":"maybe"}' } | Should -Throw '*vm must be*' }
    It 'accepts boolean vm' { (Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"s","username":"u"},"vm":false}').Vm | Should -BeFalse }
    It 'rejects <what>' -ForEach @(
        @{ what = 'a wildcard profile name'; json = '{"vpn":{"profile":"V*","server":"s","username":"u"}}'; msg = '*invalid VPN profile name*' }
        @{ what = 'a bad server name';       json = '{"vpn":{"profile":"X","server":"vpn example;rm","username":"u"}}'; msg = '*invalid server*' }
        @{ what = 'port 0';                  json = '{"vpn":{"profile":"X","server":"s","username":"u","port":0}}'; msg = '*port must be*' }
        @{ what = 'port 70000';              json = '{"vpn":{"profile":"X","server":"s","username":"u","port":70000}}'; msg = '*port must be*' }
        @{ what = 'retrySeconds 0';          json = '{"vpn":{"profile":"X","server":"s","username":"u"},"retrySeconds":0}'; msg = '*retrySeconds*' }
        @{ what = 'an invalid serverIps';    json = '{"vpn":{"profile":"X","server":"s","username":"u","serverIps":["999.1.1.1"]}}'; msg = '*serverIps*' }
        @{ what = 'lanAllow 0.0.0.0/0';      json = '{"vpn":{"profile":"X","server":"s","username":"u"},"lanAllow":["0.0.0.0/0"]}'; msg = '*lanAllow*' }
        @{ what = 'lanAllow Any';            json = '{"vpn":{"profile":"X","server":"s","username":"u"},"lanAllow":["Any"]}'; msg = '*lanAllow*' }
        @{ what = 'lanAllow 10.0.0.0/4';     json = '{"vpn":{"profile":"X","server":"s","username":"u"},"lanAllow":["10.0.0.0/4"]}'; msg = '*lanAllow*' }
        @{ what = 'lanAllow ::/0';           json = '{"vpn":{"profile":"X","server":"s","username":"u"},"lanAllow":["::/0"]}'; msg = '*lanAllow*' }
    ) { { Get-VeroConfig -Raw $json } | Should -Throw $msg }
    It 'accepts narrow LAN ranges' {
        (Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"s","username":"u"},"lanAllow":["192.168.1.0/24","10.0.0.5","fd00::/64"]}').LanAllow.Count | Should -Be 3
    }
    It 'round-trips through the canonical JSON form' {
        $c = Get-VeroConfig -Raw $script:multiJson -Active 'Backup'
        $c2 = Get-VeroConfig -Raw (ConvertTo-VeroConfigJson $c) -Active 'Backup'
        @($c2.Profiles | ForEach-Object Profile) | Should -Be @('Work', 'Backup')
        $c2.Port | Should -Be 8443; $c2.DefaultProfile | Should -Be 'Work'
    }
}

Describe 'Test-VeroCidr' {
    It 'accepts <v>' -ForEach @(@{ v = '192.168.1.0/24' }, @{ v = '10.0.0.0/8' }, @{ v = '192.168.1.7' }, @{ v = 'fe80::/64' }) { Test-VeroCidr $v | Should -BeTrue }
    It 'rejects <v>' -ForEach @(@{ v = '0.0.0.0/0' }, @{ v = '10.0.0.0/7' }, @{ v = 'Any' }, @{ v = '' }, @{ v = '1' }, @{ v = '192.168.1.0/33' }, @{ v = '::/0' }, @{ v = 'LocalSubnet' }) { Test-VeroCidr $v | Should -BeFalse }
}

Describe 'Get-VeroDecision (the strict rule)' {
    It 'user hung up (631) -> disarm, even when armed' { Get-VeroDecision -ReasonCode 631 -Armed $true | Should -Be 'disarm' }
    It 'link failure (829) while armed -> reconnect' { Get-VeroDecision -ReasonCode 829 -Armed $true | Should -Be 'reconnect' }
    It 'any other failure while armed -> reconnect' { foreach ($c in 628, 619, 809, 830, -2147013895) { Get-VeroDecision -ReasonCode $c -Armed $true | Should -Be 'reconnect' } }
    It 'failure while disarmed -> nothing' { Get-VeroDecision -ReasonCode 829 -Armed $false | Should -Be 'none' }
    It 'never yields an "unblock" decision' { foreach ($c in 631, 829, 628, 0) { foreach ($a in $true, $false) { Get-VeroDecision -ReasonCode $c -Armed $a | Should -BeIn @('disarm', 'reconnect', 'none') } } }
}

Describe 'Get-VeroRasVerdict (forged-event detection)' {
    It 'takes the newest record' {
        $v = Get-VeroRasVerdict @([pscustomobject]@{ Profile = 'A'; CoId = '1'; Code = 829; Time = (Get-Date).AddMinutes(-5) }, [pscustomobject]@{ Profile = 'A'; CoId = '2'; Code = 631; Time = (Get-Date) })
        $v.Code | Should -Be 631; $v.Conflict | Should -BeFalse
    }
    It 'flags two different codes for one connection (a forged 631 next to the real failure)' {
        $v = Get-VeroRasVerdict @([pscustomobject]@{ Profile = 'A'; CoId = 'X'; Code = 829; Time = (Get-Date).AddSeconds(-20) }, [pscustomobject]@{ Profile = 'A'; CoId = 'X'; Code = 631; Time = (Get-Date) })
        $v.Code | Should -Be 631; $v.Conflict | Should -BeTrue
    }
    It 'returns nothing without records' { Get-VeroRasVerdict @() | Should -BeNullOrEmpty }
}

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
    BeforeAll {
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
    BeforeAll {
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

Describe 'on-event (mocked RAS)' {
    BeforeAll {
        InModuleScope VeroScudo.Core { $script:EventSettleSeconds = 0 }
        Mock -ModuleName VeroScudo.Core Get-VeroExpectedCoId { 'Z' }
        $script:cfgE = Get-VeroConfig -Raw '{"vpn":{"profile":"Work","server":"s","username":"u"}}'
        Mock -ModuleName VeroScudo.Core Disable-VeroKillSwitch { }
        Mock -ModuleName VeroScudo.Core Invoke-VeroReconnect { }
    }
    BeforeEach { Set-VeroArmed $true 'test' }
    AfterEach { Set-VeroArmed $false 'test' }
    It 'ignores a 631 while the tunnel is still up (stale or forged event)' {
        Mock -ModuleName VeroScudo.Core Get-VeroRasTermination { [pscustomobject]@{ Profile = 'Work'; CoId = 'X'; Code = 631; Conflict = $false } }
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $true }
        Invoke-VeroAction -Action on-event -Config $script:cfgE
        Should -Invoke -ModuleName VeroScudo.Core Disable-VeroKillSwitch -Times 0 -Exactly
        Test-VeroArmed | Should -BeTrue
    }
    It 'treats conflicting records for one connection as a failure (stays blocked, redials)' {
        Mock -ModuleName VeroScudo.Core Get-VeroRasTermination { [pscustomobject]@{ Profile = 'Work'; CoId = 'X'; Code = 631; Conflict = $true } }
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $false }
        Invoke-VeroAction -Action on-event -Config $script:cfgE
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroReconnect -Times 1 -Exactly
        Test-VeroArmed | Should -BeTrue
    }
    It 'ignores the termination of a profile that is not active (e.g. the old one during a switch)' {
        Mock -ModuleName VeroScudo.Core Get-VeroRasTermination { [pscustomobject]@{ Profile = 'Old'; CoId = 'Y'; Code = 631; Conflict = $false } }
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $false }
        Invoke-VeroAction -Action on-event -Config $script:cfgE
        Should -Invoke -ModuleName VeroScudo.Core Disable-VeroKillSwitch -Times 0 -Exactly
        Test-VeroArmed | Should -BeTrue
    }
    It 'treats a 631 for another connection id than the one VeroScudo saw connect as a failure (raced forgery)' {
        Mock -ModuleName VeroScudo.Core Get-VeroRasTermination { [pscustomobject]@{ Profile = 'Work'; CoId = 'FRESH-GUID'; Code = 631; Conflict = $false } }
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $false }
        Invoke-VeroAction -Action on-event -Config $script:cfgE
        Should -Invoke -ModuleName VeroScudo.Core Disable-VeroKillSwitch -Times 0 -Exactly
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroReconnect -Times 1 -Exactly
        Test-VeroArmed | Should -BeTrue
    }
    It 'treats a 631 as a failure when no connect of that profile was ever seen' {
        Mock -ModuleName VeroScudo.Core Get-VeroExpectedCoId { $null }
        Mock -ModuleName VeroScudo.Core Get-VeroRasTermination { [pscustomobject]@{ Profile = 'Work'; CoId = 'Z'; Code = 631; Conflict = $false } }
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $false }
        Invoke-VeroAction -Action on-event -Config $script:cfgE
        Test-VeroArmed | Should -BeTrue
        Mock -ModuleName VeroScudo.Core Get-VeroExpectedCoId { 'Z' }
    }
    It 'disarms on a genuine 631 for the active profile' {
        Mock -ModuleName VeroScudo.Core Get-VeroRasTermination { [pscustomobject]@{ Profile = 'Work'; CoId = 'Z'; Code = 631; Conflict = $false } }
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $false }
        Invoke-VeroAction -Action on-event -Config $script:cfgE
        Should -Invoke -ModuleName VeroScudo.Core Disable-VeroKillSwitch -Times 1 -Exactly
        Test-VeroArmed | Should -BeFalse
    }
}

Describe 'Invoke-VeroSwitch (mocked)' {
    BeforeAll {
        Set-Content (Get-VeroPath).Config $script:multiJson
        Mock -ModuleName VeroScudo.Core Sync-VeroKillSwitch { }
        Mock -ModuleName VeroScudo.Core Invoke-VeroHangUp { }
        Mock -ModuleName VeroScudo.Core Invoke-VeroReconnect { }
    }
    AfterAll { Remove-TestFile (Get-VeroPath).Config, (Get-VeroPath).ActiveProfile; Set-VeroArmed $false 'test' }
    BeforeEach { Remove-TestFile (Get-VeroPath).ActiveProfile }
    It 'while armed: selects the new profile, re-filters, hangs up the old one and dials the new one' {
        Set-VeroArmed $true 'test'
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $ProfileName -eq 'Work' }
        Invoke-VeroSwitch -Name 'Backup' -Action test
        (Get-VeroConfig).Profile | Should -Be 'Backup'
        Should -Invoke -ModuleName VeroScudo.Core Sync-VeroKillSwitch -Times 1 -Exactly -ParameterFilter { $Config.Profile -eq 'Backup' }
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroHangUp -Times 1 -Exactly
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroReconnect -Times 1 -Exactly -ParameterFilter { $Config.Profile -eq 'Backup' }
        Test-VeroArmed | Should -BeTrue
    }
    It 'while off: only selects the profile, dials nothing' {
        Set-VeroArmed $false 'test'
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $false }
        Invoke-VeroSwitch -Name 'Backup' -Action test
        (Get-VeroConfig).Profile | Should -Be 'Backup'
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroReconnect -Times 0 -Exactly
        Should -Invoke -ModuleName VeroScudo.Core Sync-VeroKillSwitch -Times 0 -Exactly
    }
    It 'refuses a profile that is not in config.json' {
        { Invoke-VeroSwitch -Name 'Planted' -Action test } | Should -Throw '*unknown VPN profile*'
    }
}

Describe 'state flag and log' {
    It 'arms and disarms via the flag file' {
        Set-VeroArmed $true 'test'; Test-VeroArmed | Should -BeTrue
        Set-VeroArmed $false 'test'; Test-VeroArmed | Should -BeFalse
    }
    It 'writes log lines with action tags' {
        Write-VeroLog 'hello' 'test'
        Get-Content (Get-VeroPath).Log -Tail 1 | Should -Match '\[test\] hello$'
    }
}

Describe 'reconnect lock' {
    AfterEach { Remove-TestFile (Get-VeroPath).Lock }
    It 'is taken atomically once, and refused while held by a live loop' {
        Enter-VeroLock | Should -BeTrue
        Enter-VeroLock | Should -BeFalse
    }
    It 'takes over a stale lock (dead PID)' {
        Set-Content (Get-VeroPath).Lock 999999
        Enter-VeroLock | Should -BeTrue
    }
    It 'treats a PID reused by another program as stale' {
        Set-Content (Get-VeroPath).Lock $PID
        Mock -ModuleName VeroScudo.Core Get-Process { [pscustomobject]@{ ProcessName = 'notepad'; StartTime = (Get-Date).AddHours(-1) } }
        InModuleScope VeroScudo.Core { Test-VeroLockAlive } | Should -BeFalse
    }
    It 'treats a PowerShell started after the lock was written as stale' {
        Set-Content (Get-VeroPath).Lock $PID
        Mock -ModuleName VeroScudo.Core Get-Process { [pscustomobject]@{ ProcessName = 'powershell'; StartTime = (Get-Date).AddHours(1) } }
        InModuleScope VeroScudo.Core { Test-VeroLockAlive } | Should -BeFalse
    }
}

Describe 'updates' {
    It 'detects newer tags' { Test-VeroNewerVersion -Tag 'v9.2.0' -Current '1.1.0' | Should -BeTrue; Test-VeroNewerVersion -Tag '1.2' -Current '1.1.9' | Should -BeTrue }
    It 'ignores same or older tags' { Test-VeroNewerVersion -Tag 'v1.1.0' -Current '1.1.0' | Should -BeFalse; Test-VeroNewerVersion -Tag 'v1.0.9' -Current '1.1.0' | Should -BeFalse }
    It 'ignores garbage tags' { foreach ($t in 'latest', 'v', '', 'v1.2.3-beta', '1.2.3.4.5') { Test-VeroNewerVersion -Tag $t -Current '0.1.1' | Should -BeFalse } }
    It 'opens only this project''s release pages' {
        Test-VeroReleaseUrl 'https://github.com/GomelHawk/VeroScudo/releases/tag/v1.2.0' | Should -BeTrue
        foreach ($u in 'C:\Windows\System32\calc.exe', '\\evil\share\x.exe', 'http://github.com/GomelHawk/VeroScudo/releases/tag/v1',
                       'https://github.com.evil.io/GomelHawk/VeroScudo/releases/', 'https://github.com/Other/VeroScudo/releases/tag/v1',
                       'https://user@github.com/GomelHawk/VeroScudo/releases/tag/v1', 'file:///C:/x', '') { Test-VeroReleaseUrl $u | Should -BeFalse -Because $u }
    }
}

Describe 'Get-VeroPath' {
    It 'is redirected only by Set-VeroHome, never by the environment' {
        $env:VEROSCUDO_HOME = 'C:\planted'
        try { (Get-VeroPath).Home | Should -Be $script:TestHomeDir } finally { Remove-Item Env:\VEROSCUDO_HOME }
    }
    It 'keeps one credential per profile, outside the shared home' {
        $a = (Get-VeroPath -VpnProfile 'Work').Cred; $b = (Get-VeroPath -VpnProfile 'Backup').Cred
        $a | Should -BeLike "$env:LOCALAPPDATA\VeroScudo\cred-*.xml"; $a | Should -Not -Be $b
    }
    It 'keeps tray-writable files in the user folder' {
        (Get-VeroPath).SwitchRequest | Should -BeLike "$env:LOCALAPPDATA\VeroScudo\*"
        (Get-VeroPath).UpdateFile | Should -BeLike "$env:LOCALAPPDATA\VeroScudo\*"
    }
}

# ======================================================================== profile types (ras / openvpn / wireguard)
Describe 'Get-VeroConfig profile types' {
    It 'defaults to the built-in client' { (Get-VeroConfig -Raw $script:multiJson).Type | Should -Be 'ras' }
    It 'reads an OpenVPN profile without server or username (they come from the .ovpn)' {
        $c = Get-VeroConfig -Raw '{"profiles":[{"profile":"Reserve","type":"openvpn"}]}'
        $c.Type | Should -Be 'openvpn'; $c.Auth | Should -BeTrue; $c.Dco | Should -BeFalse
    }
    It 'reads a WireGuard profile with its endpoint and default port 51820' {
        $c = Get-VeroConfig -Raw '{"profiles":[{"profile":"wg-home","type":"wireguard","server":"wg.example.com"}]}'
        $c.Type | Should -Be 'wireguard'; $c.Port | Should -Be 51820; $c.Auth | Should -BeFalse
    }
    It 'rejects <what>' -ForEach @(
        @{ what = 'an unknown type';                 json = '{"profiles":[{"profile":"X","type":"pptp","server":"s","username":"u"}]}'; msg = '*type must be*' }
        @{ what = 'WireGuard without an endpoint';   json = '{"profiles":[{"profile":"wg","type":"wireguard"}]}'; msg = '*server is required*' }
        @{ what = 'a WireGuard name with a space';   json = '{"profiles":[{"profile":"my wg","type":"wireguard","server":"s"}]}'; msg = '*WireGuard tunnel name*' }
        @{ what = 'a built-in profile without user'; json = '{"profiles":[{"profile":"X","server":"s"}]}'; msg = '*username is required*' }
    ) { { Get-VeroConfig -Raw $json } | Should -Throw $msg }
    It 'round-trips type, auth and dco through the canonical JSON form' {
        $c = Get-VeroConfig -Raw '{"profiles":[{"profile":"Work","server":"vpn.example.com","username":"u"},{"profile":"Ovpn","type":"openvpn","auth":false,"dco":true},{"profile":"wg","type":"wireguard","server":"wg.example.com","port":51821}]}'
        $c2 = Get-VeroConfig -Raw (ConvertTo-VeroConfigJson $c)
        @($c2.Profiles | ForEach-Object Type) | Should -Be @('ras', 'openvpn', 'wireguard')
        $o = $c2.Profiles | Where-Object Profile -eq 'Ovpn'; $o.Auth | Should -BeFalse; $o.Dco | Should -BeTrue
        ($c2.Profiles | Where-Object Profile -eq 'wg').Port | Should -Be 51821
    }
}

Describe 'switch notice' {
    It 'is shown for OpenVPN and WireGuard, never for the built-in client' {
        Get-VeroSwitchNotice -Type 'ras' -ProfileName 'Work' | Should -BeNullOrEmpty
        Get-VeroSwitchNotice -Type 'openvpn' -ProfileName 'a' | Should -Match 'OpenVPN GUI'
        Get-VeroSwitchNotice -Type 'wireguard' -ProfileName 'b' | Should -Match '1-3 minutes'
    }
}

Describe 'Test-VeroOpenVpnConf (import check)' {
    BeforeAll {
        $script:ovpn = @"
client
dev tun
proto udp
remote vpn1.example.com 1194
remote 198.51.100.7 443 tcp
auth-user-pass creds.txt
ca ca.crt
tls-auth ta.key 1
redirect-gateway def1
<cert>
-----BEGIN CERTIFICATE-----
abc
-----END CERTIFICATE-----
</cert>
"@
        $script:fakeRead = { param($f) if ($f -match 'ca\.crt$') { [Text.Encoding]::UTF8.GetBytes('CA-PEM') } elseif ($f -match 'ta\.key$') { [Text.Encoding]::UTF8.GetBytes('TA-KEY') } else { throw 'missing' } }
    }
    It 'reads every remote with the default port and protocol' {
        $r = Test-VeroOpenVpnConf -Text $script:ovpn -BaseDir 'C:\x' -ReadFile $script:fakeRead
        $r.Errors.Count | Should -Be 0
        @($r.Remotes).Count | Should -Be 2
        $r.Remotes[0].Host | Should -Be 'vpn1.example.com'; $r.Remotes[0].Port | Should -Be 1194; $r.Remotes[0].Proto | Should -Be 'udp'
        $r.Remotes[1].Port | Should -Be 443; $r.Remotes[1].Proto | Should -Be 'tcp'
        $r.Auth | Should -BeTrue
    }
    It 'inlines key files and drops the plain password file' {
        $r = Test-VeroOpenVpnConf -Text $script:ovpn -BaseDir 'C:\x' -ReadFile $script:fakeRead
        $r.Text | Should -Match '<ca>\s+CA-PEM\s+</ca>'
        $r.Text | Should -Match '<tls-auth>\s+TA-KEY\s+</tls-auth>\s+key-direction 1'
        $r.Text | Should -Not -Match 'creds\.txt'
        $r.Text | Should -Match '(?m)^auth-user-pass\s*$'
        @($r.Warnings | Where-Object { $_ -match 'plain file' }).Count | Should -Be 1
    }
    It 'keeps inline blocks untouched' { (Test-VeroOpenVpnConf -Text $script:ovpn -ReadFile $script:fakeRead).Text | Should -Match '<cert>\s+-----BEGIN CERTIFICATE-----' }
    It 'refuses <what>' -ForEach @(
        @{ what = 'an up script';           line = 'up C:\evil.cmd' }
        @{ what = 'script-security 2';      line = 'script-security 2' }
        @{ what = 'a plugin DLL';           line = 'plugin evil.dll' }
        @{ what = 'its own management';     line = 'management 0.0.0.0 7505' }
        @{ what = 'a nested config';        line = 'config other.ovpn' }
        @{ what = 'a proxy';                line = 'http-proxy proxy.example.com 8080' }
    ) { (Test-VeroOpenVpnConf -Text ("remote vpn.example.com`n" + $line)).Errors.Count | Should -BeGreaterThan 0 }
    It 'needs at least one remote' { (Test-VeroOpenVpnConf -Text "client`ndev tun").Errors -join ' ' | Should -Match 'remote' }
    It 'reports a key file that cannot be read' { (Test-VeroOpenVpnConf -Text "remote a.example.com`nca missing.crt" -ReadFile { throw 'x' }).Errors -join ' ' | Should -Match 'missing\.crt' }
    It 'flags a one-time code (static challenge)' {
        $r = Test-VeroOpenVpnConf -Text "remote a.example.com`nauth-user-pass`nstatic-challenge `"Code`" 1"
        $r.StaticChallenge | Should -BeTrue
    }
    It 'warns about a split tunnel when nothing redirects the gateway' {
        (Test-VeroOpenVpnConf -Text "remote a.example.com`ndev tun").Warnings -join ' ' | Should -Match 'redirect-gateway'
    }
    It 'reads remotes inside <connection> blocks' {
        $r = Test-VeroOpenVpnConf -Text "client`n<connection>`nremote a.example.com 1194 udp`n</connection>`n<connection>`nremote b.example.com 443 tcp`n</connection>"
        @($r.Remotes | ForEach-Object Host) | Should -Be @('a.example.com', 'b.example.com')
    }
}

Describe 'OpenVPN command line and management protocol' {
    It 'adds management on localhost, hold, no scripts, password over management and no DCO' {
        $a = Get-VeroOpenVpnArgs -ConfigPath 'C:\P\a.ovpn' -Port 40001 -PwFile 'C:\S\a.pw' -LogPath 'C:\S\a.log' -Version ([version]'2.6.12')
        $a | Should -Match '--management 127\.0\.0\.1 40001 "C:\\S\\a\.pw"'
        $a | Should -Match '--management-hold'; $a | Should -Match '--management-query-passwords'
        $a | Should -Match '--script-security 1'; $a | Should -Match '--auth-user-pass'; $a | Should -Match '--disable-dco'
        $a.IndexOf('--config') | Should -BeLessThan $a.IndexOf('--script-security')     # ours come after the user's file, so they win
    }
    It 'keeps DCO when the profile allows it, and on OpenVPN older than 2.6 (no such option)' {
        Get-VeroOpenVpnArgs -ConfigPath a -Port 1 -PwFile b -LogPath c -Version ([version]'2.6.0') -Dco $true | Should -Not -Match 'disable-dco'
        Get-VeroOpenVpnArgs -ConfigPath a -Port 1 -PwFile b -LogPath c -Version ([version]'2.5.9') | Should -Not -Match 'disable-dco'
    }
    It 'asks for no password when the profile has none' { Get-VeroOpenVpnArgs -ConfigPath a -Port 1 -PwFile b -LogPath c -Auth $false | Should -Not -Match 'auth-user-pass' }
    It 'parses <line>' -ForEach @(
        @{ line = '>STATE:1607975456,CONNECTED,SUCCESS,10.8.0.6,203.0.113.5,1194,,'; kind = 'state'; field = 'LocalIp'; value = '10.8.0.6' }
        @{ line = '>STATE:1607975456,RECONNECTING,ping-restart,,,,,'; kind = 'state'; field = 'Reason'; value = 'ping-restart' }
        @{ line = ">PASSWORD:Need 'Auth' username/password"; kind = 'need'; field = 'Which'; value = 'Auth' }
        @{ line = ">PASSWORD:Need 'Auth' username/password SC:1,Enter token"; kind = 'need'; field = 'Challenge'; value = 'Enter token' }
        @{ line = ">PASSWORD:Need 'Private Key' password"; kind = 'need'; field = 'Which'; value = 'Private Key' }
        @{ line = ">PASSWORD:Verification Failed: 'Auth'"; kind = 'failed'; field = 'Dynamic'; value = $false }
        @{ line = ">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:abc:dXNlcg==:Enter PIN']"; kind = 'failed'; field = 'Dynamic'; value = $true }
        @{ line = '>HOLD:Waiting for hold release:0'; kind = 'hold'; field = 'Kind'; value = 'hold' }
        @{ line = '>INFO:OpenVPN Management Interface Version 5'; kind = 'other'; field = 'Kind'; value = 'other' }
    ) {
        $e = ConvertFrom-VeroMgmtLine $line
        $e.Kind | Should -Be $kind; $e.$field | Should -Be $value
    }
    It 'quotes and escapes credentials, and refuses line breaks' {
        Format-VeroMgmtValue 'pa"ss\word' | Should -Be '"pa\"ss\\word"'
        { Format-VeroMgmtValue "a`nsignal SIGTERM" } | Should -Throw
    }
    It 'builds the static-challenge answer' { Get-VeroStaticChallengeResponse -Password 'pw' -Response '123456' | Should -Be 'SCRV1:cHc=:MTIzNDU2' }
}

Describe 'WireGuard health and transitions' {
    It 'is <want> when <what>' -ForEach @(
        @{ what = 'the service is not running';         svc = 'stopped'; hs = @(1000); now = 1010; age = 99; want = 'down' }
        @{ what = 'the last handshake is 2 min old';     svc = 'running'; hs = @(1000); now = 1120; age = 999; want = 'up' }
        @{ what = 'the last handshake is 4 min old';     svc = 'running'; hs = @(1000); now = 1240; age = 999; want = 'stale' }
        @{ what = 'it just started without a handshake'; svc = 'running'; hs = @(0);    now = 1000; age = 5;   want = 'starting' }
        @{ what = 'it never handshook for a minute';     svc = 'running'; hs = @(0);    now = 1000; age = 60;  want = 'stale' }
        @{ what = 'one of two peers is fresh';           svc = 'running'; hs = @(10, 990); now = 1000; age = 999; want = 'up' }
    ) { Get-VeroWgHealth -ServiceState $svc -Handshakes $hs -Now $now -ServiceAgeSeconds $age | Should -Be $want }
    It 'reads <prev> -> <cur> (armed=<armed>, active=<active>, lock=<lock>) as <want>' -ForEach @(
        @{ prev = 'missing'; cur = 'running'; armed = $false; active = $false; lock = $false; want = 'arm' }      # activated in the WireGuard app
        @{ prev = 'missing'; cur = 'running'; armed = $true;  active = $true;  lock = $false; want = 'none' }     # our own (re)dial
        @{ prev = 'running'; cur = 'missing'; armed = $true;  active = $true;  lock = $false; want = 'disarm' }   # deactivated in the app
        @{ prev = 'running'; cur = 'missing'; armed = $true;  active = $true;  lock = $true;  want = 'none' }     # our own Reconnect
        @{ prev = 'running'; cur = 'missing'; armed = $false; active = $true;  lock = $false; want = 'none' }     # after our Off
        @{ prev = 'running'; cur = 'stopped'; armed = $true;  active = $true;  lock = $false; want = 'none' }     # crash: a failure, redial
        @{ prev = $null;     cur = 'running'; armed = $false; active = $false; lock = $false; want = 'none' }     # first look after start
    ) { Get-VeroWgTransition -Previous $prev -Current $cur -Armed $armed -Active $active -LockAlive $lock | Should -Be $want }
}

Describe 'Test-VeroWireGuardConf (add check)' {
    It 'reads the endpoint and finds nothing to complain about in a full-tunnel config' {
        $r = Test-VeroWireGuardConf -Text "[Interface]`nPrivateKey = x`nAddress = 10.0.0.2/32`nDNS = 10.0.0.1`n[Peer]`nPublicKey = y`nAllowedIPs = 0.0.0.0/0, ::/0`nEndpoint = wg.example.com:51820`nPersistentKeepalive = 25"
        $r.Errors.Count | Should -Be 0; $r.Warnings.Count | Should -Be 0
        $r.Server | Should -Be 'wg.example.com'; $r.Port | Should -Be 51820
    }
    It 'warns about a missing keepalive, a split tunnel and missing DNS' {
        $r = Test-VeroWireGuardConf -Text "[Interface]`nPrivateKey = x`n[Peer]`nAllowedIPs = 10.0.0.0/8`nEndpoint = [2001:db8::1]:51820"
        $r.Server | Should -Be '2001:db8::1'
        ($r.Warnings -join ' ') | Should -Match 'PersistentKeepalive'; ($r.Warnings -join ' ') | Should -Match 'split tunnel'; ($r.Warnings -join ' ') | Should -Match 'DNS'
    }
    It 'needs an endpoint' { (Test-VeroWireGuardConf -Text "[Interface]`nPrivateKey = x`n[Peer]`nAllowedIPs = 0.0.0.0/0").Errors.Count | Should -Be 1 }
}

Describe 'Get-VeroFilterSpec for reserve types' {
    BeforeAll { $script:cfgW = Get-VeroConfig -Raw '{"profiles":[{"profile":"wg","type":"wireguard","server":"wg.example.com"}]}' }
    It 'WireGuard: only UDP to the endpoint, no program condition (the kernel driver sends it), no CRL permit' {
        $eps = @([pscustomobject]@{ Ip = '203.0.113.9'; Proto = 17; Port = 51820 })
        $t = Get-SpecText (Get-VeroFilterSpec -Config $script:cfgW -Endpoints $eps -DnsServers @('192.168.1.1'))
        $srv = @($t | Where-Object { $_ -like 'VPN server*' })
        $srv.Count | Should -Be 1
        $srv[0] | Should -Match "$($script:F.Proto)=17"; $srv[0] | Should -Match "$($script:F.RPort)=51820"; $srv[0] | Should -Match "$($script:F.Addr)=203\.0\.113\.9"
        $srv[0] | Should -Not -Match $script:F.App
        @($t | Where-Object { $_ -like 'CRL*' }).Count | Should -Be 0
        @($t | Where-Object { $_ -like 'DNS*' }).Count | Should -Be 1
    }
    It 'OpenVPN: one permit per protocol/port, tied to openvpn.exe, both address families' {
        $eps = @([pscustomobject]@{ Ip = '203.0.113.9'; Proto = 17; Port = 1194 }, [pscustomobject]@{ Ip = '2001:db8::9'; Proto = 17; Port = 1194 },
                 [pscustomobject]@{ Ip = '198.51.100.7'; Proto = 6; Port = 443 })
        $t = Get-SpecText (Get-VeroFilterSpec -Config $script:cfgW -Endpoints $eps -EndpointApp 'C:\Program Files\OpenVPN\bin\openvpn.exe')
        $srv = @($t | Where-Object { $_ -like 'VPN server*' })
        $srv.Count | Should -Be 3
        foreach ($x in $srv) { $x | Should -Match "$($script:F.App)=.*openvpn\.exe" }
        @($srv | Where-Object { $_ -match "$($script:F.RPort)=443" -and $_ -match '198\.51\.100\.7' -and $_ -match "$($script:F.Proto)=6" }).Count | Should -Be 1
    }
    It 'still scopes every permit and ends with the catch-all blocks' {
        $eps = @([pscustomobject]@{ Ip = '203.0.113.9'; Proto = 17; Port = 51820 })
        $specs = Get-VeroFilterSpec -Config $script:cfgW -Endpoints $eps -TunnelLuid 77
        foreach ($x in (Get-SpecText $specs)) { $parts = $x -split '\|'; if ($parts[2] -eq 'permit') { $parts[4] | Should -Not -BeNullOrEmpty } }
        @($specs | Where-Object { -not $_.Permit }).Count | Should -Be 4
    }
    It 'never permits a server without an address' { @(Get-SpecText (Get-VeroFilterSpec -Config $script:cfgW -Endpoints @()) | Where-Object { $_ -like 'VPN server*' }).Count | Should -Be 0 }
}

Describe 'Sync-VeroKillSwitch for a WireGuard profile (mocked)' {
    BeforeAll {
        $script:cfgWs = Get-VeroConfig -Raw '{"profiles":[{"profile":"wg","type":"wireguard","server":"wg.example.com"}],"vm":false}'
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelLuid { [uint64]0 }
        Mock -ModuleName VeroScudo.Core Get-VeroDnsServer { @('192.168.1.1') }
        Mock -ModuleName VeroScudo.Core Get-VeroWfpCount { 0 }
        Mock -ModuleName VeroScudo.Core Resolve-VeroEndpoint { [pscustomobject]@{ Ip = '203.0.113.9'; Proto = 17; Port = 51820 } }
        $script:applied = $null
        Mock -ModuleName VeroScudo.Core Set-VeroWfpFilter { $script:applied = $Specs }
    }
    BeforeEach { Remove-TestFile (Get-VeroPath).WfpState, (Get-VeroPath).Emergency }
    It 'uses the WireGuard endpoint, not the RAS ports' {
        Sync-VeroKillSwitch -Config $script:cfgWs -Action test
        $srv = @(Get-SpecText $script:applied | Where-Object { $_ -like 'VPN server*' })
        $srv.Count | Should -Be 1; $srv[0] | Should -Match "$($script:F.RPort)=51820"
    }
    It '-ForceDown leaves the tunnel out even while it is up (Reconnect blocks first)' {
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelLuid { [uint64]77 }
        Sync-VeroKillSwitch -Config $script:cfgWs -Action test -ForceDown
        @(Get-SpecText $script:applied | Where-Object { $_ -like 'VPN tunnel|*' }).Count | Should -Be 0
        Sync-VeroKillSwitch -Config $script:cfgWs -Action test
        @(Get-SpecText $script:applied | Where-Object { $_ -like 'VPN tunnel|*' }).Count | Should -Be 4
    }
}

Describe 'Reconnect (the user action)' {
    BeforeAll {
        Set-Content (Get-VeroPath).Config $script:multiJson
        $script:cfgR = Get-VeroConfig
        $script:steps = New-Object System.Collections.ArrayList
        $script:tunnel = @{ Up = $true }
        Mock -ModuleName VeroScudo.Core Sync-VeroKillSwitch { [void]$script:steps.Add($(if ($ForceDown) { 'block' } else { 'sync' })) }
        Mock -ModuleName VeroScudo.Core Invoke-VeroHangUp { [void]$script:steps.Add('hangup'); $script:tunnel.Up = $false }
        Mock -ModuleName VeroScudo.Core Invoke-VeroDial { [void]$script:steps.Add('dial'); $script:tunnel.Up = $true }
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $script:tunnel.Up }
    }
    AfterAll { Remove-TestFile (Get-VeroPath).Config, (Get-VeroPath).Renew, (Get-VeroPath).Lock; Set-VeroArmed $false 'test' }
    BeforeEach { $script:steps.Clear(); $script:tunnel.Up = $true; Remove-TestFile (Get-VeroPath).Renew, (Get-VeroPath).Lock }
    It 'blocks first, then hangs up, redials, and lets traffic through only once the tunnel is back' {
        Set-VeroArmed $true 'test'
        Invoke-VeroAction -Action reconnect -Config $script:cfgR
        @($script:steps) | Should -Be @('block', 'hangup', 'sync', 'dial', 'sync')
        Test-VeroArmed | Should -BeTrue
        (Get-VeroRenewMarker).HungUp | Should -Not -BeNullOrEmpty
    }
    It 'does nothing while the VPN is off (there is nothing to reconnect)' {
        Set-VeroArmed $false 'test'
        Invoke-VeroAction -Action reconnect -Config $script:cfgR
        $script:steps.Count | Should -Be 0
    }
}

Describe 'Test-VeroRenewHangUp (our own hang-up is not "you hung up")' {
    BeforeAll {
        $now = Get-Date
        $script:mk = [pscustomobject]@{ Profile = 'Work'; Start = $now.AddSeconds(-20).ToString('o'); HungUp = $now.AddSeconds(-10).ToString('o') }
        $script:now = $now
    }
    It 'matches the hang-up of that profile inside the window' { Test-VeroRenewHangUp -Marker $script:mk -ProfileName 'Work' -EventTime $script:now.AddSeconds(-12) -Now $script:now | Should -BeTrue }
    It 'ignores another profile' { Test-VeroRenewHangUp -Marker $script:mk -ProfileName 'Backup' -EventTime $script:now.AddSeconds(-12) -Now $script:now | Should -BeFalse }
    It 'ignores a disconnect well after the reconnect (a real Off)' { Test-VeroRenewHangUp -Marker $script:mk -ProfileName 'Work' -EventTime $script:now.AddSeconds(25) -Now $script:now.AddSeconds(30) | Should -BeFalse }
    It 'ignores a stale marker' { Test-VeroRenewHangUp -Marker $script:mk -ProfileName 'Work' -EventTime $script:now -Now $script:now.AddMinutes(10) | Should -BeFalse }
    It 'ignores no marker' { Test-VeroRenewHangUp -Marker $null -ProfileName 'Work' -EventTime $script:now | Should -BeFalse }
}

Describe 'on-event during a Reconnect (mocked RAS)' {
    BeforeAll {
        InModuleScope VeroScudo.Core { $script:EventSettleSeconds = 0 }
        $script:cfgE2 = Get-VeroConfig -Raw '{"vpn":{"profile":"Work","server":"s","username":"u"}}'
        Mock -ModuleName VeroScudo.Core Disable-VeroKillSwitch { }
        Mock -ModuleName VeroScudo.Core Invoke-VeroReconnect { }
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $false }
    }
    AfterEach { Set-VeroArmed $false 'test'; Remove-TestFile (Get-VeroPath).Renew }
    It 'treats the 631 of our own hang-up as a failure: stays armed and redials' {
        Set-VeroArmed $true 'test'
        Set-VeroRenewMarker -ProfileName 'Work'; Set-VeroRenewMarker -ProfileName 'Work' -HungUp
        Mock -ModuleName VeroScudo.Core Get-VeroRasTermination { [pscustomobject]@{ Profile = 'Work'; CoId = 'R'; Code = 631; Conflict = $false; Time = (Get-Date) } }
        Invoke-VeroAction -Action on-event -Config $script:cfgE2
        Test-VeroArmed | Should -BeTrue
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroReconnect -Times 1 -Exactly
    }
}

Describe 'rejected password pauses the redial' {
    BeforeAll {
        Set-VeroHome $script:TestHomeDir -UserDir (Join-Path $script:TestHomeDir 'user')
        if (-not (Test-IsTestDir (Get-VeroPath).UserDir)) { throw 'SAFETY: user folder outside the test folder' }
        New-Item -ItemType Directory -Path (Get-VeroPath).UserDir -Force | Out-Null
    }
    AfterAll { Set-VeroHome $script:TestHomeDir; Set-VeroArmed $false 'test' }
    It 'is blocked after a rejection and free again once a newer password is stored' {
        $p = Get-VeroPath -VpnProfile 'Work'
        Remove-TestFile $p.AuthFail, $p.Cred
        Test-VeroAuthBlocked 'Work' | Should -BeFalse
        Set-VeroAuthFailed -ProfileName 'Work' -Reason 'RAS error 691' -Action test
        Test-VeroAuthBlocked 'Work' | Should -BeTrue
        Start-Sleep -Milliseconds 50
        Set-Content $p.Cred 'new'
        (Get-Item $p.Cred).LastWriteTimeUtc = (Get-Item $p.AuthFail).LastWriteTimeUtc.AddSeconds(5)
        Test-VeroAuthBlocked 'Work' | Should -BeFalse
        Remove-TestFile $p.AuthFail, $p.Cred
    }
    It 'keeps the machine blocked without dialing while paused' {
        $cfg = Get-VeroConfig -Raw '{"vpn":{"profile":"Work","server":"s","username":"u"}}'
        Set-VeroAuthFailed -ProfileName 'Work' -Reason 'test' -Action test
        Set-VeroArmed $true 'test'
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $false }
        Mock -ModuleName VeroScudo.Core Sync-VeroKillSwitch { }
        Mock -ModuleName VeroScudo.Core Invoke-VeroDial { }
        Mock -ModuleName VeroScudo.Core Get-VeroConfig { $cfg }.GetNewClosure()
        Mock -ModuleName VeroScudo.Core Start-Sleep { Set-VeroArmed $false 'test' }        # end the loop after one pass
        Invoke-VeroReconnect -Config $cfg -Action test
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroDial -Times 0 -Exactly
        Should -Invoke -ModuleName VeroScudo.Core Sync-VeroKillSwitch -Times 1 -Exactly
        Remove-TestFile (Get-VeroPath -VpnProfile 'Work').AuthFail, (Get-VeroPath).Lock
    }
}

# ======================================================================== regressions from the review of the reserve types
Describe 'Test-VeroOpenVpnConf is an allow-list that reads lines like OpenVPN' {
    It 'refuses <what>' -ForEach @(
        @{ what = 'a quoted option name';          line = '"plugin" C:\Users\me\x.dll' }
        @{ what = 'a single-quoted option name';   line = "'plugin' x.dll" }
        @{ what = 'an escaped option name';        line = 'plu\gin x.dll' }
        @{ what = 'a capitalised option name';     line = 'Plugin x.dll' }
        @{ what = 'pkcs11-providers (loads a DLL)'; line = 'pkcs11-providers C:\x.dll' }
        @{ what = 'providers / engine';            line = 'providers legacy C:\x' }
        @{ what = 'replay-persist (writes a file)'; line = 'replay-persist C:\Windows\x' }
        @{ what = 'an unknown option';             line = 'ignore-unknown-option plugin' }
        @{ what = 'setenv opt';                    line = 'setenv opt plugin x.dll' }
        @{ what = 'a port out of range';           line = 'port 70000' }
        @{ what = 'an unknown inline block';       line = "<plugin>`nx`n</plugin>" }
    ) { (Test-VeroOpenVpnConf -Text ("remote vpn.example.com`n" + $line)).Errors.Count | Should -BeGreaterThan 0 }
    It 'refuses a key file that would close its block and smuggle options in' {
        $evil = { param($f) $null = $f; [Text.Encoding]::UTF8.GetBytes("-----BEGIN-----`n</ca>`nplugin C:\evil.dll`n<ca>`n-----END-----") }
        (Test-VeroOpenVpnConf -Text "remote vpn.example.com`nca ca.crt" -ReadFile $evil).Errors -join ' ' | Should -Match 'tag line'
    }
    It 'ends an inline block where OpenVPN does (a line starting with the closing tag) and refuses what follows' {
        (Test-VeroOpenVpnConf -Text "remote vpn.example.com`n<ca>`nabc`n</ca>x`nplugin evil.dll").Errors.Count | Should -BeGreaterThan 1
    }
    It 'gives each connection block its own protocol and port' {
        $r = Test-VeroOpenVpnConf -Text "client`nproto udp`n<connection>`nremote a.example.com`nproto udp`nport 1194`n</connection>`n<connection>`nremote b.example.com`nproto tcp-client`nport 443`n</connection>"
        $r.Errors.Count | Should -Be 0
        ($r.Remotes | Where-Object Host -eq 'a.example.com').Proto | Should -Be 'udp'; ($r.Remotes | Where-Object Host -eq 'a.example.com').Port | Should -Be 1194
        ($r.Remotes | Where-Object Host -eq 'b.example.com').Proto | Should -Be 'tcp'; ($r.Remotes | Where-Object Host -eq 'b.example.com').Port | Should -Be 443
    }
    It 'accepts a typical provider config' {
        $r = Test-VeroOpenVpnConf -Text "client`ndev tun`nproto udp`nremote se-sto.example.com 1194`nresolv-retry infinite`nnobind`npersist-key`npersist-tun`nremote-cert-tls server`ncipher AES-256-GCM`nauth SHA256`nverb 3`nauth-user-pass`n<ca>`nX`n</ca>"
        $r.Errors | Should -BeNullOrEmpty
    }
}

Describe 'rejected password pause regressions' {
    BeforeAll { Set-VeroHome $script:TestHomeDir -UserDir (Join-Path $script:TestHomeDir 'user'); New-Item -ItemType Directory -Path (Get-VeroPath).UserDir -Force | Out-Null }
    AfterAll { Set-VeroHome $script:TestHomeDir }
    It 'pauses again when the newly stored password is rejected too' {
        $p = Get-VeroPath -VpnProfile 'Work'
        Remove-TestFile $p.AuthFail, $p.Cred
        Set-VeroAuthFailed -ProfileName 'Work' -Reason 'first' -Action test
        Set-Content $p.Cred 'second'; (Get-Item $p.Cred).LastWriteTimeUtc = (Get-Date).ToUniversalTime().AddSeconds(5)
        Test-VeroAuthBlocked 'Work' | Should -BeFalse                       # resumes with the new password ...
        Set-VeroAuthFailed -ProfileName 'Work' -Reason 'second' -Action test
        (Get-Item $p.AuthFail).LastWriteTimeUtc = (Get-Item $p.Cred).LastWriteTimeUtc.AddSeconds(1)
        Test-VeroAuthBlocked 'Work' | Should -BeTrue                        # ... and pauses again when that one is rejected
        Remove-TestFile $p.AuthFail, $p.Cred
    }
    It 'lifts a rejected key passphrase only with a newer passphrase, not a newer password' {
        $p = Get-VeroPath -VpnProfile 'Work'
        Set-VeroAuthFailed -ProfileName 'Work' -Reason 'key' -Action test -Which Key
        Set-Content $p.Cred 'pw'; (Get-Item $p.Cred).LastWriteTimeUtc = (Get-Item $p.AuthFail).LastWriteTimeUtc.AddSeconds(5)
        Test-VeroAuthBlocked 'Work' | Should -BeTrue
        Set-Content $p.KeyPass 'kp'; (Get-Item $p.KeyPass).LastWriteTimeUtc = (Get-Item $p.AuthFail).LastWriteTimeUtc.AddSeconds(5)
        Test-VeroAuthBlocked 'Work' | Should -BeFalse
        Remove-TestFile $p.AuthFail, $p.Cred, $p.KeyPass
    }
}

Describe 'on-event ignores RAS events for other profile types' {
    BeforeAll {
        InModuleScope VeroScudo.Core { $script:EventSettleSeconds = 0 }; Mock -ModuleName VeroScudo.Core Disable-VeroKillSwitch { }; Mock -ModuleName VeroScudo.Core Invoke-VeroReconnect { }; Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $false } }
    AfterEach { Set-VeroArmed $false 'test' }
    It 'a (forged) 631 naming a WireGuard profile does not disarm' {
        Set-VeroArmed $true 'test'
        Mock -ModuleName VeroScudo.Core Get-VeroRasTermination { [pscustomobject]@{ Profile = 'wg'; CoId = 'F'; Code = 631; Conflict = $false; Time = (Get-Date) } }
        Invoke-VeroAction -Action on-event -Config (Get-VeroConfig -Raw '{"profiles":[{"profile":"wg","type":"wireguard","server":"wg.example.com"}]}')
        Test-VeroArmed | Should -BeTrue
        Should -Invoke -ModuleName VeroScudo.Core Disable-VeroKillSwitch -Times 0 -Exactly
    }
}

Describe 'Update-VeroWgWatch: switching tunnels in the WireGuard app' {
    BeforeAll {
        Set-Content (Get-VeroPath).Config '{"profiles":[{"profile":"B","type":"wireguard","server":"b.example.com"},{"profile":"A","type":"wireguard","server":"a.example.com"}],"activeProfile":"A"}'
        Mock -ModuleName VeroScudo.Core Sync-VeroKillSwitch { }
        Mock -ModuleName VeroScudo.Core Disable-VeroKillSwitch { }
        Mock -ModuleName VeroScudo.Core Test-VeroLockAlive { $false }
    }
    AfterAll { Remove-TestFile (Get-VeroPath).Config, (Get-VeroPath).ActiveProfile; Set-VeroArmed $false 'test' }
    It 'B activated and A removed in one pass ends armed on B, never disarmed' {
        Set-VeroArmed $true 'test'
        $script:wgStates = @{ A = 'running'; B = 'missing' }
        Mock -ModuleName VeroScudo.Core Get-VeroWgState { $script:wgStates[$ProfileName] }
        $null = Update-VeroWgWatch -Config (Get-VeroConfig) -Action test             # first look
        $script:wgStates = @{ A = 'missing'; B = 'running' }
        $null = Update-VeroWgWatch -Config (Get-VeroConfig) -Action test
        Test-VeroArmed | Should -BeTrue
        (Get-VeroConfig).Profile | Should -Be 'B'
        Should -Invoke -ModuleName VeroScudo.Core Disable-VeroKillSwitch -Times 0 -Exactly
    }
}

Describe 'Windows VPN profile details (the editor)' {
    It 'knows which sign-in needs a password' {
        Test-VeroRasPassword -AuthMethods @('Eap') -EapXml '<EapHostConfig><EapMethod><Type xmlns="x">26</Type></EapMethod></EapHostConfig>' | Should -BeTrue     # EAP-MSCHAPv2
        Test-VeroRasPassword -AuthMethods @('Eap') -EapXml '<EapHostConfig><EapMethod><eapCommon:Type>13</eapCommon:Type></EapMethod></EapHostConfig>' | Should -BeFalse  # EAP-TLS
        Test-VeroRasPassword -AuthMethods @('MachineCertificate') | Should -BeFalse
        Test-VeroRasPassword -AuthMethods @('MSChapv2') | Should -BeTrue
    }
    It 'describes the protocol it found' {
        Get-VeroRasDescription -TunnelType 'Ikev2' -Password $true | Should -Match 'IKEv2'
        Get-VeroRasDescription -TunnelType 'Ikev2' -Password $false -AllUsers $true | Should -Match 'no password needed.*all users'
    }
    It 'accepts a certificate-only Windows VPN profile without a username, and keeps it that way' {
        $c = Get-VeroConfig -Raw '{"profiles":[{"profile":"Cert","server":"vpn.example.com","auth":false}]}'
        $c.Auth | Should -BeFalse; Test-VeroNeedsPassword $c | Should -BeFalse
        (Get-VeroConfig -Raw (ConvertTo-VeroConfigJson $c)).Auth | Should -BeFalse
        (Get-VeroConfig -Raw $script:multiJson).Auth | Should -BeTrue
    }
}

Describe 'Import from Windows' {
    It 'splits <a>' -ForEach @(
        @{ a = 'vpn.example.com';            h = 'vpn.example.com'; p = 0 }
        @{ a = 'vpn.example.com:4443';       h = 'vpn.example.com'; p = 4443 }
        @{ a = '203.0.113.5';                h = '203.0.113.5';     p = 0 }
        @{ a = '[2001:db8::1]:443';          h = '2001:db8::1';     p = 443 }
        @{ a = 'https://vpn.example.com/x';  h = 'vpn.example.com'; p = 0 }
    ) { $r = Split-VeroServerAddress $a; $r.Host | Should -Be $h; $r.Port | Should -Be $p }
    It 'imports <tt> with the right settings' -ForEach @(
        @{ tt = 'Ikev2';     srv = 'ike.example.com';      pw = $true;  port = 443 }
        @{ tt = 'Sstp';      srv = 'sstp.example.com:4443'; pw = $true; port = 4443 }
        @{ tt = 'L2tp';      srv = 'l2tp.example.com';     pw = $true;  port = 443 }
        @{ tt = 'Pptp';      srv = 'pptp.example.com';     pw = $true;  port = 443 }
        @{ tt = 'Automatic'; srv = 'auto.example.com';     pw = $true;  port = 443 }
        @{ tt = 'Ikev2';     srv = 'cert.example.com';     pw = $false; port = 443 }
    ) {
        $e = ConvertTo-VeroRasEntry -Vpn ([pscustomobject]@{ Name = "V-$tt"; Server = $srv; TunnelType = $tt; Password = $pw; AllUsers = $false }) -UserName 'jdoe'
        $e.Type | Should -Be 'ras'; $e.Port | Should -Be $port; $e.Server | Should -Not -Match ':'
        $e.Auth | Should -Be $pw; $e.Username | Should -Be $(if ($pw) { 'jdoe' } else { '' })
        $c = Get-VeroConfig -Raw (ConvertTo-Json -Depth 4 -InputObject @{ profiles = @(ConvertTo-VeroProfileObject $e) })     # valid config
        $c.Profile | Should -Be "V-$tt"
    }
}

Describe 'another VPN connected (Turn on asks, never decides)' {
    BeforeAll {
        $script:cfgF = Get-VeroConfig -Raw '{"profiles":[{"profile":"PieSoft","server":"vpn.example.com","username":"u"},{"profile":"Backup","server":"b.example.com","username":"u"}],"activeProfile":"PieSoft"}'
        $script:ras = @()
        Mock -ModuleName VeroScudo.Core Get-VeroWindowsVpn { $script:ras }
        Mock -ModuleName VeroScudo.Core Get-Service { }
        Mock -ModuleName VeroScudo.Core Get-Process { }
        Mock -ModuleName VeroScudo.Core Get-VeroNic { }
        Mock -ModuleName VeroScudo.Core Sync-VeroKillSwitch { }
        Mock -ModuleName VeroScudo.Core Invoke-VeroReconnect { }
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $false }
        Mock -ModuleName VeroScudo.Core Disconnect-VeroForeignVpn { }
    }
    BeforeEach { Set-VeroArmed $false 'test'; Remove-TestFile (Get-VeroPath).OnRefused, (Get-VeroPath).Foreign }
    AfterAll { Set-VeroArmed $false 'test'; Remove-TestFile (Get-VeroPath).OnRefused, (Get-VeroPath).Foreign }
    It 'finds a connected Windows VPN that is not imported, but not the active profile itself' {
        $script:ras = @([pscustomobject]@{ Name = 'PrivateVPN'; Connected = $true }, [pscustomobject]@{ Name = 'PieSoft'; Connected = $true }, [pscustomobject]@{ Name = 'Idle'; Connected = $false })
        $f = @(Get-VeroForeignVpn -Config $script:cfgF)
        $f.Count | Should -Be 1; $f[0].Name | Should -Be 'PrivateVPN'; $f[0].Configured | Should -BeFalse; $f[0].CanDisconnect | Should -BeTrue
        Format-VeroForeignVpn $f[0] | Should -Match "Windows VPN 'PrivateVPN' is connected \(not a VeroScudo profile\)"
    }
    It 'lists a vendor app tunnel as one it cannot disconnect' {
        $script:ras = @()
        Mock -ModuleName VeroScudo.Core Get-VeroNic { [pscustomobject]@{ Name = 'Local Area Connection'; Description = 'PrivateVPN TAP Adapter'; NetworkInterfaceType = 'Ethernet'; OperationalStatus = 'Up'; Id = [guid]::NewGuid().ToString() } }
        $f = @(Get-VeroForeignVpn -Config $script:cfgF)
        $f.Count | Should -Be 1; $f[0].Kind | Should -Be 'app'; $f[0].CanDisconnect | Should -BeFalse
        Mock -ModuleName VeroScudo.Core Get-VeroNic { }
    }
    It 'plain On refuses while PrivateVPN is connected, and says why' {
        $script:ras = @([pscustomobject]@{ Name = 'PrivateVPN'; Connected = $true })
        Invoke-VeroAction -Action on -Config $script:cfgF
        Test-VeroArmed | Should -BeFalse
        (Get-Content (Get-VeroPath).OnRefused -Raw | ConvertFrom-Json).Items[0] | Should -Match 'PrivateVPN'
        Should -Invoke -ModuleName VeroScudo.Core Disconnect-VeroForeignVpn -Times 0 -Exactly
    }
    It 'on-disconnect (your choice) ends it, then turns on' {
        $script:ras = @([pscustomobject]@{ Name = 'PrivateVPN'; Connected = $true })
        Invoke-VeroAction -Action on-disconnect -Config $script:cfgF
        Should -Invoke -ModuleName VeroScudo.Core Disconnect-VeroForeignVpn -Times 1 -Exactly
        Test-VeroArmed | Should -BeTrue
    }
    It 'on-force (your choice) turns on without disconnecting it' {
        $script:ras = @([pscustomobject]@{ Name = 'PrivateVPN'; Connected = $true })
        Invoke-VeroAction -Action on-force -Config $script:cfgF
        Should -Invoke -ModuleName VeroScudo.Core Disconnect-VeroForeignVpn -Times 0 -Exactly
        Test-VeroArmed | Should -BeTrue
    }
    It 'On without any other VPN just turns on' {
        $script:ras = @()
        Invoke-VeroAction -Action on -Config $script:cfgF
        Test-VeroArmed | Should -BeTrue
        Test-Path (Get-VeroPath).OnRefused | Should -BeFalse
    }
    It 'a VPN that is not a profile connecting while armed is reported for the tray, not armed' {
        Set-VeroArmed $true 'test'
        Mock -ModuleName VeroScudo.Core Get-VeroRasConnected { 'PrivateVPN' }
        Invoke-VeroAction -Action arm -Config $script:cfgF
        (Get-Content (Get-VeroPath).Foreign -Raw | ConvertFrom-Json).Name | Should -Be 'PrivateVPN'
        (Get-VeroConfig -Raw '{"profiles":[{"profile":"PieSoft","server":"vpn.example.com","username":"u"}]}').Profile | Should -Be 'PieSoft'
    }
}

Describe 'native helper blocked by Windows (Smart App Control)' {
    AfterEach { Remove-TestFile (Get-VeroPath).NativeBlocked; InModuleScope VeroScudo.Core { $script:NativeLoadFailed = $false } }
    It 'waits 1, 5, then 10 minutes between retries' {
        @(1, 2, 3, 9 | ForEach-Object { Get-VeroNativeRetrySeconds $_ }) | Should -Be @(60, 300, 600, 600)
    }
    It 'records each failure in a row and clears once the helper loads again' {
        Set-VeroNativeBlocked -Message 'policy' -Action test
        Set-VeroNativeBlocked -Message 'policy' -Action test
        $b = Get-VeroNativeBlocked
        $b.Count | Should -Be 2
        Test-VeroNativeRetryDue $b | Should -BeFalse
        Test-VeroNativeRetryDue $b -Now (Get-Date).AddMinutes(6) | Should -BeTrue
        Clear-VeroNativeBlocked -Action test
        Get-VeroNativeBlocked | Should -BeNullOrEmpty
        Test-VeroNativeRetryDue $null | Should -BeTrue
    }
    It 'the watchdog exits on a blocked helper (a fresh process retries) instead of failing every 15 s' {
        Mock -ModuleName VeroScudo.Core Invoke-VeroCheck { & (Get-Module VeroScudo.Core) { $script:NativeLoadFailed = $true }; throw 'Application Control policy has blocked this file' }
        Mock -ModuleName VeroScudo.Core Start-Sleep { throw 'the watchdog kept looping' }
        { Invoke-VeroAction -Action watchdog -Config (Get-VeroConfig -Raw $script:cfgJson) } | Should -Not -Throw
        (Get-VeroNativeBlocked).Count | Should -Be 1
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroCheck -Times 1 -Exactly
    }
    It 'a fresh watchdog does not even try before the retry time' {
        Set-VeroNativeBlocked -Message 'policy' -Action test
        Mock -ModuleName VeroScudo.Core Invoke-VeroCheck { throw 'must not run' }
        { Invoke-VeroAction -Action watchdog -Config (Get-VeroConfig -Raw $script:cfgJson) } | Should -Not -Throw
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroCheck -Times 0 -Exactly
    }
}

Describe 'review of 9052eef: regressions' {
    It 'does not count Windows'' own tunnels (Teredo, IP-HTTPS, 6to4, ISATAP) as a VPN' {
        foreach ($d in 'Teredo Tunneling Pseudo-Interface', 'Microsoft IP-HTTPS Platform Adapter', 'Microsoft 6to4 Adapter', 'Microsoft ISATAP Adapter') {
            Test-VeroTunnelAdapter ([pscustomobject]@{ Description = $d; NetworkInterfaceType = 'Tunnel' }) | Should -BeFalse -Because $d
        }
        Test-VeroTunnelAdapter ([pscustomobject]@{ Description = 'WAN Miniport (IKEv2)'; NetworkInterfaceType = 'Ppp' }) | Should -BeTrue
    }
    It 'takes system folders from the OS, not from a planted environment variable' {
        $saved = $env:ProgramFiles
        try {
            $env:ProgramFiles = 'C:\Users\planted\x'
            Get-VeroSystemDir ProgramFiles | Should -Not -Be 'C:\Users\planted\x'
        } finally { $env:ProgramFiles = $saved }
    }
    Context 'native record' {
        AfterEach { Remove-TestFile (Get-VeroPath).NativeBlocked }
        It 'a short task''s failure is shown but neither counted nor delaying the watchdog' {
            Set-VeroNativeBlocked -Message 'x' -Action test -FromTask
            $b = Get-VeroNativeBlocked
            [int]$b.Count | Should -Be 0
            Test-VeroNativeRetryDue $b -Now (Get-Date).AddSeconds(1) | Should -BeTrue
        }
    }
}

Describe 'review of 9052eef: On while already on, and vendor tunnels' {
    BeforeAll {
        $script:cfgR2 = Get-VeroConfig -Raw '{"profiles":[{"profile":"PieSoft","server":"vpn.example.com","username":"u"}]}'
        Mock -ModuleName VeroScudo.Core Get-VeroForeignVpn { [pscustomobject]@{ Name = 'PrivateVPN'; Kind = 'ras'; Configured = $false; CanDisconnect = $true; Id = 'PrivateVPN' } }
        Mock -ModuleName VeroScudo.Core Sync-VeroKillSwitch { }
        Mock -ModuleName VeroScudo.Core Invoke-VeroReconnect { }
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $false }
    }
    AfterAll { Set-VeroArmed $false 'test'; Remove-TestFile (Get-VeroPath).OnRefused }
    It 'already on: plain On warns but does not claim "not turned on"' {
        Remove-TestFile (Get-VeroPath).OnRefused
        Set-VeroArmed $true 'test'
        Invoke-VeroAction -Action on -Config $script:cfgR2
        Test-Path (Get-VeroPath).OnRefused | Should -BeFalse
        Test-VeroArmed | Should -BeTrue
    }
    It 'never logs a vendor tunnel as disconnected' {
        Mock -ModuleName VeroScudo.Core Get-VeroForeignVpn { [pscustomobject]@{ Name = 'TAP (PrivateVPN)'; Kind = 'app'; Configured = $false; CanDisconnect = $false; Id = 'TAP' } }
        $left = @(Disconnect-VeroForeignVpn -Config $script:cfgR2 -Action test)
        $left.Count | Should -Be 1
        Get-Content (Get-VeroPath).Log -Tail 3 | Where-Object { $_ -match 'disconnected:' } | Should -BeNullOrEmpty
    }
}


Describe 'security review 2026-11-02' {
    It 'resolves rasdial, schtasks and svchost to System32, not by name' {
        InModuleScope VeroScudo.Core { $script:Rasdial } | Should -Match 'System32\\rasdial\.exe$'
        InModuleScope VeroScudo.Core { $script:Schtasks } | Should -Match 'System32\\schtasks\.exe$'
        InModuleScope VeroScudo.Core { $script:Svchost } | Should -Match 'System32\\svchost\.exe$'
    }
    It 'the CRL window opens for 2 minutes and then closes' {
        Remove-TestFile (Get-VeroPath).CrlWindow
        Test-VeroCrlWindow | Should -BeFalse
        Open-VeroCrlWindow -Action test
        Test-VeroCrlWindow | Should -BeTrue
        @{ Until = (Get-Date).AddMinutes(-1).ToString('o') } | ConvertTo-Json | Set-Content (Get-VeroPath).CrlWindow
        Test-VeroCrlWindow | Should -BeFalse
        Remove-TestFile (Get-VeroPath).CrlWindow
    }
}


Describe 'security review 2026-11-02, second pass' {
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
