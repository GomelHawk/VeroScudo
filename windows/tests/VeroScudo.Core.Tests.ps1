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
        $full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
        $root = [IO.Path]::GetFullPath($script:TestHomeDir).TrimEnd('\')
        ($root -like "$([IO.Path]::GetTempPath().TrimEnd('\'))\veroscudo-test-*") -and ($full -eq $root -or $full.StartsWith("$root\", [StringComparison]::OrdinalIgnoreCase))
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
    It 'scopes every permit (never a blanket accept)' {
        foreach ($t in (Get-SpecText ($script:up + $script:down))) {
            $parts = $t -split '\|'
            if ($parts[2] -eq 'permit') { $parts[4] | Should -Not -BeNullOrEmpty -Because "permit '$($parts[0])' must have conditions" }
        }
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
    It 'allows DNS and CRL only while the tunnel is down - no DNS leak while protected' {
        @(Get-SpecText $script:down | Where-Object { $_ -like 'DNS*' -or $_ -like 'CRL*' }).Count | Should -BeGreaterThan 0
        @(Get-SpecText $script:up | Where-Object { $_ -like 'DNS*' -or $_ -like 'CRL*' }).Count | Should -Be 0
    }
    It 'restricts DNS to svchost and to the network-provided resolvers' {
        $dns = @(Get-SpecText $script:down | Where-Object { $_ -like 'DNS*' })
        $dns.Count | Should -Be 1                                 # IPv4 resolver only -> no IPv6 DNS permit
        $dns[0] | Should -Match "$($script:F.App)=.*svchost\.exe"; $dns[0] | Should -Match "$($script:F.Addr)=192\.168\.1\.1"; $dns[0] | Should -Match "$($script:F.RPort)=53"
    }
    It 'falls back to svchost-only DNS when no resolver is known' {
        $dns = @(Get-SpecText (Get-VeroFilterSpec -Config $script:cfg -ServerIps @('203.0.113.5') -TunnelType 'Sstp') | Where-Object { $_ -like 'DNS*' })
        $dns.Count | Should -Be 2
        foreach ($d in $dns) { $d | Should -Match "$($script:F.App)=.*svchost\.exe"; $d | Should -Not -Match $script:F.Addr }
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
