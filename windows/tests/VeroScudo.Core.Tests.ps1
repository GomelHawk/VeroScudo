# Pester 5 unit tests for the pure parts of VeroScudo.Core.psm1 (no firewall, no RAS).
BeforeAll {
    $env:VEROSCUDO_HOME = Join-Path ([IO.Path]::GetTempPath()) ("veroscudo-test-" + [guid]::NewGuid())
    Import-Module (Join-Path $PSScriptRoot '..\VeroScudo.Core.psm1') -Force
    $script:cfgJson = '{"vpn":{"profile":"MyVPN","server":"vpn.example.com","port":443,"username":"jdoe"},"retrySeconds":7,"vm":"auto","wifiRecoveryFix":true,"lanAllow":[]}'
}
AfterAll { Remove-Item $env:VEROSCUDO_HOME -Recurse -Force -ErrorAction SilentlyContinue }

Describe 'Get-VeroConfig' {
    It 'applies defaults and reads values' {
        $c = Get-VeroConfig -Raw $script:cfgJson
        $c.Profile | Should -Be 'MyVPN'
        $c.Port | Should -Be 443
        $c.RetrySeconds | Should -Be 7
        $c.Vm | Should -Be 'auto'
        $c.WifiRecoveryFix | Should -BeTrue
        $c.LanAllow.Count | Should -Be 0
    }
    It 'defaults port, retry and vm when omitted' {
        $c = Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"s","username":"u"}}'
        $c.Port | Should -Be 443; $c.RetrySeconds | Should -Be 10; $c.Vm | Should -Be 'auto'
    }
    It 'rejects a missing profile' { { Get-VeroConfig -Raw '{"vpn":{"server":"s","username":"u"}}' } | Should -Throw '*vpn.profile*' }
    It 'rejects an invalid vm value' { { Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"s","username":"u"},"vm":"maybe"}' } | Should -Throw '*vm must be*' }
    It 'defaults updateCheck to true and honours false' {
        (Get-VeroConfig -Raw $script:cfgJson).UpdateCheck | Should -BeTrue
        (Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"s","username":"u"},"updateCheck":false}').UpdateCheck | Should -BeFalse
    }
    It 'accepts boolean vm' { (Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"s","username":"u"},"vm":false}').Vm | Should -BeFalse }
}

Describe 'Get-VeroDecision (the strict rule)' {
    It 'user hung up (631) -> disarm, even when armed' { Get-VeroDecision -ReasonCode 631 -Armed $true | Should -Be 'disarm' }
    It 'link failure (829) while armed -> reconnect' { Get-VeroDecision -ReasonCode 829 -Armed $true | Should -Be 'reconnect' }
    It 'any other failure while armed -> reconnect' { foreach ($c in 628, 619, 809, -2147013895) { Get-VeroDecision -ReasonCode $c -Armed $true | Should -Be 'reconnect' } }
    It 'failure while disarmed -> nothing' { Get-VeroDecision -ReasonCode 829 -Armed $false | Should -Be 'none' }
    It 'never yields an "unblock" decision' { foreach ($c in 631, 829, 628, 0) { foreach ($a in $true, $false) { Get-VeroDecision -ReasonCode $c -Armed $a | Should -BeIn @('disarm', 'reconnect', 'none') } } }
}

Describe 'Get-VeroRuleSpec (the allow-list)' {
    BeforeAll { $script:cfg = Get-VeroConfig -Raw $script:cfgJson }
    It 'contains exactly the documented allow rules and nothing broader' {
        $specs = Get-VeroRuleSpec -Config $script:cfg -ServerIps @('203.0.113.5') -WslInterface 'vEthernet (WSL (Hyper-V firewall))'
        $names = $specs | ForEach-Object { $_.Name }
        $names | Should -Be @('VPN tunnel', 'DHCP', 'DNS UDP', 'DNS TCP', 'CRL SstpSvc', 'CRL CryptSvc', 'WSL switch', 'VPN server')
    }
    It 'scopes the VPN server rule to the resolved IPs and the configured port' {
        $s = (Get-VeroRuleSpec -Config $script:cfg -ServerIps @('203.0.113.5', '203.0.113.6')) | Where-Object Name -eq 'VPN server'
        $s.Params.RemoteAddress | Should -Be @('203.0.113.5', '203.0.113.6')
        $s.Params.RemotePort | Should -Be 443
        $s.Params.Protocol | Should -Be 'TCP'
    }
    It 'omits the server rule when nothing resolved (never a wildcard)' {
        (Get-VeroRuleSpec -Config $script:cfg -ServerIps @()) | Where-Object Name -eq 'VPN server' | Should -BeNullOrEmpty
    }
    It 'omits the WSL rule when no WSL interface' {
        (Get-VeroRuleSpec -Config $script:cfg -ServerIps @('203.0.113.5')) | Where-Object Name -eq 'WSL switch' | Should -BeNullOrEmpty
    }
    It 'scopes the certificate-revocation rules to the two Windows services on port 80 only' {
        $crl = (Get-VeroRuleSpec -Config $script:cfg) | Where-Object Name -like 'CRL*'
        $crl.Count | Should -Be 2
        foreach ($r in $crl) { $r.Params.RemotePort | Should -Be 80; $r.Params.Service | Should -BeIn @('SstpSvc', 'CryptSvc'); $r.Params.Program | Should -BeLike '*\svchost.exe' }
    }
    It 'adds LAN allow rules only when configured' {
        $c2 = Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"s","username":"u"},"lanAllow":["192.168.1.0/24"]}'
        ((Get-VeroRuleSpec -Config $c2) | Where-Object Name -eq 'LAN 192.168.1.0/24').Params.RemoteAddress | Should -Be '192.168.1.0/24'
    }
    It 'has no rule that allows arbitrary outbound traffic' {
        foreach ($s in (Get-VeroRuleSpec -Config $script:cfg -ServerIps @('203.0.113.5'))) {
            $p = $s.Params
            ($p.ContainsKey('InterfaceType') -or $p.ContainsKey('InterfaceAlias') -or $p.ContainsKey('RemotePort') -or $p.ContainsKey('RemoteAddress')) | Should -BeTrue -Because "rule '$($s.Name)' must be scoped"
        }
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

Describe 'Enable-VeroKillSwitch (mocked Windows)' {
    BeforeAll {
        $script:cfg1 = Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"vpn.example.com","username":"u"},"vm":false}'
        Mock -ModuleName VeroScudo.Core Resolve-VeroServerIp { '203.0.113.5' }          # ONE address -> a plain string, not an array
        Mock -ModuleName VeroScudo.Core Get-NetFirewallProfile { @([pscustomobject]@{ Name = 'Public'; DefaultOutboundAction = 'NotConfigured' }) }
        Mock -ModuleName VeroScudo.Core Set-NetFirewallProfile { }
        Mock -ModuleName VeroScudo.Core Get-NetFirewallRule { $null }
        Mock -ModuleName VeroScudo.Core New-NetFirewallRule { [pscustomobject]@{ DisplayName = $DisplayName } }
        Mock -ModuleName VeroScudo.Core Get-NetAdapter { @() }
        Mock -ModuleName VeroScudo.Core Get-VpnConnection { [pscustomobject]@{ ConnectionStatus = 'Connected' } }
    }
    It 'creates every rule and blocks outbound when the server resolves to a single IP' {
        { Enable-VeroKillSwitch -Config $script:cfg1 -Action test } | Should -Not -Throw
        Should -Invoke -ModuleName VeroScudo.Core New-NetFirewallRule -Times 7 -Exactly     # 6 base rules + VPN server (no WSL, no LAN)
        Should -Invoke -ModuleName VeroScudo.Core Set-NetFirewallProfile -Times 1 -Exactly -ParameterFilter { $DefaultOutboundAction -eq 'Block' }
        Should -Invoke -ModuleName VeroScudo.Core New-NetFirewallRule -Times 1 -Exactly -ParameterFilter { $DisplayName -eq 'VeroScudo - VPN server' -and $RemoteAddress -eq '203.0.113.5' }
    }
}

Describe 'Test-VeroLockAlive' {
    BeforeEach { New-Item (Get-VeroPath).State -ItemType Directory -Force | Out-Null; Set-Content (Get-VeroPath).Lock $PID }
    AfterEach { Remove-Item (Get-VeroPath).Lock -Force -ErrorAction SilentlyContinue }
    It 'is alive while the PowerShell process that wrote it runs' { InModuleScope VeroScudo.Core { Test-VeroLockAlive } | Should -BeTrue }
    It 'treats a dead PID as stale and removes the lock' {
        Set-Content (Get-VeroPath).Lock 999999
        InModuleScope VeroScudo.Core { Test-VeroLockAlive } | Should -BeFalse
        Test-Path (Get-VeroPath).Lock | Should -BeFalse
    }
    It 'treats a PID reused by another program as stale' {
        Mock -ModuleName VeroScudo.Core Get-Process { [pscustomobject]@{ ProcessName = 'notepad'; StartTime = (Get-Date).AddHours(-1) } }
        InModuleScope VeroScudo.Core { Test-VeroLockAlive } | Should -BeFalse
    }
    It 'treats a PowerShell started after the lock was written as stale' {
        Mock -ModuleName VeroScudo.Core Get-Process { [pscustomobject]@{ ProcessName = 'powershell'; StartTime = (Get-Date).AddHours(1) } }
        InModuleScope VeroScudo.Core { Test-VeroLockAlive } | Should -BeFalse
    }
}

Describe 'Test-VeroNewerVersion' {
    It 'detects newer tags' { Test-VeroNewerVersion -Tag 'v0.2.0' -Current '0.1.1' | Should -BeTrue; Test-VeroNewerVersion -Tag '1.0' -Current '0.9.9' | Should -BeTrue }
    It 'ignores same or older tags' { Test-VeroNewerVersion -Tag 'v0.1.3' -Current '0.1.3' | Should -BeFalse; Test-VeroNewerVersion -Tag 'v0.1.2' -Current '0.1.3' | Should -BeFalse }
    It 'ignores garbage tags' { foreach ($t in 'latest', 'v', '', 'v1.2.3-beta', '1.2.3.4.5') { Test-VeroNewerVersion -Tag $t -Current '0.1.1' | Should -BeFalse } }
}

Describe 'Get-VeroPath' {
    It 'honours VEROSCUDO_HOME' { (Get-VeroPath).Home | Should -Be $env:VEROSCUDO_HOME }
    It 'keeps the credential per user, outside the shared home' { (Get-VeroPath).Cred | Should -BeLike "$env:LOCALAPPDATA\VeroScudo\cred.xml" }
}
