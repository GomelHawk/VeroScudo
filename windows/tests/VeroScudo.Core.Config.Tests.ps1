# Pester 5 unit tests for VeroScudo.Core: config.json, paths, profile ids, the Windows VPN import and the tray's elevated Save.
# Pure parts directly; WFP / RAS / firewall calls are mocked (Core.TestSetup.ps1).
BeforeAll { . (Join-Path $PSScriptRoot 'Core.TestSetup.ps1') }
AfterAll { Remove-TestDir; Set-VeroHome $null }

Describe 'Get-VeroConfig' {
    AfterEach { Remove-TestFile (Get-VeroPath).ActiveProfile }
    It 'reads the 1.0 single-profile format and applies defaults' {
        $c = Get-VeroConfig -Raw $script:cfgJson
        $c.Profile | Should -Be 'MyVPN'; $c.Port | Should -Be 443; $c.RetrySeconds | Should -Be 7
        $c.Vm | Should -BeTrue; $c.WifiRecoveryFix | Should -BeTrue; $c.LanAllow.Count | Should -Be 0
        @($c.Profiles).Count | Should -Be 1
    }
    It 'defaults port, retry, vm and updateCheck when omitted' {
        $c = Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"s","username":"u"}}'
        $c.Port | Should -Be 443; $c.RetrySeconds | Should -Be 10; $c.Vm | Should -BeTrue; $c.UpdateCheck | Should -BeTrue
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
        @{ what = 'a serverIps that is a number'; json = '{"vpn":{"profile":"X","server":"s","username":"u","serverIps":["1"]}}'; msg = '*serverIps*' }
        @{ what = 'a serverIps with a zone'; json = '{"vpn":{"profile":"X","server":"s","username":"u","serverIps":["fe80::1%5"]}}'; msg = '*serverIps*' }
        @{ what = 'a serverIps that is a range'; json = '{"vpn":{"profile":"X","server":"s","username":"u","serverIps":["10.0.0.0/8"]}}'; msg = '*serverIps*' }
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

Describe 'Get-VeroConfig: vm is one on/off setting on every platform' {
    It '<raw> -> <want>' -ForEach @(
        @{ raw = ''; want = $true }, @{ raw = ',"vm":"auto"'; want = $true }, @{ raw = ',"vm":true'; want = $true }, @{ raw = ',"vm":false'; want = $false }
    ) {
        (Get-VeroConfig -Raw ('{"profiles":[{"profile":"W","server":"vpn.example.com","username":"u"}]' + $raw + '}')).Vm | Should -Be $want
    }
    It 'refuses anything else' { { Get-VeroConfig -Raw '{"profiles":[{"profile":"W","server":"vpn.example.com","username":"u"}],"vm":"maybe"}' } | Should -Throw }
    It 'not protected: the Default Switch stays open for its VMs even while blocked; protected: only while up' {
        $off = Get-VeroConfig -Raw '{"profiles":[{"profile":"W","server":"vpn.example.com","username":"u"}],"vm":false}'
        $on = Get-VeroConfig -Raw '{"profiles":[{"profile":"W","server":"vpn.example.com","username":"u"}],"vm":true}'
        @(Get-SpecText (Get-VeroFilterSpec -Config $off -ServerIps @('203.0.113.5') -SwitchLuid 77 -TunnelType 'Sstp') | Where-Object { $_ -like 'Default Switch*' }).Count | Should -Be 4
        @(Get-SpecText (Get-VeroFilterSpec -Config $on -ServerIps @('203.0.113.5') -SwitchLuid 77 -TunnelType 'Sstp') | Where-Object { $_ -like 'Default Switch*' }).Count | Should -Be 0
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
        # the installed layout: paths are only computed here, nothing is read or written
        Set-VeroHome $null
        try { $a = (Get-VeroPath -VpnProfile 'Work').Cred; $b = (Get-VeroPath -VpnProfile 'Backup').Cred } finally { Set-VeroHome $script:TestHomeDir }
        $a | Should -BeLike "$env:LOCALAPPDATA\VeroScudo\cred-*.xml"; $a | Should -Not -Be $b
    }
    It 'a redirected home takes the user folder with it' {
        (Get-VeroPath).UserDir | Should -Be (Join-Path $script:TestHomeDir 'user')
        (Get-VeroPath -VpnProfile 'Work').Cred | Should -BeLike (Join-Path $script:TestHomeDir 'user\cred-*.xml')
    }
    It 'keeps tray-writable files in the user folder' {
        Set-VeroHome $null                                                  # the installed layout: paths only, nothing read or written
        try { $inst = Get-VeroPath } finally { Set-VeroHome $script:TestHomeDir }
        $inst.SwitchRequest | Should -BeLike "$env:LOCALAPPDATA\VeroScudo\*"
        $inst.UpdateFile | Should -BeLike "$env:LOCALAPPDATA\VeroScudo\*"
    }
}

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

Describe 'Import-VeroSavePayload: the elevated half of the tray''s Save reads one file, text only' {
    BeforeAll {
        Mock -ModuleName VeroScudo.Core Import-VeroOpenVpnText { }
        Mock -ModuleName VeroScudo.Core Save-VeroConfig { }
        Mock -ModuleName VeroScudo.Core Remove-VeroStaleOpenVpnFile { }
    }
    It 'imports every OpenVPN text, saves the config, then removes what deleted profiles left' {
        $f = Join-Path (Get-VeroPath).State 'payload.json'
        $script:twoJson = '{"profiles":[{"profile":"MyVPN","server":"vpn.example.com","port":443,"username":"jdoe"},{"profile":"ovpn","type":"openvpn"}]}'
        @{ Config = $script:twoJson; Imports = @(@{ Profile = 'ovpn'; Text = "client`nremote vpn.example.com" }) } | ConvertTo-Json -Depth 4 | Set-Content $f
        Import-VeroSavePayload -Path $f -Sha256 (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash
        Should -Invoke -ModuleName VeroScudo.Core Import-VeroOpenVpnText -Times 1 -Exactly -ParameterFilter { $ProfileName -eq 'ovpn' -and $Text -eq "client`nremote vpn.example.com" }
        Should -Invoke -ModuleName VeroScudo.Core Save-VeroConfig -Times 1 -Exactly -ParameterFilter { $Json -eq $script:twoJson }
        Should -Invoke -ModuleName VeroScudo.Core Remove-VeroStaleOpenVpnFile -Times 1 -Exactly -ParameterFilter { @($Config.Profiles).Count -eq 2 -and $Config.Profiles[0].Profile -eq 'MyVPN' }
        Remove-TestFile $f
    }
    It 'stores no OpenVPN text for a name that is not an OpenVPN profile of the config, and none when the config is refused' {
        $f = Join-Path (Get-VeroPath).State 'payload5.json'
        @{ Config = $script:cfgJson; Imports = @(@{ Profile = 'ovpn'; Text = "client`ndev tun" }) } | ConvertTo-Json -Depth 4 | Set-Content $f
        { Import-VeroSavePayload -Path $f -Sha256 (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash } | Should -Throw '*not an OpenVPN profile*'
        @{ Config = '{"profiles":[{"profile":"ovpn","type":"openvpn"}],"retrySeconds":1}'; Imports = @(@{ Profile = 'ovpn'; Text = "client`ndev tun" }) } | ConvertTo-Json -Depth 4 | Set-Content $f
        { Import-VeroSavePayload -Path $f -Sha256 (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash } | Should -Throw '*retrySeconds*'
        Should -Invoke -ModuleName VeroScudo.Core Import-VeroOpenVpnText -Times 0 -Exactly
        Should -Invoke -ModuleName VeroScudo.Core Save-VeroConfig -Times 0 -Exactly
        Remove-TestFile $f
    }
    It 'a save that fails removes nothing' {
        Mock -ModuleName VeroScudo.Core Save-VeroConfig { throw 'invalid config' }
        $f = Join-Path (Get-VeroPath).State 'payload3.json'
        @{ Config = $script:cfgJson; Imports = @() } | ConvertTo-Json -Depth 4 | Set-Content $f
        { Import-VeroSavePayload -Path $f -Sha256 (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash } | Should -Throw '*invalid config*'
        Should -Invoke -ModuleName VeroScudo.Core Remove-VeroStaleOpenVpnFile -Times 0 -Exactly
        Remove-TestFile $f
    }
    It 'a payload that is not the approved one (swapped after the prompt) is refused before anything is read from it' {
        $f = Join-Path (Get-VeroPath).State 'payload4.json'
        @{ Config = $script:cfgJson; Imports = @() } | ConvertTo-Json -Depth 4 | Set-Content $f
        $approved = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash
        @{ Config = $script:cfgJson; Imports = @(@{ Profile = 'ovpn'; Text = 'client' }) } | ConvertTo-Json -Depth 4 | Set-Content $f
        { Import-VeroSavePayload -Path $f -Sha256 $approved } | Should -Throw '*not the one that was approved*'
        { Import-VeroSavePayload -Path $f -Sha256 'abc' } | Should -Throw '*not the one that was approved*'
        Should -Invoke -ModuleName VeroScudo.Core Save-VeroConfig -Times 0 -Exactly
        Should -Invoke -ModuleName VeroScudo.Core Import-VeroOpenVpnText -Times 0 -Exactly
        Remove-TestFile $f
    }
    It 'stores none of the OpenVPN texts when one of them is refused' {
        $f = Join-Path (Get-VeroPath).State 'payload6.json'
        $cfg2 = '{"profiles":[{"profile":"a","type":"openvpn"},{"profile":"b","type":"openvpn"}]}'
        @{ Config = $cfg2; Imports = @(@{ Profile = 'a'; Text = "client`nremote vpn.example.com" }, @{ Profile = 'b'; Text = "remote vpn.example.com`nplugin x.dll" }) } | ConvertTo-Json -Depth 4 | Set-Content $f
        { Import-VeroSavePayload -Path $f -Sha256 (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash } | Should -Throw "*'b' refused*"
        Should -Invoke -ModuleName VeroScudo.Core Import-VeroOpenVpnText -Times 0 -Exactly
        Remove-TestFile $f
    }
    It 'a payload without a config, or no file, is refused before anything is written' {
        $f = Join-Path (Get-VeroPath).State 'payload2.json'
        '{"Imports":[]}' | Set-Content $f
        { Import-VeroSavePayload -Path $f -Sha256 (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash } | Should -Throw '*without a config*'
        { Import-VeroSavePayload -Path (Join-Path (Get-VeroPath).State 'missing.json') -Sha256 ('0' * 64) } | Should -Throw
        Should -Invoke -ModuleName VeroScudo.Core Save-VeroConfig -Times 0 -Exactly
        Remove-TestFile $f
    }
}

Describe 'profile types: validation and on-disk form come from the handler table' {
    It 'WireGuard names follow the app rule, OpenVPN needs no server, the built-in client needs a username unless auth is off' {
        { Get-VeroConfig -Raw '{"profiles":[{"profile":"bad name!","type":"wireguard","server":"wg.example.com"}]}' } | Should -Throw '*WireGuard tunnel name*'
        { Get-VeroConfig -Raw '{"profiles":[{"profile":"ovpn","type":"openvpn"}]}' } | Should -Not -Throw
        { Get-VeroConfig -Raw '{"profiles":[{"profile":"Work","server":"vpn.example.com"}]}' } | Should -Throw '*username is required*'
        { Get-VeroConfig -Raw '{"profiles":[{"profile":"Work","server":"vpn.example.com","auth":false}]}' } | Should -Not -Throw
        { Get-VeroConfig -Raw '{"profiles":[{"profile":"wg","type":"wireguard"}]}' } | Should -Throw '*server is required*'
    }
    It 'on disk: the built-in client stays implicit, OpenVPN carries auth and dco, WireGuard its port' {
        $ras = ConvertTo-VeroProfileObject ([pscustomobject]@{ Profile = 'Work'; Type = 'ras'; Server = 'vpn.example.com'; Port = 443; Username = 'u'; ServerIps = @(); Auth = $false })
        @($ras.Keys) | Should -Be @('profile', 'id', 'server', 'port', 'username', 'auth')
        $o = ConvertTo-VeroProfileObject ([pscustomobject]@{ Profile = 'ovpn'; Type = 'openvpn'; Server = ''; Port = 1194; Username = ''; ServerIps = @(); Auth = $true; Dco = $true })
        @($o.Keys) | Should -Be @('profile', 'id', 'type', 'auth', 'dco')
        $w = ConvertTo-VeroProfileObject ([pscustomobject]@{ Profile = 'wg'; Type = 'wireguard'; Server = 'wg.example.com'; Port = 51820; Username = ''; ServerIps = @('203.0.113.5'); Auth = $false })
        @($w.Keys) | Should -Be @('profile', 'id', 'type', 'server', 'port', 'serverIps')
    }
}
