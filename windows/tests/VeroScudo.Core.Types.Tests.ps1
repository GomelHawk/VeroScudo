# Pester 5 unit tests for VeroScudo.Core: the profile types: OpenVPN, WireGuard, Hiddify and the handler table.
# Pure parts directly; WFP / RAS / firewall calls are mocked (Core.TestSetup.ps1).
BeforeAll { . (Join-Path $PSScriptRoot 'Core.TestSetup.ps1') }
AfterAll { Remove-TestDir; Set-VeroHome $null }

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
    It "pins VeroScudo's own TAP adapter (never another app's), not with DCO" {
        Get-VeroOpenVpnArgs -ConfigPath a -Port 1 -PwFile b -LogPath c -DevNode 'VeroScudo OpenVPN' | Should -Match '--dev-node "VeroScudo OpenVPN"'
        Get-VeroOpenVpnArgs -ConfigPath a -Port 1 -PwFile b -LogPath c -DevNode 'VeroScudo OpenVPN' -Dco $true | Should -Not -Match 'dev-node'
        Get-VeroOpenVpnArgs -ConfigPath a -Port 1 -PwFile b -LogPath c | Should -Not -Match 'dev-node'
    }

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

Describe 'OpenVPN management: one command at a time (2.7.8 dropped the second of two that arrived together - the password)' {
    BeforeAll { $script:t0 = [datetime]'2026-11-05 01:17:06' }
    It 'waits for the management password''s answer before the first command' {
        $q = New-VeroMgmtQueue; $q.SentAt = $script:t0
        Add-VeroMgmtCommand $q 'state on'; Add-VeroMgmtCommand $q 'hold release'
        Update-VeroMgmtQueue $q -Lines @('>INFO:OpenVPN Management Interface Version 6') -Now $script:t0.AddSeconds(1) | Should -BeNullOrEmpty
        Update-VeroMgmtQueue $q -Lines @('SUCCESS: password is correct') -Now $script:t0.AddSeconds(1) | Should -Be 'state on'
    }
    It 'sends username and password one after the other, each after the previous answer' {
        $q = New-VeroMgmtQueue; $q.InFlight = $null
        Add-VeroMgmtCommand $q 'username "Auth" "u"'; Add-VeroMgmtCommand $q 'password "Auth" "p"'
        Update-VeroMgmtQueue $q -Now $script:t0 | Should -Be 'username "Auth" "u"'
        Update-VeroMgmtQueue $q -Lines @(">HOLD:Waiting for hold release:0") -Now $script:t0.AddSeconds(1) | Should -BeNullOrEmpty    # a notification, not an answer
        Update-VeroMgmtQueue $q -Lines @("SUCCESS: 'Auth' username entered, but not yet verified") -Now $script:t0.AddSeconds(1) | Should -Be 'password "Auth" "p"'
        Update-VeroMgmtQueue $q -Lines @("SUCCESS: 'Auth' password entered, but not yet verified") -Now $script:t0.AddSeconds(2) | Should -BeNullOrEmpty
        $q.InFlight | Should -BeNullOrEmpty                                 # the password does not stay in the queue once answered
    }
    It 'an ERROR answer also releases the next command' {
        $q = New-VeroMgmtQueue; $q.InFlight = $null
        Add-VeroMgmtCommand $q 'hold release'; Add-VeroMgmtCommand $q 'state on'
        $null = Update-VeroMgmtQueue $q -Now $script:t0
        Update-VeroMgmtQueue $q -Lines @('ERROR: hold release failed') -Now $script:t0 | Should -Be 'state on'
    }
    It 're-sends a command nobody answered once after 5 s, then goes on with the next' {
        $q = New-VeroMgmtQueue; $q.InFlight = $null
        Add-VeroMgmtCommand $q 'password "Auth" "p"'; Add-VeroMgmtCommand $q 'state on'
        $null = Update-VeroMgmtQueue $q -Now $script:t0
        Update-VeroMgmtQueue $q -Now $script:t0.AddSeconds(4) | Should -BeNullOrEmpty
        Update-VeroMgmtQueue $q -Now $script:t0.AddSeconds(5) | Should -Be 'password "Auth" "p"'
        Update-VeroMgmtQueue $q -Now $script:t0.AddSeconds(10) | Should -Be 'state on'
    }
    It 'never re-sends the management password' {
        $q = New-VeroMgmtQueue; $q.SentAt = $script:t0
        Add-VeroMgmtCommand $q 'state on'
        Update-VeroMgmtQueue $q -Now $script:t0.AddSeconds(5) | Should -Be 'state on'
    }
    It 'a SIGTERM drops what is queued and is not held up by a re-send' {
        $q = New-VeroMgmtQueue; $q.InFlight = $null
        Add-VeroMgmtCommand $q 'username "Auth" "u"'; Add-VeroMgmtCommand $q 'password "Auth" "p"'
        $null = Update-VeroMgmtQueue $q -Now $script:t0
        Add-VeroMgmtCommand $q 'signal SIGTERM' -First
        Update-VeroMgmtQueue $q -Now $script:t0.AddSeconds(5) | Should -Be 'signal SIGTERM'
        $q.Pending.Count | Should -Be 0
    }
    It 'the session sends nothing directly except what the queue releases' {
        $src = (Get-Command Invoke-VeroOpenVpnSession).Definition
        @([regex]::Matches($src, 'Send-VeroMgmt ')).Count | Should -Be 1
        $src | Should -Match 'Send-VeroMgmt \$m \$next'
    }
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
        @{ prev = 'running'; cur = 'missing'; armed = $true;  active = $true;  lock = $true;  want = 'disarm' }   # deactivated in the app during a redial
        @{ prev = 'running'; cur = 'missing'; armed = $true;  active = $true;  lock = $true;  own = $true; want = 'none' }   # our own Reconnect
        @{ prev = 'missing'; cur = 'running'; armed = $false; active = $false; lock = $true;  want = 'none' }     # our own dial after your Off
        @{ prev = 'running'; cur = 'missing'; armed = $false; active = $true;  lock = $false; want = 'none' }     # after our Off
        @{ prev = 'running'; cur = 'stopped'; armed = $true;  active = $true;  lock = $false; want = 'none' }     # crash: a failure, redial
        @{ prev = $null;     cur = 'running'; armed = $false; active = $false; lock = $false; want = 'none' }     # first look after start
    ) { Get-VeroWgTransition -Previous $prev -Current $cur -Armed $armed -Active $active -LockAlive $lock -OwnRemoval ([bool]$own) | Should -Be $want }
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
    AfterAll { Set-VeroArmed $false 'test' }
    BeforeAll {
        Set-VeroArmed $true 'test'                                           # filters are only ever applied to an armed machine
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
        @{ what = 'setenv with a quoted opt';      line = 'setenv "opt" plugin x.dll' }
        @{ what = 'setenv with a single-quoted opt'; line = "setenv 'opt' plugin x.dll" }
        @{ what = 'setenv with an escaped opt';    line = 'setenv o\pt plugin x.dll' }
        @{ what = 'setenv of any other name';      line = 'setenv PATH C:\Users\me' }
        @{ what = 'setenv with more than a value'; line = 'setenv FORWARD_COMPATIBLE 1 plugin' }
        @{ what = 'a line OpenVPN would cut';      line = ('# ' + ('x' * 254) + 'plugin x.dll') }
        @{ what = 'a long line inside a block';    line = ("<ca>`n" + ('-' * 255) + "</ca>`n</ca>") }
        @{ what = 'a NUL character';               line = ("verb 3" + [char]0) }
        @{ what = 'a port out of range';           line = 'port 70000' }
        @{ what = 'an unknown inline block';       line = "<plugin>`nx`n</plugin>" }
    ) { (Test-VeroOpenVpnConf -Text ("remote vpn.example.com`n" + $line)).Errors.Count | Should -BeGreaterThan 0 }
    It 'accepts the setenv lines client configs carry, and one long base64 line inside a block (an inlined pkcs12)' {
        $r = Test-VeroOpenVpnConf -Text ("remote vpn.example.com`nsetenv FORWARD_COMPATIBLE 1`nsetenv CLIENT_CERT 0`nsetenv UV_ID abc-1`n<pkcs12>`n" + ('QUJD' * 200) + "`n</pkcs12>")
        $r.Errors | Should -BeNullOrEmpty
    }
    It 'refuses a key file that would close its block and smuggle options in' {
        $evil = { param($f) $null = $f; [Text.Encoding]::UTF8.GetBytes("-----BEGIN-----`n</ca>`nplugin C:\evil.dll`n<ca>`n-----END-----") }
        (Test-VeroOpenVpnConf -Text "remote vpn.example.com`nca ca.crt" -ReadFile $evil).Errors -join ' ' | Should -Match 'tag line'
    }
    It 'ends an inline block where OpenVPN does (a line starting with the closing tag) and refuses what follows' {
        (Test-VeroOpenVpnConf -Text "remote vpn.example.com`n<ca>`nabc`n</ca>x`nplugin evil.dll").Errors.Count | Should -BeGreaterThan 1
    }
    It 'takes only OpenVPN''s own white space for white space: a tag next to <what> opens no block, and what follows is checked' -ForEach @(
        @{ what = 'a no-break space';      sp = [string][char]0xA0 }
        @{ what = 'an em space';           sp = [string][char]0x2003 }
        @{ what = 'an ideographic space';  sp = [string][char]0x3000 }
        @{ what = 'a next-line character'; sp = [string][char]0x85 }
    ) {
        foreach ($t in @("$sp<ca>`nplugin evil.dll`n$sp</ca>", "<ca>$sp`nplugin evil.dll`n</ca>$sp")) {
            (Test-VeroOpenVpnConf -Text ("remote vpn.example.com`nsetenv FORWARD_COMPATIBLE 1`n" + $t)).Errors -join ' ' | Should -Match "'plugin' is not allowed"
        }
    }
    It 'reads a tag letter for letter: one in capitals opens no block' {
        (Test-VeroOpenVpnConf -Text "remote vpn.example.com`n<CA>`nplugin evil.dll`n</CA>").Errors -join ' ' | Should -Match "'plugin' is not allowed"
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

Describe "VeroScudo's own OpenVPN adapter" {
    It 'uses an existing adapter without running tapctl' {
        Mock -ModuleName VeroScudo.Core Get-VeroNic { [pscustomobject]@{ Name = 'VeroScudo OpenVPN'; Description = 'TAP-Windows Adapter V9 #3'; OperationalStatus = 'Down'; Id = '{00000000-0000-0000-0000-0000000000C3}' } }
        Mock -ModuleName VeroScudo.Core Get-VeroTapctl { throw 'must not be called' }
        Initialize-VeroOpenVpnAdapter -Action 'test' | Should -BeTrue
    }
    It 'falls back (false, one log note) when tapctl.exe is missing' {
        Mock -ModuleName VeroScudo.Core Get-VeroNic { }
        Mock -ModuleName VeroScudo.Core Get-VeroTapctl { '' }
        Initialize-VeroOpenVpnAdapter -Action 'test' | Should -BeFalse
    }
    It 'removes nothing when the adapter does not exist' {
        Mock -ModuleName VeroScudo.Core Get-VeroNic { }
        Mock -ModuleName VeroScudo.Core Get-VeroTapctl { throw 'must not be called' }
        { Remove-VeroOpenVpnAdapter -Action 'test' } | Should -Not -Throw
    }
}

Describe 'profile types: one handler per type (the dispatch table)' {
    It 'every type has every operation, and the values the rest of the module relies on' {
        $keys = 'Label', 'DefaultPort', 'PasswordCapable', 'HasDco', 'OwnLayer', 'HangUpOnOffAlways', 'SwitchNotice', 'IsConnected', 'TunnelLuid',
                'ServerPermit', 'ResolveIps', 'RasTunnelType', 'CrlWindow', 'Dial', 'HangUp', 'DialFailure', 'StatusDetail', 'ForeignText', 'ForeignHangUp',
                'NamePattern', 'NameHint', 'ServerRequired', 'UsernameRequired', 'OnDiskType', 'OnDiskPort', 'OnDiskAuth', 'ServerText'
        foreach ($t in 'ras', 'openvpn', 'wireguard') {
            $h = Get-VeroTypeHandler $t
            foreach ($k in $keys) { $h.ContainsKey($k) | Should -BeTrue -Because "$t.$k" }
            foreach ($k in 'SwitchNotice', 'IsConnected', 'TunnelLuid', 'ServerPermit', 'ResolveIps', 'RasTunnelType', 'CrlWindow', 'Dial', 'HangUp', 'DialFailure', 'StatusDetail', 'ForeignText', 'ForeignHangUp', 'OnDiskAuth', 'ServerText') {
                $h[$k] | Should -BeOfType [scriptblock] -Because "$t.$k"
            }
        }
        (Get-VeroTypeHandler 'ras').Label | Should -Be 'Windows VPN'
        (Get-VeroTypeHandler '').DefaultPort | Should -Be 443                   # '' = the built-in client, like Get-VeroConfigType
        (Get-VeroTypeHandler 'openvpn').DefaultPort | Should -Be 1194
        (Get-VeroTypeHandler 'wireguard').DefaultPort | Should -Be 51820
        (Get-VeroTypeHandler 'wireguard').PasswordCapable | Should -BeFalse
        (Get-VeroTypeHandler 'openvpn').HangUpOnOffAlways | Should -BeTrue
        { Get-VeroTypeHandler 'pptp' } | Should -Throw
    }
    It 'the built-in client never opens a CRL window for the others, and only it has a RAS tunnel type' {
        & (Get-VeroTypeHandler 'wireguard').CrlWindow | Should -BeFalse
        & (Get-VeroTypeHandler 'openvpn').RasTunnelType 'X' | Should -Be 'Automatic'
        & (Get-VeroTypeHandler 'ras').SwitchNotice 'X' | Should -BeNullOrEmpty
        & (Get-VeroTypeHandler 'wireguard').SwitchNotice 'X' | Should -Match 'WireGuard'
    }
}

Describe 'a deleted OpenVPN profile''s stored config and logs go with it (they stayed behind)' {
    It 'picks only VeroScudo''s own files of profiles that are gone' {
        $keep = @('Work-1a2b3c4d', 'ovpn-9f8e7d6c')
        $names = @('Work-1a2b3c4d.ovpn', 'Work-1a2b3c4d.log', 'Work-1a2b3c4d.prev.log',
                   'old-0badf00d.ovpn', 'old-0badf00d.log', 'old-0badf00d.prev.log', 'readme.txt', 'ovpn-9f8e7d6c.ovpn')
        @(Select-VeroStaleOpenVpnFile -Names $names -Keep $keep) | Should -Be @('old-0badf00d.ovpn', 'old-0badf00d.log', 'old-0badf00d.prev.log')
    }
    It 'keeps everything when nothing is gone, and handles an empty folder' {
        @(Select-VeroStaleOpenVpnFile -Names @('Work-1a2b3c4d.ovpn') -Keep @('Work-1a2b3c4d')).Count | Should -Be 0
        @(Select-VeroStaleOpenVpnFile -Names @() -Keep @('Work-1a2b3c4d')).Count | Should -Be 0
    }
    It 'removes the files of a profile that is no longer configured, in the (test) OpenVPN folder only' {
        Mock -ModuleName VeroScudo.Core Write-VeroLog { }
        $d = (Get-VeroPath).OpenVpnDir
        if (-not (Test-IsTestDir $d)) { throw "SAFETY: OpenVPN folder '$d' is not under the test folder" }
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        $kept = (Get-VeroPath -VpnProfile 'Work').OvpnConfig; $gone = (Get-VeroPath -VpnProfile 'Deleted').OvpnConfig
        $goneLog = (Get-VeroPath -VpnProfile 'Deleted').OvpnLog; $other = Join-Path $d 'notes.txt'
        foreach ($x in $kept, $gone, $goneLog, $other) { Set-Content -LiteralPath $x -Value 'x' }
        Remove-VeroStaleOpenVpnFile -Config (Get-VeroConfig -Raw $script:multiJson)
        Test-Path -LiteralPath $kept | Should -BeTrue
        Test-Path -LiteralPath $other | Should -BeTrue
        Test-Path -LiteralPath $gone | Should -BeFalse
        Test-Path -LiteralPath $goneLog | Should -BeFalse
        $gn = Split-Path $gone -Leaf; $gl = Split-Path $goneLog -Leaf             # other tests may leave files too: check these two by name
        Should -Invoke -ModuleName VeroScudo.Core Write-VeroLog -Times 1 -Exactly -ParameterFilter { $Message -like "removed '$gn'*" }
        Should -Invoke -ModuleName VeroScudo.Core Write-VeroLog -Times 1 -Exactly -ParameterFilter { $Message -like "removed '$gl'*" }
        Remove-TestFile $kept, $other
    }
}

Describe 'Import-VeroOpenVpnText: stores a complete config after checking it as a whole' {
    BeforeAll { Mock -ModuleName VeroScudo.Core Protect-VeroOpenVpnDir { } }
    It 'writes the checked text to the profile''s admin copy and refuses a file reference left in it' {
        $text = "client`ndev tun`nremote vpn.example.com 1194`n<ca>`n-----BEGIN CERTIFICATE-----`nAAAA`n-----END CERTIFICATE-----`n</ca>`n"
        $dst = (Get-VeroPath -VpnProfile 'ovpn-text').OvpnConfig
        New-Item -ItemType Directory -Path (Split-Path -Parent $dst) -Force | Out-Null
        $r = Import-VeroOpenVpnText -ProfileName 'ovpn-text' -Text $text
        $r.Remotes.Count | Should -Be 1
        (Get-Content $dst -Raw) | Should -Match 'remote vpn.example.com 1194'
        { Import-VeroOpenVpnText -ProfileName 'ovpn-text' -Text "client`ndev tun`nremote vpn.example.com 1194`nca C:\somewhere\ca.crt`n" } | Should -Throw '*refused*'
        Remove-TestFile $dst
    }
}

Describe 'Hiddify (VPN mode): kill-switch only' {
    BeforeAll {
        $script:cfgH = Get-VeroConfig -Raw '{"profiles":[{"profile":"Hiddify","type":"hiddify"},{"profile":"CorporateVPN","server":"vpn.example.com","username":"u"}],"activeProfile":"Hiddify"}'
        $script:cfgR = Get-VeroConfig -Raw '{"profiles":[{"profile":"CorporateVPN","server":"vpn.example.com","username":"u"}]}'
        $script:tun = [pscustomobject]@{ Name = 'tun0'; Description = 'sing-tun Tunnel'; NetworkInterfaceType = 'Unknown'; OperationalStatus = 'Up'; Id = '{00000000-0000-0000-0000-0000000000D4}' }
        $script:apps = @('C:\Program Files\Hiddify\Hiddify.exe', 'C:\Program Files\Hiddify\HiddifyCli.exe')
    }
    It 'a profile needs no server, username or password, and is stored as type hiddify' {
        $script:cfgH.Profile | Should -Be 'Hiddify'; $script:cfgH.Type | Should -Be 'hiddify'
        Test-VeroNeedsPassword $script:cfgH | Should -BeFalse
        @((ConvertTo-VeroProfileObject @($script:cfgH.Profiles)[0]).Keys) | Should -Be @('profile', 'id', 'type')
    }
    It 'the filters let only the Hiddify programs out - to anywhere, outbound only - plus its tunnel' {
        $t = Get-SpecText (Get-VeroFilterSpec -Config $script:cfgH -PermitKind 'program' -ProgramApps $script:apps -TunnelLuid 77)
        $app = @($t | Where-Object { $_ -like 'VPN app*' })
        $app.Count | Should -Be 4                                              # 2 programs x connect v4/v6
        foreach ($x in $app) { $x | Should -Match "$($script:F.App)=.*Hiddify(Cli)?\.exe"; $x | Should -Not -Match $script:F.Addr; $x | Should -Match 'af043a0a=SYSTEM\+ADMINS' }   # elevated only
        @($t | Where-Object { $_ -like 'VPN server*' }).Count | Should -Be 0
        @($t | Where-Object { $_ -like 'VPN tunnel*' }).Count | Should -Be 4
    }
    It 'no program known: nothing but the tunnel is allowed (never a program-less permit)' {
        $t = Get-SpecText (Get-VeroFilterSpec -Config $script:cfgH -PermitKind 'program' -ProgramApps @())
        @($t | Where-Object { $_ -like 'VPN app*' -or $_ -like 'VPN server*' }).Count | Should -Be 0
    }
    It 'the permit comes from the programs in an administrators-only folder' {
        Mock -ModuleName VeroScudo.Core Get-VeroHiddifyApps { $script:apps }
        $p = InModuleScope VeroScudo.Core { Get-VeroHiddifyPermit -Config (Get-VeroConfig -Raw '{"profiles":[{"profile":"Hiddify","type":"hiddify"}]}') }
        $p.Kind | Should -Be 'program'; @($p.Apps).Count | Should -Be 2; @($p.Ips).Count | Should -Be 0
    }
    It 'connected = Hiddify runs and its sing-tun adapter is up; the tunnel is that adapter' {
        # the LUID comes from the real ConvertInterfaceGuidToLuid: give the fake adapter the GUID of an interface this machine
        # has (a GUID from another PC fails with 87 - it did on the CI runner)
        $real = InModuleScope VeroScudo.Core {
            Import-VeroNative
            foreach ($n in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
                $g = [guid]::Empty
                if ([guid]::TryParse($n.Id, [ref]$g)) { try { [pscustomobject]@{ Id = "{$g}"; Luid = [VeroScudo.Iface]::LuidFromGuid($g) }; break } catch { $null = $_ } }
            }
        }
        $real | Should -Not -BeNullOrEmpty
        $script:tunReal = $script:tun.PSObject.Copy(); $script:tunReal.Id = $real.Id
        Mock -ModuleName VeroScudo.Core Get-VeroNic { $script:tunReal }
        Mock -ModuleName VeroScudo.Core Get-Process { [pscustomobject]@{ Name = 'Hiddify'; Id = 1 } }
        Test-VeroVpnConnected 'Hiddify' -Type 'hiddify' | Should -BeTrue
        Get-VeroTunnelLuid 'Hiddify' -Type 'hiddify' | Should -Be $real.Luid
        Mock -ModuleName VeroScudo.Core Get-Process { }
        Test-VeroVpnConnected 'Hiddify' -Type 'hiddify' | Should -BeFalse          # adapter left behind, app gone: not a tunnel
        Get-VeroTunnelLuid 'Hiddify' -Type 'hiddify' | Should -Be 0
    }
    It 'VeroScudo never dials or hangs up Hiddify' {
        Mock -ModuleName VeroScudo.Core Test-VeroHiddifyConnected { $true }
        { Invoke-VeroDial -Config $script:cfgH -Action 'test' } | Should -Not -Throw
        InModuleScope VeroScudo.Core { & (Get-VeroTypeHandler 'hiddify').HangUp 'Hiddify' } | Should -BeNullOrEmpty
    }
    It "is detected as 'Hiddify (VPN mode)' when another profile is active (sing-tun was not recognised at all)" {
        Mock -ModuleName VeroScudo.Core Get-VeroWindowsVpn { }
        Mock -ModuleName VeroScudo.Core Get-Service { }
        Mock -ModuleName VeroScudo.Core Get-Process { }
        Mock -ModuleName VeroScudo.Core Get-VeroNic { $script:tun }
        InModuleScope VeroScudo.Core -Parameters @{ N = $script:tun } { param($N) Test-VeroTunnelAdapter $N } | Should -BeTrue
        $f = @(Get-VeroForeignVpn -Config $script:cfgR)
        $f.Count | Should -Be 1; $f[0].Kind | Should -Be 'hiddify'; $f[0].Name | Should -Be 'Hiddify (VPN mode)'; $f[0].CanDisconnect | Should -BeFalse
        Format-VeroForeignVpn $f[0] | Should -Match 'Hiddify is connected in VPN mode \(not a VeroScudo profile\)'
        @(Get-VeroForeignVpn -Config $script:cfgH).Count | Should -Be 0              # the active profile's own tunnel
    }
    It "its own WFP layer is expected while it is the active profile, a warning otherwise" {
        @(Select-VeroForeignWfp -Type 'hiddify' -Providers @('sing-box')).Count | Should -Be 0
        @(Select-VeroForeignWfp -Type 'ras' -Providers @('sing-box')).Count | Should -Be 1
    }
    It 'Off leaves Hiddify as it is and does not claim to have disconnected it (it logged "disconnected")' {
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $true }
        Mock -ModuleName VeroScudo.Core Invoke-VeroHangUp { throw 'must not hang up Hiddify' }
        Mock -ModuleName VeroScudo.Core Disable-VeroKillSwitch { }
        Mock -ModuleName VeroScudo.Core Write-VeroLog { $script:hidLog += @($Message) }
        $script:hidLog = @()
        Invoke-VeroAction -Action off -Config $script:cfgH
        @($script:hidLog | Where-Object { $_ -match 'disconnected' }).Count | Should -Be 0
        @($script:hidLog | Where-Object { $_ -match 'Hiddify stays as it is' }).Count | Should -Be 1
    }
    It 'turns on when Hiddify connects (an edge, like a Windows VPN you connect yourself) - never right after Off' {
        Mock -ModuleName VeroScudo.Core Invoke-VeroArmConnected { }
        Mock -ModuleName VeroScudo.Core Test-VeroArmed { $false }
        Mock -ModuleName VeroScudo.Core Test-VeroLockAlive { $false }
        Mock -ModuleName VeroScudo.Core Test-VeroRecentOff { $false }
        Mock -ModuleName VeroScudo.Core Get-VeroConfig { $script:cfgH }
        InModuleScope VeroScudo.Core { $script:HiddifySeen = $null }
        Mock -ModuleName VeroScudo.Core Test-VeroHiddifyConnected { $false }
        Update-VeroHiddifyWatch -Config $script:cfgH | Should -BeFalse                  # first look
        Mock -ModuleName VeroScudo.Core Test-VeroHiddifyConnected { $true }
        Update-VeroHiddifyWatch -Config $script:cfgH | Should -BeTrue                   # came up
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroArmConnected -Times 1 -Exactly
        Update-VeroHiddifyWatch -Config $script:cfgH | Should -BeFalse                  # still up: no edge
        Mock -ModuleName VeroScudo.Core Test-VeroHiddifyConnected { $false }
        Update-VeroHiddifyWatch -Config $script:cfgH | Out-Null
        Mock -ModuleName VeroScudo.Core Test-VeroHiddifyConnected { $true }
        Mock -ModuleName VeroScudo.Core Test-VeroRecentOff { $true }
        Update-VeroHiddifyWatch -Config $script:cfgH | Should -BeFalse                  # just turned off: stays off
    }
    It 'reads the mode from Hiddify settings: only VPN mode can be protected' {
        $ad = Join-Path (Get-VeroPath).State 'hiddify-appdata'
        New-Item -ItemType Directory -Path (Join-Path $ad 'Hiddify\hiddify') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $ad 'Hiddify\hiddify\shared_preferences.json') -Value '{"flutter.service-mode":"vpn","flutter.locale":"en"}'
        Get-VeroHiddifyMode -AppData $ad | Should -Be 'vpn'
        Set-Content -LiteralPath (Join-Path $ad 'Hiddify\hiddify\shared_preferences.json') -Value '{"flutter.service-mode":"proxy"}'
        Get-VeroHiddifyMode -AppData $ad | Should -Be 'proxy'
        Get-VeroHiddifyMode -AppData (Join-Path $ad 'nothing') | Should -BeNullOrEmpty
        Remove-TestFile @(Join-Path $ad 'Hiddify\hiddify\shared_preferences.json')
    }
}

Describe 'the management password goes only to the OpenVPN that was started' {
    It 'knows which process is at the other end of a loopback connection' {
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
        $l.Start()
        $c = New-Object System.Net.Sockets.TcpClient
        try {
            $c.Connect([System.Net.IPAddress]::Loopback, $l.LocalEndpoint.Port)
            $srv = $l.AcceptTcpClient()                                        # the other end: this very process
            & (Get-Module VeroScudo.Core) { param($s, $id) Test-VeroPeerProcess -Socket $s -ProcessId $id } $c.Client $PID | Should -BeTrue
            & (Get-Module VeroScudo.Core) { param($s, $id) Test-VeroPeerProcess -Socket $s -ProcessId $id } $c.Client 4 | Should -BeFalse
            $srv.Close()
        } finally { $c.Close(); $l.Stop() }
    }
}

Describe 'every profile type answers the guard''s questions' {
    It '<type> has every handler key the shared code asks for' -ForEach @(@{ type = 'ras' }, @{ type = 'openvpn' }, @{ type = 'wireguard' }, @{ type = 'hiddify' }) {
        $h = Get-VeroTypeHandler $type
        foreach ($k in 'Label', 'Dials', 'ProbeTls', 'RelookupOnFail', 'WatchAlways', 'Watch', 'OnArmConnected', 'OnReconnected', 'IsConnected', 'TunnelLuid',
                       'ServerPermit', 'ResolveIps', 'Dial', 'HangUp', 'DialFailure', 'StatusDetail', 'ForeignText', 'ForeignHangUp', 'HangUpOnOffAlways') {
            $h.ContainsKey($k) | Should -BeTrue -Because "$type.$k"
        }
        foreach ($k in 'OnArmConnected', 'OnReconnected', 'Dial', 'HangUp') { $h[$k] | Should -BeOfType [scriptblock] }
    }
    It 'arming goes through one function and disarming through another' {
        $src = Get-ChildItem (Join-Path $PSScriptRoot '..\Core') -Filter *.ps1 | ForEach-Object { Get-Content $_.FullName }
        @($src | Where-Object { $_ -match 'Set-VeroArmed \$true' -and $_ -notmatch '^\s*#' }).Count | Should -Be 1 -Because 'only Enter-VeroArmed sets the flag'
        @($src | Where-Object { $_ -match 'Set-VeroArmed \$false' -and $_ -notmatch '^\s*#' }).Count | Should -Be 1 -Because 'only Exit-VeroArmed clears it'
    }
}

Describe 'OpenVPN config check: values that are not files, and what it warns about' {
    It 'accepts a fingerprint and "dh none" as values' {
        $fp = (1..32 | ForEach-Object { 'AB' }) -join ':'
        $r = Test-VeroOpenVpnConf -Text "remote vpn.example.com`npeer-fingerprint $fp`ndh none" -ReadFile { param($x) throw "read $x" }
        $r.Errors | Should -BeNullOrEmpty
    }
    It 'warns when nothing says which server certificate to accept, and about encryption switched off' {
        $r = Test-VeroOpenVpnConf -Text "client`nremote vpn.example.com`ncipher none"
        ($r.Warnings -join ' ') | Should -Match 'which server certificate'
        ($r.Warnings -join ' ') | Should -Match 'cipher none'
        $ok = Test-VeroOpenVpnConf -Text "client`nremote vpn.example.com`nremote-cert-tls server"
        ($ok.Warnings -join ' ') | Should -Not -Match 'which server certificate'
    }
}

Describe 'WireGuard: nothing arms by itself right after Off' {
    It 'a tunnel that starts within the Off window does not arm' {
        & (Get-Module VeroScudo.Core) { Get-VeroWgTransition -Previous 'stopped' -Current 'running' -Armed $false -Active $true -LockAlive $false -RecentOff $true } | Should -Be 'none'
        & (Get-Module VeroScudo.Core) { Get-VeroWgTransition -Previous 'stopped' -Current 'running' -Armed $false -Active $true -LockAlive $false -RecentOff $false } | Should -Be 'arm'
    }
}

Describe 'a Hiddify profile whose programs are not in an administrators-only folder' {
    It 'gets a permit with no program at all, and says so once' {
        Mock -ModuleName VeroScudo.Core Get-VeroHiddifyApps { @() }
        Mock -ModuleName VeroScudo.Core Write-VeroLog { }
        $cfg = Get-VeroConfig -Raw '{"profiles":[{"profile":"Hiddify","type":"hiddify"}]}'
        $a = & (Get-Module VeroScudo.Core) { param($c) Get-VeroHiddifyPermit -Config $c -Action test } $cfg
        $b = & (Get-Module VeroScudo.Core) { param($c) Get-VeroHiddifyPermit -Config $c -Action test } $cfg
        @($a.Apps).Count | Should -Be 0; $a.Kind | Should -Be 'program'; @($b.Apps).Count | Should -Be 0
        Should -Invoke -ModuleName VeroScudo.Core Write-VeroLog -Times 1 -Exactly
    }
}

Describe 'OpenVPN: the one-time code and when the runner stops' {
    BeforeAll {
        Set-VeroHome $script:TestHomeDir -UserDir (Join-Path $script:TestHomeDir 'user')
        if (-not (Test-IsTestDir (Get-VeroPath).UserDir)) { throw 'SAFETY: user folder outside the test folder' }
        New-Item -ItemType Directory -Path (Get-VeroPath).UserDir -Force | Out-Null
        Mock -ModuleName VeroScudo.Core Set-VeroOpenVpnStatus { }
        Mock -ModuleName VeroScudo.Core Write-VeroLog { }
    }
    AfterAll { Set-VeroHome $script:TestHomeDir }
    It 'takes the code typed after the question, not one left from an earlier question' {
        $p = Get-VeroPath -VpnProfile 'ovpn'
        if (-not (Test-IsTestDir $p.Otp)) { throw 'SAFETY: code file outside the test folder' }
        Set-Content -Path $p.Otp -Value '111111' -Encoding UTF8                          # left from before
        (Get-Item $p.Otp).LastWriteTimeUtc = [datetime]::UtcNow.AddMinutes(-5)
        $script:asked = 0
        Mock -ModuleName VeroScudo.Core Get-VeroOpenVpnStopReason { $null }
        Mock -ModuleName VeroScudo.Core Start-Sleep {
            $script:asked++
            if ($script:asked -eq 2) { Set-Content -Path (Get-VeroPath -VpnProfile 'ovpn').Otp -Value '654321' -Encoding UTF8 }   # typed now
            if ($script:asked -gt 20) { throw 'the code was never taken' }
        }
        & (Get-Module VeroScudo.Core) { Wait-VeroOtp -ProfileName 'ovpn' -Challenge 'Code' -Action test } | Should -Be '654321'
        Test-Path $p.Otp | Should -BeTrue                                                  # read, never deleted by the guard
        Remove-TestFile $p.Otp
    }
    It 'gives up when VeroScudo is turned off meanwhile' {
        Mock -ModuleName VeroScudo.Core Get-VeroOpenVpnStopReason { 'VPN turned off' }
        Mock -ModuleName VeroScudo.Core Start-Sleep { }
        & (Get-Module VeroScudo.Core) { Wait-VeroOtp -ProfileName 'ovpn' -Challenge 'Code' -Action test } | Should -BeNullOrEmpty
    }
    It 'the runner stops on a stop request, on Off and on a switch to another profile - and for nothing else' {
        Mock -ModuleName VeroScudo.Core Get-VeroConfig { [pscustomobject]@{ Profile = 'ovpn' } }
        $p = Get-VeroPath -VpnProfile 'ovpn'
        Remove-TestFile $p.OvpnStop
        Set-VeroArmed $true 'test'
        & (Get-Module VeroScudo.Core) { Get-VeroOpenVpnStopReason 'ovpn' } | Should -BeNullOrEmpty
        & (Get-Module VeroScudo.Core) { Get-VeroOpenVpnStopReason 'other' } | Should -Be "profile switched to 'ovpn'"
        Set-VeroArmed $false 'test'
        & (Get-Module VeroScudo.Core) { Get-VeroOpenVpnStopReason 'ovpn' } | Should -Be 'VPN turned off'
        Set-Content -Path $p.OvpnStop -Value 'x'
        & (Get-Module VeroScudo.Core) { Get-VeroOpenVpnStopReason 'ovpn' } | Should -Be 'stop requested'
        Remove-TestFile $p.OvpnStop
    }
}

Describe 'WireGuard health as the tray sees it (it cannot read the handshakes itself)' {
    BeforeAll {
        Mock -ModuleName VeroScudo.Core Test-VeroElevated { $false }
        $script:cacheF = (Get-VeroPath -VpnProfile 'wg').TunnelCache
    }
    AfterEach { Remove-TestFile $script:cacheF; Set-VeroArmed $false 'test' }
    It 'no service: down' {
        Mock -ModuleName VeroScudo.Core Get-VeroWgState { 'stopped' }
        & (Get-Module VeroScudo.Core) { Get-VeroWgHealthNow 'wg' } | Should -Be 'down'
    }
    It 'takes the guard''s fresh verdict; none yet: the service runs, up' {
        Mock -ModuleName VeroScudo.Core Get-VeroWgState { 'running' }
        & (Get-Module VeroScudo.Core) { Get-VeroWgHealthNow 'wg' } | Should -Be 'up'
        Set-Content -Path $script:cacheF -Value (@{ Health = 'stale'; Time = (Get-Date).ToString('o') } | ConvertTo-Json)
        & (Get-Module VeroScudo.Core) { Get-VeroWgHealthNow 'wg' } | Should -Be 'stale'
    }
    It 'a verdict the guard stopped renewing is not "healthy" while VeroScudo is on' {
        Mock -ModuleName VeroScudo.Core Get-VeroWgState { 'running' }
        Set-Content -Path $script:cacheF -Value (@{ Health = 'up'; Time = (Get-Date).AddMinutes(-10).ToString('o') } | ConvertTo-Json)
        & (Get-Module VeroScudo.Core) { Get-VeroWgHealthNow 'wg' } | Should -Be 'up'       # off: nobody judges the link
        Set-VeroArmed $true 'test'
        & (Get-Module VeroScudo.Core) { Get-VeroWgHealthNow 'wg' } | Should -Be 'stale'
    }
}
