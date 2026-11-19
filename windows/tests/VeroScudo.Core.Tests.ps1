# Pester 5 unit tests for VeroScudo.Core: arming, events, redial, Off, locks, state files, credentials and what runs elevated.
# Pure parts directly; WFP / RAS / firewall calls are mocked (Core.TestSetup.ps1).
BeforeAll { . (Join-Path $PSScriptRoot 'Core.TestSetup.ps1') }
AfterAll { Remove-TestDir; Set-VeroHome $null }

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
        Mock -ModuleName VeroScudo.Core Invoke-VeroDnsFirst { [void]$script:steps.Add('dns') }
        Invoke-VeroAction -Action reconnect -Config $script:cfgR
        @($script:steps) | Should -Be @('block', 'hangup', 'sync', 'dns', 'dial', 'sync')
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
    It 'takes a marker that could not be read (empty, half-written) by the file''s own time, for any profile' {
        $f = (Get-VeroPath).Renew
        Set-Content -Path $f -Value ''
        $m = Get-VeroRenewMarker
        $m | Should -Not -BeNullOrEmpty
        Test-VeroRenewHangUp -Marker $m -ProfileName 'Work' -EventTime (Get-Date) -Now (Get-Date) | Should -BeTrue
        Test-VeroRenewHangUp -Marker $m -ProfileName 'Work' -EventTime (Get-Date).AddMinutes(10) -Now (Get-Date).AddMinutes(10) | Should -BeFalse
        Remove-TestFile $f
    }
    It 'ignores no marker' { Test-VeroRenewHangUp -Marker $null -ProfileName 'Work' -EventTime $script:now | Should -BeFalse }
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

Describe 'another VPN connected (Turn on asks, never decides)' {
    BeforeAll {
        $script:cfgF = Get-VeroConfig -Raw '{"profiles":[{"profile":"CorporateVPN","server":"vpn.example.com","username":"u"},{"profile":"Backup","server":"b.example.com","username":"u"}],"activeProfile":"CorporateVPN"}'
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
        $script:ras = @([pscustomobject]@{ Name = 'PrivateVPN'; Connected = $true }, [pscustomobject]@{ Name = 'CorporateVPN'; Connected = $true }, [pscustomobject]@{ Name = 'Idle'; Connected = $false })
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
    It "does not list VeroScudo's own OpenVPN adapter as a VPN app (tray in another session)" {
        $script:ras = @()
        $c = Get-VeroConfig -Raw '{"profiles":[{"profile":"Ovpn","type":"openvpn","username":"u"},{"profile":"CorporateVPN","server":"vpn.example.com","username":"u"}],"activeProfile":"Ovpn"}'
        $own = [pscustomobject]@{ Name = 'PrivateVPN'; Description = 'TAP-Windows Adapter V9'; NetworkInterfaceType = 'Ethernet'; OperationalStatus = 'Up'; Id = '{00000000-0000-0000-0000-0000000000A1}' }
        $other = [pscustomobject]@{ Name = 'Other'; Description = 'TAP-Windows Adapter V9 #2'; NetworkInterfaceType = 'Ethernet'; OperationalStatus = 'Up'; Id = '{00000000-0000-0000-0000-0000000000B2}' }
        Mock -ModuleName VeroScudo.Core Get-VeroNic { $own, $other }
        Mock -ModuleName VeroScudo.Core Test-VeroOpenVpnRunnerAlive { $false }              # the tray cannot see the runner's lock
        Mock -ModuleName VeroScudo.Core Get-VeroOpenVpnNic { if ($ProfileName -eq 'Ovpn') { $own } }
        $f = @(Get-VeroForeignVpn -Config $c)
        @($f | Where-Object Id -eq 'PrivateVPN').Count | Should -Be 0
        @($f | Where-Object Id -eq 'Other').Count | Should -Be 1
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
        (Get-VeroConfig -Raw '{"profiles":[{"profile":"CorporateVPN","server":"vpn.example.com","username":"u"}]}').Profile | Should -Be 'CorporateVPN'
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

Describe 'Windows'' own tunnel adapters, OS-resolved system folders, native record' {
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

Describe 'On while already on, and vendor tunnels' {
    BeforeAll {
        $script:cfgR2 = Get-VeroConfig -Raw '{"profiles":[{"profile":"CorporateVPN","server":"vpn.example.com","username":"u"}]}'
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

Describe 'executables by full System32 path, and the CRL window' {
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

Describe 'IKEv2 connects (only RasClient 20225, no RasMan 20267)' {
    BeforeAll {
        $script:cfgI = Get-VeroConfig -Raw '{"profiles":[{"profile":"PrivateVPN","server":"vpn.private.example.com","username":"u"}]}'
        Mock -ModuleName VeroScudo.Core Sync-VeroKillSwitch { }
        Mock -ModuleName VeroScudo.Core Get-VeroTunnelType { 'Ikev2' }
        Mock -ModuleName VeroScudo.Core Get-VeroRasConnected { 'PrivateVPN' }
        Mock -ModuleName VeroScudo.Core Get-VeroRasConnectedRecord { [pscustomobject]@{ Profile = 'PrivateVPN'; CoId = '{11111111-2222-3333-4444-555555555555}'; Time = (Get-Date) } }
    }
    BeforeEach { Set-VeroArmed $false 'test'; Remove-TestFile (Get-VeroPath).RasCoId }
    AfterAll { Set-VeroArmed $false 'test'; Remove-TestFile (Get-VeroPath).RasCoId }
    It 'arms when the configured profile really is connected, and records its connection id' {
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $true }
        Invoke-VeroAction -Action arm -Config $script:cfgI
        Test-VeroArmed | Should -BeTrue
        (Get-Content (Get-VeroPath).RasCoId -Raw | ConvertFrom-Json).CoId | Should -Be '{11111111-2222-3333-4444-555555555555}'
        Should -Invoke -ModuleName VeroScudo.Core Get-VeroRasConnectedRecord -ParameterFilter { $AllowApplicationLog } -Times 1 -Exactly
    }
    It 'does not arm on a (forged) connect record while that profile is not connected' {
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $false }
        Invoke-VeroAction -Action arm -Config $script:cfgI
        Test-VeroArmed | Should -BeFalse
    }
    It 'the manual disconnect afterwards (631 with that id) turns VeroScudo off' {
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $true }
        Invoke-VeroAction -Action arm -Config $script:cfgI
        InModuleScope VeroScudo.Core { $script:EventSettleSeconds = 0 }
        Mock -ModuleName VeroScudo.Core Get-VeroRasConnectedRecord { $null }       # no RasMan record for IKEv2
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $false }
        Mock -ModuleName VeroScudo.Core Disable-VeroKillSwitch { }
        Mock -ModuleName VeroScudo.Core Get-VeroRasTermination { [pscustomobject]@{ Profile = 'PrivateVPN'; CoId = '{11111111-2222-3333-4444-555555555555}'; Code = 631; Conflict = $false } }
        Invoke-VeroAction -Action on-event -Config $script:cfgI
        Test-VeroArmed | Should -BeFalse
    }
}

Describe 'Update-VeroRasWatch: any Windows VPN type arms, whatever Windows logged' {
    BeforeAll {
        Set-Content (Get-VeroPath).Config '{"profiles":[{"profile":"CorporateVPN","server":"a.example.com","username":"u"},{"profile":"PrivateVPN","server":"b.example.com","username":"u"}],"activeProfile":"CorporateVPN"}'
        Mock -ModuleName VeroScudo.Core Invoke-VeroArmConnected { }
        Mock -ModuleName VeroScudo.Core Test-VeroLockAlive { $false }
        $script:nicUp = @()
        Mock -ModuleName VeroScudo.Core Get-VeroNic { foreach ($n in $script:nicUp) { [pscustomobject]@{ Name = $n; NetworkInterfaceType = 'Ppp'; OperationalStatus = 'Up' } } }
    }
    BeforeEach { InModuleScope VeroScudo.Core { $script:RasSeen = @{} }; Set-VeroArmed $false 'test'; Remove-TestFile (Get-VeroPath).ActiveProfile }
    AfterAll { Remove-TestFile (Get-VeroPath).Config, (Get-VeroPath).ActiveProfile; Set-VeroArmed $false 'test' }
    It 'does nothing on its first look, then arms when a profile comes up (and makes it active)' {
        $script:nicUp = @()
        Update-VeroRasWatch -Config (Get-VeroConfig) -Action test | Should -BeFalse
        $script:nicUp = @('PrivateVPN')
        Update-VeroRasWatch -Config (Get-VeroConfig) -Action test | Should -BeTrue
        (Get-VeroConfig).Profile | Should -Be 'PrivateVPN'
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroArmConnected -Times 1 -Exactly
    }
    It 'never arms on a tunnel that was already up at the first look, nor when it goes down' {
        $script:nicUp = @('CorporateVPN')
        $null = Update-VeroRasWatch -Config (Get-VeroConfig) -Action test
        $null = Update-VeroRasWatch -Config (Get-VeroConfig) -Action test
        $script:nicUp = @()
        $null = Update-VeroRasWatch -Config (Get-VeroConfig) -Action test
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroArmConnected -Times 0 -Exactly
    }
    It 'leaves our own redial alone' {
        Mock -ModuleName VeroScudo.Core Test-VeroLockAlive { $true }
        $script:nicUp = @(); $null = Update-VeroRasWatch -Config (Get-VeroConfig) -Action test
        $script:nicUp = @('CorporateVPN'); Update-VeroRasWatch -Config (Get-VeroConfig) -Action test | Should -BeFalse
        Mock -ModuleName VeroScudo.Core Test-VeroLockAlive { $false }
    }
}

# the server changed address, the cache kept the old one

Describe 'switching hangs up the old tunnel first; nothing re-arms right after Off' {
    BeforeAll {
        Set-Content (Get-VeroPath).Config '{"profiles":[{"profile":"CorporateVPN","server":"a.example.com","username":"u"},{"profile":"PrivateVPN","server":"b.example.com","username":"u"}],"activeProfile":"CorporateVPN"}'
        Mock -ModuleName VeroScudo.Core Sync-VeroKillSwitch { }
        Mock -ModuleName VeroScudo.Core Invoke-VeroReconnect { }
        Mock -ModuleName VeroScudo.Core Invoke-VeroHangUp { }
    }
    AfterAll { Remove-TestFile (Get-VeroPath).Config, (Get-VeroPath).ActiveProfile, (Get-VeroPath).OffAt; Set-VeroArmed $false 'test' }
    It 'always hangs up the old tunnel before dialing the new one, even when it already looks disconnected' {
        Remove-TestFile (Get-VeroPath).ActiveProfile
        Set-VeroArmed $true 'test'
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $false }
        Invoke-VeroSwitch -Name 'PrivateVPN' -Action test
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroHangUp -ParameterFilter { $ProfileName -eq 'CorporateVPN' } -Times 1 -Exactly
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroReconnect -Times 1 -Exactly
    }
    It 'a tunnel that comes up right after your Off does not re-arm' {
        Set-VeroArmed $false 'test'
        Set-Content (Get-VeroPath).OffAt (Get-Date).ToString('o')
        Test-VeroRecentOff | Should -BeTrue
        Set-Content (Get-VeroPath).OffAt (Get-Date).AddMinutes(-2).ToString('o')
        Test-VeroRecentOff | Should -BeFalse
    }
}

Describe 'Off during a redial' {
    It 'hangs up a tunnel that the running redial connected after your Off' {
        $cfg = Get-VeroConfig -Raw '{"vpn":{"profile":"CorporateVPN","server":"s","username":"u"}}'
        Remove-TestFile (Get-VeroPath).Lock
        Set-VeroArmed $true 'test'
        $script:st = @{ Up = $false }
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $script:st.Up }
        Mock -ModuleName VeroScudo.Core Sync-VeroKillSwitch { }
        Mock -ModuleName VeroScudo.Core Test-VeroAuthBlocked { $false }
        Mock -ModuleName VeroScudo.Core Invoke-VeroDial { Set-VeroArmed $false 'test'; $script:st.Up = $true }   # Off pressed meanwhile, dial still connects
        Mock -ModuleName VeroScudo.Core Invoke-VeroHangUp { $script:st.Up = $false }
        Invoke-VeroReconnect -Config $cfg -Action test
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroHangUp -Times 1 -Exactly
        $script:st.Up | Should -BeFalse
        Remove-TestFile (Get-VeroPath).Lock
    }
}

Describe 'Get-VeroRasConnected takes the newest connect record' {
    It 'takes the newer connect record: IKEv2 PrivateVPN (RasClient only) over the older SSTP CorporateVPN (RasMan)' {
        Mock -ModuleName VeroScudo.Core Get-WinEvent { [pscustomobject]@{ TimeCreated = (Get-Date).AddSeconds(-25); Properties = @([pscustomobject]@{ Value = '{A}' }, [pscustomobject]@{ Value = 'u' }, [pscustomobject]@{ Value = 'CorporateVPN' }) } }
        Mock -ModuleName VeroScudo.Core Get-VeroRasClientConnect { [pscustomobject]@{ Profile = 'PrivateVPN'; CoId = '{B}'; Time = (Get-Date).AddSeconds(-2) } }
        Get-VeroRasConnected -Names @('CorporateVPN', 'PrivateVPN') | Should -Be 'PrivateVPN'
        Mock -ModuleName VeroScudo.Core Get-VeroRasClientConnect { [pscustomobject]@{ Profile = 'PrivateVPN'; CoId = '{B}'; Time = (Get-Date).AddMinutes(-1) } }
        Get-VeroRasConnected -Names @('CorporateVPN', 'PrivateVPN') | Should -Be 'CorporateVPN'
    }
}

# status showed "server -> , , ,"

Describe 'a profile you choose wins over a running redial' {
    BeforeAll {
        Set-Content (Get-VeroPath).Config $script:multiJson
        $script:cfgW = Get-VeroConfig
        $script:dialed = New-Object System.Collections.ArrayList
        $script:req = $null                                                     # the tray's request, kept in memory: the real one lives in the user folder
        Mock -ModuleName VeroScudo.Core Get-VeroPendingSwitch { $script:req }
        Mock -ModuleName VeroScudo.Core Read-VeroSwitchRequest { $r = $script:req; $script:req = $null; $r }
        Mock -ModuleName VeroScudo.Core Sync-VeroKillSwitch { }
        Mock -ModuleName VeroScudo.Core Invoke-VeroHangUp { }
        Mock -ModuleName VeroScudo.Core Start-Sleep { }
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $false }
        # 'Work' never comes up; while it is being redialed the tray asks for 'Backup'
        Mock -ModuleName VeroScudo.Core Invoke-VeroDial {
            [void]$script:dialed.Add($Config.Profile)
            if ($Config.Profile -eq 'Work' -and $script:dialed.Count -eq 2) { $script:req = 'Backup' }
            if ($Config.Profile -eq 'Backup') { Set-VeroArmed $false 'test' }      # ends the test's loop
        }
    }
    AfterAll { Remove-TestFile (Get-VeroPath).Config, (Get-VeroPath).Lock, (Get-VeroPath).ActiveProfile; Set-VeroArmed $false 'test' }
    It 'stops redialing the old profile and switches to the one you chose' {
        Remove-TestFile (Get-VeroPath).ActiveProfile
        Set-VeroArmed $true 'test'
        Invoke-VeroReconnect -Config $script:cfgW -Action test
        @($script:dialed) | Should -Be @('Work', 'Work', 'Backup')
        (Get-VeroConfig).Profile | Should -Be 'Backup'
        $script:req | Should -BeNullOrEmpty                                    # the request was taken, not left behind
    }
    It 'ignores a request for the profile being redialed (nothing to switch)' {
        $script:dialed.Clear(); Remove-TestFile (Get-VeroPath).ActiveProfile
        $script:req = 'Work'
        Mock -ModuleName VeroScudo.Core Invoke-VeroDial { [void]$script:dialed.Add($Config.Profile); Set-VeroArmed $false 'test' }
        Set-VeroArmed $true 'test'
        Invoke-VeroReconnect -Config $script:cfgW -Action test
        @($script:dialed) | Should -Be @('Work')
        $script:req | Should -BeNullOrEmpty
    }
}

Describe 'install folder: no ancestor a user can rename or replace (B8)' {
    BeforeAll {
        function Rule([string]$Who, $Rights, [string]$Type = 'Allow', [string]$Prop = 'None') {
            # named rights as the enum, raw numbers (generic bits, as Get-Acl shows them) as plain ints - the function takes both
            $fr = if ($Rights -is [string] -and $Rights -notmatch '^-?\d+$') { [Security.AccessControl.FileSystemRights]$Rights } else { [int]$Rights }   # a negative number arrives as text
            [pscustomobject]@{ IdentityReference = $Who; FileSystemRights = $fr; AccessControlType = $Type; PropagationFlags = [Security.AccessControl.PropagationFlags]$Prop }
        }
    }
    It 'Program Files style rules are administrators-only' {
        $rules = @((Rule 'NT SERVICE\TrustedInstaller' 'FullControl'), (Rule 'NT AUTHORITY\SYSTEM' 'FullControl'), (Rule 'BUILTIN\Administrators' 'FullControl'),
                   (Rule 'BUILTIN\Users' 'ReadAndExecute, Synchronize'), (Rule 'CREATOR OWNER' 'FullControl' 'Allow' 'InheritOnly'))
        Test-VeroAdminOnlyRules $rules | Should -BeTrue
    }
    It 'the C:\ root is fine: users may create folders there but not rename Program Files (real-world rules; a localized name is trusted by its SID)' {
        $rules = @((Rule 'NT AUTHORITY\Authenticated Users' 4), (Rule 'NT AUTHORITY\Authenticated Users' -536805376 'Allow' 'InheritOnly'), (Rule 'BUILTIN\Users' 1179817),
                   (Rule 'S-1-5-18' 2032127), (Rule 'S-1-5-32-544' 2032127), (Rule 'S-1-15-3-65536-1888954469-739942743-1668119174-2468466756-4239452838-1296943325-355587736-700089176' 1048737))
        Test-VeroAdminOnlyRules $rules | Should -BeTrue
    }
    It 'a data drive or a profile folder is weak: Modify (Delete) for users, or DeleteSubdirectoriesAndFiles, or generic all' {
        Test-VeroAdminOnlyRules @((Rule 'NT AUTHORITY\Authenticated Users' 'Modify, Synchronize')) | Should -BeFalse
        Test-VeroAdminOnlyRules @((Rule 'BUILTIN\Users' 'DeleteSubdirectoriesAndFiles')) | Should -BeFalse
        Test-VeroAdminOnlyRules @((Rule 'DESKTOP\someone' 'FullControl')) | Should -BeFalse
        Test-VeroAdminOnlyRules @((Rule 'Everyone' 268435456)) | Should -BeFalse          # GENERIC_ALL as Get-Acl shows it
        Test-VeroAdminOnlyRules @((Rule 'BUILTIN\Users' 'ChangePermissions')) | Should -BeFalse
        # -Contents (a folder whose programs are trusted by path): creating or writing a file counts too
        Test-VeroAdminOnlyRules @((Rule 'BUILTIN\Users' 'CreateFiles')) | Should -BeTrue
        Test-VeroAdminOnlyRules -Contents @((Rule 'BUILTIN\Users' 'CreateFiles')) | Should -BeFalse
        Test-VeroAdminOnlyRules -Contents @((Rule 'BUILTIN\Users' 'AppendData')) | Should -BeFalse
        Test-VeroAdminOnlyRules -Contents @((Rule 'BUILTIN\Users' 'ReadAndExecute, Synchronize')) | Should -BeTrue
    }
    It 'a real rule collection is enumerated, not taken as one item' -Skip:($env:OS -ne 'Windows_NT') {
        Test-VeroAdminOnlyRules (Get-Acl -LiteralPath $env:LOCALAPPDATA).Access | Should -BeFalse       # the user has full control there
    }
    It 'a deny rule never makes a folder weak' {
        Test-VeroAdminOnlyRules @((Rule 'Everyone' 'FullControl' 'Deny'), (Rule 'BUILTIN\Administrators' 'FullControl')) | Should -BeTrue
    }
    It 'on this machine: Program Files passes, the user profile does not' -Skip:($env:OS -ne 'Windows_NT') {
        Test-VeroAdminOnlyPath (Join-Path (Get-VeroSystemDir ProgramFiles) 'VeroScudo') | Should -BeNullOrEmpty
        Test-VeroAdminOnlyPath (Join-Path $env:LOCALAPPDATA 'VeroScudo-weak\x') | Should -Not -BeNullOrEmpty
    }
}

Describe 'one holder per lock (files in the administrators-only locks folder, not named mutexes)' {
    It 'the first holder wins, a second call fails until the handle is disposed' {
        $a = Enter-VeroSingleton -Name 'unit-test'
        $a | Should -Not -BeNullOrEmpty
        Enter-VeroSingleton -Name 'unit-test' | Should -BeNullOrEmpty
        Test-VeroSingletonHeld -Name 'unit-test' | Should -BeTrue
        $a.Dispose()
        Test-VeroSingletonHeld -Name 'unit-test' | Should -BeFalse
        $b = Enter-VeroSingleton -Name 'unit-test'
        $b | Should -Not -BeNullOrEmpty; $b.Dispose()
    }
    It 'waits up to the given time, then gives up' {
        $a = Enter-VeroSingleton -Name 'unit-wait'
        $t = [Diagnostics.Stopwatch]::StartNew()
        Enter-VeroSingleton -Name 'unit-wait' -WaitMs 500 | Should -BeNullOrEmpty
        $t.ElapsedMilliseconds | Should -BeGreaterOrEqual 400
        $a.Dispose()
    }
    It 'the lock files live under the state folder of this (test) home' {
        Get-VeroLockDir | Should -Be (Join-Path (Get-VeroPath).State 'locks')
    }
}

Describe 'the locks folder stays administrators-only (the installer''s reset once gave it "Users: read")' {
    BeforeAll {
        function New-Rule([string]$Sid, [string]$Type = 'Allow', [bool]$Inherited = $false) {
            [pscustomobject]@{ IdentityReference = $Sid; AccessControlType = $Type; IsInherited = $Inherited }
        }
    }
    It 'accepts SYSTEM and Administrators set on the folder itself' {
        Test-VeroLockDirAcl @((New-Rule 'S-1-5-18'), (New-Rule 'S-1-5-32-544')) | Should -BeTrue
    }
    It 'refuses inherited rules - even SYSTEM and Administrators (the parent''s Users: read comes with them)' {
        Test-VeroLockDirAcl @((New-Rule 'S-1-5-18' -Inherited $true), (New-Rule 'S-1-5-32-544' -Inherited $true)) | Should -BeFalse
    }
    It 'refuses any other account allowed in: Users, Authenticated Users, Everyone, the signed-in user' {
        foreach ($sid in 'S-1-5-32-545', 'S-1-5-11', 'S-1-1-0', 'S-1-5-21-1-2-3-1001') {
            Test-VeroLockDirAcl @((New-Rule 'S-1-5-32-544'), (New-Rule $sid)) | Should -BeFalse -Because $sid
        }
    }
    It 'ignores deny rules (they take nothing from the guard)' {
        Test-VeroLockDirAcl @((New-Rule 'S-1-5-32-544'), (New-Rule 'S-1-1-0' -Type 'Deny')) | Should -BeTrue
    }
    It 'an elevated caller repairs a folder whose rules are inherited, and logs it' {
        Mock -ModuleName VeroScudo.Core Test-VeroElevated { $true }
        Mock -ModuleName VeroScudo.Core Set-VeroLockDirAcl { }            # never re-permission even the temp folder: the test would lock itself out
        Mock -ModuleName VeroScudo.Core Write-VeroLog { }
        # its own new home inside the test folder: the shared one's locks folder may already be locked down by an earlier test
        # (CI runs elevated, so the real repair ran there) - then there would be nothing to repair
        $fresh = Join-Path $script:TestHomeDir ('acl-' + [guid]::NewGuid())
        if (-not (Test-IsTestDir $fresh)) { throw "SAFETY: $fresh is not inside the test folder" }
        Set-VeroHome $fresh
        try {
            $d = Get-VeroLockDir                                            # created just now: inherited rules only
        } finally { Set-VeroHome $script:TestHomeDir }
        Should -Invoke -ModuleName VeroScudo.Core Set-VeroLockDirAcl -Times 1 -Exactly -ParameterFilter { $Path -eq $d }
        Should -Invoke -ModuleName VeroScudo.Core Write-VeroLog -Times 1 -Exactly -ParameterFilter { $Message -like 'locks folder*' }
    }
    It 'leaves a correct folder alone, and a non-elevated caller (the tray) never tries' {
        Mock -ModuleName VeroScudo.Core Set-VeroLockDirAcl { }
        Mock -ModuleName VeroScudo.Core Test-VeroElevated { $true }
        Mock -ModuleName VeroScudo.Core Test-VeroLockDirAcl { $true }
        $null = Get-VeroLockDir
        Mock -ModuleName VeroScudo.Core Test-VeroElevated { $false }
        Mock -ModuleName VeroScudo.Core Test-VeroLockDirAcl { $false }
        $null = Get-VeroLockDir
        Should -Invoke -ModuleName VeroScudo.Core Set-VeroLockDirAcl -Times 0 -Exactly
    }
    It 'Install.ps1 locks the folder down again after resetting the state folder' {
        $src = Get-Content (Join-Path $PSScriptRoot '..\Install.ps1') -Raw
        $reset = $src.IndexOf('/reset /T'); $lock = $src.IndexOf('$null = Get-VeroLockDir')
        $reset | Should -BeGreaterThan 0
        $lock | Should -BeGreaterThan $reset
    }
}

Describe 'Resolve-VeroTerminationCode (pure: when a 631 is really "you hung up")' {
    BeforeAll {
        $script:now = Get-Date
        function Term([int]$Code, [string]$CoId = 'A', [bool]$Conflict = $false, $Time = $null) {
            [pscustomobject]@{ Profile = 'Work'; Code = $Code; CoId = $CoId; Conflict = $Conflict; Time = $(if ($Time) { $Time } else { $script:now }) }
        }
    }
    It 'a clean 631 for the connection VeroScudo saw connect stands' {
        $r = Resolve-VeroTerminationCode -Termination (Term 631) -RenewMarker $null -ExpectedCoIds @('A') -Now $script:now
        $r.Code | Should -Be 631; $r.Notes | Should -BeNullOrEmpty
    }
    It 'conflicting records are a failure' {
        $r = Resolve-VeroTerminationCode -Termination (Term 631 'A' $true) -RenewMarker $null -ExpectedCoIds @('A') -Now $script:now
        $r.Code | Should -Be 0; $r.Notes[0] | Should -Match 'conflicting'
    }
    It "VeroScudo's own hang-up for Reconnect is not your Off" {
        $mk = @{ Profile = 'Work'; Start = $script:now.AddSeconds(-5).ToString('o'); HungUp = $script:now.AddSeconds(-2).ToString('o') }
        $r = Resolve-VeroTerminationCode -Termination (Term 631) -RenewMarker $mk -ExpectedCoIds @('A') -Now $script:now
        $r.Code | Should -Be 0; $r.Notes[0] | Should -Match 'own hang-up'
    }
    It 'a 631 naming a connection VeroScudo never saw connect is forged or stale' {
        $r = Resolve-VeroTerminationCode -Termination (Term 631 'ZZ') -RenewMarker $null -ExpectedCoIds @('A', 'B') -Now $script:now
        $r.Code | Should -Be 0; $r.Notes[0] | Should -Match 'names connection ZZ, but VeroScudo saw A / B'
        (Resolve-VeroTerminationCode -Termination (Term 631 'ZZ') -RenewMarker $null -ExpectedCoIds @() -Now $script:now).Notes[0] | Should -Match 'saw none'
    }
    It 'a link failure code passes through untouched, whatever the connection id' {
        $r = Resolve-VeroTerminationCode -Termination (Term 629 'ZZ' $true) -RenewMarker $null -ExpectedCoIds @() -Now $script:now
        $r.Code | Should -Be 0                                              # conflict still downgrades, but nothing else applies
        (Resolve-VeroTerminationCode -Termination (Term 629 'ZZ') -RenewMarker $null -Now $script:now).Code | Should -Be 629
    }
}

Describe 'Off works without a config that loads' {
    It '<action> removes the flag and the filters, and touches nothing else' -ForEach @(@{ action = 'off' }, @{ action = 'disarm' }) {
        Mock -ModuleName VeroScudo.Core Get-VeroConfig { throw 'config.json: invalid' }
        Mock -ModuleName VeroScudo.Core Disable-VeroKillSwitch { }
        Mock -ModuleName VeroScudo.Core Invoke-VeroHangUp { }
        Set-VeroArmed $true 'test'
        Invoke-VeroAction -Action $action
        Test-VeroArmed | Should -BeFalse
        Should -Invoke -ModuleName VeroScudo.Core Disable-VeroKillSwitch -Times 1 -Exactly
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroHangUp -Times 0 -Exactly
        Remove-TestFile (Get-VeroPath).OffAt
    }
    It 'every other action still fails on a broken config' {
        Mock -ModuleName VeroScudo.Core Get-VeroConfig { throw 'config.json: invalid' }
        { Invoke-VeroAction -Action on } | Should -Throw '*invalid*'
    }
}

Describe 'Write-VeroSecretFile: administrators and SYSTEM only, from the first moment' {
    It 'writes the text, replaces an older file and gives nobody else a rule' {
        $f = Join-Path (Get-VeroPath).State 'secret-test.pw'
        Set-Content -Path $f -Value 'old'
        if (-not (Test-IsTestDir $f)) { throw 'SAFETY: path outside the test folder' }
        & (Get-Module VeroScudo.Core) { param($path) Write-VeroSecretFile -Path $path -Text 's3cret' } $f
        # not elevated (the usual test run): the file's own creator may not read it - that is the point
        if (Test-VeroElevated) { [IO.File]::ReadAllText($f) | Should -Be 's3cret' } else { { [IO.File]::ReadAllText($f) } | Should -Throw }
        $acl = Get-Acl -LiteralPath $f
        $acl.AreAccessRulesProtected | Should -BeTrue
        $sids = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
        $sids | Should -Be @('S-1-5-18', 'S-1-5-32-544')
        Remove-TestFile $f
    }
}

Describe 'the CRL window never lasts longer than VeroScudo writes it' {
    It 'ignores an end time further away than 2 minutes' {
        $f = (Get-VeroPath).CrlWindow
        @{ Until = (Get-Date).AddMinutes(1).ToString('o') } | ConvertTo-Json | Set-Content $f
        Test-VeroCrlWindow | Should -BeTrue
        @{ Until = (Get-Date).AddDays(30).ToString('o') } | ConvertTo-Json | Set-Content $f
        Test-VeroCrlWindow | Should -BeFalse
        Remove-TestFile $f
    }
}

Describe 'stored credentials: only a credential is taken from the user''s file' {
    BeforeAll {
        Set-VeroHome $script:TestHomeDir -UserDir (Join-Path $script:TestHomeDir 'user')
        if (-not (Test-IsTestDir (Get-VeroPath).UserDir)) { throw 'SAFETY: user folder outside the test folder' }
        New-Item -ItemType Directory -Path (Get-VeroPath).UserDir -Force | Out-Null
    }
    AfterAll { Set-VeroHome $script:TestHomeDir }
    It 'ignores a file that holds something else' {
        $cfg = Get-VeroConfig -Raw $script:cfgJson
        $p = Get-VeroPath -VpnProfile $cfg.Profile
        if (-not (Test-IsTestDir $p.Cred) -or -not (Test-IsTestDir $p.KeyPass)) { throw 'SAFETY: credential path outside the test folder' }
        @{ UserName = 'x'; Password = 'y' } | Export-Clixml -LiteralPath $p.Cred
        Get-VeroCredential -Config $cfg | Should -BeNullOrEmpty
        'text' | Export-Clixml -LiteralPath $p.KeyPass
        Get-VeroKeyPassphrase -ProfileName $cfg.Profile | Should -BeNullOrEmpty
        # two objects in one file, or a document type: not a stored credential either
        $good = New-Object pscredential ('jdoe', (New-TestSecret 'p@ss w0rd'))
        @($good, $good) | Export-Clixml -LiteralPath $p.Cred
        Get-VeroCredential -Config $cfg | Should -BeNullOrEmpty
        Set-Content -LiteralPath $p.Cred -Value '<?xml version="1.0"?><!DOCTYPE Objs [<!ENTITY x "y">]><Objs xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj><Props><S N="UserName">&x;</S><SS N="Password">00</SS></Props></Obj></Objs>'
        Get-VeroCredential -Config $cfg | Should -BeNullOrEmpty
        Remove-TestFile $p.Cred, $p.KeyPass
    }
    It 'reads a credential and a key passphrase exactly as the tray stores them' {
        $cfg = Get-VeroConfig -Raw $script:cfgJson
        $p = Get-VeroPath -VpnProfile $cfg.Profile
        if (-not (Test-IsTestDir $p.Cred) -or -not (Test-IsTestDir $p.KeyPass)) { throw 'SAFETY: credential path outside the test folder' }
        $name = 'j' + [char]0x00E9 + 'doe'
        (New-Object pscredential ($name, (New-TestSecret 'p@ss "w0rd" <&>'))) | Export-Clixml -LiteralPath $p.Cred
        $c = Get-VeroCredential -Config $cfg
        $c | Should -BeOfType [pscredential]
        $c.UserName | Should -Be $name
        $c.GetNetworkCredential().Password | Should -Be 'p@ss "w0rd" <&>'
        (New-Object pscredential ('key', (New-TestSecret 'phrase'))) | Export-Clixml -LiteralPath $p.KeyPass
        (Get-VeroKeyPassphrase -ProfileName $cfg.Profile).GetNetworkCredential().Password | Should -Be 'phrase'
        Remove-TestFile $p.Cred, $p.KeyPass
    }
}

Describe 'the redial loop has one owner' {
    It 'tests never start an installed task: with a redirected home Start-VeroTask does nothing' {
        & (Get-Module VeroScudo.Core) { Start-VeroTask 'Redial' } | Should -BeFalse
    }
    It 'without the Redial task the loop runs in the caller, as before' {
        Mock -ModuleName VeroScudo.Core Invoke-VeroReconnect { }
        $cfg = Get-VeroConfig -Raw $script:cfgJson
        & (Get-Module VeroScudo.Core) { param($c) Start-VeroRedial -Config $c -Action test } $cfg
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroReconnect -Times 1 -Exactly
    }
    It 'with the task it only starts it and returns' {
        Mock -ModuleName VeroScudo.Core Invoke-VeroReconnect { }
        Mock -ModuleName VeroScudo.Core Start-VeroTask { $true }
        $cfg = Get-VeroConfig -Raw $script:cfgJson
        & (Get-Module VeroScudo.Core) { param($c) Start-VeroRedial -Config $c -Action test } $cfg
        Should -Invoke -ModuleName VeroScudo.Core Start-VeroTask -Times 1 -Exactly -ParameterFilter { $Name -eq 'Redial' }
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroReconnect -Times 0 -Exactly
    }
    It 'the redial action loops only while armed' {
        Mock -ModuleName VeroScudo.Core Invoke-VeroReconnect { }
        $cfg = Get-VeroConfig -Raw $script:cfgJson
        Set-VeroArmed $false 'test'
        Invoke-VeroAction -Action redial -Config $cfg
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroReconnect -Times 0 -Exactly
        Set-VeroArmed $true 'test'
        Invoke-VeroAction -Action redial -Config $cfg
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroReconnect -Times 1 -Exactly
        Set-VeroArmed $false 'test'
    }
}

Describe 'the CRL window is opened once per quarter of an hour, not after every failed dial' {
    It 'a dial that fails on the revocation check right after a window has closed opens no new one' {
        $f = (Get-VeroPath).CrlWindow
        $closed = @{ Until = (Get-Date).AddMinutes(-1).ToString('o'); Opened = (Get-Date).AddMinutes(-3).ToString('o') } | ConvertTo-Json
        Set-Content -Path $f -Value $closed
        Test-VeroCrlWindow | Should -BeFalse
        & (Get-Module VeroScudo.Core) { Test-VeroCrlWindowRecent } | Should -BeTrue
        $old = @{ Until = (Get-Date).AddMinutes(-28).ToString('o'); Opened = (Get-Date).AddMinutes(-30).ToString('o') } | ConvertTo-Json
        Set-Content -Path $f -Value $old
        & (Get-Module VeroScudo.Core) { Test-VeroCrlWindowRecent } | Should -BeFalse
        Set-Content -Path $f -Value (@{ Until = (Get-Date).AddMinutes(-1).ToString('o') } | ConvertTo-Json)      # a file from before 'Opened'
        & (Get-Module VeroScudo.Core) { Test-VeroCrlWindowRecent } | Should -BeTrue
        Remove-TestFile $f
    }
}

Describe 'state files are written whole and read back as written' {
    It 'keeps letters outside ASCII for the readers that use Get-Content' {
        $f = Join-Path (Get-VeroPath).State 'state-test.json'
        $name = 'VPN ' + [char]0x0416 + [char]0x00E9
        & (Get-Module VeroScudo.Core) { param($path, $n) Write-VeroStateFile -Path $path -Text (@{ Name = $n } | ConvertTo-Json) } $f $name
        $back = (Get-Content $f -Raw | ConvertFrom-Json).Name
        $back | Should -Be $name                                                # exactly, whatever the system's code page
        @(Get-ChildItem -LiteralPath (Split-Path -Parent $f) | Where-Object { $_.Name -like 'state-test.json.*.new' }).Count | Should -Be 0   # no temporary file left
        & (Get-Module VeroScudo.Core) { param($path) Write-VeroStateFile -Path $path -Text 'second' } $f       # over an existing file
        (Get-Content $f -Raw).Trim() | Should -Be 'second'
        Remove-TestFile $f
    }
}

Describe 'what the tray leaves for the guard in the user''s folder is read, never deleted' {
    BeforeAll {
        Set-VeroHome $script:TestHomeDir -UserDir (Join-Path $script:TestHomeDir 'user')
        if (-not (Test-IsTestDir (Get-VeroPath).UserDir)) { throw 'SAFETY: user folder outside the test folder' }
        New-Item -ItemType Directory -Path (Get-VeroPath).UserDir -Force | Out-Null
    }
    AfterAll { Set-VeroHome $script:TestHomeDir }
    It 'hands a switch request out once and leaves the file where it is' {
        $f = (Get-VeroPath).SwitchRequest
        Set-Content -Path $f -Value 'Backup' -Encoding UTF8
        Get-VeroPendingSwitch | Should -Be 'Backup'                           # looking does not take it
        Get-VeroPendingSwitch | Should -Be 'Backup'
        & (Get-Module VeroScudo.Core) { Read-VeroSwitchRequest } | Should -Be 'Backup'
        Test-Path -LiteralPath $f | Should -BeTrue
        & (Get-Module VeroScudo.Core) { Read-VeroSwitchRequest } | Should -BeNullOrEmpty
        Get-VeroPendingSwitch | Should -BeNullOrEmpty
        Start-Sleep -Milliseconds 30
        Set-Content -Path $f -Value 'Work' -Encoding UTF8                      # a new request is a new one
        (Get-Item $f).LastWriteTimeUtc = [datetime]::UtcNow.AddSeconds(1)
        & (Get-Module VeroScudo.Core) { Read-VeroSwitchRequest } | Should -Be 'Work'
        Remove-TestFile $f
    }
    It 'takes nothing from a file that is too large, and nothing when there is none' {
        $f = (Get-VeroPath).SwitchRequest
        Set-Content -Path $f -Value ('x' * 5000)
        & (Get-Module VeroScudo.Core) { Read-VeroSwitchRequest } | Should -BeNullOrEmpty
        Remove-TestFile $f
        & (Get-Module VeroScudo.Core) { Read-VeroSwitchRequest } | Should -BeNullOrEmpty
    }
    It 'no file of the guard deletes or writes in the user''s folder' {
        $src = Get-ChildItem (Join-Path $PSScriptRoot '..\Core') -Filter *.ps1 | ForEach-Object { Get-Content $_.FullName }
        @($src | Where-Object { $_ -match '(Remove-Item|Set-Content|WriteAllText|Out-File)[^#]*\$p\.(SwitchRequest|Otp|Cred|KeyPass|LegacyCred|UserDir)' }).Count | Should -Be 0
    }
}

Describe 'the CRL window at arm' {
    It 'does not start the 15-minute clock of failed dials' {
        $f = (Get-VeroPath).CrlWindow
        Remove-TestFile $f
        Open-VeroCrlWindow -Action test -AtArm
        Test-VeroCrlWindow | Should -BeTrue
        & (Get-Module VeroScudo.Core) { Test-VeroCrlWindowRecent } | Should -BeFalse
        Remove-TestFile $f
    }
    It 'lasts 20 seconds, not 2 minutes: a drop minutes after a connect finds HTTP and DNS closed' {
        $f = (Get-VeroPath).CrlWindow
        Remove-TestFile $f
        Open-VeroCrlWindow -Action test -AtArm
        $until = [datetime]::Parse([string](Get-Content $f -Raw | ConvertFrom-Json).Until, $null, [Globalization.DateTimeStyles]::RoundtripKind)
        ($until - (Get-Date)).TotalSeconds | Should -BeLessOrEqual 21
        Remove-TestFile $f
    }
    It 'does not cut short the 2-minute window of a dial that failed on the revocation check' {
        $f = (Get-VeroPath).CrlWindow
        Remove-TestFile $f
        Open-VeroCrlWindow -Action test
        Open-VeroCrlWindow -Action test -AtArm
        $until = [datetime]::Parse([string](Get-Content $f -Raw | ConvertFrom-Json).Until, $null, [Globalization.DateTimeStyles]::RoundtripKind)
        ($until - (Get-Date)).TotalSeconds | Should -BeGreaterThan 100
        Remove-TestFile $f
    }
}

Describe 'a state file somebody is reading at that instant' {
    It 'is still written, and no temporary file stays behind' {
        $f = Join-Path (Get-VeroPath).State 'held-test.json'
        & (Get-Module VeroScudo.Core) { param($path) Write-VeroStateFile -Path $path -Text 'first' } $f
        $reader = [IO.File]::Open($f, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)   # as Get-Content holds it
        try { & (Get-Module VeroScudo.Core) { param($path) Write-VeroStateFile -Path $path -Text 'second' } $f } finally { $reader.Dispose() }
        (Get-Content $f -Raw).Trim() | Should -Be 'second'
        @(Get-ChildItem -LiteralPath (Split-Path -Parent $f) | Where-Object { $_.Name -like 'held-test.json.*.new' }).Count | Should -Be 0
        Remove-TestFile $f
    }
    It 'Off goes through although its own note cannot be written at all' {
        Mock -ModuleName VeroScudo.Core Disable-VeroKillSwitch { }
        $f = (Get-VeroPath).OffAt
        Set-Content -Path $f -Value 'x'
        $lock = [IO.File]::Open($f, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)      # nobody else may touch it
        try {
            Set-VeroArmed $true 'test'
            { Invoke-VeroAction -Action off -Config (Get-VeroConfig -Raw $script:cfgJson) } | Should -Not -Throw
            Test-VeroArmed | Should -BeFalse
            Should -Invoke -ModuleName VeroScudo.Core Disable-VeroKillSwitch -Times 1 -Exactly
        } finally { $lock.Dispose() }
        @(Get-ChildItem -LiteralPath (Split-Path -Parent $f) | Where-Object { $_.Name -like 'off-at.txt.*.new' }).Count | Should -Be 0
        Remove-TestFile $f
    }
}

Describe 'the Redial task does not try to start itself' {
    It 'a redial that takes a pending switch goes on in its own process' {
        Mock -ModuleName VeroScudo.Core Invoke-VeroReconnect { }
        Mock -ModuleName VeroScudo.Core Start-VeroTask { $true }
        $cfg = Get-VeroConfig -Raw $script:cfgJson
        & (Get-Module VeroScudo.Core) { param($c) Start-VeroRedial -Config $c -Action redial } $cfg
        Should -Invoke -ModuleName VeroScudo.Core Start-VeroTask -Times 0 -Exactly
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroReconnect -Times 1 -Exactly
    }
}

Describe 'a program the guard starts gets the system''s environment, not the user''s' {
    It 'keeps the machine''s variables except those that name code to load, and sets the folders itself' {
        $e = & (Get-Module VeroScudo.Core) { Get-VeroCleanEnvironment -Machine @{ NUMBER_OF_PROCESSORS = '8'; OPENSSL_CONF = 'C:\x\openssl.cnf'; OPENSSL_MODULES = 'C:\x'
                                                                                COR_PROFILER = '{x}'; APPDOMAIN_MANAGER_ASM = 'x'; Path = 'C:\planted'; TEMP = 'C:\planted'; MyVar = '%SystemRoot%\y' } }
        $e['NUMBER_OF_PROCESSORS'] | Should -Be '8'
        foreach ($k in 'OPENSSL_CONF', 'OPENSSL_MODULES', 'COR_PROFILER', 'APPDOMAIN_MANAGER_ASM') { $e.ContainsKey($k) | Should -BeFalse -Because $k }
        $e['PATH'] | Should -Not -Match 'planted'; $e['PATH'] | Should -Match 'System32'
        $e['TEMP'] | Should -Match '\\Temp$'; $e['TEMP'] | Should -Not -Match 'planted'
        $e['SystemRoot'] | Should -Be (Split-Path -Parent (Get-VeroSystemDir System))
        $e['MyVar'] | Should -Not -Match '%'
    }
    It 'the started program really sees none of the caller''s variables' {
        $env:OPENSSL_CONF = 'C:\planted\openssl.cnf'; $env:VEROSCUDO_PLANTED = '1'
        try {
            $cmd = Join-Path (Get-VeroSystemDir System) 'cmd.exe'
            $p = & (Get-Module VeroScudo.Core) { param($c) Start-VeroCleanProcess -FilePath $c -ArgumentList '/c "if defined OPENSSL_CONF (exit 9) else (if defined VEROSCUDO_PLANTED (exit 8) else (if defined SystemRoot (exit 0) else (exit 7)))"' } $cmd
            $p.WaitForExit(10000) | Should -BeTrue
            $p.ExitCode | Should -Be 0
        } finally { Remove-Item Env:\OPENSSL_CONF, Env:\VEROSCUDO_PLANTED -ErrorAction SilentlyContinue }
    }
}

Describe 'a stored user name comes back as it was typed' {
    BeforeAll {
        Set-VeroHome $script:TestHomeDir -UserDir (Join-Path $script:TestHomeDir 'user')
        if (-not (Test-IsTestDir (Get-VeroPath).UserDir)) { throw 'SAFETY: user folder outside the test folder' }
        New-Item -ItemType Directory -Path (Get-VeroPath).UserDir -Force | Out-Null
    }
    AfterAll { Set-VeroHome $script:TestHomeDir }
    It '<name>' -ForEach @(@{ name = 'john_xu' }, @{ name = 'DOMAIN\j_x0041_doe' }, @{ name = 'plain' }, @{ name = 'a_b' }) {
        $cfg = Get-VeroConfig -Raw $script:cfgJson
        $p = Get-VeroPath -VpnProfile $cfg.Profile
        if (-not (Test-IsTestDir $p.Cred)) { throw 'SAFETY: credential path outside the test folder' }
        (New-Object pscredential ($name, (New-TestSecret 'pw'))) | Export-Clixml -LiteralPath $p.Cred
        (Get-VeroCredential -Config $cfg).UserName | Should -Be $name
        Remove-TestFile $p.Cred
    }
}

Describe 'what the tray leaves for the guard: one short line' {
    BeforeAll {
        Set-VeroHome $script:TestHomeDir -UserDir (Join-Path $script:TestHomeDir 'user')
        if (-not (Test-IsTestDir (Get-VeroPath).UserDir)) { throw 'SAFETY: user folder outside the test folder' }
        New-Item -ItemType Directory -Path (Get-VeroPath).UserDir -Force | Out-Null
    }
    AfterAll { Set-VeroHome $script:TestHomeDir }
    It 'takes nothing from a text of several lines' {
        $f = (Get-VeroPath).SwitchRequest
        [IO.File]::WriteAllText($f, "Work`nsecond line")
        & (Get-Module VeroScudo.Core) { Read-VeroSwitchRequest } | Should -BeNullOrEmpty
        Remove-TestFile $f
    }
}

Describe 'the watchdog loop' {
    It 'one pass: check, statistics, heartbeat - then it sleeps until the next one is due and does not check again before' {
        Mock -ModuleName VeroScudo.Core Invoke-VeroCheck { }
        Mock -ModuleName VeroScudo.Core Update-VeroQuality { 30 }
        Mock -ModuleName VeroScudo.Core Update-VeroStats { }
        Mock -ModuleName VeroScudo.Core Save-VeroStatsMinute { }
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $false }
        Mock -ModuleName VeroScudo.Core Get-VeroConfig { Get-VeroConfig -Raw '{"vpn":{"profile":"X","server":"vpn.example.com","username":"u"}}' }.GetNewClosure()
        $script:naps = @()
        Mock -ModuleName VeroScudo.Core Start-Sleep { $script:naps += $Seconds; if ($script:naps.Count -ge 2) { throw 'end of test' } }
        Remove-TestFile (Get-VeroPath).Heartbeat
        { Invoke-VeroAction -Action watchdog -Config (Get-VeroConfig -Raw $script:cfgJson) } | Should -Throw '*end of test*'
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroCheck -Times 1 -Exactly                 # not again within its 15 s
        Should -Invoke -ModuleName VeroScudo.Core Update-VeroStats -Times 1 -Exactly
        Should -Invoke -ModuleName VeroScudo.Core Save-VeroStatsMinute -Times 1 -Exactly               # on the way out
        [double]([IO.File]::ReadAllText((Get-VeroPath).Heartbeat).Trim()) | Should -BeGreaterThan 0
        $script:naps[0] | Should -BeGreaterThan 0; $script:naps[0] | Should -BeLessOrEqual 15         # until the next check, never longer
        & (Get-Module VeroScudo.Core) { Test-VeroSingletonHeld -Name 'watchdog' } | Should -BeFalse   # the one-per-session lock is given back
    }
    It 'a pass that fails is logged and the loop goes on' {
        Mock -ModuleName VeroScudo.Core Invoke-VeroCheck { throw 'adapter gone' }
        Mock -ModuleName VeroScudo.Core Update-VeroQuality { 30 }
        Mock -ModuleName VeroScudo.Core Save-VeroStatsMinute { }
        Mock -ModuleName VeroScudo.Core Write-VeroLog { }
        Mock -ModuleName VeroScudo.Core Start-Sleep { throw 'end of test' }
        { Invoke-VeroAction -Action watchdog -Config (Get-VeroConfig -Raw $script:cfgJson) } | Should -Throw '*end of test*'
        Should -Invoke -ModuleName VeroScudo.Core Write-VeroLog -Times 1 -Exactly -ParameterFilter { $Message -like 'ERROR: adapter gone*' }
    }
}

Describe 'the filter lock: Off must work even while another process is stuck' {
    It 'goes ahead without the lock after the wait, and says so' {
        Mock -ModuleName VeroScudo.Core Enter-VeroSingleton { $null }
        Mock -ModuleName VeroScudo.Core Write-VeroLog { }
        & (Get-Module VeroScudo.Core) { Invoke-VeroLocked { param($x) "ran $x" } -Arguments @('it') } | Should -Be 'ran it'
        Should -Invoke -ModuleName VeroScudo.Core Write-VeroLog -Times 1 -Exactly -ParameterFilter { $Message -like 'WARNING: another VeroScudo process has held the filter lock*' }
    }
    It 'with the lock: runs, gives it back, says nothing' {
        Mock -ModuleName VeroScudo.Core Write-VeroLog { }
        & (Get-Module VeroScudo.Core) { Invoke-VeroLocked { 'ran' } } | Should -Be 'ran'
        & (Get-Module VeroScudo.Core) { Test-VeroSingletonHeld -Name 'sync' } | Should -BeFalse
        Should -Invoke -ModuleName VeroScudo.Core Write-VeroLog -Times 0 -Exactly
    }
}
