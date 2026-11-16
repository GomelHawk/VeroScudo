# Pester 5 unit tests for VeroScudo.Core: the connection check and the statistics.
# Pure parts directly; WFP / RAS / firewall calls are mocked (Core.TestSetup.ps1).
BeforeAll { . (Join-Path $PSScriptRoot 'Core.TestSetup.ps1') }
AfterAll { Remove-TestDir; Set-VeroHome $null }

Describe 'Connection check: config.json (connectionCheck)' {
    BeforeAll { $script:one = '{"profiles":[{"profile":"Work","server":"vpn.example.com","username":"jdoe"}]' }
    It 'missing = off, every 10 s over 1 minute, 1.1.1.1 TCP 443' {
        $c = (Get-VeroConfig -Raw ($script:one + '}')).ConnectionCheck
        $c.Enabled | Should -BeFalse; $c.IntervalSeconds | Should -Be 10; $c.WindowMinutes | Should -Be 1
        @($c.Targets).Count | Should -Be 1; $c.Targets[0].Host | Should -Be '1.1.1.1'; $c.Targets[0].Method | Should -Be 'tcp'; $c.Targets[0].Port | Should -Be 443
    }
    It 'a full setting is read' {
        $c = (Get-VeroConfig -Raw ($script:one + ',"connectionCheck":{"enabled":true,"intervalSeconds":30,"windowMinutes":5,"targets":[{"host":"10.0.0.1","method":"ping"},{"host":"intranet.example.com","method":"tcp","port":8443}]}}')).ConnectionCheck
        $c.Enabled | Should -BeTrue; $c.IntervalSeconds | Should -Be 30; $c.WindowMinutes | Should -Be 5
        $c.Targets[0].Method | Should -Be 'ping'; $c.Targets[1].Host | Should -Be 'intranet.example.com'; $c.Targets[1].Port | Should -Be 8443
    }
    It 'an empty list still checks one address' {
        (Get-VeroConfig -Raw ($script:one + ',"connectionCheck":{"enabled":true,"targets":[]}}')).ConnectionCheck.Targets[0].Host | Should -Be '1.1.1.1'
    }
    It 'refuses <bad>' -ForEach @(
        @{ bad = '{"intervalSeconds":9}' }, @{ bad = '{"intervalSeconds":101}' }, @{ bad = '{"windowMinutes":0}' }, @{ bad = '{"windowMinutes":11}' },
        @{ bad = '{"enabled":"yes"}' }, @{ bad = '{"targets":[{"host":"bad host"}]}' }, @{ bad = '{"targets":[{"host":"a.example","method":"udp"}]}' },
        @{ bad = '{"targets":[{"host":"a.example","method":"tcp","port":0}]}' }, @{ bad = '{"targets":[{"host":"a"},{"host":"b"},{"host":"c"},{"host":"d"}]}' }, @{ bad = '[]' }
    ) {
        { Get-VeroConfig -Raw ($script:one + ',"connectionCheck":' + $bad + '}') } | Should -Throw
    }
    It 'survives the round trip through the on-disk form' {
        $c = Get-VeroConfig -Raw ($script:one + ',"connectionCheck":{"enabled":true,"intervalSeconds":20,"windowMinutes":3,"targets":[{"host":"1.1.1.1","method":"tcp","port":443},{"host":"10.1.2.3","method":"ping"}]}}')
        $c2 = Get-VeroConfig -Raw (ConvertTo-VeroConfigJson $c)
        $c2.ConnectionCheck.IntervalSeconds | Should -Be 20; $c2.ConnectionCheck.Targets[1].Method | Should -Be 'ping'
        @((ConvertTo-VeroCheckObject $c.ConnectionCheck).targets[1].Keys) | Should -Not -Contain 'port'
    }
}

Describe 'Connection check: the Settings form' {
    It 'splits <text>' -ForEach @(
        @{ text = '1.1.1.1'; h = '1.1.1.1'; p = $null }, @{ text = 'example.com:8443'; h = 'example.com'; p = 8443 },
        @{ text = 'https://example.com/path'; h = 'example.com'; p = 443 }, @{ text = 'http://example.com'; h = 'example.com'; p = 80 },
        @{ text = 'https://example.com:9443/x'; h = 'example.com'; p = 9443 }, @{ text = '[2001:db8::1]:443'; h = '2001:db8::1'; p = 443 },
        @{ text = '2001:db8::1'; h = '2001:db8::1'; p = $null }, @{ text = '  '; h = ''; p = $null }
    ) {
        $a = Split-VeroCheckAddress $text
        $a.Host | Should -Be $h; $a.Port | Should -Be $p
    }
    It 'the first address is never empty; empty others are dropped' {
        $c = ConvertFrom-VeroCheckForm -Enabled $true -IntervalSeconds 10 -WindowMinutes 1 -Rows @(@{ Text = ''; Method = 'tcp'; Port = 443 }, @{ Text = ''; Method = 'ping'; Port = 443 }, @{ Text = '10.0.0.1'; Method = 'ping'; Port = 443 })
        @($c.Targets).Count | Should -Be 2; $c.Targets[0].Host | Should -Be '1.1.1.1'; $c.Targets[1].Method | Should -Be 'ping'
    }
    It 'takes the port of a URL and clamps the numbers' {
        $c = ConvertFrom-VeroCheckForm -Enabled $true -IntervalSeconds 5 -WindowMinutes 99 -Rows @(@{ Text = 'https://intranet.example.com:8443/health'; Method = 'tcp'; Port = 443 })
        $c.IntervalSeconds | Should -Be 10; $c.WindowMinutes | Should -Be 10; $c.Targets[0].Host | Should -Be 'intranet.example.com'; $c.Targets[0].Port | Should -Be 8443
        (ConvertFrom-VeroCheckForm -Enabled $true -IntervalSeconds 500 -WindowMinutes 0 -Rows @(@{ Text = 'intranet.example.com:8443'; Method = 'tcp'; Port = 22 })).Targets[0].Port | Should -Be 22
    }
    It 'refuses a bad address with its row number' {
        { ConvertFrom-VeroCheckForm -Enabled $true -IntervalSeconds 10 -WindowMinutes 1 -Rows @(@{ Text = '1.1.1.1'; Method = 'tcp'; Port = 443 }, @{ Text = 'not a host!'; Method = 'ping'; Port = 443 }) } | Should -Throw '*Address 2*'
    }
}

Describe 'Connection check: the rating' {
    BeforeAll {
        function New-Samples([bool[]]$oks) { $i = 0; foreach ($ok in $oks) { @{ T = 1000.0 + $i * 10; Ok = $ok; Rtt = $(if ($ok) { 40 } else { $null }) }; $i++ } }
    }
    It '<name>' -ForEach @(
        @{ name = 'all answered: good'; oks = @($true) * 10; state = 'good' }
        @{ name = '10 % is not under 10 %: unstable'; oks = @($true) * 9 + @($false); state = 'unstable' }
        @{ name = '5 %: good'; oks = @($true) * 19 + @($false); state = 'good' }
        @{ name = '50 % is not over 50 %: unstable'; oks = @($true) * 5 + @($false) * 5; state = 'unstable' }
        @{ name = '60 %: bad'; oks = @($true) * 4 + @($false) * 6; state = 'bad' }
        @{ name = 'nothing answered: bad'; oks = @($false) * 10; state = 'bad' }
    ) {
        $s = @(New-Samples $oks)
        (Measure-VeroQuality -Samples $s -Now $s[-1].T -WindowSeconds 3600).State | Should -Be $state
    }
    It 'fewer than three checks: checking' {
        $s = @(New-Samples @($true, $true))
        (Measure-VeroQuality -Samples $s -Now $s[-1].T -WindowSeconds 3600).State | Should -Be 'checking'
    }
    It 'only the window counts' {
        $s = @(New-Samples (@($false) * 10 + @($true) * 10))
        $q = Measure-VeroQuality -Samples $s -Now $s[-1].T -WindowSeconds 95
        $q.State | Should -Be 'good'; $q.Checks | Should -Be 10; $q.RttMs | Should -Be 40
    }
    It 'no rating before one full period, however many checks' {
        $s = @(New-Samples (@($true) * 18))                              # 18 answered checks in 170 s
        (Measure-VeroQuality -Samples $s -Now 1170 -WindowSeconds 300 -Since 1000).State | Should -Be 'checking'
        (Measure-VeroQuality -Samples $s -Now 1300 -WindowSeconds 300 -Since 1000).State | Should -Be 'good'
    }
    It 'the window holds at least three rounds' {
        Get-VeroCheckWindow ([pscustomobject]@{ IntervalSeconds = 100; WindowMinutes = 1 }) | Should -Be 300
        Get-VeroCheckWindow ([pscustomobject]@{ IntervalSeconds = 20; WindowMinutes = 1 }) | Should -Be 60
        Get-VeroCheckWindow ([pscustomobject]@{ IntervalSeconds = 10; WindowMinutes = 2 }) | Should -Be 120
    }
    It 'the short texts match Linux and macOS' {
        $d = [string][char]0x00B7
        Format-VeroQuality ([pscustomobject]@{ State = 'good'; LossPct = 0; RttMs = 45 }) | Should -Be "good $d 45 ms"
        Format-VeroQuality ([pscustomobject]@{ State = 'unstable'; LossPct = 22.5; RttMs = 300 }) | Should -Be "unstable $d 22.5% lost"
        Format-VeroQuality ([pscustomobject]@{ State = 'bad'; LossPct = 60.0; RttMs = $null }) | Should -Be "bad $d 60% lost"
        Format-VeroQuality $null | Should -Be ('checking' + [char]0x2026)
    }
}

Describe 'Connection check: the watchdog (mocked checks)' {
    BeforeEach {
        Set-Content -Path (Get-VeroPath).Config -Value '{"profiles":[{"profile":"Work","server":"vpn.example.com","username":"jdoe"}],"connectionCheck":{"enabled":true,"intervalSeconds":15}}'
        Mock -ModuleName VeroScudo.Core Test-VeroArmed { $true }
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $true }
        Mock -ModuleName VeroScudo.Core Invoke-VeroProbeRound { [pscustomobject]@{ Ok = $true; RttMs = 20 } }
        InModuleScope VeroScudo.Core { $script:QualitySamples.Clear(); $script:QualityKey = ''; $script:QualityLast = '' }   # each test starts fresh
        Remove-TestFile @((Get-VeroPath).LastDown)                         # earlier sync tests leave a "blocked just now" mark
    }
    AfterEach { Remove-TestFile @((Get-VeroPath).Config, (Get-VeroPath).Quality) }
    It 'checks while protected, writes the rating for the tray and waits the interval' {
        Update-VeroQuality | Should -Be 15
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroProbeRound -Times 1 -Exactly
        Test-Path (Get-VeroPath).Quality | Should -BeTrue
        (Read-VeroQuality -ProfileName 'Work').State | Should -Be 'checking'
        Read-VeroQuality -ProfileName 'Backup' | Should -BeNullOrEmpty
    }
    It 'does not check while blocked, and drops the rating' {
        Update-VeroQuality | Out-Null
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $false }
        Update-VeroQuality | Should -Be 5
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroProbeRound -Times 1 -Exactly
        Test-Path (Get-VeroPath).Quality | Should -BeFalse
    }
    It 'does nothing while off or when the check is off' {
        Mock -ModuleName VeroScudo.Core Test-VeroArmed { $false }
        Update-VeroQuality | Out-Null
        Set-Content -Path (Get-VeroPath).Config -Value '{"profiles":[{"profile":"Work","server":"vpn.example.com","username":"jdoe"}]}'
        Mock -ModuleName VeroScudo.Core Test-VeroArmed { $true }
        Update-VeroQuality | Out-Null
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroProbeRound -Times 0 -Exactly
    }
    It 'a change of the check settings starts the rating over' {
        Update-VeroQuality | Out-Null; Update-VeroQuality | Out-Null
        InModuleScope VeroScudo.Core { $script:QualityStarted -= 3600 }   # as if the first period had long passed
        Update-VeroQuality | Out-Null                                    # the third check: a rating
        (Read-VeroQuality -ProfileName 'Work').State | Should -Be 'good'
        Set-Content -Path (Get-VeroPath).Config -Value '{"profiles":[{"profile":"Work","server":"vpn.example.com","username":"jdoe"}],"connectionCheck":{"enabled":true,"intervalSeconds":15,"windowMinutes":2}}'
        Update-VeroQuality | Out-Null
        (Read-VeroQuality -ProfileName 'Work').State | Should -Be 'checking'
    }
    It 'after a drop the next connection waits a full period again' {
        Update-VeroQuality | Out-Null; Update-VeroQuality | Out-Null
        InModuleScope VeroScudo.Core { $script:QualityStarted -= 3600 }
        Update-VeroQuality | Out-Null
        (Read-VeroQuality -ProfileName 'Work').State | Should -Be 'good'
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $false }
        Update-VeroQuality | Out-Null
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $true }
        Update-VeroQuality | Out-Null
        (Read-VeroQuality -ProfileName 'Work').State | Should -Be 'checking'
    }
    It 'a Reconnect between two rounds starts the rating over (no round saw the tunnel down)' {
        Update-VeroQuality | Out-Null; Update-VeroQuality | Out-Null
        InModuleScope VeroScudo.Core { $script:QualityStarted -= 3600 }
        Update-VeroQuality | Out-Null
        (Read-VeroQuality -ProfileName 'Work').State | Should -Be 'good'
        # the kill-switch blocked a moment ago (Sync-VeroKillSwitchCore writes this on every blocked set)
        [IO.File]::WriteAllText((Get-VeroPath).LastDown, [string]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - 2))
        Update-VeroQuality | Out-Null
        (Read-VeroQuality -ProfileName 'Work').State | Should -Be 'checking'
        Remove-TestFile @((Get-VeroPath).LastDown)
    }
    It 'an old rating is not shown' {
        Update-VeroQuality | Out-Null
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        Read-VeroQuality -ProfileName 'Work' -Now ($now + 600) | Should -BeNullOrEmpty
    }
}

Describe 'Connection check: a real TCP check against a local listener' {
    It 'answered while listening, not after' {
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $l.Start()
        $port = $l.LocalEndpoint.Port
        try { $r = @(Invoke-VeroProbeRound -Targets @([pscustomobject]@{ Host = '127.0.0.1'; Method = 'tcp'; Port = $port })); $r[0].Ok | Should -BeTrue }
        finally { $l.Stop() }
        @(Invoke-VeroProbeRound -Targets @([pscustomobject]@{ Host = '127.0.0.1'; Method = 'tcp'; Port = $port }))[0].Ok | Should -BeFalse
    }
}

Describe 'Connection check: TLS for Hiddify (its TUN answers TCP and ping itself)' {
    It 'a connection that is accepted and then dropped counts for TCP, not for TLS' {
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $l.Start()
        $port = $l.LocalEndpoint.Port
        # accept and close at once - what Hiddify's TUN does when none of its servers answers
        $ps = [powershell]::Create().AddScript({ param($L) for ($i = 0; $i -lt 4; $i++) { try { $c = $L.AcceptTcpClient(); $c.Close() } catch { break } } }).AddArgument($l)
        $h = $ps.BeginInvoke()
        try {
            $t = @([pscustomobject]@{ Host = '127.0.0.1'; Method = 'tcp'; Port = $port })
            @(Invoke-VeroProbeRound -Targets $t)[0].Ok | Should -BeTrue
            @(Invoke-VeroProbeRound -Targets $t -Tls -TimeoutMs 3000)[0].Ok | Should -BeFalse
        } finally { $l.Stop(); try { $null = $ps.EndInvoke($h) } catch { Write-Verbose 'listener stopped' }; $ps.Dispose() }
    }
    It 'a Hiddify profile is checked with TLS, the others with their own method' {
        Set-Content -Path (Get-VeroPath).Config -Value '{"profiles":[{"profile":"Hiddify","type":"hiddify"}],"connectionCheck":{"enabled":true,"intervalSeconds":15}}'
        Mock -ModuleName VeroScudo.Core Test-VeroArmed { $true }
        Mock -ModuleName VeroScudo.Core Test-VeroVpnConnected { $true }
        Mock -ModuleName VeroScudo.Core Invoke-VeroProbeRound { [pscustomobject]@{ Ok = $true; RttMs = 20 } }
        Update-VeroQuality | Out-Null
        Should -Invoke -ModuleName VeroScudo.Core Invoke-VeroProbeRound -Times 1 -Exactly -ParameterFilter { $Tls -and $TimeoutMs -eq 5000 }
        Remove-TestFile @((Get-VeroPath).Config, (Get-VeroPath).Quality)
    }
}

Describe 'Statistics: minutes per profile, day rows, bar texts' {
    BeforeEach {
        InModuleScope VeroScudo.Core { $script:StatsMinute = $null; $script:StatsPruned = '' }
        $script:statsDir = Join-Path (Get-VeroPath).State 'stats'
        if (Test-Path $script:statsDir) { Remove-TestFile @(Get-ChildItem -LiteralPath $script:statsDir -File | ForEach-Object FullName) }
    }
    It 'writes one line per minute and profile with the VPN up, with the checks of that minute' {
        $t = [datetime]'2026-11-07 10:05:10'
        Update-VeroStats -Up $true -Id 'aaa' -Name 'Work' -Now $t
        Add-VeroStatsChecks -Sent 3 -Lost 1 -Id 'aaa' -Name 'Work' -Now $t.AddSeconds(20)
        Update-VeroStats -Up $true -Id 'bbb' -Name 'Home' -Now $t.AddSeconds(40)    # switched within the minute: both
        Update-VeroStats -Up $false -Now $t.AddSeconds(60)                  # 10:06, VPN down: 10:05 is written, 10:06 is not
        Update-VeroStats -Up $false -Now $t.AddSeconds(120)
        @(Get-Content -LiteralPath (Join-Path $script:statsDir '2026-11-07.jsonl')) | Should -Be @('{"m":605,"id":"aaa","p":"Work","sent":3,"lost":1}', '{"m":605,"id":"bbb","p":"Home"}')
    }
    It 'writes an up minute without checks, and the last minute when the watchdog stops' {
        Update-VeroStats -Up $true -Id 'aaa' -Name 'Work' -Now ([datetime]'2026-11-07 23:59:30')
        Save-VeroStatsMinute
        Get-Content -LiteralPath (Join-Path $script:statsDir '2026-11-07.jsonl') | Should -Be '{"m":1439,"id":"aaa","p":"Work"}'
    }
    It 'escapes names exactly like the Linux/macOS side (JSON, ASCII) and reads them back' {
        $name = "Office $([char]0x0444) `"VPN`" \ x"
        $line = Format-VeroStatsLine -Minute 5 -Id 'aaa' -Name $name -Sent 2 -Lost 0
        $line | Should -Be '{"m":5,"id":"aaa","p":"Office \u0444 \"VPN\" \\ x","sent":2,"lost":0}'
        $r = ConvertFrom-VeroStatsText -Text $line
        $r.Names['aaa'] | Should -Be $name; $r.Data['aaa'][5].Sent | Should -Be 2
    }
    It 'reads a day: adds up repeated minutes, skips broken lines and old lines without an id, keeps the last name' {
        $r = ConvertFrom-VeroStatsText -Text ('{"m":605,"id":"w","p":"W","sent":3,"lost":1}' + "`n" + '{"m":605,"id":"w","p":"W2","sent":2,"lost":0}' + "`ngarbage`n" +
                                              '{"m":606,"id":"w","p":"W2"}' + "`n" + '{"m":1500,"id":"w","p":"W"}' + "`n" + '{"m":7,"id":"w","p":"W2","sent":1,"lost":9}' + "`n" +
                                              '{"m":8,"p":"old build"}' + "`n" + '{"m":9,"id":"h","p":"H"}' + "`n")
        $r.Data['w'].Keys.Count | Should -Be 3
        $r.Data['w'][605].Sent | Should -Be 5; $r.Data['w'][605].Lost | Should -Be 1
        $r.Data['w'][7].Lost | Should -Be 1
        $r.Data['h'][9].Sent | Should -Be 0
        $r.Names['w'] | Should -Be 'W2'
        $r.Data.Keys.Count | Should -Be 2
    }
    It 'the drop-down: active first, renamed shown by its current name, a removed one by its last name' {
        $old = ConvertFrom-VeroStatsText -Text ('{"m":900,"id":"o","p":"Old office"}' + "`n" + '{"m":100,"id":"w","p":"Work"}')
        $today = ConvertFrom-VeroStatsText -Text ('{"m":60,"id":"w","p":"Corporate"}' + "`n" + '{"m":500,"id":"h","p":"Home"}')
        $days = @($today, (ConvertFrom-VeroStatsText -Text ''), $old)
        $profiles = @([pscustomobject]@{ Id = 'w'; Profile = 'Corporate VPN' }, [pscustomobject]@{ Id = 'h'; Profile = 'Home' }, [pscustomobject]@{ Id = 'n'; Profile = 'New' })
        $c = @(Get-VeroStatsChoices -Days $days -Profiles $profiles -ActiveId 'w')
        @($c | ForEach-Object Id) | Should -Be @('w', 'h', 'o')
        @($c | ForEach-Object Label) | Should -Be @('Corporate VPN', 'Home', 'Old office (removed)')
        @(Get-VeroStatsChoices -Days @() -Profiles $profiles -ActiveId 'n').Label | Should -Be 'New'
    }
    It 'rates each bar with the connection check thresholds; unrated connected time counts as good' {
        $m = @{}
        foreach ($i in 0..9) { $m[$i] = @{ Sent = 6; Lost = 0 } }
        foreach ($i in 10..19) { $m[$i] = @{ Sent = 6; Lost = 2 } }
        foreach ($i in 20..29) { $m[$i] = @{ Sent = 6; Lost = 4 } }
        foreach ($i in 30..34) { $m[$i] = @{ Sent = 0; Lost = 0 } }
        $day = ConvertTo-VeroStatsDay -Minutes $m -BucketMinutes 10
        $day.Bars.Count | Should -Be 144
        @($day.Bars[0..4] | ForEach-Object State) | Should -Be @('good', 'unstable', 'bad', 'up', 'off')
        $day.VpnMinutes | Should -Be 35
        $day.GoodPct | Should -Be 43
        Get-VeroStatsState -UpMinutes 10 -Sent 10 -Lost 1 | Should -Be 'unstable'
    }
    It 'marks the rest of today as future and a day without this profile as not used' {
        $day = ConvertTo-VeroStatsDay -Minutes @{} -UntilMinute 600
        $day.Bars[59].State | Should -Be 'off'
        $day.Bars[60].State | Should -Be 'future'
        $day.GoodPct | Should -BeNullOrEmpty
        Format-VeroStatsTotal -Day $day | Should -Be 'not used'
    }
    It 'says what a bar and a day were - the same texts as Linux/macOS' {
        $bar = [pscustomobject]@{ Start = 860; State = 'unstable'; UpMinutes = 10; Sent = 60; Lost = 11 }
        Format-VeroStatsBar -Bar $bar | Should -Be ("14:20-14:30  unstable {0} 18 % lost (11 of 60 checks), connected 10 of 10 min" -f [char]0x2013)
        Format-VeroStatsBar -Bar ([pscustomobject]@{ Start = 0; State = 'off'; UpMinutes = 0; Sent = 0; Lost = 0 }) | Should -Be '00:00-00:10  not connected'
        Format-VeroStatsTotal -Day ([pscustomobject]@{ VpnMinutes = 580; GoodPct = 87 }) | Should -Be ("connected 9 h 40 min {0} good 87 %" -f [char]0x00B7)
    }
    It 'removes only its own day files older than the kept days' {
        New-Item -ItemType Directory -Path $script:statsDir -Force | Out-Null
        foreach ($n in '2026-10-30.jsonl', '2026-10-31.jsonl', '2026-11-07.jsonl', 'notes.jsonl', 'keep.txt') { Set-Content -LiteralPath (Join-Path $script:statsDir $n) -Value '' }
        Remove-VeroOldStats -Now ([datetime]'2026-11-07 12:00')
        @(Get-ChildItem -LiteralPath $script:statsDir -File | ForEach-Object Name | Sort-Object) | Should -Be @('2026-10-31.jsonl', '2026-11-07.jsonl', 'keep.txt', 'notes.jsonl')
    }
}

Describe 'Profile ids: statistics follow a profile across a rename' {
    It 'is the first 12 hex digits of the SHA-1 of the name - the same as Linux/macOS profile_id()' {
        Get-VeroProfileId -Name 'Work' | Should -Be '00040bab8a78'                     # linux/tests/test_import.py checks the same value
        Get-VeroProfileId -Name 'Work' | Should -Match '^[0-9a-f]{12}$'
        Get-VeroProfileId -Name 'Work' -Stored 'abcdefabcdef' | Should -Be 'abcdefabcdef'
        Get-VeroProfileId -Name 'Work' -Stored 'not-an-id' | Should -Be (Get-VeroProfileId -Name 'Work')
    }
    It 'is read from config.json, made from the name when missing, and written back' {
        $c = Get-VeroConfig -Raw '{"profiles":[{"profile":"Work","server":"vpn.example.com","username":"jdoe","id":"0123456789ab"},{"profile":"Backup","server":"vpn2.example.com","username":"jdoe"}]}'
        @($c.Profiles)[0].Id | Should -Be '0123456789ab'
        @($c.Profiles)[1].Id | Should -Be (Get-VeroProfileId -Name 'Backup')
        $c.ProfileId | Should -Be '0123456789ab'
        (ConvertTo-VeroProfileObject @($c.Profiles)[1]).id | Should -Be (Get-VeroProfileId -Name 'Backup')
        { Get-VeroConfig -Raw '{"profiles":[{"profile":"A","server":"a.example.com","username":"u","id":"0123456789ab"},{"profile":"B","server":"b.example.com","username":"u","id":"0123456789ab"}]}' } | Should -Throw '*same id*'
    }
    It 'a renamed profile keeps its id; a new profile named like it gets a different one' {
        $renamed = [pscustomobject]@{ Profile = 'Office'; Id = (Get-VeroProfileId -Name 'Work') }
        $new = [pscustomobject]@{ Profile = 'Work' }
        Set-VeroProfileIds -Entries @($renamed, $new)
        $renamed.Id | Should -Be (Get-VeroProfileId -Name 'Work')
        $new.Id | Should -Match '^[0-9a-f]{12}$'
        $new.Id | Should -Not -Be $renamed.Id
    }
}

Describe 'Statistics: VeroScudo on but no connection counts as bad' {
    BeforeEach {
        InModuleScope VeroScudo.Core { $script:StatsMinute = $null; $script:StatsPruned = '' }
        $script:statsDir = Join-Path (Get-VeroPath).State 'stats'
        if (Test-Path $script:statsDir) { Remove-TestFile @(Get-ChildItem -LiteralPath $script:statsDir -File | ForEach-Object FullName) }
    }
    It 'writes a down minute for the active profile, and an up line wins over it' {
        $t = [datetime]'2026-11-07 10:05:10'
        Update-VeroStats -Up $false -Down $true -Id 'aaa' -Name 'Work' -Now $t
        Update-VeroStats -Up $false -Down $true -Id 'aaa' -Name 'Work' -Now $t.AddSeconds(60)
        Update-VeroStats -Up $true -Id 'aaa' -Name 'Work' -Now $t.AddSeconds(75)          # 10:06: connected again
        Update-VeroStats -Up $false -Now $t.AddSeconds(120)
        @(Get-Content -LiteralPath (Join-Path $script:statsDir '2026-11-07.jsonl')) | Should -Be @('{"m":605,"id":"aaa","p":"Work","down":1}', '{"m":606,"id":"aaa","p":"Work"}')
        $r = ConvertFrom-VeroStatsText -Text ('{"m":605,"id":"aaa","p":"Work","down":1}' + "`n" + '{"m":605,"id":"aaa","p":"Work","sent":3,"lost":0}')
        $r.Data['aaa'][605].Down | Should -BeFalse; $r.Data['aaa'][605].Sent | Should -Be 3
    }
    It 'a bar with 2+ minutes without a connection is bad and says so; good % counts that time' {
        $m = @{}
        foreach ($i in 0..9) { $m[$i] = @{ Sent = 3; Lost = 0; Down = $false } }
        foreach ($i in 10..16) { $m[$i] = @{ Sent = 0; Lost = 0; Down = $true } }
        foreach ($i in 17..19) { $m[$i] = @{ Sent = 3; Lost = 0; Down = $false } }
        $m[25] = @{ Sent = 0; Lost = 0; Down = $true }                                  # one minute: not "could not connect" yet
        $day = ConvertTo-VeroStatsDay -Minutes $m
        @($day.Bars[0..2] | ForEach-Object State) | Should -Be @('good', 'bad', 'off')
        $day.VpnMinutes | Should -Be 13; $day.DownMinutes | Should -Be 8; $day.GoodPct | Should -Be 48   # 10 of 21
        Format-VeroStatsBar -Bar $day.Bars[1] | Should -Be '00:10-00:20  could not connect 7 of 10 min (VeroScudo on); connected 3 of 10 min'
        Format-VeroStatsTotal -Day $day | Should -Be ("connected 13 min {0} good 48 % {0} no connection 8 min" -f [char]0x00B7)
        Format-VeroStatsTotal -Day ([pscustomobject]@{ VpnMinutes = 0; DownMinutes = 12; GoodPct = 0 }) | Should -Be ("no connection 12 min {0} good 0 %" -f [char]0x00B7)
    }
}

Describe 'Connection check: slow answers (over 1 s per round trip)' {
    It 'marks an answer over 1000 ms per round trip slow: ping/TCP 1, a TLS handshake 2, HTTPS 3 (= quality.judge)' {
        Test-VeroCheckInTime 'ping' 1000 | Should -BeTrue
        Test-VeroCheckInTime 'ping' 1001 | Should -BeFalse
        Test-VeroCheckInTime 'tcp' 1500 | Should -BeFalse
        Test-VeroCheckInTime 'tcp' 1500 -Tls | Should -BeTrue
        Test-VeroCheckInTime 'ping' 2001 -Tls | Should -BeFalse
        Test-VeroCheckInTime 'https' 2900 | Should -BeTrue
        Test-VeroCheckInTime 'https' 3001 | Should -BeFalse
    }
    It 'rates slow answers like partial loss: unstable, never bad (= quality.rating)' {
        Get-VeroQualityRating 0 0 18 | Should -Be 'good'
        Get-VeroQualityRating 0 1 18 | Should -Be 'good'
        Get-VeroQualityRating 0 2 18 | Should -Be 'unstable'
        Get-VeroQualityRating 0 18 18 | Should -Be 'unstable'
        Get-VeroQualityRating 1 1 18 | Should -Be 'unstable'
        Get-VeroQualityRating 10 8 18 | Should -Be 'bad'
        $samples = @(0..5 | ForEach-Object { @{ T = 100.0 + $_; Ok = $true; Rtt = 1400; Ti = 0; Slow = $true } })
        $q = Measure-VeroQuality -Samples $samples -Now 106 -WindowSeconds 60
        $q.State | Should -Be 'unstable'; $q.Lost | Should -Be 0; $q.Slow | Should -Be 6; $q.RttMs | Should -Be 1400
        $d = [char]0x00B7
        Format-VeroQuality $q | Should -Be "unstable $d 100% slow, 1400 ms"
        Format-VeroQuality ([pscustomobject]@{ State = 'unstable'; LossPct = 11.1; RttMs = 300; Checks = 18; Lost = 2; Slow = 3 }) | Should -Be "unstable $d 11.1% lost, 16.7% slow"
    }
    It 'records slow answers in the statistics; a bar of slow answers is unstable, not bad (= stats.py)' {
        Format-VeroStatsLine -Minute 5 -Id 'w' -Name 'W' -Sent 6 -Lost 0 -Slow 6 | Should -Be '{"m":5,"id":"w","p":"W","sent":6,"lost":0,"slow":6}'
        Format-VeroStatsLine -Minute 5 -Id 'w' -Name 'W' -Sent 6 -Lost 1 | Should -Be '{"m":5,"id":"w","p":"W","sent":6,"lost":1}'
        $r = ConvertFrom-VeroStatsText -Text ('{"m":5,"id":"w","p":"W","sent":6,"lost":2,"slow":9}' + "`n" + '{"m":5,"id":"w","p":"W","sent":6,"lost":0,"slow":1}' + "`n" + '{"m":6,"id":"w","p":"W","down":1}')
        $r.Data['w'][5].Sent | Should -Be 12; $r.Data['w'][5].Lost | Should -Be 2; $r.Data['w'][5].Slow | Should -Be 5   # 9 capped at 6 - 2
        $r.Data['w'][6].Down | Should -BeTrue
        Get-VeroStatsState -UpMinutes 10 -Sent 60 -Lost 0 -Slow 60 | Should -Be 'unstable'
        Get-VeroStatsState -UpMinutes 10 -Sent 60 -Lost 0 -Slow 5 | Should -Be 'good'
        Get-VeroStatsState -UpMinutes 10 -Sent 60 -Lost 40 -Slow 20 | Should -Be 'bad'
        $m = @{}; foreach ($i in 0..9) { $m[$i] = @{ Sent = 6; Lost = 0; Down = $false; Slow = 6 } }
        $day = ConvertTo-VeroStatsDay -Minutes $m
        $day.Bars[0].State | Should -Be 'unstable'; $day.Bars[0].Slow | Should -Be 60
        Format-VeroStatsBar -Bar $day.Bars[0] | Should -Be ("00:00-00:10  unstable {0} 0 % lost (0 of 60 checks), 60 slow (over 1 s), connected 10 of 10 min" -f [char]0x2013)
    }
}

Describe 'Connection check: HTTPS method and per-address results' {
    It 'accepts https with a port, writes it back, and names each address' {
        $c = ConvertFrom-VeroCheckConfig ('{"enabled":true,"targets":[{"host":"api.example.com","method":"https"},{"host":"203.0.113.5","method":"https","port":8443},{"host":"1.1.1.1","method":"ping"}]}' | ConvertFrom-Json)
        @($c.Targets | ForEach-Object { Get-VeroCheckLabel $_ }) | Should -Be @('api.example.com (HTTPS)', '203.0.113.5:8443 (HTTPS)', '1.1.1.1 (ping)')
        (ConvertTo-VeroCheckObject $c).targets[1].port | Should -Be 8443
        (ConvertTo-VeroCheckObject $c).targets[0].method | Should -Be 'https'
        { ConvertFrom-VeroCheckConfig ('{"targets":[{"host":"x.example.com","method":"ftp"}]}' | ConvertFrom-Json) } | Should -Throw "*'ping', 'tcp' or 'https'*"
        $f = ConvertFrom-VeroCheckForm -Enabled $true -IntervalSeconds 10 -WindowMinutes 1 -Rows @(@{ Text = 'https://api.example.com/v1'; Method = 'https'; Port = 443 })
        $f.Targets[0].Method | Should -Be 'https'; $f.Targets[0].Host | Should -Be 'api.example.com'; $f.Targets[0].Port | Should -Be 443
    }
    It 'counts each address in the window' {
        $s = @(@{ T = 100.0; Ok = $true; Ti = 0 }, @{ T = 100.0; Ok = $false; Ti = 1 }, @{ T = 110.0; Ok = $true; Ti = 0 }, @{ T = 110.0; Ok = $false; Ti = 1 }, @{ T = 10.0; Ok = $false; Ti = 0 })
        $t = @((New-Object psobject -Property @{ Host = '1.1.1.1'; Method = 'tcp'; Port = 443 }), (New-Object psobject -Property @{ Host = 'api.example.com'; Method = 'https'; Port = 443 }))
        $per = @(Get-VeroQualityPerTarget -Samples $s -Targets $t -Now 120 -WindowSeconds 60)
        $per[0].label | Should -Be '1.1.1.1:443'; $per[0].checks | Should -Be 2; $per[0].lost | Should -Be 0
        $per[1].label | Should -Be 'api.example.com (HTTPS)'; $per[1].lost | Should -Be 2
    }
    It 'an HTTPS target to a port that does not speak TLS is not reached' {
        $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0); $l.Start()
        $port = $l.LocalEndpoint.Port
        $ps = [powershell]::Create().AddScript({ param($L) for ($i = 0; $i -lt 2; $i++) { try { $c = $L.AcceptTcpClient(); $c.Close() } catch { break } } }).AddArgument($l)
        $h = $ps.BeginInvoke()
        try { @(Invoke-VeroProbeRound -Targets @([pscustomobject]@{ Host = '127.0.0.1'; Method = 'https'; Port = $port }))[0].Ok | Should -BeFalse }
        finally { $l.Stop(); try { $null = $ps.EndInvoke($h) } catch { Write-Verbose 'listener stopped' }; $ps.Dispose() }
    }
}
