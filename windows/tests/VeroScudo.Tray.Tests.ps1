# Pester 5 unit tests for the tray's decisions (VeroScudo.Tray.psm1). No window is created; files only in a fresh temp folder.
BeforeAll {
    Get-Module VeroScudo.Tray, VeroScudo.Core | Remove-Module -Force
    Import-Module (Join-Path $PSScriptRoot '..\VeroScudo.Core.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '..\VeroScudo.Tray.psm1') -Force
    $script:TrayTestDir = Join-Path ([IO.Path]::GetTempPath()) ("veroscudo-tray-test-" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $script:TrayTestDir -Force | Out-Null
    function Facts([hashtable]$over) {
        $f = @{ Configured = $true; Name = 'Work'; Type = 'ras'; Armed = $true; Up = $true; Cred = $true; AuthBlocked = $false; Otp = $null; Conflicts = @(); Expect = $null; NativeNext = $null }
        foreach ($k in $over.Keys) { $f[$k] = $over[$k] }
        $f
    }
}
AfterAll {
    # only ever the folder this file created (a temp folder named veroscudo-tray-test-<guid>); errors are shown, never silenced
    if ($script:TrayTestDir -like (Join-Path ([IO.Path]::GetTempPath()) 'veroscudo-tray-test-*')) { Remove-Item -LiteralPath $script:TrayTestDir -Recurse -Force }
}

Describe 'ConvertTo-VeroTrayState: the tray state, title and text' {
    It 'not configured' {
        $v = ConvertTo-VeroTrayState @{ Configured = $false }
        $v.State | Should -Be 'attention'; $v.Title | Should -Be 'Not configured'; $v.Armed | Should -BeFalse
    }
    It 'protected: armed and up' {
        $v = ConvertTo-VeroTrayState (Facts @{})
        $v.State | Should -Be 'protected'; $v.Title | Should -Be 'Protected'; $v.Text | Should -Match "Work \(Windows VPN\) is connected"; $v.Connected | Should -BeTrue
    }
    It 'blocked: armed and down, with the phase you asked for' {
        (ConvertTo-VeroTrayState (Facts @{ Up = $false })).Title | Should -Be 'Blocked - reconnecting'
        (ConvertTo-VeroTrayState (Facts @{ Up = $false; Expect = 'connect' })).Title | Should -Be 'Connecting'
        (ConvertTo-VeroTrayState (Facts @{ Up = $false; Expect = 'switch' })).Title | Should -Be 'Switching'
        $v = ConvertTo-VeroTrayState (Facts @{ Up = $false; Expect = 'reconnect' })
        $v.Title | Should -Be 'Reconnecting'; $v.Expected | Should -BeTrue; $v.State | Should -Be 'blocked'
    }
    It 'off: not armed, whatever the tunnel does' {
        $v = ConvertTo-VeroTrayState (Facts @{ Armed = $false; Up = $true })
        $v.State | Should -Be 'off'; $v.Title | Should -Be 'Off'; $v.Connected | Should -BeTrue
    }
    It 'attention, in order of precedence: helper blocked, password missing, password rejected, code needed' {
        (ConvertTo-VeroTrayState (Facts @{ NativeNext = '12:30'; Cred = $false })).Title | Should -Be 'Helper blocked'
        (ConvertTo-VeroTrayState (Facts @{ Cred = $false; AuthBlocked = $true })).Title | Should -Be 'Password missing'
        (ConvertTo-VeroTrayState (Facts @{ AuthBlocked = $true; Otp = '1234' })).Title | Should -Be 'Password rejected'
        $v = ConvertTo-VeroTrayState (Facts @{ Otp = 'push 42' })
        $v.Title | Should -Be 'Code needed'; $v.Text | Should -Match 'push 42'; $v.State | Should -Be 'attention'
    }
    It 'guard not running: the watchdog has been silent for minutes (like Linux), after a blocked helper' {
        $v = ConvertTo-VeroTrayState (Facts @{ GuardStale = 5 })
        $v.State | Should -Be 'attention'; $v.Title | Should -Be 'Guard not running'; $v.Text | Should -Match 'not run for 5 min'
        (ConvertTo-VeroTrayState (Facts @{ GuardStale = 5; NativeNext = '12:30' })).Title | Should -Be 'Helper blocked'
        (ConvertTo-VeroTrayState (Facts @{ GuardStale = 0 })).Title | Should -Be 'Protected'
    }
    It 'a conflict while protected is a note, not a loss of protection' {
        $v = ConvertTo-VeroTrayState (Facts @{ Conflicts = @('another VPN is up', 'a filter layer') })
        $v.State | Should -Be 'attention'; $v.Title | Should -Be 'Protected'; $v.Text | Should -Match '^Note: another VPN is up \(\+1 more'
        (ConvertTo-VeroTrayState (Facts @{ Up = $false; Conflicts = @('x') })).State | Should -Be 'blocked'   # down: the conflict waits
    }
}

Describe 'ConvertTo-VeroExitView: the location line' {
    BeforeAll { $script:info = @{ Ip = '203.0.113.9'; Country = 'DE'; City = 'Berlin'; Org = 'Example AS'; Source = 'ipinfo'; Time = '2026-11-04T10:00:00.0000000+00:00'; Profile = 'Work' } }
    It 'nothing known yet: three messages' {
        (ConvertTo-VeroExitView -Info $null -State 'off').Text | Should -Be 'Location: shown once the VPN is connected'
        (ConvertTo-VeroExitView -Info $null -State 'protected' -Checking).Text | Should -Match '^Checking'
        (ConvertTo-VeroExitView -Info $null -State 'protected' -Failure 'timeout').Text | Should -Be 'Location not available - timeout'
    }
    It 'fresh: protected, same profile, looked up after the tunnel came up' {
        $v = ConvertTo-VeroExitView -Info $script:info -State 'protected' -ProfileName 'Work' -ProtectedSince ([datetime]'2026-11-04T09:00:00Z')
        $v.Has | Should -BeTrue; $v.Fresh | Should -BeTrue; $v.Right | Should -Be '203.0.113.9'; $v.Code | Should -Be 'DE'; $v.Place | Should -Be 'Germany / Berlin'
    }
    It 'stale: an older lookup, another profile, or not protected - shown grey with its time' {
        (ConvertTo-VeroExitView -Info $script:info -State 'protected' -ProfileName 'Work' -ProtectedSince ([datetime]'2026-11-04T11:00:00Z')).Fresh | Should -BeFalse
        (ConvertTo-VeroExitView -Info $script:info -State 'protected' -ProfileName 'Backup').Fresh | Should -BeFalse
        $v = ConvertTo-VeroExitView -Info $script:info -State 'blocked' -ProfileName 'Work'
        $v.Fresh | Should -BeFalse; $v.Right | Should -Match '^203\.0\.113\.9 - \d\d:\d\d$'
    }
    It 'a running lookup says so; preview is always fresh' {
        (ConvertTo-VeroExitView -Info $script:info -State 'protected' -ProfileName 'Work' -Checking).Right | Should -Be 'checking...'
        (ConvertTo-VeroExitView -Info $script:info -State 'protected' -ProfileName 'Work' -ProtectedSince ([datetime]'2026-11-04T11:00:00Z') -Preview).Fresh | Should -BeTrue
    }
    It 'Refresh never looks like nothing happened: a failed or refused one is shown next to the old values' {
        $v = ConvertTo-VeroExitView -Info $script:info -State 'protected' -ProfileName 'Work' -Failure 'ipinfo.io: timeout'
        $v.Right | Should -Match '^203\.0\.113\.9 - \d\d:\d\d - refresh failed$'; $v.Fresh | Should -BeFalse; $v.Tip | Should -Match 'Refresh: ipinfo.io: timeout'
        (ConvertTo-VeroExitView -Info $script:info -State 'off' -ProfileName 'Work' -Failure 'no VPN tunnel is up - nothing to check').Right | Should -Match 'no VPN tunnel is up - nothing to check$'
    }
    It 'a tunnel that is up counts also with VeroScudo off or in "Protected + note"; Hiddify gets a note' {
        (ConvertTo-VeroExitView -Info $script:info -State 'off' -ProfileName 'Work' -Connected -ProtectedSince ([datetime]'2026-11-04T09:00:00Z')).Fresh | Should -BeTrue
        (ConvertTo-VeroExitView -Info $script:info -State 'attention' -ProfileName 'Work' -Connected -ProtectedSince ([datetime]'2026-11-04T09:00:00Z')).Fresh | Should -BeTrue
        (ConvertTo-VeroExitView -Info $script:info -State 'off' -ProfileName 'Work').Fresh | Should -BeFalse
        (ConvertTo-VeroExitView -Info $script:info -State 'protected' -ProfileName 'Work' -Hiddify).Tip | Should -Match 'Hiddify spreads traffic over several servers'
    }
}

Describe 'Test-VeroTrayFileChanged: once per new write' {
    It 'first sight is not a change; a rewrite is; a missing file never is' {
        $f = Join-Path $script:TrayTestDir 'state.json'; $stamps = @{}
        Test-VeroTrayFileChanged -Path (Join-Path $script:TrayTestDir 'never.json') -Stamps $stamps | Should -BeFalse   # missing
        Set-Content -LiteralPath $f -Value 'a'; (Get-Item -LiteralPath $f).LastWriteTimeUtc = [datetime]'2026-11-04T10:00:00Z'
        Test-VeroTrayFileChanged -Path $f -Stamps $stamps | Should -BeFalse          # first sight
        Test-VeroTrayFileChanged -Path $f -Stamps $stamps | Should -BeFalse          # unchanged
        (Get-Item -LiteralPath $f).LastWriteTimeUtc = [datetime]'2026-11-04T10:00:05Z'
        Test-VeroTrayFileChanged -Path $f -Stamps $stamps | Should -BeTrue           # the guard wrote it
        Test-VeroTrayFileChanged -Path $f -Stamps $stamps | Should -BeFalse
    }
    It 'a file the guard creates after the tray started counts as a change' {
        $f = Join-Path $script:TrayTestDir 'later.json'; $stamps = @{}
        Test-VeroTrayFileChanged -Path $f -Stamps $stamps | Should -BeFalse          # not there yet: remembered as such
        Set-Content -LiteralPath $f -Value 'a'
        Test-VeroTrayFileChanged -Path $f -Stamps $stamps | Should -BeTrue
    }
}

Describe 'tray preferences (tray.json)' {
    It 'defaults when the file is missing or unreadable, and a round trip' {
        $f = Join-Path $script:TrayTestDir 'prefs\tray.json'
        $d = Get-VeroTrayPref -Path $f
        $d.keepAwake | Should -BeFalse; $d.showExit | Should -BeTrue; $d.exitInfo | Should -BeNullOrEmpty
        Set-VeroTrayPref -Path $f -Key 'keepAwake' -Value $true
        Set-VeroTrayPref -Path $f -Key 'lastProfile' -Value 'Backup'
        $p = Get-VeroTrayPref -Path $f
        $p.keepAwake | Should -BeTrue; $p.lastProfile | Should -Be 'Backup'; $p.showExit | Should -BeTrue
        Set-Content -LiteralPath $f -Value '{not json'
        (Get-VeroTrayPref -Path $f).keepAwake | Should -BeFalse
    }
}

Describe 'Resolve-VeroUpdateNotice: the update check decision' {
    It 'no release, or none newer: nothing to show' {
        $r = Resolve-VeroUpdateNotice -Info @{ checked = ''; notified = '' } -Release $null
        $r.Update | Should -BeNullOrEmpty; $r.MenuText | Should -Be 'Check for updates'; $r.Balloon | Should -BeFalse; $r.Info.checked | Should -Not -BeNullOrEmpty
        (Resolve-VeroUpdateNotice -Info @{ checked = ''; notified = '' } -Release ([pscustomobject]@{ Tag = 'v0.1.0'; Url = 'x' })).Update | Should -BeNullOrEmpty
    }
    It 'a newer release: the menu says so, the balloon once per tag' {
        $rel = [pscustomobject]@{ Tag = 'v9.9.9'; Url = 'https://github.com/GomelHawk/VeroScudo/releases/tag/v9.9.9' }
        $r = Resolve-VeroUpdateNotice -Info @{ checked = ''; notified = '' } -Release $rel
        $r.Update.Tag | Should -Be 'v9.9.9'; $r.MenuText | Should -Be 'Update available: v9.9.9'; $r.Balloon | Should -BeTrue; $r.Info.notified | Should -Be 'v9.9.9'
        $again = Resolve-VeroUpdateNotice -Info $r.Info -Release $rel
        $again.Balloon | Should -BeFalse; $again.Update.Tag | Should -Be 'v9.9.9'
    }
}

Describe 'Test-VeroUacCancelled: No on the UAC prompt, recognised by its code (the text is in the system language)' {
    It 'is true for ERROR_CANCELLED, also when wrapped (a .NET method call wraps it)' {
        $w = New-Object System.ComponentModel.Win32Exception 1223
        Test-VeroUacCancelled $w | Should -BeTrue
        Test-VeroUacCancelled (New-Object System.Management.Automation.MethodInvocationException 'x', $w) | Should -BeTrue
    }
    It 'is false for any other failure, and for nothing' {
        Test-VeroUacCancelled (New-Object System.ComponentModel.Win32Exception 2) | Should -BeFalse
        Test-VeroUacCancelled (New-Object System.InvalidOperationException 'Operation canceled by the user') | Should -BeFalse
        Test-VeroUacCancelled $null | Should -BeFalse
    }
    It 'the elevated save starts PowerShell through Process.Start, so the code survives' {
        $src = Get-Content (Join-Path $PSScriptRoot '..\VeroScudoTray.ps1') -Raw
        $src | Should -Match '\[System\.Diagnostics\.Process\]::Start\(\$si\)'
        $src | Should -Not -Match 'Start-Process \$psExe -Verb RunAs'
    }
}

Describe 'the tray native helpers (VeroScudo.Tray.cs) compile' {
    It 'compiles with the references the tray uses and defines every class the tray calls' -Skip:($env:OS -ne 'Windows_NT') {
        $src = Get-Content (Join-Path $PSScriptRoot '..\VeroScudo.Tray.cs') -Raw
        { Add-Type -ReferencedAssemblies System.Windows.Forms, System.Drawing -TypeDefinition $src -ErrorAction Stop } | Should -Not -Throw
        foreach ($t in 'VeroNative', 'VeroKeepAwake', 'VeroTrayIcon', 'VeroTheme', 'VeroMenuRenderer', 'VeroMsg', 'VeroCombo', 'VeroCheck') { ($t -as [type]) | Should -Not -BeNullOrEmpty -Because $t }
        [VeroMsg]::Show.OverloadDefinitions.Count | Should -Be 4
        ([VeroCombo] -as [type]).IsSubclassOf([System.Windows.Forms.ComboBox]) | Should -BeTrue
        ([VeroCheck] -as [type]).IsSubclassOf([System.Windows.Forms.CheckBox]) | Should -BeTrue
        [VeroTheme]::Dark().Frame.IsEmpty | Should -BeFalse; [VeroTheme]::Light().Frame.IsEmpty | Should -BeFalse
    }
}
Describe 'ConvertTo-VeroConnectionView: the CONNECTION card, tooltip and menu header' {
    BeforeAll {
        $script:chkOn = [pscustomobject]@{ Enabled = $true; IntervalSeconds = 10; WindowMinutes = 2; Targets = @([pscustomobject]@{ Host = '1.1.1.1'; Method = 'tcp'; Port = 443 }, [pscustomobject]@{ Host = '10.0.0.1'; Method = 'ping'; Port = 443 }) }
        $script:chkOff = [pscustomobject]@{ Enabled = $false; IntervalSeconds = 10; WindowMinutes = 1; Targets = @() }
        function Q([string]$s, [double]$loss = 0, $rtt = 45) { [pscustomobject]@{ State = $s; LossPct = $loss; RttMs = $rtt; Checks = 12; Lost = 2 } }
        $script:d = [string][char]0x00B7
    }
    It 'protected and rated: the quality, its colour and the word' {
        $v = ConvertTo-VeroConnectionView -St (ConvertTo-VeroTrayState (Facts @{})) -Check $script:chkOn -Quality (Q 'unstable' 22.2 310)
        $v.Text | Should -Be "unstable $($script:d) 22.2% lost"; $v.Tone | Should -Be 'warn'; $v.Word | Should -Be 'Unstable'
        $v.Tip | Should -Match '12 checks in the last 2 min: 2 lost'; $v.Tip | Should -Match '1.1.1.1:443, 10.0.0.1 \(ping\)'
        (ConvertTo-VeroConnectionView -St (ConvertTo-VeroTrayState (Facts @{})) -Check $script:chkOn -Quality (Q 'good')).Tone | Should -Be 'good'
        (ConvertTo-VeroConnectionView -St (ConvertTo-VeroTrayState (Facts @{})) -Check $script:chkOn -Quality (Q 'bad' 70)).Tone | Should -Be 'bad'
    }
    It '<name>' -ForEach @(
        @{ name = 'not rated yet: checking'; f = @{}; on = $true; text = 'checking' + [char]0x2026 }
        @{ name = 'check off'; f = @{}; on = $false; text = 'connected (check off)' }
        @{ name = 'blocked: redialing'; f = @{ Up = $false }; on = $true; text = 'redialing' }
        @{ name = 'switching'; f = @{ Up = $false; Expect = 'switch' }; on = $true; text = 'switching' }
        @{ name = 'off'; f = @{ Armed = $false; Up = $false }; on = $true; text = '-' }
        @{ name = 'off, VPN still connected'; f = @{ Armed = $false }; on = $true; text = 'connected (VPN off)' }
    ) {
        $st = ConvertTo-VeroTrayState (Facts $f)
        $v = ConvertTo-VeroConnectionView -St $st -Check $(if ($on) { $script:chkOn } else { $script:chkOff }) -Quality $null -Expect ([string]$f['Expect'])
        $v.Text | Should -Be $text; $v.Word | Should -BeNullOrEmpty
    }
    It 'the tooltip carries the word and stays within 63 characters' {
        Get-VeroTrayTip -Title 'Protected' -Word 'Good' | Should -Be 'VeroScudo - Protected, connection good'
        Get-VeroTrayTip -Title 'Protected' | Should -Be 'VeroScudo - Protected'
        (Get-VeroTrayTip -Title 'Protected' -Word 'Unstable' -Awake).Length | Should -BeLessOrEqual 63
    }
}

Describe 'ConvertTo-VeroStatusPageView: a service status page line' {
    It 'name and description, toned by the indicator' {
        $ok = '{"page":{"name":"Anthropic"},"status":{"indicator":"none","description":"All Systems Operational"}}'
        $v = ConvertTo-VeroStatusPageView -Json $ok -Url 'https://status.example.com/api/v2/status.json' -Time ([datetime]'2026-11-09 14:05')
        $v.Text | Should -Be 'Anthropic: All Systems Operational'; $v.Tone | Should -Be 'good'; $v.Tip | Should -Match 'checked 14:05 from https://status.example.com'
        $v.Badge | Should -Be 'OK'; $v.Name | Should -Be 'Anthropic'; $v.Right | Should -Be ("All Systems Operational {0} 14:05" -f [char]0x00B7)
        (ConvertTo-VeroStatusPageView -Json ($ok -replace '"none"', '"major"') -Url 'https://s.example.com/x').Badge | Should -Be '!!'
        (ConvertTo-VeroStatusPageView -Json ($ok -replace '"none"', '"minor"') -Url 'https://s.example.com/x').Tone | Should -Be 'warn'
        (ConvertTo-VeroStatusPageView -Json ($ok -replace '"none"', '"critical"') -Url 'https://s.example.com/x').Tone | Should -Be 'bad'
    }
    It 'unreachable or not a status page: says so with the host' {
        $v = ConvertTo-VeroStatusPageView -Json '' -Url 'https://status.example.com/api/v2/status.json' -Failure 'timeout'
        $v.Text | Should -Be 'status.example.com: not reachable'; $v.Tip | Should -Match 'timeout'
        $v.Badge | Should -Be '?'; $v.Name | Should -Be 'status.example.com'; $v.Right | Should -Match '^not reachable '
        (ConvertTo-VeroStatusPageView -Json '<html>' -Url 'https://status.example.com/x').Text | Should -Be 'status.example.com: not reachable'
    }
}

Describe 'Get-VeroTrayPref: every key the tray uses survives a read' {
    It 'keeps the status page switch and address (live: saved, but read back as off)' {
        $f = Join-Path $script:TrayTestDir 'tray-pref.json'
        Set-VeroTrayPref -Path $f -Key 'statusPage' -Value $true
        Set-VeroTrayPref -Path $f -Key 'statusPageUrl' -Value 'https://status.example.com/api/v2/status.json'
        $p = Get-VeroTrayPref -Path $f
        $p.statusPage | Should -BeTrue; $p.statusPageUrl | Should -Be 'https://status.example.com/api/v2/status.json'
        $p.showExit | Should -BeTrue
    }
}

Describe 'Hiddify: blocked means waiting for you, not reconnecting' {
    It 'title, text and the CONNECTION card say what really happens (VeroScudo never dials Hiddify)' {
        $f = @{ Configured = $true; Name = 'Hiddify'; Type = 'hiddify'; Armed = $true; Up = $false; Cred = $true; AuthBlocked = $false; Otp = $null; Conflicts = @(); Expect = $null; NativeNext = $null }
        $st = ConvertTo-VeroTrayState $f
        $st.Title | Should -Be 'Blocked - waiting for Hiddify'; $st.Text | Should -Match 'connect it in Hiddify'
        (ConvertTo-VeroConnectionView -St $st -Check $null -Quality $null -Hiddify).Text | Should -Be 'waiting for Hiddify'
        (ConvertTo-VeroConnectionView -St $st -Check $null -Quality $null).Text | Should -Be 'redialing'
    }
}
