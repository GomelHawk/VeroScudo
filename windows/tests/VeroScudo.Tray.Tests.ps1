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
        $r.Update.Tag | Should -Be 'v9.9.9'; $r.MenuText | Should -Be ('Update available: v9.9.9' + [char]0x2026);   # the same text as the Linux and macOS menus $r.Balloon | Should -BeTrue; $r.Info.notified | Should -Be 'v9.9.9'
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
    It 'an older good answer kept after a failed check: the failure goes into the tooltip (= statuspage.service_view failed=)' {
        $ok = '{"page":{"name":"Example"},"status":{"indicator":"none","description":"All Systems Operational"}}'
        $v = ConvertTo-VeroStatusPageView -Json $ok -Url 'https://status.example.com/x' -Time ([datetime]'2026-11-09 14:05') -LaterFailure 'timed out'
        $v.Badge | Should -Be 'OK'; $v.Right | Should -Be ("All Systems Operational {0} 14:05" -f [char]0x00B7)
        $v.Tip | Should -Match 'later check failed: timed out'
    }
}

Describe 'Get-VeroTrayPref: every key the tray uses survives a read' {
    It 'keeps the status page switch and address (was saved, but read back as off)' {
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

Describe 'New-VeroSaveCommand: what the administrator approves holds no text from a path' {
    It 'a folder name with <what> cannot end a string or add a command' -ForEach @(
        @{ what = 'an apostrophe';        dir = "C:\Users\O'Brien\AppData\Local\VeroScudo" }
        @{ what = 'typographic quotes';   dir = ('C:\Users\x' + [char]0x2019 + '; Start-Process calc; ' + [char]0x2018 + '\VeroScudo') }
        @{ what = 'a subexpression';      dir = 'C:\Users\$(Start-Process calc)\VeroScudo' }
        @{ what = 'braces and semicolons'; dir = 'C:\Users\a}; Start-Process calc; try{\VeroScudo' }
    ) {
        $hash = 'a' * 64
        $payload = Join-Path $dir 'save-0123456789abcdef0123456789abcdef.json'
        $cmd = New-VeroSaveCommand -Module (Join-Path $dir 'VeroScudo.Core.psm1') -Payload $payload -Sha256 $hash
        $cmd | Should -Not -Match 'calc'
        $errs = $null; $tokens = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($cmd, [ref]$tokens, [ref]$errs)
        @($errs).Count | Should -Be 0
        # exactly the commands VeroScudo wrote: nothing a path could have added
        $names = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() })
        $names | Should -Be @('Import-Module', 'Import-VeroSavePayload')
        # and the path comes back unchanged from its encoded form
        $b64 = @([regex]::Matches($cmd, "FromBase64String\('([A-Za-z0-9+/=]+)'\)") | ForEach-Object { $_.Groups[1].Value })
        [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64[1])) | Should -Be $payload
    }
    It 'refuses a hash that is not 64 hex digits' {
        { New-VeroSaveCommand -Module 'C:\m.psm1' -Payload 'C:\p.json' -Sha256 "abc'; calc; '" } | Should -Throw
    }
    It 'pins the module path without calling a cmdlet first' {
        $cmd = New-VeroSaveCommand -Module 'C:\m.psm1' -Payload 'C:\p.json' -Sha256 ('0' * 64)
        $cmd.Substring(0, $cmd.IndexOf('try {')) | Should -Not -Match 'Join-Path'
    }
}

Describe 'text from the network is shown as one short line' {
    It 'cuts a status page name and description and removes line breaks' {
        $json = @{ page = @{ name = ('N' * 500) }; status = @{ indicator = 'none'; description = ("line1`r`nVeroScudo: Protected" + ('x' * 500)) } } | ConvertTo-Json -Depth 4
        $v = ConvertTo-VeroStatusPageView -Json $json -Url 'https://status.example.com/api/v2/status.json' -Time (Get-Date)
        $v.Name.Length | Should -BeLessOrEqual 60
        $v.Text | Should -Not -Match "[`r`n]"
        $v.Text.Length | Should -BeLessOrEqual 200
    }
    It 'takes an answer without an indicator as unknown, not as an error' {
        $json = '{"status":{"description":"All fine"}}'
        $v = ConvertTo-VeroStatusPageView -Json $json -Url 'https://status.example.com/api/v2/status.json' -Time (Get-Date)
        $v.Badge | Should -Be '?'
    }
}

Describe 'Test-VeroStatusPageUrl' {
    It '<url> -> <ok>' -ForEach @(
        @{ url = 'https://status.claude.com/api/v2/status.json'; ok = $true }
        @{ url = 'https://status.example.com'; ok = $true }
        @{ url = 'http://status.example.com/api/v2/status.json'; ok = $false }
        @{ url = 'https://'; ok = $false }
        @{ url = 'https:///path'; ok = $false }
        @{ url = "https://status.example.com/x`n"; ok = $false }
        @{ url = 'https://status.example.com/a b'; ok = $false }
        @{ url = 'file:///C:/x'; ok = $false }
        @{ url = ''; ok = $false }
        @{ url = ('https://a.example.com/' + ('x' * 300)); ok = $false }
    ) { Test-VeroStatusPageUrl $url | Should -Be $ok }
}

Describe 'Get-VeroUpdateClickText: every outcome of "Check for updates" is said' {
    It 'blocked, no answer, latest' {
        Get-VeroUpdateClickText -Blocked | Should -Be 'Traffic is blocked right now - check again once the VPN is connected.'
        Get-VeroUpdateClickText -NoAnswer -Version '1.3.0' | Should -Be 'The update check got no answer - try again later.'
        Get-VeroUpdateClickText -Version '1.3.0' | Should -Be 'You have the latest version (1.3.0).'
    }
    It 'says the same as the Linux and macOS trays' {
        $py = Get-Content (Join-Path $PSScriptRoot '..\..\linux\veroscudo\traymodel.py') -Raw -ErrorAction SilentlyContinue
        if (-not $py) { Set-ItResult -Skipped -Because 'the linux folder is not part of this copy'; return }
        $py | Should -Match ([regex]::Escape('The update check got no answer - try again later.'))
        $py -replace '"\s*\r?\n\s*"', '' | Should -Match ([regex]::Escape('Traffic is blocked right now - check again once the VPN is connected.'))
    }
}

Describe 'Resolve-VeroTrayExpect: the phase you asked for' {
    BeforeAll { $script:t0 = [datetime]'2026-11-16 12:00:00'; function Phase([string]$k, [int]$ageSec) { @{ Kind = $k; Since = $script:t0.AddSeconds(-$ageSec); Until = $script:t0.AddSeconds(120 - $ageSec) } } }
    It 'blocked right after off, with nothing asked here: turned on elsewhere - a connect phase starts' {
        $r = Resolve-VeroTrayExpect -Expect $null -State 'blocked' -Armed $true -Last 'off' -Now $script:t0
        $r.Kind | Should -Be 'connect'; $r.Expired | Should -BeFalse; $r.Expect.Until | Should -Be $script:t0.AddMinutes(2)
    }
    It 'a drop (blocked after protected) starts no phase' {
        (Resolve-VeroTrayExpect -Expect $null -State 'blocked' -Armed $true -Last 'protected' -Now $script:t0).Expect | Should -BeNullOrEmpty
    }
    It 'ends when protected' { (Resolve-VeroTrayExpect -Expect (Phase 'switch' 5) -State 'protected' -Armed $true -Last 'blocked' -Now $script:t0).Expect | Should -BeNullOrEmpty }
    It 'goes on while blocked within its 2 minutes' {
        $r = Resolve-VeroTrayExpect -Expect (Phase 'reconnect' 60) -State 'blocked' -Armed $true -Last 'blocked' -Now $script:t0
        $r.Kind | Should -Be 'reconnect'; $r.Expired | Should -BeFalse
    }
    It 'is cancelled when no longer armed after 20 s - but not in the first moments of a Turn on' {
        (Resolve-VeroTrayExpect -Expect (Phase 'connect' 25) -State 'off' -Armed $false -Last 'off' -Now $script:t0).Expect | Should -BeNullOrEmpty
        (Resolve-VeroTrayExpect -Expect (Phase 'connect' 5) -State 'off' -Armed $false -Last 'off' -Now $script:t0).Kind | Should -Be 'connect'
    }
    It 'expires once after 2 minutes still blocked' {
        $r = Resolve-VeroTrayExpect -Expect (Phase 'connect' 121) -State 'blocked' -Armed $true -Last 'blocked' -Now $script:t0
        $r.Expired | Should -BeTrue; $r.Expect | Should -BeNullOrEmpty
        (Resolve-VeroTrayExpect -Expect $r.Expect -State 'blocked' -Armed $true -Last 'blocked' -Now $script:t0).Expired | Should -BeFalse
    }
}

Describe 'Get-VeroTransitionNotice' {
    It 'says nothing without a change, or on the first pass' {
        Get-VeroTransitionNotice -State 'protected' -Last 'protected' | Should -BeNullOrEmpty
        Get-VeroTransitionNotice -State 'protected' -Last '' | Should -BeNullOrEmpty
    }
    It 'a drop is a warning; a block you asked for is named after it; a switch or Reconnect said so itself' {
        $d = Get-VeroTransitionNotice -State 'blocked' -Last 'protected' -ProfileName 'Work'
        $d.Title | Should -Be 'VPN connection lost - traffic blocked'; $d.Icon | Should -Be 'Warning'
        $c = Get-VeroTransitionNotice -State 'blocked' -Last 'off' -ExpectKind 'connect' -ProfileName 'Work'
        $c.Title | Should -Be 'VeroScudo on - connecting'; $c.Text | Should -Match "'Work'"
        Get-VeroTransitionNotice -State 'blocked' -Last 'protected' -ExpectKind 'switch' | Should -BeNullOrEmpty
        Get-VeroTransitionNotice -State 'blocked' -Last 'protected' -ExpectKind 'reconnect' | Should -BeNullOrEmpty
    }
    It 'protected, off and attention' {
        (Get-VeroTransitionNotice -State 'protected' -Last 'blocked').Title | Should -Be 'VPN protected'
        (Get-VeroTransitionNotice -State 'off' -Last 'protected').Text | Should -Match 'NOT protected'
        $a = Get-VeroTransitionNotice -State 'attention' -Last 'protected' -Text 'Password rejected'
        $a.Title | Should -Be 'VeroScudo needs attention'; $a.Text | Should -Be 'Password rejected'
    }
    It 'the 2-minute notice names the profile' { (Get-VeroTransitionNotice -Expired -ProfileName 'Work').Text | Should -Match "^'Work' did not connect within 2 minutes" }
}

Describe 'Get-VeroMenuState' {
    It 'offers Turn on unless protected; Reconnect only while on; Hiddify is reconnected in Hiddify' {
        $m = Get-VeroMenuState -State 'protected' -Armed $true -Connected $true -Hiddify $false
        $m.On | Should -BeFalse; $m.Off | Should -BeTrue; $m.Reconnect | Should -BeTrue
        $m = Get-VeroMenuState -State 'off' -Armed $false -Connected $true -Hiddify $false       # connected with VeroScudo off: Off hangs it up
        $m.On | Should -BeTrue; $m.Off | Should -BeTrue; $m.Reconnect | Should -BeFalse
        $m = Get-VeroMenuState -State 'off' -Armed $false -Connected $true -Hiddify $true
        $m.Off | Should -BeFalse
        (Get-VeroMenuState -State 'blocked' -Armed $true -Connected $false -Hiddify $true).Reconnect | Should -BeFalse
    }
}

Describe 'Select-VeroTrayLeftover: only the tray''s own old request files' {
    It 'takes old payloads, codes and requests and nothing else' {
        $now = [datetime]'2026-11-16 12:00:00'; $old = $now.AddMinutes(-11); $new = $now.AddMinutes(-9)
        $files = @(
            @{ Name = 'save-0123456789abcdef0123456789abcdef.json'; LastWriteTimeUtc = $old }, @{ Name = 'otp-Work-1a2b3c4d.txt'; LastWriteTimeUtc = $old }
            @{ Name = 'switch.request'; LastWriteTimeUtc = $old }, @{ Name = 'save-0123456789abcdef0123456789abcdef.json.bak'; LastWriteTimeUtc = $old }
            @{ Name = 'cred-Work-1a2b3c4d.xml'; LastWriteTimeUtc = $old }, @{ Name = 'keypass-Work-1a2b3c4d.xml'; LastWriteTimeUtc = $old }
            @{ Name = 'tray.json'; LastWriteTimeUtc = $old }, @{ Name = 'update.json'; LastWriteTimeUtc = $old }
            @{ Name = 'SAVE-0123456789ABCDEF0123456789ABCDEF.json'; LastWriteTimeUtc = $old }, @{ Name = 'otp-..\x.txt'; LastWriteTimeUtc = $old }
            @{ Name = 'switch.request'; LastWriteTimeUtc = $new }
        ) | ForEach-Object { [pscustomobject]$_ }
        $take = @(Select-VeroTrayLeftover -Files $files -NowUtc $now)
        @($take | ForEach-Object Name) | Should -Be @('save-0123456789abcdef0123456789abcdef.json', 'otp-Work-1a2b3c4d.txt', 'switch.request')
        @(Select-VeroTrayLeftover -Files @() -NowUtc $now).Count | Should -Be 0
    }
}

Describe 'Test-VeroGuardStale' {
    It 'is fine within 3 minutes, counts the minutes after, and without a heartbeat goes by the tray''s own age' {
        Test-VeroGuardStale -HeartbeatEpoch 1000 -NowEpoch 1100 | Should -Be 0
        Test-VeroGuardStale -HeartbeatEpoch 1000 -NowEpoch 1400 | Should -Be 6
        Test-VeroGuardStale -HeartbeatEpoch $null -NowEpoch 5000 -TraySeconds 60 | Should -Be 0
        Test-VeroGuardStale -HeartbeatEpoch $null -NowEpoch 5000 -TraySeconds 240 | Should -Be 4
    }
}
