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
