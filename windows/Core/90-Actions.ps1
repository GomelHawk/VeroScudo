# VeroScudo core, part 90: actions and status.
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.

# ---------------------------------------------------------------- actions & status
function Get-VeroStatusServer {
    <# "<what the profile names> -> <what the filters allow>" for the status line. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, $Applied)
    $named = & (Get-VeroTypeHandler (Get-VeroConfigType $Config)).ServerText $Config
    $allowed = if ($Applied -and $Applied.PSObject.Properties['Servers']) {
        # wfp.json of 1.2 held objects with a .value here; since 1.3 plain strings - both are read
        @($Applied.Servers | ForEach-Object { if ($_ -is [string]) { $_ } else { [string]$_.value } }) -join ', '
    } else { @(Resolve-VeroServerIp -Config $Config -CacheOnly) -join ', ' }
    "$named -> $allowed"
}
function Get-VeroStatus {
    [CmdletBinding()] param($Config)
    if (-not $Config) { $Config = Get-VeroConfig }
    $p = Get-VeroPath -VpnProfile $Config.Profile
    $r = if (Test-VeroHyperVFirewall) { Get-NetFirewallHyperVRule -Name $script:VmRule -ErrorAction SilentlyContinue } else { $null }
    $type = Get-VeroConfigType $Config
    $armed = Test-VeroArmed; $up = Test-VeroVpnConnected $Config.Profile -Type $type
    $applied = Get-VeroAppliedState
    $filters = try { Get-VeroWfpCount } catch { 'n/a (needs admin)' }
    $detail = & (Get-VeroTypeHandler $type).StatusDetail $Config
    [pscustomobject]@{
        Version    = $script:Version
        Profile    = $Config.Profile
        Type       = Get-VeroTypeLabel $type
        Profiles   = (@($Config.Profiles | ForEach-Object { '{0} ({1})' -f $_.Profile, (Get-VeroTypeLabel $_.Type) }) -join ', ')
        Armed      = $armed
        Connected  = $up
        State      = if (-not $armed) { 'off' } elseif ($up) { 'protected' } else { 'blocked' }
        Connection = if (-not $Config.ConnectionCheck.Enabled) { 'check off' } elseif ($armed -and $up) { Format-VeroQuality (Read-VeroQuality -ProfileName $Config.Profile) } else { '-' }
        Client     = $detail
        Credential = if (Test-VeroNeedsPassword $Config) { [bool](Get-VeroCredential -Config $Config) } else { 'not needed' }
        PwRejected = Test-VeroAuthBlocked $Config.Profile
        Conflicts  = (@(Get-VeroConflictList) -join ' | ')
        Helper     = $(if ($nb = Get-VeroNativeBlocked) { "BLOCKED by Windows since $($nb.First) ($($nb.Count) failures), next try $($nb.Next)" } else { 'ok' })
        Filters    = $filters
        Applied    = if ($applied) { $applied.Time } else { '-' }
        Server     = Get-VeroStatusServer -Config $Config -Applied $applied
        Emergency  = Test-Path $p.Emergency
        Vm         = if (-not $r) { 'not managed' } elseif ([string]$r.Enabled -eq 'True') { 'allowed' } else { 'blocked' }
        HyperVVms  = $(if (Test-Path $p.NetSuspect) { 'blocked: the network dropped, waiting for the tunnel to work again' } elseif (Test-Path $p.VmAcl) { $j = Get-Content $p.VmAcl -Raw | ConvertFrom-Json; 'blocked by port ACLs (' + ((@($j | ForEach-Object { $_ }) | ForEach-Object VMName | Select-Object -Unique) -join ', ') + ')' } else { '-' })
        Reconnect  = Test-VeroLockAlive
        Log        = $p.Log
    }
}

function Invoke-VeroActionArm {
    <# A VPN connected (Connected task: RasMan 20267 / RasClient 20225): arm for it when it is a configured profile and really up. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'arm')
    $p = Get-VeroPath
    # a VPN connected (RasMan, System log): a configured profile becomes the active one; anything else is ignored
    $names = @($Config.Profiles | ForEach-Object Profile)
    if (Test-VeroRecentOff) { Write-VeroLog 'connect right after your Off (a redial that was already running) - not armed' $Action; return }
    $c = Get-VeroRasConnected -Names $names
    # the Connected task also fires on RasClient 20225 (user-writable log): arm only for a tunnel that is really up
    $who = if ($c -and $names -contains $c) { $c } else { $Config.Profile }
    if (($names -contains $who) -and -not (Test-VeroVpnConnected $who -Type 'ras')) {
        if (-not ($c -and $names -notcontains $c)) { Write-VeroLog "connect record for '$who', but it is not connected - ignored" $Action; return }
    }
    if ($c -and $c -ne $Config.Profile) {
        if (@($Config.Profiles | ForEach-Object Profile) -notcontains $c) {
            if (Test-VeroArmed) {                                       # tell the user (tray) - its traffic goes nowhere
                Write-VeroLog "WARNING: VPN '$c' connected, but it is not a VeroScudo profile - its traffic is blocked. Disconnect it, or import it in Settings." $Action
                Write-VeroStateFile -Path $p.Foreign -Text (@{ Name = $c; Time = (Get-Date).ToString('o') } | ConvertTo-Json)
            } else { Write-VeroLog "VPN '$c' connected - not a configured profile, VeroScudo is off: ignored" $Action }
            return
        }
        Set-VeroActiveProfile -Name $c -Action $Action
        $Config = Get-VeroConfig
    }
    # a redial of VeroScudo's own that connected after your Off or your hang-up is not you connecting
    if (-not (Test-VeroArmed) -and (Test-VeroOwnRasDial $who)) { Write-VeroLog "connect of VeroScudo's own redial after it was turned off - not armed" $Action; return }
    Invoke-VeroArmConnected -Config $Config -Action $Action
}

function Invoke-VeroActionOn {
    <# Turn on ('on' refuses next to another VPN; 'on-disconnect' ends them, 'on-force' turns on anyway): arm, filters, redial when down. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'on')
    $p = Get-VeroPath
    # another VPN is connected: plain 'on' (shortcut, script) refuses and says so - the tray asks you first and
    # then runs 'on-disconnect' (ends them, your choice) or 'on-force' (turn on anyway, their traffic is blocked)
    $foreign = @(Get-VeroForeignVpn -Config $Config)
    if ($foreign.Count -gt 0 -and $Action -eq 'on') {
        $what = ($foreign | ForEach-Object { Format-VeroForeignVpn $_ }) -join '; '
        if (-not (Test-VeroArmed)) {
            Write-VeroLog "NOT turned on: $what. Use Turn VPN on in the tray to choose, or -DisconnectOthers / -Force." $Action
            Write-VeroStateFile -Path $p.OnRefused -Text (@{ Time = (Get-Date).ToString('o'); Items = @($foreign | ForEach-Object { Format-VeroForeignVpn $_ }) } | ConvertTo-Json -Depth 3)
            return
        }
        Write-VeroLog "WARNING: already on, next to: $what - their traffic is blocked" $Action   # already on: On just redials
    }
    if ($Action -eq 'on-disconnect' -and $foreign.Count -gt 0) {
        $left = @(Disconnect-VeroForeignVpn -Config $Config -Action $Action)
        foreach ($f in $left) { Write-VeroLog "WARNING: $(Format-VeroForeignVpn $f)" $Action }
    }
    if ($Action -eq 'on-force' -and $foreign.Count -gt 0) { Write-VeroLog ("turned on anyway (your choice) next to: {0} - their traffic is blocked" -f (($foreign | ForEach-Object Name) -join ', ')) $Action }
    Clear-VeroAuthFailed -ProfileName $Config.Profile -Action $Action           # you asked: one more try with the stored password
    Enter-VeroArmed -Config $Config -Action $Action
    $notice = Get-VeroSwitchNotice -Type (Get-VeroConfigType $Config) -ProfileName $Config.Profile
    if ($notice) { Write-VeroLog "NOTICE: $notice" $Action }
    if (-not (Test-VeroVpnConnected $Config.Profile)) { Invoke-VeroReconnect -Config $Config -Action $Action }
}

function Invoke-VeroActionOff {
    <# Your Off: disarm, filters away, hang up - and nothing re-arms by itself for 30 s. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'off')
    Stop-VeroGuardState -Stamp -Action $Action
    $type = Get-VeroConfigType $Config
    $h = Get-VeroTypeHandler $type
    # OpenVPN runs only under VeroScudo: always stop it (also mid-connect); the others only when connected
    if (-not $h.Dials) { Write-VeroLog "kill-switch off - $($h.Label) stays as it is (connect and disconnect it in $($h.Label))" $Action }
    elseif ($h.HangUpOnOffAlways -or (Test-VeroVpnConnected $Config.Profile -Type $type)) {
        Invoke-VeroHangUp $Config.Profile $type
        Write-VeroLog "disconnected '$($Config.Profile)' by user (off; source: VeroScudo Off)" $Action
    }
}

function Invoke-VeroActionOnEvent {
    <# A VPN terminated (Terminated task): forged/stale/foreign records are weeded out, then the one strict decision - disarm or redial. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'on-event')
    # first of all, the filters for "down" (which also blocks the VMs and WSL): blocking needs no decision about who hung
    # up, and must not wait for the pause below or for the Redial task to start
    if ((Test-VeroArmed) -and -not (Test-VeroVpnConnected $Config.Profile)) {
        try { Sync-VeroKillSwitch -Config $Config -Action $Action } catch { Write-VeroLog "ERROR: $($_.Exception.Message)" $Action }
    }
    # then let RAS write all its records: a forged 631 raced in right after a real failure must meet the real
    # record (same connection: conflict) - and a 631 for any other connection id than the one we saw connect is refused
    if ($script:EventSettleSeconds -gt 0) { Start-Sleep -Seconds $script:EventSettleSeconds }
    $t = Get-VeroRasTermination
    if (-not $t) { Write-VeroLog 'VPN terminated, but no recent RAS record - running a check' $Action; Invoke-VeroCheck -Action $Action; return }
    Write-VeroLog "VPN '$($t.Profile)' terminated, RAS code $($t.Code)" $Action
    if ($t.Profile -ne $Config.Profile) { Write-VeroLog "not the active profile '$($Config.Profile)' - ignored" $Action; return }
    if ((Get-VeroConfigType $Config) -ne 'ras') { Write-VeroLog "'$($Config.Profile)' is not a Windows VPN profile - RAS events do not apply, ignored" $Action; return }
    if (Test-VeroVpnConnected $Config.Profile) { Write-VeroLog "'$($Config.Profile)' is still connected - stale or forged event, ignored" $Action; return }
    # the expected connection ids are read (file + System log) only when a 631 is on the table
    $want = @(if ($t.Code -eq 631) { Get-VeroExpectedCoId -ProfileName $t.Profile })
    $r = Resolve-VeroTerminationCode -Termination $t -RenewMarker (Get-VeroRenewMarker) -ExpectedCoIds $want
    foreach ($n in $r.Notes) { Write-VeroLog $n $Action }
    $code = $r.Code
    # a hang-up from before the latest On (your Off, logged late) does not undo that On; write time, not creation time (NTFS
    # keeps the old creation time of a file deleted and created again within seconds)
    if ($code -eq 631 -and (Test-VeroArmed) -and $t.PSObject.Properties['Time'] -and $t.Time -lt (Get-Item -LiteralPath (Get-VeroPath).ArmedFlag).LastWriteTime) { Write-VeroLog "the hang-up was before the latest On - ignored" $Action; return }
    Write-VeroLog ("decision source: RAS reason code {0} -> {1}" -f $code, $(if ($code -eq 631) { 'you hung up' } else { 'link failure' })) $Action
    switch (Get-VeroDecision -ReasonCode $code -Armed (Test-VeroArmed)) {
        'disarm'    { Exit-VeroArmed -Action $Action }
        'reconnect' { Start-VeroRedial -Config $Config -Action $Action }
    }
}

function Invoke-VeroActionWatchdog {
    <# The long-running watchdog loop: one per session, a check every 15 s, exits on a blocked native helper. The optional
       connection check (Update-VeroQuality) runs in the same loop on its own interval. #>
    [CmdletBinding()] param([string]$Action = 'watchdog')
    # long-running, exactly one per session: the task re-triggers every minute so a crashed loop is back within a minute,
    # and every extra start exits here at once (the launcher returning early once let one loop pile up per minute)
    # a lock file in the state folder (per home, so a unit test with a temp home never meets the installed watchdog's lock)
    $single = Enter-VeroSingleton -Name 'watchdog'
    if (-not $single) { return }
    try {
        if (-not (Test-VeroNativeRetryDue (Get-VeroNativeBlocked))) { return }      # helper blocked: not yet time to retry
        # by the UTC clock: local time goes back an hour when summer time ends, and a loop that waits for "15 s from now"
        # in local time would then sleep for that hour
        $nextCheck = [datetime]::MinValue; $nextProbe = [datetime]::MinValue
        while ($true) {
            if ([datetime]::UtcNow -ge $nextCheck) {
                try {
                    Invoke-VeroCheck -Action $Action
                    Clear-VeroNativeBlocked -Action $Action                # every good pass (a cheap Test-Path): also clears a short task's record
                    try {
                        $sc = try { Get-VeroConfig } catch { $null }; $armedNow = Test-VeroArmed
                        $upNow = [bool]$sc -and $armedNow -and (Test-VeroVpnConnected $sc.Profile -Type $sc.Type)
                        Update-VeroStats -Up $upNow -Down ([bool]$sc -and $armedNow -and -not $upNow) -Id $(if ($sc) { $sc.ProfileId } else { '' }) -Name $(if ($sc) { $sc.Profile } else { '' })
                    } catch { Write-VeroLog "ERROR: statistics: $($_.Exception.Message)" $Action }
                    Write-VeroHeartbeat
                } catch {
                    if ($script:NativeLoadFailed) { Set-VeroNativeBlocked -Message $_.Exception.Message -Action $Action; break }   # exit: a fresh process retries
                    Write-VeroLog "ERROR: $($_.Exception.Message)" $Action
                }
                $nextCheck = [datetime]::UtcNow.AddSeconds(15)
            }
            if ([datetime]::UtcNow -ge $nextProbe) {
                $wait = 30
                try { $wait = Update-VeroQuality -Action $Action } catch { Write-VeroLog "ERROR: connection check: $($_.Exception.Message)" $Action }
                $nextProbe = [datetime]::UtcNow.AddSeconds($wait)
            }
            $due = if ($nextCheck -lt $nextProbe) { $nextCheck } else { $nextProbe }
            Start-Sleep -Seconds ([Math]::Min(60, [Math]::Max(1, [int][Math]::Ceiling(($due - [datetime]::UtcNow).TotalSeconds))))   # never longer than a minute, whatever the clock does
        }
    } finally {
        try { Save-VeroStatsMinute } catch { Write-Verbose 'statistics: last minute not saved' }   # the minute so far (a restart adds to it)
        $single.Dispose()
    }
}

function Invoke-VeroActionSwitch {
    <# Switch the active profile (name from the command line or the tray's request file). #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'switch', [string]$VpnProfile)
    $name = if ($VpnProfile) { $VpnProfile } else { Read-VeroSwitchRequest }
    if (-not $name) { Write-VeroLog 'switch requested without a profile name - ignored' $Action; return }
    if (@($Config.Profiles | ForEach-Object Profile) -notcontains $name) { Write-VeroLog "switch to unknown profile '$name' - ignored" $Action; return }
    Invoke-VeroSwitch -Name $name -Action $Action
}

function Invoke-VeroActionStatus {
    <# The status lines of the command line (`-Action status`). #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config)
    $p = Get-VeroPath
    $s = Get-VeroStatus -Config $Config
    $s.PSObject.Properties | ForEach-Object { '{0,-11}: {1}' -f $_.Name, $_.Value }
    $n = Get-VeroSwitchNotice -Type (Get-VeroConfigType $Config) -ProfileName $Config.Profile
    if ($n) { "notice     : $n" }
    if (Test-Path $p.Log) { '--- last log lines'; Get-Content $p.Log -Tail 8 }
}

function Invoke-VeroAction {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][ValidateSet('arm', 'disarm', 'on', 'on-disconnect', 'on-force', 'off', 'on-event', 'netdown', 'reconnect', 'redial', 'watchdog', 'check', 'switch', 'status', 'openvpn')][string]$Action,
        $Config,
        [string]$VpnProfile
    )
    $p = Get-VeroPath
    if (-not (Test-Path $p.State)) { New-Item -ItemType Directory -Path $p.State -Force | Out-Null }
    if (-not $Config) {
        try { $Config = Get-VeroConfig }
        catch {
            # Off is the one way out and must not need a config that loads: the flag and the filters go; the VPN connection
            # itself is left as it is (its name is in the file that cannot be read)
            if ($Action -notin 'off', 'disarm') { throw }
            Write-VeroLog "config.json unusable ($($_.Exception.Message)) - turning off: kill-switch removed; the VPN connection itself is not touched" $Action
            Stop-VeroGuardState -Stamp:($Action -eq 'off') -Action $Action
            return
        }
    }
    switch ($Action) {
        'arm'       { Invoke-VeroActionArm -Config $Config -Action $Action }
        'disarm'    { Exit-VeroArmed -Action $Action }
        { $_ -in 'on', 'on-disconnect', 'on-force' } { Invoke-VeroActionOn -Config $Config -Action $Action }
        'off'       { Invoke-VeroActionOff -Config $Config -Action $Action }
        'on-event'  { Invoke-VeroActionOnEvent -Config $Config -Action $Action }
        'netdown'   { Invoke-VeroActionNetDown -Config $Config -Action $Action }
        'reconnect' {
            # the user's Reconnect: block, hang up, redial; normal traffic again only once the new tunnel is up
            if (-not (Test-VeroArmed)) { Write-VeroLog 'Reconnect: the VPN is off - use Turn on' $Action; return }
            Clear-VeroAuthFailed -ProfileName $Config.Profile -Action $Action
            Invoke-VeroReconnect -Config $Config -Action $Action -Renew
        }
        'redial'    { if (Test-VeroArmed) { Invoke-VeroReconnect -Config $Config -Action $Action } }   # the Redial task: the loop's one owner
        'openvpn'   { Invoke-VeroOpenVpnRunner -Action $Action }
        'check'     { Invoke-VeroCheck -Action $Action }
        'watchdog'  { Invoke-VeroActionWatchdog -Action $Action }
        'switch'    { Invoke-VeroActionSwitch -Config $Config -Action $Action -VpnProfile $VpnProfile }
        'status'    { Invoke-VeroActionStatus -Config $Config }
    }
}

function Get-VeroVersion { $script:Version }

function Test-VeroNewerVersion {
    <# True when a release tag (v1.2.3) is newer than the running version. Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Tag, [string]$Current = $script:Version)
    $t = $Tag.Trim() -replace '^[vV]', ''
    if ($t -notmatch '^\d+(\.\d+){1,3}\z' -or $Current -notmatch '^\d+(\.\d+){1,3}\z') { return $false }
    # number by number, missing ones are 0: 1.3 = 1.3.0 = 1.3.0.0 ([version] alone calls 1.3.0.0 newer than 1.3.0)
    $a = @($t -split '\.' | ForEach-Object { [int]$_ }); $b = @($Current -split '\.' | ForEach-Object { [int]$_ })
    for ($i = 0; $i -lt 4; $i++) {
        $x = if ($i -lt $a.Count) { $a[$i] } else { 0 }; $y = if ($i -lt $b.Count) { $b[$i] } else { 0 }
        if ($x -ne $y) { return ($x -gt $y) }
    }
    return $false
}

function Test-VeroReleaseUrl {
    <# Only this project's GitHub release pages may be opened from an update notice. Pure. #>
    [CmdletBinding()] param([AllowEmptyString()][string]$Url)
    if (-not $Url) { return $false }
    $u = $null
    if (-not [Uri]::TryCreate($Url, 'Absolute', [ref]$u)) { return $false }
    return ($u.Scheme -eq 'https' -and $u.Host -eq 'github.com' -and $u.AbsoluteUri.StartsWith($script:ReleasePrefix, [StringComparison]::Ordinal) -and -not $u.UserInfo)
}

function Get-VeroLatestRelease {
    <# GitHub "latest release" lookup; $null on any failure. Only call while traffic is allowed (never while blocked). #>
    [CmdletBinding()] param([string]$Repo = 'GomelHawk/VeroScudo', [int]$TimeoutSec = 10)
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        # no redirect followed, like the trays' other lookups: the answer comes from the address that was asked
        $r = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -TimeoutSec $TimeoutSec -UseBasicParsing -MaximumRedirection 0 -ErrorAction Stop `
                -Headers @{ 'User-Agent' = "VeroScudo/$script:Version"; Accept = 'application/vnd.github+json' }
        # the link is built here from the tag (digits and dots only), not taken from the answer: what is opened is what was checked
        if ([string]$r.tag_name -match '^[vV]?\d+(\.\d+){1,3}\z') {
            $url = $script:ReleasePrefix + 'tag/' + [string]$r.tag_name
            if (Test-VeroReleaseUrl $url) { return [pscustomobject]@{ Tag = [string]$r.tag_name; Url = $url; Name = ([string]$r.name -replace '[\x00-\x1f]', ' ') } }
        }
    } catch { Write-Verbose "update check failed: $($_.Exception.Message)" }
    return $null
}
