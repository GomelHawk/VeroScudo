# ---------------------------------------------------------------- statistics: 7 days of VPN time and connection quality
# The watchdog notes, minute by minute, which VeroScudo profile was up and - when the connection check is on - how many of
# its checks were sent and lost in that minute. One file per local day, state\stats\yyyy-MM-dd.jsonl, one line per minute
# and profile with the VPN up: {"m":605,"id":"3f2a9c0d1e2b","p":"Work"} (up, check off) or the same with "sent":3,"lost":1;
# a minute VeroScudo was on but could not connect: the same with "down":1 (shown as bad - a redial that keeps failing).
# Per profile: a corporate VPN and a home one are different connections - their problems must not be mixed. "id" is the
# profile's lasting id (Get-VeroProfileId), so a renamed profile keeps its history; "p" is its name at that minute, so a
# removed profile is still shown by its last name. A minute without a line = VPN off, PC asleep or VeroScudo off. JSON with
# ASCII escapes. Raw counts, not colours: the window groups them into bars, and a later change of the rating thresholds
# re-rates old days. Files older than $script:StatsKeepDays are removed by the watchdog. Same format on Linux/macOS.

$script:StatsKeepDays = 8                                                # 7 full days + today
$script:StatsMinute = $null                                              # the minute being collected: @{ Date; M; P = @{ id = @{ Up; Sent; Lost; Name } } }
$script:StatsPruned = ''                                                 # the date old files were last removed

function Get-VeroStatsDir { Join-Path (Get-VeroPath).State 'stats' }

function ConvertTo-VeroJsonString([string]$Text) {
    <# A JSON string with ASCII escapes - byte for byte what Python's json.dumps(ensure_ascii=True) writes. Pure. #>
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    foreach ($ch in $Text.ToCharArray()) {
        $c = [int]$ch
        if ($ch -eq '"') { [void]$sb.Append('\"') }
        elseif ($ch -eq '\') { [void]$sb.Append('\\') }
        elseif ($c -eq 10) { [void]$sb.Append('\n') } elseif ($c -eq 13) { [void]$sb.Append('\r') } elseif ($c -eq 9) { [void]$sb.Append('\t') }
        elseif ($c -eq 8) { [void]$sb.Append('\b') } elseif ($c -eq 12) { [void]$sb.Append('\f') }
        elseif ($c -lt 32 -or $c -gt 126) { [void]$sb.Append(('\u{0:x4}' -f $c)) }
        else { [void]$sb.Append($ch) }
    }
    [void]$sb.Append('"')
    $sb.ToString()
}

function Format-VeroStatsLine {
    <# One minute of one profile -> its line. Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)][int]$Minute, [Parameter(Mandatory)][string]$Id, [Parameter(Mandatory)][AllowEmptyString()][string]$Name, [int]$Sent = 0, [int]$Lost = 0, [switch]$Down)
    $head = '{{"m":{0},"id":{1},"p":{2}' -f $Minute, (ConvertTo-VeroJsonString $Id), (ConvertTo-VeroJsonString $Name)
    if ($Down) { return $head + ',"down":1}' }
    if ($Sent -gt 0) { '{0},"sent":{1},"lost":{2}}}' -f $head, $Sent, $Lost } else { $head + '}' }
}

function Save-VeroStatsMinute {
    <# Appends the collected minute to its day's file: one line per profile that was up in it. #>
    $s = $script:StatsMinute
    if (-not $s) { return }
    $lines = @(foreach ($id in $s.P.Keys) {
        $v = $s.P[$id]
        if ($v.Up) { Format-VeroStatsLine -Minute $s.M -Id $id -Name $v.Name -Sent $v.Sent -Lost $v.Lost }
        elseif ($v.Down) { Format-VeroStatsLine -Minute $s.M -Id $id -Name $v.Name -Down }      # on, but no tunnel all minute
    })
    if ($lines.Count -eq 0) { return }
    $dir = Get-VeroStatsDir
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [IO.File]::AppendAllText((Join-Path $dir "$($s.Date).jsonl"), (($lines -join "`n") + "`n"))
}

function Select-VeroStatsMinute([datetime]$Now) {
    <# The accumulator for $Now's minute; the previous minute is written first when the minute has changed. #>
    $date = $Now.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    $m = $Now.Hour * 60 + $Now.Minute
    $s = $script:StatsMinute
    if (-not $s -or $s.Date -ne $date -or $s.M -ne $m) {
        Save-VeroStatsMinute
        $script:StatsMinute = @{ Date = $date; M = $m; P = [ordered]@{} }
    }
    $script:StatsMinute
}

function Get-VeroStatsSlot($Minute, [string]$Id, [string]$Name) {
    if (-not $Minute.P.Contains($Id)) { $Minute.P[$Id] = @{ Up = $false; Down = $false; Sent = 0; Lost = 0; Name = $Name } }
    $Minute.P[$Id].Name = $Name
    $Minute.P[$Id]
}

function Update-VeroStats {
    <# The watchdog's 15-second pass: was VeroScudo's VPN up right now, on which profile? Also removes old files once a day. #>
    [CmdletBinding()] param([Parameter(Mandatory)][bool]$Up, [string]$Id = '', [string]$Name = '', [bool]$Down = $false, [datetime]$Now = (Get-Date))
    $s = Select-VeroStatsMinute $Now
    if ($Up -and $Id) { (Get-VeroStatsSlot $s $Id $Name).Up = $true }
    elseif ($Down -and $Id) { (Get-VeroStatsSlot $s $Id $Name).Down = $true }     # on, but the active profile is not connected
    if ($script:StatsPruned -ne $s.Date) { Remove-VeroOldStats -Now $Now; $script:StatsPruned = $s.Date }
}

function Add-VeroStatsChecks {
    <# One round of the connection check: its checks count in this minute for this profile (and it was up - the checks need the tunnel). #>
    [CmdletBinding()] param([Parameter(Mandatory)][int]$Sent, [Parameter(Mandatory)][int]$Lost, [Parameter(Mandatory)][string]$Id, [string]$Name = '', [datetime]$Now = (Get-Date))
    $v = Get-VeroStatsSlot (Select-VeroStatsMinute $Now) $Id $Name
    $v.Up = $true; $v.Sent += $Sent; $v.Lost += $Lost
}

function Remove-VeroOldStats {
    <# Only VeroScudo's own day files (yyyy-MM-dd.jsonl) in state\stats, and only those older than the kept days. #>
    [CmdletBinding()] param([datetime]$Now = (Get-Date))
    $dir = Get-VeroStatsDir
    if (-not (Test-Path -LiteralPath $dir)) { return }
    $oldest = $Now.Date.AddDays(-($script:StatsKeepDays - 1))
    foreach ($f in @(Get-ChildItem -LiteralPath $dir -File -Filter '*.jsonl')) {
        if ($f.Name -notmatch '^(\d{4}-\d{2}-\d{2})\.jsonl$') { continue }
        $d = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($Matches[1], 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture, 'None', [ref]$d)) { continue }
        if ($d -lt $oldest) { Remove-Item -LiteralPath $f.FullName -Force }
    }
}

$script:StatsLine = [regex]'^\s*\{"m":(\d{1,4}),"id":"([0-9A-Za-z_-]{1,64})","p":"((?:[^"\\]|\\.)*)"(?:,"sent":(\d+),"lost":(\d+))?(,"down":1)?\}\s*$'
function ConvertFrom-VeroStatsText {
    <# A day file's text -> @{ Data = @{ <id> = @{ <minute> = @{ Sent; Lost } } }; Names = @{ <id> = its last name } }. Several
       lines for one minute (the watchdog restarted) are added up; a broken line or one without an id is skipped. Pure. #>
    [CmdletBinding()] param([string]$Text)
    $data = @{}; $names = @{}; $decoded = @{}
    foreach ($line in ($Text -split "`n")) {
        $mt = $script:StatsLine.Match($line)
        if (-not $mt.Success) { continue }
        $m = [int]$mt.Groups[1].Value
        if ($m -ge 1440) { continue }
        $id = $mt.Groups[2].Value; $raw = $mt.Groups[3].Value
        if (-not $decoded.ContainsKey($raw)) { $decoded[$raw] = try { [string](('"' + $raw + '"') | ConvertFrom-Json) } catch { $raw } }
        $sent = if ($mt.Groups[4].Success) { [int]$mt.Groups[4].Value } else { 0 }
        $lost = if ($mt.Groups[5].Success) { [Math]::Min([int]$mt.Groups[5].Value, $sent) } else { 0 }
        if (-not $data.ContainsKey($id)) { $data[$id] = @{} }
        $day = $data[$id]
        $down = $mt.Groups[6].Success                                    # on, not connected - an up line for the minute wins
        if ($day.ContainsKey($m)) {
            $day[$m].Sent += $sent; $day[$m].Lost += $lost
            if (-not $down) { $day[$m].Down = $false }
        } else { $day[$m] = @{ Sent = $sent; Lost = $lost; Down = $down } }
        $names[$id] = $decoded[$raw]
    }
    @{ Data = $data; Names = $names }
}

function Read-VeroStatsDay {
    <# The tray's side: one day's minutes per profile id, and the names (empty when there is no file). #>
    [CmdletBinding()] param([Parameter(Mandatory)][datetime]$Date)
    $p = Join-Path (Get-VeroStatsDir) ($Date.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) + '.jsonl')
    $text = try { [IO.File]::ReadAllText($p) } catch { '' }
    ConvertFrom-VeroStatsText -Text $text
}

function Get-VeroStatsChoices {
    <# The window's drop-down as (Id, Label): the active profile first (also before it has data), then the other profiles with
       data, the most recently used first. Label: the current name (renamed: the history stays); a removed profile keeps its
       last name, marked. -Days: Read-VeroStatsDay results, today first; -Profiles: config.json's profiles (Id, Profile). Pure. #>
    [CmdletBinding()] param([object[]]$Days = @(), [object[]]$Profiles = @(), [string]$ActiveId = '')
    $last = @{}; $names = @{}
    for ($i = $Days.Count - 1; $i -ge 0; $i--) {                           # oldest first: a later name wins
        foreach ($id in $Days[$i].Names.Keys) { $names[$id] = $Days[$i].Names[$id] }
        foreach ($id in $Days[$i].Data.Keys) {
            $key = (6 - $i) * 10000 + (@($Days[$i].Data[$id].Keys) | Measure-Object -Maximum).Maximum
            if (-not $last.ContainsKey($id) -or $key -gt $last[$id]) { $last[$id] = $key }
        }
    }
    $now = @{}; foreach ($p in $Profiles) { $now[[string]$p.Id] = [string]$p.Profile }
    $order = @($(if ($ActiveId) { $ActiveId })) + @($last.Keys | Sort-Object { $last[$_] } -Descending | Where-Object { $_ -ne $ActiveId })
    foreach ($id in $order) {
        $label = if ($now.ContainsKey($id)) { $now[$id] } elseif ($names.ContainsKey($id)) { "$($names[$id]) (removed)" } else { "$id (removed)" }
        [pscustomobject]@{ Id = $id; Label = $label }
    }
}

function Get-VeroStatsState {
    <# One bar's colour: off (this profile not connected), up (connected, not rated - the check was off), good / unstable / bad (the connection
       check's thresholds: under 10 % lost, 10-50 %, over 50 %). Pure. #>
    [CmdletBinding()] param([int]$UpMinutes, [int]$Sent, [int]$Lost)
    if ($UpMinutes -le 0) { return 'off' }
    if ($Sent -le 0) { return 'up' }
    $loss = 100.0 * $Lost / $Sent
    if ($loss -lt 10) { 'good' } elseif ($loss -gt 50) { 'bad' } else { 'unstable' }
}

function ConvertTo-VeroStatsDay {
    <# One day's minutes -> its row: bars of -BucketMinutes each (State, Start minute, UpMinutes, DownMinutes, Sent, Lost) and
       the day's totals: VpnMinutes (connected), DownMinutes (on but not connected) and GoodPct (good bars' connected minutes
       out of connected + not connected - 'up' bars count as good: the VPN worked and nothing was measured). A bar with 2 or
       more minutes on but not connected is bad (a redial that keeps failing). -UntilMinute: today - later bars are 'future'.
       Pure. #>
    [CmdletBinding()] param([hashtable]$Minutes = @{}, [ValidateRange(1, 60)][int]$BucketMinutes = 10, [int]$UntilMinute = 1440)
    $bars = New-Object System.Collections.Generic.List[object]
    $vpn = 0; $good = 0; $downAll = 0
    for ($start = 0; $start -lt 1440; $start += $BucketMinutes) {
        $up = 0; $down = 0; $sent = 0; $lost = 0
        for ($m = $start; $m -lt [Math]::Min($start + $BucketMinutes, 1440); $m++) {
            if (-not $Minutes.ContainsKey($m)) { continue }
            $x = $Minutes[$m]
            if ($x.ContainsKey('Down') -and $x.Down) { $down++ } else { $up++; $sent += $x.Sent; $lost += $x.Lost }
        }
        $state = if ($start -ge $UntilMinute -and $up -eq 0 -and $down -eq 0) { 'future' }
                 elseif ($down -ge 2) { 'bad' }
                 else { Get-VeroStatsState -UpMinutes $up -Sent $sent -Lost $lost }
        $vpn += $up; $downAll += $down
        if ($state -eq 'good' -or $state -eq 'up') { $good += $up }
        $bars.Add([pscustomobject]@{ Start = $start; State = $state; UpMinutes = $up; DownMinutes = $down; Sent = $sent; Lost = $lost })
    }
    $all = $vpn + $downAll
    [pscustomobject]@{
        Bars        = $bars.ToArray()
        VpnMinutes  = $vpn
        DownMinutes = $downAll
        GoodPct     = $(if ($all -gt 0) { [Math]::Round(100.0 * $good / $all, 0) } else { $null })
    }
}

function Format-VeroStatsBar {
    <# A bar's hover text: "14:20-14:30  unstable - 18 % lost (11 of 60 checks), connected 10 of 10 min". Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Bar, [int]$BucketMinutes = 10)
    $t = { param($m) '{0:00}:{1:00}' -f [int][Math]::Floor($m / 60), ($m % 60) }
    $span = '{0}-{1}' -f (& $t $Bar.Start), (& $t ([Math]::Min($Bar.Start + $BucketMinutes, 1440)))
    $dash = [char]0x2013
    $dn = if ($Bar.PSObject.Properties['DownMinutes']) { [int]$Bar.DownMinutes } else { 0 }
    if ($dn -ge 2) {
        $txt = "$span  could not connect $dn of $BucketMinutes min (VeroScudo on)"
        if ($Bar.UpMinutes -gt 0) { $txt += "; connected $($Bar.UpMinutes) of $BucketMinutes min" }
        return $txt
    }
    switch ($Bar.State) {
        'future' { return $span }
        'off'    { return "$span  not connected" }
        'up'     { return "$span  connected $($Bar.UpMinutes) of $BucketMinutes min $dash not rated (connection check off)" }
        default {
            $pct = ([Math]::Round(100.0 * $Bar.Lost / $Bar.Sent, 0)).ToString([Globalization.CultureInfo]::InvariantCulture)
            "$span  $($Bar.State) $dash $pct % lost ($($Bar.Lost) of $($Bar.Sent) checks), connected $($Bar.UpMinutes) of $BucketMinutes min"
        }
    }
}

function Format-VeroStatsTotal {
    <# A day's summary: "connected 9 h 40 min - good 87 %" (+ " - no connection 12 min") / "not used". Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Day)
    $dur = { param($n) $h = [int][Math]::Floor($n / 60); $mm = $n % 60; if ($h -gt 0) { "$h h $mm min" } else { "$mm min" } }
    $dot = [char]0x00B7
    $down = if ($Day.PSObject.Properties['DownMinutes']) { [int]$Day.DownMinutes } else { 0 }
    if ($Day.VpnMinutes -le 0 -and $down -le 0) { return 'not used' }
    if ($Day.VpnMinutes -le 0) { return "no connection $(& $dur $down) $dot good 0 %" }
    $txt = "connected $(& $dur $Day.VpnMinutes) $dot good $($Day.GoodPct) %"
    if ($down -gt 0) { $txt += " $dot no connection $(& $dur $down)" }
    $txt
}
