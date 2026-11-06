# ---------------------------------------------------------------- statistics: 7 days of VPN time and connection quality
# The watchdog notes, minute by minute, whether VeroScudo's VPN was up and - when the connection check is on - how many of
# its checks were sent and lost in that minute. One file per local day, state\stats\yyyy-MM-dd.jsonl, one line per minute
# with the VPN up: {"m":605} (up, check off) or {"m":605,"sent":3,"lost":1}. A minute with no line = VPN off, PC asleep or
# VeroScudo off. Raw counts, not colours: the window can group them into any bar width, and a later change of the rating
# thresholds re-rates old days correctly. Files older than $script:StatsKeepDays are removed by the watchdog.
# The tray reads them (Read-VeroStatsDay) and draws one row per day (ConvertTo-VeroStatsDay). Same format on Linux/macOS.

$script:StatsKeepDays = 8                                                # 7 full days + today
$script:StatsMinute = $null                                              # the minute being collected: @{ Date; M; Up; Sent; Lost }
$script:StatsPruned = ''                                                 # the date old files were last removed

function Get-VeroStatsDir { Join-Path (Get-VeroPath).State 'stats' }

function Format-VeroStatsLine {
    <# One minute -> its line. Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)][int]$Minute, [int]$Sent = 0, [int]$Lost = 0)
    if ($Sent -gt 0) { '{{"m":{0},"sent":{1},"lost":{2}}}' -f $Minute, $Sent, $Lost } else { '{{"m":{0}}}' -f $Minute }
}

function Save-VeroStatsMinute {
    <# Appends the collected minute to its day's file (only when the VPN was up in it). #>
    $s = $script:StatsMinute
    if (-not $s -or -not $s.Up) { return }
    $dir = Get-VeroStatsDir
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [IO.File]::AppendAllText((Join-Path $dir "$($s.Date).jsonl"), (Format-VeroStatsLine -Minute $s.M -Sent $s.Sent -Lost $s.Lost) + "`n")
}

function Select-VeroStatsMinute([datetime]$Now) {
    <# The accumulator for $Now's minute; the previous minute is written first when the minute has changed. #>
    $date = $Now.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    $m = $Now.Hour * 60 + $Now.Minute
    $s = $script:StatsMinute
    if (-not $s -or $s.Date -ne $date -or $s.M -ne $m) {
        Save-VeroStatsMinute
        $script:StatsMinute = @{ Date = $date; M = $m; Up = $false; Sent = 0; Lost = 0 }
    }
    $script:StatsMinute
}

function Update-VeroStats {
    <# The watchdog's 15-second pass: was VeroScudo's VPN up right now? Also removes old files once a day. #>
    [CmdletBinding()] param([Parameter(Mandatory)][bool]$Up, [datetime]$Now = (Get-Date))
    $s = Select-VeroStatsMinute $Now
    if ($Up) { $s.Up = $true }
    if ($script:StatsPruned -ne $s.Date) { Remove-VeroOldStats -Now $Now; $script:StatsPruned = $s.Date }
}

function Add-VeroStatsChecks {
    <# One round of the connection check: its checks count in this minute (and the minute was up - the checks need the tunnel). #>
    [CmdletBinding()] param([Parameter(Mandatory)][int]$Sent, [Parameter(Mandatory)][int]$Lost, [datetime]$Now = (Get-Date))
    $s = Select-VeroStatsMinute $Now
    $s.Up = $true; $s.Sent += $Sent; $s.Lost += $Lost
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

function ConvertFrom-VeroStatsText {
    <# A day file's text -> @{ <minute> = @{ Sent; Lost } }. Several lines for one minute (the watchdog restarted) are added
       up; a broken line is skipped. Pure. #>
    [CmdletBinding()] param([string]$Text)
    $out = @{}
    foreach ($line in ($Text -split "`n")) {
        if ($line -notmatch '^\s*\{"m":(\d{1,4})(?:,"sent":(\d+),"lost":(\d+))?\}\s*$') { continue }
        $m = [int]$Matches[1]
        if ($m -ge 1440) { continue }
        $sent = if ($Matches[2]) { [int]$Matches[2] } else { 0 }
        $lost = if ($Matches[3]) { [Math]::Min([int]$Matches[3], $sent) } else { 0 }
        if ($out.ContainsKey($m)) { $out[$m].Sent += $sent; $out[$m].Lost += $lost } else { $out[$m] = @{ Sent = $sent; Lost = $lost } }
    }
    $out
}

function Read-VeroStatsDay {
    <# The tray's side: one day's minutes (empty when there is no file). #>
    [CmdletBinding()] param([Parameter(Mandatory)][datetime]$Date)
    $p = Join-Path (Get-VeroStatsDir) ($Date.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) + '.jsonl')
    $text = try { [IO.File]::ReadAllText($p) } catch { '' }
    ConvertFrom-VeroStatsText -Text $text
}

function Get-VeroStatsState {
    <# One bar's colour: off (no VPN), up (VPN on, not rated - the check was off), good / unstable / bad (the connection
       check's thresholds: under 10 % lost, 10-50 %, over 50 %). Pure. #>
    [CmdletBinding()] param([int]$UpMinutes, [int]$Sent, [int]$Lost)
    if ($UpMinutes -le 0) { return 'off' }
    if ($Sent -le 0) { return 'up' }
    $loss = 100.0 * $Lost / $Sent
    if ($loss -lt 10) { 'good' } elseif ($loss -gt 50) { 'bad' } else { 'unstable' }
}

function ConvertTo-VeroStatsDay {
    <# One day's minutes -> its row: bars of -BucketMinutes each (State, Start minute, UpMinutes, Sent, Lost) and the day's
       totals: VpnMinutes (minutes with the VPN up) and GoodPct (the share of that time in good bars - 'up' bars count as
       good: the VPN worked and nothing was measured). -UntilMinute: today - later bars are 'future'. Pure. #>
    [CmdletBinding()] param([hashtable]$Minutes = @{}, [ValidateRange(1, 60)][int]$BucketMinutes = 10, [int]$UntilMinute = 1440)
    $bars = New-Object System.Collections.Generic.List[object]
    $vpn = 0; $good = 0
    for ($start = 0; $start -lt 1440; $start += $BucketMinutes) {
        $up = 0; $sent = 0; $lost = 0
        for ($m = $start; $m -lt [Math]::Min($start + $BucketMinutes, 1440); $m++) {
            if ($Minutes.ContainsKey($m)) { $up++; $sent += $Minutes[$m].Sent; $lost += $Minutes[$m].Lost }
        }
        $state = if ($start -ge $UntilMinute -and $up -eq 0) { 'future' } else { Get-VeroStatsState -UpMinutes $up -Sent $sent -Lost $lost }
        $vpn += $up
        if ($state -eq 'good' -or $state -eq 'up') { $good += $up }
        $bars.Add([pscustomobject]@{ Start = $start; State = $state; UpMinutes = $up; Sent = $sent; Lost = $lost })
    }
    [pscustomobject]@{
        Bars       = $bars.ToArray()
        VpnMinutes = $vpn
        GoodPct    = $(if ($vpn -gt 0) { [Math]::Round(100.0 * $good / $vpn, 0) } else { $null })
    }
}

function Format-VeroStatsBar {
    <# A bar's hover text: "14:20-14:30  unstable - 18 % lost (11 of 60 checks), VPN on 10 of 10 min". Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Bar, [int]$BucketMinutes = 10)
    $t = { param($m) '{0:00}:{1:00}' -f [int][Math]::Floor($m / 60), ($m % 60) }
    $span = '{0}-{1}' -f (& $t $Bar.Start), (& $t ([Math]::Min($Bar.Start + $BucketMinutes, 1440)))
    $dash = [char]0x2013
    switch ($Bar.State) {
        'future' { return $span }
        'off'    { return "$span  VPN off" }
        'up'     { return "$span  VPN on $($Bar.UpMinutes) of $BucketMinutes min $dash not rated (connection check off)" }
        default {
            $pct = ([Math]::Round(100.0 * $Bar.Lost / $Bar.Sent, 0)).ToString([Globalization.CultureInfo]::InvariantCulture)
            "$span  $($Bar.State) $dash $pct % lost ($($Bar.Lost) of $($Bar.Sent) checks), VPN on $($Bar.UpMinutes) of $BucketMinutes min"
        }
    }
}

function Format-VeroStatsTotal {
    <# A day's summary: "VPN 9 h 40 min - good 87 %" / "no VPN". Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Day)
    if ($Day.VpnMinutes -le 0) { return 'no VPN' }
    $h = [int][Math]::Floor($Day.VpnMinutes / 60); $min = $Day.VpnMinutes % 60
    $dur = if ($h -gt 0) { "$h h $min min" } else { "$min min" }
    "VPN $dur $([char]0x00B7) good $($Day.GoodPct) %"
}
