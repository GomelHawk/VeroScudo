# VeroScudo core, part 66: connection quality - optional checks through the tunnel while protected (config connectionCheck).
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.
# Same rules on every platform (Linux/macOS: linux/veroscudo/quality.py; docs/ARCHITECTURE.md "Connection check"):
#  - every intervalSeconds (10-100) the watchdog checks each address once: ping, or a TCP connection to a port;
#  - every check counts: loss = failed checks / all checks of the last windowMinutes (1-10), never fewer than 3 rounds;
#  - below 10 % lost: good; 10-50 %: unstable; above 50 %: bad;
#  - no rating ("checking") until one full window has passed since the rating started: it starts over on every connect,
#    profile switch and change of the check settings (interval, window, addresses).
# The checks run only while armed and connected, so they go through the tunnel; nothing in the kill-switch is opened.

$script:CheckDefaultHost = '1.1.1.1'
$script:CheckMinChecks = 3

function New-VeroCheckTarget([string]$HostName, [string]$Method = 'tcp', [int]$Port = 443) {
    [pscustomobject]@{ Host = $HostName; Method = $Method; Port = $(if ($Method -eq 'tcp') { $Port } else { 443 }) }
}

function ConvertFrom-VeroCheckConfig {
    <# config.json's connectionCheck -> @{ Enabled; IntervalSeconds; WindowMinutes; Targets }. Missing = off with the
       defaults; an empty target list falls back to 1.1.1.1 (there is always one). Throws on anything invalid. Pure. #>
    [CmdletBinding()] param($Raw)
    $def = New-VeroCheckTarget $script:CheckDefaultHost 'tcp' 443
    if ($null -eq $Raw) { return [pscustomobject]@{ Enabled = $false; IntervalSeconds = 10; WindowMinutes = 1; Targets = @($def) } }
    if ($Raw -isnot [System.Management.Automation.PSCustomObject]) { throw 'config.json: connectionCheck must be an object' }
    function Get-P($n, $d) { if ($Raw.PSObject.Properties[$n]) { $Raw.$n } else { $d } }
    $enabled = Get-P 'enabled' $false
    if ($enabled -isnot [bool]) { throw 'config.json: connectionCheck.enabled must be true or false' }
    $interval = 0; $window = 0
    if (-not [int]::TryParse([string](Get-P 'intervalSeconds' 10), [ref]$interval) -or $interval -lt 10 -or $interval -gt 100) { throw 'config.json: connectionCheck.intervalSeconds must be 10-100' }
    if (-not [int]::TryParse([string](Get-P 'windowMinutes' 1), [ref]$window) -or $window -lt 1 -or $window -gt 10) { throw 'config.json: connectionCheck.windowMinutes must be 1-10' }
    $rawTargets = @(@(Get-P 'targets' @()) | Where-Object { $null -ne $_ })
    if ($rawTargets.Count -gt 3) { throw 'config.json: connectionCheck.targets must be a list of at most 3' }
    $targets = foreach ($t in $rawTargets) {
        if ($t -isnot [System.Management.Automation.PSCustomObject]) { throw 'config.json: each connectionCheck target must be an object {host, method, port}' }
        $h = if ($t.PSObject.Properties['host']) { ([string]$t.host).Trim() } else { '' }
        if (-not $h -or -not (Test-VeroHost $h)) { throw "config.json: invalid connectionCheck host '$h'" }
        $m = if ($t.PSObject.Properties['method']) { ([string]$t.method).ToLowerInvariant() } else { 'tcp' }
        if ($m -notin 'ping', 'tcp') { throw "config.json: connectionCheck method must be 'ping' or 'tcp'" }
        $port = 443
        if ($m -eq 'tcp' -and $t.PSObject.Properties['port']) {
            if (-not [int]::TryParse([string]$t.port, [ref]$port) -or $port -lt 1 -or $port -gt 65535) { throw "config.json: connectionCheck port must be 1-65535 ($h)" }
        }
        New-VeroCheckTarget $h $m $port
    }
    $targets = @($targets)
    if ($targets.Count -eq 0) { $targets = @($def) }
    [pscustomobject]@{ Enabled = [bool]$enabled; IntervalSeconds = $interval; WindowMinutes = $window; Targets = $targets }
}

function ConvertTo-VeroCheckObject {
    <# The on-disk form of a connectionCheck (config.json). Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Check)
    [ordered]@{
        enabled = [bool]$Check.Enabled; intervalSeconds = [int]$Check.IntervalSeconds; windowMinutes = [int]$Check.WindowMinutes
        targets = @($Check.Targets | ForEach-Object { if ($_.Method -eq 'tcp') { [ordered]@{ host = $_.Host; method = 'tcp'; port = [int]$_.Port } } else { [ordered]@{ host = $_.Host; method = 'ping' } } })
    }
}

function Split-VeroCheckAddress {
    <# What the user typed (IP, host name, host:port or URL) -> @{ Host; Port ($null = none given) }. Pure. #>
    [CmdletBinding()] param([AllowEmptyString()][string]$Text)
    $s = ([string]$Text).Trim()
    if (-not $s) { return @{ Host = ''; Port = $null } }
    if ($s -match '^([A-Za-z][A-Za-z0-9+.-]*)://') {
        $u = $null
        if ([Uri]::TryCreate($s, 'Absolute', [ref]$u)) {
            $port = $null
            if (-not $u.IsDefaultPort) { $port = $u.Port } elseif ($u.Scheme -in 'http', 'https') { $port = $u.Port }
            return @{ Host = $u.Host.Trim('[', ']'); Port = $port }
        }
        return @{ Host = $s; Port = $null }
    }
    if ($s -match '^\[([^\]]+)\](?::(\d+))?$') { return @{ Host = $Matches[1]; Port = $(if ($Matches[2]) { [int]$Matches[2] } else { $null }) } }
    if (@($s.ToCharArray() | Where-Object { $_ -eq ':' }).Count -eq 1) {
        $h, $p = $s -split ':', 2
        return @{ Host = $h; Port = $(if ($p -match '^\d+$') { [int]$p } else { $null }) }
    }
    @{ Host = ($s -split '/')[0]; Port = $null }
}

function ConvertFrom-VeroCheckForm {
    <# Settings > Connection -> a connectionCheck object. Rows: up to 3 @{ Text; Method; Port }. An empty first address
       becomes 1.1.1.1, empty others are dropped; a URL or host:port gives its host (and, for TCP, its port when the port field
       was left at 443). Throws a message for the user. Pure (the same rules as quality.from_form on Linux/macOS). #>
    [CmdletBinding()] param([bool]$Enabled, [int]$IntervalSeconds, [int]$WindowMinutes, [object[]]$Rows)
    $interval = [Math]::Min([Math]::Max($IntervalSeconds, 10), 100)
    $window = [Math]::Min([Math]::Max($WindowMinutes, 1), 10)
    $targets = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($r in @($Rows | Select-Object -First 3)) {
        $i++
        $a = Split-VeroCheckAddress ([string]$r.Text)
        $h = $a.Host
        if (-not $h) { if ($i -eq 1) { $h = $script:CheckDefaultHost } else { continue } }
        if (-not (Test-VeroHost $h)) { throw "Address ${i}: '$(([string]$r.Text).Trim())' is not an IP address, host name or URL." }
        $m = ([string]$r.Method).ToLowerInvariant(); if (-not $m) { $m = 'tcp' }
        if ($m -notin 'ping', 'tcp') { throw "Address ${i}: choose Ping or TCP." }
        $p = if ($r.Port) { [int]$r.Port } else { 443 }
        if ($m -eq 'tcp' -and $a.Port -and $p -eq 443) { $p = [int]$a.Port }
        if ($m -eq 'tcp' -and ($p -lt 1 -or $p -gt 65535)) { throw "Address ${i}: the port must be 1-65535." }
        $targets.Add((New-VeroCheckTarget $h $m $p))
    }
    if ($targets.Count -eq 0) { $targets.Add((New-VeroCheckTarget $script:CheckDefaultHost 'tcp' 443)) }
    [pscustomobject]@{ Enabled = $Enabled; IntervalSeconds = $interval; WindowMinutes = $window; Targets = $targets.ToArray() }   # .ToArray(): @(<List>) in this literal throws on PowerShell 5.1
}

function Get-VeroCheckWindow {
    <# The look-back in seconds: windowMinutes, but never fewer than 3 rounds. Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Check)
    [Math]::Max($Check.WindowMinutes * 60.0, $script:CheckMinChecks * $Check.IntervalSeconds * 1.0)   # no +1: 20 s / 1 min = 60 s, not 80
}

function Measure-VeroQuality {
    <# Samples: @{ T (seconds); Ok; Rtt (ms or $null) }, one per check -> @{ State; LossPct; RttMs; Checks; Lost }.
       -Since: when the rating started - until a full window has passed the answer is 'checking'. Pure. #>
    [CmdletBinding()] param([object[]]$Samples = @(), [Parameter(Mandatory)][double]$Now, [Parameter(Mandatory)][double]$WindowSeconds, [double]$Since = -1)
    $recent = @($Samples | Where-Object { $_ -and ($Now - [double]$_.T) -le $WindowSeconds })
    $n = $recent.Count
    $lost = @($recent | Where-Object { -not $_.Ok }).Count
    if ($n -lt $script:CheckMinChecks -or ($Since -ge 0 -and ($Now - $Since) -lt $WindowSeconds)) { return [pscustomobject]@{ State = 'checking'; LossPct = 0.0; RttMs = $null; Checks = $n; Lost = $lost } }
    $loss = 100.0 * $lost / $n
    $rtts = @($recent | Where-Object { $_.Ok -and $null -ne $_.Rtt } | ForEach-Object { [double]$_.Rtt } | Sort-Object)
    $rtt = $null
    if ($rtts.Count -gt 0) {
        $mid = [int][Math]::Floor($rtts.Count / 2)
        $med = if ($rtts.Count % 2) { $rtts[$mid] } else { ($rtts[$mid - 1] + $rtts[$mid]) / 2 }
        $rtt = [int][Math]::Round($med)
    }
    $state = if ($loss -lt 10) { 'good' } elseif ($loss -gt 50) { 'bad' } else { 'unstable' }
    [pscustomobject]@{ State = $state; LossPct = [Math]::Round($loss, 1); RttMs = $rtt; Checks = $n; Lost = $lost }
}

function Format-VeroQuality {
    <# 'good · 45 ms', 'unstable · 22.5% lost', 'checking…' - the short text of the tray. Pure. #>
    [CmdletBinding()] param($Quality)
    $dot = [string][char]0x00B7
    if (-not $Quality -or $Quality.State -eq 'checking') { return 'checking' + [char]0x2026 }
    if ($Quality.State -eq 'good') { if ($null -ne $Quality.RttMs) { return "good $dot $($Quality.RttMs) ms" } else { return 'good' } }
    '{0} {1} {2}% lost' -f $Quality.State, $dot, ([double]$Quality.LossPct).ToString('0.#', [Globalization.CultureInfo]::InvariantCulture)
}

function Invoke-VeroProbeRound {
    <# Every address once, in parallel: ping (ICMP echo) or a TCP connection. Returns one @{ Ok; RttMs } per target. #>
    [CmdletBinding()] param([object[]]$Targets, [int]$TimeoutMs = 3000)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $jobs = @(foreach ($t in $Targets) {
        $j = @{ Target = $t; Task = $null; Client = $null; Ms = $null }
        try {
            if ($t.Method -eq 'ping') { $j.Client = New-Object System.Net.NetworkInformation.Ping; $j.Task = $j.Client.SendPingAsync([string]$t.Host, $TimeoutMs) }
            else {
                $fam = if ([string]$t.Host -match ':') { [System.Net.Sockets.AddressFamily]::InterNetworkV6 } else { [System.Net.Sockets.AddressFamily]::InterNetwork }
                $j.Client = New-Object System.Net.Sockets.TcpClient($fam); $j.Task = $j.Client.ConnectAsync([string]$t.Host, [int]$t.Port)
            }
        } catch { $j.Task = $null }
        $j
    })
    while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
        $pending = 0
        foreach ($j in $jobs) { if ($j.Task -and $null -eq $j.Ms) { if ($j.Task.IsCompleted) { $j.Ms = $sw.ElapsedMilliseconds } else { $pending++ } } }
        if ($pending -eq 0) { break }
        Start-Sleep -Milliseconds 20
    }
    foreach ($j in $jobs) {
        $ok = $false; $rtt = $null
        if ($j.Task -and $null -ne $j.Ms -and -not $j.Task.IsFaulted -and -not $j.Task.IsCanceled) {
            if ($j.Target.Method -eq 'ping') {
                $r = $j.Task.Result
                if ([string]$r.Status -eq 'Success') { $ok = $true; $rtt = [int]$r.RoundtripTime }
            } else { $ok = [bool]$j.Client.Connected; if ($ok) { $rtt = [int]$j.Ms } }
        }
        try { if ($j.Client -is [System.Net.Sockets.TcpClient]) { $j.Client.Close() } elseif ($j.Client) { $j.Client.Dispose() } } catch { Write-Verbose 'probe cleanup' }
        [pscustomobject]@{ Ok = $ok; RttMs = $rtt }
    }
}

$script:QualitySamples = New-Object System.Collections.Generic.List[object]
$script:QualityKey = ''                                                  # profile + check settings the samples belong to
$script:QualityStarted = 0.0                                             # when this rating started
$script:QualityLast = ''
function Get-VeroQualityKey($Config) {
    $c = $Config.ConnectionCheck
    (@($Config.Profile, $c.IntervalSeconds, $c.WindowMinutes) + @($c.Targets | ForEach-Object { '{0}/{1}/{2}' -f $_.Host, $_.Method, $_.Port })) -join '|'
}
function Reset-VeroQuality {
    $script:QualitySamples.Clear(); $script:QualityLast = ''; $script:QualityKey = ''
    $p = (Get-VeroPath).Quality
    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
}

function Get-VeroEpoch { ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()) / 1000.0 }

function Update-VeroQuality {
    <# The watchdog's side: one round of checks when they are wanted and the VPN is on and connected; otherwise the samples
       are dropped (a new connection starts a new rating). Writes quality.json for the tray; logs only a change of the
       rating. Returns the seconds until the next round. #>
    [CmdletBinding()] param([string]$Action = 'watchdog')
    $cfg = try { Get-VeroConfig } catch { $null }
    $chk = if ($cfg) { $cfg.ConnectionCheck } else { $null }
    if (-not $chk -or -not $chk.Enabled -or -not (Test-VeroArmed) -or -not (Test-VeroVpnConnected $cfg.Profile -Type $cfg.Type)) {
        if ($script:QualitySamples.Count -gt 0 -or (Test-Path -LiteralPath (Get-VeroPath).Quality)) { Reset-VeroQuality }
        return 5
    }
    $now = Get-VeroEpoch
    $key = Get-VeroQualityKey $cfg
    $down = 0.0                                                          # the kill-switch blocked since this rating started: a new connection
    try { $down = [double]([IO.File]::ReadAllText((Get-VeroPath).LastDown).Trim()) } catch { $down = 0.0 }
    if ($key -ne $script:QualityKey -or $down -gt $script:QualityStarted) {   # new connection, other profile or other rules: start over
        $script:QualitySamples.Clear(); $script:QualityKey = $key; $script:QualityStarted = $now; $script:QualityLast = ''
    }
    $round = @(Invoke-VeroProbeRound -Targets $chk.Targets)
    foreach ($r in $round) { $script:QualitySamples.Add(@{ T = $now; Ok = [bool]$r.Ok; Rtt = $r.RttMs }) }
    try { Add-VeroStatsChecks -Sent $round.Count -Lost @($round | Where-Object { -not $_.Ok }).Count } catch { Write-VeroLog "ERROR: statistics: $($_.Exception.Message)" $Action }
    $win = Get-VeroCheckWindow $chk
    $keep = @($script:QualitySamples.ToArray() | Where-Object { ($now - [double]$_.T) -le ($win + 1) })   # .ToArray(): @(<List>) throws on PowerShell 5.1
    $script:QualitySamples.Clear(); foreach ($s in $keep) { $script:QualitySamples.Add($s) }
    $q = Measure-VeroQuality -Samples $script:QualitySamples.ToArray() -Now $now -WindowSeconds $win -Since $script:QualityStarted
    $p = (Get-VeroPath).Quality
    $json = [ordered]@{ profile = $cfg.Profile; state = $q.State; lossPct = $q.LossPct; rttMs = $q.RttMs; checks = $q.Checks; lost = $q.Lost
                        intervalSeconds = $chk.IntervalSeconds; windowMinutes = $chk.WindowMinutes; updated = $now } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText("$p.new", $json)
    Move-Item -LiteralPath "$p.new" -Destination $p -Force
    if ($q.State -ne 'checking' -and $q.State -ne $script:QualityLast) {
        Write-VeroLog ("connection quality: {0} ({1} of {2} checks lost, {3})" -f $q.State, $q.Lost, $q.Checks, $(if ($null -ne $q.RttMs) { "$($q.RttMs) ms" } else { 'no answer' })) $Action
        $script:QualityLast = $q.State
    }
    [int]$chk.IntervalSeconds
}

function Read-VeroQuality {
    <# The tray's side: the last rating of this profile, or $null (no file, another profile, or too old to trust). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName, [string]$Path, [double]$Now = 0)
    if (-not $Path) { $Path = (Get-VeroPath).Quality }
    if (-not $Now) { $Now = Get-VeroEpoch }
    try { $j = [IO.File]::ReadAllText($Path) | ConvertFrom-Json } catch { return $null }
    if (-not $j -or -not $j.PSObject.Properties['profile'] -or [string]$j.profile -ne $ProfileName) { return $null }
    try {
        $age = $Now - [double]$j.updated
        if ($age -gt [Math]::Max(3 * [int]$j.intervalSeconds, 30) -or $age -lt -60) { return $null }
        [pscustomobject]@{ State = [string]$j.state; LossPct = [double]$j.lossPct; RttMs = $(if ($null -ne $j.rttMs) { [int]$j.rttMs } else { $null }); Checks = [int]$j.checks; Lost = [int]$j.lost }
    } catch { $null }
}
