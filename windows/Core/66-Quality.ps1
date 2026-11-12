# VeroScudo core, part 66: connection quality - optional checks through the tunnel while protected (config connectionCheck).
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.
# Same rules on every platform (Linux/macOS: linux/veroscudo/quality.py; docs/ARCHITECTURE.md "Connection check"):
#  - every intervalSeconds (10-100) the watchdog checks each address once: ping, a TCP connection to a port, or HTTPS (a TLS
#    handshake and one HEAD request without credentials - any HTTP answer counts: the real way to a web service);
#  - an answer slower than 1000 ms per round trip is "slow" (ping and TCP: 1 round trip, a TLS handshake 2, HTTPS 3);
#  - every check counts: loss = failed checks / all checks of the last windowMinutes (1-10), never fewer than 3 rounds;
#  - below 10 % lost: good; 10-50 %: unstable; above 50 %: bad. Slow answers count like partial loss: 10 % or more lost or
#    slow together makes a good connection unstable - never bad (it still answers);
#  - no rating ("checking") until one full window has passed since the rating started: it starts over on every connect,
#    profile switch and change of the check settings (interval, window, addresses).
# The checks run only while armed and connected, so they go through the tunnel; nothing in the kill-switch is opened.

$script:CheckDefaultHost = '1.1.1.1'
$script:CheckMinChecks = 3
$script:CheckSlowMs = 1000                                              # per round trip: a slower answer is "slow"

function Get-VeroCheckRoundTrips([string]$Method, [switch]$Tls) {
    <# How many round trips a check takes: ping and TCP 1, a TLS handshake 2 (TCP + TLS 1.3), HTTPS 3 (+ the request).
       Pure (= quality.round_trips on Linux/macOS). #>
    if ($Method -eq 'https') { 3 } elseif ($Tls) { 2 } else { 1 }
}

function Test-VeroCheckInTime([string]$Method, [double]$Ms, [switch]$Tls) {
    <# $false = slow: answered, but slower than CheckSlowMs per round trip. Pure (= quality.judge on Linux/macOS). #>
    $Ms -le $script:CheckSlowMs * (Get-VeroCheckRoundTrips $Method -Tls:$Tls)
}

function New-VeroCheckTarget([string]$HostName, [string]$Method = 'tcp', [int]$Port = 443) {
    [pscustomobject]@{ Host = $HostName; Method = $Method; Port = $(if ($Method -in 'tcp', 'https') { $Port } else { 443 }) }
}

function Get-VeroCheckLabel($Target) {
    <# How an address is named in the tooltip and the log: "host (ping)", "host:port", "host (HTTPS)" / "host:port (HTTPS)".
       Pure (= Target.label on Linux/macOS). #>
    switch ([string]$Target.Method) {
        'ping'  { "$($Target.Host) (ping)" }
        'https' { if ([int]$Target.Port -eq 443) { "$($Target.Host) (HTTPS)" } else { "$($Target.Host):$($Target.Port) (HTTPS)" } }
        default { "$($Target.Host):$($Target.Port)" }
    }
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
        if ($m -notin 'ping', 'tcp', 'https') { throw "config.json: connectionCheck method must be 'ping', 'tcp' or 'https'" }
        $port = 443
        if ($m -in 'tcp', 'https' -and $t.PSObject.Properties['port']) {
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
        targets = @($Check.Targets | ForEach-Object { if ($_.Method -in 'tcp', 'https') { [ordered]@{ host = $_.Host; method = [string]$_.Method; port = [int]$_.Port } } else { [ordered]@{ host = $_.Host; method = 'ping' } } })
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
        if ($m -notin 'ping', 'tcp', 'https') { throw "Address ${i}: choose Ping, TCP port or HTTPS." }
        $p = if ($r.Port) { [int]$r.Port } else { 443 }
        if ($m -in 'tcp', 'https' -and $a.Port -and $p -eq 443) { $p = [int]$a.Port }
        if ($m -in 'tcp', 'https' -and ($p -lt 1 -or $p -gt 65535)) { throw "Address ${i}: the port must be 1-65535." }
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

function Get-VeroQualityRating([int]$Lost, [int]$Slow, [int]$Checks) {
    <# good / unstable / bad from the counts (Checks > 0), see the top of this file. Pure (= quality.rating); the statistics'
       bars use it too. #>
    $loss = 100.0 * $Lost / $Checks
    if ($loss -gt 50) { 'bad' } elseif ($loss -ge 10 -or 100.0 * ($Lost + $Slow) / $Checks -ge 10) { 'unstable' } else { 'good' }
}

function Measure-VeroQuality {
    <# Samples: @{ T (seconds); Ok; Rtt (ms or $null); Slow }, one per check -> @{ State; LossPct; RttMs; Checks; Lost; Slow }.
       -Since: when the rating started - until a full window has passed the answer is 'checking'. Pure. #>
    [CmdletBinding()] param([object[]]$Samples = @(), [Parameter(Mandatory)][double]$Now, [Parameter(Mandatory)][double]$WindowSeconds, [double]$Since = -1)
    $recent = @($Samples | Where-Object { $_ -and ($Now - [double]$_.T) -le $WindowSeconds })
    $n = $recent.Count
    $lost = @($recent | Where-Object { -not $_.Ok }).Count
    $slow = @($recent | Where-Object { $_.Ok -and $_.ContainsKey('Slow') -and $_.Slow }).Count
    if ($n -lt $script:CheckMinChecks -or ($Since -ge 0 -and ($Now - $Since) -lt $WindowSeconds)) { return [pscustomobject]@{ State = 'checking'; LossPct = 0.0; RttMs = $null; Checks = $n; Lost = $lost; Slow = $slow } }
    $loss = 100.0 * $lost / $n
    $rtts = @($recent | Where-Object { $_.Ok -and $null -ne $_.Rtt } | ForEach-Object { [double]$_.Rtt } | Sort-Object)
    $rtt = $null
    if ($rtts.Count -gt 0) {
        $mid = [int][Math]::Floor($rtts.Count / 2)
        $med = if ($rtts.Count % 2) { $rtts[$mid] } else { ($rtts[$mid - 1] + $rtts[$mid]) / 2 }
        $rtt = [int][Math]::Round($med)
    }
    [pscustomobject]@{ State = (Get-VeroQualityRating $lost $slow $n); LossPct = [Math]::Round($loss, 1); RttMs = $rtt; Checks = $n; Lost = $lost; Slow = $slow }
}

function Format-VeroQuality {
    <# 'good · 45 ms', 'unstable · 22.5% lost', 'unstable · 40% slow, 1450 ms', 'unstable · 11.1% lost, 16.7% slow',
       'checking…' - the short text of the tray. Pure (= quality.describe). #>
    [CmdletBinding()] param($Quality)
    $dot = [string][char]0x00B7
    $inv = [Globalization.CultureInfo]::InvariantCulture
    if (-not $Quality -or $Quality.State -eq 'checking') { return 'checking' + [char]0x2026 }
    if ($Quality.State -eq 'good') { if ($null -ne $Quality.RttMs) { return "good $dot $($Quality.RttMs) ms" } else { return 'good' } }
    $slow = if ($Quality.PSObject.Properties['Slow']) { [int]$Quality.Slow } else { 0 }
    $slowPct = if ($slow -gt 0 -and [int]$Quality.Checks -gt 0) { ([Math]::Round(100.0 * $slow / [int]$Quality.Checks, 1)).ToString('0.#', $inv) } else { '0' }
    $lost = if ($Quality.PSObject.Properties['Lost']) { [int]$Quality.Lost } else { 1 }
    if ($slow -gt 0 -and $lost -eq 0) {
        return ('{0} {1} {2}% slow' -f $Quality.State, $dot, $slowPct) + $(if ($null -ne $Quality.RttMs) { ", $($Quality.RttMs) ms" } else { '' })
    }
    ('{0} {1} {2}% lost' -f $Quality.State, $dot, ([double]$Quality.LossPct).ToString('0.#', $inv)) + $(if ($slow -gt 0) { ", $slowPct% slow" } else { '' })
}

function Invoke-VeroProbeRound {
    <# Every address once, in parallel: ping (ICMP echo) or a TCP connection. Returns one @{ Ok; RttMs } per target.
       -Tls (Hiddify profiles): a TLS handshake instead, on the target's TCP port (443 for a ping target). Hiddify's TUN answers
       pings and completes TCP handshakes itself, locally, also when none of its servers works (<1 ms to a
       fake-DNS address) - only a real server can answer a TLS handshake. A certificate that does not match (a bare IP, a
       private name) still proves the server answered: that counts as reached; a closed or reset connection does not. #>
    [CmdletBinding()] param([object[]]$Targets, [int]$TimeoutMs = 3000, [switch]$Tls)
    $anyHttps = @($Targets | Where-Object { $_.Method -eq 'https' }).Count -gt 0
    if ($anyHttps -and $TimeoutMs -lt 5000) { $TimeoutMs = 5000 }          # TLS + one request: a few round trips
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $jobs = @(foreach ($t in $Targets) {
        $j = @{ Target = $t; Task = $null; Client = $null; Ssl = $null; Stage = 'tcp'; Ms = $null; Ok = $false; Https = $false; Buf = $null }
        try {
            $j.Https = ($t.Method -eq 'https')
            if ($t.Method -eq 'ping' -and -not $Tls) { $j.Stage = 'ping'; $j.Client = New-Object System.Net.NetworkInformation.Ping; $j.Task = $j.Client.SendPingAsync([string]$t.Host, $TimeoutMs) }
            else {
                $port = if ($t.Method -eq 'ping') { 443 } else { [int]$t.Port }
                $fam = if ([string]$t.Host -match ':') { [System.Net.Sockets.AddressFamily]::InterNetworkV6 } else { [System.Net.Sockets.AddressFamily]::InterNetwork }
                $j.Client = New-Object System.Net.Sockets.TcpClient($fam); $j.Task = $j.Client.ConnectAsync([string]$t.Host, $port)
            }
        } catch { $j.Task = $null }
        $j
    })
    while ($sw.ElapsedMilliseconds -lt $TimeoutMs) {
        $pending = 0
        foreach ($j in $jobs) {
            if (-not $j.Task -or $null -ne $j.Ms) { continue }
            if (-not $j.Task.IsCompleted) { $pending++; continue }
            $failed = $j.Task.IsFaulted -or $j.Task.IsCanceled
            if ($j.Stage -eq 'tls' -and $j.Https -and -not $failed) {
                try {                                                   # HTTPS: one HEAD request, no credentials - any HTTP answer counts
                    $req = [Text.Encoding]::ASCII.GetBytes("HEAD / HTTP/1.1`r`nHost: $($j.Target.Host)`r`nUser-Agent: VeroScudo`r`nConnection: close`r`n`r`n")
                    $j.Ssl.Write($req, 0, $req.Length); $j.Ssl.Flush()
                    $j.Buf = New-Object byte[] 64
                    $j.Task = $j.Ssl.ReadAsync($j.Buf, 0, $j.Buf.Length); $j.Stage = 'http'; $pending++
                } catch { $j.Ms = $sw.ElapsedMilliseconds }
                continue
            }
            if ($j.Stage -eq 'tcp' -and ($Tls -or $j.Https) -and -not $failed -and $j.Client.Connected) {
                try {                                                   # connected (maybe only to Hiddify's TUN): now the handshake
                    $j.Ssl = New-Object System.Net.Security.SslStream($j.Client.GetStream(), $false)
                    $j.Task = $j.Ssl.AuthenticateAsClientAsync([string]$j.Target.Host); $j.Stage = 'tls'; $pending++
                } catch { $j.Ms = $sw.ElapsedMilliseconds }
                continue
            }
            $j.Ms = $sw.ElapsedMilliseconds
            switch ($j.Stage) {
                'ping' { if (-not $failed -and [string]$j.Task.Result.Status -eq 'Success') { $j.Ok = $true; $j.Ms = [int]$j.Task.Result.RoundtripTime } }
                'tcp'  { $j.Ok = (-not $failed) -and [bool]$j.Client.Connected }
                'tls'  {
                    $inner = if ($j.Task.Exception) { $j.Task.Exception.GetBaseException() } else { $null }
                    $j.Ok = (-not $failed) -or ($inner -is [System.Security.Authentication.AuthenticationException])   # the server answered
                }
                'http' { $j.Ok = (-not $failed) -and [int]$j.Task.Result -ge 5 -and [Text.Encoding]::ASCII.GetString($j.Buf, 0, 5) -eq 'HTTP/' }
            }
        }
        if ($pending -eq 0) { break }
        Start-Sleep -Milliseconds 20
    }
    foreach ($j in $jobs) {
        $ok = [bool]($j.Ok -and $null -ne $j.Ms)
        $slow = $ok -and -not (Test-VeroCheckInTime ([string]$j.Target.Method) $j.Ms -Tls:$Tls)
        try { if ($j.Ssl) { $j.Ssl.Dispose() } } catch { Write-Verbose 'probe cleanup' }
        try { if ($j.Client -is [System.Net.Sockets.TcpClient]) { $j.Client.Close() } elseif ($j.Client) { $j.Client.Dispose() } } catch { Write-Verbose 'probe cleanup' }
        [pscustomobject]@{ Ok = $ok; RttMs = $(if ($ok) { [int]$j.Ms } else { $null }); Slow = [bool]$slow }
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

function Test-VeroSlowResult($Result) {
    <# A probe result answered, but slow (a result without Slow - an older caller - is not slow). #>
    [bool]($Result.Ok -and $Result.PSObject.Properties['Slow'] -and $Result.Slow)
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
    $hid = [string]$cfg.Type -eq 'hiddify'                                  # Hiddify answers ping/TCP itself: TLS handshakes instead
    $round = @(Invoke-VeroProbeRound -Targets $chk.Targets -Tls:$hid -TimeoutMs $(if ($hid) { 5000 } else { 3000 }))
    for ($ti = 0; $ti -lt $round.Count; $ti++) { $r = $round[$ti]; $script:QualitySamples.Add(@{ T = $now; Ok = [bool]$r.Ok; Rtt = $r.RttMs; Ti = $ti; Slow = (Test-VeroSlowResult $r) }) }
    try { Add-VeroStatsChecks -Sent $round.Count -Lost @($round | Where-Object { -not $_.Ok }).Count -Slow @($round | Where-Object { Test-VeroSlowResult $_ }).Count -Id $cfg.ProfileId -Name $cfg.Profile } catch { Write-VeroLog "ERROR: statistics: $($_.Exception.Message)" $Action }
    $win = Get-VeroCheckWindow $chk
    $keep = @($script:QualitySamples.ToArray() | Where-Object { ($now - [double]$_.T) -le ($win + 1) })   # .ToArray(): @(<List>) throws on PowerShell 5.1
    $script:QualitySamples.Clear(); foreach ($s in $keep) { $script:QualitySamples.Add($s) }
    $q = Measure-VeroQuality -Samples $script:QualitySamples.ToArray() -Now $now -WindowSeconds $win -Since $script:QualityStarted
    $p = (Get-VeroPath).Quality
    $per = @(Get-VeroQualityPerTarget -Samples $script:QualitySamples.ToArray() -Targets @($chk.Targets) -Now $now -WindowSeconds $win)
    $json = [ordered]@{ profile = $cfg.Profile; state = $q.State; lossPct = $q.LossPct; rttMs = $q.RttMs; checks = $q.Checks; lost = $q.Lost; slow = $q.Slow
                        intervalSeconds = $chk.IntervalSeconds; windowMinutes = $chk.WindowMinutes; updated = $now; targets = $per } | ConvertTo-Json -Compress -Depth 4
    [IO.File]::WriteAllText("$p.new", $json)
    Move-Item -LiteralPath "$p.new" -Destination $p -Force
    if ($q.State -ne 'checking' -and $q.State -ne $script:QualityLast) {
        Write-VeroLog ("connection quality: {0} ({1} of {2} checks lost, {3} slow, {4})" -f $q.State, $q.Lost, $q.Checks, $q.Slow, $(if ($null -ne $q.RttMs) { "$($q.RttMs) ms" } else { 'no answer' })) $Action
        $script:QualityLast = $q.State
    }
    [int]$chk.IntervalSeconds
}

function Get-VeroQualityPerTarget {
    <# Each address's share of the window: @{ label; checks; lost } - the tooltip shows which address fails. Pure. #>
    [CmdletBinding()] param([object[]]$Samples = @(), [object[]]$Targets = @(), [Parameter(Mandatory)][double]$Now, [Parameter(Mandatory)][double]$WindowSeconds)
    for ($i = 0; $i -lt $Targets.Count; $i++) {
        $mine = @($Samples | Where-Object { $_ -and $_.ContainsKey('Ti') -and $_.Ti -eq $i -and ($Now - [double]$_.T) -le $WindowSeconds })
        [ordered]@{ label = (Get-VeroCheckLabel $Targets[$i]); checks = $mine.Count; lost = @($mine | Where-Object { -not $_.Ok }).Count }
    }
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
        $per = @(if ($j.PSObject.Properties['targets']) { $j.targets | ForEach-Object { $_ } | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ Label = [string]$_.label; Checks = [int]$_.checks; Lost = [int]$_.lost } } })
        [pscustomobject]@{ State = [string]$j.state; LossPct = [double]$j.lossPct; RttMs = $(if ($null -ne $j.rttMs) { [int]$j.rttMs } else { $null }); Checks = [int]$j.checks; Lost = [int]$j.lost; Targets = $per; Slow = $(if ($j.PSObject.Properties['slow']) { [int]$j.slow } else { 0 }) }
    } catch { $null }
}
