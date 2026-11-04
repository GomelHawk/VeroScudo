# VeroScudo core, part 82: WireGuard.
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.

# ---------------------------------------------------------------- WireGuard (the WireGuard for Windows app's tunnel services)
function Get-VeroWgDir { Join-Path (Get-VeroSystemDir ProgramFiles) 'WireGuard' }
function Get-VeroWgServiceName([string]$Name) { 'WireGuardTunnel$' + $Name }
function Get-VeroWgState {
    <# 'running', 'stopped' (installed, not running: crashed or stopped in services.msc) or 'missing' (not installed:
       deactivated in the WireGuard app, or never activated). Readable without admin rights. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    $s = Get-Service -Name (Get-VeroWgServiceName $ProfileName) -ErrorAction SilentlyContinue
    if (-not $s) { return 'missing' }
    if ([string]$s.Status -eq 'Running') { 'running' } else { 'stopped' }
}
function Get-VeroWgNic([string]$ProfileName) {
    Get-VeroNic | Where-Object { $_.Name -eq $ProfileName -and [string]$_.Description -like 'WireGuard*' -and [string]$_.OperationalStatus -eq 'Up' } | Select-Object -First 1
}

function Get-VeroWgHealth {
    <# Pure. 'up' = a handshake within the last 3 minutes (a live WireGuard link re-handshakes every 2); 'starting' = service
       started less than 30 s ago and no fresh handshake yet; 'stale' = running but silent (dead link: its adapter stays up);
       'down' = service not running. #>
    [CmdletBinding()] param([string]$ServiceState, [int64[]]$Handshakes = @(), [int64]$Now, [double]$ServiceAgeSeconds = 1e9,
                            [int]$StaleSeconds = $script:WgStaleSeconds, [int]$GraceSeconds = $script:WgGraceSeconds)
    if ($ServiceState -ne 'running') { return 'down' }
    $last = [int64]0
    foreach ($h in $Handshakes) { if ($h -gt $last) { $last = $h } }
    if ($last -gt 0 -and ($Now - $last) -le $StaleSeconds) { return 'up' }
    if ($ServiceAgeSeconds -lt $GraceSeconds) { return 'starting' }
    'stale'
}

function Get-VeroWgTransition {
    <# Pure. What a change of a WireGuard tunnel service between two watchdog passes means:
       'arm'    - it started (activated in the WireGuard app) while not already the armed, active profile: like connecting a
                  Windows VPN by hand, it arms VeroScudo and becomes the active profile;
       'disarm' - the active profile's service was REMOVED (deactivated in the WireGuard app) while armed and VeroScudo was
                  not reconnecting it itself: the user's Off;
       'none'   - anything else (a crash or a stop leaves the service installed: that is a failure, the redial handles it). #>
    [CmdletBinding()] param([string]$Previous, [string]$Current, [bool]$Armed, [bool]$Active, [bool]$LockAlive)
    if (-not $Previous -or $Previous -eq $Current -or $LockAlive) { return 'none' }
    if ($Current -eq 'running' -and -not ($Armed -and $Active)) { return 'arm' }
    if ($Previous -eq 'running' -and $Current -eq 'missing' -and $Armed -and $Active) { return 'disarm' }
    'none'
}

$script:WgSeen = @{}
function Update-VeroWgWatch {
    <# Watchdog pass for WireGuard profiles: service start/removal by the WireGuard app (Get-VeroWgTransition). True when it
       changed the state. Only the long-running watchdog keeps the previous observation, so only it sees the edges.
       Every 'arm' is handled before any 'disarm', and each decision re-reads the armed flag and the active profile: switching
       tunnels in the WireGuard app (B activated, A removed in one pass) must end armed on B, never disarmed. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'watchdog')
    $changed = $false
    $seen = @(foreach ($pr in @($Config.Profiles | Where-Object Type -eq 'wireguard')) {
        $cur = Get-VeroWgState $pr.Profile
        $prev = $script:WgSeen[$pr.Profile]
        $script:WgSeen[$pr.Profile] = $cur
        [pscustomobject]@{ Name = $pr.Profile; Prev = $prev; Cur = $cur }
    })
    $started = @($seen | Where-Object { $_.Cur -eq 'running' -and $_.Prev -and $_.Prev -ne 'running' })
    foreach ($x in $started) {
        $d = Get-VeroWgTransition -Previous $x.Prev -Current $x.Cur -Armed (Test-VeroArmed) -Active ($x.Name -eq (Get-VeroConfig).Profile) -LockAlive (Test-VeroLockAlive)
        if ($d -ne 'arm') { continue }
        Write-VeroLog "WireGuard tunnel '$($x.Name)' was activated outside VeroScudo - it becomes the active profile, kill-switch on (decision source: WireGuard service started)" $Action
        Set-VeroActiveProfile -Name $x.Name -Action $Action
        Set-VeroArmed $true $Action
        Sync-VeroKillSwitch -Config (Get-VeroConfig) -Action $Action
        $changed = $true
    }
    foreach ($x in @($seen | Where-Object { $started -notcontains $_ })) {
        $active = (Get-VeroConfig).Profile
        $d = Get-VeroWgTransition -Previous $x.Prev -Current $x.Cur -Armed (Test-VeroArmed) -Active ($x.Name -eq $active) -LockAlive (Test-VeroLockAlive)
        if ($d -eq 'disarm') {
            Write-VeroLog "WireGuard tunnel '$($x.Name)' was deactivated in the WireGuard app - treated as your Off (decision source: WireGuard service removed, not by VeroScudo)" $Action
            Set-VeroArmed $false $Action
            Disable-VeroKillSwitch -Action $Action
            $changed = $true
        } elseif ($x.Prev -eq 'running' -and $x.Cur -eq 'stopped' -and $x.Name -eq $active -and (Test-VeroArmed)) {
            Write-VeroLog "WireGuard service of '$($x.Name)' stopped but is still installed (crash or services.msc) - a failure: stays blocked, redials" $Action
        }
    }
    $changed
}

function Get-VeroWgServiceAge([string]$ProfileName) {
    try {
        $svc = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f ((Get-VeroWgServiceName $ProfileName) -replace "'", "''")) -ErrorAction Stop
        if ($svc -and $svc.ProcessId) { return ((Get-Date) - (Get-Process -Id $svc.ProcessId -ErrorAction Stop).StartTime).TotalSeconds }
    } catch { Write-Verbose "service age: $($_.Exception.Message)" }
    1e9
}

function Get-VeroWgHealthNow {
    <# Elevated: asks wg.exe for the handshakes (and learns the endpoint the tunnel really uses), caches the result for the
       tray. Not elevated (tray): the cached result if recent, else just "the service runs". #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    $p = Get-VeroPath -VpnProfile $ProfileName
    $state = Get-VeroWgState $ProfileName
    if ($state -ne 'running') { return 'down' }
    if (-not (Test-VeroElevated)) {
        try {
            $c = Get-Content $p.TunnelCache -Raw -ErrorAction Stop | ConvertFrom-Json
            if (((Get-Date) - [datetime]::Parse([string]$c.Time, $null, [Globalization.DateTimeStyles]::RoundtripKind)).TotalSeconds -lt 60) { return [string]$c.Health }
        } catch { Write-Verbose 'no recent WireGuard health' }
        return 'up'
    }
    $wg = Join-Path (Get-VeroWgDir) 'wg.exe'
    $hs = @()
    $ErrorActionPreference = 'Continue'                                    # (local) PS 5.1 turns native stderr into errors under Stop
    try {
        $hs = @(& $wg show $ProfileName latest-handshakes 2>$null | ForEach-Object { $f = ($_ -split '\s+'); if ($f.Count -ge 2) { [int64]$f[1] } })
        $eps = @(& $wg show $ProfileName endpoints 2>$null | ForEach-Object { $f = ($_ -split '\s+'); if ($f.Count -ge 2 -and $f[1] -match '^\[?([0-9a-fA-F:.]+)\]?:\d+$') { $Matches[1] } })
        if ($eps.Count -gt 0) { Add-VeroServerIpCache -ProfileName $ProfileName -Ips $eps }
    } catch { Write-Verbose "wg show failed: $($_.Exception.Message)" }
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $h = Get-VeroWgHealth -ServiceState $state -Handshakes $hs -Now $now -ServiceAgeSeconds 0                  # 0: 'up' or not, cheaply
    if ($h -ne 'up') { $h = Get-VeroWgHealth -ServiceState $state -Handshakes $hs -Now $now -ServiceAgeSeconds (Get-VeroWgServiceAge $ProfileName) }
    try { @{ Health = $h; Time = (Get-Date).ToString('o') } | ConvertTo-Json | Set-Content $p.TunnelCache } catch { Write-Verbose 'tunnel cache not writable' }
    $h
}

function Add-VeroServerIpCache([string]$ProfileName, [string[]]$Ips) {
    <# The address a WireGuard tunnel really talks to goes to the front of the server cache (the kill-switch then allows it). #>
    $p = Get-VeroPath -VpnProfile $ProfileName
    # [string]: Get-Content tags each line with its file path, and ConvertTo-Json would write those tags into wfp.json
    $cached = @(if (Test-Path $p.ServerIp) { Get-Content $p.ServerIp | Where-Object { $_ } | ForEach-Object { [string]$_ } })
    $all = @(@($Ips) + $cached | Where-Object { $_ } | Select-Object -Unique | Select-Object -First 8)
    if (($all -join ',') -ne ($cached -join ',')) { Set-Content -Path $p.ServerIp -Value $all }
}

function Invoke-VeroWgDial {
    <# Starts the tunnel service (installs it from the WireGuard app's stored config when it is not installed). A running
       tunnel without a fresh handshake is restarted: that also looks the server name up again. Waits up to 15 s. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core')
    $name = $Config.Profile
    $exe = Join-Path (Get-VeroWgDir) 'wireguard.exe'
    if (-not (Test-Path $exe)) { Write-VeroLog 'ERROR: WireGuard for Windows is not installed (wireguard.com/install)' $Action; return }
    $state = Get-VeroWgState $name
    if ($state -eq 'running') {
        $h = Get-VeroWgHealthNow $name
        if ($h -eq 'starting') { Start-Sleep -Seconds 5; return }
        if ($h -eq 'up') { return }
        Write-VeroLog "WireGuard '$name': no handshake for over $($script:WgStaleSeconds / 60) minutes - restarting the tunnel" $Action
        Invoke-VeroWgHangUp -ProfileName $name
        Sync-VeroKillSwitch -Config $Config -Action $Action                 # tunnel gone: the redial's DNS permit is back for the endpoint name
        $state = Get-VeroWgState $name
    }
    if ($state -eq 'stopped') {
        Start-Service -Name (Get-VeroWgServiceName $name) -ErrorAction SilentlyContinue
    } else {
        $conf = Join-Path (Get-VeroWgDir) "Data\Configurations\$name.conf.dpapi"
        if (-not (Test-Path $conf)) { Write-VeroLog "ERROR: WireGuard tunnel '$name' not found - import it in the WireGuard app first" $Action; return }
        Start-Process -FilePath $exe -ArgumentList ('/installtunnelservice "{0}"' -f $conf) -WindowStyle Hidden -Wait
    }
    $t = Get-Date
    while (((Get-Date) - $t).TotalSeconds -lt 15) { Start-Sleep -Seconds 1; if ((Get-VeroWgHealthNow $name) -eq 'up') { return }; if (Get-VeroPendingSwitch) { return } }
}

function Invoke-VeroWgHangUp {
    <# Deactivates the tunnel exactly like the WireGuard app does (removes its service), so the app shows it inactive too. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    if ((Get-VeroWgState $ProfileName) -eq 'missing') { return }
    $exe = Join-Path (Get-VeroWgDir) 'wireguard.exe'
    Start-Process -FilePath $exe -ArgumentList ('/uninstalltunnelservice {0}' -f $ProfileName) -WindowStyle Hidden -Wait
    $t = Get-Date
    while ((Get-VeroWgState $ProfileName) -ne 'missing' -and ((Get-Date) - $t).TotalSeconds -lt 10) { Start-Sleep -Milliseconds 500 }
}

function Test-VeroWireGuardConf {
    <# Checks a WireGuard .conf before it is added: returns @{ Errors; Warnings; Server; Port }. Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $errors = New-Object System.Collections.Generic.List[string]
    $warn = New-Object System.Collections.Generic.List[string]
    $section = ''; $peers = @(); $cur = $null; $dns = $false
    foreach ($raw in ($Text -split "`r?`n")) {
        $line = ($raw -replace '#.*$', '').Trim()
        if (-not $line) { continue }
        if ($line -match '^\[(\w+)\]$') {
            $section = $Matches[1].ToLowerInvariant()
            if ($section -eq 'peer') { $cur = @{ Endpoint = ''; Allowed = @(); Keepalive = 0 }; $peers += $cur }
            continue
        }
        if ($line -notmatch '^([A-Za-z]+)\s*=\s*(.*)$') { continue }
        $k = $Matches[1].ToLowerInvariant(); $v = $Matches[2].Trim()
        if ($section -eq 'interface' -and $k -eq 'dns' -and $v) { $dns = $true }
        if ($section -eq 'peer' -and $cur) {
            switch ($k) {
                'endpoint' { $cur.Endpoint = $v }
                'allowedips' { $cur.Allowed += @($v -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
                'persistentkeepalive' { $cur.Keepalive = [int]($v -replace '[^0-9]', '0') }
            }
        }
    }
    $server = ''; $port = 0
    $withEndpoint = @($peers | Where-Object { $_.Endpoint })
    if ($withEndpoint.Count -eq 0) { $errors.Add('no peer with an Endpoint - VeroScudo needs the server address for the kill-switch') }
    elseif ($withEndpoint.Count -gt 1) { $warn.Add('more than one peer has an Endpoint: VeroScudo allows only the first one through the kill-switch') }
    if ($withEndpoint.Count -ge 1) {
        $ep = $withEndpoint[0]
        if ($ep.Endpoint -match '^\[([0-9a-fA-F:.]+)\]:(\d+)$' -or $ep.Endpoint -match '^([^:\[\]]+):(\d+)$') { $server = $Matches[1]; $port = [int]$Matches[2] }
        else { $errors.Add("cannot read the Endpoint '$($ep.Endpoint)' (host:port)") }
        if ($server -and -not (Test-VeroHost $server)) { $errors.Add("invalid Endpoint host '$server'") }
        if ($ep.Keepalive -le 0) { $warn.Add('PersistentKeepalive is not set: VeroScudo judges a WireGuard link by its handshakes, so an idle tunnel would look dead and be restarted. Add "PersistentKeepalive = 25" to the [Peer].') }
        $all = @($peers | ForEach-Object { $_.Allowed })
        if ($all -notcontains '0.0.0.0/0') { $warn.Add('AllowedIPs does not contain 0.0.0.0/0 (split tunnel): while VeroScudo is on, everything outside the tunnel stays blocked.') }
    }
    if (-not $dns) { $warn.Add('No DNS in [Interface]: names may not resolve while VeroScudo blocks the local network''s DNS.') }
    [pscustomobject]@{ Errors = @($errors); Warnings = @($warn); Server = $server; Port = $port }
}
