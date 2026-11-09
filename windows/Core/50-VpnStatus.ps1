# VeroScudo core, part 50: VPN status and RAS events.
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.

# ---------------------------------------------------------------- VPN status & events
function Get-VeroNic {
    <# .NET interface list: ~ms, where the equivalent CIM cmdlets cost hundreds of ms - this runs every 15 s. #>
    [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()
}
function Get-VeroTunnelNic([string]$ProfileName) {
    Get-VeroNic | Where-Object { $_.Name -eq $ProfileName -and [string]$_.NetworkInterfaceType -eq 'Ppp' -and [string]$_.OperationalStatus -eq 'Up' } | Select-Object -First 1
}

function Test-VeroVpnConnected {
    <# Is the profile's tunnel really carrying traffic? RAS: the adapter / RAS says connected. OpenVPN: the daemon reported
       CONNECTED and that tunnel address sits on an up tunnel adapter. WireGuard: the service runs and the last handshake is
       fresh (a dead WireGuard link keeps its adapter up, so the adapter alone proves nothing). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName, [string]$Type)
    if (-not $Type) { $Type = Get-VeroProfileType $ProfileName }
    [bool](& (Get-VeroTypeHandler $Type).IsConnected $ProfileName)
}
function Test-VeroRasConnected {
    <# The built-in client's tunnel is up: the RAS adapter, else the VPN connection object, else rasdial's own list. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    if (Get-VeroTunnelNic $ProfileName) { return $true }                  # fast path: the RAS adapter is up
    $c = Get-VpnConnection -Name $ProfileName -ErrorAction SilentlyContinue
    if (-not $c) { $c = Get-VpnConnection -Name $ProfileName -AllUserConnection -ErrorAction SilentlyContinue }
    if ($c) { return $c.ConnectionStatus -eq 'Connected' }
    return ((& $script:Rasdial) -join ' ') -match ('\b' + [regex]::Escape($ProfileName) + '\b')
}

function Get-VeroRasVerdict {
    <# Pure. From 20226 records {Profile; CoId; Code; Time} picks the newest and flags a conflict: RAS writes exactly one
       termination per connection (CoID), so two with different codes mean one of them was forged. #>
    [CmdletBinding()] param([object[]]$Records)
    $recs = @($Records | Where-Object { $_ })
    if ($recs.Count -eq 0) { return $null }
    $newest = $recs | Sort-Object Time -Descending | Select-Object -First 1
    $codes = @($recs | Where-Object CoId -eq $newest.CoId | ForEach-Object { [int64]$_.Code } | Select-Object -Unique)
    [pscustomobject]@{ Profile = $newest.Profile; CoId = $newest.CoId; Code = [int64]$newest.Code; Conflict = ($codes.Count -gt 1); Time = $newest.Time }
}

function Get-VeroRasTermination {
    [CmdletBinding()] param([int]$WithinMinutes = 2)
    $recs = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'RasClient'; Id = 20226
                                              StartTime = (Get-Date).AddMinutes(-60) } -ErrorAction SilentlyContinue |
        Where-Object { $_.Properties.Count -ge 4 } |
        ForEach-Object { [pscustomobject]@{ Profile = [string]$_.Properties[2].Value; CoId = [string]$_.Properties[0].Value; Code = $_.Properties[3].Value; Time = $_.TimeCreated } }
    $recent = @($recs | Where-Object Time -ge (Get-Date).AddMinutes(-$WithinMinutes))
    if ($recent.Count -eq 0) { return $null }
    $newest = $recent | Sort-Object Time -Descending | Select-Object -First 1
    Get-VeroRasVerdict -Records @($recs | Where-Object CoId -eq $newest.CoId)    # conflict check over the last hour
}

function Get-VeroRasConnected {
    <# Profile name of the newest "connected" event: RasMan 20267 (System log - not writable by ordinary users), else
       RasClient 20225 (Application log): an IKEv2 connect logs ONLY that one. The Application log is
       user-writable, so the caller arms only when that profile really is connected - a forged record can at most turn
       VeroScudo on (the strict direction), never off. -Names: the configured profiles (to find the name in a 20225). #>
    [CmdletBinding()] param([int]$WithinMinutes = 2, [string[]]$Names = @())
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'RasMan'; Id = 20267
                                            StartTime = (Get-Date).AddMinutes(-$WithinMinutes) } -MaxEvents 1 -ErrorAction SilentlyContinue
    $r = Get-VeroRasClientConnect -WithinMinutes $WithinMinutes -Names $Names | Select-Object -First 1
    # the NEWER of the two: after a switch the System log still holds the old profile's connect (e.g.
    # SSTP CorporateVPN in RasMan, then IKEv2 PrivateVPN only in RasClient - else the old one is taken, the new one ignored)
    $rm = if ($ev -and $ev.Properties.Count -ge 3) { [pscustomobject]@{ Profile = [string]$ev.Properties[2].Value; Time = $ev.TimeCreated } } else { $null }
    if ($rm -and $r) { return $(if ($r.Time -gt $rm.Time) { $r.Profile } else { $rm.Profile }) }
    if ($rm) { return $rm.Profile }
    if ($r) { return $r.Profile }
    $null
}

function Get-VeroRasClientConnect {
    <# RasClient 20225 "connected" records (newest first) whose connection name is one of -Names: @{ Profile; CoId; Time }. #>
    [CmdletBinding()] param([int]$WithinMinutes = 60, [string[]]$Names = @())
    $evs = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'RasClient'; Id = 20225
                                               StartTime = (Get-Date).AddMinutes(-$WithinMinutes) } -MaxEvents 20 -ErrorAction SilentlyContinue)
    foreach ($e in $evs) {
        $vals = @($e.Properties | ForEach-Object { [string]$_.Value })
        $name = $vals | Where-Object { $Names -contains $_ } | Select-Object -First 1
        $coid = $vals | Where-Object { $_ -match '^\{[0-9A-Fa-f-]{36}\}$' } | Select-Object -First 1
        if ($name) { [pscustomobject]@{ Profile = $name; CoId = [string]$coid; Time = $e.TimeCreated } }
    }
}

function Get-VeroRasConnectedRecord {
    <# The newest RasMan "connected" (20267, System log - ordinary users cannot write it) for a profile, with its connection id
       (CoID). No time limit: it is the connection a later termination must belong to. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName, [switch]$AllowApplicationLog)
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'RasMan'; Id = 20267 } -MaxEvents 50 -ErrorAction SilentlyContinue |
          Where-Object { $_.Properties.Count -ge 3 -and [string]$_.Properties[2].Value -eq $ProfileName } | Select-Object -First 1
    $rm = if ($ev) { [pscustomobject]@{ Profile = $ProfileName; CoId = [string]$ev.Properties[0].Value; Time = $ev.TimeCreated } } else { $null }
    if (-not $AllowApplicationLog) { return $rm }
    # at arm only: IKEv2 has no RasMan record - take the RasClient 20225 of THIS connect (newer than any RasMan one)
    $rc = Get-VeroRasClientConnect -WithinMinutes 5 -Names @($ProfileName) | Where-Object { $_.CoId } | Select-Object -First 1
    if ($rc -and (-not $rm -or $rc.Time -gt $rm.Time)) { return $rc }
    $rm
}

function Get-VeroExpectedCoId {
    <# The connection ids a "you hung up" may name: the one recorded at arm AND the newest System-log connect of the profile -
       both are trusted sources (two connects within a second can leave the record one connection behind). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    $ids = @()
    $f = (Get-VeroPath).RasCoId
    if (Test-Path $f) { try { $j = Get-Content $f -Raw | ConvertFrom-Json; if ([string]$j.Profile -eq $ProfileName -and [string]$j.CoId) { $ids += [string]$j.CoId } } catch { Write-Verbose 'ras-coid unreadable' } }
    $r = Get-VeroRasConnectedRecord -ProfileName $ProfileName
    if ($r -and $r.CoId) { $ids += [string]$r.CoId }
    @($ids | Select-Object -Unique)
}

$script:LastDialCode = 0
function Test-VeroRecentOff {
    <# True for 30 s after your Off: a redial that was already running can still connect then - that is not you connecting. #>
    $f = (Get-VeroPath).OffAt
    if (-not (Test-Path $f)) { return $false }
    try { ((Get-Date) - [datetime]::Parse((Get-Content $f -Raw).Trim(), $null, [Globalization.DateTimeStyles]::RoundtripKind)).TotalSeconds -lt 30 } catch { $false }
}

function Save-VeroRasCoId {
    <# Records the connection id of the profile's newest connect (anti-forgery for a later "you hung up"). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    Start-Sleep -Milliseconds 500                                             # RAS writes the connect record right after it connects
    $rec = Get-VeroRasConnectedRecord -ProfileName $ProfileName -AllowApplicationLog
    if ($rec) { @{ Profile = $rec.Profile; CoId = $rec.CoId; Time = (Get-Date).ToString('o') } | ConvertTo-Json | Set-Content (Get-VeroPath).RasCoId }
}

function Invoke-VeroArmConnected {
    <# A Windows VPN profile connected by hand (any protocol): arm for it - the same steps from the Connected task and from the
       watchdog's own check, so the outcome never depends on which events a protocol logs. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'arm')
    $p = Get-VeroPath
    # an SSTP tunnel may still be checking its server certificate's revocation when the filters arrive
    if ((Get-VeroConfigType $Config) -eq 'ras' -and (Get-VeroTunnelType $Config.Profile) -in 'Sstp', 'Automatic') {
        Open-VeroCrlWindow -Action $Action -Reason 'SSTP tunnel just connected (revocation check may still run)'
    }
    # remember WHICH connection this is: a later "you hung up" must name the same connection id (anti-forgery)
    $rec = Get-VeroRasConnectedRecord -ProfileName $Config.Profile -AllowApplicationLog
    if ($rec) { @{ Profile = $rec.Profile; CoId = $rec.CoId; Time = (Get-Date).ToString('o') } | ConvertTo-Json | Set-Content $p.RasCoId }
    Update-VeroServerIpBeforeArm -Config $Config -Action $Action
    Set-VeroArmed $true $Action; Sync-VeroKillSwitch -Config $Config -Action $Action
}

function Update-VeroServerIpBeforeArm {
    <# Look the server name up NOW, while no filters are in force yet (not armed): the kill-switch then allows the address the
       tunnel really uses. A server that moved (the cache still has the old address - the
       tunnel would be cut 5 s after arming and every redial refused) is picked up before it can bite. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core')
    if ((Test-VeroArmed) -or @($Config.ServerIps).Count -gt 0) { return }
    $before = @(Resolve-VeroServerIp -Config $Config -CacheOnly)
    $now = @(& (Get-VeroTypeHandler (Get-VeroConfigType $Config)).ResolveIps $Config)
    if (($now -join ',') -ne ($before -join ',')) { Write-VeroLog ("server '{0}' resolves to {1} now (cached: {2})" -f $Config.Server, ($now -join ','), $(if ($before) { $before -join ',' } else { 'none' })) $Action }
}

$script:RasSeen = @{}
function Update-VeroRasWatch {
    <# Watchdog: a configured Windows VPN profile that BECAME connected since the last pass (15 s) while it is not the armed,
       active one arms VeroScudo for it - for every protocol, whatever Windows logged (IKEv2 writes no RasMan 20267; a type may
       write neither event). Edges only: the first look after start changes nothing, and our own Off (disarm, then hang up)
       is a falling edge. True when it armed. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'watchdog')
    $up = @(Get-VeroNic | Where-Object { [string]$_.NetworkInterfaceType -eq 'Ppp' -and [string]$_.OperationalStatus -eq 'Up' } | ForEach-Object Name)
    $armedNow = $false
    foreach ($pr in @($Config.Profiles | Where-Object Type -eq 'ras')) {
        $cur = $up -contains $pr.Profile
        $prev = $script:RasSeen[$pr.Profile]
        $script:RasSeen[$pr.Profile] = $cur
        if ($null -eq $prev -or $prev -or -not $cur -or $armedNow) { continue }
        if ((Test-VeroArmed) -and $pr.Profile -eq $Config.Profile) { continue }      # already protected by it
        if (Test-VeroRecentOff) { continue }                                         # a redial finishing just after your Off
        if (Test-VeroLockAlive) { continue }                                         # our own redial / switch is running
        Write-VeroLog "Windows VPN '$($pr.Profile)' connected - kill-switch on for it (decision source: watchdog saw the tunnel come up)" $Action
        if ($pr.Profile -ne $Config.Profile) { Set-VeroActiveProfile -Name $pr.Profile -Action $Action }
        Invoke-VeroArmConnected -Config (Get-VeroConfig) -Action $Action
        $armedNow = $true
    }
    $armedNow
}

function Get-VeroRasCode {
    <# Reason code of the newest RasClient event (20226 terminated / 20227 dial failed) for this profile. -1 if none. #>
    [CmdletBinding()] param([Parameter(Mandatory)][int]$EventId, [Parameter(Mandatory)][string]$ProfileName, [int]$WithinMinutes = 5)
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'RasClient'; Id = $EventId
                                           StartTime = (Get-Date).AddMinutes(-$WithinMinutes) } -ErrorAction SilentlyContinue |
          Where-Object { $_.Properties.Count -ge 4 -and $_.Properties[2].Value -eq $ProfileName } |
          Sort-Object TimeCreated -Descending | Select-Object -First 1
    if ($ev) { return [int64]$ev.Properties[3].Value }
    return -1
}

function Get-VeroDecision {
    <# The one judgement the guard makes. 631 = "the user disconnected" (Windows RAS). #>
    [CmdletBinding()] param([Parameter(Mandatory)][int64]$ReasonCode, [Parameter(Mandatory)][bool]$Armed)
    if ($ReasonCode -eq 631) { return 'disarm' }
    if ($Armed) { return 'reconnect' }
    return 'none'
}
