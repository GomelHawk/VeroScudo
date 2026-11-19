# VeroScudo core, part 70: dialing, rejected passwords, Reconnect.
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.

# ---------------------------------------------------------------- dialing
function Read-VeroStoredCredential {
    <# A credential the tray (or Set-VpnCredential.ps1) stored with Export-Clixml in the user's own folder, read by the
       elevated guard. The file is the user's to write, so it is not handed to the general deserializer: the two values
       are picked out of the XML - the user name and the DPAPI-protected password - and anything else in the file makes
       it "no credential". At most 64 KB, no DTD, no link in place of the file. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    try {
        $fi = New-Object IO.FileInfo $Path
        if (-not $fi.Exists -or $fi.Length -gt 65536 -or ($fi.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $null }
        $set = New-Object System.Xml.XmlReaderSettings; $set.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit; $set.XmlResolver = $null
        $doc = New-Object System.Xml.XmlDocument; $doc.XmlResolver = $null
        $r = [System.Xml.XmlReader]::Create($Path, $set)
        try { $doc.Load($r) } finally { $r.Dispose() }
        $ns = New-Object System.Xml.XmlNamespaceManager $doc.NameTable
        $ns.AddNamespace('p', 'http://schemas.microsoft.com/powershell/2004/04')
        # one object and nothing beside it
        if ($doc.SelectNodes('//p:Obj', $ns).Count -ne 1 -or @($doc.DocumentElement.ChildNodes | Where-Object { $_.NodeType -eq 'Element' }).Count -ne 1) { return $null }
        $u = $doc.SelectSingleNode('/p:Objs/p:Obj/p:Props/p:S[@N="UserName"]', $ns)
        $s = $doc.SelectSingleNode('/p:Objs/p:Obj/p:Props/p:SS[@N="Password"]', $ns)
        if (-not $u -or -not $s -or $s.InnerText -notmatch '^[0-9a-fA-F]+\z') { return $null }
        # Export-Clixml writes some characters of a string as _xHHHH_ (an underscore before an x among them): back to the name as typed
        New-Object pscredential ([System.Xml.XmlConvert]::DecodeName([string]$u.InnerText), (ConvertTo-SecureString -String $s.InnerText))
    } catch { Write-Verbose "stored credential unreadable: $($_.Exception.Message)"; $null }
}
function Get-VeroCredential {
    [CmdletBinding()] param([Parameter(Mandatory)]$Config)
    $p = Get-VeroPath -VpnProfile $Config.Profile
    foreach ($f in $p.Cred, $p.LegacyCred) {
        if (-not (Test-Path $f)) { continue }
        $c = Read-VeroStoredCredential -Path $f
        if (-not $c) { continue }
        if ($f -eq $p.Cred -or $c.UserName -eq $Config.Username) { return $c }    # the 1.0 single credential, if it is for this user
    }
    $null
}
function Get-VeroKeyPassphrase {
    <# OpenVPN: the private-key passphrase, stored like the password (DPAPI, this Windows account only). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    $f = (Get-VeroPath -VpnProfile $ProfileName).KeyPass
    Read-VeroStoredCredential -Path $f
}

$script:EventSettleSeconds = 3              # on-event waits this long before reading the termination records (tests: 0)
$script:RasAuthCodes = @(691)              # "the user name and password combination is not recognized"
# SSTP could not check the server certificate's revocation (CRL/OCSP offline): CRYPT_E_REVOCATION_OFFLINE / _NO_REVOCATION_CHECK
# + WSAEACCES (0x8007271D): with no TCP 80 permit, SSTP's revocation fetch is refused by the filters
# and RasDial returns "access forbidden" instead of a revocation code
$script:RasRevocationCodes = @(-2146885613, -2146885614, 0x80092013, 0x80092012, -2147014883, 10013)
# a dial that keeps failing this way opens the window once per this many minutes, not after every attempt: a network that
# makes every dial fail on the revocation check would otherwise keep svchost's HTTP open all the time
$script:CrlWindowEveryMinutes = 15
function Open-VeroCrlWindow {
    <# Allow svchost TCP 80 for 2 minutes so SSTP can fetch the CRL: after a dial failed on the revocation check, and right
       after an SSTP tunnel came up (it may still be checking when the filters arrive - RAS can report 829 ~5 s after arm). #>
    [CmdletBinding()] param([string]$Action = 'core', [string]$Reason = 'SSTP could not check the server certificate revocation', [switch]$AtArm)
    # -AtArm: the window of a tunnel that just connected. It keeps the time of the last window opened for a FAILED dial,
    # so a real revocation failure soon after an arm still gets its window (Test-VeroCrlWindowRecent counts only those)
    $f = (Get-VeroPath).CrlWindow
    $opened = (Get-Date).ToString('o')
    if ($AtArm) {
        $opened = ''
        if (Test-Path $f) { try { $old = Get-Content $f -Raw | ConvertFrom-Json; if ($old.PSObject.Properties['Opened']) { $opened = [string]$old.Opened } } catch { Write-Verbose 'crl window unreadable' } }
    }
    Write-VeroStateFile -Path $f -Text (@{ Until = (Get-Date).AddMinutes(2).ToString('o'); Opened = $opened } | ConvertTo-Json)
    Write-VeroLog "$Reason - HTTP (TCP 80) from Windows services allowed for 2 minutes so it can" $Action
}
function Test-VeroCrlWindow {
    $f = (Get-VeroPath).CrlWindow
    if (-not (Test-Path $f)) { return $false }
    try {
        $until = [datetime]::Parse([string](Get-Content $f -Raw | ConvertFrom-Json).Until, $null, [Globalization.DateTimeStyles]::RoundtripKind)
        # never longer than the 2 minutes Open-VeroCrlWindow writes: a later time in the file is not ours
        return ((Get-Date) -lt $until -and $until -le (Get-Date).AddMinutes(2).AddSeconds(5))
    } catch { return $false }
}
function Test-VeroCrlWindowRecent {
    <# True while the last window was opened less than $script:CrlWindowEveryMinutes ago (a failed dial does not open another). #>
    $f = (Get-VeroPath).CrlWindow
    if (-not (Test-Path $f)) { return $false }
    try {
        $j = Get-Content $f -Raw | ConvertFrom-Json
        if ($j.PSObject.Properties['Opened'] -and -not [string]$j.Opened) { return $false }   # only ever opened at an arm
        $at = if ($j.PSObject.Properties['Opened']) { [datetime]::Parse([string]$j.Opened, $null, [Globalization.DateTimeStyles]::RoundtripKind) }
              else { [datetime]::Parse([string]$j.Until, $null, [Globalization.DateTimeStyles]::RoundtripKind).AddMinutes(-2) }
        $age = ((Get-Date) - $at).TotalMinutes
        return ($age -ge 0 -and $age -lt $script:CrlWindowEveryMinutes)      # a time in the future is not ours: not counted
    } catch { return $false }
}
function Invoke-VeroDial {
    <# One connection attempt for the active profile's type.
       RAS: RasDial API with the DPAPI-stored credential - the password never appears on a command line (process lists, EDR,
       event 4688); without a stored credential, rasdial uses whatever the phonebook entry has. A rejected password stops the
       automatic redial (Set-VeroAuthFailed): retrying it every few seconds can lock the account on the VPN server. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core')
    & (Get-VeroTypeHandler (Get-VeroConfigType $Config)).Dial $Config $Action
}
function Invoke-VeroRasDial {
    <# The built-in client: RasDial API with the stored credential (see Invoke-VeroDial). #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core')
    $cred = Get-VeroCredential -Config $Config
    if ($cred) {
        Import-VeroNative
        $code = [VeroScudo.Ras]::Dial($Config.Profile, $cred.UserName, $cred.Password)
        if ($code -ne 0) { Write-Verbose "RasDial: $code" }
        $script:LastDialCode = $code
    } else {
        Write-VeroLog "WARNING: no stored credential for '$($Config.Profile)' (tray Settings or Set-VpnCredential.ps1) - dialing without password" $Action
        & $script:Rasdial $Config.Profile 2>&1 | Out-Null
        $code = $LASTEXITCODE
        $script:LastDialCode = $code
    }
    if ($script:RasAuthCodes -contains [int64]$code) { Set-VeroAuthFailed -ProfileName $Config.Profile -Reason "RAS error $code" -Action $Action }
    # ONLY the RasDial result decides - never the Application log (RasClient 20227): ordinary users can write that log, and
    # a forged "revocation offline" record would keep svchost's HTTP open for as long as the redial runs
    if ($script:RasRevocationCodes -contains [int64]$code -and -not (Test-VeroCrlWindow) -and -not (Test-VeroCrlWindowRecent)) {
        Open-VeroCrlWindow -Action $Action
        Sync-VeroKillSwitch -Config $Config -Action $Action                # the next attempt can reach the CRL
    }
}

function Invoke-VeroHangUp {
    <# Ends the profile's tunnel the way its own client does. Callers that must not be read as "the user hung up" (switch,
       Reconnect) protect themselves first: a switch makes the new profile active, Reconnect writes the renew marker. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName, [string]$Type)
    if (-not $Type) { $Type = Get-VeroProfileType $ProfileName }
    & (Get-VeroTypeHandler $Type).HangUp $ProfileName
}

# ---------------------------------------------------------------- rejected password: stop redialing until it is changed
function Set-VeroAuthFailed {
    <# -Which Key: the private-key passphrase was rejected (only a newer passphrase lifts the pause); else the password.
       Always rewritten: its time must be newer than the password that was just rejected. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName, [string]$Reason = '', [string]$Action = 'core', [ValidateSet('Auth', 'Key')][string]$Which = 'Auth')
    $p = Get-VeroPath -VpnProfile $ProfileName
    $first = -not (Test-Path $p.AuthFail)
    Write-VeroStateFile -Path $p.AuthFail -Text ("{0} {1:o} {2}" -f $Which, (Get-Date), $Reason)
    if ($first) {
        Write-VeroLog "PASSWORD REJECTED for '$ProfileName' ($Reason) - automatic redial paused so the account is not locked; traffic stays blocked. Store the right password (tray Settings), then Turn on or Reconnect." $Action
    }
}
function Clear-VeroAuthFailed {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName, [string]$Action = 'core')
    $p = Get-VeroPath -VpnProfile $ProfileName
    if (Test-Path $p.AuthFail) { Remove-Item $p.AuthFail -Force; Write-VeroLog "password pause for '$ProfileName' lifted" $Action }
}
function Test-VeroAuthBlocked {
    <# True while the profile's password was rejected and no newer password (or key passphrase) has been stored since. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    $p = Get-VeroPath -VpnProfile $ProfileName
    if (-not (Test-Path $p.AuthFail)) { return $false }
    $flag = (Get-Item $p.AuthFail).LastWriteTimeUtc
    $which = (([string](Get-Content $p.AuthFail -Raw -ErrorAction SilentlyContinue)) -split '\s+')[0]
    $f = if ($which -eq 'Key') { $p.KeyPass } else { $p.Cred }
    if ($f -and (Test-Path $f) -and (Get-Item $f).LastWriteTimeUtc -gt $flag) { return $false }
    $true
}

# ---------------------------------------------------------------- Reconnect (user): our own hang-up is not "you hung up"
function Set-VeroRenewMarker {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName, [switch]$HungUp)
    $p = Get-VeroPath
    $m = @{ Profile = $ProfileName; Start = (Get-Date).ToString('o'); HungUp = '' }
    if ($HungUp -and (Test-Path $p.Renew)) { try { $old = Get-Content $p.Renew -Raw | ConvertFrom-Json; $m.Start = [string]$old.Start } catch { Write-Verbose 'renew marker unreadable' } }
    if ($HungUp) { $m.HungUp = (Get-Date).ToString('o') }
    Write-VeroStateFile -Path $p.Renew -Text ($m | ConvertTo-Json)           # whole or not at all, any letters in the name
}
function Test-VeroRenewHangUp {
    <# Pure rule: is a termination record at $EventTime our own hang-up for Reconnect? Only for that profile, only between the
       marker's start and 30 s after the hang-up finished, and never for a marker older than 5 minutes. #>
    [CmdletBinding()] param($Marker, [string]$ProfileName, [datetime]$EventTime, [datetime]$Now = (Get-Date))
    if (-not $Marker) { return $false }
    $any = $Marker.PSObject.Properties['AnyProfile'] -and $Marker.AnyProfile       # a marker that could not be read (Get-VeroRenewMarker)
    if (-not $any -and [string]$Marker.Profile -ne $ProfileName) { return $false }
    $start = [datetime]::Parse([string]$Marker.Start, $null, [Globalization.DateTimeStyles]::RoundtripKind)
    if (($Now - $start).TotalMinutes -gt 5) { return $false }
    $end = if ([string]$Marker.HungUp) { [datetime]::Parse([string]$Marker.HungUp, $null, [Globalization.DateTimeStyles]::RoundtripKind).AddSeconds(30) } else { $Now }
    ($EventTime -ge $start.AddSeconds(-1) -and $EventTime -le $end)
}
function Get-VeroRenewMarker {
    $p = Get-VeroPath
    if (Test-Path $p.Renew) {
        try { $m = Get-Content $p.Renew -Raw | ConvertFrom-Json; if ($m -and $m.PSObject.Properties['Profile']) { return $m } } catch { Write-Verbose 'renew marker unreadable' }
        # there, but empty or half-written (read while it was being written): still VeroScudo's own Reconnect - its hang-up
        # must not be read as your Off. The file's own time says when.
        try { return [pscustomobject]@{ Profile = ''; AnyProfile = $true; Start = (Get-Item $p.Renew).LastWriteTime.ToString('o'); HungUp = '' } } catch { Write-Verbose 'renew marker gone' }
    }
    $null
}
function Resolve-VeroTerminationCode {
    <# Pure: the RAS reason code a termination record is taken at, after the anti-forgery checks. 631 ("you hung up") stands
       only when the records for that connection do not conflict, it is not VeroScudo's own hang-up for Reconnect, and it
       names a connection VeroScudo saw connect. Anything else is a link failure (0 here). @{ Code; Notes }: Notes are the
       log lines that explain each downgrade. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Termination, $RenewMarker, [string[]]$ExpectedCoIds = @(), [datetime]$Now = (Get-Date))
    $t = $Termination; $code = $t.Code
    $notes = New-Object System.Collections.Generic.List[string]
    if ($t.Conflict) { $notes.Add('conflicting termination records for one connection (forged?) - treated as a failure'); $code = 0 }
    $when = if ($t.PSObject.Properties['Time']) { $t.Time } else { $null }
    if ($code -eq 631 -and $when -and (Test-VeroRenewHangUp -Marker $RenewMarker -ProfileName $t.Profile -EventTime $when -Now $Now)) {
        $notes.Add("631 comes from VeroScudo's own hang-up for Reconnect - not your Off; stays armed"); $code = 0
    }
    if ($code -eq 631 -and $ExpectedCoIds -notcontains [string]$t.CoId) {
        $notes.Add(("'you hung up' record names connection {0}, but VeroScudo saw {1} connect - forged or stale, treated as a failure" -f $t.CoId, $(if ($ExpectedCoIds) { $ExpectedCoIds -join ' / ' } else { 'none' })))
        $code = 0
    }
    @{ Code = $code; Notes = @($notes) }
}

function Test-VeroLockAlive {
    $p = Get-VeroPath
    if (-not (Test-Path $p.Lock)) { return $false }
    $lockPid = Get-Content $p.Lock -ErrorAction SilentlyContinue | Select-Object -First 1
    # the lock survives a crash or reboot and Windows reuses PIDs: alive only if that PID is still a PowerShell
    # process that was already running when the lock was written
    $proc = if ($lockPid) { Get-Process -Id $lockPid -ErrorAction SilentlyContinue }
    $started = try { $proc.StartTime } catch { $null }
    if ($proc -and $proc.ProcessName -in 'powershell', 'pwsh' -and $started -and $started -le (Get-Item $p.Lock).LastWriteTime) { return $true }
    Remove-Item $p.Lock -Force -ErrorAction SilentlyContinue
    return $false
}

function Enter-VeroLock {
    <# Atomic: CreateNew fails when another loop holds the lock, so two processes can never both redial. #>
    $p = Get-VeroPath
    for ($i = 0; $i -lt 2; $i++) {
        try {
            $fs = [IO.File]::Open($p.Lock, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
            $b = [Text.Encoding]::ASCII.GetBytes([string]$PID); $fs.Write($b, 0, $b.Length); $fs.Close()
            return $true
        } catch [IO.IOException] {
            if (Test-VeroLockAlive) { return $false }                       # alive: someone else redials; stale: removed, retry
        }
    }
    $false
}

$script:DnsFirstSeconds = 3                                              # the redial's DNS window: at most this long
$script:DnsWindow = $false
$script:DnsFresh = @{}

function Get-VeroDialName {
    <# The names a dial of this profile has to resolve: the server (Windows VPN, WireGuard) or the .ovpn's remotes (OpenVPN).
       None for an address, pinned serverIps, or a type VeroScudo does not dial (Hiddify). #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config)
    $type = Get-VeroConfigType $Config
    if (-not (Get-VeroTypeHandler $type).Dials -or @($Config.ServerIps).Count -gt 0) { return @() }
    $hosts = if ($type -eq 'openvpn') { @(try { Get-VeroOpenVpnRemote -ProfileName $Config.Profile | ForEach-Object { [string]$_.Host } } catch { @() }) } else { @([string]$Config.Server) }
    @($hosts | Where-Object { $_ -and -not ((Test-VeroCidr $_) -and $_ -notmatch '/') } | Select-Object -Unique)
}

function Start-VeroDnsLookup([string]$Name) { [System.Net.Dns]::GetHostAddressesAsync($Name) }   # a task (tests replace it)

function Invoke-VeroDnsFirst {
    <# Blocked, right before a dial: the redial's own lookup of its server is the one DNS request that gets out. The DNS
       permit for Windows' DNS client opens, the server's names are looked up (the DNS client keeps the answers, the dial
       finds them there; a moved server's new address is cached and allowed for this dial), and the permit closes again -
       once the answers are in, after DnsFirstSeconds at most. Linux lets only the server's name out (nftables); macOS does
       the same as this (daemon.prime_dns). #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core')
    $names = @(Get-VeroDialName -Config $Config)
    if ($names.Count -eq 0) { return }
    $tasks = @{}
    $script:DnsWindow = $true
    try {
        Sync-VeroKillSwitch -Config $Config -Action $Action
        foreach ($n in $names) { $tasks[$n] = Start-VeroDnsLookup $n }
        try { $null = [System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($tasks.Values), $script:DnsFirstSeconds * 1000) }
        catch { Write-Verbose "DNS lookup of the server failed: $($_.Exception.Message)" }        # a name that does not resolve
    } finally {
        $script:DnsWindow = $false
        Sync-VeroKillSwitch -Config $Config -Action $Action
    }
    $script:DnsFresh = @{}
    foreach ($n in $tasks.Keys) {
        $t = $tasks[$n]
        if ([string]$t.Status -eq 'RanToCompletion') {
            $script:DnsFresh[$n] = @($t.Result | Where-Object { $_.AddressFamily -in 'InterNetwork', 'InterNetworkV6' } | ForEach-Object { $_.IPAddressToString })
        }
    }
    if ($script:DnsFresh.Count -eq 0) { return }
    try {
        $null = & (Get-VeroTypeHandler (Get-VeroConfigType $Config)).ResolveIps $Config      # into the cache, from the answers above
    } finally { $script:DnsFresh = @{} }
    Sync-VeroKillSwitch -Config $Config -Action $Action                                       # a moved server: allowed for this dial
}

function Start-VeroRedial {
    <# Three levels: Invoke-VeroReconnect is the redial loop (one at a time, by the reconnect lock); the 'redial' action
       is the Redial task's way into it; this function is how everybody else gets it going - the watchdog, the Terminated
       task and a profile switch start the Redial task and return. The watchdog so stays what it is, a check every 15 s
       also during an outage, and the Terminated task is free for the next event; so is On. (Your own Reconnect runs the
       loop in its own task.)
       From inside the Redial task itself (the loop took a pending switch) the task cannot be started again - it runs -
       so the loop goes on here. So does it on an install from before the task existed. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core')
    if ($Action -ne 'redial' -and (Start-VeroTask 'Redial')) { return }
    Invoke-VeroReconnect -Config $Config -Action $Action
}
function Invoke-VeroReconnect {
    <# Blocked + redial forever, until the tunnel is up or the user turns the VPN off. Follows a profile switch: the
       config (and so the active profile) is re-read on every attempt.
       -Renew (the user's Reconnect): first block - the kill-switch is applied without the tunnel while it is still up -,
       then hang up, then the normal loop; traffic flows again only once the new tunnel is up. All of it under the
       reconnect lock, so the watchdog never reads our own hang-up as a failure or as the user turning the VPN off. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core', [switch]$Renew, [switch]$Dead)
    if (-not (Enter-VeroLock)) { Write-VeroLog $(if ($Renew) { 'reconnect requested, but a reconnect is already running - it continues' } else { 'reconnect loop already running' }) $Action; return }
    $p = Get-VeroPath
    $attempt = 0
    $pausedLogged = $false
    $switchTo = $null
    try {
        if ($Renew) {
            $type = Get-VeroConfigType $Config
            $who = if ($Dead) { 'by VeroScudo (no traffic through the tunnel)' } else { 'by you' }
            Write-VeroLog "RECONNECT requested ${who}: traffic blocked, hanging up '$($Config.Profile)' ($(Get-VeroTypeLabel $type)), redialing" $Action
            Set-VeroRenewMarker -ProfileName $Config.Profile
            Sync-VeroKillSwitch -Config $Config -Action $Action -ForceDown -Force
            Invoke-VeroHangUp -ProfileName $Config.Profile -Type $type
            $t = Get-Date
            while ((Test-VeroVpnConnected $Config.Profile -Type $type) -and ((Get-Date) - $t).TotalSeconds -lt 15) { Start-Sleep -Milliseconds 500 }
            Set-VeroRenewMarker -ProfileName $Config.Profile -HungUp
            if (Test-VeroVpnConnected $Config.Profile -Type $type) { Write-VeroLog "WARNING: '$($Config.Profile)' did not hang up within 15 s - keeping it" $Action }
        }
        while ((Test-VeroArmed) -and -not (Test-VeroVpnConnected $Config.Profile)) {
            # you picked another profile while this one is being redialed: yours wins (otherwise
            # a switch from the tray is lost while this loop keeps the Switch task busy redialing)
            if (Get-VeroPendingSwitch) {
                $want = Read-VeroSwitchRequest                                   # taken by this loop (the Switch task may take it first: then it switches)
                if ($want -and $want -ne $Config.Profile -and @((Get-VeroConfig).Profiles | ForEach-Object Profile) -contains $want) {
                    Write-VeroLog "you chose '$want' while '$($Config.Profile)' was being redialed - switching to it" $Action
                    $switchTo = $want; break
                }
            }
            $attempt++
            if ($Action -eq 'watchdog') {
                # fallback only - an install without the Redial task, where the watchdog itself runs this loop: it is
                # alive and working. Without this the tray reports "Guard not running" after 3 minutes, and the minutes
                # without a connection would be missing from the statistics
                Write-VeroHeartbeat
                try { Update-VeroStats -Up $false -Down $true -Id ([string]$Config.ProfileId) -Name $Config.Profile } catch { Write-Verbose "statistics: $($_.Exception.Message)" }
            }
            Sync-VeroKillSwitch -Config $Config -Action $Action
            if (Test-VeroAuthBlocked $Config.Profile) {
                if (-not $pausedLogged) { Write-VeroLog "redial paused: the password for '$($Config.Profile)' was rejected - store the right one (tray Settings); still blocked" $Action; $pausedLogged = $true }
                Start-Sleep -Seconds $Config.RetrySeconds
                $Config = Get-VeroConfig
                continue
            }
            $h = Get-VeroTypeHandler (Get-VeroConfigType $Config)             # this attempt's profile (the config is re-read below)
            Invoke-VeroDnsFirst -Config $Config -Action $Action               # the one DNS request while blocked: the server's name
            Invoke-VeroDial -Config $Config -Action $Action
            if (Test-VeroVpnConnected $Config.Profile) {
                if (-not $h.Dials) { Write-VeroLog "$($h.Label) connected again - traffic goes through it" $Action }   # nothing was dialed
                else { Write-VeroLog "reconnected '$($Config.Profile)' after $attempt attempt(s)" $Action }
                & $h.OnReconnected $Config
                break
            }
            if (-not (Test-VeroArmed)) { break }              # you turned the VPN off during the dial: not a failure
            # Hiddify: nothing is dialed - VeroScudo waits for you to connect it there; once, then every ~5 minutes
            if ($h.Dials -or $attempt -eq 1 -or $attempt % 30 -eq 0) { Write-VeroLog "attempt $attempt failed ($(Get-VeroDialFailure $Config))" $Action }
            # a server that moved is looked up again before the next dial (Invoke-VeroDnsFirst), not here: DNS is closed
            Start-Sleep -Seconds $Config.RetrySeconds
            $Config = Get-VeroConfig
        }
        if (-not (Test-VeroArmed)) { Write-VeroLog 'you turned the VPN off - redial stopped' $Action }
    } finally {
        Remove-Item $p.Lock -Force -ErrorAction SilentlyContinue
    }
    if ($switchTo) { Invoke-VeroSwitch -Name $switchTo -Action $Action; return }       # after the lock is released: the switch redials itself
    if ((Test-VeroArmed) -and (Test-VeroVpnConnected $Config.Profile)) { Sync-VeroKillSwitch -Config $Config -Action $Action }
    elseif ($attempt -gt 0 -and -not (Test-VeroArmed) -and (Test-VeroVpnConnected $Config.Profile)) {
        # you pressed Off while this loop was dialing and the dial still connected: Off means disconnected
        Invoke-VeroHangUp $Config.Profile (Get-VeroConfigType $Config)
        Write-VeroLog "you turned VeroScudo off while it was redialing - hung up the tunnel that connected afterwards" $Action
    }
}

function Get-VeroDialFailure($Config) {
    <# One line for the log: why the last attempt did not bring the tunnel up. #>
    & (Get-VeroTypeHandler (Get-VeroConfigType $Config)).DialFailure $Config
}

function Invoke-VeroCheck {
    <# One watchdog pass: armed -> filters exactly as they should be (+ redial when down); disarmed -> nothing left behind. #>
    [CmdletBinding()] param([string]$Action = 'watchdog')
    $cfg = Get-VeroConfig
    $script:CheckCount++
    # each type's own look at what happened outside VeroScudo since the last pass (a tunnel connected by hand, a WireGuard
    # tunnel switched in its app ...): only for the types that have a profile, the built-in client always
    foreach ($type in 'ras', 'hiddify', 'wireguard', 'openvpn') {
        $h = Get-VeroTypeHandler $type
        if (-not $h.Watch -or -not ($h.WatchAlways -or @($cfg.Profiles | Where-Object Type -eq $type).Count -gt 0)) { continue }
        try { if (& $h.Watch $cfg $Action) { $cfg = Get-VeroConfig } } catch { Write-VeroLog "ERROR: $($h.Label) watch: $($_.Exception.Message)" $Action }
    }
    # about once a minute: other VPNs / kill-switches - every pass (15 s) while one is reported, so the tray's warning goes
    # away soon after you stop the other VPN (not up to a minute later)
    if (-not (Test-VeroLockAlive) -and (Get-VeroPendingSwitch -MinAgeSeconds 5)) {
        $want = Read-VeroSwitchRequest
        if ($want -and @($cfg.Profiles | ForEach-Object Profile) -contains $want) {
            Write-VeroLog "switch to '$want' was not picked up by the Switch task - switching now" $Action
            Invoke-VeroSwitch -Name $want -Action $Action
            $cfg = Get-VeroConfig
        }
    }
    if ($script:CheckCount % 4 -eq 1 -or @(Get-VeroConflictList).Count -gt 0) {
        try { Update-VeroConflict -Config $cfg -Action $Action } catch { Write-Verbose "conflict check: $($_.Exception.Message)" }
    }
    if (Test-VeroArmed) {
        Sync-VeroKillSwitch -Config $cfg -Action $Action
        if (-not (Test-VeroVpnConnected $cfg.Profile) -and -not (Test-VeroLockAlive)) { Start-VeroRedial -Config $cfg -Action $Action }
    } elseif (Test-VeroKillSwitchPresent) {
        Write-VeroLog 'disarmed but kill-switch still present - removing' $Action
        Disable-VeroKillSwitch -Action $Action
    }
}
$script:CheckCount = 0

function Invoke-VeroSwitch {
    <# Switch the active VPN profile. While armed the machine stays blocked the whole time: the old tunnel stops being
       allowed before it is hung up, and nothing is allowed out until the new one is up. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Name, [string]$Action = 'switch')
    $old = Get-VeroConfig
    $new = Get-VeroConfig -Active $Name
    if ($old.Profile -eq $new.Profile) {
        Write-VeroLog "profile '$Name' is already active" $Action
        if ((Test-VeroArmed) -and -not (Test-VeroVpnConnected $new.Profile)) { Start-VeroRedial -Config $new -Action $Action }
        return
    }
    Set-VeroActiveProfile -Name $Name -Action $Action                    # first: the old profile's 631 is then ignored
    $notice = Get-VeroSwitchNotice -Type $new.Type -ProfileName $Name
    if ($notice) { Write-VeroLog "NOTICE: $notice" $Action }
    $oldType = Get-VeroConfigType $old
    if (Test-VeroArmed) {
        Sync-VeroKillSwitch -Config $new -Action $Action
        # ALWAYS hang the old tunnel up and wait until it is really gone before dialing the new one: once blocked it can look
        # "not connected" while RAS still holds it (and its routes) - the new dial then fails until RAS gives up on it
        # (e.g. SSTP -> IKEv2: the IKEv2 attempts fail for ~1 minute until RAS logs 829)
        Invoke-VeroHangUp $old.Profile $oldType
        $t = Get-Date
        while ((Test-VeroVpnConnected $old.Profile -Type $oldType) -and ((Get-Date) - $t).TotalSeconds -lt 15) { Start-Sleep -Milliseconds 500 }
        Write-VeroLog "hung up '$($old.Profile)'" $Action
        Start-VeroRedial -Config $new -Action $Action                      # the loop's one owner dials; a switch from the watchdog does not keep the watchdog
    } elseif (Test-VeroVpnConnected $old.Profile -Type $oldType) {
        Invoke-VeroHangUp $old.Profile $oldType
        Write-VeroLog "hung up '$($old.Profile)' (VPN is off - '$Name' is selected for the next turn on)" $Action
    }
}

function Get-VeroPendingSwitch {
    <# The profile the tray asked to switch to, without consuming the request; $null when none (or it is no profile). #>
    [CmdletBinding()] param([double]$MinAgeSeconds = 0)
    Read-VeroUserInput -Path (Get-VeroPath).SwitchRequest -Name 'switch' -Peek -MinAgeSeconds $MinAgeSeconds
}

function Read-VeroSwitchRequest {
    <# The tray (unelevated) asks for a switch by writing a profile name to the user's own folder; only names that exist in
       the admin-owned config.json are honoured. The request is taken once; the file itself stays the tray's to remove
       (Read-VeroUserInput: the elevated guard deletes nothing in the user's folder). #>
    Read-VeroUserInput -Path (Get-VeroPath).SwitchRequest -Name 'switch'
}
