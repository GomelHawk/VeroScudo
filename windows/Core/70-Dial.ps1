# VeroScudo core, part 70: dialing, rejected passwords, Reconnect.
# Dot-sourced by VeroScudo.Core.psm1 into the module's scope, in order - never run on its own.

# ---------------------------------------------------------------- dialing
function Get-VeroCredential {
    [CmdletBinding()] param([Parameter(Mandatory)]$Config)
    $p = Get-VeroPath -VpnProfile $Config.Profile
    foreach ($f in $p.Cred, $p.LegacyCred) {
        if (-not (Test-Path $f)) { continue }
        try { $c = Import-Clixml $f } catch { continue }
        if ($f -eq $p.Cred -or $c.UserName -eq $Config.Username) { return $c }    # the 1.0 single credential, if it is for this user
    }
    $null
}
function Get-VeroKeyPassphrase {
    <# OpenVPN: the private-key passphrase, stored like the password (DPAPI, this Windows account only). #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ProfileName)
    $f = (Get-VeroPath -VpnProfile $ProfileName).KeyPass
    if (Test-Path $f) { try { return (Import-Clixml $f) } catch { Write-Verbose 'key passphrase unreadable' } }
    $null
}

$script:EventSettleSeconds = 3              # on-event waits this long before reading the termination records (tests: 0)
$script:RasAuthCodes = @(691)              # "the user name and password combination is not recognized"
# SSTP could not check the server certificate's revocation (CRL/OCSP offline): CRYPT_E_REVOCATION_OFFLINE / _NO_REVOCATION_CHECK
# + WSAEACCES (0x8007271D): seen live 2026-11-03 - with no TCP 80 permit, SSTP's revocation fetch is refused by the filters
# and RasDial returns "access forbidden" instead of a revocation code
$script:RasRevocationCodes = @(-2146885613, -2146885614, 0x80092013, 0x80092012, -2147014883, 10013)
function Open-VeroCrlWindow {
    <# Allow svchost TCP 80 for 2 minutes so SSTP can fetch the CRL: after a dial failed on the revocation check, and right
       after an SSTP tunnel came up (it may still be checking when the filters arrive - seen live: RAS 829 ~5 s after arm). #>
    [CmdletBinding()] param([string]$Action = 'core', [string]$Reason = 'SSTP could not check the server certificate revocation')
    @{ Until = (Get-Date).AddMinutes(2).ToString('o') } | ConvertTo-Json | Set-Content (Get-VeroPath).CrlWindow
    Write-VeroLog "$Reason - HTTP (TCP 80) from Windows services allowed for 2 minutes so it can" $Action
}
function Test-VeroCrlWindow {
    $f = (Get-VeroPath).CrlWindow
    if (-not (Test-Path $f)) { return $false }
    try { return ((Get-Date) -lt [datetime]::Parse([string](Get-Content $f -Raw | ConvertFrom-Json).Until, $null, [Globalization.DateTimeStyles]::RoundtripKind)) } catch { return $false }
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
    if ($script:RasRevocationCodes -contains [int64]$code -and -not (Test-VeroCrlWindow)) {
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
    Set-Content -Path $p.AuthFail -Value ("{0} {1:o} {2}" -f $Which, (Get-Date), $Reason) -Encoding UTF8
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
    $m | ConvertTo-Json | Set-Content $p.Renew
}
function Test-VeroRenewHangUp {
    <# Pure rule: is a termination record at $EventTime our own hang-up for Reconnect? Only for that profile, only between the
       marker's start and 30 s after the hang-up finished, and never for a marker older than 5 minutes. #>
    [CmdletBinding()] param($Marker, [string]$ProfileName, [datetime]$EventTime, [datetime]$Now = (Get-Date))
    if (-not $Marker -or [string]$Marker.Profile -ne $ProfileName) { return $false }
    $start = [datetime]::Parse([string]$Marker.Start, $null, [Globalization.DateTimeStyles]::RoundtripKind)
    if (($Now - $start).TotalMinutes -gt 5) { return $false }
    $end = if ([string]$Marker.HungUp) { [datetime]::Parse([string]$Marker.HungUp, $null, [Globalization.DateTimeStyles]::RoundtripKind).AddSeconds(30) } else { $Now }
    ($EventTime -ge $start.AddSeconds(-1) -and $EventTime -le $end)
}
function Get-VeroRenewMarker {
    $p = Get-VeroPath
    if (Test-Path $p.Renew) { try { return (Get-Content $p.Renew -Raw | ConvertFrom-Json) } catch { Write-Verbose 'renew marker unreadable' } }
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

function Invoke-VeroReconnect {
    <# Blocked + redial forever, until the tunnel is up or the user turns the VPN off. Follows a profile switch: the
       config (and so the active profile) is re-read on every attempt.
       -Renew (the user's Reconnect): first block - the kill-switch is applied without the tunnel while it is still up -,
       then hang up, then the normal loop; traffic flows again only once the new tunnel is up. All of it under the
       reconnect lock, so the watchdog never reads our own hang-up as a failure or as the user turning the VPN off. #>
    [CmdletBinding()] param([Parameter(Mandatory)]$Config, [string]$Action = 'core', [switch]$Renew)
    if (-not (Enter-VeroLock)) { Write-VeroLog $(if ($Renew) { 'reconnect requested, but a reconnect is already running - it continues' } else { 'reconnect loop already running' }) $Action; return }
    $p = Get-VeroPath
    $attempt = 0
    $pausedLogged = $false
    $switchTo = $null
    try {
        if ($Renew) {
            $type = Get-VeroConfigType $Config
            Write-VeroLog "RECONNECT requested by you: traffic blocked, hanging up '$($Config.Profile)' ($(Get-VeroTypeLabel $type)), redialing" $Action
            Set-VeroRenewMarker -ProfileName $Config.Profile
            Sync-VeroKillSwitch -Config $Config -Action $Action -ForceDown -Force
            Invoke-VeroHangUp -ProfileName $Config.Profile -Type $type
            $t = Get-Date
            while ((Test-VeroVpnConnected $Config.Profile -Type $type) -and ((Get-Date) - $t).TotalSeconds -lt 15) { Start-Sleep -Milliseconds 500 }
            Set-VeroRenewMarker -ProfileName $Config.Profile -HungUp
            if (Test-VeroVpnConnected $Config.Profile -Type $type) { Write-VeroLog "WARNING: '$($Config.Profile)' did not hang up within 15 s - keeping it" $Action }
        }
        while ((Test-VeroArmed) -and -not (Test-VeroVpnConnected $Config.Profile)) {
            # you picked another profile while this one is being redialed: yours wins (seen live: the tray's switch to WireGuard
            # was dropped because this loop kept the Switch task busy redialing OpenVPN)
            if (Get-VeroPendingSwitch) {
                $want = Read-VeroSwitchRequest                                   # taken by this loop (the Switch task may take it first: then it switches)
                if ($want -and $want -ne $Config.Profile -and @((Get-VeroConfig).Profiles | ForEach-Object Profile) -contains $want) {
                    Write-VeroLog "you chose '$want' while '$($Config.Profile)' was being redialed - switching to it" $Action
                    $switchTo = $want; break
                }
            }
            $attempt++
            Sync-VeroKillSwitch -Config $Config -Action $Action
            if (Test-VeroAuthBlocked $Config.Profile) {
                if (-not $pausedLogged) { Write-VeroLog "redial paused: the password for '$($Config.Profile)' was rejected - store the right one (tray Settings); still blocked" $Action; $pausedLogged = $true }
                Start-Sleep -Seconds $Config.RetrySeconds
                $Config = Get-VeroConfig
                continue
            }
            Invoke-VeroDial -Config $Config -Action $Action
            if (Test-VeroVpnConnected $Config.Profile) {
                if ((Get-VeroConfigType $Config) -eq 'hiddify') { Write-VeroLog "Hiddify connected again - traffic goes through it" $Action }   # nothing was dialed
                else { Write-VeroLog "reconnected '$($Config.Profile)' after $attempt attempt(s)" $Action }
                if ((Get-VeroConfigType $Config) -eq 'ras') { Save-VeroRasCoId -ProfileName $Config.Profile }   # its "you hung up" must match it
                break
            }
            # Hiddify: nothing is dialed - VeroScudo waits for you to connect it there; once, then every ~5 minutes
            if ((Get-VeroConfigType $Config) -ne 'hiddify' -or $attempt -eq 1 -or $attempt % 30 -eq 0) { Write-VeroLog "attempt $attempt failed ($(Get-VeroDialFailure $Config))" $Action }
            # the server may have moved: look it up again (the redial's DNS permit is in force while down) and let the new
            # address through before the next attempt - the cache alone would refuse it forever
            if (@($Config.ServerIps).Count -eq 0 -and (Get-VeroConfigType $Config) -eq 'ras') {
                $cached = @(Resolve-VeroServerIp -Config $Config -CacheOnly)
                $fresh = @(Resolve-VeroServerIp -Config $Config)
                if (($fresh -join ',') -ne ($cached -join ',')) {
                    Write-VeroLog ("server '{0}' now resolves to {1} - allowed for the next attempt" -f $Config.Server, ($fresh -join ',')) $Action
                    Sync-VeroKillSwitch -Config $Config -Action $Action
                }
            }
            Start-Sleep -Seconds $Config.RetrySeconds
            $Config = Get-VeroConfig
        }
        if (-not (Test-VeroArmed)) { Write-VeroLog 'disarmed during reconnect - stopping' $Action }
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
    try { if (Update-VeroRasWatch -Config $cfg -Action $Action) { $cfg = Get-VeroConfig } } catch { Write-VeroLog "ERROR: Windows VPN watch: $($_.Exception.Message)" $Action }
    if (@($cfg.Profiles | Where-Object Type -eq 'hiddify').Count -gt 0) {
        try { if (Update-VeroHiddifyWatch -Config $cfg -Action $Action) { $cfg = Get-VeroConfig } } catch { Write-VeroLog "ERROR: Hiddify watch: $($_.Exception.Message)" $Action }
    }
    if (@($cfg.Profiles | Where-Object Type -eq 'wireguard').Count -gt 0) {
        try { if (Update-VeroWgWatch -Config $cfg -Action $Action) { $cfg = Get-VeroConfig } } catch { Write-VeroLog "ERROR: WireGuard watch: $($_.Exception.Message)" $Action }
    }
    # about once a minute: other VPNs / kill-switches - every pass (15 s) while one is reported, so the tray's warning goes
    # away soon after you stop the other VPN (seen live: it stayed up to a minute after WireGuard was turned off)
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
        if (-not (Test-VeroVpnConnected $cfg.Profile) -and -not (Test-VeroLockAlive)) { Invoke-VeroReconnect -Config $cfg -Action $Action }
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
        if ((Test-VeroArmed) -and -not (Test-VeroVpnConnected $new.Profile)) { Invoke-VeroReconnect -Config $new -Action $Action }
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
        # (seen live 2026-11-03: CorporateVPN -> PrivateVPN, IKEv2 attempts failed for ~1 minute until RAS logged 829)
        Invoke-VeroHangUp $old.Profile $oldType
        $t = Get-Date
        while ((Test-VeroVpnConnected $old.Profile -Type $oldType) -and ((Get-Date) - $t).TotalSeconds -lt 15) { Start-Sleep -Milliseconds 500 }
        Write-VeroLog "hung up '$($old.Profile)'" $Action
        Invoke-VeroReconnect -Config $new -Action $Action
    } elseif (Test-VeroVpnConnected $old.Profile -Type $oldType) {
        Invoke-VeroHangUp $old.Profile $oldType
        Write-VeroLog "hung up '$($old.Profile)' (VPN is off - '$Name' is selected for the next turn on)" $Action
    }
}

function Get-VeroPendingSwitch {
    <# The profile the tray asked to switch to, without consuming the request; $null when none (or it is no profile). #>
    [CmdletBinding()] param([double]$MinAgeSeconds = 0)
    $f = (Get-VeroPath).SwitchRequest
    if (-not (Test-Path $f)) { return $null }
    if ($MinAgeSeconds -gt 0 -and ((Get-Date) - (Get-Item $f).LastWriteTime).TotalSeconds -lt $MinAgeSeconds) { return $null }
    $n = (Get-Content $f -Raw -ErrorAction SilentlyContinue)
    if ($n) { $n.Trim() } else { $null }
}

function Read-VeroSwitchRequest {
    <# The tray (unelevated) asks for a switch by writing a profile name to the user's own folder; only names that exist in
       the admin-owned config.json are honoured. #>
    $p = Get-VeroPath
    if (-not (Test-Path $p.SwitchRequest)) { return $null }
    $name = (Get-Content $p.SwitchRequest -Raw -ErrorAction SilentlyContinue)
    Remove-Item $p.SwitchRequest -Force -ErrorAction SilentlyContinue
    if ($name) { $name.Trim() } else { $null }
}
