#Requires -Version 5.1
<#
  VeroScudo tray - the part that decides, without a window. VeroScudoTray.ps1 (WinForms) collects the facts, calls these
  functions and draws the result; everything here takes explicit inputs and is unit-tested (tests/VeroScudo.Tray.Tests.ps1).
  Needs VeroScudo.Core in the session (Get-VeroTypeLabel, Test-VeroNewerVersion).
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-VeroTrayState($f) {
    <# The tray's state, title and text from what the guard reports (Get-StateFacts in the tray). Pure. #>
    if (-not $f.Configured) { return [pscustomobject]@{ State = 'attention'; Title = 'Not configured'; Text = 'Run Install.ps1 to create config.json.'; Armed = $false; Connected = $false } }
    $name = $f.Name; $why = $null; $head = 'Attention'
    $conf = @($f.Conflicts | Where-Object { $_ })
    if ($f.NativeNext) { $head = 'Helper blocked'; $why = "Windows blocked VeroScudo's helper (Smart App Control). The kill-switch stays on, but self-repair and automatic redial are paused - next try at $($f.NativeNext)." }
    elseif ($f.ContainsKey('GuardStale') -and $f.GuardStale) { $head = 'Guard not running'; $why = "VeroScudo's watchdog has not run for $($f.GuardStale) min, so nothing watches the VPN or redials it. It normally restarts within a minute; if this stays, run Install.ps1 again." }
    elseif (-not $f.Cred) { $head = 'Password missing'; $why = "No password stored for '$name', so VeroScudo cannot redial it by itself. Add it in Settings: select the profile, Set password..." }
    elseif ($f.AuthBlocked) { $head = 'Password rejected'; $why = "The VPN server rejected the password for '$name'. Store the right one in Settings, then Reconnect - traffic stays blocked meanwhile." }
    elseif ($f.Otp) { $head = 'Code needed'; $why = "'$name' asks for a one-time code: $($f.Otp)" }
    elseif ($f.Armed -and $f.Up -and $conf.Count -gt 0) {
        $head = 'Protected'                                               # you ARE protected - the note is about something else
        $why = "Note: $($conf[0])$(if ($conf.Count -gt 1) { " (+$($conf.Count - 1) more - Copy report lists them)" })."
    }
    $state = if ($why) { 'attention' } elseif (-not $f.Armed) { 'off' } elseif ($f.Up) { 'protected' } else { 'blocked' }
    $title, $text = switch ($state) {
        'protected' { 'Protected', "$name ($(Get-VeroTypeLabel $f.Type)) is connected and the kill-switch is on." }
        'blocked'   {
            switch ([string]$f.Expect) {
                'connect'   { 'Connecting', "Kill-switch on: traffic is blocked until $name is connected." }
                'switch'    { 'Switching', "Switching to $name. Traffic stays blocked until it is connected." }
                'reconnect' { 'Reconnecting', "Reconnecting $name. Traffic stays blocked until the tunnel is back." }
                default     { 'Blocked - reconnecting', "$name is not connected. Nothing leaves this PC until it is back." }
            }
        }
        'off'       { 'Off', 'The VPN is turned off: normal network, not protected.' }
        default     { $head, $why }
    }
    [pscustomobject]@{ State = $state; Title = $title; Text = $text; Armed = [bool]$f.Armed; Connected = [bool]$f.Up; Expected = ($state -eq 'blocked' -and [bool]$f.Expect) }
}

function ConvertTo-VeroExitView {
    <# What the location line shows. $Info: the last lookup (@{ Ip; Country; City; Org; Source; Time; Profile }) or $null.
       Fresh = looked up through the tunnel that is up now (protected, same profile, after it came up); otherwise grey, with
       its time. -Checking: a lookup runs; $Failure: why the last one failed; -Preview: screenshots (always fresh). Pure. #>
    [CmdletBinding()] param($Info, [string]$State, [string]$ProfileName, [datetime]$ProtectedSince = [datetime]::MinValue, [switch]$Checking,
                            [string]$Failure = '', [switch]$Preview)
    $c = $Info
    if (-not $c -or -not $c.Ip) {
        $msg = if ($Checking) { 'Checking where your traffic leaves...' } elseif ($Failure) { "Location not available - $Failure" } else { 'Location: shown once the VPN is connected' }
        return @{ Has = $false; Text = $msg; Fresh = $false }
    }
    $t = try { [datetime]::Parse([string]$c.Time, $null, [Globalization.DateTimeStyles]::RoundtripKind) } catch { [datetime]::MinValue }
    $fresh = $State -eq 'protected' -and $ProfileName -and [string]$c.Profile -eq $ProfileName -and ($Preview -or $t -ge $ProtectedSince)
    $country = try { (New-Object System.Globalization.RegionInfo([string]$c.Country)).EnglishName } catch { [string]$c.Country }
    $right = if ($Checking) { 'checking...' } elseif ($fresh) { [string]$c.Ip } else { '{0} - {1:HH:mm}' -f $c.Ip, $t }
    @{ Has = $true; Code = ([string]$c.Country).ToUpper(); Place = ((@($country, [string]$c.City) | Where-Object { $_ }) -join ' / '); Right = $right; Fresh = $fresh
       Tip = (('{0}  {1}' -f $c.Ip, $c.Org) + "`r`n" + ('from {0}, {1:yyyy-MM-dd HH:mm}, profile {2}' -f $c.Source, $t, $c.Profile)) }
}

function ConvertTo-VeroConnectionView {
    <# The status window's CONNECTION card, the tooltip and the menu header. $St: ConvertTo-VeroTrayState's result; $Check: the
       config's ConnectionCheck; $Quality: Read-VeroQuality's result or $null; $Expect: what the user waits on.
       Text: the quality while protected, else what the guard does about the connection (the two never matter at once).
       Tone: good | warn | bad | normal. Word: Good | Unstable | Bad while protected and rated, else $null. Pure
       (the same texts as connection_text / quality_word in linux/veroscudo/traymodel.py). #>
    [CmdletBinding()] param($St, $Check, $Quality, [string]$Expect)
    $enabled = [bool]($Check -and $Check.Enabled)
    $text = '-'; $tone = 'normal'; $word = $null; $tip = ''
    if (-not $St -or ($St.State -eq 'attention' -and -not $St.Armed)) { $text = '-' }
    elseif ($St.State -eq 'blocked' -or ($St.Armed -and -not $St.Connected)) {
        $text = switch ($Expect) { 'connect' { 'connecting' } 'switch' { 'switching' } 'reconnect' { 'reconnecting' } default { 'redialing' } }
        $tone = 'warn'
    }
    elseif (-not $St.Armed) { $text = if ($St.Connected) { 'connected (VPN off)' } else { '-' } }
    elseif (-not $enabled) { $text = 'connected (check off)' }
    else {
        $text = Format-VeroQuality $Quality
        if ($Quality -and $Quality.State -ne 'checking') {
            $tone = switch ($Quality.State) { 'good' { 'good' } 'unstable' { 'warn' } default { 'bad' } }
            if ($St.State -eq 'protected') { $q = [string]$Quality.State; $word = $q.Substring(0, 1).ToUpperInvariant() + $q.Substring(1) }
            $tip = '{0} checks in the last {1} min: {2} lost ({3}%){4}' -f $Quality.Checks, $Check.WindowMinutes, $Quality.Lost,
                ([double]$Quality.LossPct).ToString('0.#', [Globalization.CultureInfo]::InvariantCulture),
                $(if ($null -ne $Quality.RttMs) { ", median $($Quality.RttMs) ms" } else { '' })
        }
        $addr = @($Check.Targets | ForEach-Object { if ($_.Method -eq 'ping') { "$($_.Host) (ping)" } else { "$($_.Host):$($_.Port)" } }) -join ', '
        $tip = (@($tip, "Every $($Check.IntervalSeconds) s: $addr") | Where-Object { $_ }) -join "`r`n"
    }
    [pscustomobject]@{ Text = $text; Tone = $tone; Word = $word; Tip = $tip }
}

function Get-VeroTrayTip {
    <# 'VeroScudo - Protected, connection good' (63 characters at most: the notification area's limit). Pure. #>
    [CmdletBinding()] param([string]$Title, [string]$Word, [switch]$Awake)
    $t = "VeroScudo - $Title$(if ($Word) { ", connection $($Word.ToLowerInvariant())" })$(if ($Awake) { ', keeping PC awake' })"
    $t.Substring(0, [Math]::Min(63, $t.Length))
}

function Test-VeroTrayFileChanged {
    <# True once per new write of a state file (the guard writes them; the tray only reads). $Stamps remembers the last
       write time per path between calls; the first sight of a file is not a change. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][hashtable]$Stamps)
    $t = if (Test-Path -LiteralPath $Path) { (Get-Item -LiteralPath $Path).LastWriteTimeUtc.Ticks } else { 0 }
    $first = -not $Stamps.ContainsKey($Path)
    $changed = (-not $first) -and $t -ne 0 -and $Stamps[$Path] -ne $t
    $Stamps[$Path] = $t
    $changed
}

function Get-VeroTrayPref {
    <# The per-user tray choices (tray.json) with defaults for whatever is missing or unreadable. #>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    $o = @{ keepAwake = $false; lastProfile = ''; eventsClearedAt = ''; showExit = $true; exitInfo = $null }
    try { if (Test-Path -LiteralPath $Path) { $j = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json; foreach ($k in @($o.Keys)) { if ($j.PSObject.Properties[$k]) { $o[$k] = $j.$k } } } } catch { Write-Verbose 'tray.json unreadable' }
    $o
}
function Set-VeroTrayPref {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Key, $Value)
    $o = Get-VeroTrayPref -Path $Path; $o[$Key] = $Value
    try { New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null; $o | ConvertTo-Json | Set-Content -LiteralPath $Path -Encoding UTF8 } catch { Write-Verbose 'tray.json not writable' }
}

function Resolve-VeroUpdateNotice {
    <# The update check's decision: a newer release -> it is the update and the menu says so; the balloon is shown once per
       tag (Info.notified remembers it). Info = @{ checked; notified } as update.json holds it; returned updated. Pure. #>
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Info, $Release)
    $Info.checked = (Get-Date).ToString('o')
    if ($Release -and (Test-VeroNewerVersion -Tag $Release.Tag)) {
        $balloon = $Info.notified -ne $Release.Tag
        if ($balloon) { $Info.notified = $Release.Tag }
        return @{ Update = $Release; MenuText = "Update available: $($Release.Tag)"; Balloon = $balloon; Info = $Info }
    }
    @{ Update = $null; MenuText = 'Check for updates'; Balloon = $false; Info = $Info }
}

function Test-VeroUacCancelled {
    <# True when this exception (or one it wraps) is Windows' ERROR_CANCELLED (1223): No was pressed on the UAC prompt.
       By the code, never by the text - that is in the system's language. Pure. #>
    [CmdletBinding()] param($Exception)
    $e = $Exception
    while ($e) {
        if ($e -is [System.ComponentModel.Win32Exception] -and $e.NativeErrorCode -eq 1223) { return $true }
        $e = $e.InnerException
    }
    $false
}

Export-ModuleMember -Function ConvertTo-VeroConnectionView, Get-VeroTrayTip, ConvertTo-VeroTrayState, ConvertTo-VeroExitView, Test-VeroTrayFileChanged, Get-VeroTrayPref, Set-VeroTrayPref, Resolve-VeroUpdateNotice, Test-VeroUacCancelled
