#Requires -Version 5.1
<#
  VeroScudo tray app (Windows). Read-only view of the guard's state; every action runs the same scheduled
  task the Desktop shortcuts use, so the guard logic stays in VeroScudo.Core.psm1.
  Started hidden by the \VeroScudo\Tray task at sign-in (run.vbs tray), or manually:
    powershell -ExecutionPolicy Bypass -File VeroScudoTray.ps1 [-Preview <folder>]   # -Preview: screenshots the windows and exits
    # -PreviewOnly 'menu,editor-*' (with -Preview): only the shots with these names - quicker when checking one window
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'PreviewOnly', Justification = 'used inside nested function')]
param([int]$PollSeconds = 3, [string]$Preview, [string]$PreviewOnly, [ValidateSet('auto', 'dark', 'light')][string]$ForceTheme = 'auto')

# one tray per sign-in session: a second start (logon task, installer, by hand) exits quietly
if (-not $Preview) {
    $created = $false
    $global:TrayMutex = New-Object System.Threading.Mutex($true, 'Local\VeroScudoTray', [ref]$created)
    if (-not $created) { exit 0 }
}

# ---------------------------------------------------------------- native helpers (DPI, dark title bars, menu renderer, themed message box)
# C# in VeroScudo.Tray.cs, compiled in memory here like the core's native helper; tests/VeroScudo.Tray.Tests.ps1 compiles it too,
# so a broken helper fails the unit suite instead of the tray at sign-in.
Add-Type -ReferencedAssemblies System.Windows.Forms, System.Drawing -TypeDefinition (Get-Content (Join-Path $PSScriptRoot 'VeroScudo.Tray.cs') -Raw)
[VeroNative]::EnableDpi()
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
Import-Module (Join-Path $PSScriptRoot 'VeroScudo.Core.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'VeroScudo.Tray.psm1') -Force      # the tray's decisions (what to show), unit-tested; this file only draws

# ---------------------------------------------------------------- state
$global:Paths   = Get-VeroPath
$global:Config  = $null
try { $global:Config = Get-VeroConfig } catch { Write-Verbose "no config yet: $($_.Exception.Message)" }
$global:IconDir = @((Join-Path $PSScriptRoot 'icons'), (Join-Path (Split-Path $PSScriptRoot -Parent) 'assets\icons')) | Where-Object { Test-Path $_ } | Select-Object -First 1   # installed layout, then repo layout
if (-not $global:IconDir) { $global:IconDir = Join-Path $PSScriptRoot 'icons' }
$global:Folder  = '\VeroScudo\'
$global:Last    = $null
$global:Icons   = @{}
$global:Images  = @{}
$global:Update  = $null
$global:UpdateFile = $global:Paths.UpdateFile                         # per user: the state folder is read-only for the tray
$global:ConfigStamp = ''
function Update-ConfigCache {
    <# Re-reads config.json when it or the active-profile selection (written by the guard on a switch) changed. #>
    $stamp = (@($global:Paths.Config, $global:Paths.ActiveProfile) | ForEach-Object { if (Test-Path $_) { (Get-Item $_).LastWriteTimeUtc.Ticks } else { 0 } }) -join '/'
    if ($stamp -eq $global:ConfigStamp) { return $false }
    $global:ConfigStamp = $stamp
    try { $global:Config = Get-VeroConfig } catch { Write-Verbose "config: $($_.Exception.Message)" }
    $true
}
$global:Dark    = $true
try { $global:Dark = ((Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -ErrorAction Stop).AppsUseLightTheme -ne 1) } catch { Write-Verbose 'theme key missing' }
$global:TaskbarDark = $true
try { $global:TaskbarDark = ((Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize' -ErrorAction Stop).SystemUsesLightTheme -ne 1) } catch { Write-Verbose 'theme key missing' }
if ($ForceTheme -ne 'auto') { $global:Dark = ($ForceTheme -eq 'dark'); $global:TaskbarDark = $global:Dark }
$global:Theme = if ($global:Dark) { [VeroTheme]::Dark() } else { [VeroTheme]::Light() }
# warnings: the bright amber is unreadable on a white window - a darker one there
$global:Amber = if ($global:Dark) { [System.Drawing.Color]::FromArgb(252,187,45) } else { [System.Drawing.Color]::FromArgb(157,93,0) }
$global:Scale = [System.Drawing.Graphics]::FromHwnd([IntPtr]::Zero).DpiX / 96
function P([double]$x, [double]$y) { New-Object System.Drawing.Point([int]($x * $global:Scale), [int]($y * $global:Scale)) }
function Z([double]$w, [double]$h) { New-Object System.Drawing.Size([int]($w * $global:Scale), [int]($h * $global:Scale)) }
function Pad([double]$l, [double]$t, [double]$r, [double]$b) { New-Object System.Windows.Forms.Padding([int]($l * $global:Scale), [int]($t * $global:Scale), [int]($r * $global:Scale), [int]($b * $global:Scale)) }
$FontUI   = New-Object System.Drawing.Font('Segoe UI', 10)
$FontBold = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$FontBig  = New-Object System.Drawing.Font('Segoe UI Semibold', 15)
$FontSmall= New-Object System.Drawing.Font('Segoe UI', 8.5)
$FontMono = New-Object System.Drawing.Font('Cascadia Mono', 9)
if ($FontMono.Name -ne 'Cascadia Mono') { $FontMono = New-Object System.Drawing.Font('Consolas', 9) }

# every message goes through Show-Message (VeroScudo's own themed window, see below): the Windows message box ignores the dark
# theme and cannot be captured by -Preview. [VeroMsg]::Show (VeroScudo.Tray.cs) keeps the MessageBox call shape: (text, title, buttons, icon).
$global:PreviewDir = $null; $global:PreviewSuffix = ''; $global:ShotName = $null
function Measure-TextHeight([string]$text, $font, [int]$widthPx) {
    $flags = [System.Windows.Forms.TextFormatFlags]::WordBreak -bor [System.Windows.Forms.TextFormatFlags]::TextBoxControl
    [System.Windows.Forms.TextRenderer]::MeasureText($text, $font, (New-Object System.Drawing.Size($widthPx, 100000)), $flags).Height
}
function Get-Logical([int]$px) { [int][Math]::Ceiling($px / $global:Scale) }
function Save-FormShot($fm, [string]$name) {
    <# -Preview: the window renders itself into a PNG (not a screen copy: a window started from WSL or a task may not come to
       the front). Closed afterwards; a second shot of the same name gets -2, -3... #>
    $fm.StartPosition = 'Manual'; $fm.Location = New-Object System.Drawing.Point(40, 40); $fm.TopMost = $true
    if (-not $fm.Visible) { $fm.Show() }
    foreach ($k in 1..5) { [System.Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 200 }
    $stack = New-Object System.Collections.Stack; $stack.Push($fm)
    while ($stack.Count) { $c = $stack.Pop(); foreach ($x in $c.Controls) { $stack.Push($x) }; if ($c -is [System.Windows.Forms.TextBox] -and $c.Multiline) { $c.SelectionStart = $c.TextLength; $c.ScrollToCaret() } }
    [System.Windows.Forms.Application]::DoEvents()
    $file = Join-Path $global:PreviewDir ($name + $global:PreviewSuffix + '.png'); $n = 2
    while (Test-Path $file) { $file = Join-Path $global:PreviewDir ('{0}-{1}{2}.png' -f $name, $n, $global:PreviewSuffix); $n++ }
    $bmp = New-Object System.Drawing.Bitmap($fm.Width, $fm.Height)
    $fm.DrawToBitmap($bmp, (New-Object System.Drawing.Rectangle(0, 0, $fm.Width, $fm.Height))); $bmp.Save($file); $bmp.Dispose()
    $fm.Close()
}
function Show-Modal($form, [string]$shot) {
    <# Every dialog is shown through here: modal normally; with -Preview it is captured instead and answers "cancel". #>
    if ($global:PreviewDir) { Save-FormShot $form $shot; return }
    $form.ShowDialog() | Out-Null
}

# a missing asset means a broken install: say so in the log instead of silently showing a substitute
function Write-MissingAsset([string]$path) { try { Write-VeroLog "WARNING: missing $path - showing a fallback; reinstall to fix" 'tray' } catch { Write-Verbose 'log not writable' } }
function Get-StateIcon([string]$state, [switch]$Awake) {
    $variant = if ($global:TaskbarDark) { 'png' } else { 'badge' }
    $key = "$variant/$state"
    if (-not $global:Icons.ContainsKey($key)) {
        $ico = Join-Path $global:IconDir "$variant\$state.ico"
        $global:Icons[$key] = if (Test-Path $ico) { New-Object System.Drawing.Icon($ico) } else { Write-MissingAsset $ico; [System.Drawing.SystemIcons]::Shield }
    }
    if (-not $Awake) { return $global:Icons[$key] }
    if (-not $global:Icons.ContainsKey("$key/awake")) {
        $global:Icons["$key/awake"] = try { [VeroTrayIcon]::WithAwakeBadge((Join-Path $global:IconDir $variant), $state) } catch { try { Write-VeroLog "WARNING: keep-awake badge not drawn: $($_.Exception.Message)" 'tray' } catch { Write-Verbose 'log not writable' }; $global:Icons[$key] }
    }
    $global:Icons["$key/awake"]
}
function Get-AppIcon {
    if (-not $global:Icons.ContainsKey('app')) {
        $ico = Join-Path $global:IconDir 'app\app.ico'
        $global:Icons['app'] = if (Test-Path $ico) { New-Object System.Drawing.Icon($ico) } else { Write-MissingAsset $ico; Get-StateIcon 'protected' }
    }
    $global:Icons['app']
}
function Get-AppImage([int]$size) {
    $key = "app/$size"
    if (-not $global:Images.ContainsKey($key)) {
        $png = Join-Path $global:IconDir "app\app-$size.png"
        $global:Images[$key] = if (Test-Path $png) { [System.Drawing.Image]::FromFile($png) } else { Write-MissingAsset $png; Get-StateImage 'protected' $size }
    }
    $global:Images[$key]
}
function Get-StateImage([string]$state, [int]$size) {
    $key = "$state/$size"
    if (-not $global:Images.ContainsKey($key)) {
        $png = Join-Path $global:IconDir "png\$state-$size.png"
        $global:Images[$key] = if (Test-Path $png) { [System.Drawing.Image]::FromFile($png) } else { Write-MissingAsset $png; $null }
    }
    $global:Images[$key]
}
# ---------------------------------------------------------------- exit location (where your traffic leaves the tunnel)
# Asked only right after VeroScudo reaches Protected (connect, reconnect, switch) or when you click Refresh - so the request
# goes through the tunnel and never shows your real address. ipinfo.io first (city, country, IP, provider), Cloudflare's
# trace page as the fallback (IP and country only). In a background runspace: the window never waits for the network.
# Cached per user (tray.json); shown grey with its time while not protected. Off: Settings > "Show exit location".
$global:ExitJob = $null; $global:ExitError = ''; $global:ProtectedSince = [datetime]::MinValue; $global:PreviewExit = $null
function Test-ExitEnabled { [bool](Get-TrayPref).showExit }
function Start-ExitFetch {
    if (-not (Test-ExitEnabled) -or $global:ExitJob -or $global:PreviewDir -or -not $global:Config) { return }
    $ps = [powershell]::Create()
    [void]$ps.AddScript({
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $e1 = ''; $e2 = ''
        try {
            # bytes decoded as UTF-8 here: Windows PowerShell reads an answer without a charset as Latin-1 (a Polish city name comes out garbled)
            $w = Invoke-WebRequest -Uri 'https://ipinfo.io/json' -TimeoutSec 6 -UseBasicParsing -Headers @{ Accept = 'application/json' }
            $r = [Text.Encoding]::UTF8.GetString($w.RawContentStream.ToArray()) | ConvertFrom-Json
            if ($r.ip) { return @{ Ip = [string]$r.ip; City = [string]$r.city; Country = [string]$r.country; Org = [string]$r.org; Source = 'ipinfo.io' } }
        } catch { $e1 = $_.Exception.Message }
        try {
            $kv = @{}
            foreach ($l in ((Invoke-WebRequest -Uri 'https://www.cloudflare.com/cdn-cgi/trace' -TimeoutSec 6 -UseBasicParsing).Content -split "`n")) { $k, $v = $l -split '=', 2; if ($v) { $kv[$k.Trim()] = $v.Trim() } }
            if ($kv['ip']) { return @{ Ip = [string]$kv['ip']; City = ''; Country = [string]$kv['loc']; Org = ''; Source = 'cloudflare.com' } }
        } catch { $e2 = $_.Exception.Message }
        @{ Error = "ipinfo.io: $e1 / cloudflare.com: $e2" }
    })
    $global:ExitError = ''
    $global:ExitJob = @{ PS = $ps; Handle = $ps.BeginInvoke(); Profile = $global:Config.Profile; Started = (Get-Date) }
}
function Update-ExitFetch {
    <# Called by the 3-second timer: collects a finished lookup (or gives up after 20 s). #>
    $j = $global:ExitJob; if (-not $j) { return }
    if ($j.Handle.IsCompleted) {
        $out = $null
        try { $out = @($j.PS.EndInvoke($j.Handle)) | Select-Object -Last 1 } catch { $global:ExitError = $_.Exception.Message }
        $j.PS.Dispose(); $global:ExitJob = $null
        if ($out -and $out.Ip) {
            Set-TrayPref 'exitInfo' ([ordered]@{ Ip = $out.Ip; City = $out.City; Country = $out.Country; Org = $out.Org; Source = $out.Source; Profile = $j.Profile; Time = (Get-Date).ToString('o') })
        } elseif ($out -and $out.Error) { $global:ExitError = [string]$out.Error }
    } elseif (((Get-Date) - $j.Started).TotalSeconds -gt 20) {
        try { $j.PS.Stop() } catch { Write-Verbose 'lookup stop failed' }
        $j.PS.Dispose(); $global:ExitJob = $null; $global:ExitError = 'no answer within 20 s'
    }
}

# ---------------------------------------------------------------- service status page (opt-in, per user)
# An Atlassian Statuspage (.../api/v2/status.json, Anthropic's by default): fetched in the background by the same rules as
# the exit location - once after each connect (Protected) and on Refresh, 6 s timeout. Tells a service's own outage from your connection (Claude Code hanging: their problem or yours?).
$global:SvcJob = $null; $global:SvcResult = $null; $global:SvcNext = [datetime]::MinValue
$global:SvcDefaultUrl = 'https://status.anthropic.com/api/v2/status.json'
function Test-StatusPageEnabled { [bool](Get-TrayPref).statusPage }
function Get-StatusPageUrl { $u = [string](Get-TrayPref).statusPageUrl; if ($u) { $u } else { $global:SvcDefaultUrl } }
function Start-StatusPageFetch([switch]$Now) {
    if (-not (Test-StatusPageEnabled) -or $global:SvcJob -or $global:PreviewDir) { return }
    if (-not $Now -and (Get-Date) -lt $global:SvcNext) { return }
    $global:SvcNext = (Get-Date).AddMinutes(5)
    $url = Get-StatusPageUrl
    $ps = [powershell]::Create()
    [void]$ps.AddScript({ param($u)
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        try { $w = Invoke-WebRequest -Uri $u -TimeoutSec 6 -UseBasicParsing -Headers @{ Accept = 'application/json' }
              @{ Json = ([Text.Encoding]::UTF8.GetString($w.RawContentStream.ToArray())) } }
        catch { @{ Error = $_.Exception.Message } }
    }).AddArgument($url)
    $global:SvcJob = @{ PS = $ps; Handle = $ps.BeginInvoke(); Url = $url; Started = (Get-Date) }
}
function Update-StatusPageFetch {
    $j = $global:SvcJob; if (-not $j) { return }
    if ($j.Handle.IsCompleted -or ((Get-Date) - $j.Started).TotalSeconds -gt 15) {
        $out = $null
        if ($j.Handle.IsCompleted) { try { $out = @($j.PS.EndInvoke($j.Handle)) | Select-Object -Last 1 } catch { $out = @{ Error = $_.Exception.Message } } }
        else { try { $j.PS.Stop() } catch { Write-Verbose 'status page stop failed' }; $out = @{ Error = 'no answer within 15 s' } }
        $j.PS.Dispose(); $global:SvcJob = $null
        $global:SvcResult = @{ Url = $j.Url; Time = (Get-Date); Json = $(if ($out) { $out.Json }); Error = $(if ($out) { $out.Error }) }
    }
}
$global:PreviewSvc = $null
function Get-StatusPageView {
    if ($global:PreviewSvc) { return $global:PreviewSvc }
    if (-not (Test-StatusPageEnabled)) { return $null }
    $r = $global:SvcResult
    $u = Get-StatusPageUrl; $h = try { ([Uri]$u).Host } catch { $u }
    if (-not $r -or $global:SvcJob) {
        $right = if ($global:SvcJob) { 'checking...' } else { 'not checked yet' }          # checked after each connect and on Refresh
        return [pscustomobject]@{ Text = "${h}: $right"; Tone = 'normal'; Tip = $u; Badge = '?'; Name = $(if ($r) { (ConvertTo-VeroStatusPageView -Json $r.Json -Url $r.Url -Time $r.Time -Failure ([string]$r.Error)).Name } else { $h }); Right = $right }
    }
    ConvertTo-VeroStatusPageView -Json $r.Json -Url $r.Url -Time $r.Time -Failure ([string]$r.Error)
}

function Get-ExitView($st) {
    $c = if ($global:PreviewExit) { $global:PreviewExit } else { (Get-TrayPref).exitInfo }
    ConvertTo-VeroExitView -Info $c -State $st.State -ProfileName $(if ($global:Config) { [string]$global:Config.Profile } else { '' }) -ProtectedSince $global:ProtectedSince `
        -Checking:([bool]$global:ExitJob) -Failure ([string]$global:ExitError) -Preview:([bool]$global:PreviewExit) -Connected:([bool]$st.Connected) -Hiddify:(Test-HiddifyProfile)
}

$global:Expect = $null
function Set-TrayExpect([string]$kind) {
    <# You just asked for something that blocks traffic on purpose until a tunnel is up: Turn on ('connect'), a profile switch
       ('switch') or Reconnect ('reconnect'). For up to 2 minutes the tray calls that phase by its name instead of
       "connection lost"; it ends as soon as the tunnel is up. Still down after 2 minutes = the ordinary blocked state. #>
    $global:Expect = @{ Kind = $kind; Since = (Get-Date); Until = (Get-Date).AddMinutes(2) }
}
function Get-TrayExpect {
    if ($global:Expect -and (Get-Date) -lt $global:Expect.Until) { return $global:Expect.Kind }
    $null
}
function Get-StateFacts {
    <# What the guard reports right now; ConvertTo-VeroTrayState turns it into the tray's state, title and text. #>
    if (-not $global:Config) { return @{ Configured = $false } }
    $name = $global:Config.Profile; $type = $global:Config.Type
    $armed = Test-VeroArmed
    $cp = Get-VeroPath -VpnProfile $name
    $ovpn = if ($type -eq 'openvpn') { Get-VeroOpenVpnStatus $name } else { $null }
    $nb = Get-VeroNativeBlocked
    @{
        Configured  = $true; Name = $name; Type = $type; Armed = $armed; Up = (Test-VeroVpnConnected $name -Type $type)
        Cred        = (-not (Test-VeroNeedsPassword $global:Config)) -or (Test-Path $cp.Cred) -or (Test-Path $cp.LegacyCred)
        AuthBlocked = (Test-VeroAuthBlocked $name)
        Otp         = $(if ($ovpn -and [string]$ovpn.State -eq 'NEED_OTP') { [string]$ovpn.Challenge } else { $null })
        Conflicts   = @(if ($armed) { Get-VeroConflictList })
        Expect      = (Get-TrayExpect)
        GuardStale  = $(if ($armed) { Get-GuardStale } else { 0 })
        NativeNext  = $(if ($nb) { try { '{0:HH:mm}' -f [datetime]::Parse([string]$nb.Next, $null, [Globalization.DateTimeStyles]::RoundtripKind) } catch { 'soon' } } else { $null })
    }
}
function Get-GuardStale {
    <# Minutes since the watchdog's last good pass, when that is over 3 (it runs every 15 s); 0 = fine or not known yet. #>
    try { $age = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [double]([IO.File]::ReadAllText($global:Paths.Heartbeat).Trim()) } catch { return 0 }
    if ($age -gt 180) { [int][Math]::Floor($age / 60) } else { 0 }
}
function Get-State {
    if ($global:PreviewFacts) { return ConvertTo-VeroTrayState $global:PreviewFacts }
    ConvertTo-VeroTrayState (Get-StateFacts)
}
function Get-ConnectionView($st) {
    <# The CONNECTION card, tooltip word and menu header (ConvertTo-VeroConnectionView decides; this collects). #>
    $chk = if ($global:PreviewCheck) { $global:PreviewCheck } elseif ($global:Config) { $global:Config.ConnectionCheck } else { $null }
    $q = if ($global:PreviewFacts) { $global:PreviewQuality } elseif ($chk -and $chk.Enabled -and $global:Config) { Read-VeroQuality -ProfileName $global:Config.Profile } else { $null }
    $exp = if ($global:PreviewFacts) { [string]$global:PreviewFacts.Expect } else { [string](Get-TrayExpect) }
    ConvertTo-VeroConnectionView -St $st -Check $chk -Quality $q -Expect $exp -Hiddify:(Test-HiddifyProfile)
}
function Invoke-GuardTask([string]$name) { Start-Process (Join-Path (Get-VeroSystemDir System) 'schtasks.exe') -ArgumentList "/run /tn `"$global:Folder$name`"" -WindowStyle Hidden }
function Get-LastEvents([int]$n = 6, [string]$After = '') {
    <# The newest log lines without the date; -After 'yyyy-MM-dd HH:mm:ss': only lines written after it (Clear in the status window). #>
    if (-not (Test-Path $global:Paths.Log)) { return @() }
    Get-Content $global:Paths.Log -Tail $n | Where-Object { -not $After -or $_.Substring(0, [Math]::Min(19, $_.Length)) -gt $After } | ForEach-Object { $_ -replace '^\d{4}-\d\d-\d\d ', '' }
}
function Get-LastDrop {
    if ($global:Config -and $global:Config.Type -ne 'ras') { return (& (Get-VeroTypeHandler $global:Config.Type).StatusDetail $global:Config) }   # the client's own state, as the status line shows it
    try { $e = Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='RasClient'; Id=20226 } -MaxEvents 1 -ErrorAction Stop; if ($e.Properties[2].Value -eq $global:Config.Profile) { $c = $e.Properties[3].Value; return ('{0:HH:mm} - {1}' -f $e.TimeCreated, $(if ($c -eq 631) { 'you disconnected' } elseif ($c -eq 829) { 'link failure (829)' } else { "code $c" })) } } catch { Write-Verbose 'no RAS event' }; '-' }

# ---------------------------------------------------------------- UI building blocks
function New-Form([string]$title, [int]$w, [int]$h) {
    $f = New-Object System.Windows.Forms.Form
    $f.Text = $title; $f.ClientSize = (Z $w $h); $f.StartPosition = 'CenterScreen'
    $f.FormBorderStyle = 'FixedSingle'; $f.MaximizeBox = $false; $f.MinimizeBox = $false; $f.ShowInTaskbar = $true
    $f.BackColor = $global:Theme.Bg; $f.ForeColor = $global:Theme.Text; $f.Font = $FontUI; $f.AutoScaleMode = 'None'
    $f.Icon = Get-AppIcon
    $f.Add_HandleCreated({ [VeroNative]::Style($this.Handle, $global:Dark) })
    $f
}
function New-Card($parent, [int]$x, [int]$y, [int]$w, [int]$h) {
    $p = New-Object System.Windows.Forms.Panel; $p.Location = (P $x $y); $p.Size = (Z $w $h)
    $p.BackColor = $global:Theme.Card; $p.Padding = New-Object System.Windows.Forms.Padding(14, 10, 14, 10)
    $p.Add_Paint({ param($s, $e) $e.Graphics.DrawRectangle((New-Object System.Drawing.Pen($global:Theme.Border)), 0, 0, $s.Width - 1, $s.Height - 1) })
    $parent.Controls.Add($p); $p
}
function New-Label($parent, [string]$text, [int]$x, [int]$y, [int]$w, [int]$h, $font = $FontUI, $color = $null) {
    $l = New-Object System.Windows.Forms.Label; $l.Text = $text; $l.Location = (P $x $y); $l.Size = (Z $w $h)
    $l.Font = $font; $l.ForeColor = if ($color) { $color } else { $global:Theme.Text }; $l.BackColor = 'Transparent'; $parent.Controls.Add($l); $l
}
function New-WrapLabel($parent, [string]$text, [int]$x, [int]$y, [int]$w, $font = $FontUI, $color = $null) {
    <# A label as tall as its text needs at this width (nothing cut off); callers place what follows below its Bottom. #>
    $l = New-Label $parent $text $x $y $w 20 $font $color
    $l.Height = (Measure-TextHeight $text $font $l.Width) + [int](2 * $global:Scale)
    $l
}
function New-Button($parent, [string]$text, [int]$x, [int]$y, [int]$w, [bool]$primary = $false) {
    $b = New-Object System.Windows.Forms.Button; $b.Text = $text; $b.Location = (P $x $y); $b.Size = (Z $w 34)
    $b.FlatStyle = 'Flat'; $b.Font = $FontUI; $b.FlatAppearance.BorderSize = 1; $b.Cursor = 'Hand'
    if ($primary) { $b.BackColor = $global:Theme.Accent; $b.ForeColor = if ($global:Dark) { [System.Drawing.Color]::FromArgb(20,20,20) } else { [System.Drawing.Color]::White }; $b.FlatAppearance.BorderColor = $global:Theme.Accent }
    else { $b.BackColor = $global:Theme.Card; $b.ForeColor = $global:Theme.Text; $b.FlatAppearance.BorderColor = $global:Theme.Border; $b.FlatAppearance.MouseOverBackColor = $global:Theme.Hover }
    # disabled: drawn here - Windows paints a disabled button's text near-black on the dark theme, and a disabled primary
    # button kept its accent colour (it looked clickable)
    $b.Add_Paint({ param($s, $e)
        if ($s.Enabled) { return }
        $e.Graphics.Clear($global:Theme.Card)
        $e.Graphics.DrawRectangle((New-Object System.Drawing.Pen($global:Theme.Border)), 0, 0, $s.Width - 1, $s.Height - 1)
        $flags = [System.Windows.Forms.TextFormatFlags]::HorizontalCenter -bor [System.Windows.Forms.TextFormatFlags]::VerticalCenter -bor [System.Windows.Forms.TextFormatFlags]::WordBreak
        [System.Windows.Forms.TextRenderer]::DrawText($e.Graphics, $s.Text, $s.Font, $s.ClientRectangle, $global:Theme.Sub, $flags)
    })
    $parent.Controls.Add($b); $b
}
function New-Input($parent, [int]$x, [int]$y, [int]$w, [string]$text = '', [bool]$password = $false) {
    $t = New-Object System.Windows.Forms.TextBox; $t.Location = (P $x $y); $t.Size = (Z $w 30)
    $t.BorderStyle = 'FixedSingle'; $t.BackColor = $global:Theme.Card; $t.ForeColor = $global:Theme.Text; $t.Font = $FontUI; $t.Text = $text; if ($password) { $t.UseSystemPasswordChar = $true }
    $parent.Controls.Add($t); $t
}

# ---------------------------------------------------------------- status window
$global:StatusForm = $null
function Show-Status {
    if ($global:StatusForm -and -not $global:StatusForm.IsDisposed) { $global:StatusForm.Activate(); return }
    $f = New-Form 'VeroScudo' 460 560
    $hero = New-Card $f 20 20 420 92
    $pic = New-Object System.Windows.Forms.PictureBox; $pic.Location = (P 16 14); $pic.Size = (Z 64 64); $pic.SizeMode = 'Zoom'; $pic.BackColor = 'Transparent'; $hero.Controls.Add($pic)
    $title = New-Label $hero '' 96 16 310 32 $FontBig
    $sub   = New-Label $hero '' 96 50 310 36 $FontSmall $global:Theme.Sub
    # where the traffic leaves the tunnel: one full-width line under the header
    $loc = New-Card $f 20 126 420 44
    $badge = New-Label $loc '' 12 11 30 22 $FontSmall $global:Theme.Text; $badge.TextAlign = 'MiddleCenter'; $badge.BackColor = $global:Theme.Hover
    $badge.Font = New-Object System.Drawing.Font('Segoe UI', 8.5, [System.Drawing.FontStyle]::Bold)
    # every part spans the line's full height, text centred vertically (fonts of different sizes line up on the middle)
    $place = New-Label $loc '' 52 1 168 42 $FontUI; $place.AutoEllipsis = $true; $place.TextAlign = 'MiddleLeft'
    $ipl = New-Label $loc '' 220 1 140 42 $FontSmall $global:Theme.Sub; $ipl.TextAlign = 'MiddleRight'; $ipl.AutoEllipsis = $true
    $rl = New-Object System.Windows.Forms.LinkLabel; $rl.Text = 'Refresh'; $rl.Location = (P 362 1); $rl.Size = (Z 50 42); $rl.TextAlign = 'MiddleRight'
    $rl.Font = $FontSmall; $rl.LinkColor = $global:Theme.Accent; $rl.ActiveLinkColor = $global:Theme.Accent; $rl.BackColor = 'Transparent'; $rl.LinkBehavior = 'HoverUnderline'
    $loc.Controls.Add($rl)
    $tip = New-Object System.Windows.Forms.ToolTip
    # whenever a tunnel is up (also with VeroScudo off, also "Protected + note"): the lookup then goes through it
    $rl.Add_LinkClicked(({ if ((Get-State).Connected) { $global:ExitError = ''; Start-ExitFetch } else { $global:ExitError = 'no VPN tunnel is up - nothing to check' } }).GetNewClosure())
    # a service's own status page (Settings > Connection, opt-in): a card like the location line - tells their outage
    # from your connection
    $sc = New-Card $f 20 180 420 44
    $sBadge = New-Label $sc '' 12 11 30 22 $FontSmall $global:Theme.Text; $sBadge.TextAlign = 'MiddleCenter'; $sBadge.BackColor = $global:Theme.Hover
    $sBadge.Font = New-Object System.Drawing.Font('Segoe UI', 8.5, [System.Drawing.FontStyle]::Bold)
    $sName = New-Label $sc '' 52 1 130 42 $FontUI; $sName.AutoEllipsis = $true; $sName.TextAlign = 'MiddleLeft'
    $sRight = New-Label $sc '' 182 1 178 42 $FontSmall $global:Theme.Sub; $sRight.TextAlign = 'MiddleRight'; $sRight.AutoEllipsis = $true
    $sl = New-Object System.Windows.Forms.LinkLabel; $sl.Text = 'Refresh'; $sl.Location = (P 362 1); $sl.Size = (Z 50 42); $sl.TextAlign = 'MiddleRight'
    $sl.Font = $FontSmall; $sl.LinkColor = $global:Theme.Accent; $sl.ActiveLinkColor = $global:Theme.Accent; $sl.BackColor = 'Transparent'; $sl.LinkBehavior = 'HoverUnderline'
    $sc.Controls.Add($sl)
    $sl.Add_LinkClicked(({ $global:SvcResult = $null; Start-StatusPageFetch -Now }).GetNewClosure())
    # everything below sits in one panel: the header grows with its text (nothing cut off) and pushes it down
    $body = New-Object System.Windows.Forms.Panel; $body.Location = (P 0 170); $body.Size = (Z 460 412); $body.BackColor = $global:Theme.Bg; $f.Controls.Add($body)
    $f.ClientSize = (Z 460 582)
    $cards = @{}; $heads = @{}
    $i = 0
    foreach ($k in 'VPN profile', 'Firewall', 'Last drop', 'Connection') {
        $cx = 20 + ($i % 2) * 215; $cy = 14 + [math]::Floor($i / 2) * 78
        $c = New-Card $body $cx $cy 205 66
        $heads[$k] = New-Label $c ($k.ToUpper()) 12 8 185 16 $FontSmall $global:Theme.Sub
        $cards[$k] = New-Label $c '' 12 28 185 24 $FontBold
        $cards[$k].AutoEllipsis = $true; $heads[$k].AutoEllipsis = $true
        $i++
    }
    $other = New-Label $body '' 20 161 420 18 $FontSmall ($global:Amber); $other.AutoEllipsis = $true
    $ev = New-Card $body 20 180 420 160
    New-Label $ev 'RECENT EVENTS' 12 8 200 16 $FontSmall $global:Theme.Sub | Out-Null
    # Clear empties this view only: the log file stays (it is the record of what happened, and it is admin-owned - it rotates
    # by itself at 2 MB). Open log still shows everything.
    $clr = New-Object System.Windows.Forms.LinkLabel; $clr.Text = 'Clear'; $clr.Location = (P 360 6); $clr.Size = (Z 48 18); $clr.TextAlign = 'TopRight'
    $clr.Font = $FontSmall; $clr.LinkColor = $global:Theme.Accent; $clr.ActiveLinkColor = $global:Theme.Accent; $clr.BackColor = 'Transparent'; $clr.LinkBehavior = 'HoverUnderline'
    $ev.Controls.Add($clr)
    $evText = New-Object System.Windows.Forms.TextBox; $evText.Multiline = $true; $evText.ReadOnly = $true; $evText.BorderStyle = 'None'
    $evText.Location = (P 12 30); $evText.Size = (Z 400 122); $evText.Font = $FontMono; $evText.BackColor = $global:Theme.Card; $evText.ForeColor = $global:Theme.Text; $evText.ScrollBars = 'Vertical'; $evText.WordWrap = $true; $evText.TabStop = $false; $evText.Cursor = 'Default'
    $evText.Add_HandleCreated({ [VeroNative]::DarkScroll($this.Handle, $global:Dark) })
    $ev.Controls.Add($evText)
    $bOnOff = New-Button $body 'Turn VPN off' 20 358 99
    $bRedo  = New-Button $body 'Reconnect' 127 358 99
    $bLog   = New-Button $body 'Open log' 234 358 99
    $bCopy  = New-Button $body 'Copy report' 341 358 99 $true
    $bRedo.Add_Click(({ Request-Reconnect }).GetNewClosure())
    $bLog.Add_Click(({ if (Test-Path $global:Paths.Log) { Start-Process notepad.exe $global:Paths.Log } }).GetNewClosure())
    $bCopy.Add_Click(({ $s = Get-VeroStatus -Config $global:Config; $txt = ($s.PSObject.Properties | ForEach-Object { '{0,-11} {1}' -f $_.Name, $_.Value }) -join "`r`n"; $xv = Get-ExitView (Get-State); $txt += "`r`n" + ('{0,-11} {1}' -f 'Exit', $(if ($xv.Has) { '{0} {1} {2}' -f $xv.Code, $xv.Place, $xv.Right } else { $xv.Text })); $sv = Get-StatusPageView; if ($sv) { $txt += "`r`n" + ('{0,-11} {1}' -f 'Service', $sv.Text) }; $txt += "`r`n`r`n--- last events`r`n" + ((Get-LastEvents 15) -join "`r`n"); [System.Windows.Forms.Clipboard]::SetText($txt); $bCopy.Text = 'Copied'; }).GetNewClosure())
    $bOnOff.Add_Click(({ if ($bOnOff.Text -like '*off') { Invoke-GuardTask 'Off' } else { Request-TurnOn } }).GetNewClosure())
    $clr.Add_LinkClicked(({ Set-TrayPref 'eventsClearedAt' (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); $evText.Text = '' }).GetNewClosure())
    $refresh = ({
        $st = Get-State
        $pic.Image = Get-StateImage $st.State 64; $title.Text = $st.Title; $sub.Text = $st.Text
        $sub.Height = (Measure-TextHeight $sub.Text $FontSmall $sub.Width) + [int](2 * $global:Scale)
        $heroH = [Math]::Max([int](92 * $global:Scale), $sub.Bottom + [int](12 * $global:Scale))
        if ($hero.Height -ne $heroH) { $hero.Height = $heroH }
        $showLoc = Test-ExitEnabled
        $loc.Visible = $showLoc; $loc.Top = $hero.Bottom + [int](14 * $global:Scale)
        $prevBottom = if ($showLoc) { $loc.Bottom } else { $hero.Bottom }
        $sv = Get-StatusPageView
        $sc.Visible = [bool]$sv
        if ($sv) {
            $sc.Top = $prevBottom + [int](10 * $global:Scale); $prevBottom = $sc.Bottom
            $sBadge.Text = $sv.Badge; $sName.Text = $sv.Name; $sRight.Text = $sv.Right
            # the right text as wide as it needs, the name gets the rest (a long host name wrapped mid-word)
            $rw = [System.Windows.Forms.TextRenderer]::MeasureText($sv.Right, $FontSmall).Width + [int](6 * $global:Scale)
            $sRight.Width = [Math]::Min($rw, [int](300 * $global:Scale)); $sRight.Left = [int](360 * $global:Scale) - $sRight.Width
            $sName.Width = [Math]::Max([int](40 * $global:Scale), $sRight.Left - $sName.Left - [int](6 * $global:Scale))
            # secondary information: a neutral badge like the country code, no colour (the connection is the main thing)
            foreach ($ctl in $sc, $sName, $sRight, $sBadge) { $tip.SetToolTip($ctl, $sv.Tip) }
        }
        $bodyTop = $prevBottom
        if ($body.Top -ne $bodyTop) { $body.Top = $bodyTop }
        if ($f.ClientSize.Height -ne $body.Bottom) { $f.ClientSize = New-Object System.Drawing.Size($f.ClientSize.Width, $body.Bottom) }
        if ($showLoc) {
            $ex = Get-ExitView $st
            $badge.Visible = $ex.Has
            if ($ex.Has) {
                $badge.Text = $ex.Code; $place.Text = $ex.Place; $place.Left = [int](52 * $global:Scale); $place.Width = [int](168 * $global:Scale); $ipl.Text = $ex.Right
                $place.ForeColor = if ($ex.Fresh) { $global:Theme.Text } else { $global:Theme.Sub }
                $badge.ForeColor = $place.ForeColor
                $tip.SetToolTip($loc, $ex.Tip); $tip.SetToolTip($place, $ex.Tip); $tip.SetToolTip($ipl, $ex.Tip)
            } else {
                $place.Text = $ex.Text; $place.Left = [int](12 * $global:Scale); $place.Width = [int](346 * $global:Scale); $place.ForeColor = $global:Theme.Sub; $ipl.Text = ''
            }
        }
        $title.ForeColor = if ($st.Expected) { $global:Amber } else { switch ($st.State) { 'protected' { [System.Drawing.Color]::FromArgb(48,200,79) } 'blocked' { [System.Drawing.Color]::FromArgb(248,80,70) } 'attention' { $global:Amber } default { $global:Theme.Text } } }
        $cards['VPN profile'].Text = if ($global:Config) { $global:Config.Profile } else { '-' }
        $heads['VPN profile'].Text = if ($global:Config) { ('VPN profile - ' + (Get-VeroTypeLabel $global:Config.Type)).ToUpper() } else { 'VPN PROFILE' }
        $bRedo.Enabled = $st.Armed -and -not (Test-HiddifyProfile)            # Hiddify reconnects in Hiddify
        $cards['Firewall'].Text = if ($st.Armed) { 'kill-switch ON' } else { 'normal' }
        $cards['Firewall'].ForeColor = if ($st.Expected) { $global:Amber } elseif ($st.Armed -and -not $st.Connected) { [System.Drawing.Color]::FromArgb(248,80,70) } else { $global:Theme.Text }
        $cards['Last drop'].Text = Get-LastDrop
        # CONNECTION: the quality while protected (Settings > Connection), else what the guard does about the connection
        $cv = Get-ConnectionView $st
        $cards['Connection'].Text = $cv.Text
        $cards['Connection'].ForeColor = switch ($cv.Tone) { 'good' { [System.Drawing.Color]::FromArgb(48,200,79) } 'warn' { $global:Amber } 'bad' { [System.Drawing.Color]::FromArgb(248,80,70) } default { $global:Theme.Text } }
        $tip.SetToolTip($cards['Connection'], $cv.Tip)
        # OpenVPN / WireGuard: that card shows the client's own state (not the last drop)
        $heads['Last drop'].Text = switch ($(if ($global:Config) { [string]$global:Config.Type } else { '' })) { 'openvpn' { 'OPENVPN' } 'wireguard' { 'WIREGUARD' } default { 'LAST DROP' } }
        # lines wrap at the window edge: after a comma too, so an address list never breaks in the middle of an address
        $evNew = ((Get-LastEvents 40 -After ([string](Get-TrayPref).eventsClearedAt)) | ForEach-Object { $_ -replace ',(?=\S)', ', ' }) -join "`r`n"
        if ($evText.Text -ne $evNew) { $evText.Text = $evNew; $evText.SelectionStart = $evText.TextLength; $evText.ScrollToCaret() }   # newest at the bottom, scrollable
        $fv = @(Get-ForeignCached)
        $other.Text = if ($fv.Count -gt 0) { 'Other VPNs: ' + (($fv | ForEach-Object { '{0} ({1})' -f $_.Name, $(if ($_.Configured) { 'another profile' } elseif ($_.Kind -eq 'app') { 'VPN app' } else { 'not imported' }) }) -join ', ') } else { '' }
        # Off also hangs up a VPN VeroScudo can disconnect - never Hiddify (you disconnect it there): offered only while on
        $bOnOff.Text = if ($st.Armed -or ($st.Connected -and -not (Test-HiddifyProfile))) { 'Turn VPN off' } else { 'Turn VPN on' }
    }).GetNewClosure()
    & $refresh
    $f.Add_Shown(({ $evText.SelectionStart = $evText.TextLength; $evText.ScrollToCaret() }).GetNewClosure())   # newest line visible at once
    $tm = New-Object System.Windows.Forms.Timer; $tm.Interval = 3000; $tm.Add_Tick($refresh); $tm.Start()
    $f.Add_FormClosed(({ $tm.Stop(); $tm.Dispose() }).GetNewClosure())
    $global:StatusForm = $f
    $f.Show(); $f.Activate(); $bLog.Focus() | Out-Null
    $f
}

# ---------------------------------------------------------------- messages
function Show-Message([string]$text, [string]$title = 'VeroScudo', [string]$buttons = 'OK', [string]$icon = 'None') {
    <# VeroScudo's message box: themed like every other window, as tall as its text. Returns 'OK', 'Yes' or 'No'
       (No is the default: Enter or Esc never confirms a removal by accident). #>
    $mf = New-Form $title 460 160
    if ($icon -in 'Warning', 'Error') {
        $bar = New-Object System.Windows.Forms.Panel; $bar.Location = (P 0 0); $bar.Size = (Z 5 4000)
        $bar.BackColor = if ($icon -eq 'Error') { [System.Drawing.Color]::FromArgb(248,80,70) } else { $global:Amber }
        $mf.Controls.Add($bar)
    }
    $l = New-WrapLabel $mf $text 24 20 412 $FontUI
    $y = 20 + (Get-Logical $l.Height) + 20
    $res = @{ Value = $(if ($buttons -eq 'YesNo') { 'No' } else { 'OK' }) }
    if ($buttons -eq 'YesNo') {
        $bYes = New-Button $mf 'Yes' 210 $y 110; $bNo = New-Button $mf 'No' 330 $y 110 $true     # highlighted = the default = No
        $bYes.Add_Click(({ $res.Value = 'Yes'; $mf.Close() }).GetNewClosure()); $bNo.Add_Click(({ $res.Value = 'No'; $mf.Close() }).GetNewClosure())
        $mf.AcceptButton = $bNo; $mf.CancelButton = $bNo
    } else {
        $bOk = New-Button $mf 'OK' 330 $y 110 $true
        $bOk.Add_Click(({ $mf.Close() }).GetNewClosure()); $mf.AcceptButton = $bOk; $mf.CancelButton = $bOk
    }
    $mf.ClientSize = (Z 460 ($y + 34 + 18)); $mf.TopMost = $true
    Show-Modal $mf $(if ($global:ShotName) { $global:ShotName } else { 'message' })
    $res.Value
}
[VeroMsg]::Handler = { param($t, $ti, $b, $i) Show-Message $t $ti $b $i }

# ---------------------------------------------------------------- settings window
function Read-Password([string]$who) {
    <# Small modal: returns a SecureString or $null. #>
    $pf = New-Form 'VPN password' 420 180
    $l = New-WrapLabel $pf "Password for $who. Stored encrypted, for your Windows account only." 20 16 380 $FontSmall $global:Theme.Sub
    $y = 16 + (Get-Logical $l.Height) + 10
    $tp = New-Input $pf 20 $y 380 '' $true
    $ok = New-Button $pf 'Save' 290 ($y + 46) 110 $true; $no = New-Button $pf 'Cancel' 170 ($y + 46) 110
    $pf.ClientSize = (Z 420 ($y + 46 + 34 + 18)); $pf.AcceptButton = $ok; $pf.CancelButton = $no
    $result = @{ Value = $null }
    $ok.Add_Click(({ $sec = New-Object System.Security.SecureString; foreach ($ch in $tp.Text.ToCharArray()) { $sec.AppendChar($ch) }; $sec.MakeReadOnly(); $tp.Text = ''; $result.Value = $sec; $pf.Close() }).GetNewClosure())
    $no.Add_Click(({ $pf.Close() }).GetNewClosure())
    Show-Modal $pf 'password'
    $result.Value
}

function Read-Otp([string]$question, [string]$profileName) {
    <# OpenVPN static challenge: the code goes to the runner through a file in your own folder, read once. #>
    $of = New-Form 'One-time code' 380 170
    $l = New-WrapLabel $of "$profileName asks: $question" 20 16 340 $FontSmall $global:Theme.Sub
    $y = 16 + (Get-Logical $l.Height) + 10
    $tc = New-Input $of 20 $y 340 ''
    $ok = New-Button $of 'Send' 250 ($y + 46) 110 $true
    $of.ClientSize = (Z 380 ($y + 46 + 34 + 18)); $of.AcceptButton = $ok
    $result = @{ Value = $null }
    $ok.Add_Click(({ $result.Value = $tc.Text.Trim(); $of.Close() }).GetNewClosure())
    $of.TopMost = $true
    Show-Modal $of 'otp'
    $result.Value
}

$global:OtpAsked = ''
function Request-Otp {
    if (-not $global:Config -or $global:Config.Type -ne 'openvpn') { return }
    $s = Get-VeroOpenVpnStatus $global:Config.Profile
    if (-not $s -or [string]$s.State -ne 'NEED_OTP') { $global:OtpAsked = ''; return }
    if ($global:OtpAsked -eq [string]$s.Time) { return }
    $global:OtpAsked = [string]$s.Time
    $code = Read-Otp ([string]$s.Challenge) $global:Config.Profile
    if ($code) {
        $cp = Get-VeroPath -VpnProfile $global:Config.Profile
        New-Item -ItemType Directory -Path $cp.UserDir -Force | Out-Null
        Set-Content -Path $cp.Otp -Value $code -Encoding UTF8
    }
}

function Select-WindowsVpn([string[]]$have, [bool]$haveHiddify = $false) {
    <# Import from Windows: ONE Windows VPN profile per import, chosen by you - not every VPN on a PC is for work. Lists
       your profiles and those for all users with the type, server and sign-in VeroScudo found; profiles already in the
       list are not offered again. Nothing is selected in advance. Returns the chosen profile or nothing. #>
    $all = @(Get-VeroWindowsVpn | Sort-Object Name)
    $offer = @($all | Where-Object { $have -notcontains $_.Name -and $_.Server })
    # Hiddify (installed, VPN mode): offered here too - VeroScudo then only blocks while its tunnel is down
    $hid = if (-not $haveHiddify) { Get-VeroHiddifyOffer } else { $null }
    if ($hid) { $offer += [pscustomobject]@{ Name = 'Hiddify'; Hiddify = $true; Ok = $hid.Ok; Note = $hid.Note } }
    if ($offer.Count -eq 0) {
        $msg = if ($all.Count -eq 0) { 'No Windows VPN profile found. Create one in Settings > Network & Internet > VPN (any type: Automatic, IKEv2, SSTP, L2TP/IPsec, PPTP), connect once, then import it here.' } else { 'Every Windows VPN profile is already in the list.' }
        [VeroMsg]::Show($msg, 'VeroScudo') | Out-Null; return
    }
    $sf = New-Form 'Import from Windows' 560 380
    $l = New-WrapLabel $sf 'Choose the ONE Windows VPN profile to protect (import others one by one). Server, port, protocol and sign-in are taken from Windows.' 20 14 520 $FontSmall $global:Theme.Sub
    $ly = 14 + (Get-Logical $l.Height) + 8
    $lbx = New-Object System.Windows.Forms.ListBox; $lbx.Location = (P 20 $ly); $lbx.Size = (Z 520 (304 - $ly)); $lbx.BorderStyle = 'FixedSingle'; $lbx.SelectionMode = 'One'
    $lbx.Add_HandleCreated({ [VeroNative]::DarkScroll($this.Handle, $global:Dark) })
    $lbx.BackColor = $global:Theme.Bg; $lbx.ForeColor = $global:Theme.Text; $lbx.Font = $FontUI; $lbx.IntegralHeight = $false
    foreach ($v in $offer) {
        if ($v.PSObject.Properties['Hiddify']) { [void]$lbx.Items.Add("Hiddify  -  $($v.Note)"); continue }
        $proto = switch ($v.TunnelType) { 'Ikev2' { 'IKEv2' } 'Sstp' { 'SSTP' } 'L2tp' { 'L2TP/IPsec' } 'Pptp' { 'PPTP' } default { 'Automatic' } }
        [void]$lbx.Items.Add(('{0}  -  {1}  -  {2}  -  {3}{4}' -f $v.Name, $proto, $v.Server, $(if ($v.Password) { 'password' } else { 'certificate' }), $(if ($v.AllUsers) { '  (all users)' } else { '' })))
    }
    $lbx.SelectedIndex = -1
    $sf.Controls.Add($lbx)
    $res = @{ Value = $null }
    $ok = New-Button $sf 'Import' 430 318 110 $true; $cancel = New-Button $sf 'Cancel' 310 318 110
    $ok.Enabled = $false
    $lbx.Add_SelectedIndexChanged(({ $ok.Enabled = ($lbx.SelectedIndex -ge 0) }).GetNewClosure())
    $cancel.Add_Click(({ $sf.Close() }).GetNewClosure())
    $ok.Add_Click(({
        if ($lbx.SelectedIndex -lt 0) { return }
        $pick = $offer[$lbx.SelectedIndex]
        if ($pick.PSObject.Properties['Hiddify'] -and -not $pick.Ok) { [VeroMsg]::Show($pick.Note, 'VeroScudo') | Out-Null; return }
        $res.Value = $pick; $sf.Close() }).GetNewClosure())
    Show-Modal $sf 'import'
    if ($res.Value) { $res.Value }
}

function Show-Check([string]$what, [string[]]$warnings) {
    <# The add/edit check: warnings shown before saving. Returns $true to save anyway. #>
    if (@($warnings).Count -eq 0) { return $true }
    $msg = "$what`r`n`r`n" + ((@($warnings) | ForEach-Object { '- ' + $_ }) -join "`r`n`r`n") + "`r`n`r`nSave anyway?"
    ([VeroMsg]::Show($msg, 'VeroScudo - check', 'YesNo', 'Warning') -eq 'Yes')
}

function Request-ProfilePassword($e) {
    <# Right after a profile is added: its password, stored encrypted for this Windows account (no administrator prompt).
       Windows never hands out the password it saved, so VeroScudo has to ask once; without it no automatic redial. #>
    if (-not (Test-VeroNeedsPassword $e)) { return }
    $had = [bool](Get-VeroCredential -Config $e)                            # e.g. kept from before the profile was removed
    $sec = Read-Password "$($e.Username) ($($e.Profile)) - needed for the automatic redial$(if ($had) { '. A password is already stored: leave empty to keep it' })"
    if (-not $sec -or $sec.Length -eq 0) { if ($had) { return } ; $sec = $null }
    if (-not $sec) { [VeroMsg]::Show("No password stored for '$($e.Profile)'. VeroScudo cannot redial it by itself until you add one (select it, Set password...).", 'VeroScudo', 'OK', 'Warning') | Out-Null; return }
    $cp = Get-VeroPath -VpnProfile $e.Profile
    New-Item -ItemType Directory -Path $cp.UserDir -Force | Out-Null
    New-Object System.Management.Automation.PSCredential($e.Username, $sec) | Export-Clixml $cp.Cred
}

function New-ThemedCheck {
    <# A check box in the theme's colours (VeroCheck: WinForms draws the box white on the dark theme). #>
    $c = New-Object VeroCheck
    $c.Box = $global:Theme.Card; $c.Frame = $global:Theme.Frame; $c.Accent = $global:Theme.Accent; $c.TextDisabled = $global:Theme.Sub
    $c.Mark = if ($global:Dark) { [System.Drawing.Color]::FromArgb(20, 20, 20) } else { [System.Drawing.Color]::White }
    $c
}

function Set-DarkCombo($c) {
    <# A drop-down list in the theme's colours: the closed box is drawn here (Windows draws a DropDownList white, ignoring
       BackColor), the button and its chevron by VeroCombo (WinForms painted it light grey with a tiny arrow), the open list
       gets Windows' own dark combo theme. #>
    if ($c -is [VeroCombo]) { $c.Arrow = $global:Theme.Text; $c.ArrowDisabled = $global:Theme.Sub; $c.Frame = $global:Theme.Frame }
    $c.Add_HandleCreated({ [VeroNative]::DarkCombo($this.Handle, $global:Dark) })
    if ($c.DropDownStyle -ne 'DropDownList') { return }
    $c.DrawMode = 'OwnerDrawFixed'; $c.ItemHeight = [int](22 * $global:Scale)
    $c.Add_DrawItem({ param($s, $e)
        if ($e.Index -lt 0) { return }
        $sel = (($e.State -band [System.Windows.Forms.DrawItemState]::Selected) -ne 0) -and (($e.State -band [System.Windows.Forms.DrawItemState]::ComboBoxEdit) -eq 0)
        $bg = if ($sel) { $global:Theme.Accent } else { $global:Theme.Card }   # the inputs' fill, like the text boxes
        $fg = if ($sel) { $(if ($global:Dark) { [System.Drawing.Color]::FromArgb(20,20,20) } else { [System.Drawing.Color]::White }) } else { $global:Theme.Text }
        $e.Graphics.FillRectangle((New-Object System.Drawing.SolidBrush($bg)), $e.Bounds)
        $flags = [System.Windows.Forms.TextFormatFlags]::VerticalCenter -bor [System.Windows.Forms.TextFormatFlags]::Left -bor [System.Windows.Forms.TextFormatFlags]::EndEllipsis
        [System.Windows.Forms.TextRenderer]::DrawText($e.Graphics, $s.GetItemText($s.Items[$e.Index]), $s.Font, $e.Bounds, $fg, $bg, $flags)
    })
}
function Lock-Combo($c) {
    <# Editing keeps a profile's type and name. Locked = a disabled list holding only the current value, drawn by Set-DarkCombo
       in the theme's colours (Windows draws a disabled editable combo box light grey on the dark theme). #>
    if ($c.DropDownStyle -ne 'DropDownList') {
        $txt = $c.Text
        $c.Items.Clear(); [void]$c.Items.Add($txt)
        $c.DropDownStyle = 'DropDownList'; $c.SelectedIndex = 0
        Set-DarkCombo $c
    }
    $c.Enabled = $false; $c.TabStop = $false
}
function New-VpnProfileForm($entry) {
    <# The profile editor, per type. Every type shows only its own fields, laid out top to bottom (no fixed positions shared
       between types); text that wraps gets its measured height; switching the type of a NEW profile clears every field, so
       nothing of one profile or type leaks into another. Returns @{ Form; Result; Type } - Edit-VpnProfile shows it modal,
       -Preview screenshots it. An OpenVPN entry with a newly chosen .ovpn carries ImportFrom (imported elevated on Save). #>
    $ef = New-Form 'VPN profile' 420 400
    $types = @('ras', 'openvpn', 'wireguard')
    $W = 380                                                              # content width (logical px)
    $lType = New-Label $ef 'Type' 20 16 200 18 $FontSmall $global:Theme.Sub
    $cbType = New-Object VeroCombo; $cbType.Location = (P 20 36); $cbType.Size = (Z $W 30); $cbType.DropDownStyle = 'DropDownList'; $cbType.FlatStyle = 'Flat'; $cbType.BackColor = $global:Theme.Card; $cbType.ForeColor = $global:Theme.Text; $cbType.Font = $FontUI; Set-DarkCombo $cbType
    foreach ($t in $types) { [void]$cbType.Items.Add((Get-VeroTypeLabel $t)) }
    $ef.Controls.Add($cbType)
    $lName = New-Label $ef '' 20 0 $W 18 $FontSmall $global:Theme.Sub
    $cb = New-Object VeroCombo; $cb.Size = (Z $W 30); $cb.DropDownStyle = 'DropDown'; $cb.FlatStyle = 'Flat'; $cb.BackColor = $global:Theme.Card; $cb.ForeColor = $global:Theme.Text; $cb.Font = $FontUI; Set-DarkCombo $cb
    $ef.Controls.Add($cb)
    $lServer = New-Label $ef 'Server host name' 20 0 200 18 $FontSmall $global:Theme.Sub
    $tServer = New-Input $ef 20 0 290 ''
    $lPort = New-Label $ef 'Port' 320 0 60 18 $FontSmall $global:Theme.Sub
    $tPort = New-Input $ef 320 0 80 ''
    $lFile = New-Label $ef 'OpenVPN config (.ovpn) - imported for administrators only' 20 0 $W 18 $FontSmall $global:Theme.Sub
    $tFile = New-Input $ef 20 0 290 ''
    $bFile = New-Button $ef 'Browse...' 320 0 80
    $lUser = New-Label $ef 'Username' 20 0 200 18 $FontSmall $global:Theme.Sub
    $tUser = New-Input $ef 20 0 $W ''
    $chkDco = New-ThemedCheck; $chkDco.Text = 'Keep DCO (faster; the server permit is then not tied to openvpn.exe)'; $chkDco.AutoSize = $false; $chkDco.Size = (Z $W 40); $chkDco.ForeColor = $global:Theme.Text; $chkDco.Font = $FontSmall; $ef.Controls.Add($chkDco)
    $bConf = New-Button $ef 'Read .conf...' 20 0 140
    $hint = New-Label $ef '' 20 0 $W 18 $FontSmall $global:Theme.Sub; $hint.AutoSize = $false
    $bOk = New-Button $ef 'OK' 290 0 110 $true; $bCancel = New-Button $ef 'Cancel' 170 0 110
    $null = $lType
    $state = @{ Warnings = @(); Auth = $true; Import = $null; Ras = @{}; AutoServer = ''; Type = ''; PortUsed = $true }
    $layout = ({
        # place what this type uses, one row after the other; hide the rest
        $t = $state.Type
        $at = { param($ctl, [double]$x, [double]$y) $ctl.Location = (P $x $y); $ctl.Visible = $true }
        foreach ($c in $lServer, $tServer, $lPort, $tPort, $lFile, $tFile, $bFile, $lUser, $tUser, $chkDco, $bConf) { $c.Visible = $false }
        $y = 80
        & $at $lName 20 $y; & $at $cb 20 ($y + 20); $y += 64
        if ($t -in 'ras', 'wireguard') {
            & $at $lServer 20 $y; & $at $tServer 20 ($y + 20)
            if ($state.PortUsed) { & $at $lPort 320 $y; & $at $tPort 320 ($y + 20); $tServer.Size = (Z 290 30) } else { $tServer.Size = (Z $W 30) }
            $y += 64
        }
        if ($t -eq 'openvpn') { & $at $lFile 20 $y; & $at $tFile 20 ($y + 20); & $at $bFile 320 ($y + 18); $y += 64 }
        if ($t -eq 'openvpn' -or ($t -eq 'ras' -and $state.Auth)) { & $at $lUser 20 $y; & $at $tUser 20 ($y + 20); $y += 64 }
        if ($t -eq 'openvpn') { & $at $chkDco 20 $y; $y += 48 }
        if ($t -eq 'wireguard') { & $at $bConf 20 $y; $y += 48 }
        if ($hint.Text) {
            $px = [System.Windows.Forms.TextRenderer]::MeasureText($hint.Text, $hint.Font, (New-Object System.Drawing.Size([int]($W * $global:Scale), 2000)), [System.Windows.Forms.TextFormatFlags]::WordBreak)
            $hint.Location = (P 20 $y); $hint.Size = New-Object System.Drawing.Size([int]($W * $global:Scale), ($px.Height + 4)); $hint.Visible = $true
            $y += [Math]::Ceiling(($px.Height + 4) / $global:Scale) + 12
        } else { $hint.Visible = $false }
        $y += 6
        $bCancel.Location = (P 170 $y); $bOk.Location = (P 290 $y)
        $ef.ClientSize = (Z 420 ($y + 34 + 20))
    }).GetNewClosure()
    $onPick = ({
        # Windows VPN: fill in what the Windows profile knows; say which protocol and sign-in VeroScudo found
        if ($state.Type -ne 'ras') { & $layout; return }
        $info = $state.Ras[$cb.Text.Trim()]
        if (-not $info) {
            $state.PortUsed = $true; $state.Auth = $true
            $hint.Text = $(if ($cb.Text.Trim()) { 'Not a Windows VPN profile of this PC: create it in Settings > VPN first, connect once, then pick it here.' } else { '' })
            & $layout; return
        }
        if ($info.Server -and (-not $tServer.Text.Trim() -or $tServer.Text.Trim() -eq $state.AutoServer)) {
            $sa = Split-VeroServerAddress $info.Server
            $tServer.Text = $sa.Host; $state.AutoServer = $sa.Host
            if ($sa.Port) { $tPort.Text = [string]$sa.Port }
        }
        $state.PortUsed = $info.TunnelType -in 'Sstp', 'Automatic'          # only SSTP uses the port; the others have fixed ports
        if (-not $state.PortUsed) { $tPort.Text = '443' }
        $state.Auth = [bool]$info.Password
        if ($state.Auth -and -not $tUser.Text.Trim()) { $u = Get-VeroRasSavedUser -Name $info.Name -AllUsers $info.AllUsers; if ($u) { $tUser.Text = $u } }
        $hint.Text = Get-VeroRasDescription -TunnelType $info.TunnelType -Password $info.Password -AllUsers $info.AllUsers
        & $layout
    }).GetNewClosure()
    $apply = ({
        $t = $types[[Math]::Max(0, $cbType.SelectedIndex)]
        $state.Type = $t
        if (-not $entry) {
            # a NEW profile: nothing of the type shown before may stay (names, servers, users, files)
            $cb.Text = ''; $tServer.Text = ''; $tUser.Text = ''; $tFile.Text = ''; $chkDco.Checked = $false
            $tPort.Text = [string](Get-VeroTypeHandler $t).DefaultPort
            $state.Warnings = @(); $state.AutoServer = ''; $state.Auth = (Get-VeroTypeHandler $t).PasswordCapable; $state.PortUsed = $true
        }
        $keep = if ($entry) { $entry.Profile } else { '' }
        $cb.Items.Clear()
        $names = switch ($t) {
            'ras'       { $state.Ras = @{}; foreach ($v in @(Get-VeroWindowsVpn)) { $state.Ras[$v.Name] = $v }; @($state.Ras.Keys | Sort-Object) }
            'wireguard' { @(Get-Service -Name 'WireGuardTunnel$*' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name.Substring(16) }) }
            default     { @() }
        }
        foreach ($n in $names) { [void]$cb.Items.Add($n) }
        if ($keep) { $cb.Text = $keep }
        $lName.Text = switch ($t) { 'ras' { 'Windows VPN profile (Settings > VPN)' } 'wireguard' { 'WireGuard tunnel name (exactly as in the WireGuard app)' } default { 'Profile name (your choice)' } }
        $hint.Text = switch ($t) {
            'openvpn'   { "VeroScudo starts and stops OpenVPN connections itself: don't connect or disconnect them from OpenVPN GUI - use VeroScudo's On, Off and Reconnect." }
            'wireguard' { 'A dead WireGuard link is noticed after 1-3 minutes, not seconds; you stay blocked until it reconnects. Prefer a Windows VPN profile when you can.' }
            default     { '' }
        }
        & $onPick
    }).GetNewClosure()
    $cb.Add_SelectedIndexChanged($onPick)
    $cb.Add_Leave($onPick)
    $cbType.Add_SelectedIndexChanged($apply)
    if ($entry) {
        # editing never turns one profile into another (that silently replaced it): type and name stay
        $tServer.Text = [string]$entry.Server; $tPort.Text = [string]$entry.Port; $tUser.Text = [string]$entry.Username
        $chkDco.Checked = [bool]($entry.PSObject.Properties['Dco'] -and $entry.Dco)
        $state.Auth = $(if ($entry.PSObject.Properties['Auth']) { [bool]$entry.Auth } else { $true })
    }
    $cbType.SelectedIndex = [Math]::Max(0, [array]::IndexOf($types, $(if ($entry -and $entry.PSObject.Properties['Type'] -and $entry.Type) { [string]$entry.Type } else { 'ras' })))
    if ($entry) { Lock-Combo $cbType; Lock-Combo $cb }
    $bFile.Add_Click(({
        $dlg = New-Object System.Windows.Forms.OpenFileDialog; $dlg.Filter = 'OpenVPN config (*.ovpn;*.conf)|*.ovpn;*.conf|All files|*.*'
        if ($dlg.ShowDialog() -eq 'OK') { $tFile.Text = $dlg.FileName; if (-not $cb.Text) { $cb.Text = [IO.Path]::GetFileNameWithoutExtension($dlg.FileName) } }
    }).GetNewClosure())
    $bConf.Add_Click(({
        $dlg = New-Object System.Windows.Forms.OpenFileDialog; $dlg.Filter = 'WireGuard config (*.conf)|*.conf|All files|*.*'
        if ($dlg.ShowDialog() -ne 'OK') { return }
        $r = Test-VeroWireGuardConf -Text ([IO.File]::ReadAllText($dlg.FileName))
        if ($r.Errors.Count -gt 0) { [VeroMsg]::Show(($r.Errors -join "`r`n"), 'VeroScudo - WireGuard config') | Out-Null; return }
        $tServer.Text = $r.Server; $tPort.Text = [string]$r.Port
        if (-not $cb.Text) { $cb.Text = [IO.Path]::GetFileNameWithoutExtension($dlg.FileName) }
        $state.Warnings = @($r.Warnings)
        if ($r.Warnings.Count -gt 0) { [VeroMsg]::Show(((@($r.Warnings) | ForEach-Object { '- ' + $_ }) -join "`r`n`r`n"), 'VeroScudo - check', 'OK', 'Warning') | Out-Null }
    }).GetNewClosure())
    $res = @{ Value = $null }
    $bCancel.Add_Click(({ $ef.Close() }).GetNewClosure())
    $bOk.Add_Click(({
        $t = $state.Type
        $name = $cb.Text.Trim(); $user = $tUser.Text.Trim(); $pins = if ($entry) { @($entry.ServerIps) } else { @() }
        if (-not $name) { [VeroMsg]::Show('A profile name is required.', 'VeroScudo') | Out-Null; return }
        if ($t -eq 'openvpn') {
            $import = $null; $importText = $null; $auth = $state.Auth
            if ($tFile.Text.Trim() -or -not $entry) {
                $src = $tFile.Text.Trim()
                if (-not $src -or -not (Test-Path -LiteralPath $src)) { [VeroMsg]::Show('Choose the .ovpn file to import.', 'VeroScudo') | Out-Null; return }
                $r = Test-VeroOpenVpnConf -Text ([IO.File]::ReadAllText($src)) -BaseDir (Split-Path -Parent $src)
                if ($r.Errors.Count -gt 0) { [VeroMsg]::Show("This config cannot be used:`r`n`r`n" + ($r.Errors -join "`r`n"), 'VeroScudo - OpenVPN config') | Out-Null; return }
                if (-not (Show-Check "OpenVPN config $([IO.Path]::GetFileName($src)):" $r.Warnings)) { return }
                $import = $src; $importText = $r.Text; $auth = $r.Auth      # the complete text, inlined here as you - the elevated save gets text, never a path
            }
            if ($auth -and -not $user) { [VeroMsg]::Show('This OpenVPN config asks for a username and password: enter the username.', 'VeroScudo') | Out-Null; return }
            $res.Value = [pscustomobject]@{ Profile = $name; Type = 'openvpn'; Server = ''; Port = 1194; Username = $user; ServerIps = @(); Auth = $auth; Dco = $chkDco.Checked; ImportFrom = $import; ImportText = $importText }
        } else {
            $port = 0
            if (-not $tServer.Text.Trim() -or -not [int]::TryParse($tPort.Text, [ref]$port)) { [VeroMsg]::Show('Server and port are required.', 'VeroScudo') | Out-Null; return }
            $th = Get-VeroTypeHandler $t                                   # the same rules config.json is checked against
            if ($th.UsernameRequired -and $state.Auth -and -not $user) { [VeroMsg]::Show('A username is required (the one you sign in to this VPN with).', 'VeroScudo') | Out-Null; return }
            if ($th.NamePattern -and $name -notmatch $th.NamePattern) { [VeroMsg]::Show(($th.NameHint.Substring(0, 1).ToUpper() + $th.NameHint.Substring(1)), 'VeroScudo') | Out-Null; return }
            if ($t -eq 'wireguard' -and -not (Show-Check "WireGuard tunnel '$name':" $state.Warnings)) { return }
            $res.Value = [pscustomobject]@{ Profile = $name; Type = $t; Server = $tServer.Text.Trim(); Port = $port; Username = $(if ($t -eq 'ras' -and $state.Auth) { $user } else { '' }); ServerIps = $pins; Auth = ($t -eq 'ras' -and $state.Auth); Dco = $false; ImportFrom = $null }
        }
        $ef.Close()
    }).GetNewClosure())
    @{ Form = $ef; Result = $res; TypeBox = $cbType }
}

function Edit-VpnProfile($entry) {
    <# Modal editor for one profile entry; returns the edited entry or $null (cancel). #>
    $x = New-VpnProfileForm $entry
    Show-Modal $x.Form "editor-$(if ($entry) { 'edit' } else { 'new' })"
    $x.Result.Value
}

function Save-ConfigElevated([string]$json, [object[]]$imports = @()) {
    <# The tray runs without admin rights: config.json is written by an elevated PowerShell (UAC prompt) that validates it
       again. Everything it needs - the config text and the OpenVPN configs to import ({ Profile; Text }, inlined here as
       the user) - goes in one payload file in the user's own folder; the elevated side reads that file, checks all of it
       and writes. Why a file: a command line is visible to every local process and to audit logs, and it is too short for
       a config with inlined keys. Why text, not paths: an elevated process must not open files a non-elevated one chose. #>
    $null = Get-VeroConfig -Raw $json                                       # validate here first for a readable error
    $payload = @{ Config = $json; Imports = @($imports | ForEach-Object { @{ Profile = [string]$_.Profile; Text = [string]$_.Text } }) } | ConvertTo-Json -Depth 4 -Compress
    New-Item -ItemType Directory -Path $global:Paths.UserDir -Force | Out-Null
    $file = Join-Path $global:Paths.UserDir ('save-' + [guid]::NewGuid().ToString('N') + '.json')
    [IO.File]::WriteAllText($file, $payload, (New-Object Text.UTF8Encoding($false)))
    try {
        $mod = (Join-Path $PSScriptRoot 'VeroScudo.Core.psm1') -replace "'", "''"
        $arg = $file -replace "'", "''"
        # the elevated child pins its module path first (a planted module in the user's Documents would otherwise run as admin)
        $sysMods = "`$env:PSModulePath = `"`$PSHOME\Modules;`" + (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'WindowsPowerShell\Modules'); "
        $script = $sysMods + "try { Import-Module '$mod' -Force; Import-VeroSavePayload -Path '$arg'; exit 0 } catch { exit 1 }"
        $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
        # full path: -Verb RunAs goes through ShellExecute, which resolves a bare name via the user's (writable) App Paths key
        $psExe = Join-Path (Get-VeroSystemDir System) 'WindowsPowerShell\v1.0\powershell.exe'
        # Process.Start, not Start-Process: Start-Process turns Windows' "cancelled" (1223) into localized text, and No on the
        # UAC prompt then showed as "Not saved: <a sentence in the system language>"
        $si = New-Object System.Diagnostics.ProcessStartInfo $psExe
        $si.Verb = 'runas'; $si.UseShellExecute = $true; $si.WindowStyle = 'Hidden'
        $si.Arguments = "-NoProfile -NonInteractive -EncodedCommand $enc"
        try { $pr = [System.Diagnostics.Process]::Start($si) }
        catch { if (Test-VeroUacCancelled $_.Exception) { throw 'administrator approval was cancelled - nothing was changed' }; throw }
        $pr.WaitForExit()
        if ($pr.ExitCode -ne 0) { throw "the elevated save failed (exit $($pr.ExitCode))" }
    } finally { Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue }   # the tray's own payload file, nothing else
}

$global:SettingsForm = $null
function Show-Settings {
    if ($global:SettingsForm -and -not $global:SettingsForm.IsDisposed) { $global:SettingsForm.Activate(); return }
    $f = New-Form 'VeroScudo settings' 520 666
    # three tabs (the same on Linux and macOS): VPN profiles, Behaviour, Connection - drawn here in the theme's colours
    # (WinForms' TabControl paints its strip light grey on the dark theme)
    $pages = @(); $tabs = @()
    foreach ($i in 0..2) {
        $pg = New-Object System.Windows.Forms.Panel; $pg.Location = (P 0 64); $pg.Size = (Z 520 490); $pg.BackColor = $global:Theme.Bg; $f.Controls.Add($pg); $pages += $pg
        $t = New-Label $f (@('VPN profiles', 'Behaviour', 'Connection')[$i]) (20 + $i * 130) 14 120 30 $FontBold; $t.TextAlign = 'MiddleCenter'; $t.Cursor = 'Hand'; $tabs += $t
    }
    $bar = New-Object System.Windows.Forms.Panel; $bar.Location = (P 20 44); $bar.Size = (Z 120 3); $bar.BackColor = $global:Theme.Accent; $f.Controls.Add($bar)
    $line = New-Object System.Windows.Forms.Panel; $line.Location = (P 20 47); $line.Size = (Z 480 1); $line.BackColor = $global:Theme.Border; $f.Controls.Add($line)
    $selectTab = ({ param([int]$n)
        foreach ($k in 0..2) { $pages[$k].Visible = ($k -eq $n); $tabs[$k].ForeColor = if ($k -eq $n) { $global:Theme.Text } else { $global:Theme.Sub } }
        $bar.Left = $tabs[$n].Left
    }).GetNewClosure()
    foreach ($i in 0..2) { $idx = $i; $tabs[$i].Add_Click(({ & $selectTab $idx }).GetNewClosure()) }
    & $selectTab 0
    $global:SettingsTab = $selectTab                                        # -Preview shows every tab
    $card = New-Card $pages[0] 20 0 480 300
    $work = New-Object System.Collections.ArrayList
    if ($global:Config) { foreach ($pr in $global:Config.Profiles) { [void]$work.Add(($pr | Select-Object *, @{ n = 'ImportFrom'; e = { $null } }, @{ n = 'ImportText'; e = { $null } })) } }
    # no "default" to choose: the profile selected in the tray menu is used (the guard keeps it across reboots). config.json's
    # activeProfile is only the fallback when nothing is selected yet (first start, the selected profile removed): Save writes
    # the profile in use there, or the first one when that was removed.
    $state = @{ Active = $(if ($global:Config) { $global:Config.Profile } else { '' }) }
    $lb = New-Object System.Windows.Forms.ListBox; $lb.Location = (P 12 12); $lb.Size = (Z 284 276); $lb.BorderStyle = 'FixedSingle'
    $lb.BackColor = $global:Theme.Bg; $lb.ForeColor = $global:Theme.Text; $lb.Font = $FontUI; $lb.IntegralHeight = $false
    $lb.Add_HandleCreated({ [VeroNative]::DarkScroll($this.Handle, $global:Dark) })
    $card.Controls.Add($lb)
    $fill = ({
        $sel = $lb.SelectedIndex; $lb.Items.Clear()
        foreach ($pr in $work) {
            $needs = Test-VeroNeedsPassword $pr
            $cred = (-not $needs) -or [bool](Get-VeroCredential -Config $pr)
            $mark = if ($pr.Profile -eq $state.Active) { ' (active)' } else { '' }
            $where = if ($pr.Type -eq 'openvpn') { $(if ($pr.ImportFrom) { 'to import' } else { '.ovpn' }) } else { $pr.Server }
            $null = $where                                                  # the server is in Edit; the list line must fit
            [void]$lb.Items.Add(('{0}{1} - {2}{3}' -f $pr.Profile, $mark, (Get-VeroTypeLabel $pr.Type), $(if ($cred) { '' } else { '  [no password]' })))
        }
        if ($lb.Items.Count -gt 0) { $lb.SelectedIndex = [Math]::Max(0, [Math]::Min($sel, $lb.Items.Count - 1)) }
    }).GetNewClosure()
    & $fill
    $bImp = New-Button $card 'Import from Windows...' 308 12 160 $true; $bAdd = New-Button $card 'Add...' 308 52 160
    $bEdit = New-Button $card 'Edit...' 308 92 160; $bDel = New-Button $card 'Remove' 308 132 160
    $bPw = New-Button $card 'Set password...' 308 180 160
    $bKey = New-Button $card 'Key passphrase...' 308 220 160
    $bImp.Add_Click(({
        $have = @($work | ForEach-Object Profile)
        $v = Select-WindowsVpn $have $(@($work | Where-Object { $_.Type -eq 'hiddify' }).Count -gt 0)
        if (-not $v) { return }
        if ($v.PSObject.Properties['Hiddify']) {                            # Hiddify in VPN mode: a profile without server or password
            $name = 'Hiddify'; $n = 2; while ($have -contains $name) { $name = "Hiddify $n"; $n++ }
            [void]$work.Add([pscustomobject]@{ Profile = $name; Type = 'hiddify'; Server = ''; Port = 443; Username = ''; ServerIps = @(); Dco = $false; Auth = $false; ImportFrom = $null; ImportText = $null })
            & $fill; $lb.SelectedIndex = $lb.Items.Count - 1
            return
        }
        $e = ConvertTo-VeroRasEntry -Vpn $v -UserName (Get-VeroRasSavedUser -Name $v.Name -AllUsers $v.AllUsers)
        if ($e.Auth -and -not $e.Username) { $e = Edit-VpnProfile $e }            # the one thing Windows did not tell us
        if (-not $e) { return }
        [void]$work.Add($e)
        Request-ProfilePassword $e                                              # now, not "later in Settings": it gets forgotten
        & $fill; $lb.SelectedIndex = $lb.Items.Count - 1
    }).GetNewClosure())
    $bAdd.Add_Click(({ $e = Edit-VpnProfile $null; if ($e) { if (@($work | Where-Object Profile -eq $e.Profile)) { [VeroMsg]::Show("'$($e.Profile)' is already in the list.", 'VeroScudo') | Out-Null; return }; [void]$work.Add($e); Request-ProfilePassword $e; & $fill; $lb.SelectedIndex = $lb.Items.Count - 1 } }).GetNewClosure())
    $bEdit.Add_Click(({ $i = $lb.SelectedIndex; if ($i -lt 0) { return }; if ($work[$i].Type -eq 'hiddify') { [VeroMsg]::Show('Nothing to edit: a Hiddify profile takes its servers from the Hiddify app. Connect, disconnect and reconnect it in Hiddify (VPN mode).', 'VeroScudo') | Out-Null; return }; $e = Edit-VpnProfile $work[$i]; if ($e) { if ($state.Active -eq $work[$i].Profile) { $state.Active = $e.Profile }
        if ($work[$i].PSObject.Properties['Id'] -and $work[$i].Id) { $e | Add-Member -NotePropertyName Id -NotePropertyValue $work[$i].Id -Force }   # a rename keeps the statistics
        $work[$i] = $e; & $fill } }).GetNewClosure())
    $bDel.Add_Click(({ $i = $lb.SelectedIndex; if ($i -lt 0 -or $work.Count -le 1) { return }; $gone = $work[$i].Profile
        if ([VeroMsg]::Show("Remove '$gone' from VeroScudo?`r`n`r`nOnly VeroScudo forgets it - the VPN itself stays in Windows. You do not need to remove profiles to use another one: select it in the tray menu (VPN profile).", 'VeroScudo', 'YesNo', 'Question') -ne 'Yes') { return }; $work.RemoveAt($i); & $fill }).GetNewClosure())
    $bPw.Add_Click(({
        $i = $lb.SelectedIndex; if ($i -lt 0) { return }; $e = $work[$i]
        if (-not (Test-VeroNeedsPassword $e)) { [VeroMsg]::Show("'$($e.Profile)' needs no password here$(if ($e.Type -eq 'wireguard') { ' - the WireGuard app keeps its keys' } elseif ($e.Type -eq 'hiddify') { ' - the Hiddify app keeps its servers and keys' }).", 'VeroScudo') | Out-Null; return }
        $sec = Read-Password "$($e.Username) ($($e.Profile))"
        if ($sec) { $cp = Get-VeroPath -VpnProfile $e.Profile; New-Item -ItemType Directory -Path $cp.UserDir -Force | Out-Null
                    New-Object System.Management.Automation.PSCredential($e.Username, $sec) | Export-Clixml $cp.Cred; & $fill }
    }).GetNewClosure())
    $bKey.Add_Click(({
        $i = $lb.SelectedIndex; if ($i -lt 0) { return }; $e = $work[$i]
        if ($e.Type -ne 'openvpn') { [VeroMsg]::Show('Only an OpenVPN profile with an encrypted private key needs a key passphrase.', 'VeroScudo') | Out-Null; return }
        $sec = Read-Password "the private key of $($e.Profile)"
        if ($sec) { $cp = Get-VeroPath -VpnProfile $e.Profile; New-Item -ItemType Directory -Path $cp.UserDir -Force | Out-Null
                    New-Object System.Management.Automation.PSCredential('key', $sec) | Export-Clixml $cp.KeyPass }
    }).GetNewClosure())
    # each option: a short label and one grey line saying what it does (a long label was cut off; "Wi-Fi reset fix" said nothing)
    $card2 = New-Card $pages[1] 20 0 480 330
    $optY = 12
    $addOpt = {
        param([string]$label, [string]$about, [bool]$on, [bool]$locked)
        $c = New-ThemedCheck; $c.Text = $label; $c.Checked = $on; $c.Location = (P 12 $optY); $c.Size = (Z 450 24)
        $c.ForeColor = if ($locked) { $global:Theme.Sub } else { $global:Theme.Text }
        if ($locked) { $c.AutoCheck = $false }
        $card2.Controls.Add($c)
        $d = New-WrapLabel $card2 $about 38 ($optY + 25) 424 $FontSmall $global:Theme.Sub
        Set-Variable -Name optY -Scope 1 -Value ([int](Get-Logical $d.Bottom) + 9)
        $c
    }
    $chkStrict = & $addOpt 'Strict kill-switch (always on)' 'When the VPN drops, nothing leaves this PC until it is back or you turn the VPN off.' $true $true
    $chkVm = & $addOpt 'Protect VMs and containers' 'WSL, Docker and Hyper-V VMs follow the kill-switch too. Off: VeroScudo leaves them alone. Never covered: a VM in bridged mode (VirtualBox, VMware, an external Hyper-V switch) - it goes to the network directly, past VeroScudo.' ((-not $global:Config) -or [bool]$global:Config.Vm) $false
    $chkWifi = & $addOpt 'Keep Wi-Fi stable while reconnecting' 'Stops Windows from resetting the Wi-Fi adapter about 15 s after a redial, which would drop the new VPN connection. Recommended.' ((-not $global:Config) -or [bool]$global:Config.WifiRecoveryFix) $false
    $chkUpd = & $addOpt 'Check for updates when the tray starts' 'Asks GitHub for the latest version, never while blocked. Nothing is installed automatically.' ((-not $global:Config) -or [bool]$global:Config.UpdateCheck) $false
    $chkLoc = & $addOpt 'Show exit location' 'Shows the country and IP your traffic leaves from (asks ipinfo.io after each connect).' ([bool](Test-ExitEnabled)) $false
    $null = $chkStrict
    $card2.Height = [int](($optY + 3) * $global:Scale)                    # as tall as its options need
    $chkLoc.Add_CheckedChanged({ Set-TrayPref 'showExit' $this.Checked })   # your own setting: saved at once, no administrator prompt
    # Connection: optional quality checks through the tunnel while protected (66-Quality.ps1). The fields show only when ticked.
    $chk = if ($global:PreviewCheck) { $global:PreviewCheck } elseif ($global:Config) { $global:Config.ConnectionCheck } else { ConvertFrom-VeroCheckConfig $null }
    $card3 = New-Card $pages[2] 20 0 480 486
    $chkQ = New-ThemedCheck; $chkQ.Text = 'Check the connection quality while protected'; $chkQ.Location = (P 12 12); $chkQ.Size = (Z 450 24); $chkQ.ForeColor = $global:Theme.Text; $chkQ.Checked = [bool]$chk.Enabled; $card3.Controls.Add($chkQ)
    $more = New-Object System.Windows.Forms.Panel; $more.Location = (P 1 44); $more.Size = (Z 476 340); $more.BackColor = $global:Theme.Card; $card3.Controls.Add($more)
    New-Label $more 'Check every' 12 5 112 22 | Out-Null
    $inEvery = New-Input $more 128 2 60 ([string]$chk.IntervalSeconds)
    New-Label $more 'seconds (10-100)' 196 6 220 22 $FontSmall $global:Theme.Sub | Out-Null
    New-Label $more 'Rate the last' 12 41 112 22 | Out-Null
    $inOver = New-Input $more 128 38 60 ([string]$chk.WindowMinutes)
    New-Label $more 'minutes (1-10)' 196 42 220 22 $FontSmall $global:Theme.Sub | Out-Null
    New-Label $more 'Good: under 10 % lost. Unstable: 10-50 % or slow (over 1 s). Bad: over 50 %.' 12 76 452 20 $FontSmall $global:Theme.Sub | Out-Null
    New-Label $more 'Addresses - IP, host name or URL; at least one' 12 104 452 22 | Out-Null
    $rows = @()
    foreach ($i in 0..2) {
        $t = if ($i -lt @($chk.Targets).Count) { @($chk.Targets)[$i] } else { $null }
        $y = 132 + $i * 40
        $inHost = New-Input $more 12 $y 228 $(if ($t) { [string]$t.Host } else { '' })
        $cbM = New-Object VeroCombo; $cbM.Location = (P 248 $y); $cbM.Size = (Z 116 30); $cbM.DropDownStyle = 'DropDownList'; $cbM.FlatStyle = 'Flat'; $cbM.BackColor = $global:Theme.Card; $cbM.ForeColor = $global:Theme.Text; $cbM.Font = $FontUI; Set-DarkCombo $cbM
        [void]$cbM.Items.Add('Ping'); [void]$cbM.Items.Add('TCP port'); [void]$cbM.Items.Add('HTTPS'); $more.Controls.Add($cbM)
        $cbM.SelectedIndex = if ($t -and $t.Method -eq 'ping') { 0 } elseif ($t -and $t.Method -eq 'https') { 2 } else { 1 }
        $inPort = New-Input $more 372 $y 92 $(if ($t -and $t.Method -in 'tcp', 'https') { [string]$t.Port } else { '443' })
        $syncPort = ({ $tcp = ($cbM.SelectedIndex -ge 1); $inPort.ReadOnly = -not $tcp; $inPort.TabStop = $tcp; $inPort.ForeColor = if ($tcp) { $global:Theme.Text } else { $global:Theme.Sub } }).GetNewClosure()
        & $syncPort; $cbM.Add_SelectedIndexChanged($syncPort)
        if ($i -eq 0) { $inHost.Add_Leave({ if (-not $this.Text.Trim()) { $this.Text = '1.1.1.1' } }) }   # never empty: there is always one address
        $rows += [pscustomobject]@{ Host = $inHost; Method = $cbM; Port = $inPort }
    }
    $hint = New-WrapLabel $more 'HTTPS checks the real way to a web service (any answer counts) - e.g. api.anthropic.com. No account or key is used.' 12 254 452 $FontSmall $global:Theme.Sub
    New-WrapLabel $more 'The first rating comes one full period after each connect and each change. The checks go through the VPN tunnel; local addresses are blocked (unless lanAllow lets them through).' 12 ((Get-Logical $hint.Bottom) + 4) 452 $FontSmall $global:Theme.Sub | Out-Null
    # a service's status page (per user, saved at once): shown in the status window; independent of the checks above
    $chkSp = New-ThemedCheck; $chkSp.Text = 'Show a service status page in the status window'; $chkSp.Location = (P 12 390); $chkSp.Size = (Z 450 24); $chkSp.ForeColor = $global:Theme.Text
    $chkSp.Checked = [bool](Test-StatusPageEnabled); $card3.Controls.Add($chkSp)
    $inSp = New-Input $card3 38 420 426 (Get-StatusPageUrl)
    New-Label $card3 'Atlassian Statuspage format (.../api/v2/status.json) - Anthropic''s by default.' 38 454 426 20 $FontSmall $global:Theme.Sub | Out-Null
    $saveSp = ({
        $u = $inSp.Text.Trim(); if (-not $u) { $u = $global:SvcDefaultUrl; $inSp.Text = $u }
        if ($u -notmatch '^https://[^\s]+$' -or $u.Length -gt 300) { [VeroMsg]::Show('The status page must be an https:// address', 'VeroScudo') | Out-Null; $inSp.Text = (Get-StatusPageUrl); return }
        if ($u -ne (Get-StatusPageUrl)) { Set-TrayPref 'statusPageUrl' $u; $global:SvcResult = $null; Start-StatusPageFetch -Now }
    }).GetNewClosure()
    $inSp.Add_Leave($saveSp)
    $chkSp.Add_CheckedChanged(({ Set-TrayPref 'statusPage' $chkSp.Checked; if ($chkSp.Checked) { & $saveSp; $global:SvcResult = $null; Start-StatusPageFetch -Now } }).GetNewClosure())
    $more.Visible = $chkQ.Checked
    $chkQ.Add_CheckedChanged(({ $more.Visible = $chkQ.Checked }).GetNewClosure())
    New-Label $f 'Passwords, the exit location and the status page switches are saved at once (your account only). Saving the rest writes config.json (administrator prompt).' 20 562 480 36 $FontSmall $global:Theme.Sub | Out-Null
    $bCancel = New-Button $f 'Close' 270 612 110
    $bSave   = New-Button $f 'Save' 390 612 110 $true
    $bCancel.Add_Click(({ $f.Close() }).GetNewClosure())
    $bSave.Add_Click(({
        if ($work.Count -eq 0) { [VeroMsg]::Show('Add at least one VPN profile.', 'VeroScudo') | Out-Null; return }
        $num = { param($box, [int]$fallback) $v = 0; if ([int]::TryParse($box.Text.Trim(), [ref]$v)) { $v } elseif (-not $box.Text.Trim()) { $fallback } else { throw "'$($box.Text.Trim())' is not a whole number." } }
        try {
            $check = ConvertFrom-VeroCheckForm -Enabled $chkQ.Checked -IntervalSeconds (& $num $inEvery 10) -WindowMinutes (& $num $inOver 1) -Rows @($rows | ForEach-Object {
                @{ Text = $_.Host.Text; Method = @('ping', 'tcp', 'https')[[Math]::Max(0, $_.Method.SelectedIndex)]; Port = $(if ($_.Method.SelectedIndex -eq 0) { 443 } else { & $num $_.Port 443 }) } })
        } catch { & $selectTab 2; [VeroMsg]::Show("Not saved (Connection): $($_.Exception.Message)", 'VeroScudo') | Out-Null; return }
        Set-VeroProfileIds -Entries @($work)                                # each profile's lasting id (statistics follow it)
        $json = [ordered]@{
            profiles = @($work | ForEach-Object { ConvertTo-VeroProfileObject $_ })
            activeProfile = $(if (@($work | ForEach-Object Profile) -contains $state.Active) { $state.Active } else { $work[0].Profile })
            retrySeconds = $(if ($global:Config) { $global:Config.RetrySeconds } else { 10 }); vm = [bool]$chkVm.Checked
            wifiRecoveryFix = $chkWifi.Checked; updateCheck = $chkUpd.Checked; lanAllow = @($(if ($global:Config) { $global:Config.LanAllow } else { @() }))
            connectionCheck = ConvertTo-VeroCheckObject $check
        } | ConvertTo-Json -Depth 6
        $imports = @($work | Where-Object { $_.Type -eq 'openvpn' -and $_.ImportFrom } | ForEach-Object { [pscustomobject]@{ Profile = $_.Profile; Text = $_.ImportText } })
        try {
            Save-ConfigElevated $json $imports; $global:Config = Get-VeroConfig; Update-ProfileMenu; $f.Close()
        }
        catch { [VeroMsg]::Show("Not saved: $($_.Exception.Message)", 'VeroScudo') | Out-Null }
    }).GetNewClosure())
    $global:SettingsForm = $f
    $f.Show(); $f.Activate(); $bCancel.Focus() | Out-Null
    $f
}

# ---------------------------------------------------------------- statistics window: 7 days of VPN time and quality
# One row per day, 24 h wide, one bar per 10 minutes on a shared time grid (a problem at the same hour every day lines up
# in one column). Data: the guard's state\stats day files (67-Stats.ps1). Hover a bar for its time and numbers.
$global:StatsForm = $null; $global:PreviewStats = $null
function Get-StatsRaw {
    <# The last 7 days' files, today first: per profile id its minutes, and the names (Read-VeroStatsDay). #>
    $now = Get-Date
    foreach ($i in 0..6) { if ($global:PreviewStats) { $global:PreviewStats[$i] } else { Read-VeroStatsDay -Date $now.Date.AddDays(-$i) } }
}
function Get-StatsChoices([object[]]$raw) {
    $cfg = $global:Config
    @(Get-VeroStatsChoices -Days $raw -Profiles $(if ($cfg) { @($cfg.Profiles) } else { @() }) -ActiveId $(if ($cfg) { [string]$cfg.ProfileId } else { '' }))
}
function Get-StatsDays([object[]]$raw, [string]$id) {
    <# The 7 rows of one profile (by its lasting id), today first. #>
    $now = Get-Date
    foreach ($i in 0..6) {
        $d = $now.Date.AddDays(-$i)
        $mins = if ($id -and $raw[$i].Data.ContainsKey($id)) { $raw[$i].Data[$id] } else { @{} }
        $until = if ($i -eq 0) { $now.Hour * 60 + $now.Minute + 1 } else { 1440 }
        $row = ConvertTo-VeroStatsDay -Minutes $mins -BucketMinutes 10 -UntilMinute $until
        $name = if ($i -eq 0) { 'Today' } elseif ($i -eq 1) { 'Yesterday' } else { $d.ToString('dddd', [Globalization.CultureInfo]::InvariantCulture) }
        [pscustomobject]@{ Label = '{0}, {1}' -f $name, $d.ToString('d MMM', [Globalization.CultureInfo]::InvariantCulture); Row = $row }
    }
}
function Show-Stats {
    if ($global:StatsForm -and -not $global:StatsForm.IsDisposed) { $global:StatsForm.Activate(); return }
    $f = New-Form 'VeroScudo - Statistics' 640 682
    New-Label $f 'Last 7 days' 20 16 300 30 $FontBig | Out-Null
    New-Label $f 'One bar = 10 minutes. Hover a bar for its time and numbers.' 20 50 600 20 $FontSmall $global:Theme.Sub | Out-Null
    # one VPN profile at a time: a corporate VPN and a home one are different connections - their problems never mix
    New-Label $f 'VPN profile' 20 82 90 22 | Out-Null
    $pick = New-Object VeroCombo; $pick.Location = (P 112 78); $pick.Size = (Z 300 30); $pick.DropDownStyle = 'DropDownList'; $pick.FlatStyle = 'Flat'
    $pick.BackColor = $global:Theme.Card; $pick.ForeColor = $global:Theme.Text; $pick.Font = $FontUI; Set-DarkCombo $pick; $f.Controls.Add($pick)
    $card = New-Card $f 20 112 600 438
    # geometry in logical px; the strip is 144 bars x 4 px (3 px bar + 1 px gap) = 576 px
    $g = @{ X = 12; Top = 30; RowH = 57; BarW = 4; StripH = 24; LabelH = 20 }
    $chart = New-Object System.Windows.Forms.Panel; $chart.Location = (P 0 0); $chart.Size = (Z 600 438); $chart.BackColor = $global:Theme.Card
    $card.Controls.Add($chart)
    # double buffering: a repaint on every hover would flicker otherwise
    $chart.GetType().GetProperty('DoubleBuffered', [Reflection.BindingFlags]'NonPublic,Instance').SetValue($chart, $true, $null)
    $global:StatsIds = @()
    # (re)reads the files: the drop-down keeps the shown profile (by id: a rename keeps it), the chart follows it
    $reload = ({
        $raw = @(Get-StatsRaw)
        $cur = if ($pick.SelectedIndex -ge 0 -and $pick.SelectedIndex -lt $global:StatsIds.Count) { $global:StatsIds[$pick.SelectedIndex] } else { '' }
        $ch = Get-StatsChoices $raw
        $global:StatsLoading = $true
        $pick.Items.Clear(); foreach ($c in $ch) { [void]$pick.Items.Add($c.Label) }
        $global:StatsIds = @($ch | ForEach-Object Id)
        $at = [array]::IndexOf([string[]]$global:StatsIds, [string]$cur)
        $pick.SelectedIndex = if ($at -ge 0) { $at } elseif ($global:StatsIds.Count) { 0 } else { -1 }
        $global:StatsLoading = $false
        $global:StatsRawNow = $raw
        $global:StatsDaysNow = @(Get-StatsDays $raw $(if ($pick.SelectedIndex -ge 0) { $global:StatsIds[$pick.SelectedIndex] } else { '' }))
        $chart.Invalidate()
    }).GetNewClosure()
    $fSmall = $FontSmall; $fUI = $FontUI                                   # local copies: the handlers below are closures
    $colors = @{
        good = [System.Drawing.Color]::FromArgb(48, 200, 79); up = [System.Drawing.Color]::FromArgb(48, 200, 79)
        unstable = [System.Drawing.Color]::FromArgb(232, 163, 61); bad = [System.Drawing.Color]::FromArgb(154, 74, 42)   # amber, brown: one calm palette with the green
        off = $(if ($global:Dark) { [System.Drawing.Color]::FromArgb(70, 70, 70) } else { [System.Drawing.Color]::FromArgb(205, 205, 205) })
    }
    $chart.Add_Paint(({ param($s, $e)
        $gr = $e.Graphics; $k = $global:Scale
        $sub = New-Object System.Drawing.SolidBrush($global:Theme.Sub); $txt = New-Object System.Drawing.SolidBrush($global:Theme.Text)
        $grid = New-Object System.Drawing.Pen($global:Theme.Border); $grid.DashStyle = 'Dot'
        # the time grid: every 3 hours, labels on top, lines through all rows
        foreach ($h in 0..8) {
            $x = ($g.X + $h * 18 * $g.BarW) * $k
            $lab = '{0:00}' -f ($h * 3)
            $w = $gr.MeasureString($lab, $fSmall).Width
            $lx = [Math]::Min([Math]::Max($x - $w / 2, 0), $s.Width - $w)
            $gr.DrawString($lab, $fSmall, $sub, $lx, 8 * $k)
            $gr.DrawLine($grid, $x, ($g.Top - 4) * $k, $x, ($g.Top + 7 * $g.RowH - 8) * $k)
        }
        $i = 0
        foreach ($day in $global:StatsDaysNow) {
            $y = $g.Top + $i * $g.RowH
            $gr.DrawString($day.Label, $fUI, $txt, ($g.X - 2) * $k, $y * $k)
            $tot = Format-VeroStatsTotal -Day $day.Row
            $tw = $gr.MeasureString($tot, $fSmall).Width
            $gr.DrawString($tot, $fSmall, $sub, ($g.X + 144 * $g.BarW) * $k - $tw, ($y + 2) * $k)
            $by = ($y + $g.LabelH + 2) * $k
            foreach ($b in $day.Row.Bars) {
                if ($b.State -eq 'future') { continue }
                $bx = ($g.X + ($b.Start / 10) * $g.BarW) * $k
                $br = New-Object System.Drawing.SolidBrush($colors[$b.State])
                $gr.FillRectangle($br, [single]$bx, [single]$by, [single](($g.BarW - 1) * $k), [single]($g.StripH * $k))
                $br.Dispose()
            }
            $i++
        }
        $sub.Dispose(); $txt.Dispose(); $grid.Dispose()
    }).GetNewClosure())
    $tip = New-Object System.Windows.Forms.ToolTip; $tip.InitialDelay = 100; $tip.ReshowDelay = 50
    $chart.Add_MouseMove(({ param($s, $e)
        $k = $global:Scale; $lx = $e.X / $k; $ly = $e.Y / $k
        $row = [int][Math]::Floor(($ly - $g.Top) / $g.RowH); $inRow = ($ly - $g.Top) - $row * $g.RowH
        $bar = [int][Math]::Floor(($lx - $g.X) / $g.BarW)
        $text = ''
        if ($row -ge 0 -and $row -lt 7 -and $bar -ge 0 -and $bar -lt 144 -and $inRow -ge $g.LabelH -and $inRow -le ($g.LabelH + 2 + $g.StripH)) {
            $day = $global:StatsDaysNow[$row]
            $text = "$($day.Label)  " + (Format-VeroStatsBar -Bar $day.Row.Bars[$bar])
        }
        if ($tip.GetToolTip($s) -ne $text) { $tip.SetToolTip($s, $text) }
    }).GetNewClosure())
    $pick.Add_SelectedIndexChanged(({
        if ($global:StatsLoading -or $pick.SelectedIndex -lt 0) { return }
        $global:StatsDaysNow = @(Get-StatsDays $global:StatsRawNow $global:StatsIds[$pick.SelectedIndex]); $chart.Invalidate()
    }).GetNewClosure())
    & $reload
    # legend
    $ly = 560; $lx = 20
    foreach ($it in @(@('good', 'Good (or connected, not rated)'), @('unstable', 'Unstable'), @('bad', 'Bad or could not connect'), @('off', 'Not connected'))) {
        $sw = New-Object System.Windows.Forms.Panel; $sw.Location = (P $lx ($ly + 4)); $sw.Size = (Z 12 12); $sw.BackColor = $colors[$it[0]]; $f.Controls.Add($sw)
        $w = switch ($it[0]) { 'good' { 190 } 'bad' { 160 } 'off' { 100 } default { 80 } }
        New-Label $f $it[1] ($lx + 18) $ly $w 20 $FontSmall $global:Theme.Sub | Out-Null
        $lx += $w + 14
    }
    New-Label $f 'Good: under 10 % of the checks lost; unstable: 10-50 %, or slow answers (over 1 s); bad: over 50 % lost. Ratings need Settings > Connection; without it, connected time is green.' 20 584 600 40 $FontSmall $global:Theme.Sub | Out-Null
    $bRef = New-Button $f 'Refresh' 400 630 100
    $bRef.Add_Click($reload)
    (New-Button $f 'Close' 510 630 110 $true).Add_Click(({ $f.Close() }).GetNewClosure())
    # a minute later the picture has moved on: refresh while open
    $timer = New-Object System.Windows.Forms.Timer; $timer.Interval = 60000
    $timer.Add_Tick($reload)
    $f.Add_FormClosed(({ $timer.Stop(); $timer.Dispose() }).GetNewClosure())
    if (-not $global:PreviewDir) { $timer.Start() }
    $global:StatsForm = $f
    $f.Show(); $f.Activate(); $f
}

function Show-About {
    $f = New-Form 'About VeroScudo' 400 250
    $pic = New-Object System.Windows.Forms.PictureBox; $pic.Location = (P 24 24); $pic.Size = (Z 64 64); $pic.SizeMode = 'Zoom'; $pic.Image = Get-AppImage 128; $f.Controls.Add($pic)
    New-Label $f "VeroScudo $(Get-VeroVersion)" 104 24 260 30 $FontBig | Out-Null
    New-Label $f 'Master the switch.' 104 58 260 22 $FontUI $global:Theme.Sub | Out-Null
    New-Label $f 'VPN on + connection lost = no network until the VPN is back or you turn it off. Two actions, no backdoor.' 24 104 352 48 $FontSmall $global:Theme.Sub | Out-Null
    $link = New-Object System.Windows.Forms.LinkLabel; $link.Text = 'github.com/GomelHawk/VeroScudo'; $link.Location = (P 24 160); $link.Size = (Z 300 22); $link.LinkColor = $global:Theme.Accent; $link.ActiveLinkColor = $global:Theme.Accent; $link.BackColor = 'Transparent'; $link.Add_LinkClicked({ Start-Process 'https://github.com/GomelHawk/VeroScudo' }); $f.Controls.Add($link)
    (New-Button $f 'Close' 266 196 110 $true).Add_Click(({ $f.Close() }).GetNewClosure())
    $f.Show(); $f.Activate(); $f
}

# ---------------------------------------------------------------- tray icon + menu
$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Visible = $true
$menu = New-Object System.Windows.Forms.ContextMenuStrip
$menu.Renderer = New-Object VeroMenuRenderer($global:Theme, [single]$global:Scale); $menu.Font = $FontUI; $menu.ShowImageMargin = $true; $menu.ShowCheckMargin = $false; $menu.ImageScalingSize = Z 18 18
$iconPx = (Z 18 18).Width
# the items' (empty) image sets the icon column's width: wider than the icon, so the column holds the card's inset and the
# menu counts it in its width (the renderer draws the icon itself; item padding is not counted - items were clipped)
$blankImage = New-Object System.Drawing.Bitmap((Z 42 18).Width, $iconPx)
$menu.Padding = Pad 0 8 0 8; $menu.BackColor = $global:Theme.Bg; $menu.ForeColor = $global:Theme.Text
$menu.Add_HandleCreated({ $this.Renderer.DwmFrame = [VeroNative]::MenuFrame($this.Handle, $global:Dark, $global:Theme.Border) })
# the cards are inset 8 px from both sides and the chevron sits inside the card: Windows sizes the menu without them (it
# ignores item and side padding there), so every opening adds that room as a minimum width
# and makes the gaps between the cards and the space under the last one as wide as the cards' side margin (the bottom
# padding is not counted either). Measured after a layout: the side margin depends on how wide Windows made the items.
function Set-MenuRoom($m) {
    $m.MinimumSize = [System.Drawing.Size]::Empty
    $pref = $m.GetPreferredSize([System.Drawing.Size]::Empty)
    $m.MinimumSize = New-Object System.Drawing.Size(($pref.Width + (Z 24 0).Width), 0); $m.PerformLayout()
    $gap = $m.Renderer.MenuMargin($m)
    foreach ($i in $m.Items) { if ($i -is [System.Windows.Forms.ToolStripSeparator]) { $i.Height = $gap } }
    $m.PerformLayout()
    $last = @($m.Items | Where-Object { $_.Available }) | Select-Object -Last 1
    $h = if ($last) { $last.Bounds.Bottom + $gap } else { $pref.Height }
    $m.MinimumSize = New-Object System.Drawing.Size($m.MinimumSize.Width, $h)
}
$menu.Add_Opening({ Set-MenuRoom $this })
function Add-MenuItem([string]$text, [string]$glyph, [scriptblock]$onClick) {
    $m = $menu.Items.Add($text); $m.Tag = $glyph; $m.Padding = (Pad 0 7 16 7); $m.Margin = New-Object System.Windows.Forms.Padding(0)
    if ($glyph) { $m.Image = $blankImage; $m.ImageScaling = 'None' }
    if ($onClick) { $m.Add_Click($onClick) }
    $m
}
function Add-MenuSeparator {
    # the gap between two cards: as high as the cards' side margins
    $sep = New-Object System.Windows.Forms.ToolStripSeparator; $sep.AutoSize = $false; $sep.Height = (Z 0 8).Height; $sep.Margin = Pad 0 0 0 0; $menu.Items.Add($sep) | Out-Null
}
$menu.Renderer.Logo = Get-AppImage 64
$mHead = Add-MenuItem 'VeroScudo' 'logo' $null; $mHead.Enabled = $false; $mHead.Font = $FontBold
$null = Add-MenuSeparator
$mOn   = Add-MenuItem 'Turn VPN on'  'play' { Request-TurnOn }   
$mOff  = Add-MenuItem 'Turn VPN off' 'stop' { Invoke-GuardTask 'Off' }  
$mRedo = Add-MenuItem 'Reconnect VPN' 'redo' { Request-Reconnect }
$mProf = Add-MenuItem 'VPN profile' 'globe' $null
$mProf.DropDown.Renderer = $menu.Renderer; $mProf.DropDown.BackColor = $global:Theme.Bg; $mProf.DropDown.ForeColor = $global:Theme.Text
$mProf.DropDown.Padding = Pad 0 8 0 8
$mProf.DropDown.Add_HandleCreated({ $this.Renderer.DwmFrame = [VeroNative]::MenuFrame($this.Handle, $global:Dark, $global:Theme.Border) })
$mProf.DropDown.Add_Opening({ Set-MenuRoom $this })
$global:TrayFile = Join-Path $global:Paths.UserDir 'tray.json'              # per-user tray choices (the state folder is read-only for the tray)
function Get-TrayPref { Get-VeroTrayPref -Path $global:TrayFile }
function Set-TrayPref([string]$key, $value) { Set-VeroTrayPref -Path $global:TrayFile -Key $key -Value $value }
function Test-KeepAwakeSaved { [bool](Get-TrayPref).keepAwake }
function Save-KeepAwake([bool]$on) { Set-TrayPref 'keepAwake' $on }
$global:ForeignCache = @{ Time = [datetime]::MinValue; Items = @() }
function Get-ForeignCached {
    # the status window refreshes every 3 s; the VPN list is asked for at most every 10 s
    if (((Get-Date) - $global:ForeignCache.Time).TotalSeconds -ge 10 -and $global:Config) {
        $global:ForeignCache = @{ Time = Get-Date; Items = @(try { Get-VeroForeignVpn -Config $global:Config } catch { @() }) }
    }
    $global:ForeignCache.Items
}

function Show-ForeignPrompt($foreign) {
    <# Before Turn on: another VPN is connected. Returns 'disconnect', 'anyway' or 'cancel'. Nothing happens without a click.
       A VPN app's own tunnel cannot be ended by VeroScudo: then "Turn on anyway" is offered too (and alone if nothing can be ended). #>
    $prof = $global:Config.Profile
    $can = @($foreign | Where-Object { $_.CanDisconnect })
    $cannot = @($foreign | Where-Object { -not $_.CanDisconnect })
    $names = ($foreign | ForEach-Object { '"' + $_.Name + '"' }) -join ', '
    $one = @($foreign).Count -eq 1
    $kindText = if ($one -and -not $foreign[0].Configured -and $foreign[0].Kind -ne 'app') { ' It is not a VeroScudo profile.' } elseif ($one -and $foreign[0].Configured) { ' It is another VeroScudo profile.' } else { '' }
    $msg = $names + $(if ($one) { ' is' } else { ' are' }) + ' connected.' + $kindText + "`r`n" +
           'VeroScudo will connect "' + $prof + '" and block everything else, including ' + $(if ($one) { 'its' } else { 'their' }) + ' traffic.'
    if ($cannot.Count -gt 0) { $msg += "`r`n`r`nVeroScudo cannot disconnect a VPN app's own tunnel (" + (($cannot | ForEach-Object Name) -join ', ') + ') - close that app first, or turn on anyway (its traffic stays blocked).' }
    $pf = New-Form 'VeroScudo - another VPN is connected' 540 250
    $bar = New-Object System.Windows.Forms.Panel; $bar.Location = (P 0 0); $bar.Size = (Z 5 4000); $bar.BackColor = $global:Amber; $pf.Controls.Add($bar)
    $l = New-WrapLabel $pf $msg 24 18 496 $FontUI
    $y = 18 + (Get-Logical $l.Height) + 22
    $res = @{ Value = 'cancel' }
    $btn = @()
    if ($can.Count -gt 0) {
        $label = if ($cannot.Count -gt 0) { 'Disconnect what it can and turn on' } elseif ($one) { 'Disconnect ' + $foreign[0].Name + ' and turn on' } else { 'Disconnect all and turn on' }
        $bGo = New-Button $pf $label 0 $y 100 $true; $bGo.Add_Click(({ $res.Value = 'disconnect'; $pf.Close() }).GetNewClosure()); $btn += $bGo
    }
    if ($cannot.Count -gt 0) {
        $bAny = New-Button $pf 'Turn on anyway' 0 $y 100 ($can.Count -eq 0); $bAny.Add_Click(({ $res.Value = 'anyway'; $pf.Close() }).GetNewClosure()); $btn += $bAny
    }
    $bNo = New-Button $pf 'Cancel' 0 $y 100; $bNo.Add_Click(({ $pf.Close() }).GetNewClosure()); $btn += $bNo
    # right-aligned, each as wide as its label (a long tunnel name must not be cut off)
    $x = [int](520 * $global:Scale)
    foreach ($b in @($btn[($btn.Count - 1)..0])) {
        $b.Width = [Math]::Max([int](100 * $global:Scale), [System.Windows.Forms.TextRenderer]::MeasureText($b.Text, $b.Font).Width + [int](28 * $global:Scale))
        $x -= $b.Width; $b.Left = $x; $x -= [int](10 * $global:Scale)
    }
    if ($x -lt [int](14 * $global:Scale)) { $grow = [int](14 * $global:Scale) - $x; foreach ($b in $btn) { $b.Left += $grow }; $pf.ClientSize = New-Object System.Drawing.Size(($pf.ClientSize.Width + $grow), $pf.ClientSize.Height) }
    $pf.ClientSize = New-Object System.Drawing.Size($pf.ClientSize.Width, [int](($y + 34 + 18) * $global:Scale))
    $pf.TopMost = $true; $pf.AcceptButton = $bNo; $pf.CancelButton = $bNo
    Show-Modal $pf 'foreign'
    $res.Value
}

function Request-TurnOn {
    <# Turn VPN on: first asks when another VPN is connected (it would be blocked silently otherwise). #>
    Set-TrayExpect 'connect'
    if (-not $global:Config) { Invoke-GuardTask 'On'; return }
    $foreign = @(try { Get-VeroForeignVpn -Config $global:Config } catch { @() })
    if ($foreign.Count -eq 0) { Invoke-GuardTask 'On'; return }
    switch (Show-ForeignPrompt $foreign) {
        'disconnect' { Invoke-GuardTask 'OnDisconnect' }
        'anyway'     { Invoke-GuardTask 'OnForce' }
        default      { Write-Verbose 'turn on cancelled' }
    }
}

$global:Stamps = @{}
function Test-FileChanged([string]$path) { Test-VeroTrayFileChanged -Path $path -Stamps $global:Stamps }
$global:ShownConflicts = @()
function Show-ForeignNotice {
    <# The guard refused On (shortcut, script), or a VPN that is not a VeroScudo profile connected while armed. #>
    if (Test-FileChanged $global:Paths.OnRefused) {
        try {
            $j = Get-Content $global:Paths.OnRefused -Raw | ConvertFrom-Json
            $notify.ShowBalloonTip(10000, 'VeroScudo was not turned on', ((@($j.Items) -join '; ') + '. Use Turn VPN on in the tray menu to choose.'), [System.Windows.Forms.ToolTipIcon]::Warning)
            return $true
        } catch { Write-Verbose 'on-refused unreadable' }
    }
    if (Test-FileChanged $global:Paths.Foreign) {
        try {
            $j = Get-Content $global:Paths.Foreign -Raw | ConvertFrom-Json
            $text = '"' + $j.Name + '" connected, but it is not a VeroScudo profile.' + "`n" + 'Its traffic is blocked. Disconnect it, or import it in Settings.'
            $notify.ShowBalloonTip(10000, 'VeroScudo - another VPN', $text, [System.Windows.Forms.ToolTipIcon]::Warning)
            return $true
        } catch { Write-Verbose 'foreign unreadable' }
    }
    if ((Test-FileChanged $global:Paths.Conflicts) -and (Test-VeroArmed)) {
        $now = @(Get-VeroConflictList)
        $new = @($now | Where-Object { $global:ShownConflicts -notcontains $_ })
        $global:ShownConflicts = $now
        if ($new.Count -gt 0) { $notify.ShowBalloonTip(10000, 'VeroScudo - another VPN', $new[0], [System.Windows.Forms.ToolTipIcon]::Warning); return $true }
    }
    $false
}

function Test-HiddifyProfile { [bool]($global:Config -and [string]$global:Config.Type -eq 'hiddify') }
function Request-Reconnect {
    <# Reconnect: the elevated task blocks traffic, hangs up and redials; traffic flows again once the tunnel is back. #>
    if (Test-HiddifyProfile) { $notify.ShowBalloonTip(5000, 'VeroScudo', 'Connect and reconnect in Hiddify - VeroScudo only keeps everything else blocked while its tunnel is down.', [System.Windows.Forms.ToolTipIcon]::Info); return }
    if (-not (Test-VeroArmed)) { $notify.ShowBalloonTip(4000, 'VeroScudo', 'The VPN is off - use Turn VPN on.', [System.Windows.Forms.ToolTipIcon]::Info); return }
    Set-TrayExpect 'reconnect'
    Invoke-GuardTask 'Reconnect'
    $notify.ShowBalloonTip(5000, 'VeroScudo - reconnecting', "Traffic is blocked while '$($global:Config.Profile)' reconnects; it flows again once the tunnel is back.", [System.Windows.Forms.ToolTipIcon]::Info)
}
function Show-SwitchNotice {
    <# On every switch to an OpenVPN or WireGuard profile (also a switch back): once, not again while it stays active. #>
    if (-not $global:Config) { return $false }
    $cur = $global:Config.Profile
    if ((Get-TrayPref).lastProfile -eq $cur) { return $false }
    Set-TrayPref 'lastProfile' $cur
    $n = Get-VeroSwitchNotice -Type $global:Config.Type -ProfileName $cur
    if (-not $n) { return $false }
    $notify.ShowBalloonTip(15000, "VeroScudo - $(Get-VeroTypeLabel $global:Config.Type) profile", $n, [System.Windows.Forms.ToolTipIcon]::Warning)
    $true
}
function Request-ProfileSwitch([string]$name) {
    <# The switch itself runs in the elevated Switch task; the tray only names the profile (checked there against config.json). #>
    New-Item -ItemType Directory -Path $global:Paths.UserDir -Force | Out-Null
    Set-Content -Path $global:Paths.SwitchRequest -Value $name -Encoding UTF8
    Set-TrayExpect 'switch'
    Invoke-GuardTask 'Switch'
    $notify.ShowBalloonTip(4000, 'VeroScudo', "Switching to '$name'$(if (Test-VeroArmed) { ' - traffic stays blocked until it is connected' })", [System.Windows.Forms.ToolTipIcon]::Info)
}
function Update-ProfileMenu {
    $mProf.DropDownItems.Clear()
    if (-not $global:Config) { $mProf.Enabled = $false; return }
    $mProf.Enabled = $true
    $mProf.Text = "VPN profile: $($global:Config.Profile) ($(Get-VeroTypeLabel $global:Config.Type))"
    foreach ($pr in $global:Config.Profiles) {
        $it = $mProf.DropDownItems.Add(('{0}  ({1})' -f $pr.Profile, (Get-VeroTypeLabel $pr.Type)))
        $it.Padding = (Pad 0 7 16 7); $it.Image = $blankImage; $it.ImageScaling = 'None'
        $it.Tag = if ($pr.Profile -eq $global:Config.Profile) { 'check' } else { '' }
        $name = $pr.Profile
        $it.Add_Click(({ if ($name -ne $global:Config.Profile) { Request-ProfileSwitch $name } }).GetNewClosure())
    }
}
$null = Add-MenuSeparator
$null = Add-MenuItem 'Status'       'info' { Show-Status | Out-Null }  
$null = Add-MenuItem 'Open log'     'log' { if (Test-Path $global:Paths.Log) { Start-Process notepad.exe $global:Paths.Log } }
$null = Add-MenuItem 'Statistics'   'chart' { Show-Stats | Out-Null }
$null = Add-MenuItem 'Settings'     'gear' { Show-Settings | Out-Null }
$mAwake = Add-MenuItem 'Keep awake' 'awake' {
    $want = $mAwake.Checked; $on = [VeroKeepAwake]::Set($want); $mAwake.Checked = $on; Save-KeepAwake $on
    if ($want -and -not $on) { $notify.ShowBalloonTip(4000, 'VeroScudo', 'Keep awake is not available on this system.', [System.Windows.Forms.ToolTipIcon]::Warning) }
    Refresh
}
$mAwake.CheckOnClick = $true; $mAwake.Checked = [VeroKeepAwake]::Set((Test-KeepAwakeSaved))
$null = Add-MenuSeparator
$mUpd  = Add-MenuItem 'Check for updates' 'sync' { Invoke-UpdateCheck -Force; if ($global:Update -and (Test-VeroReleaseUrl $global:Update.Url)) { Start-Process $global:Update.Url } else { $notify.ShowBalloonTip(4000, 'VeroScudo', "You have the latest version ($(Get-VeroVersion)).", [System.Windows.Forms.ToolTipIcon]::Info) } }
$null = Add-MenuItem 'About VeroScudo' 'help' { Show-About | Out-Null }
$null = Add-MenuItem 'Exit tray (guard keeps running)' 'power' { [VeroKeepAwake]::Set($false) | Out-Null; $notify.Visible = $false; [System.Windows.Forms.Application]::Exit() }
# size every item from the widest label (ToolStrip ignores padding when measuring) : icon column 42 + text + 24
$notify.ContextMenuStrip = $menu
Update-ConfigCache | Out-Null; Update-ProfileMenu
$notify.Add_MouseClick({ param($src, $e) $null = $src; if ($e.Button -eq [System.Windows.Forms.MouseButtons]::Left) { Show-Status | Out-Null } })

function Invoke-UpdateCheck([switch]$Force) {
    # once per tray start (2 min after launch), only while traffic is allowed (never while blocked), opt-out via config updateCheck=false
    if (-not $global:Config -or ($global:Config.UpdateCheck -eq $false -and -not $Force)) { return }
    $st = Get-State; if ($st.State -eq 'blocked') { return }
    $info = @{ checked = '1970-01-01'; notified = '' }
    if (Test-Path $global:UpdateFile) { try { $j = Get-Content $global:UpdateFile -Raw | ConvertFrom-Json; $info.checked = $j.checked; $info.notified = $j.notified } catch { Write-Verbose 'update.json unreadable' } }
    $r = Resolve-VeroUpdateNotice -Info $info -Release (Get-VeroLatestRelease)
    $global:Update = $r.Update; $mUpd.Text = $r.MenuText; $info = $r.Info
    if ($r.Balloon) { $notify.ShowBalloonTip(8000, "VeroScudo $($r.Update.Tag) is available", "You run $(Get-VeroVersion). Open the tray menu to see the release.", [System.Windows.Forms.ToolTipIcon]::Info) }
    try { New-Item -ItemType Directory -Path $global:Paths.UserDir -Force | Out-Null; $info | ConvertTo-Json | Set-Content $global:UpdateFile } catch { Write-Verbose 'update.json not writable' }
}

function Refresh {
    if (Update-ConfigCache) { Update-ProfileMenu }
    $st = Get-State
    if ($st.State -eq 'protected' -and $global:Last -ne 'protected') { $global:ProtectedSince = Get-Date; Start-ExitFetch; Start-StatusPageFetch -Now }   # each (re)connect: once (location and service status)
    elseif ($st.Connected -and -not $global:LastConnected) { $global:ProtectedSince = Get-Date }    # a tunnel came up with VeroScudo off: older lookups are not this tunnel's
    $global:LastConnected = [bool]$st.Connected
    Update-ExitFetch
    Update-StatusPageFetch
    if ($st.State -eq 'blocked' -and $global:Last -eq 'off' -and -not (Get-TrayExpect)) { Set-TrayExpect 'connect'; $st = Get-State }   # turned on elsewhere (shortcut)
    if ($global:Expect) {
        $age = ((Get-Date) - $global:Expect.Since).TotalSeconds
        if ($st.State -eq 'protected') { $global:Expect = $null }                          # done: the next drop is a real one
        elseif (-not $st.Armed -and $age -gt 20) { $global:Expect = $null }                # cancelled, or turned off again
        elseif ($st.State -eq 'blocked' -and -not (Get-TrayExpect)) {
            # 2 minutes and still not connected: say so once, plainly - a start that fails must not hide behind "Connecting"
            $global:Expect = $null; $st = Get-State
            $notify.ShowBalloonTip(8000, 'VPN not connected yet - traffic blocked', "'$($global:Config.Profile)' did not connect within 2 minutes. VeroScudo keeps trying; nothing leaves this PC meanwhile.", [System.Windows.Forms.ToolTipIcon]::Warning)
        }
    }
    $notify.Icon = Get-StateIcon $st.State -Awake:([VeroKeepAwake]::Active)
    $cv = Get-ConnectionView $st
    $notify.Text = Get-VeroTrayTip -Title $st.Title -Word $cv.Word -Awake:([VeroKeepAwake]::Active)
    $mHead.Text = "VeroScudo - $($st.Title)$(if ($cv.Word) { " - $($cv.Word)" })"
    $mOn.Enabled = ($st.State -ne 'protected'); $mOff.Enabled = $st.Armed -or ($st.Connected -and -not (Test-HiddifyProfile)); $mRedo.Enabled = $st.Armed -and -not (Test-HiddifyProfile)
    $noticed = Show-SwitchNotice
    if (-not $noticed) { $noticed = Show-ForeignNotice }
    Request-Otp
    if (-not $noticed -and $global:Last -and $global:Last -ne $st.State) {
        $b = switch ($st.State) {
            'blocked'   {
                switch ([string](Get-TrayExpect)) {
                    'connect'   { @('VeroScudo on - connecting', "Kill-switch on: traffic is blocked until '$($global:Config.Profile)' is connected.", 'Info') }
                    'switch'    { $null }                                  # Request-ProfileSwitch already said "Switching to ..."
                    'reconnect' { $null }                                  # Request-Reconnect already said it
                    default     { @('VPN connection lost - traffic blocked', 'Reconnecting... nothing leaves this PC until the tunnel is back.', 'Warning') }
                }
            }
            'protected' { @('VPN protected', 'Tunnel up, kill-switch on.', 'Info') }
            'off'       { @('VPN turned off', 'Firewall back to normal - traffic is NOT protected.', 'Info') }
            default     { @('VeroScudo needs attention', $st.Text, 'Warning') }
        }
        if ($b) { $notify.ShowBalloonTip(5000, $b[0], $b[1], [System.Windows.Forms.ToolTipIcon]$b[2]) }
    }
    $global:Last = $st.State
}

# ---------------------------------------------------------------- preview mode (screenshots for review), then run
if ($Preview) {
    # Every window, every state of the status window, every dialog and message - rendered into PNGs, nothing saved, nothing
    # changed: dialogs answer "cancel"/"No", the guard is never asked to do anything. Balloon texts go to balloons.txt.
    New-Item -ItemType Directory -Path $Preview -Force | Out-Null
    $global:PreviewDir = $Preview
    $global:PreviewSuffix = if ($global:Dark) { '-dark' } else { '-light' }
    function Find-Button($root, [string]$text) {
        foreach ($c in $root.Controls) { if ($c -is [System.Windows.Forms.Button] -and $c.Text -eq $text) { return $c }; $r = Find-Button $c $text; if ($r) { return $r } }
        $null
    }
    function Test-ShotWanted([string]$name) { (-not $PreviewOnly) -or @($PreviewOnly -split ',' | Where-Object { $name -like $_.Trim() }).Count -gt 0 }
    function Invoke-Shot([string]$name, [scriptblock]$what) {
        if (-not (Test-ShotWanted $name)) { return }
        $global:ShotName = $name
        try { & $what } catch { Add-Content (Join-Path $Preview "errors$($global:PreviewSuffix).txt") "$name : $($_.Exception.Message) $($_.InvocationInfo.PositionMessage)" }
        $global:ShotName = $null
    }
    # status window: every state the guard can report
    $pn = if ($global:Config) { $global:Config.Profile } else { 'ExampleVPN' }; $pt = if ($global:Config) { $global:Config.Type } else { 'ras' }
    $wg = Format-VeroForeignVpn ([pscustomobject]@{ Name = 'example-wireguard'; Kind = 'wireguard'; Configured = $false; CanDisconnect = $true; Id = 'example-wireguard' })
    $states = [ordered]@{
        'protected' = @{}; 'blocked' = @{ Up = $false }; 'off' = @{ Armed = $false; Up = $false }
        'connecting' = @{ Up = $false; Expect = 'connect' }; 'switching' = @{ Up = $false; Expect = 'switch' }; 'reconnecting' = @{ Up = $false; Expect = 'reconnect' }
        'other-vpn' = @{ Conflicts = @("$wg - VeroScudo blocks its traffic while it is on", "another app's filter layer is installed: 'WireGuard'") }
        'no-password' = @{ Cred = $false; Up = $false }; 'password-rejected' = @{ AuthBlocked = $true; Up = $false }
        'helper-blocked' = @{ NativeNext = '23:15' }; 'one-time-code' = @{ Otp = 'Enter the code from your authenticator app'; Up = $false }
        'not-configured' = @{ Configured = $false }
    }
    $global:PreviewExit = @{ Ip = '203.0.113.25'; City = 'Example City'; Country = 'PL'; Org = 'AS64500 Example Net'; Source = 'ipinfo.io'; Profile = $pn; Time = (Get-Date).AddMinutes(-7).ToString('o') }
    foreach ($k in $states.Keys) {
        $facts = @{ Configured = $true; Name = $pn; Type = $pt; Armed = $true; Up = $true; Cred = $true; AuthBlocked = $false; Otp = $null; Conflicts = @(); NativeNext = $null; Expect = $null }
        foreach ($kv in $states[$k].GetEnumerator()) { $facts[$kv.Key] = $kv.Value }
        $global:PreviewFacts = $facts
        Invoke-Shot "status-$k" { $fm = Show-Status; Save-FormShot $fm $global:ShotName; $global:StatusForm = $null }
    }
    # the CONNECTION card while protected and rated (Settings > Connection on)
    $global:PreviewCheck = ConvertFrom-VeroCheckConfig ('{"enabled":true,"intervalSeconds":10,"windowMinutes":2,"targets":[{"host":"1.1.1.1","method":"tcp","port":443},{"host":"10.0.0.1","method":"ping"}]}' | ConvertFrom-Json)
    $quals = [ordered]@{ 'good' = @(0.0, 45, 0); 'unstable' = @(22.2, 310, 4); 'bad' = @(61.1, 900, 11); 'checking' = $null }
    foreach ($qk in $quals.Keys) {
        $qv = $quals[$qk]
        $global:PreviewQuality = if ($qv) { [pscustomobject]@{ State = $qk; LossPct = $qv[0]; RttMs = $qv[1]; Checks = 18; Lost = $qv[2] } } else { $null }
        $global:PreviewFacts = @{ Configured = $true; Name = $pn; Type = $pt; Armed = $true; Up = $true; Cred = $true; AuthBlocked = $false; Otp = $null; Conflicts = @(); NativeNext = $null; Expect = $null }
        Invoke-Shot "status-quality-$qk" { $fm = Show-Status; Save-FormShot $fm $global:ShotName; $global:StatusForm = $null }
    }
    $global:PreviewFacts = $null; $global:PreviewQuality = $null
    # the service status card: operational, a minor incident, not reachable, first check running
    $okJ = '{"page":{"name":"Anthropic"},"status":{"indicator":"none","description":"All Systems Operational"}}'
    $global:PreviewFacts = @{ Configured = $true; Name = $pn; Type = $pt; Armed = $true; Up = $true; Cred = $true; AuthBlocked = $false; Otp = $null; Conflicts = @(); NativeNext = $null; Expect = $null }
    $svcs = [ordered]@{
        'ok'          = (ConvertTo-VeroStatusPageView -Json $okJ -Url 'https://status.anthropic.com/api/v2/status.json')
        'minor'       = (ConvertTo-VeroStatusPageView -Json ($okJ -replace '"none","description":"All Systems Operational"', '"minor","description":"Partially Degraded Service"') -Url 'https://status.anthropic.com/api/v2/status.json')
        'unreachable' = (ConvertTo-VeroStatusPageView -Json '' -Url 'https://status.anthropic.com/api/v2/status.json' -Failure 'timeout')
        'checking'    = [pscustomobject]@{ Text = 'checking'; Tone = 'normal'; Tip = ''; Badge = '?'; Name = 'status.anthropic.com'; Right = 'checking...' }
    }
    foreach ($sk in $svcs.Keys) { $global:PreviewSvc = $svcs[$sk]; Invoke-Shot "status-service-$sk" { $fm = Show-Status; Save-FormShot $fm $global:ShotName; $global:StatusForm = $null } }
    $global:PreviewSvc = $null; $global:PreviewFacts = $null
    foreach ($ti in 0..2) { Invoke-Shot "settings-$(@('profiles', 'behaviour', 'connection')[$ti])" { $sf = Show-Settings; & $global:SettingsTab $ti; Save-FormShot $sf $global:ShotName; $global:SettingsForm = $null } }
    $global:PreviewCheck = $null
    # statistics: a made-up week of the first profile - a lunch-time problem every day, a bad half hour, an evening without
    # VPN, check off one day - plus a second profile and a removed one in the drop-down
    $ids = @(if ($global:Config) { $global:Config.ProfileId; @($global:Config.Profiles | ForEach-Object Id | Where-Object { $_ -ne $global:Config.ProfileId }) }) + @('a1a1a1a1a1a1', 'b2b2b2b2b2b2')   # the active profile first: it is shown
    $global:PreviewStats = @(foreach ($i in 0..6) {
        $m = @{}; $m2 = @{}
        foreach ($t in (8 * 60)..(19 * 60 + 30)) {
            if (($i -eq 4 -and $t -gt 15 * 60) -or ($i -eq 0 -and $t -gt ((Get-Date).Hour * 60 + (Get-Date).Minute))) { break }
            $lost = if ($t -ge 12 * 60 + 40 -and $t -lt 13 * 60 + 20) { [int]($t % 3 -eq 0) } elseif ($i -eq 2 -and $t -ge 16 * 60 -and $t -lt 16 * 60 + 30) { 3 } else { [int](($t * 7 + $i) % 41 -eq 0) }
            $m[$t] = if ($i -eq 5) { @{ Sent = 0; Lost = 0 } } else { @{ Sent = 3; Lost = [Math]::Min($lost, 3) } }
        }
        if ($i -eq 1) { foreach ($t in (15 * 60)..(15 * 60 + 39)) { $m[$t] = @{ Sent = 0; Lost = 0; Down = $true } } }   # on, could not connect
        foreach ($t in (20 * 60)..(22 * 60)) { if ($i -eq 0 -and $t -gt ((Get-Date).Hour * 60 + (Get-Date).Minute)) { break }; $m2[$t] = @{ Sent = 3; Lost = 0 } }
        @{ Data = @{ $ids[0] = $m; $ids[1] = $m2; 'c3c3c3c3c3c3' = @{ 600 = @{ Sent = 0; Lost = 0 } } }; Names = @{ $ids[0] = 'p0'; $ids[1] = 'p1'; 'c3c3c3c3c3c3' = 'Old office' } }
    })
    Invoke-Shot 'stats' { $fm = Show-Stats; Save-FormShot $fm $global:ShotName; $global:StatsForm = $null }
    $global:PreviewStats = $null
    Invoke-Shot 'about' { Save-FormShot (Show-About) $global:ShotName }
    foreach ($i in 0..2) { Invoke-Shot "editor-$(@('ras', 'openvpn', 'wireguard')[$i])" { $x = New-VpnProfileForm $null; $x.TypeBox.SelectedIndex = $i; $x.Form.Show(); Save-FormShot $x.Form $global:ShotName } }
    if ($global:Config) { Invoke-Shot 'editor-edit' { $x = New-VpnProfileForm @($global:Config.Profiles)[0]; $x.Form.Show(); Save-FormShot $x.Form $global:ShotName } }
    # dialogs (each captured by Show-Modal; the answer is "cancel")
    Invoke-Shot 'password' { $null = Read-Password "user@example.com ($pn)" }
    Invoke-Shot 'msg-no-password' { Request-ProfilePassword ([pscustomobject]@{ Profile = 'ExampleVPN'; Type = 'ras'; Server = 'vpn.example.com'; Port = 443; Username = 'user@example.com'; ServerIps = @(); Auth = $true; Dco = $false }) }
    Invoke-Shot 'otp' { $null = Read-Otp 'Enter the code from your authenticator app' 'ExampleOpenVPN' }
    Invoke-Shot 'import' { $null = Select-WindowsVpn @() }
    Invoke-Shot 'msg-all-imported' { $null = Select-WindowsVpn @(Get-VeroWindowsVpn | ForEach-Object Name) }
    $fWg = [pscustomobject]@{ Name = 'example-wireguard'; Kind = 'wireguard'; Configured = $false; CanDisconnect = $true; Id = 'example-wireguard' }
    $fRas = [pscustomobject]@{ Name = 'CorporateVPN'; Kind = 'ras'; Configured = $true; CanDisconnect = $true; Id = 'CorporateVPN' }
    $fApp = [pscustomobject]@{ Name = 'ExampleVPN app'; Kind = 'app'; Configured = $false; CanDisconnect = $false; Id = 'app' }
    Invoke-Shot 'foreign-one' { $null = Show-ForeignPrompt @($fWg) }
    Invoke-Shot 'foreign-profile' { $null = Show-ForeignPrompt @($fRas) }
    Invoke-Shot 'foreign-app' { $null = Show-ForeignPrompt @($fApp) }
    Invoke-Shot 'foreign-mixed' { $null = Show-ForeignPrompt @($fWg, $fApp) }
    Invoke-Shot 'msg-check' { $null = Show-Check "WireGuard tunnel 'example-wireguard':" @('AllowedIPs is not 0.0.0.0/0 - traffic outside the tunnel is blocked, not sent around it', 'No PersistentKeepalive - VeroScudo sees a dead tunnel only when traffic fails') }
    # messages behind buttons: clicked for real; every one answers No / Cancel
    if ($global:Config -and @($global:Config.Profiles).Count -ge 2) {
        $sf = Show-Settings
        Invoke-Shot 'msg-remove' { (Find-Button $sf 'Remove').PerformClick() }
        Invoke-Shot 'msg-key-passphrase' { (Find-Button $sf 'Key passphrase...').PerformClick() }
        Invoke-Shot 'password-from-settings' { (Find-Button $sf 'Set password...').PerformClick() }
        $sf.Close(); $global:SettingsForm = $null
    }
    $x = New-VpnProfileForm $null; $x.Form.Show()
    Invoke-Shot 'msg-name-required' { (Find-Button $x.Form 'OK').PerformClick() }
    $x.Form.Close()
    # tray menu
    if (Test-ShotWanted 'menu') {
    $menu.Show((New-Object System.Drawing.Point(1200, 200))); foreach ($k in 1..6) { [System.Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 300 }
    $bmp = New-Object System.Drawing.Bitmap($menu.Width, $menu.Height)
    $menu.DrawToBitmap($bmp, (New-Object System.Drawing.Rectangle(0, 0, $menu.Width, $menu.Height))); $bmp.Save((Join-Path $Preview ('menu' + $global:PreviewSuffix + '.png'))); $bmp.Dispose()
    }
    # balloon notifications are drawn by Windows: their texts, as written in this file
    $src = Get-Content $PSCommandPath | Select-String 'ShowBalloonTip\(' | ForEach-Object { $_.Line.Trim() }
    Set-Content (Join-Path $Preview 'balloons.txt') $src -Encoding UTF8
    $notify.Visible = $false; $notify.Dispose()
    [Environment]::Exit(0)
}
$timer = New-Object System.Windows.Forms.Timer; $timer.Interval = $PollSeconds * 1000; $timer.Add_Tick({ Refresh }); $timer.Start()
$firstCheck = New-Object System.Windows.Forms.Timer; $firstCheck.Interval = 120 * 1000; $firstCheck.Add_Tick({ $firstCheck.Stop(); try { Invoke-UpdateCheck } catch { Write-Verbose "update check: $($_.Exception.Message)" } }); $firstCheck.Start()
Refresh
[System.Windows.Forms.Application]::Run()
