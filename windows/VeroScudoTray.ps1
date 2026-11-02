#Requires -Version 5.1
<#
  VeroScudo tray app (Windows). Read-only view of the guard's state; every action runs the same scheduled
  task the Desktop shortcuts use, so the guard logic stays in VeroScudo.Core.psm1.
  Started hidden by the \VeroScudo\Tray task at sign-in (run.vbs tray), or manually:
    powershell -ExecutionPolicy Bypass -File VeroScudoTray.ps1 [-Preview <folder>]   # -Preview: screenshots the windows and exits
#>
param([int]$PollSeconds = 3, [string]$Preview, [ValidateSet('auto', 'dark', 'light')][string]$ForceTheme = 'auto')

# one tray per sign-in session: a second start (logon task, installer, by hand) exits quietly
if (-not $Preview) {
    $created = $false
    $global:TrayMutex = New-Object System.Threading.Mutex($true, 'Local\VeroScudoTray', [ref]$created)
    if (-not $created) { exit 0 }
}

# ---------------------------------------------------------------- native helpers (DPI, dark title bars, menu renderer)
Add-Type -ReferencedAssemblies System.Windows.Forms, System.Drawing -TypeDefinition @'
using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;

public static class VeroNative {
    [DllImport("shcore.dll")] static extern int SetProcessDpiAwareness(int value);
    [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
    [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
    public static void EnableDpi() { try { SetProcessDpiAwareness(2); } catch { SetProcessDPIAware(); } }
    public static void Style(IntPtr hwnd, bool dark) {
        int d = dark ? 1 : 0; DwmSetWindowAttribute(hwnd, 20, ref d, 4);      // DWMWA_USE_IMMERSIVE_DARK_MODE
        int r = 2;            DwmSetWindowAttribute(hwnd, 33, ref r, 4);      // DWMWA_WINDOW_CORNER_PREFERENCE = round
    }
}

// Keep awake: one power request (system + execution, never the display). Not tied to a thread, listed by
// `powercfg /requests` under the reason string, dropped by the kernel when the tray process dies.
public static class VeroKeepAwake {
    [StructLayout(LayoutKind.Sequential)] struct Ctx { public uint Version; public uint Flags; public IntPtr Reason, Pad1, Pad2; }
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr PowerCreateRequest(ref Ctx c);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool PowerSetRequest(IntPtr h, int type);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool PowerClearRequest(IntPtr h, int type);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    const int System = 1, Execution = 3;
    static IntPtr handle = IntPtr.Zero, reason = IntPtr.Zero;
    public static bool Active { get { return handle != IntPtr.Zero; } }
    public static bool Set(bool on) { if (on) return Acquire(); Release(); return false; }
    static bool Acquire() {
        if (Active) return true;
        if (reason == IntPtr.Zero) reason = Marshal.StringToHGlobalUni("VeroScudo: Keep awake is on");
        var c = new Ctx { Version = 0, Flags = 1, Reason = reason };   // POWER_REQUEST_CONTEXT_SIMPLE_STRING
        IntPtr h = PowerCreateRequest(ref c);
        if (h == IntPtr.Zero || h == new IntPtr(-1)) return false;
        if (!PowerSetRequest(h, System)) { CloseHandle(h); return false; }
        PowerSetRequest(h, Execution);                                // best effort: keeps us running under Modern Standby
        handle = h; return true;
    }
    static void Release() {
        if (!Active) return;
        PowerClearRequest(handle, System); PowerClearRequest(handle, Execution); CloseHandle(handle); handle = IntPtr.Zero;
    }
}

public class VeroTheme {
    public Color Bg, Card, Border, Text, Sub, Hover, Accent;
    public static VeroTheme Dark() { return new VeroTheme { Bg = Color.FromArgb(32,32,32), Card = Color.FromArgb(43,43,43), Border = Color.FromArgb(58,58,58), Text = Color.FromArgb(240,240,240), Sub = Color.FromArgb(160,160,160), Hover = Color.FromArgb(56,56,56), Accent = Color.FromArgb(96,205,255) }; }
    public static VeroTheme Light() { return new VeroTheme { Bg = Color.FromArgb(243,243,243), Card = Color.White, Border = Color.FromArgb(229,229,229), Text = Color.FromArgb(27,27,27), Sub = Color.FromArgb(92,92,92), Hover = Color.FromArgb(233,233,233), Accent = Color.FromArgb(0,103,192) }; }
}

// Windows-11-like menu: flat, padded, rounded hover, vector icons drawn by name from item.Tag
public class VeroMenuRenderer : ToolStripProfessionalRenderer {
    readonly VeroTheme t; readonly float scale;
    public Image Logo;
    public VeroMenuRenderer(VeroTheme theme, float dpiScale) { t = theme; scale = dpiScale; RoundedEdges = false; }
    protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e) { e.Graphics.Clear(t.Card); }
    protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e) {
        using (var p = new Pen(t.Border)) e.Graphics.DrawRectangle(p, 0, 0, e.ToolStrip.Width - 1, e.ToolStrip.Height - 1); }
    protected override void OnRenderImageMargin(ToolStripRenderEventArgs e) { using (var b = new SolidBrush(t.Card)) e.Graphics.FillRectangle(b, e.AffectedBounds); }
    protected override void OnRenderSeparator(ToolStripSeparatorRenderEventArgs e) {
        using (var p = new Pen(t.Border)) e.Graphics.DrawLine(p, S(14), e.Item.Height / 2, e.Item.Width - S(14), e.Item.Height / 2); }
    protected override void OnRenderMenuItemBackground(ToolStripItemRenderEventArgs e) {
        if (!e.Item.Selected || !e.Item.Enabled) return;
        var r = new Rectangle(S(6), S(2), e.Item.Width - S(12), e.Item.Height - S(4));
        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        using (var path = Round(r, S(5))) using (var b = new SolidBrush(t.Hover)) e.Graphics.FillPath(b, path); }
    protected override void OnRenderItemImage(ToolStripItemImageRenderEventArgs e) {
        var kind = e.Item.Tag as string; if (string.IsNullOrEmpty(kind)) return;
        var r = e.ImageRectangle; int sz = Math.Min(r.Width, r.Height); r.Y = (e.Item.Height - sz) / 2; r.Height = sz;
        if (kind == "logo") {
            if (Logo != null) { e.Graphics.InterpolationMode = InterpolationMode.HighQualityBicubic; e.Graphics.DrawImage(Logo, new Rectangle(r.X + (r.Width - sz) / 2 + S(4), r.Y + (r.Height - sz) / 2, sz, sz)); }
            return;
        }
        DrawIcon(e.Graphics, kind, new Rectangle(r.X + (r.Width - sz) / 2 + S(4), r.Y + (r.Height - sz) / 2, sz, sz), !e.Item.Enabled ? t.Sub : (kind == "awake" && e.Item is ToolStripMenuItem && ((ToolStripMenuItem)e.Item).Checked) ? t.Accent : t.Text); }
    protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e) {
        e.Graphics.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
        var r = e.TextRectangle; r.Y = 0; r.Height = e.Item.Height; r.X += S(10); r.Width = e.Item.Width - r.X - S(10);
        TextRenderer.DrawText(e.Graphics, e.Text, e.TextFont, r, e.Item.Enabled ? t.Text : t.Sub, TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.NoPadding); }
    protected override void OnRenderItemCheck(ToolStripItemImageRenderEventArgs e) { }   // no stock check box: a ticked item shows its icon in the accent colour
    protected override void OnRenderArrow(ToolStripArrowRenderEventArgs e) { e.ArrowColor = e.Item != null && e.Item.Enabled ? t.Text : t.Sub; base.OnRenderArrow(e); }
    int S(double v) { return (int)Math.Round(v * scale); }
    static GraphicsPath Round(Rectangle r, int d) { var p = new GraphicsPath(); p.AddArc(r.X, r.Y, d, d, 180, 90); p.AddArc(r.Right - d, r.Y, d, d, 270, 90); p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90); p.AddArc(r.X, r.Bottom - d, d, d, 90, 90); p.CloseFigure(); return p; }

    // 16x16 design grid, scaled; stroke 1.6 px
    void DrawIcon(Graphics g, string kind, Rectangle box, Color c) {
        var st = g.Save();
        g.SmoothingMode = SmoothingMode.AntiAlias; g.PixelOffsetMode = PixelOffsetMode.HighQuality;
        g.TranslateTransform(box.X, box.Y); g.ScaleTransform(box.Width / 16f, box.Height / 16f);
        using (var pen = new Pen(c, 1.6f)) using (var br = new SolidBrush(c)) {
            pen.StartCap = LineCap.Round; pen.EndCap = LineCap.Round; pen.LineJoin = LineJoin.Round;
            switch (kind) {
                case "play": g.FillPolygon(br, new[] { new PointF(4, 2.5f), new PointF(13.5f, 8), new PointF(4, 13.5f) }); break;
                case "stop": using (var path = Round(new Rectangle(3, 3, 10, 10), 3)) g.FillPath(br, path); break;
                case "info": g.DrawEllipse(pen, 2, 2, 12, 12); g.DrawLine(pen, 8, 7.2f, 8, 11.5f); g.FillEllipse(br, 7.1f, 4.2f, 1.8f, 1.8f); break;
                case "log":  g.DrawLines(pen, new[] { new PointF(4, 2), new PointF(10, 2), new PointF(13, 5), new PointF(13, 14), new PointF(4, 14), new PointF(4, 2) });
                             g.DrawLine(pen, 6.5f, 7.5f, 10.5f, 7.5f); g.DrawLine(pen, 6.5f, 10.5f, 10.5f, 10.5f); break;
                case "gear": {
                    var path = new GraphicsPath(); int teeth = 8; float ro = 7f, ri = 5.4f;
                    for (int i = 0; i < teeth * 2; i++) { double a = Math.PI * 2 * i / (teeth * 2) - Math.PI / 2; float r = (i % 2 == 0) ? ro : ri;
                        var pt = new PointF(8 + (float)(r * Math.Cos(a)), 8 + (float)(r * Math.Sin(a))); if (i == 0) path.StartFigure(); path.AddLine(pt, pt); }
                    path.CloseFigure(); g.FillPath(br, path);
                    using (var hole = new SolidBrush(t.Card)) g.FillEllipse(hole, 5.6f, 5.6f, 4.8f, 4.8f); break; }
                case "redo": g.DrawArc(pen, 2.5f, 3, 11, 11, 30, 300); g.FillPolygon(br, new[] { new PointF(14.6f, 6.4f), new PointF(13.6f, 1.4f), new PointF(9.8f, 4.6f) }); break;
                case "sync": g.DrawArc(pen, 2.5f, 2.5f, 11, 11, 200, 230); g.FillPolygon(br, new[] { new PointF(13.8f, 2.2f), new PointF(14.2f, 7.2f), new PointF(9.6f, 5.4f) }); break;
                case "help": g.DrawEllipse(pen, 2, 2, 12, 12); g.DrawArc(pen, 5.6f, 4.6f, 4.8f, 4.4f, 200, 230); g.DrawLine(pen, 8, 8.6f, 8, 10f); g.FillEllipse(br, 7.1f, 11.2f, 1.8f, 1.8f); break;
                case "power": g.DrawArc(pen, 2.5f, 3, 11, 11, -60, 300); g.DrawLine(pen, 8, 1.5f, 8, 7.5f); break;
                case "check": g.DrawLines(pen, new[] { new PointF(3, 8.5f), new PointF(6.5f, 12), new PointF(13, 4.5f) }); break;
                case "awake": g.DrawLines(pen, new[] { new PointF(3, 6.5f), new PointF(3, 11), new PointF(5.5f, 13.5f), new PointF(9.5f, 13.5f), new PointF(12, 11), new PointF(12, 6.5f), new PointF(3, 6.5f) });
                              g.DrawArc(pen, 10.5f, 7.2f, 4, 3.6f, -90, 180);
                              g.DrawLine(pen, 5.5f, 2, 5.5f, 4.5f); g.DrawLine(pen, 9.5f, 2, 9.5f, 4.5f); break;
                case "globe": g.DrawEllipse(pen, 2, 2, 12, 12); g.DrawEllipse(pen, 5.2f, 2, 5.6f, 12); g.DrawLine(pen, 2, 8, 14, 8); break;
            }
        }
        g.Restore(st);
    }
}
'@
[VeroNative]::EnableDpi()
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
Import-Module (Join-Path $PSScriptRoot 'VeroScudo.Core.psm1') -Force

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

# a missing asset means a broken install: say so in the log instead of silently showing a substitute
function Write-MissingAsset([string]$path) { try { Write-VeroLog "WARNING: missing $path - showing a fallback; reinstall to fix" 'tray' } catch { Write-Verbose 'log not writable' } }
function Get-StateIcon([string]$state) {
    $variant = if ($global:TaskbarDark) { 'png' } else { 'badge' }
    $key = "$variant/$state"
    if (-not $global:Icons.ContainsKey($key)) {
        $ico = Join-Path $global:IconDir "$variant\$state.ico"
        $global:Icons[$key] = if (Test-Path $ico) { New-Object System.Drawing.Icon($ico) } else { Write-MissingAsset $ico; [System.Drawing.SystemIcons]::Shield }
    }
    $global:Icons[$key]
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
function Get-State {
    if (-not $global:Config) { return [pscustomobject]@{ State = 'attention'; Title = 'Not configured'; Text = 'Run Install.ps1 to create config.json'; Armed = $false; Connected = $false } }
    $name = $global:Config.Profile; $type = $global:Config.Type
    $armed = Test-VeroArmed; $up = Test-VeroVpnConnected $name -Type $type
    $cp = Get-VeroPath -VpnProfile $name
    $cred = (-not (Test-VeroNeedsPassword $global:Config)) -or (Test-Path $cp.Cred) -or (Test-Path $cp.LegacyCred)
    $ovpn = if ($type -eq 'openvpn') { Get-VeroOpenVpnStatus $name } else { $null }
    $conflicts = @(if ($armed) { Get-VeroConflictList })
    $why = $null
    $nb = Get-VeroNativeBlocked
    if ($nb) {
        $next = try { '{0:HH:mm}' -f [datetime]::Parse([string]$nb.Next, $null, [Globalization.DateTimeStyles]::RoundtripKind) } catch { 'soon' }
        $why = "Windows blocked VeroScudo's helper (Smart App Control). The kill-switch stays on, but self-repair and automatic redial are paused - next try at $next."
    } elseif (-not $cred) { $why = "VPN password for '$name' not stored - open Settings" }
    elseif (Test-VeroAuthBlocked $name) { $why = "The password for '$name' was rejected. Store the right one in Settings, then Reconnect - traffic stays blocked meanwhile." }
    elseif ($ovpn -and [string]$ovpn.State -eq 'NEED_OTP') { $why = "'$name' asks for a one-time code: $($ovpn.Challenge)" }
    elseif ($armed -and $up -and $conflicts.Count -gt 0) { $why = "Next to VeroScudo: $($conflicts[0])" }
    $state = if ($why) { 'attention' } elseif (-not $armed) { 'off' } elseif ($up) { 'protected' } else { 'blocked' }
    $title, $text = switch ($state) {
        'protected' { 'Protected', "$name ($(Get-VeroTypeLabel $type)) connected - kill-switch on" }
        'blocked'   { 'Blocked - reconnecting', "$name lost - nothing leaves this PC until it is back" }
        'off'       { 'Off', 'VPN turned off by you - normal network, not protected' }
        default     { 'Attention', $why }
    }
    [pscustomobject]@{ State = $state; Title = $title; Text = $text; Armed = $armed; Connected = $up }
}
function Invoke-GuardTask([string]$name) { Start-Process schtasks.exe -ArgumentList "/run /tn `"$global:Folder$name`"" -WindowStyle Hidden }
function Get-LastEvents([int]$n = 6) { if (Test-Path $global:Paths.Log) { Get-Content $global:Paths.Log -Tail $n | ForEach-Object { $_ -replace '^\d{4}-\d\d-\d\d ', '' } } else { @() } }
function Get-LastDrop {
    if ($global:Config -and $global:Config.Type -eq 'openvpn') { $s = Get-VeroOpenVpnStatus $global:Config.Profile; if ($s) { return ('{0}{1}' -f $s.State, $(if ($s.Reason) { ' - ' + $s.Reason })) }; return '-' }
    if ($global:Config -and $global:Config.Type -eq 'wireguard') { return "handshake $(Get-VeroWgHealthNow $global:Config.Profile)" }
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
function New-Button($parent, [string]$text, [int]$x, [int]$y, [int]$w, [bool]$primary = $false) {
    $b = New-Object System.Windows.Forms.Button; $b.Text = $text; $b.Location = (P $x $y); $b.Size = (Z $w 34)
    $b.FlatStyle = 'Flat'; $b.Font = $FontUI; $b.FlatAppearance.BorderSize = 1; $b.Cursor = 'Hand'
    if ($primary) { $b.BackColor = $global:Theme.Accent; $b.ForeColor = if ($global:Dark) { [System.Drawing.Color]::FromArgb(20,20,20) } else { [System.Drawing.Color]::White }; $b.FlatAppearance.BorderColor = $global:Theme.Accent }
    else { $b.BackColor = $global:Theme.Card; $b.ForeColor = $global:Theme.Text; $b.FlatAppearance.BorderColor = $global:Theme.Border; $b.FlatAppearance.MouseOverBackColor = $global:Theme.Hover }
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
    $title = New-Label $hero '' 96 18 300 30 $FontBig
    $sub   = New-Label $hero '' 96 50 310 36 $FontSmall $global:Theme.Sub
    $cards = @{}; $heads = @{}
    $i = 0
    foreach ($k in 'VPN profile', 'Firewall', 'Last drop', 'Redial') {
        $cx = 20 + ($i % 2) * 215; $cy = 126 + [math]::Floor($i / 2) * 78
        $c = New-Card $f $cx $cy 205 66
        $heads[$k] = New-Label $c ($k.ToUpper()) 12 8 180 16 $FontSmall $global:Theme.Sub
        $cards[$k] = New-Label $c '' 12 28 185 24 $FontBold
        $i++
    }
    $other = New-Label $f '' 20 273 420 18 $FontSmall ([System.Drawing.Color]::FromArgb(252,187,45))
    $ev = New-Card $f 20 292 420 160
    New-Label $ev 'RECENT EVENTS' 12 8 200 16 $FontSmall $global:Theme.Sub | Out-Null
    $evText = New-Object System.Windows.Forms.TextBox; $evText.Multiline = $true; $evText.ReadOnly = $true; $evText.BorderStyle = 'None'
    $evText.Location = (P 12 30); $evText.Size = (Z 396 120); $evText.Font = $FontMono; $evText.BackColor = $global:Theme.Card; $evText.ForeColor = $global:Theme.Text; $evText.ScrollBars = 'None'; $evText.WordWrap = $false; $evText.TabStop = $false; $evText.Cursor = 'Default'
    $ev.Controls.Add($evText)
    $bOnOff = New-Button $f 'Turn VPN off' 20 470 99
    $bRedo  = New-Button $f 'Reconnect' 127 470 99
    $bLog   = New-Button $f 'Open log' 234 470 99
    $bCopy  = New-Button $f 'Copy report' 341 470 99 $true
    $bRedo.Add_Click(({ Request-Reconnect }).GetNewClosure())
    $bLog.Add_Click(({ if (Test-Path $global:Paths.Log) { Start-Process notepad.exe $global:Paths.Log } }).GetNewClosure())
    $bCopy.Add_Click(({ $s = Get-VeroStatus -Config $global:Config; $txt = ($s.PSObject.Properties | ForEach-Object { '{0,-11} {1}' -f $_.Name, $_.Value }) -join "`r`n"; $txt += "`r`n`r`n--- last events`r`n" + ((Get-LastEvents 15) -join "`r`n"); [System.Windows.Forms.Clipboard]::SetText($txt); $bCopy.Text = 'Copied'; }).GetNewClosure())
    $bOnOff.Add_Click(({ if ($bOnOff.Text -like '*off') { Invoke-GuardTask 'Off' } else { Request-TurnOn } }).GetNewClosure())
    $refresh = ({
        $st = Get-State
        $pic.Image = Get-StateImage $st.State 64; $title.Text = $st.Title; $sub.Text = $st.Text
        $title.ForeColor = switch ($st.State) { 'protected' { [System.Drawing.Color]::FromArgb(48,200,79) } 'blocked' { [System.Drawing.Color]::FromArgb(248,80,70) } 'attention' { [System.Drawing.Color]::FromArgb(252,187,45) } default { $global:Theme.Text } }
        $cards['VPN profile'].Text = if ($global:Config) { $global:Config.Profile } else { '-' }
        $heads['VPN profile'].Text = if ($global:Config) { ('VPN profile - ' + (Get-VeroTypeLabel $global:Config.Type)).ToUpper() } else { 'VPN PROFILE' }
        $bRedo.Enabled = $st.Armed
        $cards['Firewall'].Text = if ($st.Armed) { 'kill-switch ON' } else { 'normal' }
        $cards['Firewall'].ForeColor = if ($st.Armed -and -not $st.Connected) { [System.Drawing.Color]::FromArgb(248,80,70) } else { $global:Theme.Text }
        $cards['Last drop'].Text = Get-LastDrop
        $cards['Redial'].Text = if ($st.Armed -and -not $st.Connected) { 'running' } else { 'idle' }
        $evText.Text = (Get-LastEvents 6) -join "`r`n"; $evText.Select(0, 0)
        $fv = @(Get-ForeignCached)
        $other.Text = if ($fv.Count -gt 0) { 'Other VPNs: ' + (($fv | ForEach-Object { '{0} ({1})' -f $_.Name, $(if ($_.Configured) { 'another profile' } elseif ($_.Kind -eq 'app') { 'VPN app' } else { 'not imported' }) }) -join ', ') } else { '' }
        $bOnOff.Text = if ($st.Armed -or $st.Connected) { 'Turn VPN off' } else { 'Turn VPN on' }
    }).GetNewClosure()
    & $refresh
    $tm = New-Object System.Windows.Forms.Timer; $tm.Interval = 3000; $tm.Add_Tick($refresh); $tm.Start()
    $f.Add_FormClosed(({ $tm.Stop(); $tm.Dispose() }).GetNewClosure())
    $global:StatusForm = $f
    $f.Show(); $f.Activate(); $bLog.Focus() | Out-Null
    $f
}

# ---------------------------------------------------------------- settings window
function Read-Password([string]$who) {
    <# Small modal: returns a SecureString or $null. #>
    $pf = New-Form 'VPN password' 360 150
    New-Label $pf "Password for $who (stored encrypted for your Windows account)" 20 16 320 36 $FontSmall $global:Theme.Sub | Out-Null
    $tp = New-Input $pf 20 58 320 '' $true
    $ok = New-Button $pf 'Save' 230 100 110 $true
    $result = @{ Value = $null }
    $ok.Add_Click(({ $sec = New-Object System.Security.SecureString; foreach ($ch in $tp.Text.ToCharArray()) { $sec.AppendChar($ch) }; $sec.MakeReadOnly(); $tp.Text = ''; $result.Value = $sec; $pf.Close() }).GetNewClosure())
    $pf.ShowDialog() | Out-Null
    $result.Value
}

function Read-Otp([string]$question, [string]$profileName) {
    <# OpenVPN static challenge: the code goes to the runner through a file in your own folder, read once. #>
    $of = New-Form 'One-time code' 360 170
    New-Label $of "$profileName asks: $question" 20 16 320 40 $FontSmall $global:Theme.Sub | Out-Null
    $tc = New-Input $of 20 62 320 ''
    $ok = New-Button $of 'Send' 230 110 110 $true
    $result = @{ Value = $null }
    $ok.Add_Click(({ $result.Value = $tc.Text.Trim(); $of.Close() }).GetNewClosure())
    $of.TopMost = $true
    $of.ShowDialog() | Out-Null
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

function Select-WindowsVpn([string[]]$have) {
    <# Import from Windows: ONE Windows VPN profile per import, chosen by you - not every VPN on a PC is for work. Lists
       your profiles and those for all users with the type, server and sign-in VeroScudo found; profiles already in the
       list are not offered again. Nothing is selected in advance. Returns the chosen profile or nothing. #>
    $all = @(Get-VeroWindowsVpn | Sort-Object Name)
    $offer = @($all | Where-Object { $have -notcontains $_.Name -and $_.Server })
    if ($offer.Count -eq 0) {
        $msg = if ($all.Count -eq 0) { 'No Windows VPN profile found. Create one in Settings > Network & Internet > VPN (any type: Automatic, IKEv2, SSTP, L2TP/IPsec, PPTP), connect once, then import it here.' } else { 'Every Windows VPN profile is already in the list.' }
        [System.Windows.Forms.MessageBox]::Show($msg, 'VeroScudo') | Out-Null; return
    }
    $sf = New-Form 'Import from Windows' 560 380
    New-Label $sf 'Choose the ONE Windows VPN profile to protect (import others one by one). Server, port, protocol and sign-in are taken from Windows.' 20 14 520 36 $FontSmall $global:Theme.Sub | Out-Null
    $lbx = New-Object System.Windows.Forms.ListBox; $lbx.Location = (P 20 54); $lbx.Size = (Z 520 250); $lbx.BorderStyle = 'FixedSingle'; $lbx.SelectionMode = 'One'
    $lbx.BackColor = $global:Theme.Bg; $lbx.ForeColor = $global:Theme.Text; $lbx.Font = $FontUI; $lbx.IntegralHeight = $false
    foreach ($v in $offer) {
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
    $ok.Add_Click(({ if ($lbx.SelectedIndex -ge 0) { $res.Value = $offer[$lbx.SelectedIndex] }; $sf.Close() }).GetNewClosure())
    $sf.ShowDialog() | Out-Null
    if ($res.Value) { $res.Value }
}

function Show-Check([string]$what, [string[]]$warnings) {
    <# The add/edit check: warnings shown before saving. Returns $true to save anyway. #>
    if (@($warnings).Count -eq 0) { return $true }
    $msg = "$what`r`n`r`n" + ((@($warnings) | ForEach-Object { '- ' + $_ }) -join "`r`n`r`n") + "`r`n`r`nSave anyway?"
    ([System.Windows.Forms.MessageBox]::Show($msg, 'VeroScudo - check', 'YesNo', 'Warning') -eq 'Yes')
}

function Edit-VpnProfile($entry) {
    <# Modal editor for one profile entry, per type; returns the edited entry or $null (cancel). An OpenVPN entry with a newly
       chosen .ovpn carries ImportFrom: the elevated save imports it (checked again there). #>
    $ef = New-Form 'VPN profile' 420 400
    $types = @('ras', 'openvpn', 'wireguard')
    New-Label $ef 'Type' 20 16 200 18 $FontSmall $global:Theme.Sub | Out-Null
    $cbType = New-Object System.Windows.Forms.ComboBox; $cbType.Location = (P 20 36); $cbType.Size = (Z 380 30); $cbType.DropDownStyle = 'DropDownList'; $cbType.FlatStyle = 'Flat'; $cbType.BackColor = $global:Theme.Bg; $cbType.ForeColor = $global:Theme.Text; $cbType.Font = $FontUI
    foreach ($t in $types) { [void]$cbType.Items.Add((Get-VeroTypeLabel $t)) }
    $ef.Controls.Add($cbType)
    $lName = New-Label $ef 'Windows VPN profile' 20 80 380 18 $FontSmall $global:Theme.Sub
    $cb = New-Object System.Windows.Forms.ComboBox; $cb.Location = (P 20 100); $cb.Size = (Z 380 30); $cb.DropDownStyle = 'DropDown'; $cb.FlatStyle = 'Flat'; $cb.BackColor = $global:Theme.Bg; $cb.ForeColor = $global:Theme.Text; $cb.Font = $FontUI
    $ef.Controls.Add($cb)
    $lServer = New-Label $ef 'Server host name' 20 144 200 18 $FontSmall $global:Theme.Sub
    $tServer = New-Input $ef 20 164 290 $(if ($entry) { $entry.Server } else { '' })
    $lPort = New-Label $ef 'Port' 320 144 60 18 $FontSmall $global:Theme.Sub
    $tPort = New-Input $ef 320 164 80 $(if ($entry) { [string]$entry.Port } else { '443' })
    $lFile = New-Label $ef 'OpenVPN config (.ovpn) - imported for administrators only' 20 144 380 18 $FontSmall $global:Theme.Sub
    $tFile = New-Input $ef 20 164 290 ''
    $bFile = New-Button $ef 'Browse...' 320 162 80
    $lUser = New-Label $ef 'Username' 20 208 200 18 $FontSmall $global:Theme.Sub
    $tUser = New-Input $ef 20 228 380 $(if ($entry) { $entry.Username } else { '' })
    $chkDco = New-Object System.Windows.Forms.CheckBox; $chkDco.Text = 'Keep DCO (faster; the server permit is then not tied to openvpn.exe)'; $chkDco.Location = (P 20 268); $chkDco.Size = (Z 380 24); $chkDco.ForeColor = $global:Theme.Text; $chkDco.Checked = [bool]($entry -and $entry.PSObject.Properties['Dco'] -and $entry.Dco); $ef.Controls.Add($chkDco)
    $bConf = New-Button $ef 'Read .conf...' 20 266 140
    $hint = New-Label $ef '' 20 300 380 36 $FontSmall $global:Theme.Sub
    $state = @{ Warnings = @(); Auth = $(if ($entry -and $entry.PSObject.Properties['Auth']) { [bool]$entry.Auth } else { $true }); Import = $null; Ras = @{}; AutoServer = '' }
    $onPick = ({
        # Windows VPN: fill in what the Windows profile already knows, say which protocol and sign-in VeroScudo found
        if ($types[[Math]::Max(0, $cbType.SelectedIndex)] -ne 'ras') { return }
        $info = $state.Ras[$cb.Text.Trim()]
        if (-not $info) {
            $hint.Text = 'Not a Windows VPN profile of this PC: create it in Settings > VPN first, connect once, then pick it here.'
            foreach ($c in $lPort, $tPort) { $c.Visible = $true }
            return
        }
        if ($info.Server -and (-not $tServer.Text.Trim() -or $tServer.Text.Trim() -eq $state.AutoServer)) { $tServer.Text = $info.Server; $state.AutoServer = $info.Server }
        $portUsed = $info.TunnelType -in 'Sstp', 'Automatic'                # only SSTP uses the port; the others have fixed ports
        foreach ($c in $lPort, $tPort) { $c.Visible = $portUsed }
        if (-not $portUsed) { $tPort.Text = '443' }
        $state.Auth = [bool]$info.Password
        foreach ($c in $lUser, $tUser) { if ($c) { $c.Enabled = $state.Auth } }
        $hint.Text = Get-VeroRasDescription -TunnelType $info.TunnelType -Password $info.Password -AllUsers $info.AllUsers
    }).GetNewClosure()
    $apply = ({
        $t = $types[[Math]::Max(0, $cbType.SelectedIndex)]
        $keep = if ($entry) { $cb.Text } else { '' }                        # Items.Clear() can blank the text of an edited entry
        $cb.Items.Clear()
        $names = switch ($t) {
            'ras'       { $state.Ras = @{}; foreach ($v in @(Get-VeroWindowsVpn)) { $state.Ras[$v.Name] = $v }; @($state.Ras.Keys | Sort-Object) }
            'wireguard' { @(Get-Service -Name 'WireGuardTunnel$*' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name.Substring(16) }) }
            default     { @() }
        }
        foreach ($n in $names) { [void]$cb.Items.Add($n) }
        if ($keep) { $cb.Text = $keep } elseif (-not $entry -and $cb.Items.Count -gt 0) { $cb.SelectedIndex = 0 }
        $lName.Text = switch ($t) { 'ras' { 'Windows VPN profile (Settings > VPN)' } 'wireguard' { 'WireGuard tunnel name (exactly as in the WireGuard app)' } default { 'Profile name' } }
        $isOvpn = ($t -eq 'openvpn')
        foreach ($c in $lServer, $tServer, $lPort, $tPort) { $c.Visible = -not $isOvpn }
        foreach ($c in $lFile, $tFile, $bFile, $chkDco) { $c.Visible = $isOvpn }
        $bConf.Visible = ($t -eq 'wireguard')
        $hint.Text = Get-VeroSwitchNotice -Type $t -ProfileName $(if ($cb.Text) { $cb.Text } else { 'this profile' })
        if (-not $entry -and $t -eq 'wireguard' -and $tPort.Text -eq '443') { $tPort.Text = '51820' }
        if (-not $entry -and $t -eq 'ras' -and $tPort.Text -eq '51820') { $tPort.Text = '443' }
        foreach ($c in $lUser, $tUser) { if ($c) { $c.Enabled = $true } }
        & $onPick
    }).GetNewClosure()
    $cb.Add_SelectedIndexChanged($onPick)
    $cb.Add_Leave($onPick)
    $cbType.Add_SelectedIndexChanged($apply)
    $cbType.SelectedIndex = [Math]::Max(0, [array]::IndexOf($types, $(if ($entry -and $entry.PSObject.Properties['Type'] -and $entry.Type) { [string]$entry.Type } else { 'ras' })))
    if ($entry) { $cb.Text = $entry.Profile; $cbType.Enabled = $false; & $onPick }
    $bFile.Add_Click(({
        $dlg = New-Object System.Windows.Forms.OpenFileDialog; $dlg.Filter = 'OpenVPN config (*.ovpn;*.conf)|*.ovpn;*.conf|All files|*.*'
        if ($dlg.ShowDialog() -eq 'OK') { $tFile.Text = $dlg.FileName; if (-not $cb.Text) { $cb.Text = [IO.Path]::GetFileNameWithoutExtension($dlg.FileName) } }
    }).GetNewClosure())
    $bConf.Add_Click(({
        $dlg = New-Object System.Windows.Forms.OpenFileDialog; $dlg.Filter = 'WireGuard config (*.conf)|*.conf|All files|*.*'
        if ($dlg.ShowDialog() -ne 'OK') { return }
        $r = Test-VeroWireGuardConf -Text ([IO.File]::ReadAllText($dlg.FileName))
        if ($r.Errors.Count -gt 0) { [System.Windows.Forms.MessageBox]::Show(($r.Errors -join "`r`n"), 'VeroScudo - WireGuard config') | Out-Null; return }
        $tServer.Text = $r.Server; $tPort.Text = [string]$r.Port
        if (-not $cb.Text) { $cb.Text = [IO.Path]::GetFileNameWithoutExtension($dlg.FileName) }
        $state.Warnings = @($r.Warnings)
        if ($r.Warnings.Count -gt 0) { [System.Windows.Forms.MessageBox]::Show(((@($r.Warnings) | ForEach-Object { '- ' + $_ }) -join "`r`n`r`n"), 'VeroScudo - check', 'OK', 'Warning') | Out-Null }
    }).GetNewClosure())
    $res = @{ Value = $null }
    $bOk = New-Button $ef 'OK' 290 350 110 $true; $bCancel = New-Button $ef 'Cancel' 170 350 110
    $bCancel.Add_Click(({ $ef.Close() }).GetNewClosure())
    $bOk.Add_Click(({
        $t = $types[[Math]::Max(0, $cbType.SelectedIndex)]
        $name = $cb.Text.Trim(); $user = $tUser.Text.Trim(); $pins = if ($entry) { @($entry.ServerIps) } else { @() }
        if (-not $name) { [System.Windows.Forms.MessageBox]::Show('A profile name is required.', 'VeroScudo') | Out-Null; return }
        if ($t -eq 'openvpn') {
            $import = $null; $auth = $state.Auth
            if ($entry -and $name -ne $entry.Profile -and -not $tFile.Text.Trim()) { [System.Windows.Forms.MessageBox]::Show('A renamed OpenVPN profile needs its .ovpn again (the import is stored under the name): choose the file.', 'VeroScudo') | Out-Null; return }
            if ($tFile.Text.Trim() -or -not $entry) {
                $src = $tFile.Text.Trim()
                if (-not $src -or -not (Test-Path -LiteralPath $src)) { [System.Windows.Forms.MessageBox]::Show('Choose the .ovpn file to import.', 'VeroScudo') | Out-Null; return }
                $r = Test-VeroOpenVpnConf -Text ([IO.File]::ReadAllText($src)) -BaseDir (Split-Path -Parent $src)
                if ($r.Errors.Count -gt 0) { [System.Windows.Forms.MessageBox]::Show("This config cannot be used:`r`n`r`n" + ($r.Errors -join "`r`n"), 'VeroScudo - OpenVPN config') | Out-Null; return }
                if (-not (Show-Check "OpenVPN config $([IO.Path]::GetFileName($src)):" $r.Warnings)) { return }
                $import = $src; $auth = $r.Auth
            }
            if ($auth -and -not $user) { [System.Windows.Forms.MessageBox]::Show('This OpenVPN config asks for a username and password: enter the username.', 'VeroScudo') | Out-Null; return }
            $res.Value = [pscustomobject]@{ Profile = $name; Type = 'openvpn'; Server = ''; Port = 1194; Username = $user; ServerIps = @(); Auth = $auth; Dco = $chkDco.Checked; ImportFrom = $import }
        } else {
            $port = 0
            if (-not $tServer.Text.Trim() -or -not [int]::TryParse($tPort.Text, [ref]$port)) { [System.Windows.Forms.MessageBox]::Show('Server and port are required.', 'VeroScudo') | Out-Null; return }
            if ($t -eq 'ras' -and $state.Auth -and -not $user) { [System.Windows.Forms.MessageBox]::Show('A username is required (the one you sign in to this VPN with).', 'VeroScudo') | Out-Null; return }
            if ($t -eq 'wireguard' -and $name -notmatch '^[A-Za-z0-9_=+.-]{1,32}$') { [System.Windows.Forms.MessageBox]::Show('A WireGuard tunnel name is 1-32 of A-Z a-z 0-9 _ = + . -', 'VeroScudo') | Out-Null; return }
            if ($t -eq 'wireguard' -and -not (Show-Check "WireGuard tunnel '$name':" $state.Warnings)) { return }
            $res.Value = [pscustomobject]@{ Profile = $name; Type = $t; Server = $tServer.Text.Trim(); Port = $port; Username = $(if ($t -eq 'ras' -and $state.Auth) { $user } else { '' }); ServerIps = $pins; Auth = ($t -eq 'ras' -and $state.Auth); Dco = $false; ImportFrom = $null }
        }
        $ef.Close()
    }).GetNewClosure())
    & $apply
    $ef.ShowDialog() | Out-Null
    $res.Value
}

function Save-ConfigElevated([string]$json, [object[]]$imports = @()) {
    <# The tray runs without admin rights: config.json is written by an elevated PowerShell (UAC prompt) that validates it
       again. The JSON travels Base64-encoded inside -EncodedCommand - no temp file another process could swap. OpenVPN
       configs to import ({ Profile; Source }) are read, checked and stored by that same elevated process, before the config. #>
    $null = Get-VeroConfig -Raw $json                                       # validate here first for a readable error
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    $imp = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject @($imports | ForEach-Object { @{ Profile = $_.Profile; Source = $_.Source } }) -Depth 3 -Compress)))
    $mod = (Join-Path $PSScriptRoot 'VeroScudo.Core.psm1') -replace "'", "''"
    $script = "try { Import-Module '$mod' -Force; `$list = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$imp')) | ConvertFrom-Json; foreach (`$i in @(`$list | ForEach-Object { `$_ })) { if (`$i) { `$null = Import-VeroOpenVpnProfile -ProfileName `$i.Profile -Source `$i.Source } }; Save-VeroConfig -Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$b64'))) | Out-Null; exit 0 } catch { exit 1 }"
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
    $pr = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList "-NoProfile -NonInteractive -EncodedCommand $enc"
    if ($pr.ExitCode -ne 0) { throw "the elevated save failed (exit $($pr.ExitCode))" }
}

$global:SettingsForm = $null
function Show-Settings {
    if ($global:SettingsForm -and -not $global:SettingsForm.IsDisposed) { $global:SettingsForm.Activate(); return }
    $f = New-Form 'VeroScudo settings' 520 664
    New-Label $f 'VPN profiles' 20 16 200 22 $FontBold | Out-Null
    $card = New-Card $f 20 42 480 300
    $work = New-Object System.Collections.ArrayList
    if ($global:Config) { foreach ($pr in $global:Config.Profiles) { [void]$work.Add(($pr | Select-Object *, @{ n = 'ImportFrom'; e = { $null } })) } }
    $state = @{ Default = $(if ($global:Config) { $global:Config.DefaultProfile } else { '' }) }
    $lb = New-Object System.Windows.Forms.ListBox; $lb.Location = (P 12 12); $lb.Size = (Z 300 276); $lb.BorderStyle = 'FixedSingle'
    $lb.BackColor = $global:Theme.Bg; $lb.ForeColor = $global:Theme.Text; $lb.Font = $FontUI; $lb.IntegralHeight = $false
    $card.Controls.Add($lb)
    $fill = ({
        $sel = $lb.SelectedIndex; $lb.Items.Clear()
        foreach ($pr in $work) {
            $needs = Test-VeroNeedsPassword $pr
            $cred = (-not $needs) -or [bool](Get-VeroCredential -Config $pr)
            $mark = if ($pr.Profile -eq $state.Default) { ' (default)' } else { '' }
            $where = if ($pr.Type -eq 'openvpn') { $(if ($pr.ImportFrom) { 'to import' } else { '.ovpn' }) } else { $pr.Server }
            [void]$lb.Items.Add(('{0}{1} - {2} - {3}{4}' -f $pr.Profile, $mark, (Get-VeroTypeLabel $pr.Type), $where, $(if ($cred) { '' } else { '  [no password]' })))
        }
        if ($lb.Items.Count -gt 0) { $lb.SelectedIndex = [Math]::Max(0, [Math]::Min($sel, $lb.Items.Count - 1)) }
    }).GetNewClosure()
    & $fill
    $bImp = New-Button $card 'Import from Windows...' 324 12 140 $true; $bAdd = New-Button $card 'Add...' 324 52 140
    $bEdit = New-Button $card 'Edit...' 324 92 140; $bDel = New-Button $card 'Remove' 324 132 140
    $bDef = New-Button $card 'Make default' 324 172 140; $bPw = New-Button $card 'Set password...' 324 220 140
    $bKey = New-Button $card 'Key passphrase...' 324 260 140
    $bImp.Add_Click(({
        $have = @($work | ForEach-Object Profile)
        $v = Select-WindowsVpn $have
        if (-not $v) { return }
        $e = ConvertTo-VeroRasEntry -Vpn $v -UserName (Get-VeroRasSavedUser -Name $v.Name -AllUsers $v.AllUsers)
        if ($e.Auth -and -not $e.Username) { $e = Edit-VpnProfile $e }            # the one thing Windows did not tell us
        if (-not $e) { return }
        [void]$work.Add($e); if (-not $state.Default) { $state.Default = $e.Profile }
        & $fill; $lb.SelectedIndex = $lb.Items.Count - 1
    }).GetNewClosure())
    $bAdd.Add_Click(({ $e = Edit-VpnProfile $null; if ($e) { if (@($work | Where-Object Profile -eq $e.Profile)) { [System.Windows.Forms.MessageBox]::Show("'$($e.Profile)' is already in the list.", 'VeroScudo') | Out-Null; return }; [void]$work.Add($e); if (-not $state.Default) { $state.Default = $e.Profile }; & $fill; $lb.SelectedIndex = $lb.Items.Count - 1 } }).GetNewClosure())
    $bEdit.Add_Click(({ $i = $lb.SelectedIndex; if ($i -lt 0) { return }; $e = Edit-VpnProfile $work[$i]; if ($e) { if ($state.Default -eq $work[$i].Profile) { $state.Default = $e.Profile }; $work[$i] = $e; & $fill } }).GetNewClosure())
    $bDel.Add_Click(({ $i = $lb.SelectedIndex; if ($i -lt 0 -or $work.Count -le 1) { return }; $gone = $work[$i].Profile; $work.RemoveAt($i); if ($state.Default -eq $gone) { $state.Default = $work[0].Profile }; & $fill }).GetNewClosure())
    $bDef.Add_Click(({ $i = $lb.SelectedIndex; if ($i -ge 0) { $state.Default = $work[$i].Profile; & $fill } }).GetNewClosure())
    $bPw.Add_Click(({
        $i = $lb.SelectedIndex; if ($i -lt 0) { return }; $e = $work[$i]
        if (-not (Test-VeroNeedsPassword $e)) { [System.Windows.Forms.MessageBox]::Show("'$($e.Profile)' needs no password here$(if ($e.Type -eq 'wireguard') { ' - the WireGuard app keeps its keys' }).", 'VeroScudo') | Out-Null; return }
        $sec = Read-Password "$($e.Username) ($($e.Profile))"
        if ($sec) { $cp = Get-VeroPath -VpnProfile $e.Profile; New-Item -ItemType Directory -Path $cp.UserDir -Force | Out-Null
                    New-Object System.Management.Automation.PSCredential($e.Username, $sec) | Export-Clixml $cp.Cred; & $fill }
    }).GetNewClosure())
    $bKey.Add_Click(({
        $i = $lb.SelectedIndex; if ($i -lt 0) { return }; $e = $work[$i]
        if ($e.Type -ne 'openvpn') { [System.Windows.Forms.MessageBox]::Show('Only an OpenVPN profile with an encrypted private key needs a key passphrase.', 'VeroScudo') | Out-Null; return }
        $sec = Read-Password "the private key of $($e.Profile)"
        if ($sec) { $cp = Get-VeroPath -VpnProfile $e.Profile; New-Item -ItemType Directory -Path $cp.UserDir -Force | Out-Null
                    New-Object System.Management.Automation.PSCredential('key', $sec) | Export-Clixml $cp.KeyPass }
    }).GetNewClosure())
    New-Label $f 'Behaviour' 20 356 200 22 $FontBold | Out-Null
    $card2 = New-Card $f 20 382 480 150
    $chkStrict = New-Object System.Windows.Forms.CheckBox; $chkStrict.Text = 'Strict kill-switch (always on - cannot be disabled)'; $chkStrict.Checked = $true; $chkStrict.AutoCheck = $false; $chkStrict.Location = (P 12 12); $chkStrict.Size = (Z 450 24); $chkStrict.ForeColor = $global:Theme.Sub; $card2.Controls.Add($chkStrict)
    $chkVm = New-Object System.Windows.Forms.CheckBox; $chkVm.Text = 'Protect WSL / Docker Desktop traffic too'; $chkVm.Location = (P 12 42); $chkVm.Size = (Z 450 24); $chkVm.ForeColor = $global:Theme.Text; $chkVm.Checked = (-not $global:Config) -or ($global:Config.Vm -ne $false); $card2.Controls.Add($chkVm)
    $chkWifi = New-Object System.Windows.Forms.CheckBox; $chkWifi.Text = 'Wi-Fi reset fix (recommended; applied by the installer)'; $chkWifi.Location = (P 12 72); $chkWifi.Size = (Z 450 24); $chkWifi.ForeColor = $global:Theme.Text; $chkWifi.Checked = (-not $global:Config) -or $global:Config.WifiRecoveryFix; $card2.Controls.Add($chkWifi)
    $chkUpd = New-Object System.Windows.Forms.CheckBox; $chkUpd.Text = 'Check for a new release when the tray starts'; $chkUpd.Location = (P 12 102); $chkUpd.Size = (Z 450 24); $chkUpd.ForeColor = $global:Theme.Text; $chkUpd.Checked = (-not $global:Config) -or $global:Config.UpdateCheck; $card2.Controls.Add($chkUpd)
    New-Label $f 'Passwords are saved at once (your account only). Saving the rest writes config.json (administrator prompt).' 20 544 480 36 $FontSmall $global:Theme.Sub | Out-Null
    $bCancel = New-Button $f 'Close' 270 604 110
    $bSave   = New-Button $f 'Save' 390 604 110 $true
    $bCancel.Add_Click(({ $f.Close() }).GetNewClosure())
    $bSave.Add_Click(({
        if ($work.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show('Add at least one VPN profile.', 'VeroScudo') | Out-Null; return }
        $json = [ordered]@{
            profiles = @($work | ForEach-Object { ConvertTo-VeroProfileObject $_ })
            activeProfile = $state.Default
            retrySeconds = $(if ($global:Config) { $global:Config.RetrySeconds } else { 10 }); vm = $(if ($chkVm.Checked) { 'auto' } else { $false })
            wifiRecoveryFix = $chkWifi.Checked; updateCheck = $chkUpd.Checked; lanAllow = @($(if ($global:Config) { $global:Config.LanAllow } else { @() }))
        } | ConvertTo-Json -Depth 6
        $imports = @($work | Where-Object { $_.Type -eq 'openvpn' -and $_.ImportFrom } | ForEach-Object { [pscustomobject]@{ Profile = $_.Profile; Source = $_.ImportFrom } })
        try { Save-ConfigElevated $json $imports; $global:Config = Get-VeroConfig; Update-ProfileMenu; $f.Close() }
        catch { [System.Windows.Forms.MessageBox]::Show("Not saved: $($_.Exception.Message)", 'VeroScudo') | Out-Null }
    }).GetNewClosure())
    $global:SettingsForm = $f
    $f.Show(); $f.Activate(); $bCancel.Focus() | Out-Null
    $f
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
$iconPx = (Z 18 18).Width; $blankImage = New-Object System.Drawing.Bitmap($iconPx, $iconPx)
$menu.Padding = Pad 0 6 0 6; $menu.BackColor = $global:Theme.Card; $menu.ForeColor = $global:Theme.Text
$menu.Add_HandleCreated({ [VeroNative]::Style($this.Handle, $global:Dark) })
function Add-MenuItem([string]$text, [string]$glyph, [scriptblock]$onClick) {
    $m = $menu.Items.Add($text); $m.Tag = $glyph; $m.Padding = (Pad 0 7 16 7); $m.Margin = New-Object System.Windows.Forms.Padding(0)
    if ($glyph) { $m.Image = $blankImage; $m.ImageScaling = 'None' }
    if ($onClick) { $m.Add_Click($onClick) }
    $m
}
function Add-MenuSeparator {
    $sep = New-Object System.Windows.Forms.ToolStripSeparator; $sep.Margin = Pad 0 3 0 3; $menu.Items.Add($sep) | Out-Null
}
$menu.Renderer.Logo = Get-AppImage 64
$mHead = Add-MenuItem 'VeroScudo' 'logo' $null; $mHead.Enabled = $false; $mHead.Font = $FontBold
$null = Add-MenuSeparator
$mOn   = Add-MenuItem 'Turn VPN on'  'play' { Request-TurnOn }   
$mOff  = Add-MenuItem 'Turn VPN off' 'stop' { Invoke-GuardTask 'Off' }  
$mRedo = Add-MenuItem 'Reconnect VPN' 'redo' { Request-Reconnect }
$mProf = Add-MenuItem 'VPN profile' 'globe' $null
$mProf.DropDown.Renderer = $menu.Renderer; $mProf.DropDown.BackColor = $global:Theme.Card; $mProf.DropDown.ForeColor = $global:Theme.Text
$mProf.DropDown.Padding = Pad 0 6 0 6
$mProf.DropDown.Add_HandleCreated({ [VeroNative]::Style($this.Handle, $global:Dark) })
$global:TrayFile = Join-Path $global:Paths.UserDir 'tray.json'              # per-user tray choices (the state folder is read-only for the tray)
function Get-TrayPref {
    $o = @{ keepAwake = $false; lastProfile = '' }
    try { if (Test-Path $global:TrayFile) { $j = Get-Content $global:TrayFile -Raw | ConvertFrom-Json; foreach ($k in @($o.Keys)) { if ($j.PSObject.Properties[$k]) { $o[$k] = $j.$k } } } } catch { Write-Verbose 'tray.json unreadable' }
    $o
}
function Set-TrayPref([string]$key, $value) {
    $o = Get-TrayPref; $o[$key] = $value
    try { New-Item -ItemType Directory -Path $global:Paths.UserDir -Force | Out-Null; $o | ConvertTo-Json | Set-Content $global:TrayFile -Encoding UTF8 } catch { Write-Verbose 'tray.json not writable' }
}
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
    <# Before Turn on: another VPN is connected. Returns 'disconnect', 'anyway' or 'cancel'. Nothing happens without a click. #>
    $prof = $global:Config.Profile
    $canAll = -not @($foreign | Where-Object { -not $_.CanDisconnect })
    $names = ($foreign | ForEach-Object { '"' + $_.Name + '"' }) -join ', '
    $one = @($foreign).Count -eq 1
    $kindText = if ($one -and -not $foreign[0].Configured -and $foreign[0].Kind -ne 'app') { ' It is not a VeroScudo profile.' } elseif ($one -and $foreign[0].Configured) { ' It is another VeroScudo profile.' } else { '' }
    $msg = $names + $(if ($one) { ' is' } else { ' are' }) + ' connected.' + $kindText + "`r`n" +
           'VeroScudo will connect "' + $prof + '" and block everything else, including ' + $(if ($one) { 'its' } else { 'their' }) + ' traffic.'
    if (-not $canAll) { $msg += "`r`n`r`nVeroScudo cannot disconnect a VPN app's own tunnel - close that app first, or turn on anyway (its traffic stays blocked)." }
    $pf = New-Form 'VeroScudo' 480 230
    New-Label $pf $msg 20 18 440 120 $FontUI | Out-Null
    $res = @{ Value = 'cancel' }
    $label = if (-not $canAll) { 'Turn on anyway' } elseif ($one) { 'Disconnect ' + $foreign[0].Name + ' and turn on' } else { 'Disconnect them and turn on' }
    if ($label.Length -gt 34) { $label = if ($canAll) { 'Disconnect and turn on' } else { 'Turn on anyway' } }
    $bGo = New-Button $pf $label 20 170 300 $true; $bNo = New-Button $pf 'Cancel' 340 170 120
    $bGo.Add_Click(({ $res.Value = $(if ($canAll) { 'disconnect' } else { 'anyway' }); $pf.Close() }).GetNewClosure())
    $bNo.Add_Click(({ $pf.Close() }).GetNewClosure())
    $pf.TopMost = $true; $pf.AcceptButton = $bNo
    $pf.ShowDialog() | Out-Null
    $res.Value
}

function Request-TurnOn {
    <# Turn VPN on: first asks when another VPN is connected (it would be blocked silently otherwise). #>
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
function Test-FileChanged([string]$path) {
    # true once per new write of a state file (the guard writes them; the tray only reads)
    $t = if (Test-Path $path) { (Get-Item $path).LastWriteTimeUtc.Ticks } else { 0 }
    $first = -not $global:Stamps.ContainsKey($path)
    $changed = (-not $first) -and $t -ne 0 -and $global:Stamps[$path] -ne $t
    $global:Stamps[$path] = $t
    $changed
}
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

function Request-Reconnect {
    <# Reconnect: the elevated task blocks traffic, hangs up and redials; traffic flows again once the tunnel is back. #>
    if (-not (Test-VeroArmed)) { $notify.ShowBalloonTip(4000, 'VeroScudo', 'The VPN is off - use Turn VPN on.', [System.Windows.Forms.ToolTipIcon]::Info); return }
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
    $rel = Get-VeroLatestRelease
    $info.checked = (Get-Date).ToString('o')
    if ($rel -and (Test-VeroNewerVersion -Tag $rel.Tag)) {
        $global:Update = $rel
        $mUpd.Text = "Update available: $($rel.Tag)"
        if ($info.notified -ne $rel.Tag) {
            $notify.ShowBalloonTip(8000, "VeroScudo $($rel.Tag) is available", "You run $(Get-VeroVersion). Open the tray menu to see the release.", [System.Windows.Forms.ToolTipIcon]::Info)
            $info.notified = $rel.Tag
        }
    } else { $global:Update = $null; $mUpd.Text = 'Check for updates' }
    try { New-Item -ItemType Directory -Path $global:Paths.UserDir -Force | Out-Null; $info | ConvertTo-Json | Set-Content $global:UpdateFile } catch { Write-Verbose 'update.json not writable' }
}

function Refresh {
    if (Update-ConfigCache) { Update-ProfileMenu }
    $st = Get-State
    $notify.Icon = Get-StateIcon $st.State
    $tip = "VeroScudo - $($st.Title)$(if ([VeroKeepAwake]::Active) { ', keeping PC awake' })"; $notify.Text = $tip.Substring(0, [Math]::Min(63, $tip.Length))
    $mHead.Text = "VeroScudo - $($st.Title)"
    $mOn.Enabled = ($st.State -ne 'protected'); $mOff.Enabled = $st.Armed -or $st.Connected; $mRedo.Enabled = $st.Armed
    $noticed = Show-SwitchNotice
    if (-not $noticed) { $noticed = Show-ForeignNotice }
    Request-Otp
    if (-not $noticed -and $global:Last -and $global:Last -ne $st.State) {
        $b = switch ($st.State) {
            'blocked'   { @('VPN connection lost - traffic blocked', 'Reconnecting... nothing leaves this PC until the tunnel is back.', 'Warning') }
            'protected' { @('VPN protected', 'Tunnel up, kill-switch on.', 'Info') }
            'off'       { @('VPN turned off', 'Firewall back to normal - traffic is NOT protected.', 'Info') }
            default     { @('VeroScudo needs attention', $st.Text, 'Warning') }
        }
        $notify.ShowBalloonTip(5000, $b[0], $b[1], [System.Windows.Forms.ToolTipIcon]$b[2])
    }
    $global:Last = $st.State
}

# ---------------------------------------------------------------- preview mode (screenshots for review), then run
if ($Preview) {
    New-Item -ItemType Directory -Path $Preview -Force | Out-Null
    $suffix = if ($global:Dark) { '-dark' } else { '-light' }
    foreach ($maker in @({ Show-Status }, { Show-Settings }, { Show-About })) {
        $fm = & $maker
        $fm.StartPosition = 'Manual'; $fm.Location = New-Object System.Drawing.Point(40, 40); $fm.TopMost = $true
        foreach ($k in 1..5) { [System.Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 250 }
        $bmp = New-Object System.Drawing.Bitmap($fm.Width, $fm.Height); $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($fm.Location, [System.Drawing.Point]::Empty, $fm.Size)
        $name = (($fm.Text -replace '[^A-Za-z]', '').ToLower()) + $suffix + '.png'; $bmp.Save((Join-Path $Preview $name)); $g.Dispose(); $fm.Close()
    }
    $menu.Show((New-Object System.Drawing.Point(1200, 200))); foreach ($k in 1..6) { [System.Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 300 }
    $mw = $menu.Width + 40; $mh = $menu.Height + 40
    $bmp = New-Object System.Drawing.Bitmap($mw, $mh); $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen((New-Object System.Drawing.Point(1180, 180)), [System.Drawing.Point]::Empty, (New-Object System.Drawing.Size($mw, $mh))); $bmp.Save((Join-Path $Preview ('menu' + $suffix + '.png'))); $g.Dispose()
    $notify.Visible = $false; $notify.Dispose()
    [Environment]::Exit(0)
}
$timer = New-Object System.Windows.Forms.Timer; $timer.Interval = $PollSeconds * 1000; $timer.Add_Tick({ Refresh }); $timer.Start()
$firstCheck = New-Object System.Windows.Forms.Timer; $firstCheck.Interval = 120 * 1000; $firstCheck.Add_Tick({ $firstCheck.Stop(); try { Invoke-UpdateCheck } catch { Write-Verbose "update check: $($_.Exception.Message)" } }); $firstCheck.Start()
Refresh
[System.Windows.Forms.Application]::Run()
