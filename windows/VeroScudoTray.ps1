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
    $armed = Test-VeroArmed; $up = Test-VeroVpnConnected $global:Config.Profile
    $cp = Get-VeroPath -VpnProfile $global:Config.Profile
    $cred = (Test-Path $cp.Cred) -or (Test-Path $cp.LegacyCred)
    $state = if (-not $cred) { 'attention' } elseif (-not $armed) { 'off' } elseif ($up) { 'protected' } else { 'blocked' }
    $title, $text = switch ($state) {
        'protected' { 'Protected', "$($global:Config.Profile) connected - kill-switch on" }
        'blocked'   { 'Blocked - reconnecting', "$($global:Config.Profile) lost - nothing leaves this PC until it is back" }
        'off'       { 'Off', 'VPN turned off by you - normal network, not protected' }
        default     { 'Attention', "VPN password for '$($global:Config.Profile)' not stored - open Settings" }
    }
    [pscustomobject]@{ State = $state; Title = $title; Text = $text; Armed = $armed; Connected = $up }
}
function Invoke-GuardTask([string]$name) { Start-Process schtasks.exe -ArgumentList "/run /tn `"$global:Folder$name`"" -WindowStyle Hidden }
function Get-LastEvents([int]$n = 6) { if (Test-Path $global:Paths.Log) { Get-Content $global:Paths.Log -Tail $n | ForEach-Object { $_ -replace '^\d{4}-\d\d-\d\d ', '' } } else { @() } }
function Get-LastDrop { try { $e = Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='RasClient'; Id=20226 } -MaxEvents 1 -ErrorAction Stop; if ($e.Properties[2].Value -eq $global:Config.Profile) { $c = $e.Properties[3].Value; return ('{0:HH:mm} - {1}' -f $e.TimeCreated, $(if ($c -eq 631) { 'you disconnected' } elseif ($c -eq 829) { 'link failure (829)' } else { "code $c" })) } } catch { Write-Verbose 'no RAS event' }; '-' }

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
    $cards = @{}
    $i = 0
    foreach ($k in 'VPN profile', 'Firewall', 'Last drop', 'Redial') {
        $cx = 20 + ($i % 2) * 215; $cy = 126 + [math]::Floor($i / 2) * 78
        $c = New-Card $f $cx $cy 205 66
        New-Label $c ($k.ToUpper()) 12 8 180 16 $FontSmall $global:Theme.Sub | Out-Null
        $cards[$k] = New-Label $c '' 12 28 185 24 $FontBold
        $i++
    }
    $ev = New-Card $f 20 292 420 160
    New-Label $ev 'RECENT EVENTS' 12 8 200 16 $FontSmall $global:Theme.Sub | Out-Null
    $evText = New-Object System.Windows.Forms.TextBox; $evText.Multiline = $true; $evText.ReadOnly = $true; $evText.BorderStyle = 'None'
    $evText.Location = (P 12 30); $evText.Size = (Z 396 120); $evText.Font = $FontMono; $evText.BackColor = $global:Theme.Card; $evText.ForeColor = $global:Theme.Text; $evText.ScrollBars = 'None'; $evText.WordWrap = $false; $evText.TabStop = $false; $evText.Cursor = 'Default'
    $ev.Controls.Add($evText)
    $bOnOff = New-Button $f 'Turn VPN off' 20 470 135
    $bLog   = New-Button $f 'Open log' 165 470 130
    $bCopy  = New-Button $f 'Copy report' 305 470 135 $true
    $bLog.Add_Click(({ if (Test-Path $global:Paths.Log) { Start-Process notepad.exe $global:Paths.Log } }).GetNewClosure())
    $bCopy.Add_Click(({ $s = Get-VeroStatus -Config $global:Config; $txt = ($s.PSObject.Properties | ForEach-Object { '{0,-11} {1}' -f $_.Name, $_.Value }) -join "`r`n"; $txt += "`r`n`r`n--- last events`r`n" + ((Get-LastEvents 15) -join "`r`n"); [System.Windows.Forms.Clipboard]::SetText($txt); $bCopy.Text = 'Copied'; }).GetNewClosure())
    $bOnOff.Add_Click(({ if ($bOnOff.Text -like '*off') { Invoke-GuardTask 'Off' } else { Invoke-GuardTask 'On' } }).GetNewClosure())
    $refresh = ({
        $st = Get-State
        $pic.Image = Get-StateImage $st.State 64; $title.Text = $st.Title; $sub.Text = $st.Text
        $title.ForeColor = switch ($st.State) { 'protected' { [System.Drawing.Color]::FromArgb(48,200,79) } 'blocked' { [System.Drawing.Color]::FromArgb(248,80,70) } 'attention' { [System.Drawing.Color]::FromArgb(252,187,45) } default { $global:Theme.Text } }
        $cards['VPN profile'].Text = if ($global:Config) { $global:Config.Profile } else { '-' }
        $cards['Firewall'].Text = if ($st.Armed) { 'kill-switch ON' } else { 'normal' }
        $cards['Firewall'].ForeColor = if ($st.Armed -and -not $st.Connected) { [System.Drawing.Color]::FromArgb(248,80,70) } else { $global:Theme.Text }
        $cards['Last drop'].Text = Get-LastDrop
        $cards['Redial'].Text = if ($st.Armed -and -not $st.Connected) { 'running' } else { 'idle' }
        $evText.Text = (Get-LastEvents 6) -join "`r`n"; $evText.Select(0, 0)
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

function Edit-VpnProfile($entry) {
    <# Modal editor for one profile entry; returns the edited entry or $null (cancel). #>
    $ef = New-Form 'VPN profile' 420 300
    New-Label $ef 'Windows VPN profile' 20 16 200 18 $FontSmall $global:Theme.Sub | Out-Null
    $cb = New-Object System.Windows.Forms.ComboBox; $cb.Location = (P 20 36); $cb.Size = (Z 380 30); $cb.DropDownStyle = 'DropDownList'; $cb.FlatStyle = 'Flat'; $cb.BackColor = $global:Theme.Bg; $cb.ForeColor = $global:Theme.Text; $cb.Font = $FontUI
    $names = @(Get-VpnConnection -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
    if ($entry -and $names -notcontains $entry.Profile) { $names += $entry.Profile }
    $names | ForEach-Object { [void]$cb.Items.Add($_) }
    if ($entry) { $cb.SelectedItem = $entry.Profile } elseif ($names.Count -gt 0) { $cb.SelectedIndex = 0 }
    $ef.Controls.Add($cb)
    New-Label $ef 'Server host name' 20 80 200 18 $FontSmall $global:Theme.Sub | Out-Null
    $tServer = New-Input $ef 20 100 290 $(if ($entry) { $entry.Server } else { '' })
    New-Label $ef 'Port' 320 80 60 18 $FontSmall $global:Theme.Sub | Out-Null
    $tPort = New-Input $ef 320 100 80 $(if ($entry) { [string]$entry.Port } else { '443' })
    New-Label $ef 'Username' 20 144 200 18 $FontSmall $global:Theme.Sub | Out-Null
    $tUser = New-Input $ef 20 164 380 $(if ($entry) { $entry.Username } else { '' })
    $res = @{ Value = $null }
    $bOk = New-Button $ef 'OK' 290 240 110 $true; $bCancel = New-Button $ef 'Cancel' 170 240 110
    $bCancel.Add_Click(({ $ef.Close() }).GetNewClosure())
    $bOk.Add_Click(({
        $port = 0
        if (-not $cb.SelectedItem -or -not $tServer.Text.Trim() -or -not $tUser.Text.Trim() -or -not [int]::TryParse($tPort.Text, [ref]$port)) { [System.Windows.Forms.MessageBox]::Show('Profile, server, port and username are required.', 'VeroScudo') | Out-Null; return }
        $pins = if ($entry) { @($entry.ServerIps) } else { @() }
        $res.Value = [pscustomobject]@{ Profile = [string]$cb.SelectedItem; Server = $tServer.Text.Trim(); Port = $port; Username = $tUser.Text.Trim(); ServerIps = $pins }
        $ef.Close()
    }).GetNewClosure())
    $ef.ShowDialog() | Out-Null
    $res.Value
}

function Save-ConfigElevated([string]$json) {
    <# The tray runs without admin rights: config.json is written by an elevated PowerShell (UAC prompt) that validates it
       again. The JSON travels Base64-encoded inside -EncodedCommand - no temp file another process could swap. #>
    $null = Get-VeroConfig -Raw $json                                       # validate here first for a readable error
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    $mod = (Join-Path $PSScriptRoot 'VeroScudo.Core.psm1') -replace "'", "''"
    $script = "try { Import-Module '$mod' -Force; Save-VeroConfig -Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$b64'))) | Out-Null; exit 0 } catch { exit 1 }"
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
    $pr = Start-Process powershell.exe -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList "-NoProfile -NonInteractive -EncodedCommand $enc"
    if ($pr.ExitCode -ne 0) { throw "the elevated save failed (exit $($pr.ExitCode))" }
}

$global:SettingsForm = $null
function Show-Settings {
    if ($global:SettingsForm -and -not $global:SettingsForm.IsDisposed) { $global:SettingsForm.Activate(); return }
    $f = New-Form 'VeroScudo settings' 520 600
    New-Label $f 'VPN profiles' 20 16 200 22 $FontBold | Out-Null
    $card = New-Card $f 20 42 480 236
    $work = New-Object System.Collections.ArrayList
    if ($global:Config) { foreach ($pr in $global:Config.Profiles) { [void]$work.Add($pr) } }
    $state = @{ Default = $(if ($global:Config) { $global:Config.DefaultProfile } else { '' }) }
    $lb = New-Object System.Windows.Forms.ListBox; $lb.Location = (P 12 12); $lb.Size = (Z 300 210); $lb.BorderStyle = 'FixedSingle'
    $lb.BackColor = $global:Theme.Bg; $lb.ForeColor = $global:Theme.Text; $lb.Font = $FontUI; $lb.IntegralHeight = $false
    $card.Controls.Add($lb)
    $fill = ({
        $sel = $lb.SelectedIndex; $lb.Items.Clear()
        foreach ($pr in $work) {
            $cred = [bool](Get-VeroCredential -Config $pr)
            $mark = if ($pr.Profile -eq $state.Default) { ' (default)' } else { '' }
            [void]$lb.Items.Add(('{0}{1} - {2}{3}' -f $pr.Profile, $mark, $pr.Server, $(if ($cred) { '' } else { '  [no password]' })))
        }
        if ($lb.Items.Count -gt 0) { $lb.SelectedIndex = [Math]::Max(0, [Math]::Min($sel, $lb.Items.Count - 1)) }
    }).GetNewClosure()
    & $fill
    $bAdd = New-Button $card 'Add...' 324 12 140; $bEdit = New-Button $card 'Edit...' 324 52 140; $bDel = New-Button $card 'Remove' 324 92 140
    $bDef = New-Button $card 'Make default' 324 132 140; $bPw = New-Button $card 'Set password...' 324 188 140
    $bAdd.Add_Click(({ $e = Edit-VpnProfile $null; if ($e) { if (@($work | Where-Object Profile -eq $e.Profile)) { [System.Windows.Forms.MessageBox]::Show("'$($e.Profile)' is already in the list.", 'VeroScudo') | Out-Null; return }; [void]$work.Add($e); if (-not $state.Default) { $state.Default = $e.Profile }; & $fill; $lb.SelectedIndex = $lb.Items.Count - 1 } }).GetNewClosure())
    $bEdit.Add_Click(({ $i = $lb.SelectedIndex; if ($i -lt 0) { return }; $e = Edit-VpnProfile $work[$i]; if ($e) { if ($state.Default -eq $work[$i].Profile) { $state.Default = $e.Profile }; $work[$i] = $e; & $fill } }).GetNewClosure())
    $bDel.Add_Click(({ $i = $lb.SelectedIndex; if ($i -lt 0 -or $work.Count -le 1) { return }; $gone = $work[$i].Profile; $work.RemoveAt($i); if ($state.Default -eq $gone) { $state.Default = $work[0].Profile }; & $fill }).GetNewClosure())
    $bDef.Add_Click(({ $i = $lb.SelectedIndex; if ($i -ge 0) { $state.Default = $work[$i].Profile; & $fill } }).GetNewClosure())
    $bPw.Add_Click(({
        $i = $lb.SelectedIndex; if ($i -lt 0) { return }; $e = $work[$i]
        $sec = Read-Password "$($e.Username) ($($e.Profile))"
        if ($sec) { $cp = Get-VeroPath -VpnProfile $e.Profile; New-Item -ItemType Directory -Path $cp.UserDir -Force | Out-Null
                    New-Object System.Management.Automation.PSCredential($e.Username, $sec) | Export-Clixml $cp.Cred; & $fill }
    }).GetNewClosure())
    New-Label $f 'Behaviour' 20 292 200 22 $FontBold | Out-Null
    $card2 = New-Card $f 20 318 480 150
    $chkStrict = New-Object System.Windows.Forms.CheckBox; $chkStrict.Text = 'Strict kill-switch (always on - cannot be disabled)'; $chkStrict.Checked = $true; $chkStrict.AutoCheck = $false; $chkStrict.Location = (P 12 12); $chkStrict.Size = (Z 450 24); $chkStrict.ForeColor = $global:Theme.Sub; $card2.Controls.Add($chkStrict)
    $chkVm = New-Object System.Windows.Forms.CheckBox; $chkVm.Text = 'Protect WSL / Docker Desktop traffic too'; $chkVm.Location = (P 12 42); $chkVm.Size = (Z 450 24); $chkVm.ForeColor = $global:Theme.Text; $chkVm.Checked = (-not $global:Config) -or ($global:Config.Vm -ne $false); $card2.Controls.Add($chkVm)
    $chkWifi = New-Object System.Windows.Forms.CheckBox; $chkWifi.Text = 'Wi-Fi reset fix (recommended; applied by the installer)'; $chkWifi.Location = (P 12 72); $chkWifi.Size = (Z 450 24); $chkWifi.ForeColor = $global:Theme.Text; $chkWifi.Checked = (-not $global:Config) -or $global:Config.WifiRecoveryFix; $card2.Controls.Add($chkWifi)
    $chkUpd = New-Object System.Windows.Forms.CheckBox; $chkUpd.Text = 'Check for a new release when the tray starts'; $chkUpd.Location = (P 12 102); $chkUpd.Size = (Z 450 24); $chkUpd.ForeColor = $global:Theme.Text; $chkUpd.Checked = (-not $global:Config) -or $global:Config.UpdateCheck; $card2.Controls.Add($chkUpd)
    New-Label $f 'Passwords are saved at once (your account only). Saving the rest writes config.json (administrator prompt).' 20 480 480 36 $FontSmall $global:Theme.Sub | Out-Null
    $bCancel = New-Button $f 'Close' 270 540 110
    $bSave   = New-Button $f 'Save' 390 540 110 $true
    $bCancel.Add_Click(({ $f.Close() }).GetNewClosure())
    $bSave.Add_Click(({
        if ($work.Count -eq 0) { [System.Windows.Forms.MessageBox]::Show('Add at least one VPN profile.', 'VeroScudo') | Out-Null; return }
        $json = [ordered]@{
            profiles = @($work | ForEach-Object { $o = [ordered]@{ profile = $_.Profile; server = $_.Server; port = $_.Port; username = $_.Username }; if (@($_.ServerIps).Count -gt 0) { $o.serverIps = @($_.ServerIps) }; $o })
            activeProfile = $state.Default
            retrySeconds = $(if ($global:Config) { $global:Config.RetrySeconds } else { 10 }); vm = $(if ($chkVm.Checked) { 'auto' } else { $false })
            wifiRecoveryFix = $chkWifi.Checked; updateCheck = $chkUpd.Checked; lanAllow = @($(if ($global:Config) { $global:Config.LanAllow } else { @() }))
        } | ConvertTo-Json -Depth 6
        try { Save-ConfigElevated $json; $global:Config = Get-VeroConfig; Update-ProfileMenu; $f.Close() }
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
$mOn   = Add-MenuItem 'Turn VPN on'  'play' { Invoke-GuardTask 'On' }   
$mOff  = Add-MenuItem 'Turn VPN off' 'stop' { Invoke-GuardTask 'Off' }  
$mProf = Add-MenuItem 'VPN profile' 'globe' $null
$mProf.DropDown.Renderer = $menu.Renderer; $mProf.DropDown.BackColor = $global:Theme.Card; $mProf.DropDown.ForeColor = $global:Theme.Text
$mProf.DropDown.Padding = Pad 0 6 0 6
$mProf.DropDown.Add_HandleCreated({ [VeroNative]::Style($this.Handle, $global:Dark) })
$global:TrayFile = Join-Path $global:Paths.UserDir 'tray.json'              # per-user tray choices (the state folder is read-only for the tray)
function Test-KeepAwakeSaved {
    try { if (Test-Path $global:TrayFile) { return [bool](Get-Content $global:TrayFile -Raw | ConvertFrom-Json).keepAwake } } catch { Write-Verbose 'tray.json unreadable' }
    $false
}
function Save-KeepAwake([bool]$on) {
    try { New-Item -ItemType Directory -Path $global:Paths.UserDir -Force | Out-Null; @{ keepAwake = $on } | ConvertTo-Json | Set-Content $global:TrayFile -Encoding UTF8 } catch { Write-Verbose 'tray.json not writable' }
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
    $mProf.Text = "VPN profile: $($global:Config.Profile)"
    foreach ($pr in $global:Config.Profiles) {
        $it = $mProf.DropDownItems.Add($pr.Profile)
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
    $mOn.Enabled = ($st.State -ne 'protected'); $mOff.Enabled = $st.Armed -or $st.Connected
    if ($global:Last -and $global:Last -ne $st.State) {
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
