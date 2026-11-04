// VeroScudo tray helpers (Windows): DPI awareness, dark title bars, keep-awake, the keep-awake badge on the tray icon,
// the theme colours, the menu renderer, and the themed message box shim. Compiled in memory by VeroScudoTray.ps1 at
// start (Add-Type with System.Windows.Forms and System.Drawing referenced), never written to disk as a DLL - the same way
// the core loads its native helper. tests/VeroScudo.Tray.Tests.ps1 compiles this file with the same references.
using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;

public static class VeroNative {
    [DllImport("shcore.dll")] static extern int SetProcessDpiAwareness(int value);
    [DllImport("user32.dll")] static extern bool SetProcessDPIAware();
    [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);
    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)] static extern int SetWindowTheme(IntPtr hwnd, string app, string idList);
    public static void EnableDpi() { try { SetProcessDpiAwareness(2); } catch { SetProcessDPIAware(); } }
    // dark scroll bars on text and list boxes (the light default looks like a white bar on a dark window)
    public static void DarkScroll(IntPtr hwnd, bool dark) { try { SetWindowTheme(hwnd, dark ? "DarkMode_Explorer" : "Explorer", null); } catch { } }
    public static void DarkCombo(IntPtr hwnd, bool dark) { try { SetWindowTheme(hwnd, dark ? "DarkMode_CFD" : "CFD", null); } catch { } }
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

// Keep-awake badge on the tray icon: a green ring with a dark border in the bottom-right corner, where the
// shield narrows, so the state glyph stays readable. Drawn at the tray's real pixel size (SM_CXSMICON at the
// current DPI) instead of shipping a second icon set; proportions are the 16 px design scaled up.
// The base comes from the shipped <state>-<size>.png, not the .ico: every .ico frame is PNG-compressed and
// System.Drawing's Icon/DrawIcon cannot decode those (it paints uninitialised memory).
public static class VeroTrayIcon {
    [DllImport("user32.dll")] static extern bool DestroyIcon(IntPtr h);
    static readonly int[] Sizes = { 16, 24, 32, 48, 64, 128, 256 };
    public static Icon WithAwakeBadge(string pngDir, string state) {
        int px = SystemInformation.SmallIconSize.Width;
        int src = Sizes[Sizes.Length - 1];
        foreach (int s in Sizes) if (s >= px) { src = s; break; }        // exact size, else the next larger one scaled down
        string file = System.IO.Path.Combine(pngDir, state + "-" + src + ".png");
        using (var baseImg = Image.FromFile(file))
        using (var bmp = new Bitmap(px, px, System.Drawing.Imaging.PixelFormat.Format32bppArgb)) {
            using (var g = Graphics.FromImage(bmp)) {
                g.Clear(Color.Transparent);
                g.SmoothingMode = SmoothingMode.AntiAlias; g.PixelOffsetMode = PixelOffsetMode.HighQuality;
                g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                g.DrawImage(baseImg, new Rectangle(0, 0, px, px));
                float u = px / 16f, d = 7f * u, x = px - d;
                float border = 1.4f * u, hole = border + 1.6f * u;          // dark border, green ring, dark centre
                using (var dark = new SolidBrush(Color.FromArgb(20, 20, 20)))
                using (var green = new SolidBrush(Color.FromArgb(46, 204, 64))) {
                    g.FillEllipse(dark, x, x, d, d);
                    g.FillEllipse(green, x + border, x + border, d - 2 * border, d - 2 * border);
                    g.FillEllipse(dark, x + hole, x + hole, d - 2 * hole, d - 2 * hole);
                }
            }
            IntPtr h = bmp.GetHicon();
            try { return (Icon)Icon.FromHandle(h).Clone(); }               // the clone owns its own copy of the handle
            finally { DestroyIcon(h); }
        }
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

// Every message goes through the tray's own themed window; this keeps the MessageBox call shape (text, title, buttons, icon)
// and hands the call to the PowerShell handler the tray installs.
public static class VeroMsg {
    public static System.Management.Automation.ScriptBlock Handler;
    public static string Show(string text) { return Show(text, "VeroScudo", "OK", "None"); }
    public static string Show(string text, string title) { return Show(text, title, "OK", "None"); }
    public static string Show(string text, string title, string buttons) { return Show(text, title, buttons, "None"); }
    public static string Show(string text, string title, string buttons, string icon) {
        foreach (var o in Handler.Invoke(text, title, buttons, icon)) { if (o != null) return o.ToString(); }
        return "None";
    }
}
