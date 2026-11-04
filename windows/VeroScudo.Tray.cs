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
    // the tray menu and its submenu: dark mode, Windows 11's small rounded corners and its own 1 px border in the theme's
    // colour. True when Windows took the corners (Windows 11) - the renderer then leaves the border to Windows, because a
    // square line drawn by hand is cut off at the rounded corners. False on Windows 10: the renderer draws the border.
    public static bool MenuFrame(IntPtr hwnd, bool dark, Color border) {
        int d = dark ? 1 : 0; DwmSetWindowAttribute(hwnd, 20, ref d, 4);       // DWMWA_USE_IMMERSIVE_DARK_MODE
        int r = 3; bool rounded = DwmSetWindowAttribute(hwnd, 33, ref r, 4) == 0;   // DWMWA_WINDOW_CORNER_PREFERENCE = round small
        if (rounded) { int c = border.R | (border.G << 8) | (border.B << 16); DwmSetWindowAttribute(hwnd, 34, ref c, 4); }   // DWMWA_BORDER_COLOR
        return rounded;
    }
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
    public Color Bg, Card, Border, Text, Sub, Hover, Accent, Frame;    // Frame: the outline of an input (combo box, check box)
    public static VeroTheme Dark() { return new VeroTheme { Bg = Color.FromArgb(32,32,32), Card = Color.FromArgb(43,43,43), Border = Color.FromArgb(58,58,58), Text = Color.FromArgb(240,240,240), Sub = Color.FromArgb(160,160,160), Hover = Color.FromArgb(56,56,56), Accent = Color.FromArgb(96,205,255), Frame = Color.FromArgb(118,118,118) }; }
    public static VeroTheme Light() { return new VeroTheme { Bg = Color.FromArgb(243,243,243), Card = Color.White, Border = Color.FromArgb(229,229,229), Text = Color.FromArgb(27,27,27), Sub = Color.FromArgb(92,92,92), Hover = Color.FromArgb(233,233,233), Accent = Color.FromArgb(0,103,192), Frame = Color.FromArgb(138,138,138) }; }
}

// Combo box in the theme's colours. With FlatStyle.Flat WinForms paints the drop-down button itself, in the light system
// colour with a tiny arrow - on the dark theme the boxes did not read as drop-downs at all (seen 2026-11-05). This paints
// over WinForms after every paint: the button in the box's own colour with a clear chevron, and an outline like an input.
public class VeroCombo : ComboBox {
    public Color Arrow = SystemColors.ControlText, ArrowDisabled = SystemColors.GrayText, Frame = SystemColors.ControlDark;
    public VeroCombo() { FlatStyle = FlatStyle.Flat; }
    protected override void WndProc(ref Message m) {
        base.WndProc(ref m);
        if (m.Msg == 0x000F || m.Msg == 0x0085) PaintChrome(IntPtr.Zero);                      // WM_PAINT, WM_NCPAINT
        else if ((m.Msg == 0x0317 || m.Msg == 0x0318) && m.WParam != IntPtr.Zero) PaintChrome(m.WParam);   // WM_PRINT(CLIENT): DrawToBitmap, -Preview
    }
    void PaintChrome(IntPtr hdc) {
        if (!IsHandleCreated || Width < 8 || Height < 8) return;
        using (Graphics g = hdc == IntPtr.Zero ? Graphics.FromHwnd(Handle) : Graphics.FromHdc(hdc)) {
            int bw = Math.Max(SystemInformation.HorizontalScrollBarArrowWidth + 4, Height * 3 / 4);
            Rectangle btn = new Rectangle(Width - bw - 1, 1, bw, Height - 2);
            using (SolidBrush b = new SolidBrush(BackColor)) {
                if (Enabled) g.FillRectangle(b, btn);
                else {
                    // disabled (a locked field in Edit): Windows draws its own disabled style - a bright inner frame that stops at
                    // the button (seen 2026-11-05). Paint the whole box, so a locked field looks like an open one, chevron dimmed.
                    g.FillRectangle(b, 1, 1, Width - 2, Height - 2);
                    TextRenderer.DrawText(g, Text, Font, new Rectangle(3, 1, Width - bw - 6, Height - 2), ForeColor, BackColor,
                        TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.EndEllipsis | TextFormatFlags.NoPrefix);
                }
            }
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float s = Math.Max(3f, Height / 9f), cx = btn.Left + btn.Width / 2f, cy = btn.Top + btn.Height / 2f;
            using (Pen p = new Pen(Enabled ? Arrow : ArrowDisabled, Math.Max(1.5f, Height / 18f))) {
                p.StartCap = LineCap.Round; p.EndCap = LineCap.Round; p.LineJoin = LineJoin.Round;
                g.DrawLines(p, new PointF[] { new PointF(cx - s, cy - s / 2), new PointF(cx, cy + s / 2), new PointF(cx + s, cy - s / 2) });
            }
            g.SmoothingMode = SmoothingMode.None;
            using (Pen i = new Pen(BackColor)) g.DrawRectangle(i, 1, 1, Width - 3, Height - 3);   // WinForms' inner outline (it doubled the frame)
            using (Pen f = new Pen(Frame)) g.DrawRectangle(f, 0, 0, Width - 1, Height - 1);
        }
    }
}

// Check box in the theme's colours: WinForms draws its box white on the dark theme. Box outlined like an input, filled with
// the accent and a check mark when checked; the text wraps (Size fixed by the caller) and the box sits beside its first line.
public class VeroCheck : CheckBox {
    public Color Box = SystemColors.Window, Frame = SystemColors.ControlDark, Accent = SystemColors.Highlight, Mark = SystemColors.HighlightText, TextDisabled = SystemColors.GrayText;
    public VeroCheck() { SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true); }
    protected override void OnPaint(PaintEventArgs e) {
        Graphics g = e.Graphics;
        g.Clear(BackColor);
        int s = Math.Max(12, (int)Math.Round(Font.Height * 0.85)), gap = Math.Max(6, s / 2);
        TextFormatFlags tf = TextFormatFlags.WordBreak | TextFormatFlags.Left | TextFormatFlags.NoPrefix;
        int tw = Math.Max(1, Width - s - gap - 2);
        Size ts = TextRenderer.MeasureText(g, Text, Font, new Size(tw, int.MaxValue), tf);
        int top = Math.Max(0, (Height - ts.Height) / 2);
        Rectangle box = new Rectangle(1, top + Math.Max(0, (Font.Height - s) / 2), s, s);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        using (GraphicsPath path = Round(box, Math.Max(2, s / 5))) {
            using (SolidBrush b = new SolidBrush(Checked ? Accent : Box)) g.FillPath(b, path);
            using (Pen p = new Pen(Checked ? Accent : Frame)) g.DrawPath(p, path);
        }
        if (Checked) {
            using (Pen m = new Pen(Mark, Math.Max(1.5f, s / 7f))) {
                m.StartCap = LineCap.Round; m.EndCap = LineCap.Round; m.LineJoin = LineJoin.Round;
                g.DrawLines(m, new PointF[] { new PointF(box.Left + s * 0.24f, box.Top + s * 0.52f), new PointF(box.Left + s * 0.42f, box.Top + s * 0.70f), new PointF(box.Left + s * 0.76f, box.Top + s * 0.32f) });
            }
        }
        g.SmoothingMode = SmoothingMode.None;
        Rectangle tr = new Rectangle(box.Right + gap, top, tw, ts.Height);
        TextRenderer.DrawText(g, Text, Font, tr, Enabled ? ForeColor : TextDisabled, tf);
        if (Focused && ShowFocusCues) ControlPaint.DrawFocusRectangle(g, Rectangle.Inflate(tr, 2, 1));
    }
    static GraphicsPath Round(Rectangle r, int rad) {
        GraphicsPath p = new GraphicsPath(); int d = rad * 2;
        p.AddArc(r.Left, r.Top, d, d, 180, 90); p.AddArc(r.Right - d, r.Top, d, d, 270, 90);
        p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90); p.AddArc(r.Left, r.Bottom - d, d, d, 90, 90);
        p.CloseFigure(); return p;
    }
}

// Windows-11-like menu: flat, padded, rounded hover, vector icons drawn by name from item.Tag
public class VeroMenuRenderer : ToolStripProfessionalRenderer {
    readonly VeroTheme t; readonly float scale;
    public Image Logo;
    public bool DwmFrame;
    const int IconX = 18;                                              // the icon: inside the card (8) plus the card's padding (10)
    // the menu's own width (the tray sets a minimum that leaves room for the cards' margins and the chevron): an item can be
    // laid out wider than the menu and is clipped there, so nothing is measured from the item's width
    static int MenuWidth(ToolStripItem item) { return item.Owner != null ? item.Owner.Width : item.Width; }
    // the margin around the cards: 8 px, or the space Windows leaves right of the items if that is more (it lays them out
    // narrower than the menu) - the same on every side; the tray sizes the gaps and the bottom from MenuMargin too
    int Margin(ToolStripItem item) { return Math.Max(S(8), MenuWidth(item) - item.Bounds.Right); }
    public int MenuMargin(ToolStrip menu) {
        foreach (ToolStripItem i in menu.Items) if (i.Available && !(i is ToolStripSeparator)) return Margin(i);
        return S(8);
    }
    public VeroMenuRenderer(VeroTheme theme, float dpiScale) { t = theme; scale = dpiScale; RoundedEdges = false; }
    // Styled like the windows: the window colour behind, the items in cards (Card fill, 1 px Border, rounded) - one card per
    // group between separators, the separators being the gaps between cards - and the hover a rounded block inside its card.
    protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e) { e.Graphics.Clear(t.Bg); }
    protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e) {
        if (DwmFrame) return;
        using (var p = new Pen(t.Border)) e.Graphics.DrawRectangle(p, 0, 0, e.ToolStrip.Width - 1, e.ToolStrip.Height - 1); }
    protected override void OnRenderImageMargin(ToolStripRenderEventArgs e) { }        // the background shows; the cards are drawn per item
    protected override void OnRenderSeparator(ToolStripSeparatorRenderEventArgs e) { }  // a gap between two cards
    protected override void OnRenderMenuItemBackground(ToolStripItemRenderEventArgs e) {
        var g = e.Graphics; g.SmoothingMode = SmoothingMode.AntiAlias;
        if ((e.Item.Tag as string) != "logo") {                          // the header sits on the background, like a window title
            bool first, last; GroupEdges(e.Item, out first, out last);
            int w = MenuWidth(e.Item), m = Margin(e.Item);
            var card = new Rectangle(m - e.Item.Bounds.X, 0, w - 1 - 2 * m, e.Item.Height - 1);   // spans pixels m .. w-1-m of the menu
            int rad = S(7);
            using (var fill = Segment(card, rad, first, last, true)) using (var b = new SolidBrush(t.Card)) g.FillPath(b, fill);
            using (var edge = Segment(card, rad, first, last, false)) using (var p = new Pen(t.Border)) g.DrawPath(p, edge);
            if (e.Item.Selected && e.Item.Enabled) {
                var r = new Rectangle(m - e.Item.Bounds.X + S(4), first ? S(4) : S(1), w - 2 * m - S(8), e.Item.Height - (first ? S(4) : S(1)) - (last ? S(4) : S(1)));
                using (var path = Round(r, S(5))) using (var b = new SolidBrush(t.Hover)) g.FillPath(b, path);
            }
        }
        g.SmoothingMode = SmoothingMode.None;
    }
    // is this item the first / last of its card (the visible items between two separators)?
    static void GroupEdges(ToolStripItem item, out bool first, out bool last) {
        first = true; last = true;
        var items = item.Owner != null ? item.Owner.Items : null; if (items == null) return;
        int i = items.IndexOf(item);
        for (int k = i - 1; k >= 0; k--) { var x = items[k]; if (!x.Available) continue; first = x is ToolStripSeparator || (x.Tag as string) == "logo"; break; }
        for (int k = i + 1; k < items.Count; k++) { var x = items[k]; if (!x.Available) continue; last = x is ToolStripSeparator; break; }
    }
    // the slice of a rounded card that one item covers: rounded on top for the first item, at the bottom for the last; as a
    // fill (closed) or as the outline (open at the edges shared with the neighbouring items)
    static GraphicsPath Segment(Rectangle r, int rad, bool first, bool last, bool fill) {
        var p = new GraphicsPath(); int d = rad * 2;
        if (fill) {
            // an edge shared with the next item reaches 3 px past this item: its anti-aliased edge is clipped away, else it
            // showed as a faint line between the items of one card
            if (first) { p.AddArc(r.X, r.Y, d, d, 180, 90); p.AddArc(r.Right - d, r.Y, d, d, 270, 90); } else { p.AddLine(r.X, r.Y - 3, r.Right, r.Y - 3); }
            if (last) { p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90); p.AddArc(r.X, r.Bottom - d, d, d, 90, 90); } else { p.AddLine(r.Right, r.Bottom + 3, r.X, r.Bottom + 3); }
            p.CloseFigure(); return p;
        }
        // the outline: both sides, plus the rounded top (first item) and the rounded bottom (last item), each an open figure
        int top = first ? r.Y + rad : r.Y - 3, bottom = last ? r.Bottom - rad : r.Bottom + 3;
        p.StartFigure(); p.AddLine(r.X, top, r.X, bottom);
        p.StartFigure(); p.AddLine(r.Right, top, r.Right, bottom);
        if (first) { p.StartFigure(); p.AddArc(r.X, r.Y, d, d, 180, 90); p.AddArc(r.Right - d, r.Y, d, d, 270, 90); }
        if (last) { p.StartFigure(); p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90); p.AddArc(r.X, r.Bottom - d, d, d, 90, 90); }
        return p;
    }
    protected override void OnRenderItemImage(ToolStripItemImageRenderEventArgs e) {
        var kind = e.Item.Tag as string; if (string.IsNullOrEmpty(kind)) return;
        var r = e.ImageRectangle; int sz = Math.Min(r.Width, r.Height); r.Y = (e.Item.Height - sz) / 2; r.Height = sz;
        if (kind == "logo") {
            if (Logo != null) { e.Graphics.InterpolationMode = InterpolationMode.HighQualityBicubic; e.Graphics.DrawImage(Logo, new Rectangle(S(IconX), r.Y + (r.Height - sz) / 2, sz, sz)); }
            return;
        }
        DrawIcon(e.Graphics, kind, new Rectangle(S(IconX), r.Y + (r.Height - sz) / 2, sz, sz), !e.Item.Enabled ? t.Sub : (kind == "awake" && e.Item is ToolStripMenuItem && ((ToolStripMenuItem)e.Item).Checked) ? t.Accent : t.Text); }
    protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e) {
        e.Graphics.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;
        var r = e.TextRectangle; r.Y = 0; r.Height = e.Item.Height; r.Width = MenuWidth(e.Item) - r.X - S(30);   // the wide icon column gives the gap; the right end leaves room for the chevron
        bool head = (e.Item.Tag as string) == "logo";                    // the header is a disabled item, but a heading like the windows' ones
        TextRenderer.DrawText(e.Graphics, e.Text, e.TextFont, r, (e.Item.Enabled || head) ? t.Text : t.Sub, TextFormatFlags.VerticalCenter | TextFormatFlags.Left | TextFormatFlags.NoPadding | TextFormatFlags.EndEllipsis); }
    protected override void OnRenderItemCheck(ToolStripItemImageRenderEventArgs e) { }   // no stock check box: a ticked item shows its icon in the accent colour
    // a submenu's arrow: a chevron like the combo boxes' (the stock one is a tiny triangle)
    protected override void OnRenderArrow(ToolStripArrowRenderEventArgs e) {
        var g = e.Graphics; var st = g.Save(); g.SmoothingMode = SmoothingMode.AntiAlias;
        float s = S(3.5), cx = e.Item != null ? MenuWidth(e.Item) - S(22) : e.ArrowRectangle.Left + e.ArrowRectangle.Width / 2f, cy = e.Item != null ? e.Item.Height / 2f : e.ArrowRectangle.Top + e.ArrowRectangle.Height / 2f;
        using (var p = new Pen(e.Item != null && e.Item.Enabled ? t.Text : t.Sub, Math.Max(1.5f, S(1.6)))) {
            p.StartCap = LineCap.Round; p.EndCap = LineCap.Round; p.LineJoin = LineJoin.Round;
            g.DrawLines(p, new[] { new PointF(cx - s / 2, cy - s), new PointF(cx + s / 2, cy), new PointF(cx - s / 2, cy + s) });
        }
        g.Restore(st);
    }
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
