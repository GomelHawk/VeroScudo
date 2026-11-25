<#
.SYNOPSIS
    ksbench - a vendor-neutral VPN kill-switch leak bench for Windows 10 (21H2+) and 11.
.DESCRIPTION
    Connect your VPN, then in an elevated PowerShell:
        powershell -ExecutionPolicy Bypass -File .\ksbench.ps1
    It watches the physical network adapter (Windows' built-in pktmon) while it breaks the VPN in a few
    ways and scores what got out. Rules and weights: SCENARIOS.md. Every change is undone at the end
    (also on Ctrl-C); if the window was closed during a run:  .\ksbench.ps1 -Restore
    Nothing is installed, nothing is rebooted, no files are deleted.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'used by the functions below (script scope)')]
[CmdletBinding()]
param(
    [string]$Product,
    [string[]]$Server,
    [string[]]$Iface,
    [switch]$Online,
    [switch]$NoOnline,
    [switch]$Yes,
    [string]$AppProcess,
    [string[]]$Only,
    [ValidateRange(10, 120)][int]$Hold = 60,
    [ValidateRange(10, 120)][int]$Recover = 60,
    [string]$Out,
    [switch]$List,
    [switch]$Restore
)
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
# 'powershell -File ... -Only D1,D4' hands the list over as ONE string: split it here (also a typed array, any case)
$Only = @($Only | ForEach-Object { "$_" -split '[,\s]+' } | Where-Object { $_ } | ForEach-Object { $_.Trim().ToUpper() })

$Version = '0.1.0'
# id, group, weight, title - keep in sync with ksbench.py and SCENARIOS.md (a test checks it)
$Scenarios = @(
    @('S1', 'steady', 10, 'DNS stays in the tunnel'),
    @('S2', 'steady', 7, 'IPv6 stays in the tunnel'),
    @('S3', 'steady', 10, 'A program bound to the physical adapter cannot get out'),
    @('S4', 'steady', 3, 'UDP/QUIC, STUN and ping stay in the tunnel'),
    @('D1', 'outage', 12, 'VPN server unreachable'),
    @('D2', 'outage', 8, 'VPN client process killed'),
    @('D3', 'outage', 9, 'Tunnel adapter goes down'),
    @('D4', 'outage', 12, 'Physical link drops and comes back'),
    @('D5', 'outage', 7, 'No DNS leak during any outage'),
    @('V1', 'outage', 7, 'Virtual machines and WSL stay inside'),
    @('T1', 'tamper', 10, 'Another program adds a firewall allow rule'),
    @('T2', 'tamper', 5, 'The kill-switch app is killed')
)
$Budget = 240     # seconds for all outage and tamper tests together
$Fault = 10       # seconds an adapter stays down (D3, D4, T1, T2)
$Cap = 40
$Critical = @('S1', 'S2', 'S3', 'D1', 'D2', 'D3', 'D4', 'T1', 'T2')
$Meaning = @{
    S1 = "the names of the sites you visit go to your internet provider's DNS, even with the VPN on."
    S2 = 'your real IPv6 address is visible to sites, even with the VPN on.'
    S3 = 'any program can go around the VPN by choosing the network adapter itself (some apps and malware do).'
    S4 = 'some UDP traffic (video calls, QUIC, WebRTC) or ping goes around the VPN.'
    D1 = 'when the VPN server stops answering, your traffic goes out without the VPN.'
    D2 = 'when the VPN app crashes, your traffic goes out without the VPN.'
    D3 = 'when the tunnel drops, your traffic goes out without the VPN.'
    D4 = 'after a Wi-Fi or cable drop, traffic gets out before the VPN is back.'
    D5 = "while the VPN reconnects, the names of the sites you visit go to your provider's DNS."
    T1 = "another program's firewall rule is enough to get around the kill-switch."
    T2 = 'if the kill-switch app is closed or crashes, the protection is gone.'
    V1 = 'traffic of your virtual machines or WSL can go out without the VPN when it drops.'
}
$Recommend = "Recommendation: change your kill-switch to one that blocks at the firewall by default.`n" +
    "VeroScudo - free and open source, from the authors of this bench: https://github.com/GomelHawk/VeroScudo`n" +
    'Run this bench again with it to compare.'
$NeverKill = @('system', 'idle', 'svchost', 'lsass', 'csrss', 'wininit', 'winlogon', 'services', 'smss', 'registry',
    'explorer', 'powershell', 'pwsh', 'dwm', 'msmpeng', 'conhost')
$DisruptText = @"
The next tests break the VPN on purpose - about 3 minutes, 4 at most. A blocked server or a killed client
stays so until the tunnel goes down (at most {0} s); the bench then waits up to {1} s for the VPN to come back.
Each change is undone at once (also on Ctrl-C; '.\ksbench.ps1 -Restore' if the window was closed during the run):
  D1  a Windows Firewall rule blocks the VPN server
  D3  the tunnel adapter is disabled for 10 s (skipped for Windows' own VPN client: it has no adapter to disable)
  D4  the physical network adapter is disabled for 10 s - you are offline meanwhile
  T1  a Windows Firewall allow rule for the test addresses + the physical adapter disabled for 10 s
  D2  the VPN client process is killed (asks first; skipped if the VPN runs inside Windows)
  T2  (experts, only with -AppProcess) the kill-switch app's process is killed + the adapter disabled for 10 s
Nothing is installed, nothing is rebooted, no files are deleted.
"@
$OnlinePrompt = @'

Online check: the bench will ask https://1.1.1.1 (and https://[2606:4700:4700::1111]) every 2 s
which IP address they see you coming from. If a leak happens, Cloudflare sees your real IP address.
It does not change the score - it only shows the leaked address and checks the bench itself.
Run the online check? [Y/n]
'@

$KsCode = @'
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace KsBench
{
    public class Pkt
    {
        public int Ver; public string Src; public string Dst; public int Proto;
        public int SPort = -1; public int DPort = -1; public int IType = -1; public int Ttl = -1; public double Ts;
        public string QName;
        public string Prog; public bool Known;     // the program that sent it (Owners), once looked up
        public string Where()
        {
            string n = Proto == 6 ? "tcp" : Proto == 17 ? "udp" : Proto == 1 ? "icmp" : Proto == 58 ? "icmp6" : "proto" + Proto;
            return Dst + " " + n + "/" + (DPort >= 0 ? DPort.ToString() : IType.ToString());
        }
    }

    public static class Parse
    {
        static readonly string[] Lan = {
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
            "224.0.0.0/4", "255.255.255.255/32", "0.0.0.0/8", "fe80::/10", "fc00::/7", "ff00::/8", "::1/128", "::/128",
            "198.18.0.0/15" };                                  // not on the internet either: proxy apps' fake DNS answers with these
        static readonly string[] Test = { "198.51.100.0/24", "2001:db8::/32" };   // where the bench sends its own traffic

        static string Addr(byte[] b, int o, int len)
        {
            byte[] a = new byte[len];
            Array.Copy(b, o, a, 0, len);
            return new IPAddress(a).ToString();
        }

        public static Pkt Ip(byte[] b, int o, int n)
        {
            if (n < 1) return null;
            int ver = b[o] >> 4, proto, off;
            Pkt p;
            if (ver == 4 && n >= 20)
            {
                proto = b[o + 9];
                p = new Pkt { Ver = 4, Src = Addr(b, o + 12, 4), Dst = Addr(b, o + 16, 4), Proto = proto, Ttl = b[o + 8] };
                off = (b[o] & 15) * 4;
                if ((((b[o + 6] << 8) | b[o + 7]) & 0x1FFF) != 0) return p;
            }
            else if (ver == 6 && n >= 40)
            {
                int nh = b[o + 6];
                off = 40;
                string src = Addr(b, o + 8, 16), dst = Addr(b, o + 24, 16);
                while ((nh == 0 || nh == 43 || nh == 44 || nh == 51 || nh == 60) && n >= off + 8)
                {
                    int nxt = b[o + off], ln;
                    if (nh == 44)
                    {
                        if ((((b[o + off + 2] << 8) | b[o + off + 3]) & 0xFFF8) != 0)
                            return new Pkt { Ver = 6, Src = src, Dst = dst, Proto = nxt, Ttl = b[o + 7] };
                        ln = 8;
                    }
                    else if (nh == 51) ln = (b[o + off + 1] + 2) * 4;
                    else ln = (b[o + off + 1] + 1) * 8;
                    nh = nxt;
                    off += ln;
                }
                proto = nh;
                p = new Pkt { Ver = 6, Src = src, Dst = dst, Proto = nh, Ttl = b[o + 7] };
            }
            else return null;
            if ((proto == 6 || proto == 17) && n >= off + 4)
            {
                p.SPort = (b[o + off] << 8) | b[o + off + 1];
                p.DPort = (b[o + off + 2] << 8) | b[o + off + 3];
                if (proto == 17 && p.DPort == 53) p.QName = DnsName(b, o + off + 8 + 12, o + n);
            }
            else if ((proto == 1 || proto == 58) && n > off) p.IType = b[o + off];
            return p;
        }

        // the name a DNS query asks for, or null when the captured bytes do not hold it whole
        static string DnsName(byte[] b, int pos, int end)
        {
            var labels = new List<string>();
            while (pos < end)
            {
                int len = b[pos];
                if (len == 0) return labels.Count > 0 ? string.Join(".", labels.ToArray()).ToLowerInvariant() : null;
                if (len > 63 || pos + 1 + len > end) return null;
                labels.Add(System.Text.Encoding.ASCII.GetString(b, pos + 1, len));
                pos += 1 + len;
            }
            return null;
        }

        public static Pkt Frame(byte[] d, int o, int n, int lt)
        {
            if (lt == 1)
            {
                if (n < 14) return null;
                int et = (d[o + 12] << 8) | d[o + 13], off = 14;
                while ((et == 0x8100 || et == 0x88A8) && n >= off + 4) { et = (d[o + off + 2] << 8) | d[o + off + 3]; off += 4; }
                return (et == 0x0800 || et == 0x86DD) ? Ip(d, o + off, n - off) : null;
            }
            if (lt == 12 || lt == 14 || lt == 101) return Ip(d, o, n);
            if (lt == 113 && n >= 16)
            {
                int et = (d[o + 14] << 8) | d[o + 15];
                return (et == 0x0800 || et == 0x86DD) ? Ip(d, o + 16, n - 16) : null;
            }
            if (lt == 0 && n >= 4) return Ip(d, o + 4, n - 4);
            return null;
        }

        public static Pkt Hex(string hex, int lt)
        {
            byte[] b = new byte[hex.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return Frame(b, 0, b.Length, lt);
        }

        public static bool IsLan(string addr) { return In(addr, Lan); }

        // the bench's own test traffic: to its test addresses, or a DNS query for one of its names - always counted
        public static bool IsTest(Pkt p) { return In(p.Dst, Test) || (p.QName != null && p.QName.StartsWith("ksb-")); }

        static bool In(string addr, string[] nets)
        {
            IPAddress a;
            if (!IPAddress.TryParse(addr, out a)) return false;
            byte[] ab = a.GetAddressBytes();
            foreach (string c in nets)
            {
                string[] parts = c.Split('/');
                byte[] nb = IPAddress.Parse(parts[0]).GetAddressBytes();
                if (nb.Length != ab.Length) continue;
                int bits = int.Parse(parts[1]);
                bool ok = true;
                for (int i = 0; i < bits && ok; i++)
                {
                    int m = 0x80 >> (i % 8);
                    if ((ab[i / 8] & m) != (nb[i / 8] & m)) ok = false;
                }
                if (ok) return true;
            }
            return false;
        }

        public static string Classify(Pkt p, ICollection<string> servers) { return Classify(p, servers, null, null); }

        // app: the VPN app's program files - a packet its programs sent (p.Prog) is its own: a kill-switch lets the VPN app out;
        // never the bench's own test traffic.
        // own: "proto|local port|server port" of the VPN's connection to its server - from that socket to that port it is the VPN
        // moving to another of its servers (a name with several addresses), also when no program owns the socket (kernel WireGuard)
        public static string Classify(Pkt p, ICollection<string> servers, ICollection<string> app, ICollection<string> own)
        {
            if (p == null) return "ignore";
            if (servers.Contains(p.Dst) || (own != null && own.Contains(p.Proto + "|" + p.SPort + "|" + p.DPort) && !Forwarded(p.Ttl))) return "server";
            if (p.Proto == 17 && (Is(p.DPort, 67, 68, 546, 547) || Is(p.SPort, 67, 68, 546, 547))) return "ignore";
            if (p.Proto == 58 && Is(p.IType, 130, 131, 132, 133, 134, 135, 136, 137, 143)) return "ignore";
            if (app != null && p.Prog != null && app.Contains(p.Prog) && !Forwarded(p.Ttl) && !IsTest(p)) return "app";
            if ((p.Proto == 6 || p.Proto == 17) && (p.DPort == 53 || p.DPort == 853)) return "dns";
            if (IsLan(p.Dst)) return "lan";
            return Forwarded(p.Ttl) ? "vmleak" : "leak";
        }

        static bool Is(int v, params int[] set) { return Array.IndexOf(set, v) >= 0; }

        // a packet this computer forwarded for a VM or WSL: one hop used - 63 (Linux/macOS guests) or 127 (Windows guests)
        public static bool Forwarded(int ttl) { return ttl == 63 || ttl == 127; }

        static uint U32(byte[] f, int p, bool le)
        {
            return le ? (uint)(f[p] | f[p + 1] << 8 | f[p + 2] << 16 | f[p + 3] << 24)
                      : (uint)(f[p] << 24 | f[p + 1] << 16 | f[p + 2] << 8 | f[p + 3]);
        }

        static int U16(byte[] f, int p, bool le) { return le ? f[p] | f[p + 1] << 8 : f[p] << 8 | f[p + 1]; }

        // outbound IP packets (sender MAC is one of ours) from a pcapng file
        public static List<Pkt> ReadPcapng(string path, ICollection<string> macs)
        {
            List<Pkt> res = new List<Pkt>();
            byte[] f = File.ReadAllBytes(path);
            List<int> lts = new List<int>();
            List<double> rs = new List<double>();
            bool le = true;
            int pos = 0;
            while (pos + 12 <= f.Length)
            {
                uint type = U32(f, pos, le);
                if (type == 0x0A0D0D0A) { le = f[pos + 8] == 0x4D; lts.Clear(); rs.Clear(); }
                int blen = (int)U32(f, pos + 4, le);
                if (blen < 12 || pos + blen > f.Length) break;
                if (type == 1)
                {
                    lts.Add(U16(f, pos + 8, le));
                    double r = 1e-6;
                    int op = pos + 16;
                    while (op + 4 <= pos + blen - 4)
                    {
                        int code = U16(f, op, le), ol = U16(f, op + 2, le);
                        if (code == 0) break;
                        if (code == 9 && ol >= 1)
                        {
                            byte v = f[op + 4];
                            r = (v & 0x80) != 0 ? Math.Pow(2, -(v & 0x7F)) : Math.Pow(10, -v);
                        }
                        op += 4 + ((ol + 3) & ~3);
                    }
                    rs.Add(r);
                }
                else if (type == 6 && blen >= 32)
                {
                    int ifid = (int)U32(f, pos + 8, le);
                    ulong ts = ((ulong)U32(f, pos + 12, le) << 32) | U32(f, pos + 16, le);
                    int cap = (int)U32(f, pos + 20, le), d = pos + 28;
                    if (ifid < lts.Count && d + cap <= pos + blen && lts[ifid] == 1 && cap >= 14)
                    {
                        Pkt p = Outbound(f, d, cap, macs);
                        if (p != null) { p.Ts = ts * rs[ifid]; res.Add(p); }
                    }
                }
                pos += blen;
            }
            return res;
        }

        static string Mac(byte[] f, int o) { return BitConverter.ToString(f, o, 6).Replace("-", "").ToLowerInvariant(); }

        // A frame we sent: Ethernet with our MAC as sender, or (Wi-Fi adapters, where pktmon records raw 802.11) a data
        // frame to the access point (ToDS) with our MAC as transmitter and an LLC/SNAP header in front of the IP packet.
        public static Pkt Outbound(byte[] f, int d, int cap, ICollection<string> macs)
        {
            if (cap >= 32 && (f[d] & 0x0C) == 0x08)
            {
                int hl = 24 + ((f[d] & 0x80) != 0 ? 2 : 0) + ((f[d + 1] & 0x80) != 0 ? 4 : 0);
                if (cap >= hl + 8 && f[d + hl] == 0xAA && f[d + hl + 1] == 0xAA && f[d + hl + 2] == 0x03
                    && f[d + hl + 3] == 0 && f[d + hl + 4] == 0 && f[d + hl + 5] == 0)
                {
                    if ((f[d + 1] & 0x03) != 0x01 || !macs.Contains(Mac(f, d + 10))) return null;
                    int et = (f[d + hl + 6] << 8) | f[d + hl + 7];
                    return (et == 0x0800 || et == 0x86DD) ? Ip(f, d + hl + 8, cap - hl - 8) : null;
                }
            }
            return macs.Contains(Mac(f, d + 6)) ? Frame(f, d, cap, 1) : null;
        }

        public static Pkt HexOut(string hex, ICollection<string> macs)
        {
            byte[] b = new byte[hex.Length / 2];
            for (int i = 0; i < b.Length; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return Outbound(b, 0, b.Length, macs);
        }

        public static List<Pkt> Pick(List<Pkt> pkts, double t0, double t1, ICollection<string> servers, string cls)
        {
            return Pick(pkts, t0, t1, servers, cls, null, null);
        }

        public static List<Pkt> Pick(List<Pkt> pkts, double t0, double t1, ICollection<string> servers, string cls, ICollection<string> app, ICollection<string> own)
        {
            List<Pkt> r = new List<Pkt>();
            foreach (Pkt p in pkts)
                if (p.Ts >= t0 && p.Ts <= t1 && Classify(p, servers, app, own) == cls) r.Add(p);
            r.Sort(delegate (Pkt a, Pkt b) { return a.Ts.CompareTo(b.Ts); });
            return r;
        }
    }

    // which program owns each local port, looked up every 0.02 s through the run (a packet capture does not tell)
    public static class Owners
    {
        [DllImport("iphlpapi.dll")] static extern uint GetExtendedTcpTable(IntPtr t, ref int size, bool order, int af, int cls, uint res);
        [DllImport("iphlpapi.dll")] static extern uint GetExtendedUdpTable(IntPtr t, ref int size, bool order, int af, int cls, uint res);
        [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

        // "proto|port" -> spans {pid, first seen, last seen}: ports come back (ephemeral ports), a packet belongs to the
        // program that held its port at that moment
        public static readonly Dictionary<string, List<double[]>> Held = new Dictionary<string, List<double[]>>();
        public static readonly Dictionary<int, string> Paths = new Dictionary<int, string>();
        static Thread T;
        static volatile bool Stop;

        public static void Start()
        {
            if (T != null) return;
            Stop = false;
            T = new Thread(delegate () { while (!Stop) { try { Poll(); } catch (Exception) { } Thread.Sleep(20); } });   // a VPN app's short checks too
            T.IsBackground = true;
            T.Start();
        }

        public static void Halt() { Stop = true; T = null; }

        static void Poll()
        {
            List<int[]> rows = new List<int[]>();
            Read(true, 2, rows); Read(true, 23, rows); Read(false, 2, rows); Read(false, 23, rows);
            double now = Probe.Now();
            List<int> fresh = new List<int>();
            lock (Held) foreach (int[] r in rows) if (!Paths.ContainsKey(r[2]) && !fresh.Contains(r[2])) fresh.Add(r[2]);
            Dictionary<int, string> found = new Dictionary<int, string>();
            foreach (int pid in fresh) found[pid] = Image(pid);
            lock (Held)
            {
                foreach (KeyValuePair<int, string> kv in found) Paths[kv.Key] = kv.Value;
                foreach (int[] r in rows)
                {
                    if (r[2] <= 4) continue;           // Windows itself (0: a closed connection's TIME_WAIT, 4: System) - never the VPN app
                    string k = r[0] + "|" + r[1];
                    List<double[]> spans;
                    if (!Held.TryGetValue(k, out spans)) Held[k] = spans = new List<double[]>();
                    double[] last = spans.Count > 0 ? spans[spans.Count - 1] : null;
                    if (last != null && (int)last[0] == r[2] && now - last[2] < 1.0) last[2] = now;
                    else spans.Add(new double[] { r[2], now, now });
                }
            }
        }

        // MIB_TCPROW_OWNER_PID 24 bytes (port at 8, pid at 20), MIB_TCP6ROW_OWNER_PID 56 (20, 52),
        // MIB_UDPROW_OWNER_PID 12 (4, 8), MIB_UDP6ROW_OWNER_PID 28 (20, 24); the port in network byte order
        static void Read(bool tcp, int af, List<int[]> rows)
        {
            int size = 0, cls = tcp ? 5 : 1;
            if (tcp) GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, cls, 0); else GetExtendedUdpTable(IntPtr.Zero, ref size, false, af, cls, 0);
            if (size <= 0) return;
            size += 4096;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                uint rc = tcp ? GetExtendedTcpTable(buf, ref size, false, af, cls, 0) : GetExtendedUdpTable(buf, ref size, false, af, cls, 0);
                if (rc != 0) return;
                int n = Marshal.ReadInt32(buf);
                int len = tcp ? (af == 2 ? 24 : 56) : (af == 2 ? 12 : 28);
                int po = tcp ? (af == 2 ? 8 : 20) : (af == 2 ? 4 : 20);
                int pi = tcp ? (af == 2 ? 20 : 52) : (af == 2 ? 8 : 24);
                for (int i = 0; i < n; i++)
                {
                    IntPtr row = new IntPtr(buf.ToInt64() + 4 + (long)i * len);
                    rows.Add(new int[] { tcp ? 6 : 17, (Marshal.ReadByte(row, po) << 8) | Marshal.ReadByte(row, po + 1), Marshal.ReadInt32(row, pi) });
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        static string Image(int pid)
        {
            IntPtr h = OpenProcess(0x1000, false, pid);                 // PROCESS_QUERY_LIMITED_INFORMATION
            if (h == IntPtr.Zero) return null;
            try
            {
                StringBuilder sb = new StringBuilder(1024);
                int n = sb.Capacity;
                return QueryFullProcessImageName(h, 0, sb, ref n) ? sb.ToString() : null;
            }
            finally { CloseHandle(h); }
        }

        // "proto|local port|server port" of the VPN's connection to its server (Parse.Classify)
        public static HashSet<string> Own(List<Pkt> pkts, ICollection<string> servers)
        {
            HashSet<string> r = new HashSet<string>();
            foreach (Pkt p in pkts) if (p.SPort > 0 && servers.Contains(p.Dst)) r.Add(p.Proto + "|" + p.SPort + "|" + p.DPort);
            return r;
        }

        // the program file that held this local port at ts (0.5 s either side), or null - also when two could have
        public static string Program(Dictionary<string, List<double[]>> held, Dictionary<int, string> paths, int proto, int port, double ts)
        {
            List<double[]> spans;
            if (!held.TryGetValue(proto + "|" + port, out spans)) return null;
            int who = -1;
            foreach (double[] sp in spans)
            {
                if (ts < sp[1] - 0.5 || ts > sp[2] + 0.5) continue;
                if (who >= 0 && who != (int)sp[0]) return null;
                who = (int)sp[0];
            }
            string f;
            return who >= 0 && paths.TryGetValue(who, out f) ? f : null;
        }

        // the program of each packet - once, for packets older than `before` (the look is every 0.02 s)
        public static void Know(List<Pkt> pkts, double before)
        {
            lock (Held)
                foreach (Pkt p in pkts)
                    if (!p.Known && p.Ts < before) { p.Prog = p.SPort > 0 ? Program(Held, Paths, p.Proto, p.SPort, p.Ts) : null; p.Known = true; }
        }

        // a packet whose program was not seen is the VPN app's when it belongs to one of the app's connections (the same
        // protocol, local port, address and port - also a resend after the app was killed: the system still closes its
        // connections), or when one of its programs sent to the same address, protocol and port within `window` s (a socket
        // shorter than one look) - never the bench's own test traffic, never a VM's
        public static void Near(List<Pkt> pkts, ICollection<string> app, double window)
        {
            Dictionary<string, List<Pkt>> seen = new Dictionary<string, List<Pkt>>();
            Dictionary<string, string> flows = new Dictionary<string, string>();
            foreach (Pkt p in pkts)
            {
                if (p.Prog == null || !app.Contains(p.Prog)) continue;
                if (p.SPort > 0) flows[p.Proto + "|" + p.SPort + "|" + p.Dst + "|" + p.DPort] = p.Prog;   // a real port (a fragment has none)
                string k = p.Dst + "|" + p.Proto + "|" + p.DPort;
                List<Pkt> l;
                if (!seen.TryGetValue(k, out l)) seen[k] = l = new List<Pkt>();
                l.Add(p);
            }
            foreach (List<Pkt> l in seen.Values) l.Sort(delegate (Pkt a, Pkt b) { return a.Ts.CompareTo(b.Ts); });
            foreach (Pkt p in pkts)
            {
                List<Pkt> l;
                if (!p.Known || p.Prog != null || Parse.IsTest(p) || Parse.Forwarded(p.Ttl)) continue;
                string flow;
                if (p.SPort > 0 && flows.TryGetValue(p.Proto + "|" + p.SPort + "|" + p.Dst + "|" + p.DPort, out flow)) { p.Prog = flow; continue; }
                if (!seen.TryGetValue(p.Dst + "|" + p.Proto + "|" + p.DPort, out l)) continue;
                int lo = 0, hi = l.Count;
                while (lo < hi) { int mid = (lo + hi) / 2; if (l[mid].Ts < p.Ts - window) lo = mid + 1; else hi = mid; }
                if (lo < l.Count && l[lo].Ts <= p.Ts + window) p.Prog = l[lo].Prog;
            }
        }

        // the VPN app's program files: those that sent to the VPN server (pkts known), and the other programs in their folder
        // (its tray or UI) - never a system program or the bench itself, never by the Windows folder
        public static HashSet<string> App(List<Pkt> pkts, ICollection<string> servers, ICollection<string> never, string sysDir)
        {
            List<string> sent = new List<string>();
            foreach (Pkt p in pkts) if (p.Prog != null && servers.Contains(p.Dst)) sent.Add(p.Prog);
            List<string> all;
            lock (Held) all = new List<string>(Paths.Values);
            return App(sent, all, never, sysDir);
        }

        public static HashSet<string> App(ICollection<string> sent, ICollection<string> progs, ICollection<string> never, string sysDir)
        {
            HashSet<string> app = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string f in sent) if (f != null && !Sys(f, never)) app.Add(f);
            HashSet<string> dirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string f in app) { string d = Dir(f); if (d != null && !d.StartsWith(sysDir, StringComparison.OrdinalIgnoreCase)) dirs.Add(d); }
            HashSet<string> r = new HashSet<string>(app, StringComparer.OrdinalIgnoreCase);
            foreach (string f in progs) if (f != null && !Sys(f, never) && Dir(f) != null && dirs.Contains(Dir(f))) r.Add(f);
            return r;
        }

        static string Dir(string f) { int i = f.LastIndexOfAny(new char[] { '\\', '/' }); return i > 0 ? f.Substring(0, i) : null; }

        static bool Sys(string f, ICollection<string> never)
        {
            string n = f.Substring(f.LastIndexOfAny(new char[] { '\\', '/' }) + 1).ToLowerInvariant();
            if (n.EndsWith(".exe")) n = n.Substring(0, n.Length - 4);
            return never.Contains(n) || n.StartsWith("python") || n.StartsWith("systemd") || n == "powershell" || n == "pwsh";
        }
    }

    public static class Probe
    {
        [DllImport("iphlpapi.dll")]
        static extern int GetBestInterface(uint dest, out uint index);

        public static HashSet<int> Phys = new HashSet<int>();
        public static bool Online, V6, WentDown;
        public static double DownAt;
        public static string Label;
        public static HashSet<string> VpnIps = new HashSet<string>();
        public static string[] ExitIps() { lock (VpnIps) return new List<string>(VpnIps).ToArray(); }
        public static List<string[]> Hits = new List<string[]>();
        static readonly List<KeyValuePair<double, Socket>> Keep = new List<KeyValuePair<double, Socket>>();
        static readonly Random Rnd = new Random();

        public static double Now() { return (DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds; }

        public static int BestIf(string ip)
        {
            uint i;
            byte[] a = IPAddress.Parse(ip).GetAddressBytes();
            try { return GetBestInterface(BitConverter.ToUInt32(a, 0), out i) == 0 ? (int)i : -1; }
            catch (Exception) { return -1; }
        }

        // a route to the loopback adapter is a kill-switch's dead end, not a tunnel
        public static bool TunnelUp() { int i = BestIf("198.51.100.7"); return i > 0 && !Phys.Contains(i) && i != System.Net.NetworkInformation.NetworkInterface.LoopbackInterfaceIndex; }

        static Socket Make(string dst, SocketType st, ProtocolType pt, int ifIdx)
        {
            IPAddress a = IPAddress.Parse(dst);
            Socket s = new Socket(a.AddressFamily, st, pt);
            if (ifIdx > 0)
            {
                if (a.AddressFamily == AddressFamily.InterNetwork)
                    s.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)31, IPAddress.HostToNetworkOrder(ifIdx));
                else
                    s.SetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)31, ifIdx);  // *_UNICAST_IF
            }
            return s;
        }

        public static void Udp(string dst, int port, byte[] data, int ifIdx)
        {
            try
            {
                using (Socket s = Make(dst, SocketType.Dgram, ProtocolType.Udp, ifIdx))
                    s.SendTo(data ?? Encoding.ASCII.GetBytes("ksbench"), new IPEndPoint(IPAddress.Parse(dst), port));
            }
            catch (Exception) { }
        }

        public static void Tcp(string dst, int port, int ifIdx)
        {
            try
            {
                Socket s = Make(dst, SocketType.Stream, ProtocolType.Tcp, ifIdx);
                s.Blocking = false;
                try { s.Connect(new IPEndPoint(IPAddress.Parse(dst), port)); } catch (SocketException) { }
                lock (Keep) Keep.Add(new KeyValuePair<double, Socket>(Now(), s));
            }
            catch (Exception) { }
        }

        public static void Reap(double age)
        {
            lock (Keep)
                for (int i = Keep.Count - 1; i >= 0; i--)
                    if (Now() - Keep[i].Key >= age) { try { Keep[i].Value.Close(); } catch (Exception) { } Keep.RemoveAt(i); }
        }

        public static void PingOnce(string dst) { try { using (Ping p = new Ping()) p.Send(dst, 300); } catch (Exception) { } }

        public static string UniqueName()
        {
            const string abc = "abcdefghijklmnopqrstuvwxyz0123456789";
            StringBuilder sb = new StringBuilder("ksb-");
            lock (Rnd) for (int i = 0; i < 12; i++) sb.Append(abc[Rnd.Next(abc.Length)]);
            return sb.Append(".example.com").ToString();
        }

        public static byte[] DnsPacket(string name)
        {
            List<byte> q = new List<byte>();
            int id;
            lock (Rnd) id = Rnd.Next(65536);
            q.AddRange(new byte[] { (byte)(id >> 8), (byte)id, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 });
            foreach (string l in name.Split('.')) { q.Add((byte)l.Length); q.AddRange(Encoding.ASCII.GetBytes(l)); }
            q.AddRange(new byte[] { 0, 0, 1, 0, 1 });
            return q.ToArray();
        }

        public static void SystemLookup(string name) { try { Dns.BeginGetHostAddresses(name, null, null); } catch (Exception) { } }

#pragma warning disable SYSLIB0014   // HttpWebRequest: the API that works the same on Windows PowerShell 5.1
        static string Fetch(string url)
        {
            try
            {
                HttpWebRequest r = (HttpWebRequest)WebRequest.Create(url);
                r.Proxy = null; r.Timeout = 1500; r.ReadWriteTimeout = 1500;
                using (WebResponse resp = r.GetResponse())
                using (StreamReader sr = new StreamReader(resp.GetResponseStream()))
                {
                    Match m = Regex.Match(sr.ReadToEnd(), @"^ip=(\S+)$", RegexOptions.Multiline);
                    return m.Success ? m.Groups[1].Value : null;
                }
            }
            catch (Exception) { return null; }
        }

        public static void OnlineTick(string label)
        {
            if (!Online) return;
            ThreadPool.QueueUserWorkItem(delegate (object o)
            {
                string[] urls = V6 ? new[] { "https://1.1.1.1/cdn-cgi/trace", "https://[2606:4700:4700::1111]/cdn-cgi/trace" }
                                   : new[] { "https://1.1.1.1/cdn-cgi/trace" };
                foreach (string url in urls)
                {
                    string ip = Fetch(url);
                    if (ip == null) continue;
                    bool up = TunnelUp();     // answered through the tunnel: a VPN exit address
                    lock (VpnIps)
                    {
                        if (up) VpnIps.Add(ip);
                        else if (!VpnIps.Contains(ip))
                            Hits.Add(new[] { label ?? "", ip, Now().ToString(CultureInfo.InvariantCulture) });
                    }
                }
            });
        }

        // mode 0: probe only; 1: also note whether the tunnel went down; 2: return true once the tunnel is up for 3 s;
        // 3: like 1, and return true 5 s after the tunnel went down
        public static bool ProbeFor(double seconds, int mode)
        {
            double end = Now() + seconds, lastDns = 0, lastOnline = 0, lastCheck = 0, okSince = 0;
            while (Now() < end)
            {
                double now = Now();
                Udp("198.51.100.7", 443, null, 0);
                Tcp("198.51.100.7", 443, 0);
                if (V6) Udp("2001:db8::7", 443, null, 0);
                if (now - lastDns >= 2)
                {
                    SystemLookup(UniqueName());
                    Udp("198.51.100.53", 53, DnsPacket(UniqueName()), 0);
                    lastDns = now;
                }
                if (now - lastOnline >= 2) { OnlineTick(Label); lastOnline = now; }
                Reap(1.0);
                if (mode != 0 && now - lastCheck >= 1)
                {
                    lastCheck = now;
                    bool up = TunnelUp();
                    if ((mode == 1 || mode == 3) && !up && !WentDown) { WentDown = true; DownAt = now; }
                    if (mode == 3 && WentDown && now - DownAt >= 5) return true;
                    if (mode == 2)
                    {
                        if (!up) okSince = 0;
                        else if (okSince == 0) okSince = now;
                        else if (now - okSince >= 3) return true;
                    }
                }
                Thread.Sleep(250);
            }
            return mode != 2;
        }
    }
}
'@
if (-not ('KsBench.Parse' -as [type])) { Add-Type -TypeDefinition $KsCode -Language CSharp -IgnoreWarnings }

# ---------------------------------------------------------------- journal: every change written down first

$script:JournalDir = Join-Path ([IO.Path]::GetTempPath()) 'ksbench'
$script:JournalPath = Join-Path $script:JournalDir 'journal.json'
$script:Journal = New-Object System.Collections.ArrayList
$script:UndoFailed = New-Object System.Collections.ArrayList

function Save-Journal {
    ConvertTo-Json -InputObject @($script:Journal) -Depth 3 | Set-Content -LiteralPath $script:JournalPath -Encoding UTF8
}

function Add-Change([string]$Desc, [string]$Kind, [string]$Name) {
    $it = [pscustomobject]@{ desc = $Desc; kind = $Kind; name = $Name; done = $false }
    [void]$script:Journal.Add($it)
    Save-Journal
    if ($Kind -ne 'pktmon') { Write-Host "      + change: $Desc" }
}

function Undo-Change($It) {
    try {
        switch ($It.kind) {
            'fw' { Remove-NetFirewallRule -Name $It.name -ErrorAction Stop }
            'adapter' { Enable-NetAdapter -Name $It.name -Confirm:$false -ErrorAction Stop }
            'pktmon' { $null = & pktmon stop 2>&1 }
        }
        if ($It.kind -ne 'pktmon') { Write-Host "      - undone: $($It.desc)" }
    } catch {
        Write-Host "      ! COULD NOT UNDO '$($It.desc)': $($_.Exception.Message)" -ForegroundColor Red
        [void]$script:UndoFailed.Add($It.desc)
    }
    $It.done = $true
    Save-Journal
}

function Undo-Since([int]$Index, [switch]$KeepCapture) {
    for ($i = $script:Journal.Count - 1; $i -ge $Index; $i--) {
        $it = $script:Journal[$i]
        if (-not $it.done -and -not ($KeepCapture -and $it.kind -eq 'pktmon')) { Undo-Change $it }
    }
}

function Get-PendingChange {
    if (-not (Test-Path -LiteralPath $script:JournalPath)) { return @() }
    try { return @(Get-Content -LiteralPath $script:JournalPath -Raw | ConvertFrom-Json | Where-Object { -not $_.done }) }
    catch { return @() }
}

function Invoke-Restore {
    $pending = Get-PendingChange
    if (-not $pending) { Write-Host "Nothing to restore ($script:JournalPath has no open changes)."; return }
    $script:Journal = New-Object System.Collections.ArrayList
    foreach ($it in @(Get-Content -LiteralPath $script:JournalPath -Raw | ConvertFrom-Json)) { [void]$script:Journal.Add($it) }
    Undo-Since 0
    Write-Host "Restored $($pending.Count) change(s)."
}

# ---------------------------------------------------------------- capture (pktmon, one file per test)

$script:Pkts = New-Object 'System.Collections.Generic.List[KsBench.Pkt]'
$script:Seg = 0

function Start-Capture {
    $script:Seg++
    $script:SegEtl = Join-Path $script:RunDir "seg$($script:Seg).etl"
    $script:SegStart = [KsBench.Probe]::Now()
    # no text parsing (pktmon answers in the Windows language): start, and stop only on its exit code. Written down
    # after the start - a capture that never started (another tool's) must never be stopped by the bench
    $o = & pktmon start --capture --comp nics --pkt-size 128 --file-name $script:SegEtl --file-size 256 2>&1
    if ($LASTEXITCODE -ne 0) { throw "ksbench: pktmon could not start a capture (is another tool capturing?): $($o | Out-String)" }
    Add-Change 'packet capture (pktmon)' 'pktmon' ''
}

function Stop-Capture {
    $it = $script:Journal | Where-Object { $_.kind -eq 'pktmon' -and -not $_.done } | Select-Object -Last 1
    if ($it) { Undo-Change $it }
    $end = [KsBench.Probe]::Now()
    $pcap = [IO.Path]::ChangeExtension($script:SegEtl, '.pcapng')
    $null = & pktmon etl2pcap $script:SegEtl --out $pcap 2>&1
    if ($LASTEXITCODE -ne 0) { $null = & pktmon pcapng $script:SegEtl --out $pcap 2>&1 }
    if (-not (Test-Path -LiteralPath $pcap)) { throw 'pktmon could not convert its capture to pcapng' }
    $got = [KsBench.Parse]::ReadPcapng($pcap, $script:Macs)
    if ($got.Count -gt 0) {
        $first = ($got | Measure-Object -Property Ts -Minimum).Minimum
        if ([Math]::Abs($first - $script:SegStart) -gt 60) {    # timestamps not in Unix time: anchor at the start
            $shift = $script:SegStart - $first
            foreach ($p in $got) { $p.Ts += $shift }
        }
    }
    $script:Pkts.AddRange($got)
    $null = $end
}

# ---------------------------------------------------------------- helpers

function Test-Wanted([string]$Id) { return (-not $Only) -or ($Only -contains $Id) }
function Get-Title([string]$Id) { return ($Scenarios | Where-Object { $_[0] -eq $Id })[3] }

function Read-YesNo([string]$Question, [bool]$Default) {
    if (-not $script:Interactive) { return $Default }
    $a = (Read-Host $Question).Trim().ToLower()
    if (-not $a) { return $Default }
    return $a.StartsWith('y')
}

function Set-Result([string]$Id, [string]$Status, [string]$Detail = '', $Evidence = $null) {
    $script:Res[$Id] = [ordered]@{ status = $Status; detail = $Detail; evidence = $Evidence }
    $color = @{ pass = 'Green'; fail = 'Red' }[$Status]
    $line = '  {0}  {1,-7} {2}{3}' -f $Id, $Status.ToUpper(), (Get-Title $Id), $(if ($Detail) { " - $Detail" } else { '' })
    if ($color) { Write-Host $line -ForegroundColor $color } else { Write-Host $line }
}

function Get-Evidence($Items, [double]$T0) {
    if (-not $Items -or $Items.Count -eq 0) { return $null }
    $top = $Items | Group-Object { $_.Where() } | Sort-Object Count -Descending | Select-Object -First 5
    return [ordered]@{
        packets  = $Items.Count
        first_ms = [int](($Items[0].Ts - $T0) * 1000)
        last_ms  = [int](($Items[$Items.Count - 1].Ts - $T0) * 1000)
        to       = @($top | ForEach-Object { "$($_.Name) ($($_.Count))" })
        programs = @($Items | Where-Object { $_.Prog } | ForEach-Object { Split-Path -Leaf $_.Prog } | Sort-Object -Unique)
    }
}

function Get-ServerName([string[]]$Name, [string[]]$Server) {
    <# Of the names looked up, those that resolve to a VPN server address - the client finding its own server for the
       reconnect. Your provider sees the connection to that address anyway, so the look-up tells it nothing new. Resolved
       after the outages, through the VPN - all at once, at most 5 s: a dead resolver must not stall the bench. #>
    $ask = @(foreach ($n in $Name) { if ($n) { @{ Name = $n; Ar = $(try { [System.Net.Dns]::BeginGetHostAddresses($n, $null, $null) } catch { $null }) } } })
    $end = [KsBench.Probe]::Now() + 5
    foreach ($q in $ask) {
        if (-not $q.Ar) { continue }
        $left = [int][Math]::Max(0, ($end - [KsBench.Probe]::Now()) * 1000)
        if (-not $q.Ar.AsyncWaitHandle.WaitOne($left)) { continue }
        $a = try { @([System.Net.Dns]::EndGetHostAddresses($q.Ar) | ForEach-Object { $_.IPAddressToString }) } catch { @() }
        if (@($a | Where-Object { $Server -contains $_ }).Count) { $q.Name }
    }
}

function Get-AppProgram {
    <# The VPN app's program files - those that sent to the VPN server and the others in their folder. #>
    [KsBench.Owners]::Know($script:Pkts, [KsBench.Probe]::Now() - 0.7)       # 0.5 s margin + one look
    $app = [KsBench.Owners]::App($script:Pkts, [string[]]@($script:Servers.Keys), [string[]]$NeverKill, [Environment]::GetFolderPath('Windows'))
    [KsBench.Owners]::Near($script:Pkts, $app, 1.0)                           # sockets too short for a look
    return , $app
}

function Get-Leak([double]$T0, [double]$T1, [string]$Class = 'leak') {
    <# The VPN server(s) and the exit addresses the online check saw through the tunnel count as the VPN's: a VPN with
       several servers (Hiddify) talks to all of them, also over connections too short to see which program made them. #>
    $wait = [Math]::Min(0.7, $T1 + 0.7 - [KsBench.Probe]::Now())
    if ($wait -gt 0) { Start-Sleep -Milliseconds ([int]($wait * 1000)) }      # the program of the last packets is looked up too
    $srv = [string[]]@($script:Servers.Keys)
    $vpn = [string[]]@($srv + [KsBench.Probe]::ExitIps())
    return , [KsBench.Parse]::Pick($script:Pkts, $T0, $T1, $vpn, $Class, (Get-AppProgram), [KsBench.Owners]::Own($script:Pkts, $srv))
}

function Get-PhysicalAdapter {
    $tun = [KsBench.Probe]::BestIf('198.51.100.7')
    if ($Iface) { $ads = @($Iface | ForEach-Object { Get-NetAdapter -Name $_ }) }
    else {
        $idx = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0', '::/0' -ErrorAction SilentlyContinue |
                Where-Object { $_.NextHop -notin '0.0.0.0', '::' -and $_.InterfaceIndex -ne $tun } |
                Select-Object -ExpandProperty InterfaceIndex -Unique)
        $ads = @($idx | ForEach-Object { Get-NetAdapter -InterfaceIndex $_ -ErrorAction SilentlyContinue } |
                Where-Object { $_ -and $_.Status -eq 'Up' -and $_.MacAddress })
    }
    return , $ads
}

function Find-Server([double]$Seconds = 3.0, [switch]$SamePortOnly) {
    Start-Capture
    $t0 = [KsBench.Probe]::Now()
    while ([KsBench.Probe]::Now() - $t0 -lt $Seconds) {
        foreach ($port in 443, 53000, 3478) { [KsBench.Probe]::Udp('198.51.100.99', $port, (New-Object byte[] 400), 0) }
        [KsBench.Probe]::Tcp('198.51.100.99', 443, 0)
        Start-Sleep -Milliseconds 100
    }
    Start-Sleep -Milliseconds 500
    [KsBench.Probe]::Reap(0)
    Stop-Capture
    $c = @{}
    foreach ($p in $script:Pkts) {
        if ($p.Ts -lt $t0 -or [KsBench.Parse]::Classify($p, [string[]]@()) -ne 'leak') { continue }
        if ($p.Dst.StartsWith('198.51.100.') -or $p.Dst.ToLower().StartsWith('2001:db8')) { continue }
        $k = "$($p.Dst)|$($p.Proto)|$($p.DPort)"
        $c[$k] = 1 + [int]$c[$k]
    }
    $found = @($c.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object {
            $f = $_.Key.Split('|'); [pscustomobject]@{ Ip = $f[0]; Proto = [int]$f[1]; Port = [int]$f[2]; Count = $_.Value } })
    if ($SamePortOnly) {
        $ports = @($script:Servers.Values | ForEach-Object { "$($_.Proto)|$($_.Port)" })
        return , @($found | Where-Object { $ports -contains "$($_.Proto)|$($_.Port)" -and $_.Count -ge 5 })
    }
    return , $found
}

function Wait-Recovery([string]$Label) {
    [KsBench.Probe]::Label = $Label
    $back = [KsBench.Probe]::ProbeFor($Recover, 2)
    $script:ManualAt = $null
    while (-not $back -and $script:Interactive) {
        if ($null -eq $script:ManualAt) { $script:ManualAt = [KsBench.Probe]::Now() }    # from here on the user acts - D5 stops counting
        if (-not (Read-YesNo '  The VPN is not back. Reconnect it (or restart the app), then press Enter (n = stop the bench) [Y/n]' $true)) { break }
        $back = [KsBench.Probe]::ProbeFor(30, 2)
    }
    if ($null -ne $script:ManualAt -and $script:Deadline) { $script:Deadline += [KsBench.Probe]::Now() - $script:ManualAt }   # the time you took to reconnect is not the bench's
    if ($back) { [void][KsBench.Probe]::ProbeFor(1.5, 0) }
    return $back
}

function Test-Fits([int]$Seconds) { return [KsBench.Probe]::Now() + $Seconds -le $script:Deadline }

# -UntilDown: the fault stays until the tunnel goes down (+5 s), at most $HoldSec; otherwise exactly $HoldSec
function Invoke-Outage([string]$Id, [scriptblock]$Inject, [int]$HoldSec, [scriptblock]$Restore = $null, [switch]$UntilDown) {
    if (-not (Test-Fits ([Math]::Min($HoldSec, $Fault) + 20))) {
        Set-Result $Id 'not run' "the $([int]($Budget / 60))-minute limit for the outage tests was reached"; return
    }
    if (-not [KsBench.Probe]::TunnelUp()) {
        Write-Host "  $Id  waiting up to 15 s for the VPN to be connected..."
        if (-not [KsBench.Probe]::ProbeFor(15, 2)) { Set-Result $Id 'not run' 'the VPN was not connected when the test started'; return }
    }
    Write-Host "  $Id  running... $(Get-Title $Id)"
    Start-Capture
    $mark = $script:Journal.Count
    $t0 = [KsBench.Probe]::Now()
    $why = $null
    try { $why = & $Inject } catch { $why = "the bench could not make the change ($($_.Exception.Message))" }
    if ($why) { Undo-Since $mark; Stop-Capture; Set-Result $Id 'n/a' $why; return }
    if ($UntilDown) { Write-Host "      fault active until the tunnel goes down (at most $HoldSec s) - sending test traffic, watching $($script:PhysNames -join ', ')" }
    else { Write-Host "      fault active for $HoldSec s - sending test traffic, watching $($script:PhysNames -join ', ')" }
    [KsBench.Probe]::Label = $Id
    [KsBench.Probe]::WentDown = $false
    [void][KsBench.Probe]::ProbeFor($HoldSec, $(if ($UntilDown) { 3 } else { 1 }))
    $wentDown = [KsBench.Probe]::WentDown
    if ($wentDown) { Write-Host ('      the tunnel went down after {0:N0} s' -f ([KsBench.Probe]::DownAt - $t0)) }
    if ($Restore) { & $Restore } else { Undo-Since $mark -KeepCapture }
    Write-Host "      waiting for the VPN to come back (up to $Recover s), still watching for leaks..."
    $tw = [KsBench.Probe]::Now()
    $back = Wait-Recovery $Id
    if ($back) { Write-Host ('      VPN is back after {0:N0} s' -f ([KsBench.Probe]::Now() - $tw)) } else { Write-Host '      the VPN did not come back' }
    Undo-Since $mark -KeepCapture          # whatever this test still holds (T1's allow rule) goes now, not at the end
    Stop-Capture
    $t1 = [KsBench.Probe]::Now()
    if ($back) {
        foreach ($f in (Find-Server 1.5 -SamePortOnly)) { $script:Servers[$f.Ip] = @{ Proto = $f.Proto; Port = $f.Port } }
    }
    [void]$script:Windows.Add(@($t0, $t1))
    $leak = Get-Leak $t0 $t1
    if ($wentDown -or $leak.Count) { [void]$script:DnsWindows.Add(@($t0, $(if ($null -ne $script:ManualAt) { $script:ManualAt } else { $t1 }))) }   # D5 only where the test really tested something
    $dns = Get-Leak $t0 $t1 'dns'
    $hits = @([KsBench.Probe]::Hits | Where-Object { $_[0] -eq $Id } | ForEach-Object { $_[1] })
    $ev = [ordered]@{ tunnel_went_down = $wentDown; recovered = $back; leak = (Get-Evidence $leak $t0); dns = (Get-Evidence $dns $t0); online = $hits }
    if ($leak.Count -eq 0 -and -not $wentDown) {
        Set-Result $Id 'n/a' ("the tunnel stayed up for all $HoldSec s of the fault, so the kill-switch was not tested (nothing could leak); " +
            $(if ($UntilDown) { 'a longer -Hold may help' } else { 'the VPN kept its route into the tunnel meanwhile' })) $ev
    } elseif ($leak.Count -gt 0) {
        $e = $ev.leak
        Set-Result $Id 'fail' (('{0} packets leaked, first {1:N1} s after the fault, to {2}' -f $e.packets, ($e.first_ms / 1000), (@($e.to)[0..([Math]::Min(2, $e.to.Count - 1))] -join ', ')) +
            $(if ($e.programs) { " - sent by $($e.programs -join ', ')" } else { '' })) $ev
    } elseif ($hits) {
        Set-Result $Id 'invalid' 'the online check saw your real IP but the capture did not - traffic left through an adapter the bench does not watch (use -Iface)' $ev
    } else {
        Set-Result $Id 'pass' 'the tunnel went down and nothing leaked' $ev
    }
    if (-not $back) { $script:Stopped = $true }
}

function Block-Server {
    $prof = (Get-NetConnectionProfile -InterfaceIndex $script:Phys[0].ifIndex -ErrorAction SilentlyContinue | Select-Object -First 1).NetworkCategory
    $name = switch ("$prof") { 'DomainAuthenticated' { 'Domain' } 'Private' { 'Private' } default { 'Public' } }
    if (-not (Get-NetFirewallProfile -PolicyStore ActiveStore -Name $name).Enabled) {
        return "Windows Firewall is off for the $name profile, so the bench cannot block the VPN server"
    }
    $addr = @($script:Servers.Keys)
    foreach ($dir in 'Outbound', 'Inbound') {
        $n = "ksbench-$([guid]::NewGuid())"
        Add-Change "Windows Firewall rule: block the VPN server $($addr -join ', ') ($dir)" 'fw' $n
        $null = New-NetFirewallRule -Name $n -DisplayName "ksbench: block the VPN server ($dir)" -Group 'ksbench' `
            -Direction $dir -Action Block -RemoteAddress $addr -Profile Any
    }
    return $null
}

function Disable-Adapter([string]$Name) {
    Add-Change "adapter '$Name' disabled" 'adapter' $Name
    Disable-NetAdapter -Name $Name -Confirm:$false
}

function Stop-ProcessList($Procs) {
    foreach ($p in $Procs) {
        Write-Host "      + killing $($p.Name) (pid $($p.Id))"
        try { Stop-Process -Id $p.Id -Force } catch { Write-Host "      ! could not kill $($p.Name): $($_.Exception.Message)" }
    }
}

function Get-SafeProcess([int[]]$Ids) {
    return , @($Ids | Sort-Object -Unique | Where-Object { $_ -gt 4 -and $_ -ne $PID } |
            ForEach-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue } |
            Where-Object { $_ -and $NeverKill -notcontains $_.Name.ToLower() })
}

# ---------------------------------------------------------------- scenarios

function Invoke-Steady {
    $script:SteadyStart = [KsBench.Probe]::Now()
    $v6 = [KsBench.Probe]::V6
    Start-Capture
    if (Test-Wanted 'S1') {
        Write-Host '  S1  running... 2 DNS look-ups through the system resolver + direct DNS queries'
        $t0 = [KsBench.Probe]::Now()
        foreach ($i in 1..2) {
            [KsBench.Probe]::SystemLookup([KsBench.Probe]::UniqueName())
            [KsBench.Probe]::Udp('198.51.100.53', 53, [KsBench.Probe]::DnsPacket([KsBench.Probe]::UniqueName()), 0)
            [KsBench.Probe]::Tcp('198.51.100.53', 53, 0)
            if ($v6) { [KsBench.Probe]::Udp('2001:db8::53', 53, [KsBench.Probe]::DnsPacket([KsBench.Probe]::UniqueName()), 0) }
            Start-Sleep -Seconds 1
        }
        $s1 = @($t0, ([KsBench.Probe]::Now() + 1))
    }
    if (Test-Wanted 'S2') {
        if ($v6) {
            Write-Host '  S2  running... UDP, TCP and ping over IPv6'
            $t0 = [KsBench.Probe]::Now()
            foreach ($i in 1..2) {
                [KsBench.Probe]::Udp('2001:db8::2', 443, $null, 0); [KsBench.Probe]::Tcp('2001:db8::2', 443, 0)
                [KsBench.Probe]::PingOnce('2001:db8::2'); Start-Sleep -Milliseconds 700
            }
            $s2 = @($t0, ([KsBench.Probe]::Now() + 1))
        }
    }
    if (Test-Wanted 'S3') {
        Write-Host "  S3  running... UDP and TCP from sockets bound to $($script:PhysNames -join ', ')"
        $t0 = [KsBench.Probe]::Now()
        foreach ($i in 1..2) {
            foreach ($a in $script:Phys) {
                [KsBench.Probe]::Udp('198.51.100.13', 443, $null, $a.ifIndex); [KsBench.Probe]::Tcp('198.51.100.13', 443, $a.ifIndex)
                if ($v6) { [KsBench.Probe]::Udp('2001:db8::13', 443, $null, $a.ifIndex); [KsBench.Probe]::Tcp('2001:db8::13', 443, $a.ifIndex) }
            }
            Start-Sleep -Seconds 1
        }
        $s3 = @($t0, ([KsBench.Probe]::Now() + 1))
    }
    if (Test-Wanted 'S4') {
        Write-Host '  S4  running... a QUIC-sized UDP packet, a STUN request and a ping'
        $t0 = [KsBench.Probe]::Now()
        $quic = New-Object byte[] 1200; $quic[0] = 0xC0
        $stun = [byte[]](0, 1, 0, 0, 0x21, 0x12, 0xA4, 0x42) + (New-Object byte[] 12)
        foreach ($i in 1..2) {
            [KsBench.Probe]::Udp('198.51.100.14', 443, $quic, 0); [KsBench.Probe]::Udp('198.51.100.14', 3478, $stun, 0)
            [KsBench.Probe]::PingOnce('198.51.100.14'); Start-Sleep -Milliseconds 700
        }
        $s4 = @($t0, ([KsBench.Probe]::Now() + 1))
    }
    Start-Sleep -Seconds 1
    [KsBench.Probe]::Reap(0)
    Stop-Capture
    $script:SteadyEnd = [KsBench.Probe]::Now()
    if (Test-Wanted 'S1') {
        $dns = Get-Leak $s1[0] $s1[1] 'dns'; $ev = Get-Evidence $dns $s1[0]
        if ($dns.Count) { Set-Result 'S1' 'fail' "$($ev.packets) DNS packets went out of the tunnel to $($ev.to -join ', ')" $ev } else { Set-Result 'S1' 'pass' }
    }
    if (Test-Wanted 'S2') {
        if (-not $v6) { Set-Result 'S2' 'n/a' 'this network has no IPv6, so IPv6 cannot leak here' }
        else {
            $l = @((Get-Leak $s2[0] $s2[1]) | Where-Object { $_.Ver -eq 6 }); $ev = Get-Evidence $l $s2[0]
            if ($l.Count) { Set-Result 'S2' 'fail' "$($ev.packets) IPv6 packets bypassed the tunnel" $ev } else { Set-Result 'S2' 'pass' }
        }
    }
    if (Test-Wanted 'S3') {
        $l = @((Get-Leak $s3[0] $s3[1]) | Where-Object { $_.Dst -in '198.51.100.13', '2001:db8::13' }); $ev = Get-Evidence $l $s3[0]
        if ($l.Count) { Set-Result 'S3' 'fail' "$($ev.packets) packets got out next to the tunnel (the kill-switch only changes routes)" $ev } else { Set-Result 'S3' 'pass' }
    }
    if (Test-Wanted 'S4') {
        $l = @((Get-Leak $s4[0] $s4[1]) | Where-Object { $_.Dst -eq '198.51.100.14' }); $ev = Get-Evidence $l $s4[0]
        if ($l.Count) { Set-Result 'S4' 'fail' "$($ev.packets) packets bypassed the tunnel" $ev } else { Set-Result 'S4' 'pass' }
    }
}

# Over Remote Desktop, disabling the adapter may cut the session: asked once (no = skip D4, T1, T2)
function Test-AdapterOk([string]$Id, [string]$Name) {
    if ($env:SESSIONNAME -notlike 'RDP-*') { return $true }
    if ($null -eq $script:RdpOk) {
        $script:RdpOk = Read-YesNo "  You are connected over Remote Desktop: D4, T1 and T2 disable '$Name' for $Fault s and the session may drop. Run them anyway? [y/N]" $false
    }
    if (-not $script:RdpOk) { Set-Result $Id 'skipped' 'running over Remote Desktop - disabling the adapter could cut the session' }
    return $script:RdpOk
}

function Invoke-Disruptive {
    $script:Deadline = [KsBench.Probe]::Now() + $Budget
    $script:RdpOk = $null
    $pn = $script:Phys[0].Name
    $adapterBack = {          # only the adapter: T1's allow rule stays while the VPN comes back
        $it = $script:Journal | Where-Object { $_.kind -eq 'adapter' -and -not $_.done } | Select-Object -Last 1
        if ($it) { Undo-Change $it }
        Stop-Capture          # the adapter is back: start a new capture so pktmon sees it again
        for ($i = 0; $i -lt 100 -and (Get-NetAdapter -Name $pn).Status -ne 'Up'; $i++) { Start-Sleep -Milliseconds 200 }
        Start-Capture
        $ok = $false
        for ($i = 0; $i -lt 60 -and -not $ok; $i++) {
            $ok = [bool](Get-NetIPAddress -InterfaceAlias $pn -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    Where-Object { $_.AddressState -eq 'Preferred' -and $_.PrefixOrigin -ne 'WellKnown' })
            if (-not $ok) { [void][KsBench.Probe]::ProbeFor(0.5, 0) }
        }
        if (-not $ok) { Write-Host "      ! '$pn' is enabled but has no address yet - if it stays offline, turn it off and on in Settings" }
    }
    if ((Test-Wanted 'D1') -and -not $script:Stopped) { Invoke-Outage 'D1' { Block-Server } $Hold -UntilDown }
    if ((Test-Wanted 'D3') -and -not $script:Stopped) {
        $tun = Get-NetAdapter -InterfaceIndex ([KsBench.Probe]::BestIf('198.51.100.7')) -ErrorAction SilentlyContinue
        if (-not $tun) {
            Set-Result 'D3' 'n/a' "the tunnel is not a network adapter that can be disabled (Windows' own VPN client)"
        } else {
            $tn = $tun.Name
            Invoke-Outage 'D3' { Disable-Adapter $tn; $null } $Fault
        }
    }
    if ((Test-Wanted 'D4') -and -not $script:Stopped -and (Test-AdapterOk 'D4' $pn)) {
        Invoke-Outage 'D4' { Disable-Adapter $pn; $null } $Fault $adapterBack
    }
    if ((Test-Wanted 'T1') -and -not $script:Stopped -and (Test-AdapterOk 'T1' $pn)) {
        Invoke-Outage 'T1' {
            $n = "ksbench-$([guid]::NewGuid())"
            Add-Change 'Windows Firewall rule: allow 198.51.100.0/24, 2001:db8::/32 (Outbound)' 'fw' $n
            $null = New-NetFirewallRule -Name $n -DisplayName 'ksbench: allow the test addresses' -Group 'ksbench' `
                -Direction Outbound -Action Allow -RemoteAddress '198.51.100.0/24', '2001:db8::/32' -Profile Any
            Disable-Adapter $pn; $null
        } $Fault $adapterBack
    }
    if ((Test-Wanted 'D2') -and -not $script:Stopped) {
        $ids = @()
        foreach ($s in $script:Servers.Keys) { $ids += @(Get-NetTCPConnection -RemoteAddress $s -ErrorAction SilentlyContinue | ForEach-Object OwningProcess) }
        foreach ($p in $script:OuterPorts) { $ids += @(Get-NetUDPEndpoint -LocalPort $p -ErrorAction SilentlyContinue | ForEach-Object OwningProcess) }
        $procs = Get-SafeProcess $ids
        if (-not $procs) {
            Set-Result 'D2' 'n/a' 'no user process owns the VPN connection (the VPN runs inside Windows or in a driver) - nothing to kill safely'
        } elseif (-not (Test-Fits ($Fault + 20))) {
            Set-Result 'D2' 'not run' "the $([int]($Budget / 60))-minute limit for the outage tests was reached"
        } else {
            $desc = ($procs | ForEach-Object { "$($_.Name) (pid $($_.Id))" }) -join ', '
            if ((Read-YesNo "  D2 will kill the VPN client process $desc. OK? [y/N]" $false) -or $Yes) {
                Invoke-Outage 'D2' { Stop-ProcessList $procs; $null } $Hold { } -UntilDown
            } else { Set-Result 'D2' 'skipped' "you chose not to kill $desc" }
        }
    }
    if ((Test-Wanted 'T2') -and -not $script:Stopped) {
        if (-not (Test-Fits ($Fault + 20))) { Set-Result 'T2' 'not run' "the $([int]($Budget / 60))-minute limit for the outage tests was reached" }
        else {
            $name = $AppProcess                               # an expert's option: no question - nobody knows that name
            if (-not $name) { Set-Result 'T2' 'n/a' "an expert test: run it by naming the kill-switch app's process with -AppProcess" }
            else {
                $name = $name -replace '\.exe$', ''
                $procs = Get-SafeProcess @(Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object Id)
                if (-not $procs) { Set-Result 'T2' 'skipped' "no running process named $name" }
                elseif (Test-AdapterOk 'T2' $pn) { Invoke-Outage 'T2' { Stop-ProcessList $procs; Start-Sleep -Seconds 1; Disable-Adapter $pn; $null } $Fault $adapterBack }
            }
        }
    }
    if (Test-Wanted 'D5') {
        if ($script:DnsWindows.Count -eq 0) { Set-Result 'D5' 'n/a' 'no outage test took the tunnel down' }
        else {
            $dns = New-Object 'System.Collections.Generic.List[KsBench.Pkt]'
            foreach ($w in $script:DnsWindows) { $dns.AddRange((Get-Leak $w[0] $w[1] 'dns')) }
            $own = @(Get-ServerName -Name @($dns | ForEach-Object { $_.QName } | Where-Object { $_ } | Select-Object -Unique) -Server @($script:Servers.Keys))
            $mine = @($dns | Where-Object { $_.QName -and $own -contains $_.QName })    # the VPN server's own name: not a leak, shown
            $dns = @($dns | Where-Object { -not ($_.QName -and $own -contains $_.QName) })
            $ev = Get-Evidence $dns $script:DnsWindows[0][0]
            $names = @($dns | ForEach-Object { $_.QName } | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 5)
            if ($ev -and $names.Count) { $ev['names'] = $names }
            if ($mine.Count) { if (-not $ev) { $ev = [ordered]@{} }; $ev['server_name_lookups'] = [ordered]@{ packets = $mine.Count; names = @($own | Sort-Object) } }
            $note = if ($mine.Count) { "$($mine.Count) look-ups of the VPN server's own name ($((@($own | Sort-Object)) -join ', ')) not counted" } else { '' }
            if ($dns.Count) {
                $d = "$($ev.packets) DNS packets went out while the VPN was down, to $(@($ev.to)[0..([Math]::Min(2, $ev.to.Count - 1))] -join ', ')" + $(if ($names.Count) { " - names: $($names -join ', ')" } else { '' })
                Set-Result 'D5' 'fail' $(if ($note) { "$d; $note" } else { $d }) $ev
            } else { Set-Result 'D5' 'pass' $note $ev }
        }
    }
    if (Test-Wanted 'V1') {
        $spans = @($script:Windows | ForEach-Object { , $_ })
        if ($script:SteadyEnd) { $spans += , @($script:SteadyStart, $script:SteadyEnd) }
        $vm = New-Object 'System.Collections.Generic.List[KsBench.Pkt]'
        foreach ($w in $spans) { $vm.AddRange((Get-Leak $w[0] $w[1] 'vmleak')) }
        if ($vm.Count) {
            $ev = Get-Evidence $vm $spans[0][0]
            Set-Result 'V1' 'fail' "$($ev.packets) packets of a VM or WSL went out without the VPN, to $(@($ev.to)[0..([Math]::Min(2, $ev.to.Count - 1))] -join ', ')" $ev
        } elseif (-not @(Get-NetAdapter -Name 'vEthernet*' -ErrorAction SilentlyContinue).Count) { Set-Result 'V1' 'n/a' 'no virtual machines, WSL or containers on this computer' }
        elseif ($script:Windows.Count -eq 0) { Set-Result 'V1' 'n/a' 'no outage test ran' }
        else { Set-Result 'V1' 'pass' 'no packet of a VM or WSL went out' }
    }
}

function Get-Verdict([object]$Score, [string[]]$Failed, [int]$Tested, [int]$Total) {
    if ($null -eq $Score -or $Tested -lt $Total / 2) {
        return 'UNCLEAR', 'Too few tests ran to judge this kill-switch - run the outage tests too (they need your OK).'
    }
    if ($Score -ge 90) {
        if (-not $Failed) { return 'STRONG', 'No leak found. This kill-switch did its job in every test that ran - keep it.' }
        return 'STRONG', 'No traffic leak; only a minor gap (below). This kill-switch is good - keep it.'
    }
    if ($Score -ge 70) {
        return 'FAIR', 'No traffic leak while the VPN was down, but there are gaps (below). Acceptable for everyday use; for anything sensitive pick a kill-switch without them.'
    }
    return 'POOR', 'Your real traffic got out. This kill-switch does not protect you when it matters - it gives a false sense of safety.'
}

function Write-Report {
    $tested = @($Scenarios | Where-Object { $script:Res[$_[0]].status -in 'pass', 'fail' })
    $total = ($tested | ForEach-Object { $_[2] } | Measure-Object -Sum).Sum
    $got = ($tested | Where-Object { $script:Res[$_[0]].status -eq 'pass' } | ForEach-Object { $_[2] } | Measure-Object -Sum).Sum
    $score = if ($total) { [int][Math]::Round(100.0 * $got / $total) } else { $null }
    $failed = @($Scenarios | Where-Object { $script:Res[$_[0]].status -eq 'fail' } | ForEach-Object { $_[0] })
    $capped = ($null -ne $score) -and $score -gt $Cap -and @($failed | Where-Object { $Critical -contains $_ }).Count -gt 0
    if ($capped) { $score = $Cap }
    $allW = ($Scenarios | ForEach-Object { $_[2] } | Measure-Object -Sum).Sum
    Write-Host ("`n{0,-4} {1,-8} {2,-7} {3}" -f 'ID', 'Result', 'Points', 'Scenario')
    foreach ($s in $Scenarios) {
        $r = $script:Res[$s[0]]
        $pts = if ($r.status -in 'pass', 'fail') { '{0}/{1}' -f $(if ($r.status -eq 'pass') { $s[2] } else { 0 }), $s[2] } else { '-' }
        Write-Host ('{0,-4} {1,-8} {2,-7} {3}{4}' -f $s[0], $r.status.ToUpper(), $pts, $s[3], $(if ($r.detail) { " - $($r.detail)" } else { '' }))
    }
    $level, $verdict = Get-Verdict $score $failed $total $allW
    $color = @{ STRONG = 'Green'; FAIR = 'Yellow'; POOR = 'Red'; UNCLEAR = 'Yellow' }[$level]
    Write-Host ("`n" + ('=' * 78))
    $ran = @($Scenarios | Where-Object { $script:Res[$_[0]].status -in 'pass', 'fail' }).Count
    Write-Host ('SCORE: {0} / 100   ({1})   - from the {2} tests that could run here; {3} could not run on this setup and do not count' -f $(if ($null -ne $score) { $score } else { '-' }), $level, $ran, ($Scenarios.Count - $ran)) -ForegroundColor $color
    if ($capped) { Write-Host "(capped at ${Cap}: a leak in a critical test outweighs the points of the tests that passed)" }
    Write-Host $verdict -ForegroundColor $color
    if ($failed) {
        Write-Host "`nWhat failed means for you:"
        foreach ($s in $failed) { Write-Host "  $s  $($Meaning[$s])" }
    }
    if ($level -eq 'POOR') {
        # never VeroScudo recommended to VeroScudo itself (by its name, or installed here)
        if ("$script:ProductName" -match 'veroscudo' -or (Test-Path -LiteralPath (Join-Path $env:ProgramFiles 'VeroScudo'))) {
            Write-Host "`nThis is VeroScudo itself: see what failed above and its README (limits, settings)." -ForegroundColor Cyan
        } else { Write-Host ("`n" + $Recommend) -ForegroundColor Cyan }
    }
    $el = [int]([KsBench.Probe]::Now() - $script:TStart)
    Write-Host ('Run time: {0} min {1} s' -f [int][Math]::Floor($el / 60), ($el % 60))
    Write-Host ('=' * 78)
    if (@($script:Res.Values | Where-Object { $_.status -eq 'invalid' })) {
        Write-Host 'Results incomplete: the online check saw a leak the capture missed (see INVALID above).' -ForegroundColor Yellow
    }
    $real = @([KsBench.Probe]::Hits | ForEach-Object { $_[1] } | Sort-Object -Unique)
    if ($real) { Write-Host "Online check: Cloudflare saw an address other than the VPN's: $($real -join ', ')" -ForegroundColor Red }
    elseif ([KsBench.Probe]::Online) { Write-Host "Online check: Cloudflare only ever saw the VPN's address ($(@([KsBench.Probe]::VpnIps) -join ', '))." }
    else { Write-Host 'Online check: not run.' }
    $own = Get-Leak 0 ([KsBench.Probe]::Now() + 1) 'app'
    $appEv = Get-Evidence $own $(if ($own.Count) { $own[0].Ts } else { 0 })
    if ($own.Count) {
        $names = @($own | ForEach-Object { $_.QName } | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 5)
        $appEv['names'] = $names
        Write-Host ("Not counted - the VPN app's own connections outside the tunnel ({0}): {1} packets, to {2}{3}" -f
            ($appEv.programs -join ', '), $appEv.packets, (@($appEv.to | Select-Object -First 3) -join ', '),
            $(if ($names) { " - names: $($names -join ', ')" } else { '' }))
    }
    $os = Get-CimInstance Win32_OperatingSystem
    $doc = [ordered]@{
        tool = 'ksbench'; version = $Version; os = "$($os.Caption) $($os.Version)"; product = $script:ProductName
        date = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz'); score = $score; level = $level; capped = $capped
        points_tested = $total; points_total = $allW; adapters = $script:PhysNames; servers = @($script:Servers.Keys)
        online_check = [KsBench.Probe]::Online; online_hits = @([KsBench.Probe]::Hits | ForEach-Object { [ordered]@{ scenario = $_[0]; ip = $_[1] } })
        vpn_exit_ips = @([KsBench.Probe]::VpnIps); vpn_app_traffic = $appEv
        scenarios = @($Scenarios | ForEach-Object { [ordered]@{ id = $_[0]; group = $_[1]; weight = $_[2]; title = $_[3]; status = $script:Res[$_[0]].status; detail = $script:Res[$_[0]].detail; evidence = $script:Res[$_[0]].evidence } })
    }
    $path = if ($Out) { $Out } else { Join-Path $script:RunDir 'report.json' }
    ConvertTo-Json -InputObject $doc -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
    Write-Host "Report: $path"
}

function Invoke-Bench {
    if ($List) {
        foreach ($s in $Scenarios) { Write-Host ('{0,-3} {1,-7} {2,3}  {3}' -f $s[0], $s[1], $s[2], $s[3]) }
        Write-Host ("`n" + ($DisruptText -f $Hold, $Recover)); return
    }
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) { throw 'ksbench: run it in an elevated PowerShell (Run as administrator) - it needs to watch the network adapter.' }
    if (-not (Test-Path -LiteralPath $script:JournalDir)) { $null = New-Item -ItemType Directory -Path $script:JournalDir }
    if ($Restore) { Invoke-Restore; return }
    if (Get-PendingChange) { throw "ksbench: an earlier run did not finish undoing its changes. Run '.\ksbench.ps1 -Restore' first." }
    if (-not (Get-Command pktmon -ErrorAction SilentlyContinue)) { throw 'ksbench: pktmon is missing - it needs Windows 10 21H2 or later.' }

    $script:Interactive = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected -and -not $Yes
    $script:Res = @{}
    foreach ($s in $Scenarios) { $script:Res[$s[0]] = [ordered]@{ status = 'not run'; detail = ''; evidence = $null } }
    $script:Servers = @{}
    $script:Windows = New-Object System.Collections.ArrayList
    $script:DnsWindows = New-Object System.Collections.ArrayList
    $script:ManualAt = $null
    $script:Stopped = $false
    $script:RunDir = Join-Path $script:JournalDir ('run-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $null = New-Item -ItemType Directory -Path $script:RunDir
    $script:Journal = New-Object System.Collections.ArrayList

    $os = Get-CimInstance Win32_OperatingSystem
    Write-Host "ksbench $Version - VPN kill-switch leak bench ($($os.Caption) $($os.Version))"
    $script:ProductName = $Product
    if (-not $script:ProductName -and $script:Interactive) { $script:ProductName = (Read-Host 'Name of the VPN / kill-switch app you are testing (for the report)').Trim() }
    if (-not $script:ProductName) { $script:ProductName = 'unnamed' }

    $script:Phys = Get-PhysicalAdapter
    if (-not $script:Phys) { throw 'ksbench: no physical network adapter with a default route found - name it with -Iface' }
    $script:PhysNames = @($script:Phys | ForEach-Object Name)
    $script:Macs = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($a in $script:Phys) {
        [void]$script:Macs.Add(($a.MacAddress -replace '[-:]', '').ToLower())
        [void][KsBench.Probe]::Phys.Add([int]$a.ifIndex)
    }
    if (-not [KsBench.Probe]::TunnelUp()) {
        throw 'ksbench: the VPN does not seem to be connected (traffic to the internet does not go through a tunnel adapter). Connect it and run again.'
    }
    [KsBench.Probe]::V6 = [bool](Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceIndex -in $script:Phys.ifIndex -and $_.PrefixOrigin -ne 'WellKnown' -and $_.IPAddress -notlike 'fe80*' })
    $doOnline = if ($Online) { $true } elseif ($NoOnline) { $false } elseif ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
        $a = (Read-Host $OnlinePrompt).Trim().ToLower(); (-not $a) -or $a.StartsWith('y') } else { $false }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $script:TStart = [KsBench.Probe]::Now()
    [KsBench.Owners]::Start()
    try {
        Write-Host "Watching: $($script:PhysNames -join ', '); tunnel: interface $([KsBench.Probe]::BestIf('198.51.100.7'))"
        Write-Host "Capture files: $script:RunDir"
        $found = Find-Server
        if ($Server) {
            foreach ($s in $Server) {
                foreach ($ip in [Net.Dns]::GetHostAddresses($s)) { $script:Servers[$ip.ToString()] = @{ Proto = 0; Port = 0 } }
            }
            foreach ($f in $found) { if ($script:Servers.ContainsKey($f.Ip)) { $script:Servers[$f.Ip] = @{ Proto = $f.Proto; Port = $f.Port } } }
        } else {
            if (-not $found) { throw "ksbench: saw no traffic to a VPN server on $($script:PhysNames -join ', '). Name the server with -Server and the adapter with -Iface." }
            $top = $found[0].Count
            $cand = @($found | Where-Object { $_.Count -ge [Math]::Max(5, [int]($top / 5)) })
            Write-Host 'VPN server(s) seen on the physical adapter:'
            foreach ($c in $cand) { Write-Host ('  {0}  {1}/{2}' -f $c.Ip, @{ 6 = 'tcp'; 17 = 'udp' }[$c.Proto], $c.Port) }
            if (-not (Read-YesNo 'Is this your VPN server? [Y/n]' $true)) { throw 'ksbench: name the VPN server with -Server and run again.' }
            foreach ($c in $cand) { $script:Servers[$c.Ip] = @{ Proto = $c.Proto; Port = $c.Port } }
        }
        $script:OuterPorts = @($script:Pkts | Where-Object { $script:Servers.ContainsKey($_.Dst) -and $_.SPort -gt 0 -and $_.Proto -eq 17 } | ForEach-Object SPort | Sort-Object -Unique)   # UDP: D2 looks them up as UDP endpoints
        if ($doOnline) {
            [KsBench.Probe]::Online = $true
            [KsBench.Probe]::OnlineTick($null); Start-Sleep -Seconds 3
            if ([KsBench.Probe]::VpnIps.Count -eq 0) {
                [KsBench.Probe]::Online = $false
                Write-Host 'Online check: no answer from Cloudflare through the VPN - check not available.'
            }
        }
        Write-Host "`nSteady state (VPN connected):"
        Invoke-Steady
        if (@($Scenarios | Where-Object { $_[1] -ne 'steady' -and (Test-Wanted $_[0]) })) {
            Write-Host ("`n" + ($DisruptText -f $Hold, $Recover))
            if ((Read-YesNo 'Run the outage and tamper tests? [y/N]' $false) -or $Yes) {
                Write-Host "`nOutage and tamper tests:"
                Invoke-Disruptive
            } else {
                foreach ($s in $Scenarios) { if ($s[1] -ne 'steady' -and (Test-Wanted $s[0])) { $script:Res[$s[0]] = [ordered]@{ status = 'skipped'; detail = 'you chose not to run the outage tests'; evidence = $null } } }
            }
        }
    } finally {
        [KsBench.Owners]::Halt()
        if (@($script:Journal | Where-Object { -not $_.done -and $_.kind -ne 'pktmon' })) { Write-Host "Undoing the bench's changes:" }
        Undo-Since 0
        if ($script:UndoFailed.Count) {
            Write-Host "!! Some changes could not be undone (lines marked '!'). Run '.\ksbench.ps1 -Restore', or remove the Windows Firewall rules of group 'ksbench' and enable the adapter by hand." -ForegroundColor Red
        }
    }
    Write-Report
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-Bench }
