// VeroScudo native helpers (Windows, 64-bit): the WFP kill-switch, RasDial without a command-line password,
// interface LUIDs. Compiled once by Install.ps1 into VeroScudo.Native.dll; VeroScudo.Core.psm1 falls back to
// compiling this file when the DLL is absent (development, CI).
//
// Why WFP and not Windows Defender Firewall rules: a default-block firewall profile still honours every enabled
// outbound *allow* rule (Store apps, Core Networking, installer-added rules, GPO), so it is not a kill-switch.
// WFP filters in our own sublayer are evaluated next to the firewall's: a BLOCK there is final no matter what the
// firewall allows. Our PERMITs are soft (they do not clear the action right), so the user's own firewall blocks
// still apply on top. Filters are PERSISTENT: they survive reboots and BFE restarts, which keeps an armed machine
// strict from boot until the user turns VeroScudo off.
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security;

namespace VeroScudo
{
    public static class Layer
    {
        public static readonly Guid ConnectV4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
        public static readonly Guid ConnectV6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
        public static readonly Guid RecvAcceptV4 = new Guid("e1cd9fe7-f4b5-4273-96c0-592e487b8650");
        public static readonly Guid RecvAcceptV6 = new Guid("a3b42c97-9f04-4672-b87e-cee9c483257f");
    }

    public static class Field
    {
        public static readonly Guid Flags = new Guid("632ce23b-5167-435c-86d7-e903684aa80c");
        public static readonly Guid LocalInterface = new Guid("4cd62a49-59c3-4969-b7f3-bda5d32890a4");
        public static readonly Guid RemoteAddress = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
        public static readonly Guid Protocol = new Guid("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");
        public static readonly Guid RemotePort = new Guid("c35a604d-d22b-4e1a-91b4-68f674ee674b");
        public static readonly Guid LocalPort = new Guid("0c1ba1af-5765-453f-af22-a8f791ac775b");  // = ICMP type for ICMP
        public static readonly Guid AppId = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
        public static readonly Guid UserId = new Guid("af043a0a-b34d-4f86-979c-c90371af6e66");     // FWPM_CONDITION_ALE_USER_ID
    }

    /// <summary>One WFP filter, described in managed terms. Conditions on the same field are OR-ed, different fields AND-ed.</summary>
    public sealed class FilterSpec
    {
        public string Name;
        public Guid Layer;
        public bool Permit;
        public byte Weight;                          // 0..15 inside our sublayer; permits above the catch-all block
        internal readonly List<Cond> Conds = new List<Cond>();

        public FilterSpec(string name, Guid layer, bool permit, byte weight) { Name = name; Layer = layer; Permit = permit; Weight = weight; }

        public FilterSpec Loopback() { Conds.Add(Cond.U32(Field.Flags, Native.FWP_MATCH_FLAGS_ALL_SET, 0x1)); return this; }   // FWP_CONDITION_FLAG_IS_LOOPBACK
        public FilterSpec Interface(ulong luid) { Conds.Add(Cond.U64(Field.LocalInterface, luid)); return this; }
        public FilterSpec Protocol(byte p) { Conds.Add(Cond.U8(Field.Protocol, p)); return this; }
        public FilterSpec RemotePort(ushort p) { Conds.Add(Cond.U16(Field.RemotePort, p)); return this; }
        public FilterSpec LocalPort(ushort p) { Conds.Add(Cond.U16(Field.LocalPort, p)); return this; }
        public FilterSpec IcmpType(ushort t) { return LocalPort(t); }
        public FilterSpec App(string path) { Conds.Add(Cond.AppId(path)); return this; }
        /// <summary>Only traffic sent as Local System or by an elevated administrator: Windows' own services and drivers
        /// (IKE, L2TP, PPTP) and what an administrator's elevated process has them send - never an ordinary program of
        /// the signed-in user, whose token does not carry the Administrators group.</summary>
        public FilterSpec Privileged() { Conds.Add(Cond.Privileged()); return this; }
        /// <summary>"203.0.113.5", "192.168.1.0/24", "fe80::/10"</summary>
        public FilterSpec Remote(string cidr) { Conds.Add(Cond.Addr(cidr)); return this; }

        public override string ToString()
        {
            var parts = new List<string>();
            foreach (var c in Conds) parts.Add(c.ToString());
            return string.Format("{0}|{1}|{2}|{3}|{4}", Name, Layer, Permit ? "permit" : "block", Weight, string.Join(",", parts.ToArray()));
        }
    }

    internal sealed class Cond
    {
        public Guid Field; public uint Match; public uint Type; public ulong Inline; public byte[] Bytes; public string Text;
        public static Cond U8(Guid f, byte v) { return new Cond { Field = f, Type = Native.FWP_UINT8, Inline = v, Text = v.ToString() }; }
        public static Cond U16(Guid f, ushort v) { return new Cond { Field = f, Type = Native.FWP_UINT16, Inline = v, Text = v.ToString() }; }
        public static Cond U32(Guid f, uint match, uint v) { return new Cond { Field = f, Match = match, Type = Native.FWP_UINT32, Inline = v, Text = "0x" + v.ToString("x") }; }
        public static Cond U64(Guid f, ulong v) { return new Cond { Field = f, Type = Native.FWP_UINT64, Inline = v, Text = "luid:" + v }; }
        public static Cond AppId(string path) { return new Cond { Field = VeroScudo.Field.AppId, Type = Native.FWP_BYTE_BLOB_TYPE, Text = path }; }
        public static Cond Privileged() { return new Cond { Field = VeroScudo.Field.UserId, Type = Native.FWP_SECURITY_DESCRIPTOR_TYPE, Text = "SYSTEM+ADMINS" }; }
        public static Cond Addr(string cidr)
        {
            string ip = cidr; int prefix = -1;
            int slash = cidr.IndexOf('/');
            if (slash >= 0) { ip = cidr.Substring(0, slash); prefix = int.Parse(cidr.Substring(slash + 1)); }
            IPAddress a = IPAddress.Parse(ip);
            byte[] b = a.GetAddressBytes();
            if (a.AddressFamily == AddressFamily.InterNetwork)
            {
                if (prefix < 0) prefix = 32;
                if (prefix > 32) throw new ArgumentException("bad IPv4 prefix: " + cidr);
                return new Cond { Field = VeroScudo.Field.RemoteAddress, Type = Native.FWP_V4_ADDR_MASK, Bytes = b, Inline = (ulong)prefix, Text = cidr };
            }
            if (prefix < 0) prefix = 128;
            if (prefix > 128) throw new ArgumentException("bad IPv6 prefix: " + cidr);
            return new Cond { Field = VeroScudo.Field.RemoteAddress, Type = Native.FWP_V6_ADDR_MASK, Bytes = b, Inline = (ulong)prefix, Text = cidr };
        }
        public override string ToString() { return Field.ToString().Substring(0, 8) + "=" + Text; }
    }

    public static class Wfp
    {
        public static readonly Guid ProviderKey = new Guid("7e1b5a38-3c9d-4f0e-9a6b-5e2d0c8f4a01");
        public static readonly Guid SubLayerKey = new Guid("7e1b5a38-3c9d-4f0e-9a6b-5e2d0c8f4a02");
        public const int MaxFilters = 256;           // filter keys are derived from an index, so they can be swept without enumeration

        public static Guid FilterKey(int i)
        {
            return new Guid(0x7e1b5a38, 0x3c9d, 0x4f0e, 0x9a, 0x6b, 0x5e, 0x2d, 0x0c, 0x8f, (byte)(i >> 8), (byte)(i & 0xff));
        }

        /// <summary>Atomically replaces every VeroScudo filter with <paramref name="specs"/> (one transaction: no gap, no partial state).</summary>
        public static void Apply(FilterSpec[] specs)
        {
            if (specs.Length > MaxFilters) throw new ArgumentException("too many filters");
            using (var e = new Engine())
            {
                e.Begin();
                try
                {
                    e.EnsureProviderAndSubLayer();
                    for (int i = 0; i < MaxFilters; i++) e.DeleteFilter(FilterKey(i));
                    for (int i = 0; i < specs.Length; i++) e.AddFilter(FilterKey(i), specs[i]);
                    e.Commit();
                }
                catch { e.Abort(); throw; }
            }
        }

        /// <summary>Asks WFP whether it accepts these filters, and changes nothing: they are added inside a transaction that is
        /// always rolled back (under keys of their own, so filters in force are not touched even there). Throws what WFP
        /// answers when it refuses one. The installer's self-test and the unit tests use it before anything is applied.</summary>
        public static void Validate(FilterSpec[] specs)
        {
            using (var e = new Engine())
            {
                e.Begin();
                try
                {
                    e.EnsureProviderAndSubLayer();
                    for (int i = 0; i < specs.Length; i++) e.AddFilter(Guid.NewGuid(), specs[i]);
                }
                finally { e.Abort(); }
            }
        }

        /// <summary>Removes every VeroScudo filter (the sublayer and provider stay; they filter nothing).</summary>
        public static void Clear()
        {
            using (var e = new Engine())
            {
                e.Begin();
                try { for (int i = 0; i < MaxFilters; i++) e.DeleteFilter(FilterKey(i)); e.Commit(); }
                catch { e.Abort(); throw; }
            }
        }

        /// <summary>Clear() plus the sublayer and the provider (uninstall).</summary>
        public static void Remove()
        {
            using (var e = new Engine())
            {
                e.Begin();
                try
                {
                    for (int i = 0; i < MaxFilters; i++) e.DeleteFilter(FilterKey(i));
                    e.DeleteSubLayerAndProvider();
                    e.Commit();
                }
                catch { e.Abort(); throw; }
            }
        }

        /// <summary>Number of consecutive VeroScudo filters present, starting at key 0.</summary>
        public static int Count()
        {
            using (var e = new Engine())
            {
                int n = 0;
                while (n < MaxFilters && e.FilterExists(FilterKey(n))) n++;
                return n;
            }
        }

        /// <summary>Field keys a layer accepts (diagnostics / tests: proves the GUIDs above are real).</summary>
        public static Guid[] LayerFields(Guid layer)
        {
            using (var e = new Engine()) return e.LayerFields(layer);
        }

        /// <summary>"weight|name" of every other WFP sublayer (read-only; the conflict check warns about one with our top weight).</summary>
        public static string[] SubLayers()
        {
            using (var e = new Engine()) return e.SubLayerNames();
        }

        /// <summary>Display names of every other WFP provider (read-only; the conflict check looks for other VPN apps' kill-switches).</summary>
        public static string[] Providers()
        {
            using (var e = new Engine()) return e.ProviderNames();
        }
    }

    internal sealed class Engine : IDisposable
    {
        IntPtr h;
        readonly List<IntPtr> allocs = new List<IntPtr>();
        readonly List<IntPtr> wfpAllocs = new List<IntPtr>();

        public Engine()
        {
            if (IntPtr.Size != 8) throw new PlatformNotSupportedException("VeroScudo needs 64-bit PowerShell");
            Check(Native.FwpmEngineOpen0(null, Native.RPC_C_AUTHN_WINNT, IntPtr.Zero, IntPtr.Zero, out h), "FwpmEngineOpen0");
        }
        public void Dispose()
        {
            FreeAll();
            if (h != IntPtr.Zero) { Native.FwpmEngineClose0(h); h = IntPtr.Zero; }
        }

        public void Begin() { Check(Native.FwpmTransactionBegin0(h, 0), "FwpmTransactionBegin0"); }
        public void Commit() { Check(Native.FwpmTransactionCommit0(h), "FwpmTransactionCommit0"); }
        public void Abort() { Native.FwpmTransactionAbort0(h); }

        public void EnsureProviderAndSubLayer()
        {
            var prov = new FWPM_PROVIDER0
            {
                providerKey = Wfp.ProviderKey,
                displayData = new FWPM_DISPLAY_DATA0 { name = Str("VeroScudo"), description = Str("VeroScudo VPN kill-switch") },
                flags = Native.FWPM_PROVIDER_FLAG_PERSISTENT,
            };
            uint r = Native.FwpmProviderAdd0(h, ref prov, IntPtr.Zero);
            if (r != 0 && r != Native.FWP_E_ALREADY_EXISTS) Check(r, "FwpmProviderAdd0");

            var sub = new FWPM_SUBLAYER0
            {
                subLayerKey = Wfp.SubLayerKey,
                displayData = new FWPM_DISPLAY_DATA0 { name = Str("VeroScudo"), description = Str("VeroScudo VPN kill-switch") },
                flags = Native.FWPM_SUBLAYER_FLAG_PERSISTENT,
                providerKey = GuidPtr(Wfp.ProviderKey),
                weight = 0xFFFF,
            };
            r = Native.FwpmSubLayerAdd0(h, ref sub, IntPtr.Zero);
            if (r != 0 && r != Native.FWP_E_ALREADY_EXISTS) Check(r, "FwpmSubLayerAdd0");
        }

        public void DeleteSubLayerAndProvider()
        {
            Guid s = Wfp.SubLayerKey, p = Wfp.ProviderKey;
            uint r = Native.FwpmSubLayerDeleteByKey0(h, ref s);
            if (r != 0 && r != Native.FWP_E_SUBLAYER_NOT_FOUND) Check(r, "FwpmSubLayerDeleteByKey0");
            r = Native.FwpmProviderDeleteByKey0(h, ref p);
            if (r != 0 && r != Native.FWP_E_PROVIDER_NOT_FOUND) Check(r, "FwpmProviderDeleteByKey0");
        }

        public void DeleteFilter(Guid key)
        {
            uint r = Native.FwpmFilterDeleteByKey0(h, ref key);
            if (r != 0 && r != Native.FWP_E_FILTER_NOT_FOUND) Check(r, "FwpmFilterDeleteByKey0");
        }

        public bool FilterExists(Guid key)
        {
            IntPtr f;
            uint r = Native.FwpmFilterGetByKey0(h, ref key, out f);
            if (r == 0) { Native.FwpmFreeMemory0(ref f); return true; }
            if (r == Native.FWP_E_FILTER_NOT_FOUND) return false;
            Check(r, "FwpmFilterGetByKey0");
            return false;
        }

        public void AddFilter(Guid key, FilterSpec s)
        {
            try
            {
                int n = s.Conds.Count;
                int csize = Marshal.SizeOf(typeof(FWPM_FILTER_CONDITION0));
                IntPtr conds = n > 0 ? Alloc(csize * n) : IntPtr.Zero;
                for (int i = 0; i < n; i++)
                {
                    var c = s.Conds[i];
                    var fc = new FWPM_FILTER_CONDITION0 { fieldKey = c.Field, matchType = c.Match };
                    fc.conditionValue.type = c.Type;
                    fc.conditionValue.value = ValueOf(c);
                    Marshal.StructureToPtr(fc, new IntPtr(conds.ToInt64() + (long)i * csize), false);
                }
                var f = new FWPM_FILTER0
                {
                    filterKey = key,
                    displayData = new FWPM_DISPLAY_DATA0 { name = Str("VeroScudo - " + s.Name), description = Str("VeroScudo kill-switch") },
                    flags = Native.FWPM_FILTER_FLAG_PERSISTENT,
                    providerKey = GuidPtr(Wfp.ProviderKey),
                    layerKey = s.Layer,
                    subLayerKey = Wfp.SubLayerKey,
                    numFilterConditions = (uint)n,
                    filterCondition = conds,
                };
                f.weight.type = Native.FWP_UINT8; f.weight.value = s.Weight;
                f.action.type = s.Permit ? Native.FWP_ACTION_PERMIT : Native.FWP_ACTION_BLOCK;
                ulong id;
                Check(Native.FwpmFilterAdd0(h, ref f, IntPtr.Zero, out id), "FwpmFilterAdd0 '" + s.Name + "'");
            }
            finally { FreeAll(); }
        }

        ulong ValueOf(Cond c)
        {
            switch (c.Type)
            {
                case Native.FWP_UINT8:
                case Native.FWP_UINT16:
                case Native.FWP_UINT32:
                    return c.Inline;
                case Native.FWP_UINT64:
                {
                    IntPtr p = Alloc(8); Marshal.WriteInt64(p, (long)c.Inline); return (ulong)p.ToInt64();
                }
                case Native.FWP_V4_ADDR_MASK:
                {
                    // FWP_V4_ADDR_AND_MASK { UINT32 addr; UINT32 mask; } in host byte order
                    uint addr = (uint)(c.Bytes[0] << 24 | c.Bytes[1] << 16 | c.Bytes[2] << 8 | c.Bytes[3]);
                    int prefix = (int)c.Inline;
                    uint mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
                    IntPtr p = Alloc(8); Marshal.WriteInt32(p, 0, (int)(addr & mask)); Marshal.WriteInt32(p, 4, (int)mask);
                    return (ulong)p.ToInt64();
                }
                case Native.FWP_V6_ADDR_MASK:
                {
                    // FWP_V6_ADDR_AND_MASK { UINT8 addr[16]; UINT8 prefixLength; }
                    IntPtr p = Alloc(17); Marshal.Copy(c.Bytes, 0, p, 16); Marshal.WriteByte(p, 16, (byte)c.Inline);
                    return (ulong)p.ToInt64();
                }
                case Native.FWP_SECURITY_DESCRIPTOR_TYPE:
                {
                    // FWP_BYTE_BLOB { UINT32 size; UINT8* data; } holding a self-relative security descriptor that grants
                    // "match" (FWP_ACTRL_MATCH_FILTER = 0x1, "CC" in SDDL) to Local System and to the Administrators group
                    // (a group a non-elevated program's token holds only as deny-only, so it does not match)
                    var sd = new System.Security.AccessControl.RawSecurityDescriptor("O:SYG:SYD:(A;;CC;;;SY)(A;;CC;;;BA)");
                    byte[] raw = new byte[sd.BinaryLength];
                    sd.GetBinaryForm(raw, 0);
                    IntPtr data = Alloc(raw.Length); Marshal.Copy(raw, 0, data, raw.Length);
                    IntPtr blob = Alloc(IntPtr.Size * 2);
                    Marshal.WriteInt32(blob, 0, raw.Length); Marshal.WriteIntPtr(blob, IntPtr.Size, data);
                    return (ulong)blob.ToInt64();
                }
                case Native.FWP_BYTE_BLOB_TYPE:
                {
                    IntPtr blob;
                    Check(Native.FwpmGetAppIdFromFileName0(c.Text, out blob), "FwpmGetAppIdFromFileName0 '" + c.Text + "'");
                    wfpAllocs.Add(blob);
                    return (ulong)blob.ToInt64();
                }
            }
            throw new ArgumentException("unsupported condition type " + c.Type);
        }

        public Guid[] LayerFields(Guid layer)
        {
            IntPtr lp;
            Check(Native.FwpmLayerGetByKey0(h, ref layer, out lp), "FwpmLayerGetByKey0");
            try
            {
                var l = (FWPM_LAYER0)Marshal.PtrToStructure(lp, typeof(FWPM_LAYER0));
                var res = new Guid[l.numFields];
                int fsize = Marshal.SizeOf(typeof(FWPM_FIELD0));
                for (int i = 0; i < l.numFields; i++)
                {
                    var fld = (FWPM_FIELD0)Marshal.PtrToStructure(new IntPtr(l.field.ToInt64() + (long)i * fsize), typeof(FWPM_FIELD0));
                    res[i] = (Guid)Marshal.PtrToStructure(fld.fieldKey, typeof(Guid));
                }
                return res;
            }
            finally { Native.FwpmFreeMemory0(ref lp); }
        }

        IntPtr Alloc(int size) { IntPtr p = Marshal.AllocHGlobal(size); allocs.Add(p); return p; }
        IntPtr Str(string s) { IntPtr p = Marshal.StringToHGlobalUni(s); allocs.Add(p); return p; }
        IntPtr GuidPtr(Guid g) { IntPtr p = Alloc(16); Marshal.StructureToPtr(g, p, false); return p; }
        void FreeAll()
        {
            foreach (var p in allocs) Marshal.FreeHGlobal(p);
            allocs.Clear();
            for (int i = 0; i < wfpAllocs.Count; i++) { IntPtr p = wfpAllocs[i]; Native.FwpmFreeMemory0(ref p); }
            wfpAllocs.Clear();
        }

        public string[] ProviderNames()
        {
            var names = new List<string>();
            IntPtr en;
            Check(Native.FwpmProviderCreateEnumHandle0(h, IntPtr.Zero, out en), "FwpmProviderCreateEnumHandle0");
            try
            {
                while (true)
                {
                    IntPtr entries; uint n;
                    Check(Native.FwpmProviderEnum0(h, en, 64, out entries, out n), "FwpmProviderEnum0");
                    try
                    {
                        for (int i = 0; i < n; i++)
                        {
                            IntPtr pp = Marshal.ReadIntPtr(entries, i * IntPtr.Size);
                            var prov = (FWPM_PROVIDER0)Marshal.PtrToStructure(pp, typeof(FWPM_PROVIDER0));
                            if (prov.providerKey == Wfp.ProviderKey) continue;
                            names.Add(prov.displayData.name != IntPtr.Zero ? Marshal.PtrToStringUni(prov.displayData.name) : prov.providerKey.ToString());
                        }
                    }
                    finally { if (entries != IntPtr.Zero) Native.FwpmFreeMemory0(ref entries); }
                    if (n < 64) break;
                }
            }
            finally { Native.FwpmProviderDestroyEnumHandle0(h, en); }
            return names.ToArray();
        }

        public string[] SubLayerNames()
        {
            var names = new List<string>();
            IntPtr en;
            Check(Native.FwpmSubLayerCreateEnumHandle0(h, IntPtr.Zero, out en), "FwpmSubLayerCreateEnumHandle0");
            try
            {
                while (true)
                {
                    IntPtr entries; uint n;
                    Check(Native.FwpmSubLayerEnum0(h, en, 64, out entries, out n), "FwpmSubLayerEnum0");
                    try
                    {
                        for (int i = 0; i < n; i++)
                        {
                            IntPtr pp = Marshal.ReadIntPtr(entries, i * IntPtr.Size);
                            var sl = (FWPM_SUBLAYER0)Marshal.PtrToStructure(pp, typeof(FWPM_SUBLAYER0));
                            if (sl.subLayerKey == Wfp.SubLayerKey) continue;
                            string name = sl.displayData.name != IntPtr.Zero ? Marshal.PtrToStringUni(sl.displayData.name) : sl.subLayerKey.ToString();
                            names.Add(sl.weight.ToString() + "|" + name);
                        }
                    }
                    finally { if (entries != IntPtr.Zero) Native.FwpmFreeMemory0(ref entries); }
                    if (n < 64) break;
                }
            }
            finally { Native.FwpmSubLayerDestroyEnumHandle0(h, en); }
            return names.ToArray();
        }

        internal static void Check(uint r, string what)
        {
            if (r != 0) throw new InvalidOperationException(string.Format("{0} failed: 0x{1:X8}", what, r));
        }
    }

    public static class Iface
    {
        /// <summary>Interface index -> LUID (the WFP local-interface condition matches LUIDs).</summary>
        public static ulong LuidFromIndex(uint ifIndex)
        {
            ulong luid;
            uint r = Native.ConvertInterfaceIndexToLuid(ifIndex, out luid);
            if (r != 0) throw new InvalidOperationException(string.Format("ConvertInterfaceIndexToLuid({0}) failed: {1}", ifIndex, r));
            return luid;
        }

        /// <summary>The LUID of the interface the route to this IPv4 address uses right now; 0 = no route. One system call
        /// (GetBestInterface) - cheap enough to ask every second.</summary>
        public static ulong BestLuid(string ipv4)
        {
            uint idx;
            byte[] a = System.Net.IPAddress.Parse(ipv4).GetAddressBytes();
            if (Native.GetBestInterface(BitConverter.ToUInt32(a, 0), out idx) != 0) return 0;
            ulong luid;
            return Native.ConvertInterfaceIndexToLuid(idx, out luid) == 0 ? luid : 0;
        }

        /// <summary>Interface GUID (NetworkInterface.Id) -> LUID: the fast path, no CIM query.</summary>
        public static ulong LuidFromGuid(Guid id)
        {
            ulong luid;
            uint r = Native.ConvertInterfaceGuidToLuid(ref id, out luid);
            if (r != 0) throw new InvalidOperationException(string.Format("ConvertInterfaceGuidToLuid({0}) failed: {1}", id, r));
            return luid;
        }
    }

    /// <summary>Routes for the "internet leads nowhere" while the tunnel is down (WSL and VM traffic is NAT-forwarded by
    /// Windows and follows the routing table, not the host's WFP filters). Created in the active store only - gone after a
    /// reboot - with Marker as their metric, so a route VeroScudo made is recognised again. One system call per route (the
    /// CIM cmdlets take ~100 ms each). MIB_IPFORWARD_ROW2 is read and written as raw bytes at its documented offsets; Read()
    /// is how a test checks those offsets against the real table.</summary>
    public static class Route
    {
        public const int Marker = 7;
        const int RowSize = 104;              // sizeof(MIB_IPFORWARD_ROW2)
        const int OffIndex = 8, OffPrefix = 12, OffPrefixLen = 40, OffNextHop = 44, OffMetric = 84;

        static void WriteAddr(IntPtr row, int off, IPAddress ip)
        {
            byte[] b = ip.GetAddressBytes();
            if (ip.AddressFamily == AddressFamily.InterNetwork) { Marshal.WriteInt16(row, off, 2); Marshal.Copy(b, 0, row + off + 4, 4); }
            else { Marshal.WriteInt16(row, off, 23); Marshal.Copy(b, 0, row + off + 8, 16); }
        }

        static IntPtr Build(uint ifIndex, string prefix, int length)
        {
            IPAddress ip = IPAddress.Parse(prefix);
            int max = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            if (length < 1 || length > max) throw new ArgumentOutOfRangeException("length");
            IntPtr row = Marshal.AllocHGlobal(RowSize);
            for (int i = 0; i < RowSize; i++) Marshal.WriteByte(row, i, 0);
            Native.InitializeIpForwardEntry(row);
            Marshal.WriteInt64(row, 0, 0);                                  // by index, not LUID
            Marshal.WriteInt32(row, OffIndex, (int)ifIndex);
            WriteAddr(row, OffPrefix, ip);
            Marshal.WriteByte(row, OffPrefixLen, (byte)length);
            WriteAddr(row, OffNextHop, ip.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any);   // on-link
            Marshal.WriteInt32(row, OffMetric, Marker);
            return row;
        }

        /// <summary>0 = added; 5010 = it exists already; any other value: the Win32 error.</summary>
        public static uint Add(uint ifIndex, string prefix, int length)
        {
            IntPtr row = Build(ifIndex, prefix, length);
            try { return Native.CreateIpForwardEntry2(row); } finally { Marshal.FreeHGlobal(row); }
        }

        /// <summary>0 = removed; 1168 = not there; any other value: the Win32 error.</summary>
        public static uint Delete(uint ifIndex, string prefix, int length)
        {
            IntPtr row = Build(ifIndex, prefix, length);
            try { return Native.DeleteIpForwardEntry2(row); } finally { Marshal.FreeHGlobal(row); }
        }

        static string ReadAddr(IntPtr row, int off)
        {
            short fam = Marshal.ReadInt16(row, off);
            byte[] b = new byte[fam == 2 ? 4 : 16];
            if (fam == 2) Marshal.Copy(row + off + 4, b, 0, 4); else if (fam == 23) Marshal.Copy(row + off + 8, b, 0, 16); else return null;
            return new IPAddress(b).ToString();
        }

        /// <summary>The whole routing table (IPv4 and IPv6) as "ifIndex|prefix/length|nextHop|metric".</summary>
        public static string[] Read()
        {
            IntPtr table;
            uint r = Native.GetIpForwardTable2(0, out table);
            if (r != 0) throw new InvalidOperationException("GetIpForwardTable2 failed: " + r);
            try
            {
                int n = Marshal.ReadInt32(table, 0);
                var list = new List<string>(n);
                for (int i = 0; i < n; i++)
                {
                    IntPtr row = table + 8 + i * RowSize;
                    string pre = ReadAddr(row, OffPrefix), hop = ReadAddr(row, OffNextHop);
                    if (pre == null || hop == null) continue;
                    list.Add(string.Format("{0}|{1}/{2}|{3}|{4}", (uint)Marshal.ReadInt32(row, OffIndex), pre, Marshal.ReadByte(row, OffPrefixLen), hop, (uint)Marshal.ReadInt32(row, OffMetric)));
                }
                return list.ToArray();
            }
            finally { Native.FreeMibTable(table); }
        }
    }

    /// <summary>The routes to nowhere at the very moment the tunnel's route goes, not up to a second later when the
    /// watchdog looks: while a full tunnel is up the watchdog hands over the routes it would add (Arm), and Windows calls
    /// back on every IPv4 route change; when the route to the internet then no longer leads into the tunnel, the routes are
    /// added from that callback. Nothing changes in the routing table while the tunnel holds the route. Once per Arm; the
    /// watchdog records what was added (its own sync finds the routes there) and removes them as before.</summary>
    public static class RouteGuard
    {
        internal delegate void Callback(IntPtr context, IntPtr row, int type);
        static readonly Callback cb = OnChange;          // kept alive: Windows holds a pointer to it
        static readonly object gate = new object();
        static IntPtr handle = IntPtr.Zero;
        static ulong tunnel;
        static uint lo;
        static string[] prefixes = new string[0];
        static string armedFlag = "";
        /// <summary>When the routes were added from the callback (UTC), else DateTime.MinValue.</summary>
        public static DateTime Fired = DateTime.MinValue;

        /// <summary>Watch for the route leaving tunnelLuid; prefixes are "a.b.c.d/len" for the loopback index lo. Nothing
        /// is added once flag (VeroScudo's "armed" file) is gone: Off removes it before it hangs up.</summary>
        public static void Arm(ulong tunnelLuid, uint loIndex, string[] list, string flag)
        {
            lock (gate)
            {
                tunnel = tunnelLuid; lo = loIndex; prefixes = list ?? new string[0]; armedFlag = flag ?? "";
                if (handle == IntPtr.Zero)
                {
                    uint r = Native.NotifyRouteChange2(2, cb, IntPtr.Zero, false, out handle);
                    if (r != 0) { handle = IntPtr.Zero; throw new InvalidOperationException("NotifyRouteChange2 failed: " + r); }
                }
            }
        }

        public static void Disarm()
        {
            lock (gate) { tunnel = 0; prefixes = new string[0]; }
        }

        public static bool Armed { get { lock (gate) { return tunnel != 0; } } }

        static void OnChange(IntPtr context, IntPtr row, int type)
        {
            try
            {
                string[] todo; uint idx;
                lock (gate)
                {
                    if (tunnel == 0 || Iface.BestLuid("1.1.1.1") == tunnel) return;
                    if (armedFlag.Length == 0 || !System.IO.File.Exists(armedFlag)) { tunnel = 0; prefixes = new string[0]; return; }   // turned off
                    todo = prefixes; idx = lo; tunnel = 0; prefixes = new string[0];
                }
                foreach (string p in todo)
                {
                    string[] f = p.Split('/');
                    try { Route.Add(idx, f[0], int.Parse(f[1])); } catch { }
                }
                Fired = DateTime.UtcNow;
            }
            catch { }                                     // never let an exception out of a Windows callback
        }
    }

    /// <summary>A DNS responder on a loopback address that answers ONLY the VPN server's names, with the addresses
    /// VeroScudo has cached - for the NRPT rule that sends exactly those names here while the tunnel is down, so the redial
    /// finds its server without a DNS packet leaving the PC. Every other name: REFUSED. Never reachable from the network.</summary>
    public static class LocalDns
    {
        static UdpClient udp;
        static System.Threading.Thread loop;
        static Dictionary<string, string[]> map = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        public static string Address;

        /// <summary>Listens on the first of these loopback addresses that is free (port 53). True when listening.</summary>
        public static bool Start(string[] candidates)
        {
            if (udp != null) return true;
            foreach (string a in candidates)
            {
                IPAddress ip;
                if (!IPAddress.TryParse(a, out ip) || !IPAddress.IsLoopback(ip)) continue;      // loopback only, ever
                try { udp = new UdpClient(new IPEndPoint(ip, 53)); Address = a; break; }
                catch (SocketException) { }
            }
            if (udp == null) return false;
            loop = new System.Threading.Thread(Serve) { IsBackground = true, Name = "VeroScudo local DNS" };
            loop.Start();
            return true;
        }

        public static void Stop()
        {
            UdpClient u = udp; udp = null; Address = null;
            if (u != null) u.Close();
        }

        /// <summary>The names to answer and their addresses (replaced as a whole: names not given are refused).</summary>
        public static void SetAnswers(string[] names, string[] addresses)
        {
            var m = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            foreach (string n in names ?? new string[0]) if (!string.IsNullOrEmpty(n)) m[n.TrimEnd('.')] = addresses ?? new string[0];
            map = m;
        }

        static void Serve()
        {
            while (true)
            {
                UdpClient u = udp;
                if (u == null) return;
                IPEndPoint from = new IPEndPoint(IPAddress.Any, 0);
                byte[] q;
                try { q = u.Receive(ref from); }
                catch (ObjectDisposedException) { return; }
                catch (SocketException) { continue; }
                if (!IPAddress.IsLoopback(from.Address)) continue;                            // nothing from outside
                byte[] r = Answer(q, map);
                if (r != null) { try { u.Send(r, r.Length, from); } catch (Exception) { } }
            }
        }

        /// <summary>The reply to one DNS query: A/AAAA of a known name (TTL 30), no data for its other types, REFUSED for
        /// any other name; null for what is not one well-formed standard query. Pure.</summary>
        public static byte[] Answer(byte[] q, Dictionary<string, string[]> names)
        {
            if (q == null || q.Length < 17 || (q[2] & 0xF8) != 0 || q[4] != 0 || q[5] != 1) return null;   // a query, QDCOUNT 1
            var labels = new List<string>();
            int o = 12;
            while (o < q.Length && q[o] != 0)
            {
                int n = q[o];
                if (n > 63 || o + 1 + n > q.Length) return null;
                labels.Add(System.Text.Encoding.ASCII.GetString(q, o + 1, n));
                o += 1 + n;
            }
            if (o + 5 > q.Length) return null;
            int qtype = (q[o + 1] << 8) | q[o + 2], qclass = (q[o + 3] << 8) | q[o + 4];
            int qend = o + 5;
            string name = string.Join(".", labels.ToArray());
            string[] addrs = null;
            bool known = qclass == 1 && names != null && names.TryGetValue(name, out addrs);
            var ans = new List<byte[]>();
            if (known)
            {
                foreach (string a in addrs)
                {
                    IPAddress ip;
                    if (!IPAddress.TryParse(a, out ip)) continue;
                    byte[] b = ip.GetAddressBytes();
                    if ((qtype == 1 && b.Length == 4) || (qtype == 28 && b.Length == 16)) ans.Add(b);
                }
            }
            var r = new List<byte>();
            r.Add(q[0]); r.Add(q[1]);
            r.Add((byte)(0x84 | (q[2] & 0x01)));                     // QR, AA, RD as asked
            r.Add((byte)(known ? 0x00 : 0x05));                       // NOERROR / REFUSED
            r.AddRange(new byte[] { 0, 1, 0, (byte)ans.Count, 0, 0, 0, 0 });
            for (int i = 12; i < qend; i++) r.Add(q[i]);
            foreach (byte[] b in ans)
            {
                r.AddRange(new byte[] { 0xC0, 0x0C, 0, (byte)qtype, 0, 1, 0, 0, 0, 30, 0, (byte)b.Length });
                r.AddRange(b);
            }
            return r.ToArray();
        }
    }

    public static class Ras
    {
        // RASDIALPARAMSW (64-bit): dwSize, szEntryName[257], szPhoneNumber[129], szCallbackNumber[129], szUserName[257],
        // szPassword[257], szDomain[16], dwSubEntry, dwCallbackId (ULONG_PTR), dwIfIndex (Win7+), szEncPassword (Win7+).
        const int OffEntry = 4, OffUser = 1034, OffPassword = 1548, LenName = 257, LenPassword = 257;
        static readonly int[] Sizes = { 2128, 2120, 2112 };       // newest layout first; RasDial rejects an unknown dwSize with 632

        /// <summary>Dials a phonebook entry with an explicit credential. The password never appears on a command line and the
        /// unmanaged copy is zeroed before it is freed. Returns the RAS error code (0 = connected).</summary>
        public static int Dial(string entry, string user, SecureString password)
        {
            if (IntPtr.Size != 8) throw new PlatformNotSupportedException("VeroScudo needs 64-bit PowerShell");
            if (entry.Length >= LenName || (user ?? "").Length >= LenName) throw new ArgumentException("entry or user name too long");
            int code = 632;
            foreach (int size in Sizes)
            {
                IntPtr buf = Marshal.AllocHGlobal(size);
                IntPtr pw = IntPtr.Zero;
                try
                {
                    ZeroMemory(buf, size);
                    Marshal.WriteInt32(buf, 0, size);
                    WriteChars(buf, OffEntry, entry);
                    WriteChars(buf, OffUser, user ?? "");
                    if (password != null)
                    {
                        if (password.Length >= LenPassword) throw new ArgumentException("password too long");
                        pw = Marshal.SecureStringToGlobalAllocUnicode(password);
                        CopyMemory(new IntPtr(buf.ToInt64() + OffPassword), pw, (UIntPtr)(uint)(password.Length * 2));
                    }
                    IntPtr conn;
                    code = (int)Native.RasDial(IntPtr.Zero, null, buf, 0, IntPtr.Zero, out conn);
                    if (code != 0 && conn != IntPtr.Zero) Native.RasHangUp(conn);
                }
                finally
                {
                    ZeroMemory(buf, size);
                    Marshal.FreeHGlobal(buf);
                    if (pw != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(pw);
                }
                if (code != 632) return code;
            }
            return code;
        }

        /// <summary>The username Windows saved for a VPN entry (RasGetCredentials, user name only - the password is never
        /// requested); "" when none. allUsers: the all-users phonebook.</summary>
        public static string SavedUserName(string entry, bool allUsers)
        {
            const int Size = 4 + 4 + 257 * 2 + 257 * 2 + 16 * 2;          // RASCREDENTIALSW
            IntPtr buf = Marshal.AllocHGlobal(Size);
            try
            {
                ZeroMemory(buf, Size);
                Marshal.WriteInt32(buf, 0, Size);
                Marshal.WriteInt32(buf, 4, 0x1);                              // RASCM_UserName
                string pbk = allUsers ? Environment.ExpandEnvironmentVariables(@"%ProgramData%\Microsoft\Network\Connections\Pbk\rasphone.pbk") : null;
                if (Native.RasGetCredentials(pbk, entry, buf) != 0) return "";
                if ((Marshal.ReadInt32(buf, 4) & 0x1) == 0) return "";
                return Marshal.PtrToStringUni(new IntPtr(buf.ToInt64() + 8)) ?? "";
            }
            finally { ZeroMemory(buf, Size); Marshal.FreeHGlobal(buf); }
        }

        static void WriteChars(IntPtr buf, int off, string s)
        {
            char[] c = s.ToCharArray();
            if (c.Length > 0) Marshal.Copy(c, 0, new IntPtr(buf.ToInt64() + off), c.Length);
        }
        static void ZeroMemory(IntPtr p, int size) { Marshal.Copy(new byte[size], 0, p, size); }
        [DllImport("kernel32.dll", EntryPoint = "RtlMoveMemory")] static extern void CopyMemory(IntPtr dst, IntPtr src, UIntPtr len);
    }

    // ------------------------------------------------------------------ interop
    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_DISPLAY_DATA0 { public IntPtr name; public IntPtr description; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_BYTE_BLOB { public uint size; public IntPtr data; }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    internal struct FWP_VALUE0 { [FieldOffset(0)] public uint type; [FieldOffset(8)] public ulong value; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_FILTER_CONDITION0 { public Guid fieldKey; public uint matchType; public FWP_VALUE0 conditionValue; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_ACTION0 { public uint type; public Guid filterType; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct CONTEXT_UNION { public ulong lo; public ulong hi; }     // union { UINT64 rawContext; GUID providerContextKey; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_FILTER0
    {
        public Guid filterKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public IntPtr providerKey;
        public FWP_BYTE_BLOB providerData;
        public Guid layerKey;
        public Guid subLayerKey;
        public FWP_VALUE0 weight;
        public uint numFilterConditions;
        public IntPtr filterCondition;
        public FWPM_ACTION0 action;
        public CONTEXT_UNION context;
        public IntPtr reserved;
        public ulong filterId;
        public FWP_VALUE0 effectiveWeight;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_PROVIDER0
    {
        public Guid providerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public FWP_BYTE_BLOB providerData;
        public IntPtr serviceName;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_SUBLAYER0
    {
        public Guid subLayerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public IntPtr providerKey;
        public FWP_BYTE_BLOB providerData;
        public ushort weight;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_FIELD0 { public IntPtr fieldKey; public uint type; public uint dataType; }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_LAYER0
    {
        public Guid layerKey;
        public FWPM_DISPLAY_DATA0 displayData;
        public uint flags;
        public uint numFields;
        public IntPtr field;
        public Guid defaultSubLayerKey;
        public ushort layerId;
    }

    public static class Native
    {
        internal const uint RPC_C_AUTHN_WINNT = 10;
        internal const uint FWP_UINT8 = 1, FWP_UINT16 = 2, FWP_UINT32 = 3, FWP_UINT64 = 4, FWP_BYTE_BLOB_TYPE = 12;
        internal const uint FWP_SECURITY_DESCRIPTOR_TYPE = 14;
        internal const uint FWP_V4_ADDR_MASK = 0x100, FWP_V6_ADDR_MASK = 0x101;
        internal const uint FWP_MATCH_EQUAL = 0, FWP_MATCH_FLAGS_ALL_SET = 6;
        internal const uint FWP_ACTION_BLOCK = 0x1001, FWP_ACTION_PERMIT = 0x1002;
        internal const uint FWPM_FILTER_FLAG_PERSISTENT = 0x1, FWPM_PROVIDER_FLAG_PERSISTENT = 0x1, FWPM_SUBLAYER_FLAG_PERSISTENT = 0x1;
        internal const uint FWP_E_FILTER_NOT_FOUND = 0x80320003, FWP_E_PROVIDER_NOT_FOUND = 0x80320005;
        internal const uint FWP_E_SUBLAYER_NOT_FOUND = 0x80320007, FWP_E_ALREADY_EXISTS = 0x80320009;

        /// <summary>Struct sizes/offsets as the marshaller lays them out (unit-tested against the documented x64 layout).</summary>
        public static string Layout()
        {
            Func<Type, string, int> o = (t, f) => Marshal.OffsetOf(t, f).ToInt32();
            var F = typeof(FWPM_FILTER0);
            return string.Format("filter={0} cond={1} value={2} sublayer={3} provider={4} | layerKey={5} weight={6} num={7} action={8} context={9} filterId={10} eff={11}",
                Marshal.SizeOf(F), Marshal.SizeOf(typeof(FWPM_FILTER_CONDITION0)), Marshal.SizeOf(typeof(FWP_VALUE0)),
                Marshal.SizeOf(typeof(FWPM_SUBLAYER0)), Marshal.SizeOf(typeof(FWPM_PROVIDER0)),
                o(F, "layerKey"), o(F, "weight"), o(F, "numFilterConditions"), o(F, "action"), o(F, "context"), o(F, "filterId"), o(F, "effectiveWeight"));
        }

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)]
        internal static extern uint FwpmEngineOpen0(string serverName, uint authnService, IntPtr authIdentity, IntPtr session, out IntPtr engineHandle);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmEngineClose0(IntPtr engineHandle);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmTransactionCommit0(IntPtr engineHandle);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmTransactionAbort0(IntPtr engineHandle);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmProviderAdd0(IntPtr engineHandle, ref FWPM_PROVIDER0 provider, IntPtr sd);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmProviderDeleteByKey0(IntPtr engineHandle, ref Guid key);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmSubLayerAdd0(IntPtr engineHandle, ref FWPM_SUBLAYER0 subLayer, IntPtr sd);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmSubLayerDeleteByKey0(IntPtr engineHandle, ref Guid key);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterAdd0(IntPtr engineHandle, ref FWPM_FILTER0 filter, IntPtr sd, out ulong id);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterDeleteByKey0(IntPtr engineHandle, ref Guid key);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmFilterGetByKey0(IntPtr engineHandle, ref Guid key, out IntPtr filter);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmLayerGetByKey0(IntPtr engineHandle, ref Guid key, out IntPtr layer);
        [DllImport("fwpuclnt.dll")] internal static extern void FwpmFreeMemory0(ref IntPtr p);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmProviderCreateEnumHandle0(IntPtr engineHandle, IntPtr enumTemplate, out IntPtr enumHandle);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmProviderEnum0(IntPtr engineHandle, IntPtr enumHandle, uint numEntriesRequested, out IntPtr entries, out uint numEntriesReturned);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmProviderDestroyEnumHandle0(IntPtr engineHandle, IntPtr enumHandle);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmSubLayerCreateEnumHandle0(IntPtr engineHandle, IntPtr enumTemplate, out IntPtr enumHandle);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmSubLayerEnum0(IntPtr engineHandle, IntPtr enumHandle, uint numEntriesRequested, out IntPtr entries, out uint numEntriesReturned);
        [DllImport("fwpuclnt.dll")] internal static extern uint FwpmSubLayerDestroyEnumHandle0(IntPtr engineHandle, IntPtr enumHandle);
        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] internal static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);
        [DllImport("iphlpapi.dll")] internal static extern uint ConvertInterfaceIndexToLuid(uint ifIndex, out ulong luid);
        [DllImport("iphlpapi.dll")] internal static extern uint GetBestInterface(uint destAddr, out uint bestIfIndex);
        [DllImport("iphlpapi.dll")] internal static extern void InitializeIpForwardEntry(IntPtr row);
        [DllImport("iphlpapi.dll")] internal static extern uint CreateIpForwardEntry2(IntPtr row);
        [DllImport("iphlpapi.dll")] internal static extern uint DeleteIpForwardEntry2(IntPtr row);
        [DllImport("iphlpapi.dll")] internal static extern uint GetIpForwardTable2(ushort family, out IntPtr table);
        [DllImport("iphlpapi.dll")] internal static extern void FreeMibTable(IntPtr memory);
        [DllImport("iphlpapi.dll")] internal static extern uint NotifyRouteChange2(ushort family, RouteGuard.Callback callback, IntPtr context, bool initialNotification, out IntPtr handle);
        [DllImport("iphlpapi.dll")] internal static extern uint ConvertInterfaceGuidToLuid(ref Guid guid, out ulong luid);
        [DllImport("rasapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RasDialW")]
        internal static extern uint RasDial(IntPtr extensions, string phonebook, IntPtr dialParams, uint notifierType, IntPtr notifier, out IntPtr rasConn);
        [DllImport("rasapi32.dll", EntryPoint = "RasHangUpW")] internal static extern uint RasHangUp(IntPtr rasConn);
        [DllImport("rasapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RasGetCredentialsW")]
        internal static extern uint RasGetCredentials(string phonebook, string entry, IntPtr credentials);
    }
}
