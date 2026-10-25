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

        /// <summary>Interface GUID (NetworkInterface.Id) -> LUID: the fast path, no CIM query.</summary>
        public static ulong LuidFromGuid(Guid id)
        {
            ulong luid;
            uint r = Native.ConvertInterfaceGuidToLuid(ref id, out luid);
            if (r != 0) throw new InvalidOperationException(string.Format("ConvertInterfaceGuidToLuid({0}) failed: {1}", id, r));
            return luid;
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
        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode)] internal static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);
        [DllImport("iphlpapi.dll")] internal static extern uint ConvertInterfaceIndexToLuid(uint ifIndex, out ulong luid);
        [DllImport("iphlpapi.dll")] internal static extern uint ConvertInterfaceGuidToLuid(ref Guid guid, out ulong luid);
        [DllImport("rasapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "RasDialW")]
        internal static extern uint RasDial(IntPtr extensions, string phonebook, IntPtr dialParams, uint notifierType, IntPtr notifier, out IntPtr rasConn);
        [DllImport("rasapi32.dll", EntryPoint = "RasHangUpW")] internal static extern uint RasHangUp(IntPtr rasConn);
    }
}
