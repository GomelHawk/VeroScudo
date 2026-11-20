#!/usr/bin/env python3
"""ksbench - a vendor-neutral VPN kill-switch leak bench for Linux and macOS.

Connect your VPN, then run as root:   sudo python3 ksbench.py
It watches the physical network adapter while it breaks the VPN in a few ways
and scores what got out. Rules and weights: SCENARIOS.md. Undo a run that was
interrupted:  sudo python3 ksbench.py --restore
Needs only Python 3.9+ (standard library). Linux: iproute2, iptables or nft.
macOS: tcpdump, pfctl, route, ifconfig, lsof (all part of macOS).
"""
import argparse
import ipaddress
import json
import os
import platform
import random
import re
import shutil
import signal
import socket
import ssl
import string
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

VERSION = "0.1.0"
IS_LINUX = sys.platform.startswith("linux")
IS_MAC = sys.platform == "darwin"

# Probe targets: documentation addresses (RFC 5737 / RFC 3849). They never belong to anyone,
# so a probe that shows up on the physical adapter is a leak - and nothing reaches a third party.
P_SERVERS = "198.51.100.99"     # traffic through the tunnel to find the VPN server
P_DNS4, P_DNS6 = "198.51.100.53", "2001:db8::53"
P_V6 = "2001:db8::2"
P_BOUND4, P_BOUND6 = "198.51.100.13", "2001:db8::13"
P_MISC4 = "198.51.100.14"
P_OUT4, P_OUT6 = "198.51.100.7", "2001:db8::7"
ALLOW_NETS = ("198.51.100.0/24", "2001:db8::/32")
ONLINE4 = "https://1.1.1.1/cdn-cgi/trace"
ONLINE6 = "https://[2606:4700:4700::1111]/cdn-cgi/trace"

# id, group, weight, title - keep in sync with ksbench.ps1 and SCENARIOS.md (a test checks it)
SCENARIOS = [
    ("S1", "steady", 10, "DNS stays in the tunnel"),
    ("S2", "steady", 7, "IPv6 stays in the tunnel"),
    ("S3", "steady", 10, "A program bound to the physical adapter cannot get out"),
    ("S4", "steady", 3, "UDP/QUIC, STUN and ping stay in the tunnel"),
    ("D1", "outage", 12, "VPN server unreachable"),
    ("D2", "outage", 8, "VPN client process killed"),
    ("D3", "outage", 9, "Tunnel adapter goes down"),
    ("D4", "outage", 12, "Physical link drops and comes back"),
    ("D5", "outage", 7, "No DNS leak during any outage"),
    ("V1", "outage", 7, "Virtual machines and WSL stay inside"),
    ("T1", "tamper", 10, "Another program adds a firewall allow rule"),
    ("T2", "tamper", 5, "The kill-switch app is killed"),
]
NEVER_KILL = {"systemd", "init", "networkmanager", "launchd", "kernel_task", "configd", "sshd", "system",
              "svchost", "lsass", "csrss", "wininit", "services", "smss", "registry", "idle", "python3", "python"}

_LAN = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
    "224.0.0.0/4", "255.255.255.255/32", "0.0.0.0/8", "fe80::/10", "fc00::/7", "ff00::/8", "::1/128", "::/128")]


# ---------------------------------------------------------------- packets

class Pkt:
    __slots__ = ("dport", "dst", "itype", "proto", "sport", "src", "ttl", "ver")

    def __init__(self, ver, src, dst, proto, sport=None, dport=None, itype=None, ttl=None):
        self.ver, self.src, self.dst, self.proto = ver, src, dst, proto
        self.sport, self.dport, self.itype, self.ttl = sport, dport, itype, ttl

    def where(self):
        name = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp6"}.get(self.proto, f"proto{self.proto}")
        return f"{self.dst} {name}/{self.dport if self.dport is not None else self.itype}"


def parse_ip(b):
    """IPv4/IPv6 packet -> Pkt, or None."""
    if len(b) < 1:
        return None
    ver = b[0] >> 4
    if ver == 4 and len(b) >= 20:
        ihl = (b[0] & 15) * 4
        proto, frag = b[9], struct.unpack_from("!H", b, 6)[0] & 0x1FFF
        p = Pkt(4, socket.inet_ntop(socket.AF_INET, b[12:16]), socket.inet_ntop(socket.AF_INET, b[16:20]), proto, ttl=b[8])
        off = ihl
        if frag:
            return p
    elif ver == 6 and len(b) >= 40:
        nh, off = b[6], 40
        src, dst = socket.inet_ntop(socket.AF_INET6, b[8:24]), socket.inet_ntop(socket.AF_INET6, b[24:40])
        while nh in (0, 43, 44, 51, 60) and len(b) >= off + 8:
            if nh == 44:
                if struct.unpack_from("!H", b, off + 2)[0] & 0xFFF8:
                    return Pkt(6, src, dst, b[off], ttl=b[7])
                nxt, ln = b[off], 8
            elif nh == 51:
                nxt, ln = b[off], (b[off + 1] + 2) * 4
            else:
                nxt, ln = b[off], (b[off + 1] + 1) * 8
            nh, off = nxt, off + ln
        p, proto = Pkt(6, src, dst, nh, ttl=b[7]), nh
    else:
        return None
    if proto in (6, 17) and len(b) >= off + 4:
        p.sport, p.dport = struct.unpack_from("!HH", b, off)
    elif proto in (1, 58) and len(b) > off:
        p.itype = b[off]
    return p


def parse_frame(data, linktype):
    """A captured frame -> Pkt, or None for ARP and anything that is not IP."""
    if linktype == 1:                       # Ethernet
        if len(data) < 14:
            return None
        etype, off = struct.unpack_from("!H", data, 12)[0], 14
        while etype in (0x8100, 0x88A8) and len(data) >= off + 4:
            etype, off = struct.unpack_from("!H", data, off + 2)[0], off + 4
        return parse_ip(data[off:]) if etype in (0x0800, 0x86DD) else None
    if linktype in (12, 14, 101):           # raw IP
        return parse_ip(data)
    if linktype == 113 and len(data) >= 16:  # Linux cooked
        return parse_ip(data[16:]) if struct.unpack_from("!H", data, 14)[0] in (0x0800, 0x86DD) else None
    if linktype == 0 and len(data) >= 4:    # BSD loopback/null
        return parse_ip(data[4:])
    return None


def is_lan(addr):
    try:
        a = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(a.version == n.version and a in n for n in _LAN)


def forwarded(ttl):
    """A packet this computer forwarded for a VM or WSL: one hop already used - 63 (Linux, macOS guests) or 127 (Windows
    guests). What the computer sends itself leaves with 64, 128 or 255."""
    return ttl in (63, 127)


def classify(p, servers):
    """'server' | 'ignore' | 'dns' | 'lan' | 'leak' (sent by the computer itself) | 'vmleak' (forwarded for a VM or WSL)
    for an outbound packet on the physical adapter."""
    if p is None:
        return "ignore"
    if p.dst in servers:
        return "server"
    if p.proto == 17 and (p.dport in (67, 68, 546, 547) or p.sport in (67, 68, 546, 547)):
        return "ignore"                     # DHCP
    if p.proto == 58 and p.itype in (130, 131, 132, 133, 134, 135, 136, 137, 143):
        return "ignore"                     # neighbour discovery, router solicitation, MLD
    if p.proto in (6, 17) and p.dport in (53, 853):
        return "dns"
    if is_lan(p.dst):
        return "lan"
    return "vmleak" if forwarded(p.ttl) else "leak"


def read_pcap_stream(f, emit):
    """Read a classic pcap stream (tcpdump -w -) and call emit(ts, linktype, frame) per record."""
    hdr = _read_exact(f, 24)
    if not hdr:
        return
    magic = hdr[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = ">"
    else:
        raise ValueError("not a pcap stream")
    div = 1e9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
    linktype = struct.unpack(e + "I", hdr[20:24])[0] & 0xFFFF
    while True:
        rec = _read_exact(f, 16)
        if not rec:
            return
        sec, frac, incl, _ = struct.unpack(e + "IIII", rec)
        data = _read_exact(f, incl)
        if data is None:
            return
        emit(sec + frac / div, linktype, data)


def _read_exact(f, n):
    buf = b""
    while len(buf) < n:
        chunk = f.read(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


# ---------------------------------------------------------------- capture

class Capture:
    """Records every outbound IP packet on the physical adapters for the whole run."""

    def __init__(self, ifaces):
        self.ifaces = ifaces
        self.pkts, self.frames, self.lock = [], 0, threading.Lock()
        self.stop_ev, self.threads, self.procs = threading.Event(), [], []

    def add(self, ts, iface, linktype, frame, outgoing):
        if outgoing is None:                # no direction from the OS: our own MAC as sender means outbound
            outgoing = linktype == 1 and iface["mac"] is not None and frame[6:12] == iface["mac"]
        if not outgoing:
            return
        p = parse_frame(frame, linktype)
        with self.lock:
            self.frames += 1
            if p is not None and len(self.pkts) < 500000:
                self.pkts.append((ts, iface["name"], p))

    def start(self):
        for i in self.ifaces:
            t = threading.Thread(target=self._linux if IS_LINUX else self._mac, args=(i,), daemon=True)
            t.start()
            self.threads.append(t)
        time.sleep(0.5)

    def stop(self):
        self.stop_ev.set()
        for p in self.procs:
            if p.poll() is None:
                p.terminate()
        for t in self.threads:
            t.join(2)

    def window(self, t0, t1):
        with self.lock:
            return [x for x in self.pkts if t0 <= x[0] <= t1]

    def _linux(self, iface):
        while not self.stop_ev.is_set():
            try:
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
                s.bind((iface["name"], 0))
                s.settimeout(0.2)
            except OSError:
                time.sleep(0.2)
                continue
            while not self.stop_ev.is_set():
                try:
                    data, addr = s.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if addr[2] != 4:            # PACKET_OUTGOING
                    continue
                lt = 1 if addr[3] == 1 else 101 if addr[3] in (512, 65534, 776, 778) else None
                if lt is not None:
                    self.add(time.time(), iface, lt, data, True)
            s.close()

    def _mac(self, iface):
        while not self.stop_ev.is_set():
            p = subprocess.Popen(["tcpdump", "-i", iface["name"], "-n", "-U", "-s", "200", "-w", "-"],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            self.procs.append(p)
            try:
                read_pcap_stream(p.stdout, lambda ts, lt, fr: self.add(ts, iface, lt, fr, None))
            except (OSError, ValueError):
                pass
            if p.poll() is None:
                p.terminate()
            time.sleep(0.3)                 # the adapter went down: start again when it is back


# ---------------------------------------------------------------- shell helpers

def run(argv, inp=None, check=False):
    r = subprocess.run(argv, input=inp, capture_output=True, text=True, check=False)
    if check and r.returncode != 0:
        raise RuntimeError("{} failed: {}".format(" ".join(argv), r.stderr.strip()))
    return r


def run_json(argv):
    r = run(argv)
    try:
        return json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else []
    except ValueError:
        return []


UNDO_FAILED = []


class Journal:
    """Every change is written down before it is made, so --restore can undo an interrupted run."""

    def __init__(self, path):
        self.path, self.items = path, []

    def __len__(self):
        return len(self.items)

    def add(self, desc, undo):
        self.items.append({"desc": desc, "undo": undo, "done": False})
        self._save()
        print(f"      + change: {desc}", flush=True)

    def undo_last(self):
        for it in reversed(self.items):
            if not it["done"]:
                self._undo(it)
                return

    def undo_since(self, mark):
        for it in reversed(self.items[mark:]):
            if not it["done"]:
                self._undo(it)

    def undo_all(self):
        for it in reversed(self.items):
            if not it["done"]:
                self._undo(it)

    def _undo(self, it):
        ok = True
        for argv in it["undo"]:
            r = run(argv)
            if r.returncode != 0:
                ok = False
                print(f"      ! COULD NOT UNDO '{it['desc']}': {' '.join(argv)} -> {r.stderr.strip()}", flush=True)
                UNDO_FAILED.append(" ".join(argv))
        it["done"] = True
        self._save()
        if ok:
            print(f"      - undone: {it['desc']}", flush=True)

    @staticmethod
    def pending(path):
        try:
            with open(path) as f:
                return [it for it in json.load(f) if not it["done"]]
        except (OSError, ValueError):
            return []

    def _save(self):
        with open(self.path, "w") as f:
            json.dump(self.items, f, indent=1)

    @staticmethod
    def restore(path):
        if not os.path.exists(path):
            print(f"Nothing to restore ({path} not found).")
            return
        with open(path) as f:
            j = Journal(path)
            j.items = json.load(f)
        pending = [it for it in j.items if not it["done"]]
        for it in reversed(pending):
            j._undo(it)
        print(f"Restored {len(pending)} change(s).")
        if UNDO_FAILED:
            print("Some commands failed - check the lines marked '!' above (a rule may already be gone).")


# ---------------------------------------------------------------- platforms

class Linux:
    name = "Linux"

    def check_tools(self):
        if not shutil.which("ip"):
            return "the 'ip' command (iproute2) is missing"
        return None

    def physical(self):
        links = {lk["ifname"]: lk for lk in run_json(["ip", "-j", "-d", "link", "show"])}
        tunnel_kinds = {"tun", "wireguard", "dummy", "vxlan", "gre", "ipip", "sit", "ip6tnl"}

        def ok(n):
            lk = links.get(n, {})
            kind = (lk.get("linkinfo") or {}).get("info_kind")
            return lk.get("link_type") == "ether" and kind not in tunnel_kinds
        names = []
        for fam in ("-4", "-6"):
            for r in run_json(["ip", "-j", fam, "route", "show", "default"]):
                if r.get("dev") and r.get("gateway") and ok(r["dev"]) and r["dev"] not in names:
                    names.append(r["dev"])
        return [self.iface(n) for n in names]

    def iface(self, n):
        info = run_json(["ip", "-j", "addr", "show", "dev", n])
        a = info[0] if info else {}
        mac = a.get("address")
        v4 = [x["local"] for x in a.get("addr_info", []) if x.get("family") == "inet"]
        v6 = [x["local"] for x in a.get("addr_info", []) if x.get("family") == "inet6" and x.get("scope") == "global"]
        return {"name": n, "mac": bytes.fromhex(mac.replace(":", "")) if mac else None, "v4": v4, "v6": v6}

    def route_iface(self, dst):
        fam = "-6" if ":" in dst else "-4"
        r = run_json(["ip", "-j", fam, "route", "get", dst])
        return r[0].get("dev") if r and r[0].get("type", "unicast") == "unicast" else None

    def _fw(self):
        return "iptables" if shutil.which("iptables") else "nft" if shutil.which("nft") else None

    def block_servers(self, j, servers):
        fw = self._fw()
        if fw is None:
            return "neither iptables nor nft is installed"
        if fw == "nft":
            return self._nft(j, "ksbench_block", servers, "drop", "block the VPN server")
        do, undo = [], []
        for ip in sorted(servers):
            tool = "ip6tables" if ":" in ip else "iptables"
            if shutil.which(tool):
                for chain, flag in (("OUTPUT", "-d"), ("INPUT", "-s")):
                    do.append([tool, "-w", "-I", chain, "1", flag, ip, "-j", "DROP"])
                    undo.append([tool, "-w", "-D", chain, flag, ip, "-j", "DROP"])
        return self._iptables(j, "firewall rule: block the VPN server " + ", ".join(sorted(servers)), do, undo)

    def allow_probes(self, j):
        fw = self._fw()
        if fw is None:
            return "neither iptables nor nft is installed"
        if fw == "nft":
            return self._nft(j, "ksbench_allow", ALLOW_NETS, "accept", "allow the probe addresses")
        do, undo = [], []
        for net in ALLOW_NETS:
            tool = "ip6tables" if ":" in net else "iptables"
            if shutil.which(tool):
                do.append([tool, "-w", "-I", "OUTPUT", "1", "-d", net, "-j", "ACCEPT"])
                undo.append([tool, "-w", "-D", "OUTPUT", "-d", net, "-j", "ACCEPT"])
        return self._iptables(j, "firewall rule: allow " + ", ".join(ALLOW_NETS), do, undo)

    @staticmethod
    def _iptables(j, desc, do, undo):
        j.add(desc, undo)                   # written down first: an undo of a rule that never got in only fails
        for argv in do:
            run(argv, check=True)

    def _nft(self, j, table, addrs, verdict, desc):
        lines = [f"table inet {table} {{",
                 "  chain out { type filter hook output priority -400; policy accept;"]
        for a in addrs:
            lines.append("    {} daddr {} {}".format("ip6" if ":" in a else "ip", a, verdict))
        lines.append("  }")
        if verdict == "drop":
            lines.append("  chain inp { type filter hook input priority -400; policy accept;")
            for a in addrs:
                lines.append("    {} saddr {} drop".format("ip6" if ":" in a else "ip", a))
            lines.append("  }")
        lines.append("}")
        j.add(f"nft table {table}: {desc}", [["nft", "delete", "table", "inet", table]])
        run(["nft", "-f", "-"], inp="\n".join(lines) + "\n", check=True)

    def link(self, j, name, up):
        if not up:
            j.add(f"adapter {name} down", [["ip", "link", "set", "dev", name, "up"]])
            run(["ip", "link", "set", "dev", name, "down"], check=True)
        else:
            j.undo_last()

    def conn_pids(self, servers, lports):
        out, r = {}, run(["ss", "-Htunap"])
        for line in r.stdout.splitlines():
            f = line.split()
            if len(f) < 6:
                continue
            local, peer = _host_port(f[4]), _host_port(f[5])
            if peer[0] in servers or local[1] in lports:
                for name, pid in re.findall(r'\("([^"]+)",pid=(\d+)', line):
                    out[int(pid)] = name
        return out

    @staticmethod
    def vm_present():
        """Bridges VMs and containers sit behind (Docker, libvirt, LXD, VirtualBox host-only, VMware)."""
        try:
            names = os.listdir("/sys/class/net")
        except OSError:
            return False
        return any(n.startswith(("docker", "br-", "virbr", "lxdbr", "vboxnet", "vmnet", "podman", "cni")) for n in names)

    def os_desc(self):
        try:
            with open("/etc/os-release") as f:
                m = re.search(r'^PRETTY_NAME="?([^"\n]+)', f.read(), re.MULTILINE)
                return m.group(1) if m else "Linux"
        except OSError:
            return "Linux " + platform.release()


class Mac:
    name = "macOS"

    def check_tools(self):
        for t in ("tcpdump", "pfctl", "route", "ifconfig", "lsof"):
            if not shutil.which(t):
                return f"the '{t}' command is missing"
        return None

    def physical(self):
        names = []
        for fam in ([], ["-inet6"]):
            m = re.search(r"interface:\s*(\S+)", run(["route", "-n", "get"] + fam + ["default"]).stdout)
            if m and not re.match(r"(utun|ipsec|ppp|tun|tap|gif|stf|lo)", m.group(1)) and m.group(1) not in names:
                names.append(m.group(1))
        return [self.iface(n) for n in names]

    def iface(self, n):
        out = run(["ifconfig", n]).stdout
        m = re.search(r"ether\s+([0-9a-f:]{17})", out)
        v4 = re.findall(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out)
        v6 = [a.split("%")[0] for a in re.findall(r"inet6\s+(\S+)", out) if not a.lower().startswith("fe80")]
        return {"name": n, "mac": bytes.fromhex(m.group(1).replace(":", "")) if m else None, "v4": v4, "v6": v6}

    def route_iface(self, dst):
        fam = ["-inet6"] if ":" in dst else []
        m = re.search(r"interface:\s*(\S+)", run(["route", "-n", "get"] + fam + [dst]).stdout)
        return m.group(1) if m else None

    def _pf(self, j, rules, desc):
        if 'anchor "com.apple/*"' not in run(["pfctl", "-sr"]).stdout:
            return "the main pf ruleset has no com.apple anchor, so the bench cannot add a rule"
        e = run(["pfctl", "-E"])
        tok = re.search(r"Token\s*:\s*(\d+)", e.stderr + e.stdout)
        undo = [["pfctl", "-a", "com.apple/ksbench", "-F", "all"]]
        if tok:
            undo.append(["pfctl", "-X", tok.group(1)])
        old = run(["pfctl", "-a", "com.apple/ksbench", "-sr"]).stdout
        j.add("pf anchor com.apple/ksbench: " + desc, undo)
        run(["pfctl", "-a", "com.apple/ksbench", "-f", "-"], inp=old + rules, check=True)
        return None

    def block_servers(self, j, servers):
        lst = ", ".join(sorted(servers))
        return self._pf(j, f"block drop out quick to {{ {lst} }}\nblock drop in quick from {{ {lst} }}\n",
                        "block the VPN server")

    def allow_probes(self, j):
        return self._pf(j, "pass out quick to {{ {} }}\n".format(", ".join(ALLOW_NETS)), "allow the probe addresses")

    def link(self, j, name, up):
        if not up:
            j.add(f"adapter {name} down", [["ifconfig", name, "up"]])
            run(["ifconfig", name, "down"], check=True)
        else:
            j.undo_last()

    def conn_pids(self, servers, lports):
        out, sel = {}, ["-i@" + s for s in servers] + [f"-i:{p}" for p in lports]
        for s in sel:
            for line in run(["lsof", "-nP", s]).stdout.splitlines()[1:]:
                f = line.split()
                if len(f) > 1 and f[1].isdigit():
                    out[int(f[1])] = f[0]
        return out

    @staticmethod
    def vm_present():
        """The vmnet bridge NAT-mode VMs sit behind (Parallels, VMware Fusion, UTM, Lima: bridge100 and up)."""
        return any(n.startswith(("bridge1", "vmenet", "vmnet")) for n in run(["ifconfig", "-l"]).stdout.split())

    def os_desc(self):
        return "macOS " + platform.mac_ver()[0]


def _host_port(s):
    host, _, port = s.rpartition(":")
    host = host.strip("[]").split("%")[0]
    host = host.removeprefix("::ffff:")
    return host, int(port) if port.isdigit() else None


# ---------------------------------------------------------------- probes

def _send(fam, typ, dst, port, data=b"ksbench", bind=None, keep=None):
    try:
        s = socket.socket(fam, typ)
        if bind:
            _bind_iface(s, bind, fam == socket.AF_INET6)
        if typ == socket.SOCK_DGRAM:
            s.sendto(data, (dst, port))
            s.close()
        else:
            s.setblocking(False)
            s.connect_ex((dst, port))
            if keep is not None:
                keep.append((time.time(), s))
            else:
                time.sleep(0.05)
                s.close()
    except OSError:
        pass


def _bind_iface(s, name, v6):
    if IS_LINUX:
        s.setsockopt(socket.SOL_SOCKET, 25, name.encode() + b"\0")      # SO_BINDTODEVICE
    else:
        idx = struct.pack("I", socket.if_nametoindex(name))
        s.setsockopt(socket.IPPROTO_IPV6 if v6 else socket.IPPROTO_IP, 125 if v6 else 25, idx)  # *_BOUND_IF


def udp(dst, port, data=b"ksbench", bind=None):
    _send(socket.AF_INET6 if ":" in dst else socket.AF_INET, socket.SOCK_DGRAM, dst, port, data, bind)


def tcp(dst, port, bind=None, keep=None):
    _send(socket.AF_INET6 if ":" in dst else socket.AF_INET, socket.SOCK_STREAM, dst, port, bind=bind, keep=keep)


def ping(dst, seq=1):
    v6 = ":" in dst
    try:
        s = socket.socket(socket.AF_INET6 if v6 else socket.AF_INET, socket.SOCK_RAW,
                          socket.IPPROTO_ICMPV6 if v6 else socket.IPPROTO_ICMP)
        body = struct.pack("!BBHHH", 128 if v6 else 8, 0, 0, os.getpid() & 0xFFFF, seq) + b"ksbench"
        if not v6:
            body = body[:2] + struct.pack("!H", _csum(body)) + body[4:]
        s.sendto(body, (dst, 0))
        s.close()
    except OSError:
        pass


def _csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def unique_name():
    return "ksb-{}.example.com".format("".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(12)))


def dns_packet(name):
    q = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", random.randint(0, 65535), 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def system_lookup(name):
    def go():
        try:
            socket.getaddrinfo(name, 443)
        except OSError:
            pass
    threading.Thread(target=go, daemon=True).start()


def online_ip(url, timeout=1.5):
    """The address Cloudflare sees us coming from, or None (no answer)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                         urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(url, timeout=timeout) as r:
            m = re.search(r"^ip=(\S+)$", r.read(4096).decode("ascii", "replace"), re.MULTILINE)
            return m.group(1) if m else None
    except Exception:                       # noqa: BLE001 - any failure means "no answer"
        return None


# ---------------------------------------------------------------- the bench

def ask(question, default, interactive):
    if not interactive:
        return default
    try:
        a = input(question).strip().lower()
    except EOFError:
        return default
    return default if not a else a.startswith("y")


class Bench:
    def __init__(self, args, plat):
        self.a, self.p = args, plat
        self.interactive = sys.stdin.isatty() and not args.yes
        self.res = {sid: {"status": "not run", "detail": ""} for sid, _, _, _ in SCENARIOS}
        tmp = os.path.join(tempfile.gettempdir(), "ksbench")
        os.makedirs(tmp, mode=0o700, exist_ok=True)
        self.tmp = tmp
        self.j = Journal(os.path.join(tmp, "journal.json"))
        self.servers = {}                   # ip -> (proto, port)
        self.vpn_ips, self.online, self.online_hits = set(), False, []
        self.outage_windows, self.keep = [], []
        self.dns_windows, self.manual_at = [], None    # D5: tests that took the tunnel down, until the bench asked for help
        self.stopped = False

    # -- helpers
    def say(self, msg):
        print(msg, flush=True)

    def tunnel_iface(self):
        dev = self.p.route_iface(P_OUT4)
        return dev if dev and dev not in self.phys_names else None

    def tunnel_up(self):
        return self.tunnel_iface() is not None

    def has_v6(self):
        return any(i["v6"] for i in self.phys)

    def set(self, sid, status, detail="", **ev):
        self.res[sid] = dict(status=status, detail=detail, **ev)
        self.say(f"  {sid}  {status.upper():<7} {self.title(sid)}" + (f" - {detail}" if detail else ""))

    @staticmethod
    def title(sid):
        return next(t for s, _, _, t in SCENARIOS if s == sid)

    def wanted(self, sid):
        return not self.a.only or sid in self.a.only

    # -- online check
    def online_tick(self, label):
        def go():
            for url in (ONLINE4, ONLINE6) if self.has_v6() else (ONLINE4,):
                ip = online_ip(url)
                if ip is None:
                    continue
                if self.tunnel_up():        # answered through the tunnel: a VPN exit address
                    self.vpn_ips.add(ip)
                elif ip not in self.vpn_ips:
                    self.online_hits.append({"scenario": label, "ip": ip, "t": time.time()})
        if self.online:
            threading.Thread(target=go, daemon=True).start()

    # -- server detection
    def find_servers(self, seconds=3.0, same_port_only=False):
        t0 = time.time()
        while time.time() - t0 < seconds:
            for port in (443, 53000, 3478):
                udp(P_SERVERS, port, b"x" * 400)
            tcp(P_SERVERS, 443)
            time.sleep(0.1)
        time.sleep(0.5)
        count = {}
        for _, _, p in self.cap.window(t0, time.time()):
            if classify(p, {}) != "leak" or p.dst.startswith("198.51.100.") or p.dst.lower().startswith("2001:db8"):
                continue
            k = (p.dst, p.proto, p.dport)
            count[k] = count.get(k, 0) + 1
        found = sorted(count.items(), key=lambda kv: -kv[1])
        if same_port_only:
            ports = {(pr, po) for pr, po in self.servers.values()}
            return {ip: (pr, po) for (ip, pr, po), n in found if (pr, po) in ports and n >= 5}
        return found

    def outer_lports(self):
        ports = set()
        for _, _, p in self.cap.window(0, time.time()):
            if p.dst in self.servers and p.sport:
                ports.add(p.sport)
        return ports

    # -- probing during outages
    def probe_until(self, deadline, label, until=None):
        last_dns = last_online = last_check = 0.0
        ok_since = None
        while time.time() < deadline:
            now = time.time()
            udp(P_OUT4, 443)
            tcp(P_OUT4, 443, keep=self.keep)
            if self.has_v6():
                udp(P_OUT6, 443)
            if now - last_dns >= 2:
                system_lookup(unique_name())
                udp(P_DNS4, 53, dns_packet(unique_name()))
                last_dns = now
            if now - last_online >= 2:
                self.online_tick(label)
                last_online = now
            while self.keep and now - self.keep[0][0] > 1.0:
                self.keep.pop(0)[1].close()
            if until is not None and now - last_check >= 1:
                last_check = now
                if until != self.tunnel_up and until():
                    return True
                if until == self.tunnel_up and until():
                    ok_since = ok_since or now
                    if now - ok_since >= 3:
                        return True
                else:
                    ok_since = None
            time.sleep(0.25)
        return until is None

    def wait_recovery(self, label):
        """Keep probing while the product reconnects; leaks right at reconnect count."""
        back = self.probe_until(time.time() + self.a.recover, label, until=self.tunnel_up)
        self.manual_at = None
        while not back and self.interactive:
            self.manual_at = self.manual_at or time.time()     # from here on the user acts - D5 stops counting
            if not ask("  The VPN is not back. Reconnect it (or restart the app), then press Enter "
                       "(n = stop the bench) [Y/n] ", True, True):
                break
            back = self.probe_until(time.time() + 30, label, until=self.tunnel_up)
        if back:
            self.probe_until(time.time() + 1.5, label)
            new = self.find_servers(1.5, same_port_only=True)
            self.servers.update(new)
            for _ in range(3):
                self.online_tick(None)
        return back

    def vmleaks(self, t0, t1):
        return [(ts, p) for ts, _, p in self.cap.window(t0, t1) if classify(p, self.servers) == "vmleak"]

    def leaks(self, t0, t1):
        leak, dns = [], []
        for ts, _, p in self.cap.window(t0, t1):
            c = classify(p, self.servers)
            if c == "leak":
                leak.append((ts, p))
            elif c == "dns":
                dns.append((ts, p))
        return leak, dns

    @staticmethod
    def evidence(items, t0):
        if not items:
            return {}
        items = sorted(items, key=lambda x: x[0])
        dst = {}
        for _, p in items:
            dst[p.where()] = dst.get(p.where(), 0) + 1
        top = sorted(dst.items(), key=lambda kv: -kv[1])[:5]
        return {"packets": len(items), "first_ms": int((items[0][0] - t0) * 1000),
                "last_ms": int((items[-1][0] - t0) * 1000), "to": [f"{d} ({n})" for d, n in top]}

    def fits(self, seconds):
        return time.time() + seconds <= self.deadline

    def outage(self, sid, inject, restore, hold, until_down=False):
        """until_down: the fault stays until the tunnel goes down (+5 s), at most `hold` s; else exactly `hold` s."""
        if not self.fits(min(hold, FAULT) + 20):
            self.set(sid, "not run", f"the {BUDGET // 60}-minute limit for the outage tests was reached")
            return
        if not self.tunnel_up():
            self.say(f"  {sid}  waiting up to 15 s for the VPN to be connected...")
            if not self.probe_until(time.time() + 15, None, until=self.tunnel_up):
                self.set(sid, "not run", "the VPN was not connected when the test started")
                return
        self.say(f"  {sid}  running... {self.title(sid)}")
        mark = len(self.j)
        t0 = time.time()
        try:
            why = inject()
        except (RuntimeError, OSError) as e:
            why = f"the bench could not make the change ({e})"
        if why:
            self.j.undo_since(mark)
            self.set(sid, "n/a", why)
            return
        watching = ", ".join(sorted(self.phys_names))
        if until_down:
            self.say(f"      fault active until the tunnel goes down (at most {hold} s) - sending test traffic, watching {watching}")
        else:
            self.say(f"      fault active for {hold} s - sending test traffic, watching {watching}")
        went_down = [None]

        def watch():
            if went_down[0] is None and not self.tunnel_up():
                went_down[0] = time.time()
                self.say(f"      the tunnel went down after {went_down[0] - t0:.0f} s")
            return until_down and went_down[0] is not None and time.time() - went_down[0] >= 5
        self.probe_until(t0 + hold, sid, until=watch)
        went_down[0] = went_down[0] is not None
        restore()
        self.say(f"      waiting for the VPN to come back (up to {self.a.recover} s), still watching for leaks...")
        t_wait = time.time()
        back = self.wait_recovery(sid)
        self.say(f"      VPN is back after {time.time() - t_wait:.0f} s" if back else "      the VPN did not come back")
        self.j.undo_since(mark)             # whatever this test still holds (T1's allow rule) goes now, not at the end
        t1 = time.time()
        self.outage_windows.append((t0, t1))
        leak, dns = self.leaks(t0, t1)
        if went_down[0] or leak:            # D5 only where the test really tested something
            self.dns_windows.append((t0, self.manual_at or t1))
        hits = [h for h in self.online_hits if h["scenario"] == sid]
        ev = {"tunnel_went_down": went_down[0], "recovered": back, "leak": self.evidence(leak, t0),
              "dns": self.evidence(dns, t0), "online": hits}
        if not leak and not went_down[0]:
            self.set(sid, "n/a", f"the tunnel stayed up for all {hold} s of the fault, so the kill-switch was not "
                     "tested (nothing could leak); a longer --hold may help", **ev)
        elif leak:
            e = ev["leak"]
            self.set(sid, "fail", f"{e['packets']} packets leaked, first {e['first_ms'] / 1000:.1f} s after the fault, "
                     f"to {', '.join(e['to'][:3])}", **ev)
        elif hits:
            self.set(sid, "invalid", "the online check saw your real IP but the capture did not - "
                     "traffic left through an adapter the bench does not watch (use --iface)", **ev)
        else:
            self.set(sid, "pass", "the tunnel went down and nothing leaked", **ev)
        if not back:
            self.stopped = True

    # -- scenarios
    def steady(self):
        self.steady_window = (time.time(), None)
        tun = self.tunnel_iface()
        if self.wanted("S1"):
            self.say("  S1  running... 3 DNS look-ups through the system resolver + direct DNS queries")
            t0 = time.time()
            for _ in range(2):
                system_lookup(unique_name())
                udp(P_DNS4, 53, dns_packet(unique_name()))
                tcp(P_DNS4, 53)
                if self.has_v6():
                    udp(P_DNS6, 53, dns_packet(unique_name()))
                time.sleep(1)
            time.sleep(1.0)
            _, dns = self.leaks(t0, time.time())
            ev = self.evidence(dns, t0)
            self.set("S1", "fail" if dns else "pass",
                     f"{ev['packets']} DNS packets went out of the tunnel to {', '.join(ev['to'])}"
                     if dns else "", dns=ev)
        if self.wanted("S2"):
            if not self.has_v6():
                self.set("S2", "n/a", "this network has no IPv6, so IPv6 cannot leak here")
            else:
                self.say("  S2  running... UDP, TCP and ping over IPv6")
                t0 = time.time()
                for _ in range(2):
                    udp(P_V6, 443)
                    tcp(P_V6, 443)
                    ping(P_V6)
                    time.sleep(1)
                time.sleep(1.0)
                leak = [(ts, p) for ts, p in self.leaks(t0, time.time())[0] if p.ver == 6]
                ev = self.evidence(leak, t0)
                self.set("S2", "fail" if leak else "pass",
                         f"{ev['packets']} IPv6 packets bypassed the tunnel" if leak else "", leak=ev)
        if self.wanted("S3"):
            self.say("  S3  running... UDP and TCP from sockets bound to " + ", ".join(sorted(self.phys_names)))
            t0 = time.time()
            for _ in range(2):
                for i in self.phys:
                    udp(P_BOUND4, 443, bind=i["name"])
                    tcp(P_BOUND4, 443, bind=i["name"])
                    if i["v6"]:
                        udp(P_BOUND6, 443, bind=i["name"])
                        tcp(P_BOUND6, 443, bind=i["name"])
                time.sleep(1)
            time.sleep(1.0)
            leak = [(ts, p) for ts, p in self.leaks(t0, time.time())[0] if p.dst in (P_BOUND4, P_BOUND6)]
            ev = self.evidence(leak, t0)
            self.set("S3", "fail" if leak else "pass",
                     f"{ev['packets']} packets got out next to the tunnel (the kill-switch only changes routes)"
                     if leak else "", leak=ev)
        if self.wanted("S4"):
            self.say("  S4  running... a QUIC-sized UDP packet, a STUN request and a ping")
            t0 = time.time()
            for k in range(2):
                udp(P_MISC4, 443, b"\xc0" + b"q" * 1199)       # QUIC-sized
                udp(P_MISC4, 3478, b"\x00\x01\x00\x00\x21\x12\xa4\x42" + os.urandom(12))  # STUN binding
                ping(P_MISC4, k + 1)
                time.sleep(1)
            time.sleep(1.0)
            leak = [(ts, p) for ts, p in self.leaks(t0, time.time())[0] if p.dst == P_MISC4]
            ev = self.evidence(leak, t0)
            self.set("S4", "fail" if leak else "pass",
                     f"{ev['packets']} packets bypassed the tunnel" if leak else "", leak=ev)
        self.steady_window = (self.steady_window[0], time.time())
        self.say(f"  (tunnel adapter: {tun})")

    def adapter_ok(self, sid, name):
        """Over SSH, taking the adapter down may cut the session: ask once (no = skip D4, T1, T2)."""
        if not os.environ.get("SSH_CONNECTION"):
            return True
        if self.ssh_ok is None:
            self.ssh_ok = ask(f"  You are connected over SSH: D4, T1 and T2 take {name} down for {FAULT} s and this "
                              "session may drop. Run them anyway? [y/N] ", False, self.interactive)
        if not self.ssh_ok:
            self.set(sid, "skipped", "running over SSH - taking the adapter down could cut the session")
        return self.ssh_ok

    def disruptive(self):
        hold = self.a.hold
        self.deadline = time.time() + BUDGET
        self.ssh_ok = None
        servers = set(self.servers)
        name = self.phys[0]["name"]

        def adapter_off():
            return self.p.link(self.j, name, False)
        if self.wanted("D1") and not self.stopped:
            self.outage("D1", lambda: self.p.block_servers(self.j, servers), self.j.undo_last, hold, until_down=True)
        if self.wanted("D3") and not self.stopped:
            tun = self.tunnel_iface() or "none"
            self.outage("D3", lambda: self.p.link(self.j, tun, False), self.j.undo_last, FAULT)
        if self.wanted("D4") and not self.stopped and self.adapter_ok("D4", name):
            self.outage("D4", adapter_off, lambda: self.link_up(name), FAULT)
        if self.wanted("T1") and not self.stopped and self.adapter_ok("T1", name):
            def inject():
                return self.p.allow_probes(self.j) or adapter_off()

            def restore():
                self.link_up(name)          # the adapter first, the allow rule stays while the VPN comes back
            self.outage("T1", inject, restore, FAULT)
        if self.wanted("D2") and not self.stopped:
            pids = {p: n for p, n in self.p.conn_pids(servers, self.outer_lports()).items()
                    if p > 1 and p != os.getpid() and n.lower() not in NEVER_KILL}
            if not pids:
                self.set("D2", "n/a", "no user process owns the VPN connection (the VPN runs in the kernel "
                         "or in a system service) - nothing to kill safely")
            elif not self.fits(FAULT + 20):
                self.set("D2", "not run", f"the {BUDGET // 60}-minute limit for the outage tests was reached")
            else:
                desc = ", ".join(f"{n} (pid {p})" for p, n in sorted(pids.items()))
                if ask(f"  D2 will kill the VPN client process {desc}. OK? [y/N] ", False, self.interactive) \
                        or self.a.yes:
                    self.outage("D2", lambda: self._kill(pids), lambda: None, hold, until_down=True)
                else:
                    self.set("D2", "skipped", "you chose not to kill " + desc)
        if self.wanted("T2") and not self.stopped:
            pname = self.a.app_process                    # an expert's option: no question - nobody knows that name
            if not pname:
                self.set("T2", "n/a", "an expert test: run it by naming the kill-switch app's process with --app-process")
            elif not self.fits(FAULT + 20):
                self.set("T2", "not run", f"the {BUDGET // 60}-minute limit for the outage tests was reached")
            else:
                pids = {int(x): pname for x in run(["pgrep", "-x", pname]).stdout.split()}
                pids = {p: n for p, n in pids.items() if p > 1 and p != os.getpid() and n.lower() not in NEVER_KILL}
                if not pids:
                    self.set("T2", "skipped", f"no running process named {pname}")
                elif self.adapter_ok("T2", name):
                    def inject2():
                        self._kill(pids)
                        time.sleep(1)
                        return adapter_off()
                    self.outage("T2", inject2, lambda: self.link_up(name), FAULT)
        windows = self.outage_windows
        if self.wanted("D5"):
            if not self.dns_windows:
                self.set("D5", "n/a", "no outage test took the tunnel down")
            else:
                dns = []
                for t0, t1 in self.dns_windows:
                    dns += self.leaks(t0, t1)[1]
                ev = self.evidence(dns, self.dns_windows[0][0]) if dns else {}
                self.set("D5", "fail" if dns else "pass",
                         f"{ev['packets']} DNS packets went out while the VPN was down, to {', '.join(ev['to'][:3])}" if dns else "", dns=ev)
        if self.wanted("V1"):
            spans = list(windows) + ([self.steady_window] if getattr(self, "steady_window", (0, None))[1] else [])
            vm = []
            for t0, t1 in spans:
                vm += self.vmleaks(t0, t1)
            ev = self.evidence(vm, spans[0][0]) if vm else {}
            if vm:
                self.set("V1", "fail", f"{ev['packets']} packets of a VM or WSL went out without the VPN, to "
                         f"{', '.join(ev['to'][:3])}", leak=ev)
            elif not self.p.vm_present():
                self.set("V1", "n/a", "no virtual machines, WSL or containers on this computer")
            elif not windows:
                self.set("V1", "n/a", "no outage test ran")
            else:
                self.set("V1", "pass", "no packet of a VM or WSL went out")

    def _kill(self, pids):
        for p, n in pids.items():
            self.say(f"      + killing {n} (pid {p})")
            try:
                os.kill(p, 9)
            except OSError as e:
                self.say(f"      ! could not kill {n}: {e}")

    def link_up(self, name):
        """Undo 'adapter down' and wait until the adapter has its address again."""
        self.j.undo_last()
        for _ in range(60):
            if self.p.iface(name)["v4"] or self.p.iface(name)["v6"]:
                return
            time.sleep(0.5)
        self.say(f"      ! {name} is up but has no address yet - if it stays offline, turn Wi-Fi/the adapter off and on")

    # -- the run
    def run(self):
        why = self.p.check_tools()
        if why:
            sys.exit("ksbench: " + why)
        if Journal.pending(self.j.path):
            sys.exit("ksbench: an earlier run did not finish undoing its changes. "
                     "Run 'sudo python3 ksbench.py --restore' first.")
        self.say(f"ksbench {VERSION} - VPN kill-switch leak bench ({self.p.os_desc()})")
        product = self.a.product
        if product is None and self.interactive:
            try:
                product = input("Name of the VPN / kill-switch app you are testing (for the report): ").strip()
            except EOFError:
                product = ""
        self.product = product or "unnamed"

        phys = [self.p.iface(n) for n in self.a.iface] if self.a.iface else self.p.physical()
        self.phys = [i for i in phys if i["mac"] is not None or IS_LINUX]
        if not self.phys:
            sys.exit("ksbench: no physical network adapter with a default route found - name it with --iface")
        self.phys_names = {i["name"] for i in self.phys}
        if not self.tunnel_up():
            sys.exit("ksbench: the VPN does not seem to be connected (traffic to the internet does not go through a "
                     "tunnel adapter). Connect it and run again.")

        self.online = self.a.online
        if self.online is None:
            self.online = ask(ONLINE_PROMPT, True, sys.stdin.isatty()) if sys.stdin.isatty() else False
        self.cap = Capture(self.phys)
        self.cap.start()
        self.t_start = time.time()

        def stop(*_):
            raise KeyboardInterrupt
        for sg in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(sg, stop)
        try:
            self._run_inner()
        except KeyboardInterrupt:
            self.say("\nInterrupted - undoing the bench's changes.")
        finally:
            for sg in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                signal.signal(sg, signal.SIG_IGN)   # never stop half-way through the undo
            if len(self.j):
                self.say("Undoing the bench's changes:")
            self.j.undo_all()
            if UNDO_FAILED:
                self.say("!! Some changes could not be undone (lines marked '!'). Run 'sudo python3 ksbench.py "
                         "--restore', or run the commands shown by hand.")
            self.cap.stop()
            for _, s in self.keep:
                s.close()
        return self.report()

    def _run_inner(self):
        self.say("Watching: {}; tunnel: {}".format(", ".join(sorted(self.phys_names)), self.tunnel_iface()))
        if self.a.server:
            for s in self.a.server:
                for ai in socket.getaddrinfo(s, None):
                    self.servers[ai[4][0].split("%")[0]] = (None, None)
            found = self.find_servers()
            for (ip, pr, po), _ in found:
                if ip in self.servers:
                    self.servers[ip] = (pr, po)
        else:
            found = self.find_servers()
            if not found:
                frames = self.cap.frames
                sys.exit(f"ksbench: saw no traffic to a VPN server on {', '.join(self.phys_names)} ({frames} frames "
                         "captured). Name the server with --server and the adapter with --iface.")
            top = found[0][1]
            cand = [k for k, n in found if n >= max(5, top // 5)]
            self.say("VPN server(s) seen on the physical adapter:")
            for ip, pr, po in cand:
                self.say("  {}  {}/{}".format(ip, {6: "tcp", 17: "udp"}.get(pr, pr), po))
            if not ask("Is this your VPN server? [Y/n] ", True, self.interactive):
                sys.exit("ksbench: name the VPN server with --server and run again.")
            for ip, pr, po in cand:
                self.servers[ip] = (pr, po)
        if self.online:
            for _ in range(3):
                self.online_tick(None)
            time.sleep(2.5)
            if not self.vpn_ips:
                self.online = False
                self.say("Online check: no answer from Cloudflare through the VPN - check not available.")
        self.say("\nSteady state (VPN connected):")
        self.steady()
        if any(self.wanted(s) for s, g, _, _ in SCENARIOS if g != "steady"):
            self.say("\n" + DISRUPT_TEXT % (self.a.hold, self.a.recover))
            if os.environ.get("SSH_CONNECTION"):
                self.say("WARNING: you are connected over SSH - D4 takes the network adapter down.")
            if ask("Run the outage and tamper tests? [y/N] ", False, self.interactive) or self.a.yes:
                self.say("\nOutage and tamper tests:")
                self.disruptive()
            else:
                for s, g, _, _ in SCENARIOS:
                    if g != "steady" and self.wanted(s):
                        self.res[s] = {"status": "skipped", "detail": "you chose not to run the outage tests"}

    def report(self):
        tested = [(s, w) for s, _, w, _ in SCENARIOS if self.res[s]["status"] in ("pass", "fail")]
        total = sum(w for _, w in tested)
        got = sum(w for s, w in tested if self.res[s]["status"] == "pass")
        score = round(100.0 * got / total) if total else None
        failed = [s for s, _, _, _ in SCENARIOS if self.res[s]["status"] == "fail"]
        capped = score is not None and score > CAP and any(s in CRITICAL for s in failed)
        if capped:
            score = CAP
        print(f"\n{'ID':<4} {'Result':<8} {'Points':<7} Scenario")
        for s, _, w, t in SCENARIOS:
            r = self.res[s]
            pts = f"{w if r['status'] == 'pass' else 0}/{w}" if r["status"] in ("pass", "fail") else "-"
            print(f"{s:<4} {r['status'].upper():<8} {pts:<7} {t}" + (f" - {r['detail']}" if r["detail"] else ""))
        all_w = sum(w for _, _, w, _ in SCENARIOS)
        level, verdict = judge(score, failed, total, all_w)
        print("\n" + "=" * 78)
        ran = sum(1 for s, _, _, _ in SCENARIOS if self.res[s]["status"] in ("pass", "fail"))
        print(f"SCORE: {score if score is not None else '-'} / 100   ({level})   - from the {ran} tests that could run here; "
              f"{len(SCENARIOS) - ran} could not run on this setup and do not count")
        if capped:
            print(f"(capped at {CAP}: a leak in a critical test outweighs the points of the tests that passed)")
        print(verdict)
        if failed:
            print("\nWhat failed means for you:")
            for s in failed:
                print(f"  {s}  {MEANING[s]}")
        if level == "POOR":
            if is_veroscudo(self.product):
                print("\nThis is VeroScudo itself: see what failed above and its README (limits, settings).")
            else:
                print("\n" + RECOMMEND + (" (macOS: alpha)" if IS_MAC else ""))
        el = int(time.time() - self.t_start)
        print(f"Run time: {el // 60} min {el % 60} s")
        print("=" * 78)
        if any(r["status"] == "invalid" for r in self.res.values()):
            print("Results incomplete: the online check saw a leak the capture missed (see INVALID above).")
        real = sorted({h["ip"] for h in self.online_hits})
        if real:
            print("Online check: Cloudflare saw an address other than the VPN's: {}".format(", ".join(real)))
        elif self.online:
            print("Online check: Cloudflare only ever saw the VPN's address ({}).".format(", ".join(sorted(self.vpn_ips))))
        else:
            print("Online check: not run.")
        doc = {"tool": "ksbench", "version": VERSION, "os": self.p.os_desc(), "product": self.product,
               "date": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "score": score, "level": level, "capped": capped,
               "points_tested": total,
               "points_total": all_w, "adapters": sorted(self.phys_names),
               "servers": sorted(self.servers), "online_check": self.online, "online_hits": self.online_hits,
               "vpn_exit_ips": sorted(self.vpn_ips),
               "scenarios": [dict(id=s, group=g, weight=w, title=t, **self.res[s]) for s, g, w, t in SCENARIOS]}
        out = self.a.out or os.path.join(self.tmp, "report-{}.json".format(time.strftime("%Y%m%d-%H%M%S")))
        with open(out, "w") as f:
            json.dump(doc, f, indent=2)
        print("Report: " + out)
        return doc


BUDGET = 240                                # seconds for all outage and tamper tests together
FAULT = 10                                  # seconds an adapter stays down (D3, D4, T1, T2)
CAP = 40
CRITICAL = {"S1", "S2", "S3", "D1", "D2", "D3", "D4", "T1", "T2"}
MEANING = {
    "S1": "the names of the sites you visit go to your internet provider's DNS, even with the VPN on.",
    "S2": "your real IPv6 address is visible to sites, even with the VPN on.",
    "S3": "any program can go around the VPN by choosing the network adapter itself (some apps and malware do).",
    "S4": "some UDP traffic (video calls, QUIC, WebRTC) or ping goes around the VPN.",
    "D1": "when the VPN server stops answering, your traffic goes out without the VPN.",
    "D2": "when the VPN app crashes, your traffic goes out without the VPN.",
    "D3": "when the tunnel drops, your traffic goes out without the VPN.",
    "D4": "after a Wi-Fi or cable drop, traffic gets out before the VPN is back.",
    "D5": "while the VPN reconnects, the names of the sites you visit go to your provider's DNS.",
    "T1": "another program's firewall rule is enough to get around the kill-switch.",
    "T2": "if the kill-switch app is closed or crashes, the protection is gone.",
    "V1": "traffic of your virtual machines or WSL can go out without the VPN when it drops.",
}
RECOMMEND = ("Recommendation: change your kill-switch to one that blocks at the firewall by default.\n"
             "VeroScudo - free and open source, from the authors of this bench: https://github.com/GomelHawk/VeroScudo\n"
             "Run this bench again with it to compare.")


def is_veroscudo(product):
    """The product under test is VeroScudo (by its name, or installed here) - the bench never recommends it to itself."""
    return "veroscudo" in (product or "").lower() or os.path.isdir("/opt/veroscudo")


def judge(score, failed, tested, total):
    """(level, plain-language verdict) for the summary."""
    if score is None or tested < total / 2:
        return "UNCLEAR", ("Too few tests ran to judge this kill-switch - run the outage tests too "
                           "(they need your OK).")
    if score >= 90:
        if not failed:
            return "STRONG", "No leak found. This kill-switch did its job in every test that ran - keep it."
        return "STRONG", "No traffic leak; only a minor gap (below). This kill-switch is good - keep it."
    if score >= 70:
        return "FAIR", ("No traffic leak while the VPN was down, but there are gaps (below). Acceptable for "
                        "everyday use; for anything sensitive pick a kill-switch without them.")
    return "POOR", ("Your real traffic got out. This kill-switch does not protect you when it matters - "
                    "it gives a false sense of safety.")


ONLINE_PROMPT = """
Online check: the bench will ask https://1.1.1.1 (and https://[2606:4700:4700::1111]) every 2 s
which IP address they see you coming from. If a leak happens, Cloudflare sees your real IP address.
It does not change the score - it only shows the leaked address and checks the bench itself.
Run the online check? [Y/n] """

DISRUPT_TEXT = """The next tests break the VPN on purpose - about 3 minutes, 4 at most. A blocked server or a killed client
stays so until the tunnel goes down (at most %d s); the bench then waits up to %d s for the VPN to come back.
Each change is undone at once (also on Ctrl-C; 'sudo python3 ksbench.py --restore' if the run dies):
  D1  a firewall rule blocks the VPN server
  D3  the tunnel adapter is taken down for 10 s
  D4  the physical network adapter is taken down for 10 s - you are offline meanwhile
  T1  a firewall allow rule for the test addresses + the physical adapter down for 10 s
  D2  the VPN client process is killed (asks first; skipped if the VPN runs in the kernel/system)
  T2  (experts, only with --app-process) the kill-switch app's process is killed + the adapter down for 10 s
Nothing is installed, nothing is rebooted, no files are deleted."""


def main(argv=None):
    ap = argparse.ArgumentParser(description="Vendor-neutral VPN kill-switch leak bench. Run as root with the VPN "
                                 "connected. Scenarios and scoring: SCENARIOS.md")
    ap.add_argument("--product", help="name of the app under test (for the report)")
    ap.add_argument("--server", action="append", help="VPN server address or name (default: detected)")
    ap.add_argument("--iface", action="append", help="physical adapter to watch (default: detected)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--online", dest="online", action="store_true", default=None, help="run the online check, no question")
    g.add_argument("--no-online", dest="online", action="store_false", help="skip the online check, no question")
    ap.add_argument("--yes", action="store_true", help="run the outage and tamper tests without asking")
    ap.add_argument("--app-process", help="kill-switch app process for T2")
    ap.add_argument("--only", type=lambda s: [x.strip().upper() for x in s.split(",")], help="e.g. S1,D1")
    ap.add_argument("--hold", type=int, default=60, help="longest a blocked server / killed client waits for the tunnel to go down (default 60)")
    ap.add_argument("--recover", type=int, default=60, help="seconds to wait for the VPN to come back (default 60)")
    ap.add_argument("--out", help="report file (JSON)")
    ap.add_argument("--list", action="store_true", help="list the scenarios and exit")
    ap.add_argument("--restore", action="store_true", help="undo the changes of an interrupted run")
    a = ap.parse_args(argv)
    a.hold, a.recover = min(max(a.hold, 10), 120), min(max(a.recover, 10), 120)
    if a.list:
        for s, g_, w, t in SCENARIOS:
            print(f"{s:<3} {g_:<7} {w:>3}  {t}")
        print("\n" + DISRUPT_TEXT % (a.hold, a.recover))
        return 0
    if not (IS_LINUX or IS_MAC):
        sys.exit("ksbench.py runs on Linux and macOS; on Windows use ksbench.ps1.")
    if os.geteuid() != 0:
        sys.exit("ksbench: run as root (sudo) - it needs to watch the network adapter.")
    if a.restore:
        Journal.restore(os.path.join(tempfile.gettempdir(), "ksbench", "journal.json"))
        return 0
    doc = Bench(a, Linux() if IS_LINUX else Mac()).run()
    return 0 if doc["score"] is not None else 2


if __name__ == "__main__":
    sys.exit(main())
