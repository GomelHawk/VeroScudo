from veroscudo import netutil, nm


def test_iface_never_returns_a_physical_card(tmp_path, monkeypatch):
    monkeypatch.setattr(nm, "SYS_NET", tmp_path)
    (tmp_path / "wlp2s0" / "device").mkdir(parents=True)        # physical: has a backing device
    (tmp_path / "tun0").mkdir()
    out = {"GENERAL.IP-IFACE": "wlp2s0", "GENERAL.DEVICES": "wlp2s0"}
    monkeypatch.setattr(nm, "_nmcli", lambda *a: out.get(a[1], ""))
    monkeypatch.setattr(nm, "ipv4_by_iface", lambda: {"wlp2s0": ["192.0.2.50"]})
    assert nm.iface("Work") is None                             # stay blocked rather than open the Wi-Fi card
    out["GENERAL.IP-IFACE"] = "tun0"
    assert nm.iface("Work") == "tun0"


def test_iface_ignores_devices_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(nm, "SYS_NET", tmp_path)
    monkeypatch.setattr(nm, "_nmcli", lambda *a: {"GENERAL.IP-IFACE": "", "GENERAL.DEVICES": "eth0"}[a[1]])
    assert nm.iface("Work") is None


# an SSTP connection: GENERAL.IP-IFACE names the card, the tunnel is ppp0
IP_ADDR_SSTP = ("1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever\n"
                "2: eth0    inet 198.51.100.236/20 brd 198.51.100.255 scope global dynamic noprefixroute eth0\\       valid_lft 86000sec\n"
                "9: ppp0    inet 192.0.2.103 peer 192.0.2.1/32 scope global ppp0\\       valid_lft forever preferred_lft forever\n")


def sstp(tmp_path, monkeypatch, ip4="192.0.2.103/32", addrs=None):
    monkeypatch.setattr(nm, "SYS_NET", tmp_path)
    (tmp_path / "eth0" / "device").mkdir(parents=True, exist_ok=True)
    (tmp_path / "ppp0").mkdir(exist_ok=True)
    calls = []
    out = {"GENERAL.IP-IFACE": "eth0", "GENERAL.DEVICES": "eth0", "IP4.ADDRESS": ip4}
    monkeypatch.setattr(nm, "_nmcli", lambda *a: calls.append(a[1]) or out[a[1]])
    monkeypatch.setattr(nm, "ipv4_by_iface", lambda: netutil.parse_ip_addr(IP_ADDR_SSTP) if addrs is None else addrs)
    return out, calls


def test_ppp_based_vpn_tunnel_is_found_by_its_own_address(tmp_path, monkeypatch):
    sstp(tmp_path, monkeypatch)
    assert nm.iface("CorporateVPN") == "ppp0"


def test_by_address_never_a_physical_card_and_never_a_guess(tmp_path, monkeypatch):
    sstp(tmp_path, monkeypatch, addrs={"eth0": ["192.0.2.103"]})                  # only the card holds it: blocked
    assert nm.iface("CorporateVPN") is None
    (tmp_path / "tun9").mkdir()
    sstp(tmp_path, monkeypatch, addrs={"ppp0": ["192.0.2.103"], "tun9": ["192.0.2.103"]})   # two tunnels: no guess
    assert nm.iface("CorporateVPN") is None
    sstp(tmp_path, monkeypatch, ip4="192.0.2.200/32")                             # nobody holds its address
    assert nm.iface("CorporateVPN") is None
    sstp(tmp_path, monkeypatch, ip4="--")
    assert nm.iface("CorporateVPN") is None


def test_inactive_connection_asks_nothing_more(tmp_path, monkeypatch):
    out, calls = sstp(tmp_path, monkeypatch)
    out["GENERAL.IP-IFACE"] = ""
    assert nm.iface("CorporateVPN") is None and calls == ["GENERAL.IP-IFACE"]


def test_parse_ip_addr_reads_point_to_point_links():
    a = netutil.parse_ip_addr(IP_ADDR_SSTP)
    assert a == {"lo": ["127.0.0.1"], "eth0": ["198.51.100.236"], "ppp0": ["192.0.2.103"]}


def test_nameservers_skip_loopback_stubs(tmp_path):
    f = tmp_path / "resolv.conf"
    f.write_text("nameserver 127.0.0.53\nnameserver 192.168.1.1\nnameserver fe80::1%wlp2s0\noptions edns0\n")
    assert nm.nameservers(f) == ["192.168.1.1", "fe80::1"]


def test_vm_bridges_are_bridges_with_virtual_ports_only(tmp_path, monkeypatch):
    """docker0 (veth ports), virbr0 (tap ports) and an empty bridge qualify; a bridge with the Wi-Fi card enslaved never
    does - allowing it would be a door to the LAN; a plain interface is not a bridge."""
    monkeypatch.setattr(nm, "SYS_NET", tmp_path)
    (tmp_path / "docker0" / "bridge").mkdir(parents=True)
    (tmp_path / "docker0" / "brif" / "veth1a2b").mkdir(parents=True)
    (tmp_path / "veth1a2b").mkdir()
    (tmp_path / "virbr0" / "bridge").mkdir(parents=True)
    (tmp_path / "virbr0" / "brif" / "vnet0").mkdir(parents=True)
    (tmp_path / "vnet0").mkdir()
    (tmp_path / "lxdbr0" / "bridge").mkdir(parents=True)             # no ports yet
    (tmp_path / "br0" / "bridge").mkdir(parents=True)
    (tmp_path / "br0" / "brif" / "wlp2s0").mkdir(parents=True)
    (tmp_path / "wlp2s0" / "device").mkdir(parents=True)              # physical
    (tmp_path / "tun0").mkdir()
    (tmp_path / "eth0" / "device").mkdir(parents=True)
    assert nm.vm_bridges() == ["docker0", "lxdbr0", "virbr0"]


def test_vm_bridges_without_sysfs(tmp_path, monkeypatch):
    monkeypatch.setattr(nm, "SYS_NET", tmp_path / "missing")
    assert nm.vm_bridges() == []
