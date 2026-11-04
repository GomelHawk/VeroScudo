from veroscudo import nm


def test_iface_never_returns_a_physical_card(tmp_path, monkeypatch):
    monkeypatch.setattr(nm, "SYS_NET", tmp_path)
    (tmp_path / "wlp2s0" / "device").mkdir(parents=True)        # physical: has a backing device
    (tmp_path / "tun0").mkdir()
    out = {"GENERAL.IP-IFACE": "wlp2s0", "GENERAL.DEVICES": "wlp2s0"}
    monkeypatch.setattr(nm, "_nmcli", lambda *a: out[a[1]])
    assert nm.iface("Work") is None                             # stay blocked rather than open the Wi-Fi card
    out["GENERAL.IP-IFACE"] = "tun0"
    assert nm.iface("Work") == "tun0"


def test_iface_ignores_devices_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(nm, "SYS_NET", tmp_path)
    monkeypatch.setattr(nm, "_nmcli", lambda *a: {"GENERAL.IP-IFACE": "", "GENERAL.DEVICES": "eth0"}[a[1]])
    assert nm.iface("Work") is None


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
