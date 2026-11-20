"""The VPN server's name answered on this machine while blocked (macOS; Windows: VeroScudo.Native.cs LocalDns)."""
import socket
import struct

from veroscudo import localdns

NAMES = {"vpn.example.com": ["203.0.113.5", "2001:db8::5"]}


def query(name, qtype=1, ident=0x1234):
    q = b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


def test_answers_the_servers_name_in_any_case():
    r = localdns.answer(query("VPN.Example.com"), NAMES)
    assert r[:2] == b"\x12\x34" and r[3] & 0x0F == 0 and struct.unpack_from("!H", r, 6)[0] == 1
    assert r[-4:] == socket.inet_aton("203.0.113.5")
    r6 = localdns.answer(query("vpn.example.com", 28), NAMES)
    assert r6[-16:] == socket.inet_pton(socket.AF_INET6, "2001:db8::5")


def test_refuses_every_other_name_and_ignores_garbage():
    r = localdns.answer(query("news.example.org"), NAMES)
    assert r[3] & 0x0F == 5 and struct.unpack_from("!H", r, 6)[0] == 0
    assert localdns.answer(b"\x01\x02\x03", NAMES) is None
    assert localdns.answer(query("vpn.example.com")[:5], NAMES) is None


def test_a_responder_on_loopback_answers_a_real_query():
    r = localdns.Responder()
    assert r.start(ports=(0,))                                   # any free port
    try:
        r.set_answers(NAMES)
        port = r._sock.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as c:
            c.settimeout(2)
            c.sendto(query("vpn.example.com"), ("127.0.0.1", port))
            assert c.recv(512)[-4:] == socket.inet_aton("203.0.113.5")
    finally:
        r.stop()


def test_resolver_files_only_veroscudos_own(tmp_path):
    d = tmp_path / "resolver"
    assert localdns.sync_files(["vpn.example.com"], 53153, d)
    f = d / "vpn.example.com"
    assert f.read_text().splitlines() == [localdns.MARK, "nameserver 127.0.0.1", "port 53153"]
    assert not localdns.sync_files(["vpn.example.com"], 53153, d)          # unchanged: nothing written
    (d / "corp.example").write_text("nameserver 10.0.0.1\n")             # the user's own file
    (d / "other.example.com").write_text("nameserver 10.0.0.2\n")
    assert localdns.sync_files([], None, d)
    assert not f.exists()
    assert (d / "corp.example").read_text() == "nameserver 10.0.0.1\n"   # never touched
    (d / "vpn.example.com").write_text("nameserver 10.9.9.9\n")          # the user's own file for that very name
    localdns.sync_files(["vpn.example.com"], 53153, d)
    assert (d / "vpn.example.com").read_text() == "nameserver 10.9.9.9\n"


def test_no_path_tricks_in_a_name(tmp_path):
    d = tmp_path / "resolver"
    localdns.sync_files(["../evil", "/etc/passwd", ".hidden"], 53153, d)
    assert not d.exists() or list(d.iterdir()) == []
