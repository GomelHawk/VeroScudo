"""Unit tests for ksbench.py: packet parsing, classification, pcap reading, scoring, the undo journal,
and that the scenario table is the same in ksbench.py, ksbench.ps1 and SCENARIOS.md."""
import io
import json
import os
import re
import struct
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import ksbench


def _read(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as f:
        return f.read()


VEC = json.loads(_read(HERE, "vectors.json"))


@pytest.mark.parametrize("v", VEC["vectors"], ids=lambda v: v["name"])
def test_parse_and_classify(v):
    p = ksbench.parse_frame(bytes.fromhex(v["hex"]), v["linktype"])
    if v["expect"] is None:
        assert p is None
        return
    exp = dict(v["expect"])
    cls = exp.pop("cls")
    for k, want in exp.items():
        assert getattr(p, k) == want, k
    p.prog = v.get("prog")
    assert ksbench.classify(p, set(VEC["servers"]), set(VEC["app"]), {tuple(x) for x in VEC["own"]}) == cls


def test_vpn_app():
    progs = {"/opt/Hiddify/HiddifyCli", "/opt/Hiddify/hiddify", "/usr/bin/firefox", "/usr/lib/systemd/systemd-resolved",
             "/usr/bin/python3.14"}
    assert ksbench.vpn_app({"/opt/Hiddify/HiddifyCli"}, progs) == {"/opt/Hiddify/HiddifyCli", "/opt/Hiddify/hiddify"}
    assert ksbench.vpn_app({"/usr/sbin/openvpn"}, {"/usr/sbin/sshd"}) == {"/usr/sbin/openvpn"}   # a system folder: only itself
    assert ksbench.vpn_app({"/usr/bin/python3.14", "/usr/lib/systemd/systemd-resolved"}, progs) == set()  # the bench, the system
    assert ksbench.vpn_app({None}, progs) == set()                     # kernel WireGuard: no program at all


def test_credit_near_only_the_same_endpoint_within_a_second():
    def pkt(dst, sport, prog=None, ttl=128):
        p = ksbench.Pkt(4, "192.168.1.20", dst, 17, sport, 443, ttl=ttl)
        p.prog, p.known = prog, True
        return p
    app = {"/opt/vpn/vpnd"}
    a = pkt("203.0.113.9", 50000, "/opt/vpn/vpnd")
    short = pkt("203.0.113.9", 50001)                 # a socket shorter than one look, 0.03 s before the app's packet
    late = pkt("203.0.113.9", 50002)                  # the same endpoint, 5 s later: counted
    other = pkt("203.0.113.10", 50003)                # another address: counted
    test = pkt("198.51.100.7", 50004)                 # the bench's own test address: never
    vm = pkt("203.0.113.9", 50005, ttl=127)           # forwarded for a VM: never
    ksbench.credit_near([(10.0, a), (9.97, short), (15.0, late), (10.0, other), (10.0, test), (10.0, vm)], app)
    assert short.prog == "/opt/vpn/vpnd"
    assert late.prog is None and other.prog is None and test.prog is None and vm.prog is None
    resend = pkt("203.0.113.9", 50000)                # the app's own connection, 60 s later (killed: the system closes it)
    ksbench.credit_near([(10.0, a), (70.0, resend)], app)
    assert resend.prog == "/opt/vpn/vpnd"
    frag_a, frag = pkt("203.0.113.9", None, "/opt/vpn/vpnd"), pkt("203.0.113.9", None)   # no port: never one connection
    ksbench.credit_near([(10.0, frag_a), (70.0, frag)], app)
    assert frag.prog is None


def test_owners_follow_a_port_from_program_to_program():
    o = ksbench.Owners(lambda: [], lambda pid: {1: "/opt/vpn/vpnd", 2: "/usr/bin/firefox"}[pid])
    o.paths = {1: "/opt/vpn/vpnd", 2: "/usr/bin/firefox"}
    o.held = {(6, 40000): [[1, 100.0, 105.0], [2, 200.0, 210.0]], (17, 5353): [[1, 100.0, 300.0], [2, 150.0, 160.0]]}
    assert o.program(6, 40000, 104.0) == "/opt/vpn/vpnd"
    assert o.program(6, 40000, 205.0) == "/usr/bin/firefox"        # the same port, later another program's
    assert o.program(6, 40000, 150.0) is None                      # nobody held it then
    assert o.program(17, 5353, 155.0) is None                      # two could have: counted


def test_pcap_stream_both_byte_orders():
    frame = bytes.fromhex(VEC["vectors"][1]["hex"])
    for e, magic in (("<", 0xA1B2C3D4), (">", 0xA1B2C3D4), ("<", 0xA1B23C4D)):
        rec = struct.pack(e + "IIII", 1700000000, 500000 if magic == 0xA1B2C3D4 else 500000000, len(frame), len(frame))
        blob = struct.pack(e + "IHHiIII", magic, 2, 4, 0, 0, 65535, 1) + rec + frame
        got = []
        ksbench.read_pcap_stream(io.BytesIO(blob), lambda ts, lt, fr, out=got: out.append((ts, lt, fr)))
        assert got == [(1700000000.5, 1, frame)]


def test_pcap_stream_truncated_record_stops_quietly():
    blob = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 1, 0, 100, 100) + b"x"
    got = []
    ksbench.read_pcap_stream(io.BytesIO(blob), lambda *a: got.append(a))
    assert got == []


def test_capture_keeps_only_our_outbound_frames():
    cap = ksbench.Capture([])
    iface = {"name": "en0", "mac": bytes.fromhex("aabbccddeeff")}
    ours = bytes.fromhex(VEC["vectors"][1]["hex"])
    theirs = ours[:6] + bytes.fromhex("010203040506") + ours[12:]
    cap.add(1.0, iface, 1, ours, None)
    cap.add(2.0, iface, 1, theirs, None)
    assert [t for t, _, _ in cap.pkts] == [1.0]


@pytest.mark.parametrize("score,failed,tested,level", [
    (100, [], 90, "STRONG"),
    (93, ["D5"], 100, "STRONG"),
    (80, ["S4", "D5"], 100, "FAIR"),
    (40, ["D3"], 100, "POOR"),
    (100, [], 40, "UNCLEAR"),
    (None, [], 0, "UNCLEAR"),
])
def test_judge(score, failed, tested, level):
    assert ksbench.judge(score, failed, tested, 100)[0] == level


def test_every_scenario_has_a_meaning():
    assert set(ksbench.MEANING) == {s for s, _, _, _ in ksbench.SCENARIOS}
    assert ksbench.CRITICAL <= set(ksbench.MEANING)


def test_journal_undo_and_restore(tmp_path, capsys):
    path = str(tmp_path / "journal.json")
    j = ksbench.Journal(path)
    j.add("first", [["true"]])
    j.add("second", [["false"]])          # an undo that fails must be reported, not hidden
    assert len(ksbench.Journal.pending(path)) == 2
    ksbench.Journal.restore(path)
    out = capsys.readouterr().out
    assert "undone: first" in out and "COULD NOT UNDO 'second'" in out
    assert ksbench.Journal.pending(path) == []
    ksbench.UNDO_FAILED.clear()


def test_journal_written_before_the_change(tmp_path, monkeypatch):
    path = str(tmp_path / "journal.json")
    j = ksbench.Journal(path)
    seen = []

    def fake_run(argv, inp=None, check=False):
        seen.append(len(ksbench.Journal.pending(path)))
        raise RuntimeError("iptables failed")
    monkeypatch.setattr(ksbench, "run", fake_run)
    with pytest.raises(RuntimeError):
        ksbench.Linux._iptables(j, "rule", [["iptables", "-I", "OUTPUT"]], [["true"]])
    assert seen == [1]          # the undo was on disk before the first change ran


def _ps1_scenarios():
    src = _read(os.path.dirname(HERE), "ksbench.ps1")
    return [(a, b, int(c), d) for a, b, c, d in re.findall(r"@\('(\w\d)', '(\w+)', (\d+), '([^']+)'\)", src)]


def _md_scenarios():
    src = _read(os.path.dirname(HERE), "SCENARIOS.md")
    return [(a, b, int(c), d.strip()) for a, b, c, d in
            re.findall(r"^\| (\w\d) \| (\w+) \| (\d+) \| ([^|]+)\|", src, re.MULTILINE)]


def test_scenarios_in_sync():
    py = [tuple(s) for s in ksbench.SCENARIOS]
    assert _ps1_scenarios() == py
    assert _md_scenarios() == py


def test_constants_in_sync_with_ps1():
    src = _read(os.path.dirname(HERE), "ksbench.ps1")
    assert f"$Budget = {ksbench.BUDGET}" in src
    assert f"$Cap = {ksbench.CAP}" in src
    crit = re.search(r"\$Critical = @\(([^)]*)\)", src).group(1)
    assert set(re.findall(r"'(\w\d)'", crit)) == ksbench.CRITICAL
    for sid, text in ksbench.MEANING.items():
        assert text in src.replace("''", "'"), sid


def test_weights_add_up_to_100():
    assert sum(w for _, _, w, _ in ksbench.SCENARIOS) == 100


def test_server_name_lookups_are_the_names_that_resolve_to_a_vpn_server():
    answers = {"vpn.example.com": {"203.0.113.5"}, "news.example.org": {"198.51.100.7"}}
    got = ksbench.server_names({"vpn.example.com", "news.example.org", None}, {"203.0.113.5": ("udp", 1194)},
                               resolve=lambda n: answers.get(n, set()))
    assert got == {"vpn.example.com"}
