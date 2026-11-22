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
    assert ksbench.classify(p, set(VEC["servers"])) == cls


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
