"""The VPN server's name answered on this machine while the tunnel is down - on a firewall that cannot let DNS out for one
name only (macOS pf; Windows: VeroScudo.Native.cs LocalDns + an NRPT rule). A responder on 127.0.0.1 answers ONLY the
server's names, with the addresses VeroScudo has cached; a resolver file (/etc/resolver/<name>, marked as VeroScudo's)
sends exactly those names to it. The redial so finds its server without a DNS packet leaving the machine."""
from __future__ import annotations

import ipaddress
import os
import socket
import struct
import tempfile
import threading
from pathlib import Path

ADDRESS = "127.0.0.1"
PORTS = (53153, 53154, 53155, 53156)        # the first free one; a resolver file names its port, so never port 53
MARK = "# VeroScudo: the VPN server while the tunnel is down - removed when it is up"
RESOLVER_DIR = Path("/etc/resolver")
TTL = 30


def answer(q: bytes, names: dict) -> bytes | None:
    """The reply to one DNS query: A/AAAA of a known name, no data for its other types, REFUSED for any other name; None
    for what is not one well-formed standard query. Pure (same rules as LocalDns.Answer on Windows)."""
    if len(q) < 17 or q[2] & 0xF8 or q[4:6] != b"\x00\x01":
        return None
    labels, o = [], 12
    while o < len(q) and q[o]:
        n = q[o]
        if n > 63 or o + 1 + n > len(q):
            return None
        labels.append(q[o + 1:o + 1 + n].decode("ascii", "replace"))
        o += 1 + n
    if o + 5 > len(q):
        return None
    qtype, qclass = struct.unpack_from("!HH", q, o + 1)
    qend = o + 5
    name = ".".join(labels).lower()
    known = qclass == 1 and name in names
    ans = []
    if known:
        for a in names[name]:
            try:
                b = ipaddress.ip_address(a).packed
            except ValueError:
                continue
            if (qtype == 1 and len(b) == 4) or (qtype == 28 and len(b) == 16):
                ans.append(b)
    head = q[:2] + bytes([0x84 | (q[2] & 1), 0x00 if known else 0x05]) + struct.pack("!HHHH", 1, len(ans), 0, 0)
    body = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, TTL, len(b)) + b for b in ans)
    return head + q[12:qend] + body


class Responder:
    """UDP on 127.0.0.1, in a thread; the names and addresses are replaced as a whole (names not given are refused)."""

    def __init__(self) -> None:
        self.port: int | None = None
        self.names: dict = {}
        self._sock: socket.socket | None = None

    def start(self, ports=None) -> bool:
        if self._sock:
            return True
        for p in PORTS if ports is None else ports:              # read at the call: tests use their own
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.bind((ADDRESS, p))
            except OSError:
                s.close()
                continue
            self._sock, self.port = s, s.getsockname()[1]           # the real port (also when 0 asked for any)
            threading.Thread(target=self._serve, daemon=True, name="local-dns").start()
            return True
        return False

    def set_answers(self, names: dict) -> None:
        self.names = {k.rstrip(".").lower(): list(v) for k, v in names.items() if v}

    def stop(self) -> None:
        s, self._sock, self.port = self._sock, None, None
        if s:
            s.close()

    def _serve(self) -> None:
        while self._sock:
            try:
                q, peer = self._sock.recvfrom(512)
            except OSError:
                return
            if not peer[0].startswith("127."):
                continue                                # nothing from outside (it listens on loopback anyway)
            r = answer(q, self.names)
            if r is not None:
                try:
                    self._sock.sendto(r, peer)
                except OSError:
                    pass


def _write(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".veroscudo-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)                              # our own temporary file
        raise


def ours(path: Path) -> bool:
    try:
        return path.read_text().splitlines()[:1] == [MARK]
    except (OSError, UnicodeDecodeError):
        return False


def sync_files(names: list, port: int | None, directory: Path | None = None) -> bool:
    """One resolver file per name -> 127.0.0.1:port (or none: names empty / port None). Only files marked as VeroScudo's are
    ever replaced or removed - a resolver file of the user's own for that name is left alone. True = something changed."""
    directory = RESOLVER_DIR if directory is None else directory           # read at the call: tests point it elsewhere
    want = {n.rstrip(".").lower() for n in names if n and "/" not in n and not n.startswith(".")} if port else set()
    changed = False
    if directory.is_dir():
        for f in directory.iterdir():
            if f.name not in want and ours(f):
                f.unlink()
                changed = True
    for n in want:
        f = directory / n
        text = f"{MARK}\nnameserver {ADDRESS}\nport {port}\n"
        if f.exists() and not ours(f):
            continue                                    # the user's own file for that name
        if f.exists() and f.read_text() == text:
            continue
        directory.mkdir(mode=0o755, parents=True, exist_ok=True)
        _write(f, text)
        changed = True
    return changed
