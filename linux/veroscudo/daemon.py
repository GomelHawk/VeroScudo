"""The guard: arms on connect, decides on disconnect, redials forever while armed and down, keeps the ruleset exact."""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import subprocess
import threading
import time
from pathlib import Path

from . import hiddify, localdns, quality, stats
from .backend import firewall, nm
from .config import Config, config_path
from .netutil import usable_server_ip
from .state import Decision, StateStore, decide, write_atomic

log = logging.getLogger("veroscudo")
WATCHDOG_SECONDS = 15
# How long a marker written by our own `off` / `reconnect` explains the down-event that follows it. NetworkManager reports
# the deactivation within seconds; the margins cover a slow D-Bus or a suspended laptop. The Windows guard keeps the same
# two ideas with its own windows (30 s after Off; 30 s after its own hang-up, marker at most 5 min old) because RAS logs
# its records differently - see docs/ARCHITECTURE.md, "Timing windows". Both markers are consumed on first use.
OFF_MARKER_SECONDS = 60.0
RENEW_MARKER_SECONDS = 120.0

# The connection check (Settings > Connection) saw every check fail this many rounds in a row: the tunnel is up but carries
# nothing (a server gone silent - SSTP and OpenVPN notice it only when their own keepalive gives up, minutes later). The guard
# then does what the user's Reconnect does - at most once per DEAD_PAUSE_SECONDS while no check answers, so a check address
# that is always down cannot make it redial in a loop (any answer ends the pause). Same numbers on Windows (Core/66-Quality.ps1).
# pf (macOS) cannot let out DNS for one name only: while blocked the system resolver gets no DNS, except for the redial's
# own lookup of the server right before each dial - at most this long (Windows: the same, Core/70-Dial.ps1)
DNS_FIRST_SECONDS = 3.0
DEAD_ROUNDS = 3
DEAD_PAUSE_SECONDS = 600.0

OFF_STAMP = "off.at"            # when Off last ran (a redial in flight must not undo it); in the run folder


def force_off(store: StateStore) -> None:
    """Off without a Guard - for a config.json that does not load: the note that Off just ran, the flag, the rules. The
    VPN connection itself is left as it is (its name is in the file that cannot be read)."""
    try:
        (store.home / OFF_STAMP).write_text(str(time.time()))
    except OSError:
        pass
    with store.firewall_lock():
        if store.set_armed(False):
            log.info("DISARMED")
        firewall.clear()
        store.set_applied(None, None)


def lockdown(store: StateStore) -> None:
    """Under the firewall lock: everything but loopback, DHCP and neighbour discovery blocked, and noted as "nothing
    is let through" - the one fallback of every path that cannot apply the real rules to an armed machine."""
    firewall.apply(firewall.render_lockdown())
    store.set_applied(None, None)


class Guard:
    def __init__(self, cfg: Config, store: StateStore | None = None) -> None:
        self.base = cfg
        self.store = store or StateStore()
        self.off_marker = self.store.home / "off.marker"     # set by `veroscudo off` so a polling backend knows it was deliberate
        self.renew_marker = self.store.home / "renew.marker"  # set by `veroscudo reconnect`: its own take-down is not your Off
        self.dead_marker = self.store.home / "dead.marker"    # set with it when the reconnect is the guard's own (dead tunnel)
        self.off_stamp = self.store.home / OFF_STAMP         # when `veroscudo off` last ran (a redial in flight must not undo it)
        self._events = threading.RLock()                     # one VPN event at a time: read the markers, decide, act
        self._loop_thread: threading.Thread | None = None
        self._applied: str | None = None
        # how many dials a redial loop makes before it hands over: None = until connected (the daemon). The CLI (and so the
        # tray) dials once and returns - still armed and blocked; the daemon's watchdog takes the redial over within 15 s
        self.attempts: int | None = None
        self._cfg_stamp = self._stamp()
        self.quality = quality.Monitor(self.store.home / "quality.json")   # Settings > Connection; read by the tray
        self.stats = stats.Recorder(self.store.state)                      # tray > Statistics: VPN time and quality per minute
        hiddify.register(cfg.profiles)                                     # (Config.load does it on every reload)
        self._hiddify_hosts: dict = {}           # Hiddify server host name -> (addresses, when looked up)
        self._hiddify_good: dict = {}            # profile id -> the last good permit set (a broken file keeps it)
        self._hiddify_said: dict = {}            # what was logged last per topic - each problem is logged once
        self._lookup_next = False                # look the server name up after the next block (a redial failed)
        self._cgroup_ok = True                   # False once nftables refused the cgroup rule (kernel without nft_socket)
        self.local = localdns.Responder()        # pf: the server's name answered on this machine while blocked
        self.dead_rounds = 0                     # connection-check rounds in a row with every check failed
        self._dead_next = 0.0                    # monotonic time before which no dead-tunnel reconnect starts

    @staticmethod
    def _stamp() -> tuple[float, int]:
        try:
            st = config_path().stat()
            return (st.st_mtime, st.st_size)
        except OSError:
            return (0.0, 0)

    def reload_config(self) -> bool:
        """Picks up a changed config.json (the tray's Settings, `veroscudo import`) without a restart. A file that does not
        load keeps the running configuration - the kill-switch never loses its profile to a typo - and is logged once."""
        stamp = self._stamp()
        if stamp == self._cfg_stamp:
            return False
        self._cfg_stamp = stamp
        try:
            new = Config.load()
        except Exception as e:  # noqa: BLE001 - whatever is wrong with the file: the running one stays
            log.error("config.json changed but cannot be used (%s) - keeping the previous configuration", e)
            return False
        self.base = new
        log.info("config.json changed - profiles: %s (default '%s', active '%s')", ", ".join(new.names),
                 new.default_profile, self.cfg.profile)
        return True

    @property
    def cfg(self) -> Config:
        """The configuration with the current runtime profile selection (it changes on a switch, from any process)."""
        active = self.store.active
        return self.base.with_active(active) if active in self.base.names else self.base

    # ---- firewall ------------------------------------------------------------
    def vm_wanted(self) -> bool:
        """Settings > Behaviour, "Protect VMs and containers": their traffic follows the kill-switch (through the tunnel
        only, nothing while blocked) - or, off, VeroScudo leaves them alone."""
        return bool(self.cfg.vm)

    def server_ips(self, cfg: Config) -> list[str]:
        """The server addresses the rules allow: pinned ones, else the cached ones - building the rules never waits for DNS
        (a VPN that died abruptly leaves the resolver pointed at its DNS behind the dead tunnel: a lookup then hangs for
        ~20 s, and the redial with it). Only with nothing cached yet is the name looked up here (enable_killswitch looks
        it up afterwards)."""
        if cfg.server_ips:
            return list(cfg.server_ips)
        if cfg.current.vpn_type == hiddify.KIND:
            return []                                          # its servers are endpoints (hiddify_endpoints)
        ips = self.cached_server_ips(cfg) or self.lookup_server_ips(cfg)
        live = [ip for ip in nm.live_endpoints(cfg.profile) if ip not in ips and usable_server_ip(ip)]
        if live:                                               # WireGuard: the address it really uses (its own lookup)
            ips = list(dict.fromkeys(live + ips))[:8]
            write_atomic(self.store.server_cache(cfg.profile), "\n".join(ips))
            log.info("WireGuard '%s' uses %s - allowed and cached", cfg.profile, ", ".join(live))
        return ips

    def lookup_server_ips(self, cfg: Config) -> list[str]:
        """Resolve and merge with the cache (newest first, at most 8): a moved VPN host keeps working and a lookup that
        fails while blocked still leaves the last known addresses."""
        cache = self.store.server_cache(cfg.profile)
        cached = self.cached_server_ips(cfg)
        merged = list(dict.fromkeys(nm.resolve(cfg.server) + cached))[:8]
        if merged and merged != cached:
            write_atomic(cache, "\n".join(merged))
        if not merged:
            log.warning("cannot resolve %s and no cached IP", cfg.server)
        return merged

    def cached_server_ips(self, cfg: Config) -> list[str]:
        """The last known addresses of the profile's server: the per-profile cache, else the 1.0 single file, else []."""
        for f in (self.store.server_cache(cfg.profile), self.store.server_ip):
            if f.exists():
                return [ip for ip in f.read_text().split() if usable_server_ip(ip)]   # an older cache may hold fake-DNS answers
        return []

    def _say_once(self, topic: str, msg: str | None, level: int = logging.WARNING) -> None:
        if msg and self._hiddify_said.get(topic) != msg:
            log.log(level, msg)
        self._hiddify_said[topic] = msg

    def hiddify_endpoints(self, cfg: Config) -> tuple:
        """A Hiddify profile's permits outside the tunnel, parsed from Hiddify's LIVE config on every pass: each proxy
        server (TCP and UDP) and each direct DNS server, host names resolved (a failed lookup keeps the last good addresses).
        A file that cannot be read or parsed keeps the last good set (else the cached one from the state folder)."""
        p = cfg.current
        if p.vpn_type != hiddify.KIND:
            return ()
        cache = self.store.server_cache(cfg.profile)
        try:
            conf = hiddify.read_config(p.config_path)
            eps, dropped = hiddify.endpoints(conf)
        except Exception as e:  # noqa: BLE001 - never the file's content in the log (it holds a secret)
            self._say_once("read", f"Hiddify's config {p.config_path} cannot be used ({type(e).__name__}: "
                                   f"{str(e)[:80] if isinstance(e, OSError) else 'invalid'}) - keeping the last good servers")
            return tuple(self._hiddify_good.get(p.id) or self.cached_hiddify_endpoints(cfg))
        self._say_once("read", None)
        try:
            hiddify.share_tun(p.config_path, conf, self.store.home / hiddify.SHARED_NAME)   # for the user's status and tray
        except Exception as e:  # noqa: BLE001 - the permits never depend on this copy
            self._say_once("share", f"Hiddify: its tunnel settings could not be shared with the tray ({type(e).__name__})")
        self._say_once("dropped", f"Hiddify: {len(dropped)} server entr{'y' if len(dropped) == 1 else 'ies'} not allowed "
                                  f"(private, local or invalid address, or over {hiddify.MAX_ENDPOINTS}): "
                                  f"{', '.join(dropped[:5])}{' ...' if len(dropped) > 5 else ''}" if dropped else None)
        resolved = hiddify.resolve_endpoints(eps, nm.resolve, self._hiddify_hosts)
        if not resolved:
            self._say_once("none", "Hiddify: no usable server in its config - Hiddify itself stays blocked")
            return tuple(self._hiddify_good.get(p.id) or self.cached_hiddify_endpoints(cfg))
        self._say_once("none", None)
        if resolved != self._hiddify_good.get(p.id):
            self._hiddify_good[p.id] = resolved
            try:
                write_atomic(cache, hiddify.dump_cache(resolved))
            except OSError:
                pass
        return tuple(resolved)

    def cached_hiddify_endpoints(self, cfg: Config) -> list:
        try:
            return hiddify.parse_cache(self.store.server_cache(cfg.profile).read_text())
        except OSError:
            return []

    def desired_ruleset(self, tunnel_up: bool, window: bool = False) -> tuple[str, str | None]:
        """The ruleset for the current state and the tunnel interface it allows (None: blocked - the tunnel is down, or up
        without an interface the backend will trust)."""
        cfg = self.cfg
        tun = nm.iface(cfg.profile) if tunnel_up else None
        dns = None if tun else firewall.DnsPolicy(nm.resolver_uid(), tuple(nm.nameservers() or nm.nm_dns()),
                                                  names=self.dns_names(cfg), window=window)
        vm = self.vm_wanted()
        bridges = tuple(nm.vm_bridges())                       # re-read on every pass: a bridge created later is picked up within 15 s
        return firewall.render_ruleset(cfg, self.server_ips(cfg), tun, vm_allowed=bool(tun) and vm, dns=dns, bridges=bridges,
                                       vms_free=not vm, endpoints=self.hiddify_endpoints(cfg),
                                       cgroup=self.hiddify_cgroup(cfg)), tun

    @staticmethod
    def dns_names(cfg: Config) -> tuple[str, ...] | None:
        """The only names the redial may look up while blocked: the VPN server's (none when it is an address). None for
        Hiddify either: VeroScudo does not dial it and its core resolves its servers through its own permits - a DNS
        permit for the system resolver would let the names of the sites you visit out while its tunnel is down."""
        if cfg.current.vpn_type == hiddify.KIND:
            return ()
        server = cfg.server.strip()
        try:
            ipaddress.ip_address(server.strip("[]"))
            return ()
        except ValueError:
            return (server,) if server else ()

    def hiddify_cgroup(self, cfg: Config) -> tuple[str, int] | None:
        """A Hiddify profile: Hiddify's root service, let out by its cgroup like the Windows guard lets its programs out -
        unless nftables refused that rule once (then the server list alone, as before)."""
        if cfg.current.vpn_type != hiddify.KIND or not self._cgroup_ok:
            return None
        return hiddify.service_cgroup()

    def enable_killswitch(self, tunnel_up: bool, force: bool = False) -> None:
        """Applies the ruleset when it differs from what is in force or when it is no longer in force (a `nft flush ruleset`
        or `pfctl -d` by another tool). Atomic: nft -f replaces the table in one transaction. The rules are built from the
        cached server addresses; the name is looked up afterwards, outside the lock, while the tunnel is allowed (DNS goes
        through it) or after a failed redial - and the rules are applied again if the addresses changed."""
        plan = self._plan(tunnel_up)                           # name lookups and questions to the VPN service: not under the lock
        with self.store.firewall_lock():
            tun = self._apply(tunnel_up, force, plan)
        self.sync_resolver(tun)                                # pf: the local answer while blocked, before any lookup
        cfg = self.cfg
        # blocked, after a failed redial: Linux looks the server up again here (only its name gets out); pf does it in
        # prime_dns, the only moment it has DNS
        if not (tun or (self._lookup_next and firewall.matches_dns_names())) or not self._looks_up(cfg):
            return
        self._lookup_next = False
        before = self.cached_server_ips(cfg)
        if self.lookup_server_ips(cfg) != before:
            plan = self._plan(tunnel_up)
            with self.store.firewall_lock():
                self._apply(tunnel_up, False, plan)

    def update_local_dns(self) -> None:
        """pf only: the responder runs (started once) and answers the active profile's server name with its cached
        addresses; the resolver file that sends the name to it exists only while armed and blocked (sync_resolver)."""
        if firewall.matches_dns_names():
            return
        if not self.local.port:
            if self.local.start():
                log.info("local DNS answer for the VPN server listens on %s:%s (used only while the tunnel is down)",
                         localdns.ADDRESS, self.local.port)
            else:
                self._say_once("localdns", "no free port for the local DNS answer - the redial asks the network's DNS "
                               "for a second instead")
                return
        cfg = self.cfg
        names = self.dns_names(cfg) or ()
        ips = self.cached_server_ips(cfg) if names else []
        self.local.set_answers({n: ips for n in names} if ips else {})

    def sync_resolver(self, tun: str | None, remove: bool = False) -> None:
        """pf only: while armed and blocked, /etc/resolver/<server name> sends that name to the local answer - the redial
        finds its server with no DNS packet leaving the Mac (the system resolver's cache may be empty after a drop).
        Otherwise no file of VeroScudo's. Files not marked as VeroScudo's are never touched."""
        if firewall.matches_dns_names():
            return
        cfg = self.cfg
        names = list(self.dns_names(cfg) or ()) if not remove and self.store.armed and not tun and self.local.port else []
        if names and not self.cached_server_ips(cfg):
            names = []
        try:
            if localdns.sync_files(names, self.local.port if names else None):
                log.info("resolver file: %s", f"'{names[0]}' answered locally while the tunnel is down" if names
                         else "VeroScudo's resolver file removed")
        except OSError:
            log.exception("resolver file")

    def prime_dns(self) -> None:
        """pf only, right before a dial: the redial's own lookup of the server. First from the resolver's cache with DNS
        still closed (no packet leaves); only without an answer the rules open DNS to the network's resolvers for that
        lookup and close it again - once answered, after DNS_FIRST_SECONDS at most. A moved server's new address is cached
        and allowed. Linux needs none of it: only that name ever gets out there."""
        cfg = self.cfg
        if firewall.matches_dns_names() or not self.dns_names(cfg) or not self._looks_up(cfg):
            return
        # first with DNS still closed: the system resolver answers from its cache (fresh - the server was looked up while
        # the tunnel was up), and a query it would send is dropped before it leaves the Mac. Only without an answer: the window
        found = self._lookup_within(cfg.server, 1.0)
        if not found:
            try:
                plan = self._plan(False, window=True)
                with self.store.firewall_lock():
                    self._apply(False, False, plan)
                found = self._lookup_within(cfg.server, DNS_FIRST_SECONDS)
            finally:
                plan = self._plan(False)
                with self.store.firewall_lock():
                    self._apply(False, False, plan)
        self._lookup_next = False
        cached = self.cached_server_ips(cfg)
        merged = list(dict.fromkeys([ip for ip in found if usable_server_ip(ip)] + cached))[:8]
        if merged != cached:
            write_atomic(self.store.server_cache(cfg.profile), "\n".join(merged))
            log.info("server '%s' now resolves to %s - allowed for this attempt", cfg.server, ", ".join(merged))
            self.enable_killswitch(tunnel_up=False)

    @staticmethod
    def _lookup_within(name: str, seconds: float) -> list:
        """The addresses of `name` from the system resolver, or [] after `seconds` (the lookup may go on in its thread)."""
        found: list = []
        t = threading.Thread(target=lambda: found.extend(nm.resolve(name)), daemon=True)
        t.start()
        t.join(seconds)
        return list(found)

    @staticmethod
    def _looks_up(cfg: Config) -> bool:
        """The profile's server is known by name (not pinned with serverIps, not Hiddify's endpoints)."""
        return bool(cfg.server) and not cfg.server_ips and cfg.current.vpn_type != hiddify.KIND

    def _plan(self, tunnel_up: bool, window: bool = False):
        """The ruleset for this state and the tunnel it allows - or the error that kept it from being built, which
        _apply then handles under the lock like a refused ruleset. window: only prime_dns asks for its DNS window - never
        the watchdog's thread, so a plan of its own can never open DNS (at worst it closes the window early)."""
        try:
            return self.desired_ruleset(tunnel_up, window=True) if window else self.desired_ruleset(tunnel_up)
        except Exception as e:  # noqa: BLE001 - whatever it was, _apply fails closed on it
            return e

    def _apply(self, tunnel_up: bool, force: bool, plan) -> str | None:
        """Under the firewall lock: the planned ruleset, applied if needed. Returns the tunnel it allows.
        Not armed (any more - an Off since the caller looked): nothing is applied; rules on a machine that is off would
        block it until the next watchdog pass. Fail closed: when the rules cannot be built or loaded, an armed machine is
        never left without a table."""
        if not self.store.armed:
            return None
        try:
            if isinstance(plan, Exception):
                raise plan
            tun = self._apply_rules(tunnel_up, force, plan)
        except Exception:
            self._fail_closed()
            raise
        self._say_once("emergency", None)
        return tun

    def _fail_closed(self) -> None:
        """The rules for this state could not be applied. Rules already in force stay (the transaction changed nothing);
        with none in force, everything but loopback and DHCP is blocked until a later pass succeeds (Windows:
        Enable-VeroEmergencyBlock)."""
        if not self.store.armed:
            return
        try:
            if firewall.is_active():
                self._say_once("emergency", "kill-switch: the new rules could not be applied - the rules in force stay",
                               logging.ERROR)
                return
            lockdown(self.store)
            self._applied = None
            self._say_once("emergency", "EMERGENCY: the kill-switch rules could not be applied - everything but DHCP is "
                                        "blocked until they can (see the error that follows)", logging.CRITICAL)
        except Exception:
            log.exception("EMERGENCY: the kill-switch rules AND the lockdown could not be applied - NOT PROTECTED")

    def _in_force(self, rs: str) -> bool:
        """These rules are the ones in force - by the shared note, not this process's memory: a CLI call (Reconnect, a
        switch) may have applied others and ended before it put these back."""
        return self.store.applied_rules() == hashlib.sha256(rs.encode()).hexdigest() and firewall.is_active()

    def _apply_rules(self, tunnel_up: bool, force: bool, plan: tuple[str, str | None]) -> str | None:
        rs, tun = plan
        if not force and self._in_force(rs):
            return tun
        try:
            firewall.apply(rs)
        except subprocess.CalledProcessError:
            if "socket cgroupv2" not in rs:
                raise
            # this kernel cannot match a cgroup (no nft_socket): Hiddify's servers by address only, as before
            self._cgroup_ok = False
            log.warning("kill-switch: nftables refused the rule for Hiddify's service (cgroup) - Hiddify is let out by "
                        "its server addresses only")
            rs, tun = self.desired_ruleset(tunnel_up)
            if not force and self._in_force(rs):
                return tun
            firewall.apply(rs)
        why = "armed" if self._applied is None else ("changed" if rs != self._applied else "table was missing")
        self._applied = rs
        self.store.set_applied(self.cfg.profile, tun, rs)
        if not tun:
            self.store.mark_down()                          # the connection check's rating starts over (quality.py)
        log.info("kill-switch %s (profile=%s, tunnel=%s)", why, self.cfg.profile, "up" if tun else "DOWN")
        return tun

    def disable_killswitch(self, unless_armed: bool = False) -> None:
        """-unless_armed: the watchdog's tidy-up of a leftover table - re-checked under the lock, because another process
        may have armed since the watchdog looked (then the table is wanted, and it stays)."""
        with self.store.firewall_lock():
            if unless_armed and self.store.armed:
                log.info("kill-switch kept: armed meanwhile by another process")
                return
            firewall.clear()
            self._applied = None
            self.store.set_applied(None, None)
        log.info("kill-switch OFF (firewall restored)")
        self.sync_resolver(None, remove=True)                  # pf: VeroScudo's resolver file goes with the rules

    def boot(self) -> None:
        """Before the network starts: if armed, put the kill-switch back. No DNS here - cached server IPs only;
        the daemon re-resolves and redials once NetworkManager is up."""
        if not self.store.armed:
            return
        cfg = self.cfg
        hid = cfg.current.vpn_type == hiddify.KIND               # Hiddify: its last good servers, from the state folder
        ips, eps = [], ()
        with self.store.firewall_lock():
            try:
                ips = [] if hid else list(cfg.server_ips) or self.cached_server_ips(cfg)
                eps = tuple(self.cached_hiddify_endpoints(cfg)) if hid else ()
                firewall.apply(firewall.render_ruleset(cfg, ips, None, vm_allowed=False, dns=firewall.DnsPolicy(), endpoints=eps))
            except Exception:                                  # never boot open: the lockdown instead, the daemon retries
                log.exception("boot: armed, but the kill-switch rules could not be applied - everything but DHCP is blocked")
                lockdown(self.store)
                return
            self.store.set_applied(cfg.profile, None)
        shown = ips or [f"{a}:{p}" for a, p, _ in eps]
        log.info("boot: armed - kill-switch ON before the network starts (server %s)", ", ".join(shown[:8]) or "not cached")

    # ---- actions -------------------------------------------------------------
    def arm(self) -> None:
        self.off_marker.unlink(missing_ok=True)            # a stale Off must never turn a later real drop into a disarm
        self.off_stamp.unlink(missing_ok=True)
        if not self.store.armed and self._looks_up(self.cfg):
            # nothing is blocked yet: look the name up now, so the address the VPN client dials (a name can answer with
            # changing addresses) is allowed from the first rule on
            self.lookup_server_ips(self.cfg)
        with self.store.firewall_lock():                   # the flag never changes while another process applies or clears
            if self.store.set_armed(True):
                log.info("ARMED")
        # the rules right after it. Not inside that lock: working them out asks the VPN service and may look names up,
        # and an Off must not wait for that. Whoever takes the lock in between sees "armed" and applies the same rules;
        # an Off in between wins (_apply looks at the flag again)
        self.enable_killswitch(nm.is_connected(self.cfg.profile))

    def disarm(self) -> None:
        with self.store.firewall_lock():
            if self.store.set_armed(False):
                log.info("DISARMED")
            self.disable_killswitch()

    def on(self) -> None:
        self.resume_after_password()
        self.arm()
        if not nm.is_connected(self.cfg.profile):
            self.reconnect()

    def renew(self, dead: bool = False) -> None:
        """The user's Reconnect: block first (the ruleset without the tunnel while it is still up), take the connection down,
        redial; traffic flows again only once the tunnel is back. NetworkManager reports our own take-down as
        'user-requested' - the renew marker makes the daemon read it as a failure (stay armed), not as your Off.
        dead: the guard's own Reconnect of a tunnel that carries nothing (see DEAD_ROUNDS) - a stored-password pause stays."""
        if not self.store.armed:
            log.info("Reconnect: the VPN is off - use `veroscudo on`")
            return
        if self.store.lock_alive():
            log.info("reconnect requested, but a reconnect is already running - it continues")
            return
        cfg = self.cfg
        if cfg.current.vpn_type == hiddify.KIND:
            log.info("Reconnect: '%s' is a Hiddify profile - %s", cfg.profile, hiddify.RECONNECT_HINT)
            return
        if dead:
            log.warning("no answer through '%s' for %d connection-check rounds in a row - reconnecting it: traffic blocked, "
                        "taking it down, redialing", cfg.profile, DEAD_ROUNDS)
            self.dead_marker.write_text(str(time.time()))
        else:
            self.resume_after_password()
            log.info("RECONNECT requested by you: traffic blocked, taking down '%s', redialing", cfg.profile)
        self.renew_marker.write_text(str(time.time()))
        self.enable_killswitch(tunnel_up=False, force=True)
        if nm.is_connected(cfg.profile) or nm.is_stale(cfg.profile):
            nm.down(cfg.profile)
        self.reconnect()

    @staticmethod
    def _take_marker(marker: Path, max_age: float) -> bool:
        """True (once) when the marker was written within the last `max_age` seconds; the marker is consumed either way."""
        try:
            written = marker.stat().st_mtime
            text = marker.read_text().strip()
        except OSError:
            return False
        try:
            started = float(text)
        except ValueError:
            started = written                              # empty or half-written: the file's own time says when
        marker.unlink(missing_ok=True)
        return time.time() - started <= max_age

    def _take_off_marker(self) -> bool:
        """`veroscudo off` took the connection down just now - the down-event that follows is deliberate."""
        return self._take_marker(self.off_marker, OFF_MARKER_SECONDS)

    def _take_renew_marker(self) -> bool:
        """Our own Reconnect took the connection down just now - not the user's Off."""
        return self._take_marker(self.renew_marker, RENEW_MARKER_SECONDS)

    def _off_recent(self) -> bool:
        """You pressed Off and nothing armed since (arm removes the note) - however long a dial in flight then takes."""
        return self.off_stamp.exists()

    def off(self) -> None:
        self.renew_marker.unlink(missing_ok=True)
        try:
            self.off_stamp.write_text(str(time.time()))
        except OSError:
            pass
        connected = nm.is_connected(self.cfg.profile) and self.cfg.current.vpn_type != hiddify.KIND   # Hiddify stays up
        if connected:                                      # only when a down-event will follow and consume it
            self.off_marker.write_text(str(time.time()))
        self.disarm()
        if connected:
            nm.down(self.cfg.profile)
            log.info("disconnected '%s' by user (off)", self.cfg.profile)

    def use(self, name: str) -> None:
        """Switch the active profile. While armed the machine stays blocked throughout: the old tunnel stops being allowed
        before it is taken down, nothing is allowed out until the new one is up."""
        old = self.cfg
        new = self.base.with_active(name)                      # raises on a name that is not in config.json
        if old.profile == new.profile:
            log.info("profile '%s' is already active", name)
            if self.store.armed and not nm.is_connected(name):
                self.reconnect()
            return
        self.resume_after_password()
        self.store.set_active(name)                            # first: the old profile's deactivation is then ignored
        log.info("active profile -> '%s'", name)
        if self.store.armed:
            self.enable_killswitch(tunnel_up=False)
            if nm.is_connected(old.profile):
                nm.down(old.profile)
                log.info("took down '%s'", old.profile)
            self.reconnect()
        elif nm.is_connected(old.profile):
            nm.down(old.profile)
            log.info("took down '%s' (VPN is off - '%s' is selected for the next turn on)", old.profile, name)

    def resume_after_password(self) -> None:
        """Your On / Reconnect / switch: you have stored the password - redial again (Windows lifts the pause the same way)."""
        if self.store.clear_auth_failed():
            log.info("password pause lifted - redialing")

    def on_event_auth(self, profile: str, which: str) -> None:
        with self._events:
            self._on_event_auth(profile, which)

    def _on_event_auth(self, profile: str, which: str) -> None:
        """The VPN refused the active profile for its password: stop redialing, so the server does not lock the account;
        traffic stays blocked. The tray shows Password missing / rejected (Windows: Set-VeroAuthFailed)."""
        if profile != self.cfg.profile or not self.store.armed:
            return
        if self.store.set_auth_failed(profile, which):
            log.info("PASSWORD %s for '%s' - automatic redial paused so the account is not locked; traffic stays blocked. "
                     "Store the right password in the system's VPN settings, then Turn on or Reconnect.",
                     "MISSING" if which == "missing" else "REJECTED", profile)

    def on_event_up(self, profile: str) -> None:
        with self._events:
            self._on_event_up(profile)

    def _on_event_up(self, profile: str) -> None:
        if profile not in self.base.names:
            return
        self.store.clear_auth_failed()                         # connected: whatever was wrong with the password is fixed
        if not self.store.armed and self._off_recent() and self.store.lock_alive():
            # a dial VeroScudo had started before your Off has just succeeded: Off stands - take it down, do not arm
            log.info("'%s' connected by a redial that was running when you turned the VPN off - disconnecting it", profile)
            self.off_marker.write_text(str(time.time()))       # the down-event that follows is deliberate
            nm.down(profile)
            return
        if profile != self.cfg.profile:
            self.store.set_active(profile)
            log.info("'%s' connected - now the active profile", profile)
        self.arm()

    def on_event_down(self, profile: str, user_requested: bool) -> None:
        with self._events:
            self._on_event_down(profile, user_requested)

    def _on_event_down(self, profile: str, user_requested: bool) -> None:
        if profile != self.cfg.profile:
            log.info("VPN '%s' went down - not the active profile, ignored", profile)
            return
        if nm.is_connected(profile):
            log.info("VPN '%s' reported down but is connected - ignored", profile)
            return
        off = self._take_off_marker()
        renewing = self._take_renew_marker()
        dead = self._take_marker(self.dead_marker, RENEW_MARKER_SECONDS) and renewing
        deliberate = off or (user_requested and not renewing)
        if renewing and not off:
            log.info("VPN '%s' went down by VeroScudo's own Reconnect - not your Off", profile)
        self.off_marker.unlink(missing_ok=True)
        d = decide(deliberate, self.store.armed)
        log.info("VPN '%s' terminated (user_requested=%s) -> %s (decision source: %s)", profile, deliberate, d.value,
                 "veroscudo off" if off else "NetworkManager reason")
        # the status window's "Last drop": why, in the words the Windows tray uses for its RAS event
        self.store.record_drop(profile, "turned off" if off else "no traffic through the tunnel" if dead else
                               "Reconnect" if renewing else "you disconnected" if deliberate else "connection lost")
        if d is Decision.DISARM:
            self.disarm()
        elif d is Decision.RECONNECT:
            self.reconnect_async()

    def reconnect_async(self) -> None:
        if self._loop_thread and self._loop_thread.is_alive():
            return
        self._loop_thread = threading.Thread(target=self.reconnect, daemon=True)
        self._loop_thread.start()

    def reconnect(self) -> None:
        """Blocked + redial forever, until the tunnel is up or the user turns the VPN off. Follows a profile switch."""
        if not self.store.take_lock():
            log.info("reconnect loop already running")
            return
        attempt = 0
        try:
            while self.store.armed and not nm.is_connected(self.cfg.profile):
                if self.store.auth_failed(self.cfg.profile):
                    log.info("redial paused: the password of '%s' was refused - traffic stays blocked", self.cfg.profile)
                    break
                attempt += 1
                self.enable_killswitch(tunnel_up=False)
                if self.cfg.current.vpn_type == hiddify.KIND:   # connected in Hiddify only: wait for its tunnel, never dial
                    self._say_once("wait", hiddify.NOT_CONNECTED, logging.INFO)
                    if self.attempts is not None and attempt >= self.attempts:
                        break
                    time.sleep(self.cfg.retry_seconds)
                    continue
                if nm.is_stale(self.cfg.profile):            # WireGuard: activated but silent - take it down for a fresh start
                    # stale = no handshake within 3 minutes, or none at all 30 s after it started (nm.wg_state)
                    log.info("WireGuard '%s': silent - no recent handshake with its server - restarting it", self.cfg.profile)
                    self.store.record_drop(self.cfg.profile, "WireGuard silent (no handshake)")
                    # our own take-down: NetworkManager reports it as user-requested - the renew marker keeps it from
                    # reading as your Off
                    self.renew_marker.write_text(str(time.time()))
                    nm.down(self.cfg.profile)
                nm.reset_resolver()                          # Linux: resolved forgets the timeouts of the blocked queries
                self.prime_dns()
                if nm.up(self.cfg.profile):
                    self.enable_killswitch(tunnel_up=False)    # WireGuard: allow the address it just looked up itself
                    nm.wait_connected(self.cfg.profile)
                if nm.is_connected(self.cfg.profile):
                    if self.cfg.current.vpn_type == hiddify.KIND:
                        log.info("Hiddify connected again - traffic goes through it")       # nothing was dialed
                    else:
                        log.info("reconnected '%s' after %d attempt(s)", self.cfg.profile, attempt)
                    break
                if not self.store.armed:                     # you turned the VPN off during the dial: not a failure
                    break
                log.info("attempt %d failed", attempt)
                self._lookup_next = True                     # the server may have moved: look it up with the next block
                if self.attempts is not None and attempt >= self.attempts:
                    log.info("still not connected - traffic stays blocked; the VeroScudo service keeps redialing every %d s",
                             self.cfg.retry_seconds)
                    break
                time.sleep(self.cfg.retry_seconds)
            if not self.store.armed:
                log.info("you turned the VPN off - redial stopped")
        finally:
            self.store.release_lock()
        if not self.store.armed and attempt and self._off_recent() and nm.is_connected(self.cfg.profile):
            log.info("'%s' connected after you turned the VPN off - disconnecting it", self.cfg.profile)
            nm.down(self.cfg.profile)                          # Hiddify: nothing is taken down (nm.down leaves it alone)
            return
        if self.store.armed and nm.is_connected(self.cfg.profile):
            self._say_once("wait", None)                       # the next drop is told again
            self.enable_killswitch(tunnel_up=True)

    def watchdog(self) -> None:
        self.reload_config()
        self.update_local_dns()
        armed = bool(self.store.armed)
        up = armed and nm.is_connected(self.cfg.profile)
        self.record_minute(up, down=armed and not up)
        if self.store.armed:
            self.enable_killswitch(up)
            if not up and not self.store.lock_alive() and not self.store.auth_failed(self.cfg.profile):
                self.reconnect_async()
        elif firewall.is_active():
            log.info("disarmed but kill-switch still active - restoring")
            self.disable_killswitch(unless_armed=True)

    def record_minute(self, up: bool, down: bool = False) -> None:
        """Statistics: VeroScudo's own VPN up right now (armed and the active profile connected; other VPNs do not count),
        or down: armed, but the active profile is not connected (a minute with only down passes is shown as bad)."""
        try:
            self.stats.tick(up, self.cfg.current.id, self.cfg.profile, down=down)
        except OSError:
            log.exception("statistics")

    # ---- connection quality (optional) ---------------------------------------
    def quality_tick(self) -> float:
        """One round of checks if they are wanted and the VPN is on and connected; otherwise the samples are dropped (a new
        connection starts a new rating). Returns the seconds until the next round. Logs only a change of the rating."""
        cfg = self.cfg
        chk = cfg.check
        if not chk.enabled or not self.store.armed or not nm.is_connected(cfg.profile):
            if self.quality.samples or self.quality.path.exists():
                self.quality.reset()
            self.dead_rounds = 0                 # failed rounds of an earlier connection never count for the next
            return 5.0 if not chk.enabled else min(5.0, chk.interval_seconds)
        results = quality.run_round(chk.targets, tls=cfg.current.vpn_type == hiddify.KIND)   # Hiddify answers ping/TCP itself
        try:
            self.stats.checks(len(results), sum(1 for r in results if not r[0]), cfg.current.id, cfg.profile,
                              slow=sum(1 for r in results if r[0] and len(r) > 2 and r[2]))
        except OSError:
            log.exception("statistics")
        self.dead_check(cfg, results)
        q = self.quality.add_round(chk, cfg.profile, results, down_at=self.store.last_down())
        try:
            self.stats.rated(q.state, cfg.current.id, cfg.profile)          # the bar is never better than what the status showed
        except OSError:
            log.exception("statistics")
        if q.state != "checking" and q.state != self.quality.last_state:
            log.info("connection quality: %s (%s of %s checks lost, %s slow, %s)", q.state, q.lost, q.checks, q.slow,
                     f"{q.rtt_ms} ms" if q.rtt_ms is not None else "no answer")
            self.quality.last_state = q.state
        return float(chk.interval_seconds)

    def dead_check(self, cfg: Config, results) -> None:
        """Counts the rounds in which every check failed; at DEAD_ROUNDS in a row the guard reconnects the profile itself (in
        a thread: the redial must not stop the checks). Never for Hiddify - VeroScudo does not dial it - and at most once per
        DEAD_PAUSE_SECONDS; both cases are logged once."""
        if not results or any(r[0] for r in results):
            self.dead_rounds = 0
            self._say_once("dead", None)
            if results:
                self._dead_next = 0.0            # an answer: the check addresses work - the next stall may redial at once
            return
        self.dead_rounds += 1
        if self.dead_rounds < DEAD_ROUNDS:
            return
        self.dead_rounds = 0
        if cfg.current.vpn_type == hiddify.KIND:
            self._say_once("dead", f"no answer through '{cfg.profile}' for {DEAD_ROUNDS} connection-check rounds in a row - "
                           f"VeroScudo does not dial Hiddify: {hiddify.RECONNECT_HINT}")
            return
        if time.monotonic() < self._dead_next:
            self._say_once("dead", f"still no answer through '{cfg.profile}' after VeroScudo reconnected it - check the "
                           "addresses in Settings > Connection (next automatic reconnect in at most 10 minutes)")
            return
        self._dead_next = time.monotonic() + DEAD_PAUSE_SECONDS
        threading.Thread(target=self.renew, kwargs={"dead": True}, daemon=True, name="dead-tunnel").start()

    def quality_loop(self) -> None:
        while True:
            started = time.monotonic()
            try:
                wait = self.quality_tick()
            except Exception:
                log.exception("connection check")
                wait = 30.0
            time.sleep(max(1.0, wait - (time.monotonic() - started)))

    # ---- main loop -----------------------------------------------------------
    def run(self) -> None:
        log.info("VeroScudo daemon, profiles: %s (active '%s')", ", ".join(self.base.names), self.cfg.profile)
        try:
            self.watchdog()
        except Exception:                                      # the loop below tries again in 15 s; the watch must start
            log.exception("watchdog")

        def tick():
            while True:
                time.sleep(WATCHDOG_SECONDS)
                try:
                    self.watchdog()
                except Exception:
                    log.exception("watchdog")

        threading.Thread(target=tick, daemon=True).start()
        threading.Thread(target=self.quality_loop, daemon=True, name="quality").start()
        nm.watch(lambda: set(self.base.names), on_up=self.on_event_up, on_down=self.on_event_down, on_auth=self.on_event_auth)
