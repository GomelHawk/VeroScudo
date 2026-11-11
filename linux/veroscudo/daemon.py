"""The guard: arms on connect, decides on disconnect, redials forever while armed and down, keeps the ruleset exact."""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

from . import hiddify, quality, stats
from .backend import firewall, nm
from .config import Config, config_path
from .state import Decision, StateStore, decide

log = logging.getLogger("veroscudo")
WATCHDOG_SECONDS = 15
# How long a marker written by our own `off` / `reconnect` explains the down-event that follows it. NetworkManager reports
# the deactivation within seconds; the margins cover a slow D-Bus or a suspended laptop. The Windows guard keeps the same
# two ideas with its own windows (30 s after Off; 30 s after its own hang-up, marker at most 5 min old) because RAS logs
# its records differently - see docs/ARCHITECTURE.md, "Timing windows". Both markers are consumed on first use.
OFF_MARKER_SECONDS = 60.0
RENEW_MARKER_SECONDS = 120.0


class Guard:
    def __init__(self, cfg: Config, store: StateStore | None = None) -> None:
        self.base = cfg
        self.store = store or StateStore()
        self.off_marker = self.store.home / "off.marker"     # set by `veroscudo off` so a polling backend knows it was deliberate
        self.renew_marker = self.store.home / "renew.marker"  # set by `veroscudo reconnect`: its own take-down is not your Off
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
        except (OSError, ValueError, KeyError, TypeError) as e:
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
        return self.cached_server_ips(cfg) or self.lookup_server_ips(cfg)

    def lookup_server_ips(self, cfg: Config) -> list[str]:
        """Resolve and merge with the cache (newest first, at most 8): a moved VPN host keeps working and a lookup that
        fails while blocked still leaves the last known addresses."""
        cache = self.store.server_cache(cfg.profile)
        cached = self.cached_server_ips(cfg)
        merged = list(dict.fromkeys(nm.resolve(cfg.server) + cached))[:8]
        if merged and merged != cached:
            cache.write_text("\n".join(merged))
        if not merged:
            log.warning("cannot resolve %s and no cached IP", cfg.server)
        return merged

    def cached_server_ips(self, cfg: Config) -> list[str]:
        """The last known addresses of the profile's server: the per-profile cache, else the 1.0 single file, else []."""
        for f in (self.store.server_cache(cfg.profile), self.store.server_ip):
            if f.exists():
                return f.read_text().split()
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
            eps, dropped = hiddify.endpoints(hiddify.read_config(p.config_path))
        except (OSError, ValueError) as e:                     # never the file's content in the log (it holds a secret)
            self._say_once("read", f"Hiddify's config {p.config_path} cannot be used ({type(e).__name__}: "
                                   f"{str(e)[:80] if isinstance(e, OSError) else 'invalid'}) - keeping the last good servers")
            return tuple(self._hiddify_good.get(p.id) or self.cached_hiddify_endpoints(cfg))
        self._say_once("read", None)
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
                cache.write_text(hiddify.dump_cache(resolved))
            except OSError:
                pass
        return tuple(resolved)

    def cached_hiddify_endpoints(self, cfg: Config) -> list:
        try:
            return hiddify.parse_cache(self.store.server_cache(cfg.profile).read_text())
        except OSError:
            return []

    def desired_ruleset(self, tunnel_up: bool) -> tuple[str, str | None]:
        """The ruleset for the current state and the tunnel interface it allows (None: blocked - the tunnel is down, or up
        without an interface the backend will trust)."""
        cfg = self.cfg
        tun = nm.iface(cfg.profile) if tunnel_up else None
        dns = None if tun else firewall.DnsPolicy(nm.resolver_uid(), tuple(nm.nameservers() or nm.nm_dns()))
        vm = self.vm_wanted()
        bridges = tuple(nm.vm_bridges())                       # re-read on every pass: a bridge created later is picked up within 15 s
        return firewall.render_ruleset(cfg, self.server_ips(cfg), tun, vm_allowed=bool(tun) and vm, dns=dns, bridges=bridges,
                                       vms_free=not vm, endpoints=self.hiddify_endpoints(cfg)), tun

    def enable_killswitch(self, tunnel_up: bool, force: bool = False) -> None:
        """Applies the ruleset when it differs from what is in force or when it is no longer in force (a `nft flush ruleset`
        or `pfctl -d` by another tool). Atomic: nft -f replaces the table in one transaction. The rules are built from the
        cached server addresses; the name is looked up afterwards, outside the lock, while the tunnel is allowed (DNS goes
        through it) or after a failed redial - and the rules are applied again if the addresses changed."""
        with self.store.firewall_lock():
            tun = self._apply(tunnel_up, force)
        cfg = self.cfg
        if not (tun or self._lookup_next) or not self._looks_up(cfg):
            return
        self._lookup_next = False
        before = self.cached_server_ips(cfg)
        if self.lookup_server_ips(cfg) != before:
            with self.store.firewall_lock():
                self._apply(tunnel_up, False)

    @staticmethod
    def _looks_up(cfg: Config) -> bool:
        """The profile's server is known by name (not pinned with serverIps, not Hiddify's endpoints)."""
        return bool(cfg.server) and not cfg.server_ips and cfg.current.vpn_type != hiddify.KIND

    def _apply(self, tunnel_up: bool, force: bool) -> str | None:
        """Under the firewall lock: the ruleset for this state, applied if needed. Returns the tunnel it allows."""
        rs, tun = self.desired_ruleset(tunnel_up)
        if not force and rs == self._applied and firewall.is_active():
            return tun
        firewall.apply(rs)
        why = "armed" if self._applied is None else ("changed" if rs != self._applied else "table was missing")
        self._applied = rs
        self.store.set_applied(self.cfg.profile, tun)
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

    def boot(self) -> None:
        """Before the network starts: if armed, put the kill-switch back. No DNS here - cached server IPs only;
        the daemon re-resolves and redials once NetworkManager is up."""
        if not self.store.armed:
            return
        cfg = self.cfg
        hid = cfg.current.vpn_type == hiddify.KIND               # Hiddify: its last good servers, from the state folder
        ips = [] if hid else list(cfg.server_ips) or self.cached_server_ips(cfg)
        eps = tuple(self.cached_hiddify_endpoints(cfg)) if hid else ()
        with self.store.firewall_lock():
            firewall.apply(firewall.render_ruleset(cfg, ips, None, vm_allowed=False, dns=firewall.DnsPolicy(), endpoints=eps))
            self.store.set_applied(cfg.profile, None)
        shown = ips or [f"{a}:{p}" for a, p, _ in eps]
        log.info("boot: armed - kill-switch ON before the network starts (server %s)", ", ".join(shown[:8]) or "not cached")

    # ---- actions -------------------------------------------------------------
    def arm(self) -> None:
        self.off_marker.unlink(missing_ok=True)            # a stale Off must never turn a later real drop into a disarm
        if not self.store.armed and self._looks_up(self.cfg):
            # nothing is blocked yet: look the name up now, so the address the VPN client dials (a name can answer with
            # changing addresses) is allowed from the first rule on
            self.lookup_server_ips(self.cfg)
        with self.store.firewall_lock():                   # flag and filters change together, never interleaved with another process
            if self.store.set_armed(True):
                log.info("ARMED")
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

    def renew(self) -> None:
        """The user's Reconnect: block first (the ruleset without the tunnel while it is still up), take the connection down,
        redial; traffic flows again only once the tunnel is back. NetworkManager reports our own take-down as
        'user-requested' - the renew marker makes the daemon read it as a failure (stay armed), not as your Off."""
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
            started = float(marker.read_text().strip() or 0)
        except (OSError, ValueError):
            return False
        marker.unlink(missing_ok=True)
        return time.time() - started <= max_age

    def _take_off_marker(self) -> bool:
        """`veroscudo off` took the connection down just now - the down-event that follows is deliberate."""
        return self._take_marker(self.off_marker, OFF_MARKER_SECONDS)

    def _take_renew_marker(self) -> bool:
        """Our own Reconnect took the connection down just now - not the user's Off."""
        return self._take_marker(self.renew_marker, RENEW_MARKER_SECONDS)

    def off(self) -> None:
        self.renew_marker.unlink(missing_ok=True)
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
        """The VPN refused the active profile for its password: stop redialing, so the server does not lock the account;
        traffic stays blocked. The tray shows Password missing / rejected (Windows: Set-VeroAuthFailed)."""
        if profile != self.cfg.profile or not self.store.armed:
            return
        if self.store.set_auth_failed(profile, which):
            log.info("PASSWORD %s for '%s' - automatic redial paused so the account is not locked; traffic stays blocked. "
                     "Store the right password in the system's VPN settings, then Turn on or Reconnect.",
                     "MISSING" if which == "missing" else "REJECTED", profile)

    def on_event_up(self, profile: str) -> None:
        if profile not in self.base.names:
            return
        self.store.clear_auth_failed()                         # connected: whatever was wrong with the password is fixed
        if profile != self.cfg.profile:
            self.store.set_active(profile)
            log.info("'%s' connected - now the active profile", profile)
        self.arm()

    def on_event_down(self, profile: str, user_requested: bool) -> None:
        if profile != self.cfg.profile:
            log.info("VPN '%s' went down - not the active profile, ignored", profile)
            return
        if nm.is_connected(profile):
            log.info("VPN '%s' reported down but is connected - ignored", profile)
            return
        off = self._take_off_marker()
        renewing = self._take_renew_marker()
        deliberate = off or (user_requested and not renewing)
        if renewing and not off:
            log.info("VPN '%s' went down by VeroScudo's own Reconnect - not your Off", profile)
        self.off_marker.unlink(missing_ok=True)
        d = decide(deliberate, self.store.armed)
        log.info("VPN '%s' terminated (user_requested=%s) -> %s (decision source: %s)", profile, deliberate, d.value,
                 "veroscudo off" if off else "NetworkManager reason")
        # the status window's "Last drop": why, in the words the Windows tray uses for its RAS event
        self.store.record_drop(profile, "turned off" if off else "Reconnect" if renewing else
                               "you disconnected" if deliberate else "connection lost")
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
                    log.info("WireGuard '%s': no handshake for over 3 minutes - restarting it", self.cfg.profile)
                    self.store.record_drop(self.cfg.profile, "no WireGuard handshake for 3 min")
                    # our own take-down: NetworkManager reports it as user-requested - the renew marker keeps it from
                    # reading as your Off (without it the guard disarmed itself here)
                    self.renew_marker.write_text(str(time.time()))
                    nm.down(self.cfg.profile)
                if nm.up(self.cfg.profile):
                    nm.wait_connected(self.cfg.profile)
                if nm.is_connected(self.cfg.profile):
                    if self.cfg.current.vpn_type == hiddify.KIND:
                        log.info("Hiddify connected again - traffic goes through it")       # nothing was dialed
                    else:
                        log.info("reconnected '%s' after %d attempt(s)", self.cfg.profile, attempt)
                    break
                log.info("attempt %d failed", attempt)
                self._lookup_next = True                     # the server may have moved: look it up with the next block
                if self.attempts is not None and attempt >= self.attempts:
                    log.info("still not connected - traffic stays blocked; the VeroScudo service keeps redialing every %d s",
                             self.cfg.retry_seconds)
                    break
                time.sleep(self.cfg.retry_seconds)
            if not self.store.armed:
                log.info("disarmed during reconnect - stopping")
        finally:
            self.store.release_lock()
        if self.store.armed and nm.is_connected(self.cfg.profile):
            self._say_once("wait", None)                       # the next drop is told again
            self.enable_killswitch(tunnel_up=True)

    def watchdog(self) -> None:
        self.reload_config()
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
            return 5.0 if not chk.enabled else min(5.0, chk.interval_seconds)
        results = quality.run_round(chk.targets, tls=cfg.current.vpn_type == hiddify.KIND)   # Hiddify answers ping/TCP itself
        try:
            self.stats.checks(len(results), sum(1 for ok, _ in results if not ok), cfg.current.id, cfg.profile)
        except OSError:
            log.exception("statistics")
        q = self.quality.add_round(chk, cfg.profile, results, down_at=self.store.last_down())
        if q.state != "checking" and q.state != self.quality.last_state:
            log.info("connection quality: %s (%s of %s checks lost, %s)", q.state, q.lost, q.checks,
                     f"{q.rtt_ms} ms" if q.rtt_ms is not None else "no answer")
            self.quality.last_state = q.state
        return float(chk.interval_seconds)

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
        self.watchdog()

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
