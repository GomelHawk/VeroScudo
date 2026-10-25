"""The guard: arms on connect, decides on disconnect, redials forever while armed and down, keeps the ruleset exact."""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

from .backend import firewall, nm
from .config import Config
from .state import Decision, StateStore, decide

log = logging.getLogger("veroscudo")
WATCHDOG_SECONDS = 15


class Guard:
    def __init__(self, cfg: Config, store: StateStore | None = None) -> None:
        self.base = cfg
        self.store = store or StateStore()
        self.off_marker = self.store.home / "off.marker"     # set by `veroscudo off` so a polling backend knows it was deliberate
        self._loop_thread: threading.Thread | None = None
        self._applied: str | None = None
        self._lock = threading.Lock()

    @property
    def cfg(self) -> Config:
        """The configuration with the current runtime profile selection (it changes on a switch, from any process)."""
        active = self.store.active
        return self.base.with_active(active) if active in self.base.names else self.base

    # ---- firewall ------------------------------------------------------------
    def vm_wanted(self) -> bool:
        if self.cfg.vm == "auto":
            return Path("/var/run/docker.sock").exists() or Path("/run/libvirt").exists()
        return bool(self.cfg.vm)

    def server_ips(self, cfg: Config) -> list[str]:
        """Pinned addresses win. Otherwise resolve and merge with the cache (newest first, at most 8): a moved VPN host keeps
        working and a lookup that fails while blocked still leaves the last known addresses."""
        if cfg.server_ips:
            return list(cfg.server_ips)
        cache = self.store.server_cache(cfg.profile)
        cached: list[str] = []
        for f in (cache, self.store.server_ip):
            if f.exists():
                cached = f.read_text().split()
                break
        merged = list(dict.fromkeys(nm.resolve(cfg.server) + cached))[:8]
        if merged and merged != cached:
            cache.write_text("\n".join(merged))
        if not merged:
            log.warning("cannot resolve %s and no cached IP", cfg.server)
        return merged

    def desired_ruleset(self, tunnel_up: bool) -> str:
        cfg = self.cfg
        tun = nm.iface(cfg.profile) if tunnel_up else None
        dns = None if tun else firewall.DnsPolicy(nm.resolver_uid(), tuple(nm.nameservers()))
        return firewall.render_ruleset(cfg, self.server_ips(cfg), tun, vm_allowed=bool(tun) and self.vm_wanted(), dns=dns)

    def enable_killswitch(self, tunnel_up: bool, force: bool = False) -> None:
        """Applies the ruleset when it differs from what is in force or when the table went missing (a `nft flush ruleset`
        by another tool). Atomic: nft -f replaces the table in one transaction."""
        with self._lock:
            rs = self.desired_ruleset(tunnel_up)
            if not force and rs == self._applied and firewall.is_active():
                return
            firewall.apply(rs)
            why = "armed" if self._applied is None else ("changed" if rs != self._applied else "table was missing")
            self._applied = rs
            tun = 'oifname "' in rs.split("chain forward")[0]
            log.info("kill-switch %s (profile=%s, tunnel=%s)", why, self.cfg.profile, "up" if tun else "DOWN")

    def disable_killswitch(self) -> None:
        with self._lock:
            firewall.clear()
            self._applied = None
        log.info("kill-switch OFF (firewall restored)")

    def boot(self) -> None:
        """Before the network starts: if armed, put the kill-switch back. No DNS here - cached server IPs only;
        the daemon re-resolves and redials once NetworkManager is up."""
        if not self.store.armed:
            return
        cfg = self.cfg
        ips = list(cfg.server_ips)
        for f in (self.store.server_cache(cfg.profile), self.store.server_ip):
            if not ips and f.exists():
                ips = f.read_text().split()
        firewall.apply(firewall.render_ruleset(cfg, ips, None, vm_allowed=False, dns=firewall.DnsPolicy()))
        log.info("boot: armed - kill-switch ON before the network starts (server %s)", ", ".join(ips) or "not cached")

    # ---- actions -------------------------------------------------------------
    def arm(self) -> None:
        if self.store.set_armed(True):
            log.info("ARMED")
        self.enable_killswitch(nm.is_connected(self.cfg.profile))

    def disarm(self) -> None:
        if self.store.set_armed(False):
            log.info("DISARMED")
        self.disable_killswitch()

    def on(self) -> None:
        self.arm()
        if not nm.is_connected(self.cfg.profile):
            self.reconnect()

    def off(self) -> None:
        self.off_marker.touch()
        self.disarm()
        if nm.is_connected(self.cfg.profile):
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

    def on_event_up(self, profile: str) -> None:
        if profile not in self.base.names:
            return
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
        deliberate = user_requested or self.off_marker.exists()
        self.off_marker.unlink(missing_ok=True)
        d = decide(deliberate, self.store.armed)
        log.info("VPN '%s' terminated (user_requested=%s) -> %s", profile, deliberate, d.value)
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
                attempt += 1
                self.enable_killswitch(tunnel_up=False)
                nm.up(self.cfg.profile)
                if nm.is_connected(self.cfg.profile):
                    log.info("reconnected '%s' after %d attempt(s)", self.cfg.profile, attempt)
                    break
                log.info("attempt %d failed", attempt)
                time.sleep(self.cfg.retry_seconds)
            if not self.store.armed:
                log.info("disarmed during reconnect - stopping")
        finally:
            self.store.release_lock()
        if self.store.armed and nm.is_connected(self.cfg.profile):
            self.enable_killswitch(tunnel_up=True)

    def watchdog(self) -> None:
        if self.store.armed:
            up = nm.is_connected(self.cfg.profile)
            self.enable_killswitch(up)
            if not up and not self.store.lock_alive():
                self.reconnect_async()
        elif firewall.is_active():
            log.info("disarmed but kill-switch still active - restoring")
            self.disable_killswitch()

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
        nm.watch(lambda: set(self.base.names), on_up=self.on_event_up, on_down=self.on_event_down)
