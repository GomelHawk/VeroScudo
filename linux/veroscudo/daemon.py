"""The guard: arms on connect, decides on disconnect, redials forever while armed and down."""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

from . import firewall, nm
from .config import Config
from .state import Decision, StateStore, decide

log = logging.getLogger("veroscudo")


class Guard:
    def __init__(self, cfg: Config, store: StateStore | None = None) -> None:
        self.cfg = cfg
        self.store = store or StateStore()
        self.off_marker = self.store.home / "off.marker"     # set by `veroscudo off` so a polling backend knows it was deliberate
        self._loop_thread: threading.Thread | None = None

    # ---- firewall ------------------------------------------------------------
    def vm_wanted(self) -> bool:
        if self.cfg.vm == "auto":
            return Path("/var/run/docker.sock").exists() or Path("/run/libvirt").exists()
        return bool(self.cfg.vm)

    def enable_killswitch(self, tunnel_up: bool) -> None:
        ips = nm.resolve(self.cfg.server)
        if ips:
            self.store.server_ip.write_text("\n".join(ips))
        elif self.store.server_ip.exists():
            ips = self.store.server_ip.read_text().split()
        else:
            log.warning("cannot resolve %s and no cached IP", self.cfg.server)
        tun = nm.iface(self.cfg.profile) if tunnel_up else None
        firewall.apply(firewall.render_ruleset(self.cfg, ips, tun, vm_allowed=tunnel_up and self.vm_wanted()))
        log.info("kill-switch ON (tunnel=%s, vm=%s)", tun, "allowed" if tunnel_up else "blocked")

    def disable_killswitch(self) -> None:
        firewall.clear()
        log.info("kill-switch OFF (firewall restored)")

    def boot(self) -> None:
        """Before the network starts: if armed, put the kill-switch back. No DNS here - cached server IPs only;
        the daemon re-resolves and redials once NetworkManager is up."""
        if not self.store.armed:
            return
        ips = self.store.server_ip.read_text().split() if self.store.server_ip.exists() else []
        firewall.apply(firewall.render_ruleset(self.cfg, ips, None, vm_allowed=False))
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
            log.info("disconnected by user (off)")

    def on_event_down(self, user_requested: bool) -> None:
        deliberate = user_requested or self.off_marker.exists()
        self.off_marker.unlink(missing_ok=True)
        d = decide(deliberate, self.store.armed)
        log.info("VPN terminated (user_requested=%s) -> %s", deliberate, d.value)
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
        """Blocked + redial forever, until the tunnel is up or the user turns the VPN off."""
        if self.store.lock_alive():
            log.info("reconnect loop already running")
            return
        self.store.take_lock()
        attempt = 0
        try:
            while self.store.armed and not nm.is_connected(self.cfg.profile):
                attempt += 1
                self.enable_killswitch(tunnel_up=False)
                nm.up(self.cfg.profile)
                if nm.is_connected(self.cfg.profile):
                    log.info("reconnected after %d attempt(s)", attempt)
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
            self.enable_killswitch(nm.is_connected(self.cfg.profile))
            if not nm.is_connected(self.cfg.profile):
                self.reconnect_async()
        elif firewall.is_active():
            log.info("disarmed but kill-switch still active - restoring")
            self.disable_killswitch()

    # ---- main loop -----------------------------------------------------------
    def run(self) -> None:
        log.info("VeroScudo daemon for profile '%s'", self.cfg.profile)
        self.watchdog()

        def tick():
            while True:
                time.sleep(300)
                try:
                    self.watchdog()
                except Exception:
                    log.exception("watchdog")

        threading.Thread(target=tick, daemon=True).start()
        nm.watch(self.cfg.profile, on_up=self.arm, on_down=self.on_event_down)
