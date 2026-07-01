"""Network-change monitor for the macOS port.

macOS hands the default route around as the active link changes (Wi-Fi <->
Ethernet, joining/leaving a network, a DHCP renew that moves the gateway). When
that happens, the tunnel's gateway/interface-dependent routes and the SOCKS
proxy's IP_BOUND_IF pin go stale, so the proxy's upstream sockets start failing
with ENETUNREACH and the DoH host-route excludes the wrong gateway. The system
DNS can also drift: a service added after start is never repointed, and a DHCP
renew can reset a service's DNS off the local resolver.

It reacts on a change by:

  * re-applying the tunnel's ifscope/DoH-exclude routes for the new gateway and
    re-pinning the SOCKS upstream to the new interface (DPI runs only); this also
    brings the IPv6 device redirect up when a v6 default route is acquired
    mid-session (e.g. a VPN coming up) and tears it down when v6 is lost, so v6
    HTTPS gets the same SNI fragmentation without needing a restart;
  * re-asserting the local resolver across all network services (always, even
    DoH-only) via dns_control.reconcile().

Wake-up is event-driven: it reads the kernel PF_ROUTE socket, which emits a
message the instant a route is added/changed/deleted, so a network switch is
reconciled in well under a second instead of waiting out a poll. A periodic
timeout (MONITOR_INTERVAL) still fires as a floor to catch drift a route message
can't signal (a DHCP renew that changes only a service's DNS). If the routing
socket can't be opened it degrades to pure interval polling.

It is a daemon thread; stop() ends it (waking the select via a self-pipe).
Teardown stops it FIRST so it can't race the route/DNS restore by re-adding what
teardown is removing.
"""

from __future__ import annotations

import logging
import os
import select
import socket
import threading

from .. import config
from . import dns_control, socks_proxy, tunnel

log = logging.getLogger("dohproxy.macos.monitor")

# macOS PF_ROUTE address family (sys/socket.h). socket.AF_ROUTE exists on Darwin
# but fall back to the literal so this never NameErrors on an odd build.
_AF_ROUTE = getattr(socket, "AF_ROUTE", 17)
# After a route message, wait this long (interruptibly) before reading the
# default route: a single network switch emits a burst of messages and the new
# default may not be installed at the first one, so let it settle and coalesce.
_SETTLE = 0.4


class NetworkMonitor:
    def __init__(self, tun: "tunnel.Tunnel | None" = None) -> None:
        self._tun = tun
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._wake_r: int | None = None
        self._wake_w: int | None = None
        # Last default route we reconciled against. Seed from the tunnel's
        # as-built routes so the first poll only fires on a genuine change.
        if tun is not None:
            gw, iface, gw6, iface6 = tun.current()
            self._last_v4 = (gw, iface)
            self._last_v6 = (gw6, iface6)
        else:
            self._last_v4 = (None, None)
            self._last_v6 = (None, None)
        # Whether we have already warned that our default-override routes were
        # hijacked (a VPN taking over the default). Warn once per transition.
        self._device_warned = False

    def start(self) -> None:
        self._wake_r, self._wake_w = os.pipe()
        self._thread = threading.Thread(
            target=self._loop, name="net-monitor", daemon=True
        )
        self._thread.start()
        log.info("network-change monitor started (route-socket + %.0fs floor)",
                 config.MONITOR_INTERVAL)

    def _open_route_socket(self) -> socket.socket | None:
        """Open the kernel routing socket, or None if unavailable (then poll)."""
        try:
            s = socket.socket(_AF_ROUTE, socket.SOCK_RAW, 0)
            s.setblocking(False)
            return s
        except OSError as exc:
            log.info("routing socket unavailable (%s); polling every %.0fs",
                     exc, config.MONITOR_INTERVAL)
            return None

    def _loop(self) -> None:
        rsock = self._open_route_socket()
        if rsock is None:
            self._poll_loop()
            return
        try:
            while not self._stop.is_set():
                try:
                    readable, _, _ = select.select(
                        [rsock, self._wake_r], [], [], config.MONITOR_INTERVAL
                    )
                except (OSError, ValueError):
                    break  # a fd was closed under us (stop)
                if self._stop.is_set() or self._wake_r in readable:
                    break
                if rsock in readable:
                    _drain(rsock)
                    # Let the route table settle and coalesce the burst; bail
                    # immediately if stop() fires during the wait.
                    if self._stop.wait(_SETTLE):
                        break
                # Both a route event and the periodic timeout reconcile: the timer
                # is the floor that catches DNS drift a route message can't signal.
                self._safe_tick()
        finally:
            rsock.close()

    def _poll_loop(self) -> None:
        # Fallback when the routing socket can't be opened: Event.wait doubles as
        # the sleep AND the stop signal, so teardown isn't delayed by a poll.
        while not self._stop.wait(config.MONITOR_INTERVAL):
            self._safe_tick()

    def _safe_tick(self) -> None:
        try:
            self._tick()
        except Exception:  # noqa: BLE001 - a bad poll must not kill the monitor
            log.exception("network monitor tick failed")

    def _tick(self) -> None:
        # Always keep the system DNS pointed at the local resolver. Cheap and
        # useful even DoH-only (covers a freshly added/renewed network service).
        try:
            dns_control.reconcile()
        except Exception:  # noqa: BLE001
            log.exception("DNS reconcile failed")

        if self._tun is None or self._stop.is_set():
            return

        # A VPN using the same /1 default-override trick can steal our device
        # routes without changing the 0/0 default (so the gateway compare below
        # wouldn't notice). Check every tick and warn once per transition -- app
        # traffic then bypasses the SNI splitter until the conflict is resolved.
        self._check_device_routes()

        gw, iface = tunnel.default_route()
        if not gw or not iface:
            return  # network is momentarily down; wait for it to come back
        gw6, iface6 = (tunnel.default_route6()
                       if config.TUNNEL_IPV6 else (None, None))

        if (gw, iface) == self._last_v4 and (gw6, iface6) == self._last_v6:
            return  # nothing moved

        log.warning("default route changed -> %s via %s%s; re-applying tunnel",
                    gw, iface,
                    f" / v6 {gw6} via {iface6}" if gw6 else "")
        self._tun.reapply_routes(gw, iface, gw6, iface6)
        socks_proxy.set_bound_iface(iface)
        self._last_v4 = (gw, iface)
        self._last_v6 = (gw6, iface6)

    def _check_device_routes(self) -> None:
        """Warn once when a VPN/other tool steals our default-override routes (SNI
        splitting silently bypassed), and note recovery once they return."""
        if self._tun is None:
            return
        try:
            stolen = self._tun.device_routes_intact()
        except Exception:  # noqa: BLE001 - a bad probe must not kill the monitor
            return
        if stolen and not self._device_warned:
            log.warning("default-override route(s) no longer point at the tunnel "
                        "(%s); another VPN/tool has taken over the default route, so "
                        "SNI fragmentation is BYPASSED for that traffic. Disable the "
                        "conflicting tunnel, or FreeGSM's DPI, to avoid the conflict.",
                        ", ".join(stolen))
            self._device_warned = True
        elif not stolen and self._device_warned:
            log.info("default-override routes back on the tunnel; SNI fragmentation "
                     "restored.")
            self._device_warned = False

    def stop(self) -> None:
        self._stop.set()
        # Wake the select() so it returns immediately instead of waiting out the
        # interval. Best-effort; the loop also re-checks _stop.
        if self._wake_w is not None:
            try:
                os.write(self._wake_w, b"x")
            except OSError:
                pass
        t = self._thread
        if t is not None:
            t.join(timeout=2)
        for fd in (self._wake_r, self._wake_w):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self._wake_r = self._wake_w = None


def _drain(rsock: socket.socket) -> None:
    """Discard all pending routing messages so select() doesn't re-fire on the
    same backlog. We don't parse them -- any message just means 'routes moved,
    re-check the default route'."""
    while True:
        try:
            if not rsock.recv(4096):
                return
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            return
