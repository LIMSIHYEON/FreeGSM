"""Network-change monitor for the macOS port.

macOS hands the default route around as the active link changes (Wi-Fi <->
Ethernet, joining/leaving a network, a DHCP renew that moves the gateway). When
that happens, the tunnel's gateway/interface-dependent routes and the SOCKS
proxy's IP_BOUND_IF pin go stale, so the proxy's upstream sockets start failing
with ENETUNREACH and the DoH host-route excludes the wrong gateway. The system
DNS can also drift: a service added after start is never repointed, and a DHCP
renew can reset a service's DNS off the local resolver.

This polls the default route on a fixed interval and, on a change:

  * re-applies the tunnel's ifscope/DoH-exclude routes for the new gateway and
    re-pins the SOCKS upstream to the new interface (DPI runs only); this also
    brings the IPv6 device redirect up when a v6 default route is acquired
    mid-session (e.g. a VPN coming up) and tears it down when v6 is lost, so v6
    HTTPS gets the same SNI fragmentation without needing a restart;
  * re-asserts the local resolver across all network services (always, even
    DoH-only) via dns_control.reconcile().

It is a daemon thread; stop() ends it. Teardown stops it FIRST so it can't race
the route/DNS restore by re-adding what teardown is removing.
"""

from __future__ import annotations

import logging
import threading

from .. import config
from . import dns_control, socks_proxy, tunnel

log = logging.getLogger("dohproxy.macos.monitor")


class NetworkMonitor:
    def __init__(self, tun: "tunnel.Tunnel | None" = None) -> None:
        self._tun = tun
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # Last default route we reconciled against. Seed from the tunnel's
        # as-built routes so the first poll only fires on a genuine change.
        if tun is not None:
            gw, iface, gw6, iface6 = tun.current()
            self._last_v4 = (gw, iface)
            self._last_v6 = (gw6, iface6)
        else:
            self._last_v4 = (None, None)
            self._last_v6 = (None, None)

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._loop, name="net-monitor", daemon=True
        )
        self._thread.start()
        log.info("network-change monitor started (every %.0fs)", config.MONITOR_INTERVAL)

    def _loop(self) -> None:
        # Event.wait doubles as the sleep AND the stop signal: it returns True the
        # instant stop() is called, so teardown isn't delayed by a poll interval.
        while not self._stop.wait(config.MONITOR_INTERVAL):
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

    def stop(self) -> None:
        self._stop.set()
        t = self._thread
        if t is not None:
            t.join(timeout=2)
