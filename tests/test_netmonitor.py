"""NetworkMonitor reaction to route changes (the trigger side of the v6 fix).

Verifies the monitor fires tunnel.reapply_routes -- with the right v6 args -- when
the default route changes, and is silent when nothing moved. The tunnel and the
route-reading shell-outs are faked, so no root or real network is involved.
"""

from __future__ import annotations

import socket
import threading
import unittest
from unittest import mock

try:
    from dohproxy.macos import netmonitor
except Exception:  # noqa: BLE001 - netmonitor pulls socks_proxy -> httpx
    netmonitor = None


class _FakeTun:
    def __init__(self, gw="10.0.0.1", iface="en0", gw6=None, iface6=None, stolen=None):
        self._cur = (gw, iface, gw6, iface6)
        self.reapplied: list[tuple] = []
        self.stolen = stolen or []  # device_routes_intact() return value

    def current(self):
        return self._cur

    def reapply_routes(self, gw, iface, gw6=None, iface6=None):
        self.reapplied.append((gw, iface, gw6, iface6))

    def device_routes_intact(self):
        return self.stolen


@unittest.skipIf(netmonitor is None, "netmonitor (httpx) not importable here")
class NetMonitorTest(unittest.TestCase):
    def setUp(self):
        # Silence the always-on DNS reconcile and pin SOCKS re-pin to a no-op.
        for name in ("dns_control.reconcile", "socks_proxy.set_bound_iface"):
            mod, attr = name.split(".")
            p = mock.patch.object(getattr(netmonitor, mod), attr, return_value=None)
            p.start()
            self.addCleanup(p.stop)

    def _patch_routes(self, v4, v6):
        p4 = mock.patch.object(netmonitor.tunnel, "default_route", return_value=v4)
        p6 = mock.patch.object(netmonitor.tunnel, "default_route6", return_value=v6)
        p4.start(); p6.start()
        self.addCleanup(p4.stop); self.addCleanup(p6.stop)

    def test_v6_acquired_midsession_triggers_reapply_with_v6(self):
        tun = _FakeTun(gw="10.0.0.1", iface="en0", gw6=None, iface6=None)
        mon = netmonitor.NetworkMonitor(tun)
        # v4 unchanged, but a v6 default route just appeared.
        self._patch_routes(("10.0.0.1", "en0"), ("fe80::1%en0", "en0"))
        with mock.patch.object(netmonitor.config, "TUNNEL_IPV6", True):
            mon._tick()
        self.assertEqual(tun.reapplied, [("10.0.0.1", "en0", "fe80::1%en0", "en0")])

    def test_no_change_is_silent(self):
        tun = _FakeTun(gw="10.0.0.1", iface="en0", gw6="fe80::1%en0", iface6="en0")
        mon = netmonitor.NetworkMonitor(tun)
        self._patch_routes(("10.0.0.1", "en0"), ("fe80::1%en0", "en0"))
        with mock.patch.object(netmonitor.config, "TUNNEL_IPV6", True):
            mon._tick()
        self.assertEqual(tun.reapplied, [])

    def test_v6_ignored_when_tunnel_ipv6_disabled(self):
        tun = _FakeTun(gw="10.0.0.1", iface="en0", gw6=None, iface6=None)
        mon = netmonitor.NetworkMonitor(tun)
        self._patch_routes(("10.0.0.1", "en0"), ("fe80::1%en0", "en0"))
        with mock.patch.object(netmonitor.config, "TUNNEL_IPV6", False):
            mon._tick()
        self.assertEqual(tun.reapplied, [])  # v6 not consulted -> nothing moved

    def test_network_down_skips_reapply_but_forgets_last_route(self):
        # Link down: no reapply this tick, but the last-applied route is cleared so
        # the recovery is treated as a change even if it lands on the same gateway
        # (macOS flushes our interface-scoped routes when the interface drops).
        tun = _FakeTun(gw="10.0.0.1", iface="en0")
        mon = netmonitor.NetworkMonitor(tun)
        self._patch_routes((None, None), (None, None))
        mon._tick()
        self.assertEqual(tun.reapplied, [])
        self.assertEqual(mon._last_v4, (None, None))
        self.assertEqual(mon._last_v6, (None, None))

    def test_link_bounce_to_same_gateway_reapplies(self):
        # A Wi-Fi/Ethernet bounce that returns to the SAME gateway still flushes
        # the interface-scoped routes, so the monitor must rebuild them: a down
        # tick then an up tick (identical gateway) => exactly one reapply.
        tun = _FakeTun(gw="10.0.0.1", iface="en0")  # seeds _last = (10.0.0.1, en0)
        mon = netmonitor.NetworkMonitor(tun)
        with mock.patch.object(netmonitor.config, "TUNNEL_IPV6", False):
            self._patch_routes((None, None), (None, None))
            mon._tick()                                   # link down
            self.assertEqual(tun.reapplied, [])
            self._patch_routes(("10.0.0.1", "en0"), (None, None))
            mon._tick()                                   # link back, same gateway
        self.assertEqual(tun.reapplied, [("10.0.0.1", "en0", None, None)])

    def test_device_route_hijack_warns_once_then_clears(self):
        # A VPN stole our /1 override: the gateway is unchanged (so no reapply) but
        # the monitor must still warn -- once -- that the splitter is bypassed.
        tun = _FakeTun(gw="10.0.0.1", iface="en0", stolen=["0/1 -> utun9"])
        mon = netmonitor.NetworkMonitor(tun)
        self._patch_routes(("10.0.0.1", "en0"), (None, None))
        with mock.patch.object(netmonitor.config, "TUNNEL_IPV6", False):
            with self.assertLogs("dohproxy.macos.monitor", level="WARNING") as cm:
                mon._tick()
            self.assertTrue(any("BYPASSED" in m for m in cm.output))
            self.assertTrue(mon._device_warned)
            # Still stolen next tick: no duplicate warning.
            with mock.patch.object(netmonitor.log, "warning") as warn:
                mon._tick()
                warn.assert_not_called()
            # Routes recovered: flag clears.
            tun.stolen = []
            mon._tick()
            self.assertFalse(mon._device_warned)

    def test_reverse_vpn_bypass_warns_once_then_clears(self):
        # A full-tunnel VPN is up: route get default -> gateway-less via a foreign
        # utun. Our /1 overrides shadow it and the SOCKS pin stays on the physical
        # link, so app TCP bypasses the VPN (real IP leaks). Warn once; recover
        # when a real gateway returns.
        tun = _FakeTun(gw="10.0.0.1", iface="en0")
        mon = netmonitor.NetworkMonitor(tun)
        with mock.patch.object(netmonitor.config, "TUNNEL_IPV6", False):
            self._patch_routes((None, "utun4"), (None, None))
            with self.assertLogs("dohproxy.macos.monitor", level="WARNING") as cm:
                mon._tick()
            self.assertTrue(any("BYPASSES the VPN" in m for m in cm.output))
            self.assertTrue(mon._reverse_vpn_warned)
            self.assertEqual(tun.reapplied, [])  # gateway-less -> no reapply
            # Still bypassing next tick: no duplicate warning.
            with mock.patch.object(netmonitor.log, "warning") as warn:
                mon._tick()
                warn.assert_not_called()
            # VPN gone, real gateway back: flag clears and traffic reapplies.
            self._patch_routes(("10.0.0.1", "en0"), (None, None))
            mon._tick()
            self.assertFalse(mon._reverse_vpn_warned)

    def test_genuine_link_down_is_not_a_reverse_bypass(self):
        # No default route at all (iface is None) is a link-down, not a VPN
        # shadowing us -- it must NOT trip the reverse-bypass warning.
        tun = _FakeTun(gw="10.0.0.1", iface="en0")
        mon = netmonitor.NetworkMonitor(tun)
        with mock.patch.object(netmonitor.config, "TUNNEL_IPV6", False):
            self._patch_routes((None, None), (None, None))
            with mock.patch.object(netmonitor.log, "warning") as warn:
                mon._tick()
                warn.assert_not_called()
        self.assertFalse(mon._reverse_vpn_warned)

    def test_our_own_utun_default_is_not_a_reverse_bypass(self):
        # A gateway-less default via OUR OWN tunnel device is us, not a foreign
        # VPN -- excluded so we never warn about ourselves.
        tun = _FakeTun(gw="10.0.0.1", iface="en0")
        mon = netmonitor.NetworkMonitor(tun)
        with mock.patch.object(netmonitor.config, "TUNNEL_IPV6", False):
            self._patch_routes((None, netmonitor.config.TUN_DEVICE), (None, None))
            with mock.patch.object(netmonitor.log, "warning") as warn:
                mon._tick()
                warn.assert_not_called()
        self.assertFalse(mon._reverse_vpn_warned)


@unittest.skipIf(netmonitor is None, "netmonitor (httpx) not importable here")
class NetMonitorLoopTest(unittest.TestCase):
    """The route-socket-driven wake-up loop and its polling fallback."""

    def test_route_message_triggers_a_tick(self):
        # Feed the loop a fake routing socket (one end of a socketpair) and write
        # to it to simulate a kernel route message; the loop must run a tick.
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        a.setblocking(False)
        fired = threading.Event()
        mon = netmonitor.NetworkMonitor(None)
        with mock.patch.object(mon, "_open_route_socket", return_value=a), \
             mock.patch.object(netmonitor, "_SETTLE", 0.01), \
             mock.patch.object(mon, "_tick", side_effect=lambda: fired.set()):
            mon.start()
            b.send(b"\x00" * 16)  # simulate a routing message
            self.assertTrue(fired.wait(2.0), "route message did not trigger a tick")
            mon.stop()
        self.assertFalse(mon._thread.is_alive())

    def test_polling_fallback_ticks_when_no_route_socket(self):
        fired = threading.Event()
        mon = netmonitor.NetworkMonitor(None)
        with mock.patch.object(mon, "_open_route_socket", return_value=None), \
             mock.patch.object(netmonitor.config, "MONITOR_INTERVAL", 0.02), \
             mock.patch.object(mon, "_tick", side_effect=lambda: fired.set()):
            mon.start()
            self.assertTrue(fired.wait(2.0), "polling fallback never ticked")
            mon.stop()
        self.assertFalse(mon._thread.is_alive())

    def test_stop_is_clean_when_idle(self):
        # No route traffic and a long interval: stop() must still wake the select
        # and join promptly via the self-pipe rather than waiting out the floor.
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        a.setblocking(False)
        mon = netmonitor.NetworkMonitor(None)
        with mock.patch.object(mon, "_open_route_socket", return_value=a), \
             mock.patch.object(netmonitor.config, "MONITOR_INTERVAL", 30.0):
            mon.start()
            mon.stop()
        self.assertFalse(mon._thread.is_alive())

    def test_drain_empties_pending_messages(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        a.setblocking(False)
        b.send(b"x" * 32)
        netmonitor._drain(a)  # must not raise and must consume the backlog
        with self.assertRaises(BlockingIOError):
            a.recv(4096)


if __name__ == "__main__":
    unittest.main()
