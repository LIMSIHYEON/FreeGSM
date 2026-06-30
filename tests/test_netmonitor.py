"""NetworkMonitor reaction to route changes (the trigger side of the v6 fix).

Verifies the monitor fires tunnel.reapply_routes -- with the right v6 args -- when
the default route changes, and is silent when nothing moved. The tunnel and the
route-reading shell-outs are faked, so no root or real network is involved.
"""

from __future__ import annotations

import unittest
from unittest import mock

try:
    from dohproxy.macos import netmonitor
except Exception:  # noqa: BLE001 - netmonitor pulls socks_proxy -> httpx
    netmonitor = None


class _FakeTun:
    def __init__(self, gw="10.0.0.1", iface="en0", gw6=None, iface6=None):
        self._cur = (gw, iface, gw6, iface6)
        self.reapplied: list[tuple] = []

    def current(self):
        return self._cur

    def reapply_routes(self, gw, iface, gw6=None, iface6=None):
        self.reapplied.append((gw, iface, gw6, iface6))


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

    def test_network_down_skips_reapply(self):
        tun = _FakeTun()
        mon = netmonitor.NetworkMonitor(tun)
        self._patch_routes((None, None), (None, None))
        mon._tick()
        self.assertEqual(tun.reapplied, [])


if __name__ == "__main__":
    unittest.main()
