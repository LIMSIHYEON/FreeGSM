"""VPN coexistence hardening: primary-resolver leak detection + device-route
hijack detection.

Two silent failures a VPN can cause once FreeGSM is running:
  * a full-tunnel VPN sets DNS via configd (invisible to networksetup), so the
    effective primary resolver stops being 127.0.0.1 and lookups leak past DoH --
    dns_control.verify_primary_resolver() surfaces that;
  * a VPN using the same 0/1 + 128/1 default-override trick steals our device
    routes, so app traffic bypasses the SNI splitter -- tunnel.device_routes_intact()
    (and the monitor's warn-once wrapper) surfaces that.

Everything shells out; scutil / netstat are faked, so no root or real VPN needed.
"""

from __future__ import annotations

import types
import unittest
from unittest import mock

from dohproxy.macos import dns_control, tunnel


def _ns(stdout: str = "", rc: int = 0) -> types.SimpleNamespace:
    return types.SimpleNamespace(returncode=rc, stdout=stdout, stderr="")


# --------------------------------------------------------------------------- #
# scutil --dns primary-resolver parsing
# --------------------------------------------------------------------------- #
_SCUTIL_LOCAL = """\
DNS configuration

resolver #1
  nameserver[0] : 127.0.0.1
  flags    : Request A records, Request AAAA records
  reach    : 0x00030002 (Reachable,Local Address)
"""

_SCUTIL_VPN = """\
DNS configuration

resolver #1
  nameserver[0] : 10.8.0.1
  if_index : 14 (utun4)
  flags    : Request A records, Request AAAA records
"""


class PrimaryResolverParseTest(unittest.TestCase):
    def _scutil(self, out: str, rc: int = 0):
        return mock.patch.object(dns_control.subprocess, "run", return_value=_ns(out, rc))

    def test_reads_first_nameserver(self):
        with self._scutil(_SCUTIL_LOCAL):
            self.assertEqual(dns_control.primary_resolver(), "127.0.0.1")

    def test_reads_vpn_resolver(self):
        with self._scutil(_SCUTIL_VPN):
            self.assertEqual(dns_control.primary_resolver(), "10.8.0.1")

    def test_none_when_absent(self):
        with self._scutil("DNS configuration\n\nresolver #1\n  domain : local\n"):
            self.assertIsNone(dns_control.primary_resolver())

    def test_none_on_subprocess_error(self):
        with mock.patch.object(dns_control.subprocess, "run",
                               side_effect=OSError("boom")):
            self.assertIsNone(dns_control.primary_resolver())


class VerifyPrimaryResolverTest(unittest.TestCase):
    def setUp(self):
        dns_control._primary_leak_warned = False
        self.addCleanup(setattr, dns_control, "_primary_leak_warned", False)

    def test_ok_when_local(self):
        with mock.patch.object(dns_control, "primary_resolver", return_value="127.0.0.1"):
            self.assertTrue(dns_control.verify_primary_resolver())
        self.assertFalse(dns_control._primary_leak_warned)

    def test_ok_when_unreadable(self):
        # An unreadable resolver must not raise a false leak warning.
        with mock.patch.object(dns_control, "primary_resolver", return_value=None):
            self.assertTrue(dns_control.verify_primary_resolver())
        self.assertFalse(dns_control._primary_leak_warned)

    def test_warns_once_on_leak_then_recovers(self):
        with mock.patch.object(dns_control, "primary_resolver", return_value="10.8.0.1"):
            with self.assertLogs("dohproxy.macos.dns", level="WARNING") as cm:
                self.assertFalse(dns_control.verify_primary_resolver())
            self.assertTrue(any("bypass" in m for m in cm.output))
            self.assertTrue(dns_control._primary_leak_warned)
            # Second call while still leaking: no new warning (warn-once).
            with mock.patch.object(dns_control.log, "warning") as warn:
                self.assertFalse(dns_control.verify_primary_resolver())
                warn.assert_not_called()
        # Resolver returns to ours -> flag clears.
        with mock.patch.object(dns_control, "primary_resolver", return_value="127.0.0.1"):
            self.assertTrue(dns_control.verify_primary_resolver())
        self.assertFalse(dns_control._primary_leak_warned)


# --------------------------------------------------------------------------- #
# tunnel device-route hijack detection
# --------------------------------------------------------------------------- #
_NETSTAT_V4_OURS = """\
Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            10.0.0.1           UGScg          en0
0/1                198.18.0.1         UGSc       utun123
127                127.0.0.1          UCS            lo0
128/1              198.18.0.1         UGSc       utun123
"""

_NETSTAT_V4_STOLEN = """\
Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            10.0.0.1           UGScg          en0
0/1                10.9.0.1           UGSc         utun9
128/1              10.9.0.1           UGSc         utun9
"""

_NETSTAT_V6_OURS = """\
Routing tables

Internet6:
Destination                    Gateway                Flags        Netif Expire
::/1                           fe80::1%utun123        UGc        utun123
8000::/1                       fe80::1%utun123        UGc        utun123
"""


class _Netstat:
    """Fakes tunnel._run for netstat, returning a v4/v6 table per the -f family."""

    def __init__(self, v4: str, v6: str = _NETSTAT_V6_OURS) -> None:
        self._v4, self._v6 = v4, v6

    def __call__(self, args, check=True):
        if "inet6" in args:
            return _ns(self._v6)
        return _ns(self._v4)


class DeviceRoutesIntactTest(unittest.TestCase):
    def _tunnel(self, v6_up: bool = False) -> tunnel.Tunnel:
        t = tunnel.Tunnel("/nonexistent/tun2socks")
        t._dev = "utun123"
        t._v6_up = v6_up
        return t

    def test_intact_when_all_ours(self):
        t = self._tunnel()
        with mock.patch.object(tunnel, "_run", _Netstat(_NETSTAT_V4_OURS)):
            self.assertEqual(t.device_routes_intact(), [])

    def test_detects_v4_hijack(self):
        t = self._tunnel()
        with mock.patch.object(tunnel, "_run", _Netstat(_NETSTAT_V4_STOLEN)):
            stolen = t.device_routes_intact()
        self.assertEqual(stolen, ["0/1 -> utun9", "128/1 -> utun9"])

    def test_v6_checked_only_when_v6_up(self):
        stolen_v6 = _NETSTAT_V6_OURS.replace("utun123", "utun9")
        # v6 down: v6 table ignored even if hijacked.
        t = self._tunnel(v6_up=False)
        with mock.patch.object(tunnel, "_run", _Netstat(_NETSTAT_V4_OURS, stolen_v6)):
            self.assertEqual(t.device_routes_intact(), [])
        # v6 up: the v6 hijack is now reported.
        t2 = self._tunnel(v6_up=True)
        with mock.patch.object(tunnel, "_run", _Netstat(_NETSTAT_V4_OURS, stolen_v6)):
            self.assertEqual(t2.device_routes_intact(),
                             ["::/1 -> utun9", "8000::/1 -> utun9"])

    def test_missing_route_is_not_reported_as_hijack(self):
        # A /1 route simply absent (owner None) is not a hijack -- only a route
        # pointing at a *different* interface is.
        t = self._tunnel()
        v4_missing = "Routing tables\n\nInternet:\nDestination Gateway Flags Netif\n" \
                     "default 10.0.0.1 UGScg en0\n"
        with mock.patch.object(tunnel, "_run", _Netstat(v4_missing)):
            self.assertEqual(t.device_routes_intact(), [])


if __name__ == "__main__":
    unittest.main()
