"""Tunnel IPv6 device-redirect lifecycle (the mid-session-v6 fix).

These cover the behaviour that closes the "IPv6 acquired mid-session is not
redirected until restart" gap: reapply_routes() must bring the ::/1 + 8000::/1
device redirect (and the utun's v6 address) up when a v6 default route appears
after start, and tear it down when v6 is lost -- without ever re-adding the utun
address or stacking duplicate routes.

No root or real network needed: tunnel._run (every route/ifconfig shell-out) is
replaced with a recorder that reports success.
"""

from __future__ import annotations

import types
import unittest
from unittest import mock

from dohproxy.macos import tunnel


def _ok(stderr: str = "") -> types.SimpleNamespace:
    return types.SimpleNamespace(returncode=0, stdout="", stderr=stderr)


class _Recorder:
    """Stands in for tunnel._run, capturing each argv and returning success."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def __call__(self, args, check=True):  # noqa: D401 - mimics _run signature
        self.calls.append(list(args))
        return _ok()

    def with_dest(self, verb: str):
        """All route argv (minus the leading route/-n/verb) for 'add' or 'delete'."""
        out = []
        for c in self.calls:
            if c[:1] == ["route"] and verb in c:
                out.append(c)
        return out


def _v6_device_adds(rec: _Recorder):
    return [c for c in rec.calls
            if "add" in c and "::/1" in " ".join(c) or "8000::/1" in " ".join(c)]


class TunnelIPv6Test(unittest.TestCase):
    def setUp(self) -> None:
        self.rec = _Recorder()
        patcher = mock.patch.object(tunnel, "_run", self.rec)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.t = tunnel.Tunnel("/nonexistent/tun2socks")
        # Pretend the v4 tunnel is already up on en0; _proc stays None so no
        # crash-state file is written (that path needs root).
        self.t._gw, self.t._iface = "10.0.0.1", "en0"

    def _added_routes_text(self) -> str:
        return "\n".join(" ".join(c) for c in self.rec.calls if "add" in c)

    def _has_route_add(self, needle: str) -> bool:
        return any("add" in c and needle in " ".join(c) for c in self.rec.calls)

    def _has_route_delete(self, needle: str) -> bool:
        return any("delete" in c and needle in " ".join(c) for c in self.rec.calls)

    # -- mid-session acquisition -------------------------------------------- #
    def test_v6_acquired_midsession_brings_up_device_redirect(self):
        self.assertFalse(self.t._v6_up)
        self.t.reapply_routes("10.0.0.1", "en0", "fe80::1%en0", "en0")
        self.assertTrue(self.t._v6_up)
        # utun got a v6 address and both /1 halves point at the device.
        self.assertTrue(any("inet6" in c and "ifconfig" in c for c in self.rec.calls),
                        "utun should be given a v6 address")
        self.assertTrue(self._has_route_add("::/1"))
        self.assertTrue(self._has_route_add("8000::/1"))
        # The device routes are tracked for cleanup but kept OUT of the scoped set
        # (so a later v4-only change doesn't tear them down).
        self.assertEqual(len(self.t._v6_device), 2)
        for r in self.t._v6_device:
            self.assertNotIn(r, self.t._scoped)
            self.assertIn(r, self.t._routes)

    def test_reapply_with_same_v6_is_idempotent(self):
        self.t.reapply_routes("10.0.0.1", "en0", "fe80::1%en0", "en0")
        first = len(self.t._routes)
        addr_calls = sum(1 for c in self.rec.calls if "inet6" in c and "ifconfig" in c)
        self.t.reapply_routes("10.0.0.1", "en0", "fe80::1%en0", "en0")
        # No second utun-address add, no duplicate device routes.
        self.assertEqual(sum(1 for c in self.rec.calls if "inet6" in c and "ifconfig" in c),
                         addr_calls)
        self.assertEqual(len(self.t._v6_device), 2)
        # _routes grows only by the rebuilt scoped routes, never by extra ::/1s.
        self.assertEqual(self.t._routes.count(["-inet6", "-net", "::/1",
                                               "-interface", self.t._dev]), 1)

    # -- mid-session loss --------------------------------------------------- #
    def test_v6_lost_midsession_tears_down_device_redirect(self):
        self.t.reapply_routes("10.0.0.1", "en0", "fe80::1%en0", "en0")
        self.assertTrue(self.t._v6_up)
        self.t.reapply_routes("10.0.0.1", "en0", None, None)
        self.assertFalse(self.t._v6_up)
        self.assertEqual(self.t._v6_device, [])
        self.assertTrue(self._has_route_delete("::/1"))
        self.assertTrue(self._has_route_delete("8000::/1"))
        # The torn-down device routes are no longer tracked for deletion on stop().
        self.assertNotIn(["-inet6", "-net", "::/1", "-interface", self.t._dev],
                         self.t._routes)

    def test_v6_reacquired_after_loss_does_not_re_add_utun_address(self):
        self.t.reapply_routes("10.0.0.1", "en0", "fe80::1%en0", "en0")
        self.t.reapply_routes("10.0.0.1", "en0", None, None)
        addr_calls = sum(1 for c in self.rec.calls if "inet6" in c and "ifconfig" in c)
        self.t.reapply_routes("10.0.0.1", "en0", "fe80::1%en0", "en0")
        # Address already added once -> not re-added; device routes back up.
        self.assertEqual(sum(1 for c in self.rec.calls if "inet6" in c and "ifconfig" in c),
                         addr_calls)
        self.assertTrue(self.t._v6_up)
        self.assertEqual(len(self.t._v6_device), 2)

    # -- v4-only change must not disturb v6 --------------------------------- #
    def test_v4_only_change_keeps_v6_device_routes(self):
        self.t.reapply_routes("10.0.0.1", "en0", "fe80::1%en0", "en0")
        before = list(self.t._v6_device)
        # Wi-Fi -> Ethernet, same v6 gateway: device routes must remain intact.
        self.t.reapply_routes("192.168.1.1", "en1", "fe80::1%en0", "en0")
        self.assertTrue(self.t._v6_up)
        self.assertEqual(self.t._v6_device, before)

    # -- teardown ----------------------------------------------------------- #
    def test_stop_clears_v6_state(self):
        self.t.reapply_routes("10.0.0.1", "en0", "fe80::1%en0", "en0")
        self.t.stop()
        self.assertFalse(self.t._v6_up)
        self.assertEqual(self.t._v6_device, [])
        self.assertEqual(self.t._routes, [])

    def test_disabled_when_no_v6_default(self):
        # A reapply that never had v6 stays v6-down and touches no v6 device routes.
        self.t.reapply_routes("10.0.0.1", "en0", None, None)
        self.assertFalse(self.t._v6_up)
        self.assertFalse(self._has_route_add("::/1"))


if __name__ == "__main__":
    unittest.main()
