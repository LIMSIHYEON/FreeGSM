"""pf plaintext-DNS kill switch (the DPI-off fail-closed fix).

Covers the generated ruleset, token parsing, and the install/restore command
sequencing -- without root and without touching the real pf or /Library: pfctl
(pf_control._run) is replaced with a recorder and the state-file paths are
redirected into a temp dir.
"""

from __future__ import annotations

import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from dohproxy.macos import pf_control


class _Pfctl:
    """Records each pfctl argv. Returns success by default; ``-E`` carries a
    token on stderr. ``fail_on`` forces a non-zero return for a given flag."""

    def __init__(self, fail_on: str | None = None, token: str = "777") -> None:
        self.calls: list[list[str]] = []
        self.fail_on = fail_on
        self.token = token

    def __call__(self, args):
        self.calls.append(list(args))
        rc = 1 if (self.fail_on and self.fail_on in args) else 0
        stderr = f"Token : {self.token}\n" if args[:1] == ["-E"] else ""
        if rc != 0:
            stderr = "pfctl: error"
        return types.SimpleNamespace(returncode=rc, stdout="", stderr=stderr)

    def flags(self) -> list[str]:
        """First element of each recorded argv (the pfctl flag)."""
        return [c[0] for c in self.calls if c]


class PfRulesetTest(unittest.TestCase):
    def test_ruleset_blocks_plaintext_dns_both_families(self):
        rs = pf_control.build_ruleset()
        # Drops UDP and TCP :53 to non-loopback, v4 and v6.
        self.assertIn("block drop out quick proto udp from any to !127.0.0.0/8 port = 53", rs)
        self.assertIn("block drop out quick proto tcp from any to !127.0.0.0/8 port = 53", rs)
        self.assertIn("block drop out quick proto udp from any to !::1 port = 53", rs)
        self.assertIn("block drop out quick proto tcp from any to !::1 port = 53", rs)

    def test_translation_anchors_precede_filter_rules(self):
        # pf requires nat/rdr (translation) rules before block (filter) rules; a
        # ruleset with block before nat-anchor fails to load.
        rs = pf_control.build_ruleset()
        self.assertLess(rs.index("nat-anchor"), rs.index("block drop"))
        self.assertLess(rs.index("rdr-anchor"), rs.index("block drop"))
        # Apple's anchors are preserved so system features keep working.
        self.assertIn('load anchor "com.apple" from "/etc/pf.anchors/com.apple"', rs)

    def test_quic_block_is_opt_in_and_udp_443_only(self):
        # Default ruleset does not touch :443 at all.
        rs = pf_control.build_ruleset()
        self.assertNotIn("port = 443", rs)
        # With QUIC on, UDP/443 to non-loopback is dropped for both families...
        rq = pf_control.build_ruleset(block_quic=True)
        self.assertIn("block drop out quick proto udp from any to !127.0.0.0/8 port = 443", rq)
        self.assertIn("block drop out quick proto udp from any to !::1 port = 443", rq)
        # ...but TCP/443 is NEVER blocked (that would kill all HTTPS, incl. DoH).
        self.assertNotIn("proto tcp from any to !127.0.0.0/8 port = 443", rq)

    def test_quic_only_omits_dns_block(self):
        # QUIC-only (DNS block off): :53 rules absent, :443 present, anchors intact.
        rs = pf_control.build_ruleset(block_dns=False, block_quic=True)
        self.assertNotIn("port = 53", rs)
        self.assertIn("port = 443", rs)
        self.assertLess(rs.index("nat-anchor"), rs.index("block drop"))

    def test_parse_token(self):
        self.assertEqual(pf_control._parse_token("Token : 12345\n"), "12345")
        self.assertEqual(pf_control._parse_token("pf enabled\nToken : 9\n"), "9")
        self.assertIsNone(pf_control._parse_token("no token here"))


class PfLifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        tmp = Path(self._tmp.name)
        # Redirect every on-disk path into the temp dir.
        for name, val in (("_STATE_DIR", tmp),
                          ("RULES_FILE", tmp / "freegsm.pf.conf"),
                          ("MARKER_FILE", tmp / "pf_state.json")):
            p = mock.patch.object(pf_control, name, val)
            p.start()
            self.addCleanup(p.stop)
        # Reset module state between tests.
        pf_control._active = False
        pf_control._token = None
        self.addCleanup(setattr, pf_control, "_active", False)
        self.addCleanup(setattr, pf_control, "_token", None)
        self.addCleanup(self._tmp.cleanup)

    def _install(self, pf: _Pfctl) -> bool:
        with mock.patch.object(pf_control, "_run", pf):
            return pf_control.install()

    def _restore(self, pf: _Pfctl) -> None:
        with mock.patch.object(pf_control, "_run", pf):
            pf_control.restore()

    def test_install_loads_rules_then_enables(self):
        pf = _Pfctl()
        self.assertTrue(self._install(pf))
        self.assertTrue(pf_control._active)
        self.assertEqual(pf_control._token, "777")
        # Order: load our ruleset (-f), then enable (-E).
        self.assertEqual(pf.flags(), ["-f", "-E"])
        self.assertTrue(pf_control.RULES_FILE.exists())
        self.assertTrue(pf_control.MARKER_FILE.exists())

    def test_restore_reloads_system_then_releases_token(self):
        pf = _Pfctl()
        self._install(pf)
        pf2 = _Pfctl()
        self._restore(pf2)
        # System ruleset reloaded first, then our enable reference released.
        self.assertEqual(pf2.calls[0], ["-f", pf_control.SYSTEM_PF_CONF])
        self.assertIn(["-X", "777"], pf2.calls)
        self.assertFalse(pf_control._active)
        self.assertFalse(pf_control.MARKER_FILE.exists())

    def test_install_rolls_back_when_enable_fails(self):
        pf = _Pfctl(fail_on="-E")
        self.assertFalse(self._install(pf))
        self.assertFalse(pf_control._active)
        # After a failed enable we reload the system ruleset to undo the load.
        self.assertEqual(pf.calls[-1], ["-f", pf_control.SYSTEM_PF_CONF])
        self.assertFalse(pf_control.MARKER_FILE.exists())

    def test_install_aborts_when_rule_load_fails(self):
        pf = _Pfctl(fail_on="-f")
        self.assertFalse(self._install(pf))
        self.assertFalse(pf_control._active)
        # We never reach -E when the load fails.
        self.assertNotIn("-E", pf.flags())

    def test_restore_is_noop_when_never_installed(self):
        pf = _Pfctl()
        self._restore(pf)
        # Nothing of ours to undo -> pf is not touched at all.
        self.assertEqual(pf.calls, [])

    def test_install_is_idempotent(self):
        pf = _Pfctl()
        self.assertTrue(self._install(pf))
        n = len(pf.calls)
        self.assertTrue(self._install(pf))  # second call: already active
        self.assertEqual(len(pf.calls), n)

    def test_install_refuses_when_no_block_requested(self):
        pf = _Pfctl()
        with mock.patch.object(pf_control, "_run", pf):
            self.assertFalse(pf_control.install(block_dns=False, block_quic=False))
        self.assertFalse(pf_control._active)
        self.assertEqual(pf.calls, [])  # pf untouched

    def test_install_writes_requested_quic_rules(self):
        pf = _Pfctl()
        with mock.patch.object(pf_control, "_run", pf):
            self.assertTrue(pf_control.install(block_dns=False, block_quic=True))
        rs = pf_control.RULES_FILE.read_text(encoding="utf-8")
        self.assertIn("port = 443", rs)
        self.assertNotIn("port = 53", rs)

    def test_restore_uses_persisted_token_after_crash(self):
        # Simulate a crashed run: marker on disk, no in-memory state.
        pf_control.MARKER_FILE.write_text('{"token": "555"}', encoding="utf-8")
        pf_control._active = False
        pf_control._token = None
        pf = _Pfctl()
        self._restore(pf)
        self.assertIn(["-X", "555"], pf.calls)
        self.assertFalse(pf_control.MARKER_FILE.exists())


if __name__ == "__main__":
    unittest.main()
