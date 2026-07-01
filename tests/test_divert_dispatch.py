"""WinDivert capture-loop packet classification (Diverter._dispatch).

_dispatch is the fork in the capture loop (CLAUDE.md "Packet dispatch"): it
decides, per captured packet, whether it is a UDP/53 query (offload to the DoH
thread pool), a TCP packet for the HTTPS splitting relay, a TCP packet for the
DNS proxy, or something to pass through untouched. This test pins that routing
table down without opening a real WinDivert handle: a bare Diverter is built with
__new__, given a synchronous stand-in pool and a send collector, and the three
downstream handlers are mocked so each assertion is purely "which one fired".

The gate that matters most is DPI_BYPASS: only when it is on do outbound :443 and
the relay's own replies (src == HTTPS_PROXY_PORT) go to the HTTPS relay; with it
off, all TCP is DNS. divert imports pydivert (pure-Python; the kernel driver only
loads on open()), so it imports on macOS; the module skips if pydivert is absent.
"""

from __future__ import annotations

import unittest
from unittest import mock

try:
    from dohproxy import config, divert
except Exception as exc:  # noqa: BLE001 - pydivert may be absent in this env
    divert = None
    _IMPORT_ERR = exc


class FakePool:
    """Runs submitted work synchronously so the UDP handler mock records its
    call inline (the real pool offloads the blocking DoH round-trip)."""

    def submit(self, fn, *args):
        fn(*args)


class Sender:
    def __init__(self) -> None:
        self.sent: list = []

    def __call__(self, packet) -> None:
        self.sent.append(packet)


class FakePacket:
    """Only the fields _dispatch inspects. udp/tcp mirror pydivert's
    ``packet.udp``/``packet.tcp`` accessors (None when not that protocol)."""

    def __init__(self, *, udp=False, tcp=False, src_port=0, dst_port=0,
                 is_outbound=True):
        self.udp = object() if udp else None
        self.tcp = object() if tcp else None
        self.src_port = src_port
        self.dst_port = dst_port
        self.is_outbound = is_outbound


@unittest.skipIf(divert is None, "pydivert not importable here")
class DispatchTest(unittest.TestCase):
    def setUp(self) -> None:
        self.d = divert.Diverter.__new__(divert.Diverter)
        self.d._pool = FakePool()
        self.sender = Sender()
        self.d._send = self.sender

    def _dispatch(self, pkt, dpi=True):
        """Route ``pkt`` with the three handlers mocked; return (udp, tcp, https)."""
        with mock.patch.object(divert.config, "DPI_BYPASS", dpi), \
             mock.patch.object(divert.udp_handler, "handle") as udp, \
             mock.patch.object(divert.tcp_proxy, "handle_packet") as tcp, \
             mock.patch.object(divert.https_proxy, "handle_packet") as https:
            self.d._dispatch(pkt)
        return udp, tcp, https

    # --- UDP ---------------------------------------------------------------- #
    def test_outbound_udp_53_goes_to_udp_handler(self):
        pkt = FakePacket(udp=True, dst_port=53, is_outbound=True)
        udp, tcp, https = self._dispatch(pkt)
        udp.assert_called_once_with(pkt, self.d._send)
        tcp.assert_not_called()
        https.assert_not_called()
        self.assertEqual(self.sender.sent, [], "UDP/53 must not be passed through")

    def test_inbound_udp_53_is_passed_through(self):
        # Only *outbound* :53 is a query to upgrade; an inbound one isn't ours.
        pkt = FakePacket(udp=True, dst_port=53, is_outbound=False)
        udp, tcp, https = self._dispatch(pkt)
        udp.assert_not_called()
        self.assertEqual(self.sender.sent, [pkt])

    def test_udp_non_53_is_passed_through(self):
        pkt = FakePacket(udp=True, dst_port=443, is_outbound=True)
        udp, tcp, https = self._dispatch(pkt)
        udp.assert_not_called()
        tcp.assert_not_called()
        https.assert_not_called()
        self.assertEqual(self.sender.sent, [pkt])

    # --- TCP, DPI on -------------------------------------------------------- #
    def test_outbound_tcp_443_goes_to_https_relay(self):
        pkt = FakePacket(tcp=True, dst_port=443, is_outbound=True)
        udp, tcp, https = self._dispatch(pkt, dpi=True)
        https.assert_called_once_with(pkt, self.d._send)
        tcp.assert_not_called()

    def test_relay_reply_goes_to_https_relay(self):
        # The relay's own reply leg (src == HTTPS_PROXY_PORT), even inbound.
        pkt = FakePacket(tcp=True, src_port=config.HTTPS_PROXY_PORT, is_outbound=False)
        udp, tcp, https = self._dispatch(pkt, dpi=True)
        https.assert_called_once_with(pkt, self.d._send)
        tcp.assert_not_called()

    def test_tcp_53_goes_to_tcp_proxy(self):
        pkt = FakePacket(tcp=True, dst_port=53, is_outbound=True)
        udp, tcp, https = self._dispatch(pkt, dpi=True)
        tcp.assert_called_once_with(pkt, self.d._send)
        https.assert_not_called()

    # --- TCP, DPI off ------------------------------------------------------- #
    def test_dpi_off_routes_443_to_tcp_proxy(self):
        # With the SNI relay disabled, the HTTPS gate is closed, so even a :443
        # packet falls through to the DNS proxy path.
        pkt = FakePacket(tcp=True, dst_port=443, is_outbound=True)
        udp, tcp, https = self._dispatch(pkt, dpi=False)
        https.assert_not_called()
        tcp.assert_called_once_with(pkt, self.d._send)

    # --- Neither -------------------------------------------------------------#
    def test_non_tcp_udp_is_passed_through(self):
        pkt = FakePacket(udp=False, tcp=False)  # e.g. ICMP
        udp, tcp, https = self._dispatch(pkt)
        udp.assert_not_called()
        tcp.assert_not_called()
        https.assert_not_called()
        self.assertEqual(self.sender.sent, [pkt])


if __name__ == "__main__":
    unittest.main()
