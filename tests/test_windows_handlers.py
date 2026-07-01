"""Windows WinDivert packet handlers (udp_handler / tcp_proxy / https_proxy).

These modules do the packet surgery that the CLAUDE.md "Packet dispatch" and
"Invariants" sections describe: swap a captured query into its reply in place
(UDP), or rewrite an outbound client->server packet's destination to a local
relay port and inject it INBOUND, remembering the real server so the relay's
reply can be rewritten back (TCP/53 + TCP/443). The invariants under test:

  * injected packets must carry direction == INBOUND (loopback inject is what
    the local stack delivers to our listener);
  * a redirect must NOT re-match the capture filter -- redirected queries carry
    dst == relay-port (not 53/443), rewritten replies carry src == the real
    server (53/443);
  * fail-closed on a DoH error (drop) unless FAIL_OPEN forwards the plaintext;
  * the per-relay _conn_map is keyed by (src_addr, src_port) and cleaned up on
    RST/FIN; an unknown reply is dropped, never leaked.

pydivert is pure-Python (the WinDivert kernel driver only loads when a handle is
actually opened), so these import and their rewrite logic runs on any OS. A
faked Packet exercises it with no live capture. If pydivert is absent the whole
module is skipped.
"""

from __future__ import annotations

import unittest
from unittest import mock

try:
    from dohproxy import config, udp_handler, tcp_proxy, https_proxy
    from pydivert.consts import Direction
except Exception as exc:  # noqa: BLE001 - pydivert may be absent in this env
    udp_handler = None
    _IMPORT_ERR = exc


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #
class _TCP:
    def __init__(self, rst=False, fin=False) -> None:
        self.rst = rst
        self.fin = fin


class FakePacket:
    """Stand-in for a pydivert Packet: just the attributes the handlers touch."""

    def __init__(self, src_addr, dst_addr, src_port, dst_port, *,
                 payload=b"", is_outbound=True, direction=None, rst=False, fin=False):
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.src_port = src_port
        self.dst_port = dst_port
        self.payload = payload
        self.is_outbound = is_outbound
        self.direction = direction
        self.tcp = _TCP(rst, fin)


class Sender:
    """Records injected packets so tests can assert send()/drop behaviour."""

    def __init__(self) -> None:
        self.sent: list = []

    def __call__(self, packet) -> None:
        self.sent.append(packet)


# --------------------------------------------------------------------------- #
# UDP/53 -- in-place query -> reply synthesis
# --------------------------------------------------------------------------- #
@unittest.skipIf(udp_handler is None, "pydivert not importable here")
class UdpHandlerTest(unittest.TestCase):
    def _pkt(self):
        return FakePacket("1.2.3.4", "8.8.8.8", 5000, 53, payload=b"\x12\x34query")

    def test_success_swaps_into_inbound_reply(self):
        pkt, send = self._pkt(), Sender()
        answer = b"\x12\x34\x81\x80answer"
        with mock.patch.object(udp_handler.dnscache, "resolve", return_value=answer):
            udp_handler.handle(pkt, send)
        self.assertEqual(send.sent, [pkt])
        # Addresses/ports swapped so the reply is client<-server:53.
        self.assertEqual((pkt.src_addr, pkt.src_port), ("8.8.8.8", 53))
        self.assertEqual((pkt.dst_addr, pkt.dst_port), ("1.2.3.4", 5000))
        self.assertEqual(pkt.payload, answer)
        self.assertEqual(pkt.direction, Direction.INBOUND)

    def test_fail_closed_drops_on_doh_error(self):
        pkt, send = self._pkt(), Sender()
        with mock.patch.object(udp_handler.config, "FAIL_OPEN", False), \
             mock.patch.object(udp_handler.dnscache, "resolve",
                               side_effect=RuntimeError("down")):
            udp_handler.handle(pkt, send)
        self.assertEqual(send.sent, [], "a DoH error must not leak a reply")
        self.assertEqual(pkt.payload, b"\x12\x34query", "packet must be untouched")

    def test_fail_open_forwards_original_plaintext(self):
        pkt, send = self._pkt(), Sender()
        with mock.patch.object(udp_handler.config, "FAIL_OPEN", True), \
             mock.patch.object(udp_handler.dnscache, "resolve",
                               side_effect=RuntimeError("down")):
            udp_handler.handle(pkt, send)
        # Original query forwarded unchanged (still outbound to :53).
        self.assertEqual(send.sent, [pkt])
        self.assertEqual((pkt.dst_addr, pkt.dst_port), ("8.8.8.8", 53))
        self.assertEqual(pkt.payload, b"\x12\x34query")

    def test_empty_payload_is_ignored(self):
        pkt = FakePacket("1.2.3.4", "8.8.8.8", 5000, 53, payload=b"")
        send = Sender()
        resolve = mock.Mock()
        with mock.patch.object(udp_handler.dnscache, "resolve", resolve):
            udp_handler.handle(pkt, send)
        self.assertEqual(send.sent, [])
        resolve.assert_not_called()


# --------------------------------------------------------------------------- #
# TCP/53 -- redirect to local proxy + reply rewrite
# --------------------------------------------------------------------------- #
@unittest.skipIf(udp_handler is None, "pydivert not importable here")
class TcpProxyTest(unittest.TestCase):
    def setUp(self) -> None:
        tcp_proxy._conn_map.clear()

    def test_outbound_query_redirected_to_proxy_port(self):
        pkt = FakePacket("1.2.3.4", "8.8.8.8", 5000, 53, is_outbound=True)
        send = Sender()
        tcp_proxy.handle_packet(pkt, send)
        # Remembered the real server, keyed by the client's (addr, port).
        self.assertEqual(tcp_proxy._conn_map[("1.2.3.4", 5000)], ("8.8.8.8", 53))
        # Redirected at the host's own IP on the proxy port (not 53 -> won't
        # re-match the filter), injected INBOUND.
        self.assertEqual(pkt.dst_addr, "1.2.3.4")
        self.assertEqual(pkt.dst_port, config.TCP_PROXY_PORT)
        self.assertEqual(pkt.direction, Direction.INBOUND)
        self.assertEqual(send.sent, [pkt])

    def test_reply_rewritten_back_to_real_server(self):
        tcp_proxy._conn_map[("1.2.3.4", 5000)] = ("8.8.8.8", 53)
        # Proxy -> client packet: src is the proxy port, dst is the client.
        pkt = FakePacket("1.2.3.4", "1.2.3.4", config.TCP_PROXY_PORT, 5000,
                         is_outbound=False)
        send = Sender()
        tcp_proxy.handle_packet(pkt, send)
        # Source rewritten back to server:53 so the client's socket accepts it.
        self.assertEqual((pkt.src_addr, pkt.src_port), ("8.8.8.8", 53))
        self.assertEqual(pkt.direction, Direction.INBOUND)
        self.assertEqual(send.sent, [pkt])

    def test_unknown_reply_is_dropped(self):
        pkt = FakePacket("1.2.3.4", "1.2.3.4", config.TCP_PROXY_PORT, 5000,
                         is_outbound=False)
        send = Sender()
        tcp_proxy.handle_packet(pkt, send)  # _conn_map empty
        self.assertEqual(send.sent, [], "a reply for an unknown flow must be dropped")

    def test_rst_on_redirect_forgets_the_mapping(self):
        pkt = FakePacket("1.2.3.4", "8.8.8.8", 5000, 53, is_outbound=True, rst=True)
        tcp_proxy.handle_packet(pkt, Sender())
        self.assertNotIn(("1.2.3.4", 5000), tcp_proxy._conn_map)

    def test_fin_on_reply_forgets_the_mapping(self):
        tcp_proxy._conn_map[("1.2.3.4", 5000)] = ("8.8.8.8", 53)
        pkt = FakePacket("1.2.3.4", "1.2.3.4", config.TCP_PROXY_PORT, 5000,
                         is_outbound=False, fin=True)
        tcp_proxy.handle_packet(pkt, Sender())
        self.assertNotIn(("1.2.3.4", 5000), tcp_proxy._conn_map)

    def test_unmatched_packet_passes_through(self):
        # Neither an outbound :53 query nor a reply from the proxy port.
        pkt = FakePacket("1.2.3.4", "8.8.8.8", 999, 53, is_outbound=False)
        send = Sender()
        tcp_proxy.handle_packet(pkt, send)
        self.assertEqual(send.sent, [pkt])
        self.assertIsNone(pkt.direction, "a passed-through packet must be untouched")


# --------------------------------------------------------------------------- #
# TCP/443 -- SNI relay redirect + reply rewrite
# --------------------------------------------------------------------------- #
@unittest.skipIf(udp_handler is None, "pydivert not importable here")
class HttpsProxyTest(unittest.TestCase):
    def setUp(self) -> None:
        https_proxy._conn_map.clear()

    def test_outbound_443_redirected_to_relay_port(self):
        pkt = FakePacket("1.2.3.4", "93.184.216.34", 6000, 443, is_outbound=True)
        send = Sender()
        https_proxy.handle_packet(pkt, send)
        self.assertEqual(https_proxy._conn_map[("1.2.3.4", 6000)],
                         ("93.184.216.34", 443))
        self.assertEqual(pkt.dst_addr, "1.2.3.4")
        self.assertEqual(pkt.dst_port, config.HTTPS_PROXY_PORT)
        self.assertEqual(pkt.direction, Direction.INBOUND)
        self.assertEqual(send.sent, [pkt])

    def test_reply_rewritten_back_to_server_443(self):
        https_proxy._conn_map[("1.2.3.4", 6000)] = ("93.184.216.34", 443)
        pkt = FakePacket("1.2.3.4", "1.2.3.4", config.HTTPS_PROXY_PORT, 6000,
                         is_outbound=False)
        send = Sender()
        https_proxy.handle_packet(pkt, send)
        self.assertEqual((pkt.src_addr, pkt.src_port), ("93.184.216.34", 443))
        self.assertEqual(pkt.direction, Direction.INBOUND)
        self.assertEqual(send.sent, [pkt])

    def test_unknown_reply_is_dropped(self):
        pkt = FakePacket("1.2.3.4", "1.2.3.4", config.HTTPS_PROXY_PORT, 6000,
                         is_outbound=False)
        send = Sender()
        https_proxy.handle_packet(pkt, send)
        self.assertEqual(send.sent, [])

    def test_rst_on_redirect_forgets_the_mapping(self):
        pkt = FakePacket("1.2.3.4", "93.184.216.34", 6000, 443,
                         is_outbound=True, rst=True)
        https_proxy.handle_packet(pkt, Sender())
        self.assertNotIn(("1.2.3.4", 6000), https_proxy._conn_map)

    def test_unmatched_packet_passes_through(self):
        pkt = FakePacket("1.2.3.4", "93.184.216.34", 6000, 443, is_outbound=False)
        send = Sender()
        https_proxy.handle_packet(pkt, send)
        self.assertEqual(send.sent, [pkt])
        self.assertIsNone(pkt.direction)


if __name__ == "__main__":
    unittest.main()
