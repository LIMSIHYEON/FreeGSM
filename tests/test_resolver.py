"""Local loopback DoH resolver (dohproxy/macos/resolver.py).

This is the macOS DNS path that replaces the Windows udp_handler/tcp_proxy: it
receives plaintext DNS on 127.0.0.1 and re-resolves every query over DoH. The
contracts that matter here are fail-closed (a DoH error drops the query, never
answers in plaintext), TC-truncation of an oversized UDP answer (so the client
retries over TCP instead of relying on droppable IP fragmentation), and correct
length-prefixed framing on the TCP stream.

DoH is faked at ``dnscache.resolve`` so no network / httpx round-trip happens.
resolver imports dnscache -> doh -> httpx; if httpx is absent (e.g. a
Windows-only dev box) the whole module is skipped rather than failing import.
"""

from __future__ import annotations

import struct
import unittest
from unittest import mock

try:
    from dohproxy.macos import resolver
    from dohproxy import dnsutil
except Exception as exc:  # noqa: BLE001 - httpx/doh may be absent in this env
    resolver = None
    _IMPORT_ERR = exc


# --------------------------------------------------------------------------- #
# Wire-format helpers
# --------------------------------------------------------------------------- #
def _name(s: str) -> bytes:
    out = b""
    for label in s.split("."):
        if label:
            out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def query(name="example.com", qtype=1, qclass=1, txid=0x1234) -> bytes:
    """A minimal, parseable DNS query with no OPT record (512-byte UDP limit)."""
    hdr = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # RD, QD=1
    return hdr + _name(name) + struct.pack("!HH", qtype, qclass)


def frame(msg: bytes) -> bytes:
    """A DNS-over-TCP frame: 2-byte length prefix + message (RFC 7766)."""
    return struct.pack("!H", len(msg)) + msg


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #
class FakeUDPSocket:
    def __init__(self) -> None:
        self.sent: list = []  # (data, addr)
        self.fail = False

    def sendto(self, data, addr):
        if self.fail:
            raise OSError("send failed")
        self.sent.append((data, addr))


class FakeStream:
    """A blocking-stream stand-in: recv() drains a fixed buffer, sendall()
    records, and settimeout() is a no-op. An empty buffer reads as EOF."""

    def __init__(self, incoming: bytes) -> None:
        self._buf = bytearray(incoming)
        self.sent = bytearray()

    def recv(self, n: int) -> bytes:
        if not self._buf:
            return b""
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def sendall(self, data) -> None:
        self.sent += data

    def settimeout(self, _t) -> None:
        pass


@unittest.skipIf(resolver is None, "resolver (httpx/doh) not importable here")
class UDPResolveTest(unittest.TestCase):
    def setUp(self) -> None:
        self.r = resolver._UDPResolver()
        self.r._sock = FakeUDPSocket()
        self.client = ("127.0.0.1", 5300)

    def tearDown(self) -> None:
        self.r._pool.shutdown(wait=False)

    def test_success_replies_with_doh_answer(self):
        q = query()
        answer = b"\x12\x34\x81\x80answer-bytes"  # small: under the 512 limit
        with mock.patch.object(resolver.dnscache, "resolve", return_value=answer):
            self.r._resolve_and_reply(q, self.client)
        self.assertEqual(self.r._sock.sent, [(answer, self.client)])

    def test_fail_closed_sends_nothing_on_doh_error(self):
        q = query()
        with mock.patch.object(resolver.dnscache, "resolve",
                               side_effect=RuntimeError("upstream down")):
            self.r._resolve_and_reply(q, self.client)
        self.assertEqual(self.r._sock.sent, [], "a DoH error must not leak a reply")

    def test_oversized_answer_is_truncated_for_tcp_retry(self):
        q = query()  # no OPT -> 512-byte UDP limit
        big = b"\x12\x34\x81\x80" + b"\x00" * 600  # > 512
        with mock.patch.object(resolver.dnscache, "resolve", return_value=big):
            self.r._resolve_and_reply(q, self.client)
        self.assertEqual(len(self.r._sock.sent), 1)
        reply, addr = self.r._sock.sent[0]
        self.assertEqual(addr, self.client)
        # The client should get the minimal TC=1 response, not the oversized one.
        self.assertEqual(reply, dnsutil.truncated_response(q))
        self.assertTrue(reply[2] & 0x02, "TC bit must be set")
        self.assertTrue(reply[2] & 0x80, "QR bit must be set")

    def test_edns_advertised_size_is_respected(self):
        # A client advertising a 4096 EDNS payload should NOT get truncated at
        # 512; a ~1KB answer fits under its advertised limit.
        q = query()
        q = q[:10] + struct.pack("!H", 1) + q[12:]  # ARCOUNT = 1
        q += b"\x00" + struct.pack("!HHIH", 41, 4096, 0, 0)  # OPT, udpsize 4096
        answer = b"\x12\x34\x81\x80" + b"\x00" * 1000  # > 512 but < 4096
        with mock.patch.object(resolver.dnscache, "resolve", return_value=answer):
            self.r._resolve_and_reply(q, self.client)
        self.assertEqual(self.r._sock.sent, [(answer, self.client)])


@unittest.skipIf(resolver is None, "resolver (httpx/doh) not importable here")
class TCPResolveTest(unittest.TestCase):
    def _serve(self, incoming: bytes, resolve):
        sock = FakeStream(incoming)
        handler = resolver._TCPHandler.__new__(resolver._TCPHandler)
        with mock.patch.object(resolver.dnscache, "resolve", resolve):
            handler._serve(sock)
        return sock

    def test_single_query_gets_length_prefixed_answer(self):
        q = query()
        answer = b"\x12\x34\x81\x80answer"
        sock = self._serve(frame(q), mock.Mock(return_value=answer))
        self.assertEqual(bytes(sock.sent), frame(answer))

    def test_pipelined_queries_each_answered(self):
        q1, q2 = query("a.example"), query("b.example")
        answers = {q1: b"AAAA-1", q2: b"BBBB-2"}
        sock = self._serve(frame(q1) + frame(q2),
                           mock.Mock(side_effect=lambda x: answers[x]))
        self.assertEqual(bytes(sock.sent), frame(answers[q1]) + frame(answers[q2]))

    def test_empty_frame_is_skipped_stream_stays_open(self):
        q = query()
        answer = b"resp"
        # A zero-length frame carries nothing to resolve; the stream must stay
        # open and the following real query is still answered.
        sock = self._serve(frame(b"") + frame(q), mock.Mock(return_value=answer))
        self.assertEqual(bytes(sock.sent), frame(answer))

    def test_eof_before_header_sends_nothing(self):
        resolve = mock.Mock()
        sock = self._serve(b"", resolve)
        self.assertEqual(bytes(sock.sent), b"")
        resolve.assert_not_called()

    def test_truncated_body_sends_nothing(self):
        # Header claims 10 bytes but only 3 arrive, then EOF.
        resolve = mock.Mock()
        sock = self._serve(struct.pack("!H", 10) + b"abc", resolve)
        self.assertEqual(bytes(sock.sent), b"")
        resolve.assert_not_called()

    def test_fail_closed_closes_without_answering(self):
        q = query()
        sock = self._serve(frame(q), mock.Mock(side_effect=RuntimeError("down")))
        self.assertEqual(bytes(sock.sent), b"", "a DoH error must not leak a reply")


if __name__ == "__main__":
    unittest.main()
