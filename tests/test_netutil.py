"""Shared socket primitives (dohproxy/netutil.py).

recv_exactly is the framing workhorse behind both the macOS resolver's TCP/53
loop and the SOCKS greeting/request parser: it must reassemble a short read
across multiple recv() calls and, crucially, return a SHORT buffer (never block
forever or raise) when the peer closes early -- every caller length-checks the
result to detect that. pump is the one-directional copy at the heart of the
relay; a real socketpair verifies it drains to EOF and then half-closes the
write side so the peer sees EOF too.

netutil imports no httpx / platform code, so it always loads.
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
import unittest

from dohproxy import config, netutil

_LOG = logging.getLogger("test.netutil")


def _recv_all(sock: socket.socket) -> bytes:
    """Drain ``sock`` until the peer half-closes (EOF)."""
    out = bytearray()
    while True:
        chunk = sock.recv(65535)
        if not chunk:
            return bytes(out)
        out += chunk


def _walk_records(buf: bytes) -> bytes:
    """Concatenate the bodies of every well-formed TLS record in ``buf`` -- what
    the destination server reassembles."""
    out = bytearray()
    pos = 0
    while pos + 5 <= len(buf):
        ln = int.from_bytes(buf[pos + 3:pos + 5], "big")
        out += buf[pos + 5:pos + 5 + ln]
        pos += 5 + ln
    return bytes(out)


class FakeSock:
    """recv() returns each scripted chunk in turn; b'' means EOF."""

    def __init__(self, chunks) -> None:
        self._chunks = list(chunks)
        self.recv_calls = 0

    def settimeout(self, _t) -> None:  # recv_full_hello / pump call this
        pass

    def recv(self, n: int) -> bytes:
        self.recv_calls += 1
        if not self._chunks:
            return b""
        chunk = self._chunks.pop(0)
        if len(chunk) <= n:
            return chunk
        # Honour the requested size; push the remainder back for the next call.
        self._chunks.insert(0, chunk[n:])
        return chunk[:n]


def _tls_record(body: bytes, version: int = 0x0301) -> bytes:
    """A single TLS handshake record (content type 0x16) wrapping ``body``."""
    return bytes([0x16]) + struct.pack("!H", version) + struct.pack("!H", len(body)) + body


class RecvExactlyTest(unittest.TestCase):
    def test_reassembles_across_chunks(self):
        sock = FakeSock([b"ab", b"cd", b"ef"])
        self.assertEqual(netutil.recv_exactly(sock, 6), b"abcdef")

    def test_reads_exactly_n_and_leaves_the_rest(self):
        sock = FakeSock([b"abcdef"])
        self.assertEqual(netutil.recv_exactly(sock, 4), b"abcd")
        self.assertEqual(netutil.recv_exactly(sock, 2), b"ef")

    def test_short_buffer_on_early_eof(self):
        sock = FakeSock([b"abc", b""])  # peer closes after 3 bytes
        got = netutil.recv_exactly(sock, 10)
        self.assertEqual(got, b"abc")
        self.assertLess(len(got), 10, "caller relies on a short read to detect EOF")

    def test_immediate_eof_returns_empty(self):
        self.assertEqual(netutil.recv_exactly(FakeSock([b""]), 4), b"")

    def test_zero_length_request(self):
        self.assertEqual(netutil.recv_exactly(FakeSock([b"data"]), 0), b"")


class RecvFullHelloTest(unittest.TestCase):
    """A ClientHello that spans multiple TCP segments must be reassembled before
    split_hello sees it, or the record-layer split silently doesn't fire and the
    SNI leaks. recv_full_hello reads exactly up to the record boundary."""

    def _timeout(self):
        return config.HTTPS_FIRST_READ_TIMEOUT

    def test_reassembles_record_across_segments(self):
        record = _tls_record(bytes(range(256)) + bytes(44))  # 300-byte body, 305 total
        first = record[:100]                                  # header + partial body
        sock = FakeSock([record[100:]])                       # the rest arrives later
        got = netutil.recv_full_hello(sock, first, self._timeout())
        self.assertEqual(got, record)

    def test_already_complete_reads_nothing_more(self):
        record = _tls_record(bytes(120))
        sock = FakeSock([b"should-not-be-read"])
        got = netutil.recv_full_hello(sock, record, self._timeout())
        self.assertEqual(got, record)
        self.assertEqual(sock.recv_calls, 0, "a complete record needs no extra recv")

    def test_does_not_over_read_past_the_record(self):
        record = _tls_record(bytes(300))                      # 305 total
        first = record[:100]
        trailing = b"EARLY-APP-DATA"
        sock = FakeSock([record[100:] + trailing])
        got = netutil.recv_full_hello(sock, first, self._timeout())
        self.assertEqual(got, record, "returns exactly the ClientHello record")
        # The bytes after the record are left unconsumed for the pump loop.
        self.assertEqual(sock.recv(len(trailing)), trailing)

    def test_non_tls_first_byte_returns_untouched(self):
        blob = b"GET / HTTP/1.1\r\n"                           # plaintext on :443
        sock = FakeSock([b"more"])
        got = netutil.recv_full_hello(sock, blob, self._timeout())
        self.assertEqual(got, blob)
        self.assertEqual(sock.recv_calls, 0)

    def test_eof_before_record_completes_returns_partial(self):
        record = _tls_record(bytes(300))
        first = record[:100]
        sock = FakeSock([record[100:150], b""])               # peer closes early
        got = netutil.recv_full_hello(sock, first, self._timeout())
        self.assertEqual(got, record[:150])
        self.assertLess(len(got), len(record), "short buffer -> split_hello forwards untouched")

    def test_oversized_length_field_is_capped(self):
        # Header claims a 60000-byte body (> the 2^14 spec cap); an endless feed
        # must not be read past MAX_CLIENT_HELLO.
        header = bytes([0x16]) + struct.pack("!H", 0x0301) + struct.pack("!H", 60000)
        sock = FakeSock([bytes(70000)])
        got = netutil.recv_full_hello(sock, header, self._timeout())
        self.assertLessEqual(len(got), config.MAX_CLIENT_HELLO)


class PumpTest(unittest.TestCase):
    def test_copies_to_eof_then_half_closes_write(self):
        src_a, src_b = socket.socketpair()      # feed pump by writing to src_b
        dst_a, dst_b = socket.socketpair()       # read pump's output from dst_b
        self.addCleanup(lambda: [s.close() for s in (src_a, src_b, dst_a, dst_b)])

        src_b.sendall(b"hello world")
        src_b.close()  # EOF -> pump's read loop ends

        netutil.pump(src_a, dst_a)

        # Everything was forwarded, and the write side was shut so dst_b sees EOF.
        received = bytearray()
        while True:
            chunk = dst_b.recv(65535)
            if not chunk:
                break
            received += chunk
        self.assertEqual(bytes(received), b"hello world")


class SplitRelayTest(unittest.TestCase):
    """End-to-end coverage of the shared relay used by both the Windows
    (https_proxy) and macOS (socks_proxy) :443 paths: it must fragment a TLS
    ClientHello into two records on the wire, leave non-TLS / non-443 traffic
    byte-identical, and copy both directions to completion."""

    def _relay(self, first_payload: bytes, port: int) -> bytes:
        client, client_peer = socket.socketpair()
        upstream, upstream_peer = socket.socketpair()
        self.addCleanup(lambda: [s.close() for s in
                                 (client, client_peer, upstream, upstream_peer)])
        # Client sends its opening bytes then half-closes so the forward pump
        # reaches EOF; the fake server has nothing to say, so half-close its side
        # too and the reverse pump ends at once. split_relay then returns.
        client_peer.sendall(first_payload)
        client_peer.shutdown(socket.SHUT_WR)
        upstream_peer.shutdown(socket.SHUT_WR)

        t = threading.Thread(
            target=netutil.split_relay,
            args=(client, upstream, "example.com", port, _LOG, "TEST"),
            daemon=True,
        )
        t.start()
        forwarded = _recv_all(upstream_peer)  # everything the relay sent upstream
        t.join(timeout=5)
        self.assertFalse(t.is_alive(), "split_relay did not return")
        return forwarded

    def test_clienthello_is_fragmented_into_two_records(self):
        hello = _tls_record(bytes(range(256)) + bytes(44))  # 300-byte body
        forwarded = self._relay(hello, 443)
        # Two records on the wire (one extra 5-byte header), but the handshake the
        # server reassembles is byte-identical to the original.
        self.assertEqual(len(forwarded), len(hello) + 5)
        self.assertEqual(_walk_records(forwarded), hello[5:])

    def test_plaintext_on_443_is_forwarded_untouched(self):
        blob = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"  # not a TLS handshake
        self.assertEqual(self._relay(blob, 443), blob)

    def test_non_443_port_is_piped_without_a_first_read(self):
        # A server-speaks-first / non-TLS port must not be split, and the client's
        # first bytes must still reach upstream unchanged.
        data = b"SSH-2.0-OpenSSH\r\n"
        self.assertEqual(self._relay(data, 22), data)


if __name__ == "__main__":
    unittest.main()
