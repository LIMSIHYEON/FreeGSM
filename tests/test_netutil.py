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

import socket
import unittest

from dohproxy import netutil


class FakeSock:
    """recv() returns each scripted chunk in turn; b'' means EOF."""

    def __init__(self, chunks) -> None:
        self._chunks = list(chunks)

    def recv(self, n: int) -> bytes:
        if not self._chunks:
            return b""
        chunk = self._chunks.pop(0)
        if len(chunk) <= n:
            return chunk
        # Honour the requested size; push the remainder back for the next call.
        self._chunks.insert(0, chunk[n:])
        return chunk[:n]


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


if __name__ == "__main__":
    unittest.main()
