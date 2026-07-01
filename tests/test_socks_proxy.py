"""SOCKS5 proxy helpers + the hardcoded-DNS DoH path (dohproxy/macos/socks_proxy.py).

Covers the parts of the SOCKS proxy beyond the datagram-header parser
(test_socks_parse): the physical-interface detection / re-pin used to keep
upstream sockets off the utun (avoiding a routing loop), and ``_dns_over_doh``,
which closes the DPI-ON hardcoded-DNS gap. Its contract mirrors the resolver's:
fail-closed on a DoH error, TC-truncate an oversized answer, and wrap the reply
for the original destination -- verified here with faked DoH and a synchronous
stand-in for the worker thread so the assertions are deterministic.

socks_proxy imports the DoH client (httpx); if httpx isn't installed the whole
module is skipped rather than failing import.
"""

from __future__ import annotations

import socket
import struct
import subprocess
import unittest
from unittest import mock

try:
    from dohproxy.macos import socks_proxy
    from dohproxy import config, dnsutil
except Exception as exc:  # noqa: BLE001 - httpx/doh may be absent in this env
    socks_proxy = None
    _IMPORT_ERR = exc


def _query(name="example.com", qtype=1) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    return hdr + out + b"\x00" + struct.pack("!HH", qtype, 1)


class _SyncThread:
    """Runs the target synchronously on start() so a spawned DoH round-trip is
    complete (and its semaphore released) by the time _dns_over_doh returns."""

    def __init__(self, target=None, name=None, daemon=None, args=(), kwargs=None):
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}

    def start(self):
        self._target(*self._args, **self._kwargs)


class FakeRelay:
    def __init__(self) -> None:
        self.sent: list = []  # (data, addr)

    def sendto(self, data, addr):
        self.sent.append((data, addr))


@unittest.skipIf(socks_proxy is None, "socks_proxy (httpx) not importable here")
class BoundIfaceTest(unittest.TestCase):
    def setUp(self) -> None:
        self._orig = socks_proxy._bound_if_index
        socks_proxy._bound_if_index = 0

    def tearDown(self) -> None:
        socks_proxy._bound_if_index = self._orig

    def test_resolves_and_updates_index(self):
        with mock.patch.object(socks_proxy.socket, "if_nametoindex", return_value=5):
            self.assertTrue(socks_proxy.set_bound_iface("en0"))
        self.assertEqual(socks_proxy._bound_if_index, 5)

    def test_returns_false_and_keeps_index_on_oserror(self):
        socks_proxy._bound_if_index = 7
        with mock.patch.object(socks_proxy.socket, "if_nametoindex",
                               side_effect=OSError("no such iface")):
            self.assertFalse(socks_proxy.set_bound_iface("bogus0"))
        self.assertEqual(socks_proxy._bound_if_index, 7, "index must survive failure")

    def test_same_index_is_a_noop_but_still_true(self):
        socks_proxy._bound_if_index = 5
        with mock.patch.object(socks_proxy.socket, "if_nametoindex", return_value=5):
            self.assertTrue(socks_proxy.set_bound_iface("en0"))
        self.assertEqual(socks_proxy._bound_if_index, 5)

    def test_zero_index_is_false(self):
        with mock.patch.object(socks_proxy.socket, "if_nametoindex", return_value=0):
            self.assertFalse(socks_proxy.set_bound_iface("en9"))
        self.assertEqual(socks_proxy._bound_if_index, 0)


@unittest.skipIf(socks_proxy is None, "socks_proxy (httpx) not importable here")
class PhysicalIfaceTest(unittest.TestCase):
    def test_parses_interface_line(self):
        out = ("   route to: default\n"
               "destination: default\n"
               "    gateway: 192.168.0.1\n"
               "  interface: en0\n"
               "      flags: <UP,GATEWAY,DONE,STATIC>\n")
        with mock.patch.object(socks_proxy.subprocess, "run",
                               return_value=mock.Mock(stdout=out)):
            self.assertEqual(socks_proxy.physical_iface(), "en0")

    def test_returns_none_when_no_default_route(self):
        err = subprocess.CalledProcessError(1, ["route", "-n", "get", "default"])
        with mock.patch.object(socks_proxy.subprocess, "run", side_effect=err):
            self.assertIsNone(socks_proxy.physical_iface())

    def test_returns_none_when_interface_absent(self):
        with mock.patch.object(socks_proxy.subprocess, "run",
                               return_value=mock.Mock(stdout="destination: default\n")):
            self.assertIsNone(socks_proxy.physical_iface())


@unittest.skipIf(socks_proxy is None, "socks_proxy (httpx) not importable here")
class DnsOverDohTest(unittest.TestCase):
    def setUp(self) -> None:
        self.relay = FakeRelay()
        self.client = ("127.0.0.1", 40000)
        # ATYP+ADDR+PORT for 8.8.8.8:53, echoed verbatim on the reply.
        self.dst_hdr = b"\x01" + socket.inet_aton("8.8.8.8") + struct.pack("!H", 53)
        self._thread_patch = mock.patch.object(socks_proxy.threading, "Thread", _SyncThread)
        self._thread_patch.start()

    def tearDown(self) -> None:
        self._thread_patch.stop()

    def _run(self, query, resolve):
        with mock.patch.object(socks_proxy.dnscache, "resolve", resolve):
            socks_proxy._dns_over_doh(self.relay, self.client, self.dst_hdr, query)

    def test_success_wraps_answer_for_original_dst(self):
        q = _query()
        answer = b"\x12\x34\x81\x80answer"
        self._run(q, mock.Mock(return_value=answer))
        self.assertEqual(self.relay.sent,
                         [(b"\x00\x00\x00" + self.dst_hdr + answer, self.client)])

    def test_fail_closed_sends_nothing_on_doh_error(self):
        self._run(_query(), mock.Mock(side_effect=RuntimeError("down")))
        self.assertEqual(self.relay.sent, [], "a DoH error must not leak a reply")

    def test_empty_query_is_dropped(self):
        resolve = mock.Mock()
        self._run(b"", resolve)
        self.assertEqual(self.relay.sent, [])
        resolve.assert_not_called()

    def test_oversized_answer_is_truncated(self):
        q = _query()  # no OPT -> 512-byte UDP limit
        big = b"\x12\x34\x81\x80" + b"\x00" * 600
        self._run(q, mock.Mock(return_value=big))
        self.assertEqual(len(self.relay.sent), 1)
        data, addr = self.relay.sent[0]
        self.assertEqual(addr, self.client)
        self.assertEqual(data, b"\x00\x00\x00" + self.dst_hdr + dnsutil.truncated_response(q))

    def test_inflight_permit_is_released_across_many_calls(self):
        # If the bounded semaphore were leaked, calls beyond its capacity would be
        # dropped (fail-closed). Running well past capacity must still send them all.
        n = config.WORKER_THREADS * 2 + 5
        with mock.patch.object(socks_proxy.dnscache, "resolve", return_value=b"ok"):
            for _ in range(n):
                socks_proxy._dns_over_doh(self.relay, self.client, self.dst_hdr, _query())
        self.assertEqual(len(self.relay.sent), n)


if __name__ == "__main__":
    unittest.main()
