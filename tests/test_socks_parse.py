"""SOCKS5 UDP-ASSOCIATE datagram header parsing (_parse_dst).

This is the wire parser on the path that closes the DPI-ON hardcoded-DNS gap, so
its handling of v4 / v6 / domain address types and malformed input matters.

socks_proxy imports the DoH client (httpx); if httpx isn't installed (e.g. a
Windows-only dev box), the whole module is skipped rather than failing import.
"""

from __future__ import annotations

import socket
import struct
import unittest

try:
    from dohproxy.macos import socks_proxy
except Exception as exc:  # noqa: BLE001 - httpx/doh may be absent in this env
    socks_proxy = None
    _IMPORT_ERR = exc


@unittest.skipIf(socks_proxy is None, "socks_proxy (httpx) not importable here")
class ParseDstTest(unittest.TestCase):
    def test_ipv4(self):
        data = b"\x01" + socket.inet_aton("8.8.8.8") + struct.pack("!H", 53)
        host, port, family, off = socks_proxy._parse_dst(data, 0)
        self.assertEqual((host, port, family), ("8.8.8.8", 53, socket.AF_INET))
        self.assertEqual(off, len(data))

    def test_ipv6(self):
        packed = socket.inet_pton(socket.AF_INET6, "2001:4860:4860::8888")
        data = b"\x04" + packed + struct.pack("!H", 53)
        host, port, family, off = socks_proxy._parse_dst(data, 0)
        self.assertEqual(family, socket.AF_INET6)
        self.assertEqual(port, 53)
        self.assertEqual(socket.inet_pton(socket.AF_INET6, host), packed)

    def test_domain(self):
        name = b"dns.example"
        data = b"\x03" + bytes([len(name)]) + name + struct.pack("!H", 853)
        host, port, family, off = socks_proxy._parse_dst(data, 0)
        self.assertEqual((host, port, family), ("dns.example", 853, 0))

    def test_truncated_returns_none(self):
        self.assertIsNone(socks_proxy._parse_dst(b"\x01\x08\x08", 0))  # short v4
        self.assertIsNone(socks_proxy._parse_dst(b"\x09", 0))          # bad atyp

    def test_offset_respected(self):
        # The real caller starts at offset 3 (after RSV+FRAG).
        data = b"\x00\x00\x00\x01" + socket.inet_aton("1.1.1.1") + struct.pack("!H", 53)
        host, port, family, off = socks_proxy._parse_dst(data, 3)
        self.assertEqual((host, port), ("1.1.1.1", 53))


if __name__ == "__main__":
    unittest.main()
