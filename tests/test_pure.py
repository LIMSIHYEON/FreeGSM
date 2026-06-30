"""Pure-logic tests shared by both ports: TLS record fragmentation, DNS query
helpers, and config derivation (including the new BLOCK_PLAINTEXT_DNS flag).

No sockets, no root, no network -- just byte math, so these are the fast core of
the suite and run anywhere.
"""

from __future__ import annotations

import struct
import unittest

from dohproxy import config, dnsutil, dpi


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _tls_record(body: bytes, version: int = 0x0301) -> bytes:
    """A single TLS handshake record wrapping ``body``."""
    return bytes([0x16]) + struct.pack("!H", version) + struct.pack("!H", len(body)) + body


def _walk_records(buf: bytes) -> bytes:
    """Concatenate the bodies of every well-formed TLS record in ``buf`` -- what
    a server reassembles. Used to assert a split is byte-identical on the wire."""
    out = bytearray()
    pos = 0
    while pos + 5 <= len(buf):
        ln = int.from_bytes(buf[pos + 3:pos + 5], "big")
        out += buf[pos + 5:pos + 5 + ln]
        pos += 5 + ln
    return bytes(out)


def _dns_query(name: str = "example.com", qtype: int = 1, *, ar: int = 0,
               edns_size: int = 0) -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, ar)
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    q += struct.pack("!HH", qtype, 1)
    extra = b""
    if ar:
        # An OPT pseudo-record: root name, TYPE 41, CLASS = UDP payload size.
        extra = b"\x00" + struct.pack("!HHIH", 41, edns_size, 0, 0)
    return header + q + extra


# --------------------------------------------------------------------------- #
# DPI: TLS record-layer fragmentation
# --------------------------------------------------------------------------- #
class SplitHelloTest(unittest.TestCase):
    def test_split_is_byte_identical_on_the_wire(self):
        hello = _tls_record(bytes(range(256)) + bytes(range(200)))  # 456-byte body
        for _ in range(200):  # split_len is random; the invariant must always hold
            segs = dpi.split_hello(hello)
            self.assertEqual(b"".join(segs), b"".join(segs))  # sanity
            self.assertEqual(_walk_records(b"".join(segs)), hello[5:],
                             "reassembled handshake bytes must equal the original")

    def test_split_emits_two_records(self):
        hello = _tls_record(bytes(300))
        seen_two = False
        for _ in range(200):
            segs = dpi.split_hello(hello)
            self.assertIn(len(segs), (1, 2))
            if len(segs) == 2:
                seen_two = True
                # First record's length field is rewritten to its smaller body.
                self.assertTrue(dpi.is_tls_handshake(segs[0]))
                ln0 = int.from_bytes(segs[0][3:5], "big")
                self.assertEqual(ln0, len(segs[0]) - 5)
        self.assertTrue(seen_two, "a 300-byte hello should fragment into two records")

    def test_incomplete_record_is_forwarded_untouched(self):
        # Header claims 500 body bytes but only 100 are buffered -> don't fragment.
        partial = bytes([0x16]) + struct.pack("!H", 0x0301) + struct.pack("!H", 500) + bytes(100)
        self.assertEqual(dpi.split_hello(partial), [partial])

    def test_non_tls_falls_back_to_byte_split(self):
        blob = bytes(range(100))
        segs = dpi.split_hello(blob)
        self.assertEqual(b"".join(segs), blob)

    def test_tls_record_len(self):
        self.assertEqual(dpi.tls_record_len(_tls_record(bytes(42))[:5]), (42, True))
        self.assertEqual(dpi.tls_record_len(b"\x16\x99\x99\x00\x05"), (0, False))  # bad version
        self.assertEqual(dpi.tls_record_len(b"\x17\x03\x01\x00\x05"), (0, False))  # not handshake


# --------------------------------------------------------------------------- #
# DNS query helpers
# --------------------------------------------------------------------------- #
class DnsUtilTest(unittest.TestCase):
    def test_describe_query(self):
        self.assertEqual(dnsutil.describe_query(_dns_query("example.com", 1)), "example.com A")
        self.assertEqual(dnsutil.describe_query(_dns_query("ipv6.test", 28)), "ipv6.test AAAA")

    def test_describe_query_never_raises(self):
        self.assertTrue(dnsutil.describe_query(b"\x00\x01garbage"))

    def test_udp_payload_limit_default_512(self):
        self.assertEqual(dnsutil.udp_payload_limit(_dns_query()), 512)

    def test_udp_payload_limit_reads_edns(self):
        q = _dns_query(ar=1, edns_size=1232)
        self.assertEqual(dnsutil.udp_payload_limit(q), 1232)

    def test_truncated_response_sets_tc_and_qr(self):
        q = _dns_query()
        resp = dnsutil.truncated_response(q)
        self.assertIsNotNone(resp)
        flags = struct.unpack_from("!H", resp, 2)[0]
        self.assertTrue(flags & 0x8000, "QR must be set")
        self.assertTrue(flags & 0x0200, "TC must be set")
        # Echoes the question, drops all answer/authority/additional counts.
        self.assertEqual(struct.unpack_from("!HHH", resp, 6), (0, 0, 0))

    def test_truncated_response_on_garbage_returns_none(self):
        self.assertIsNone(dnsutil.truncated_response(b"\x00"))


# --------------------------------------------------------------------------- #
# config derivation
# --------------------------------------------------------------------------- #
class ConfigTest(unittest.TestCase):
    def test_doh_server_ip_extracted_from_literal_ip_url(self):
        # Default upstream is a literal IP, so the DPI layer can exclude it.
        self.assertEqual(config.DOH_SERVER_IP, "1.0.0.1")
        self.assertIsNone(config.DOH_SERVER_IP6)

    def test_env_flag_parsing(self):
        import os
        for truthy in ("1", "true", "YES", "on"):
            os.environ["FREEGSM_TEST_FLAG"] = truthy
            self.assertTrue(config._env_flag("FREEGSM_TEST_FLAG", "x", default=False))
        for falsy in ("0", "false", "no", "off"):
            os.environ["FREEGSM_TEST_FLAG"] = falsy
            self.assertFalse(config._env_flag("FREEGSM_TEST_FLAG", "x", default=True))
        # Empty/whitespace is treated as unset -> falls through to the default.
        os.environ["FREEGSM_TEST_FLAG"] = "  "
        self.assertTrue(config._env_flag("FREEGSM_TEST_FLAG", "x", default=True))
        del os.environ["FREEGSM_TEST_FLAG"]

    def test_block_plaintext_dns_defaults_off(self):
        self.assertFalse(config.BLOCK_PLAINTEXT_DNS)

    def test_divert_filter_excludes_doh_upstream(self):
        # The capture filter must never grab our own DoH channel.
        self.assertIn("1.0.0.1", config.DIVERT_FILTER)
        self.assertIn("udp.DstPort == 53", config.DIVERT_FILTER)


if __name__ == "__main__":
    unittest.main()
