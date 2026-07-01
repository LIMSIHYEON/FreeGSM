"""TTL-aware DNS cache (dohproxy/dnscache.py).

Builds DNS messages by hand and exercises the cache's correctness contract: keyed
on the question (case-insensitive, DO-bit-aware), hits rewrite the transaction ID
and 0x20 case and decrement every RR TTL, only safe responses are stored, and any
malformed message falls through to an un-cached resolve. The clock is faked so
expiry/decrement are deterministic.

dnscache imports doh -> httpx; if httpx is absent (e.g. a Windows-only dev box)
the whole module is skipped rather than failing import.
"""

from __future__ import annotations

import struct
import unittest
from unittest import mock

try:
    from dohproxy import dnscache
except Exception as exc:  # noqa: BLE001 - httpx/doh may be absent in this env
    dnscache = None
    _IMPORT_ERR = exc


# --------------------------------------------------------------------------- #
# Wire-format builders
# --------------------------------------------------------------------------- #
def _name(s: str) -> bytes:
    out = b""
    for label in s.split("."):
        if label:
            out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def query(name="example.com", qtype=1, qclass=1, txid=0x1234, do=False,
          opcode=0) -> bytes:
    flags = 0x0100 | ((opcode & 0xF) << 11)  # RD + opcode
    arcount = 1 if do else 0
    msg = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, arcount)
    msg += _name(name) + struct.pack("!HH", qtype, qclass)
    if do:
        # OPT: root name, TYPE=41, CLASS=udpsize, TTL flags has DO (0x8000), RDLEN 0
        msg += b"\x00" + struct.pack("!HHIH", 41, 4096, 0x8000, 0)
    return msg


def _rr(name_wire: bytes, rtype: int, ttl: int, rdata: bytes, rclass=1) -> bytes:
    return name_wire + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def _question_end(q: bytes) -> int:
    pos = 12
    while q[pos] != 0:
        pos += 1 + q[pos]
    return pos + 1 + 4


def response(q: bytes, answers=(), authority=(), additional=(), rcode=0,
             tc=False) -> bytes:
    """answers/authority/additional: iterables of pre-encoded RR bytes."""
    flags = 0x8180 | (rcode & 0xF)  # QR + RD + RA
    if tc:
        flags |= 0x0200
    an, ns, ar = list(answers), list(authority), list(additional)
    hdr = q[:2] + struct.pack("!HHHHH", flags, 1, len(an), len(ns), len(ar))
    return hdr + q[12:_question_end(q)] + b"".join(an + ns + ar)


def a_record(name="example.com", ttl=300, ip="93.184.216.34") -> bytes:
    return _rr(_name(name), 1, ttl, bytes(int(o) for o in ip.split(".")))


def soa_record(name="example.com", ttl=3600, minimum=60) -> bytes:
    rdata = (_name("ns.example.com") + _name("hostmaster.example.com")
             + struct.pack("!IIIII", 1, 7200, 3600, 1209600, minimum))
    return _rr(_name(name), 6, ttl, rdata)


def _answer_ttls(msg: bytes):
    """Return the TTL of every (non-OPT) RR after the question, in order."""
    ancount, nscount, arcount = struct.unpack_from("!HHH", msg, 6)
    pos = _question_end(msg)
    ttls = []
    for _ in range(ancount + nscount + arcount):
        # skip name (handle a compression pointer)
        if msg[pos] & 0xC0 == 0xC0:
            pos += 2
        else:
            while msg[pos] != 0:
                pos += 1 + msg[pos]
            pos += 1
        rtype, _rclass, ttl = struct.unpack_from("!HHI", msg, pos)
        rdlen = struct.unpack_from("!H", msg, pos + 8)[0]
        if rtype != 41:
            ttls.append(ttl)
        pos += 10 + rdlen
    return ttls


class _Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


@unittest.skipIf(dnscache is None, "dnscache (httpx/doh) not importable here")
class DnsCacheTest(unittest.TestCase):
    def setUp(self):
        dnscache.clear()
        self.clock = _Clock()
        p = mock.patch.object(dnscache, "_clock", self.clock)
        p.start()
        self.addCleanup(p.stop)
        self.addCleanup(dnscache.clear)

    # -- basic store / hit -------------------------------------------------- #
    def test_miss_returns_none(self):
        self.assertIsNone(dnscache.get(query()))

    def test_store_then_hit(self):
        q = query()
        dnscache.put(q, response(q, [a_record(ttl=300)]))
        hit = dnscache.get(q)
        self.assertIsNotNone(hit)
        self.assertEqual(hit[:2], q[:2])
        self.assertEqual(_answer_ttls(hit), [300])  # 0s elapsed

    def test_hit_rewrites_id_and_0x20_case(self):
        q1 = query(name="example.com", txid=0x1111)
        dnscache.put(q1, response(q1, [a_record(ttl=120)]))
        q2 = query(name="ExAmPle.COM", txid=0x2222)  # same name, new id + case
        hit = dnscache.get(q2)
        self.assertIsNotNone(hit)
        self.assertEqual(hit[:2], q2[:2])  # new transaction id echoed
        # The served question must be the client's exact bytes (0x20 case), not
        # the originally-cached lowercase form.
        self.assertEqual(hit[12:_question_end(hit)], q2[12:_question_end(q2)])

    def test_ttl_decrements_with_elapsed_time(self):
        q = query()
        dnscache.put(q, response(q, [a_record(ttl=300)]))
        self.clock.t += 100
        self.assertEqual(_answer_ttls(dnscache.get(q)), [200])

    def test_expired_entry_is_a_miss_and_evicted(self):
        q = query()
        dnscache.put(q, response(q, [a_record(ttl=300)]))
        self.clock.t += 300  # expires_at == now -> expired
        self.assertIsNone(dnscache.get(q))
        self.clock.t += 1
        self.assertIsNone(dnscache.get(q))

    # -- key separation ----------------------------------------------------- #
    def test_qtype_separates_entries(self):
        qa = query(qtype=1)
        qaaaa = query(qtype=28)
        dnscache.put(qa, response(qa, [a_record(ttl=300)]))
        self.assertIsNotNone(dnscache.get(qa))
        self.assertIsNone(dnscache.get(qaaaa))

    def test_do_bit_separates_entries(self):
        q_plain = query(do=False, txid=1)
        q_do = query(do=True, txid=2)
        dnscache.put(q_plain, response(q_plain, [a_record(ttl=300)]))
        self.assertIsNotNone(dnscache.get(q_plain))
        self.assertIsNone(dnscache.get(q_do))  # DO query is a different key

    # -- what must NOT be cached ------------------------------------------- #
    def test_servfail_not_cached(self):
        q = query()
        dnscache.put(q, response(q, [a_record(ttl=300)], rcode=2))
        self.assertIsNone(dnscache.get(q))

    def test_truncated_not_cached(self):
        q = query()
        dnscache.put(q, response(q, [a_record(ttl=300)], tc=True))
        self.assertIsNone(dnscache.get(q))

    def test_zero_ttl_not_cached(self):
        q = query()
        dnscache.put(q, response(q, [a_record(ttl=0)]))
        self.assertIsNone(dnscache.get(q))

    def test_non_query_opcode_not_cached(self):
        q = query(opcode=2)  # STATUS
        dnscache.put(q, response(q, [a_record(ttl=300)]))
        self.assertIsNone(dnscache.get(q))

    # -- negative caching --------------------------------------------------- #
    def test_nxdomain_capped_by_soa_minimum(self):
        q = query(name="nope.example.com")
        # SOA ttl 3600 but MINIMUM 60 -> negative cache lifetime is 60s.
        resp = response(q, authority=[soa_record(name="example.com",
                                                  ttl=3600, minimum=60)], rcode=3)
        dnscache.put(q, resp)
        self.assertIsNotNone(dnscache.get(q))
        self.clock.t += 59
        self.assertIsNotNone(dnscache.get(q))
        self.clock.t += 1  # now 60s elapsed
        self.assertIsNone(dnscache.get(q))

    # -- compression-pointer answers --------------------------------------- #
    def test_compressed_answer_name_roundtrips(self):
        q = query(name="example.com")
        # Answer whose NAME is a pointer (0xC00C) to the question name at off 12.
        ptr_a = _rr(b"\xc0\x0c", 1, 300, bytes([93, 184, 216, 34]))
        dnscache.put(q, response(q, [ptr_a]))
        self.clock.t += 50
        hit = dnscache.get(q)
        self.assertIsNotNone(hit)
        self.assertEqual(_answer_ttls(hit), [250])

    def test_opt_in_answer_is_not_decremented(self):
        q = query()
        opt = b"\x00" + struct.pack("!HHIH", 41, 4096, 0x8000, 0)
        resp = response(q, answers=[a_record(ttl=300)], additional=[opt])
        dnscache.put(q, resp)
        self.clock.t += 100
        hit = dnscache.get(q)
        # The A record decremented to 200; the OPT "TTL" (flags) is untouched.
        self.assertEqual(_answer_ttls(hit), [200])
        opt_ttl = struct.unpack_from("!I", hit, len(hit) - 6)[0]
        self.assertEqual(opt_ttl, 0x8000)

    # -- eviction ----------------------------------------------------------- #
    def test_capacity_eviction(self):
        with mock.patch.object(dnscache.config, "DNS_CACHE_MAX", 4):
            for i in range(10):
                q = query(name=f"h{i}.example.com")
                dnscache.put(q, response(q, [a_record(name=f"h{i}.example.com",
                                                      ttl=300)]))
            self.assertLessEqual(len(dnscache._store), 4)

    # -- resolve() wrapper -------------------------------------------------- #
    def test_resolve_serves_second_call_from_cache(self):
        q = query()
        resp = response(q, [a_record(ttl=300)])
        with mock.patch.object(dnscache.config, "DNS_CACHE", True), \
             mock.patch.object(dnscache.doh, "resolve", return_value=resp) as m:
            r1 = dnscache.resolve(q)
            r2 = dnscache.resolve(q)
        self.assertEqual(m.call_count, 1)  # second call hit the cache
        self.assertEqual(r1[2:], resp[2:])
        self.assertEqual(_answer_ttls(r2), [300])

    def test_resolve_falls_back_on_unparseable_query(self):
        junk = b"\x00\x01"  # too short to parse
        with mock.patch.object(dnscache.config, "DNS_CACHE", True), \
             mock.patch.object(dnscache.doh, "resolve", return_value=b"ANSWER") as m:
            out = dnscache.resolve(junk)
        self.assertEqual(out, b"ANSWER")
        self.assertEqual(m.call_count, 1)
        self.assertEqual(len(dnscache._store), 0)  # nothing stored

    def test_resolve_disabled_always_calls_doh(self):
        q = query()
        resp = response(q, [a_record(ttl=300)])
        with mock.patch.object(dnscache.config, "DNS_CACHE", False), \
             mock.patch.object(dnscache.doh, "resolve", return_value=resp) as m:
            dnscache.resolve(q)
            dnscache.resolve(q)
        self.assertEqual(m.call_count, 2)

    def test_resolve_propagates_doh_error(self):
        q = query()
        with mock.patch.object(dnscache.config, "DNS_CACHE", True), \
             mock.patch.object(dnscache.doh, "resolve",
                               side_effect=RuntimeError("upstream down")):
            with self.assertRaises(RuntimeError):
                dnscache.resolve(q)


if __name__ == "__main__":
    unittest.main()
