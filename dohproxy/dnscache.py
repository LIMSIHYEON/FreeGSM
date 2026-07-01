"""TTL-aware DNS response cache layered on top of the stateless DoH client.

``doh.resolve`` is deliberately stateless -- a DNS query and a DoH body are the
same bytes (RFC 8484), no parsing -- so every repeated lookup pays a full DoH
round-trip. This module adds an *optional* in-memory cache in front of it without
touching that invariant: it lives in its own module, parses only enough of the
wire format to do its job, and on ANY anomaly falls straight through to a plain
``doh.resolve`` (no caching). A cache miss or a malformed message therefore
behaves exactly like the un-cached path, so the fail-closed guarantee is intact
-- the cache can only ever turn a network round-trip into a memory hit, never
manufacture or corrupt an answer.

Entries are keyed on the *question* (lowercased QNAME + QTYPE + QCLASS + the EDNS
DO bit), so two queries that differ only in transaction ID, 0x20 case
randomisation, or EDNS padding share one entry. On a hit the stored response is
rewritten to carry the new query's ID and exact question bytes, and every
resource-record TTL is decremented by the seconds elapsed since it was stored, so
a client never sees a frozen countdown.

Only safe-to-cache responses are stored: a single-question standard query
(opcode 0), a non-truncated NOERROR/NXDOMAIN response, and a positive minimum
TTL. Negative responses are capped by the SOA MINIMUM (RFC 2308). This module is
used by both ports: the macOS resolver + SOCKS UDP/53 path and the Windows
UDP/53 + TCP/53 handlers all call ``resolve`` here instead of ``doh.resolve``.
"""

from __future__ import annotations

import logging
import struct
import threading
import time

from . import config, doh

log = logging.getLogger("dohproxy.dnscache")

# OPT pseudo-record (EDNS0); its "TTL" field is flags, not a real TTL, so it is
# excluded from min-TTL computation and never decremented.
_TYPE_OPT = 41
_TYPE_SOA = 6

# Indirection so tests can freeze/advance time; production calls monotonic().
def _clock() -> float:
    return time.monotonic()


# (key) -> [response_bytes, stored_at, expires_at]
_store: dict[tuple, list] = {}
_lock = threading.Lock()


# --------------------------------------------------------------------------- #
# Wire-format parsing (just enough; any anomaly -> caller falls back, no cache)
# --------------------------------------------------------------------------- #
def _skip_name(msg: bytes, pos: int) -> int | None:
    """Return the offset just past the (possibly compressed) name at ``pos``, or
    None if it runs off the end / uses a reserved label type. A compression
    pointer (0xC0) terminates the name in two bytes."""
    n = len(msg)
    while True:
        if pos >= n:
            return None
        length = msg[pos]
        if length == 0:
            return pos + 1
        kind = length & 0xC0
        if kind == 0xC0:
            return pos + 2 if pos + 2 <= n else None
        if kind != 0:
            return None  # reserved label type
        pos += 1 + length
    # unreachable


def _question(msg: bytes) -> tuple[bytes, int, int, int] | None:
    """Parse a single-question header+question. Returns
    (qname_lowercased_wire, qtype, qclass, question_end) or None.

    The QNAME is returned in its raw wire form (length-prefixed labels) lowercased
    so it can serve as a case-insensitive key. Compression is illegal in a
    question, so a pointer is rejected."""
    if len(msg) < 12:
        return None
    qd = struct.unpack_from("!H", msg, 4)[0]
    if qd != 1:
        return None  # only single-question messages are cached
    pos = 12
    name = bytearray()
    n = len(msg)
    while True:
        if pos >= n:
            return None
        length = msg[pos]
        if length & 0xC0:
            return None  # pointer/reserved not allowed in a question
        name.append(length)
        pos += 1
        if length == 0:
            break
        end = pos + length
        if end > n:
            return None
        name += msg[pos:end].lower()
        pos = end
    if pos + 4 > n:
        return None
    qtype, qclass = struct.unpack_from("!HH", msg, pos)
    return bytes(name), qtype, qclass, pos + 4


def _do_bit(msg: bytes, qend: int) -> bool:
    """True if the query advertises EDNS DNSSEC OK. Walks the additional section
    for an OPT record; on any trouble returns False (best-effort, never raises)."""
    try:
        arcount = struct.unpack_from("!H", msg, 10)[0]
        ancount = struct.unpack_from("!H", msg, 6)[0]
        nscount = struct.unpack_from("!H", msg, 8)[0]
        pos = _walk_skip(msg, qend, ancount + nscount)
        if pos is None:
            return False
        for _ in range(arcount):
            pos = _skip_name(msg, pos)
            if pos is None or pos + 10 > len(msg):
                return False
            rtype, _rclass, ttl = struct.unpack_from("!HHI", msg, pos)
            rdlen = struct.unpack_from("!H", msg, pos + 8)[0]
            if rtype == _TYPE_OPT:
                return bool(ttl & 0x8000)  # DO is the top bit of the flags word
            pos += 10 + rdlen
    except (struct.error, IndexError):
        return False
    return False


def _walk_skip(msg: bytes, pos: int, count: int) -> int | None:
    """Skip ``count`` resource records starting at ``pos`` without inspecting
    them. Returns the offset past the last, or None on malformation."""
    n = len(msg)
    for _ in range(count):
        pos = _skip_name(msg, pos)
        if pos is None or pos + 10 > n:
            return None
        rdlen = struct.unpack_from("!H", msg, pos + 8)[0]
        pos += 10 + rdlen
        if pos > n:
            return None
    return pos


def _cacheable_ttl(msg: bytes, qend: int) -> int | None:
    """Return the cache lifetime for a response, or None if it must not be cached.

    Lifetime = the minimum TTL across all real (non-OPT) resource records, capped
    by config.DNS_CACHE_MAX_TTL. For a negative answer (no answer records) it is
    additionally capped by the SOA MINIMUM field (RFC 2308). Returns None for a
    truncated response, a response with no cacheable records, or a zero minimum.
    """
    flags = struct.unpack_from("!H", msg, 2)[0]
    if flags & 0x0200:  # TC: a truncated response is not authoritative content
        return None
    rcode = flags & 0x000F
    if rcode not in (0, 3):  # cache only NOERROR / NXDOMAIN
        return None
    ancount, nscount, arcount = struct.unpack_from("!HHH", msg, 6)
    pos = qend
    n = len(msg)
    min_ttl: int | None = None
    soa_minimum: int | None = None
    total = ancount + nscount + arcount
    for i in range(total):
        pos = _skip_name(msg, pos)
        if pos is None or pos + 10 > n:
            return None
        rtype, _rclass, ttl = struct.unpack_from("!HHI", msg, pos)
        rdlen = struct.unpack_from("!H", msg, pos + 8)[0]
        rdata = pos + 10
        pos = rdata + rdlen
        if pos > n:
            return None
        if rtype == _TYPE_OPT:
            continue  # OPT TTL is flags, not a lifetime
        ttl &= 0x7FFFFFFF  # defensively mask the sign bit
        min_ttl = ttl if min_ttl is None else min(min_ttl, ttl)
        if rtype == _TYPE_SOA:
            # SOA MINIMUM is the last uint32 of RDATA (mname, rname, then five
            # uint32s: serial, refresh, retry, expire, minimum).
            if rdlen >= 4:
                soa_minimum = struct.unpack_from("!I", msg, pos - 4)[0] & 0x7FFFFFFF
    if min_ttl is None or min_ttl <= 0:
        return None
    if ancount == 0 and soa_minimum is not None:
        min_ttl = min(min_ttl, soa_minimum)
        if min_ttl <= 0:
            return None
    return min(min_ttl, config.DNS_CACHE_MAX_TTL)


def _rewrite_for_serve(cached: bytes, query: bytes, qend_q: int,
                       qend_c: int, elapsed: int) -> bytes | None:
    """Build the response to send for a cache hit: the cached bytes with the new
    query's transaction ID and exact question bytes, and every RR TTL decremented
    by ``elapsed`` seconds. Returns None on any structural surprise so the caller
    falls back to a live resolve."""
    # The question sections are byte-identical in length (same name labels, qtype,
    # qclass -- they only differ in case), so splicing keeps every later offset.
    if qend_q != qend_c:
        return None
    out = bytearray(cached)
    out[0:2] = query[0:2]              # transaction ID
    out[12:qend_c] = query[12:qend_q]  # echo the client's exact 0x20 case
    ancount, nscount, arcount = struct.unpack_from("!HHH", out, 6)
    pos = qend_c
    n = len(out)
    for _ in range(ancount + nscount + arcount):
        p = _skip_name(out, pos)
        if p is None or p + 10 > n:
            return None
        rtype, _rclass, ttl = struct.unpack_from("!HHI", out, p)
        rdlen = struct.unpack_from("!H", out, p + 8)[0]
        if rtype != _TYPE_OPT:
            new_ttl = (ttl & 0x7FFFFFFF) - elapsed
            if new_ttl < 0:
                new_ttl = 0
            struct.pack_into("!I", out, p + 4, new_ttl)
        pos = p + 10 + rdlen
        if pos > n:
            return None
    return bytes(out)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def _key(qname: bytes, qtype: int, qclass: int, do: bool) -> tuple:
    return (qname, qtype, qclass, do)


def _evict_if_full() -> None:
    """Caller holds _lock. Keep the store under DNS_CACHE_MAX by dropping expired
    entries first, then the oldest by insertion order (dicts preserve it)."""
    if len(_store) < config.DNS_CACHE_MAX:
        return
    now = _clock()
    for k in [k for k, v in _store.items() if v[2] <= now]:
        _store.pop(k, None)
    while len(_store) >= config.DNS_CACHE_MAX:
        try:
            _store.pop(next(iter(_store)))
        except StopIteration:
            break


def get(query: bytes) -> bytes | None:
    """Return a cached response for ``query`` (ID/question/TTLs rewritten), or
    None on a miss or any parse trouble."""
    parsed = _question(query)
    if parsed is None:
        return None
    qname, qtype, qclass, qend_q = parsed
    if struct.unpack_from("!H", query, 2)[0] & 0x7800:  # opcode != QUERY
        return None
    key = _key(qname, qtype, qclass, _do_bit(query, qend_q))
    now = _clock()
    with _lock:
        entry = _store.get(key)
        if entry is None:
            return None
        cached, stored_at, expires_at = entry
        if expires_at <= now:
            _store.pop(key, None)
            return None
    parsed_c = _question(cached)
    if parsed_c is None:
        return None
    elapsed = int(now - stored_at)
    return _rewrite_for_serve(cached, query, qend_q, parsed_c[3], elapsed)


def put(query: bytes, response: bytes) -> None:
    """Store ``response`` for ``query`` if it is safe to cache (best-effort)."""
    parsed = _question(query)
    if parsed is None:
        return
    qname, qtype, qclass, qend_q = parsed
    if struct.unpack_from("!H", query, 2)[0] & 0x7800:  # opcode != QUERY
        return  # don't key a non-QUERY (STATUS/NOTIFY/UPDATE) under a plain name
    parsed_r = _question(response)
    if parsed_r is None:
        return
    if not (struct.unpack_from("!H", response, 2)[0] & 0x8000):
        return  # not a response (QR=0); never cache
    ttl = _cacheable_ttl(response, parsed_r[3])
    if ttl is None:
        return
    key = _key(qname, qtype, qclass, _do_bit(query, qend_q))
    now = _clock()
    with _lock:
        _evict_if_full()
        _store[key] = [response, now, now + ttl]


def resolve(query: bytes) -> bytes:
    """Cache-aware drop-in for ``doh.resolve``: serve from cache or fetch over DoH
    and store. Raises exactly like ``doh.resolve`` on a fetch failure, so callers
    keep failing closed."""
    if not config.DNS_CACHE:
        return doh.resolve(query)
    hit = get(query)
    if hit is not None:
        return hit
    answer = doh.resolve(query)
    try:
        put(query, answer)
    except Exception:  # noqa: BLE001 - caching must never break a good answer
        log.debug("cache store skipped", exc_info=True)
    return answer


def clear() -> None:
    """Drop all entries (test/teardown helper)."""
    with _lock:
        _store.clear()
