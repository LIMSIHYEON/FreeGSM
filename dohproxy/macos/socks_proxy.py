"""Local SOCKS5 proxy that fragments the TLS ClientHello (macOS DPI bypass).

In the macOS DPI design, tun2socks reads the utun device, terminates each
outbound TCP flow, and forwards it here as a SOCKS5 CONNECT. This proxy:

  * opens an upstream socket to the real destination, PINNED to the physical
    interface via IP_BOUND_IF so it bypasses utun (no routing loop -- the macOS
    analogue of the WinDivert reserved-port exclusion);
  * for :443, re-emits the first client segment (the ClientHello) as two TLS
    records via dpi.split_hello, so a one-record SNI matcher can't read the
    host; for any other port it just pipes through;
  * then runs a dumb bidirectional pipe.

CONNECT and UDP ASSOCIATE are supported. UDP ASSOCIATE is what closes the
hardcoded-DNS gap: with the tunnel up, every outbound UDP datagram reaches us
via tun2socks, so a UDP/53 query to an app's hardcoded plaintext DNS server is
re-resolved over DoH here instead of leaking. UDP/443 (QUIC) is dropped (so
HTTP/3 falls back to the SNI-fragmented TCP path) and other UDP is relayed to
the real destination, pinned off the utun the same way as the TCP upstream.

It binds 127.0.0.1 so only local clients (tun2socks) can reach it. The TCP
split/relay logic mirrors the Windows https_proxy relay, but this module imports
no pydivert so it loads on macOS.
"""

from __future__ import annotations

import logging
import selectors
import socket
import socketserver
import struct
import subprocess
import threading
import time

from .. import config, dnscache, netutil
from ..dnsutil import describe_query, truncated_response, udp_payload_limit

log = logging.getLogger("dohproxy.macos.socks")

# macOS socket options to pin a socket to a specific interface (bypass utun).
IP_BOUND_IF = 25
IPV6_BOUND_IF = 125

# Physical interface index that upstream sockets are pinned to. Set at start and
# updated by the network monitor when the default interface changes.
_bound_if_index = 0

# Bounds concurrent in-flight UDP/53 DoH round-trips (each runs on its own short-
# lived thread) so a burst can't spawn unbounded threads; excess is dropped
# (fail-closed), mirroring the resolver's UDP path.
_udp_dns_inflight = threading.BoundedSemaphore(config.WORKER_THREADS * 2)


def physical_iface() -> str | None:
    """Default-route interface name (e.g. 'en0')."""
    try:
        out = subprocess.run(
            ["route", "-n", "get", "default"], capture_output=True, text=True, check=True
        ).stdout
    except subprocess.CalledProcessError:
        return None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            return line.split()[1]
    return None


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def set_bound_iface(iface: str) -> bool:
    """Re-pin upstream sockets to ``iface`` (called when the default interface
    changes). Returns False if the index can't be resolved."""
    global _bound_if_index
    try:
        idx = socket.if_nametoindex(iface)
    except OSError:
        return False
    if idx and idx != _bound_if_index:
        _bound_if_index = idx
        log.info("re-pinned upstream sockets to %s (if_index=%d)", iface, idx)
    return bool(idx)


def _pin(s: socket.socket, family: int) -> None:
    """Pin ``s`` to the physical interface so it never re-enters the utun."""
    if not _bound_if_index:
        return
    try:
        if family == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, IPV6_BOUND_IF, _bound_if_index)
        else:
            s.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, _bound_if_index)
    except OSError as exc:
        log.debug("IP_BOUND_IF failed: %s", exc)


def _connect_upstream(host: str, port: int, family: int) -> socket.socket:
    s = socket.socket(family, socket.SOCK_STREAM)
    _pin(s, family)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(config.HTTPS_CONNECT_TIMEOUT)
    s.connect((host, port))
    s.settimeout(None)
    return s


# --------------------------------------------------------------------------- #
# SOCKS5
# --------------------------------------------------------------------------- #
class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        c = self.request
        try:
            self._serve(c)
        except OSError as exc:
            log.debug("socks conn error: %s", exc)

    def _serve(self, c: socket.socket) -> None:
        # Greeting: VER=5, NMETHODS, methods[]
        head = netutil.recv_exactly(c, 2)
        if len(head) < 2 or head[0] != 0x05:
            return
        nmethods = head[1]
        if len(netutil.recv_exactly(c, nmethods)) < nmethods:
            return  # truncated greeting
        c.sendall(b"\x05\x00")  # no authentication

        # Request: VER CMD RSV ATYP DST.ADDR DST.PORT
        req = netutil.recv_exactly(c, 4)
        if len(req) < 4 or req[0] != 0x05:
            return
        cmd, atyp = req[1], req[3]
        if cmd not in (0x01, 0x03):  # CONNECT or UDP ASSOCIATE
            c.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")  # cmd not supported
            return

        if atyp == 0x01:  # IPv4
            addr = netutil.recv_exactly(c, 4)
            if len(addr) < 4:
                return
            host = socket.inet_ntoa(addr)
            family = socket.AF_INET
        elif atyp == 0x04:  # IPv6
            addr = netutil.recv_exactly(c, 16)
            if len(addr) < 16:
                return
            host = socket.inet_ntop(socket.AF_INET6, addr)
            family = socket.AF_INET6
        elif atyp == 0x03:  # domain name
            dlen = netutil.recv_exactly(c, 1)
            if not dlen:
                return
            name = netutil.recv_exactly(c, dlen[0])
            if len(name) < dlen[0]:
                return  # truncated host name
            try:
                host = name.decode("ascii")  # IDNs arrive as ASCII punycode
            except UnicodeDecodeError:
                # Dropping non-ASCII bytes ("ignore") could turn one host name
                # into a different valid one; reject instead.
                c.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")  # host unreachable
                return
            family = 0  # resolve below
        else:
            c.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")  # atyp not supported
            return
        portb = netutil.recv_exactly(c, 2)
        if len(portb) < 2:
            return  # truncated port
        (port,) = struct.unpack("!H", portb)

        if cmd == 0x03:  # UDP ASSOCIATE -- the parsed DST is the client's
            _udp_associate(c)  # expected source addr and is intentionally ignored
            return

        # Resolve domain (tun2socks normally sends an IP, but support both).
        if family == 0:
            try:
                ai = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)[0]
                family, _, _, _, sa = ai
                host = sa[0]
            except OSError:
                c.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")  # host unreachable
                return

        try:
            upstream = _connect_upstream(host, port, family)
        except OSError as exc:
            log.warning("[SOCKS] upstream %s:%d failed: %s", host, port, exc)
            c.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")  # connection refused
            return

        # Success reply (BND.ADDR/PORT are ignored by clients; send zeros).
        c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

        try:
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        try:
            netutil.split_relay(c, upstream, host, port, log, "SOCKS")
        finally:
            upstream.close()


# --------------------------------------------------------------------------- #
# SOCKS5 UDP ASSOCIATE
# --------------------------------------------------------------------------- #
# Datagram wire format (RFC 1928 sec. 7):
#   +-----+------+------+----------+----------+----------+
#   | RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
#   +-----+------+------+----------+----------+----------+
#   |  2  |  1   |  1   | Variable |    2     | Variable |
def _parse_dst(data: bytes, off: int):
    """Parse ATYP/ADDR/PORT starting at ``off``. Returns
    (host, port, family, end_offset) or None on a malformed/unsupported addr."""
    try:
        atyp = data[off]
        off += 1
        if atyp == 0x01:  # IPv4
            host = socket.inet_ntoa(data[off:off + 4]); off += 4
            family = socket.AF_INET
        elif atyp == 0x04:  # IPv6
            host = socket.inet_ntop(socket.AF_INET6, data[off:off + 16]); off += 16
            family = socket.AF_INET6
        elif atyp == 0x03:  # domain
            dlen = data[off]; off += 1
            host = data[off:off + dlen].decode("ascii"); off += dlen
            family = 0
        else:
            return None
        (port,) = struct.unpack_from("!H", data, off)
        off += 2
    except (IndexError, struct.error, UnicodeDecodeError, OSError):
        # OSError: inet_ntoa/inet_ntop reject a truncated address. Treat any
        # malformed datagram as undecodable (drop it) rather than letting it raise
        # and tear down the whole UDP association.
        return None
    return host, port, family, off


def _udp_associate(c: socket.socket) -> None:
    """Service a UDP ASSOCIATE: bind a loopback UDP relay socket, tell tun2socks
    its address, then shuttle datagrams until the TCP control connection closes.

    UDP/53 is upgraded to DoH (fail-closed); UDP/443 is dropped when BLOCK_QUIC
    so HTTP/3 falls back to the SNI-fragmented TCP path; any other UDP is relayed
    to its real destination through a per-flow socket pinned off the utun."""
    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        relay.bind((config.SOCKS_PROXY_HOST, 0))
    except OSError as exc:
        log.warning("[SOCKS] UDP associate bind failed: %s", exc)
        c.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")  # general failure
        relay.close()
        return
    bnd_ip, bnd_port = relay.getsockname()[:2]
    c.sendall(b"\x05\x00\x00\x01" + socket.inet_aton(bnd_ip) + struct.pack("!H", bnd_port))
    log.info("[SOCKS] UDP associate on %s:%d", bnd_ip, bnd_port)

    nat: dict[tuple[str, int], list] = {}  # (host,port) -> [sock, last_ts, dst_hdr]
    client_addr: list = [None]             # tun2socks's UDP source (replies go here)
    sel = selectors.DefaultSelector()
    sel.register(c, selectors.EVENT_READ, "ctrl")
    sel.register(relay, selectors.EVENT_READ, "client")

    def _close_flow(key: tuple[str, int]) -> None:
        st = nat.pop(key, None)
        if st is None:
            return
        try:
            sel.unregister(st[0])
        except (KeyError, ValueError):
            pass
        try:
            st[0].close()
        except OSError:
            pass

    def _on_client() -> None:
        try:
            data, src = relay.recvfrom(65535)
        except OSError:
            return
        client_addr[0] = src
        if len(data) < 4 or data[2] != 0x00:  # FRAG != 0 unsupported
            return
        parsed = _parse_dst(data, 3)
        if parsed is None:
            return
        host, port, family, off = parsed
        dst_hdr = data[3:off]   # ATYP+ADDR+PORT, echoed verbatim on the reply
        payload = data[off:]

        if port == 53:
            _dns_over_doh(relay, src, dst_hdr, payload)
            return
        if port == 443 and config.BLOCK_QUIC:
            return  # drop QUIC -> HTTP/3 falls back to the fragmented TCP path
        if family == 0:
            return  # a domain target inside a datagram is unexpected; drop

        key = (host, port)
        st = nat.get(key)
        if st is None:
            try:
                us = socket.socket(family, socket.SOCK_DGRAM)
                _pin(us, family)
                us.setblocking(False)
            except OSError:
                return
            st = [us, time.monotonic(), dst_hdr]
            nat[key] = st
            sel.register(us, selectors.EVENT_READ, ("upstream", key))
        st[1] = time.monotonic()
        try:
            st[0].sendto(payload, (host, port))
        except OSError:
            _close_flow(key)

    def _on_upstream(key: tuple[str, int], us: socket.socket) -> None:
        try:
            data, _ = us.recvfrom(65535)
        except OSError:
            return
        st = nat.get(key)
        if st is None or client_addr[0] is None:
            return
        st[1] = time.monotonic()
        try:
            relay.sendto(b"\x00\x00\x00" + st[2] + data, client_addr[0])
        except OSError:
            pass

    def _sweep(now: float) -> None:
        for key in [k for k, st in nat.items() if now - st[1] > config.UDP_RELAY_IDLE]:
            _close_flow(key)

    try:
        while True:
            events = sel.select(timeout=config.UDP_RELAY_IDLE)
            for key_obj, _mask in events:
                tag = key_obj.data
                if tag == "ctrl":
                    # Any readability on the control conn = data or EOF; per RFC
                    # 1928 the association ends when this TCP connection drops.
                    if not c.recv(4096):
                        return
                elif tag == "client":
                    _on_client()
                elif isinstance(tag, tuple) and tag[0] == "upstream":
                    _on_upstream(tag[1], key_obj.fileobj)
            _sweep(time.monotonic())
    except OSError as exc:
        log.debug("[SOCKS] UDP associate ended: %s", exc)
    finally:
        for st in list(nat.values()):
            try:
                st[0].close()
            except OSError:
                pass
        sel.close()
        relay.close()


def _dns_over_doh(relay: socket.socket, client, dst_hdr: bytes, query: bytes) -> None:
    """Re-resolve a hardcoded-DNS UDP/53 query over DoH on a short-lived thread,
    then send the answer back wrapped for the original destination. Fail-closed:
    on any DoH error nothing is sent."""
    if not query:
        return
    if not _udp_dns_inflight.acquire(blocking=False):
        log.warning("[SOCKS] UDP/53 queue full; dropping query (fail-closed)")
        return

    def _work() -> None:
        desc = describe_query(query)
        log.info("[INTERCEPT] UDP/53(hardcoded)  %s", desc)
        try:
            answer = dnscache.resolve(query)
        except Exception as exc:  # noqa: BLE001 - fail-closed
            log.warning("[FAILED]    UDP/53  %s  -> DoH error: %s; dropped", desc, exc)
            return
        # Truncate an oversized answer so the client retries over TCP (which the
        # tunnel also splits) rather than relying on droppable IP fragmentation.
        if len(answer) > udp_payload_limit(query):
            tc = truncated_response(query)
            if tc is not None:
                answer = tc
        try:
            relay.sendto(b"\x00\x00\x00" + dst_hdr + answer, client)
        except OSError:
            pass

    def _runner() -> None:
        try:
            _work()
        finally:
            _udp_dns_inflight.release()

    threading.Thread(target=_runner, name="socks-udp-dns", daemon=True).start()


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_server(bound_iface: str | None = None) -> socketserver.ThreadingTCPServer:
    """Start the SOCKS5 splitting proxy. ``bound_iface`` is the physical
    interface (default: auto-detect) that upstream sockets are pinned to.

    Raises RuntimeError if the interface index can't be determined: without the
    IP_BOUND_IF pin the upstream sockets would follow the utun default route and
    loop straight back into this proxy, so we refuse to start (fail-closed)
    rather than serve a routing loop.
    """
    global _bound_if_index
    iface = bound_iface or physical_iface()
    if iface:
        try:
            _bound_if_index = socket.if_nametoindex(iface)
        except OSError:
            _bound_if_index = 0
    if not _bound_if_index:
        raise RuntimeError(
            f"could not determine physical interface index (iface={iface!r}); "
            "refusing to start SOCKS proxy to avoid a utun routing loop"
        )
    log.info("upstream sockets pinned to %s (if_index=%d)", iface, _bound_if_index)

    server = _Server((config.SOCKS_PROXY_HOST, config.SOCKS_PROXY_PORT), _Handler)
    threading.Thread(target=server.serve_forever, name="socks-proxy", daemon=True).start()
    log.info("SOCKS5 splitting proxy listening on %s:%d",
             config.SOCKS_PROXY_HOST, config.SOCKS_PROXY_PORT)
    return server
