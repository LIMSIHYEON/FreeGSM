# FreeGSM

Windows app (Admin-only) that transparently upgrades the machine's plaintext DNS
to **DNS-over-HTTPS** and defeats **SNI-based DPI blocking**, without changing any
system setting. Stop the process and everything reverts. IPv4 only.

Two independent jobs, both driven by a single **WinDivert** capture loop:
1. **DoH** — outbound DNS (UDP/53 + TCP/53) is re-resolved over an encrypted
   HTTP/2 connection to a DoH server. Stateless: a DNS query and a DoH request
   body are the *same bytes* (RFC 8484), so no DNS parsing.
2. **SNI/DPI bypass** — outbound TCP/443 is relayed through a local process that
   re-emits the TLS ClientHello as **two TLS records** (record-layer
   fragmentation, ported from Jigsaw's Intra), so a one-record SNI matcher can't
   read the host while the server reassembles normally. Toggle: `FREEGSM_DPI`.

## Module map (`dohproxy/`)

| File | Responsibility |
|------|----------------|
| `main.py` | Entry: admin check → start DoH client → **probe upstream (refuse to start if unreachable)** → start TCP/HTTPS servers → run capture loop in a daemon thread, Ctrl+C to stop. |
| `config.py` | All tunables + builds the WinDivert `DIVERT_FILTER` string. Read this first to understand the capture filter. |
| `divert.py` | `Diverter`: the one WinDivert handle. `recv()` → `_dispatch()` classifies each packet and routes to a handler. Thread-safe injection via `_send` (a lock). |
| `doh.py` | DoH client (shared `httpx.Client`, HTTP/2, kept-alive). `resolve(query)->bytes`, `probe()`. Raises on failure so callers can fail-closed. Stateless (no DNS parsing). |
| `dnscache.py` | Optional TTL-aware cache in front of `doh.resolve` (`resolve(query)->bytes`). Keyed on the question (qname/qtype/qclass + EDNS DO bit); a hit rewrites the txn ID + 0x20 case and decrements every RR TTL. Any parse anomaly falls through to an un-cached `doh.resolve`, so fail-closed is intact. **Cross-platform**: the macOS resolver + SOCKS UDP/53 path AND the Windows `udp_handler`/`tcp_proxy` handlers all call `dnscache.resolve`. Toggle: `FREEGSM_DNS_CACHE`. |
| `udp_handler.py` | UDP/53: runs on a **thread pool** (blocking DoH round-trip). Mutates the captured packet in place into its reply and injects inbound. |
| `tcp_proxy.py` | TCP/53: WinDivert redirect to a local DoH-terminating server (`socketserver`). Packet rewriting is **inline on the capture thread**. |
| `https_proxy.py` | TCP/443 SNI relay: same redirect trick; terminates the connection, fragments the ClientHello via `dpi.split_hello`, then dumb bidirectional pipe. |
| `dpi.py` | Pure TLS primitives: `split_hello` (the Intra port) + `sni_name` (logging only). No I/O. |
| `dnsutil.py` | `describe_query` — human-readable query string for logs only. Never raises. |

Root: `run.py` (PyInstaller entry, wraps `main`), `verify_lolps.py` (SNI test), `build.ps1`.

## Packet dispatch (`divert.py:_dispatch`)

```
outbound UDP dst:53          -> udp_handler.handle   (thread pool)
TCP, if DPI on and
  (outbound dst:443 OR src==HTTPS_PROXY_PORT) -> https_proxy.handle_packet
TCP otherwise (dst:53 / src==TCP_PROXY_PORT)  -> tcp_proxy.handle_packet
anything else                -> passed through untouched
```

Both TCP relays use the same redirect recipe: rewrite an outbound client→server
packet's destination to `src_addr:<local-port>` and inject it **INBOUND** (aiming
at the host's own interface IP, *not* 127.0.0.1 — loopback injection doesn't work
with WinDivert); rewrite the relay→client reply's source back to the real
`server:port`. A per-relay `_conn_map` keyed by `(src_addr, src_port)` remembers
the original destination; it's touched only from the capture thread, so no lock.

## Invariants — break these and it silently fails

- **Never insert/remove bytes on the WinDivert path.** That desyncs the client
  kernel's TCP sequence numbers and triggers a RST. This is the entire reason the
  ClientHello split happens in a userspace relay (which owns both sockets) rather
  than by editing packets. Mutating addresses/ports/payload-as-whole is fine.
- **Fail-closed.** On any DoH error the query is *dropped*, not leaked in
  plaintext (`FAIL_OPEN=False`). Because of this, `main.py` probes the upstream at
  startup and refuses to run if unreachable — otherwise a bad upstream kills all
  DNS on the machine.
- **The relay's upstream sockets bind to a reserved source-port range**
  (`UPSTREAM_PORT_BASE..+COUNT`, default 30000–32047) that `DIVERT_FILTER`
  excludes, so they're never re-captured (no inject loop). The DoH upstream IP is
  excluded the same way. If you add a new outbound socket on a filtered port,
  exclude it in the filter or you'll capture your own traffic.
- **Injected packets must not re-match the filter.** Redirected queries carry
  dst==proxy-port (not 53); rewritten replies carry src==53. Keep that property
  when editing handlers.
- Handlers run in two regimes: **UDP = thread pool** (blocking DoH ok), **TCP
  packet-rewrite = inline on the capture thread** (must stay fast, non-blocking).

## Commands

```powershell
# Run from source — MUST be an ELEVATED terminal (WinDivert loads a kernel driver)
pip install -r requirements.txt
python -m dohproxy.main

# Build single self-elevating exe -> dist\FreeGSM.exe (bundles WinDivert)
powershell -ExecutionPolicy Bypass -File .\build.ps1

# Verify DoH (app running, elevated)
nslookup example.com        # UDP path
nslookup -vc example.com    # forces TCP path
# Verify SNI bypass: expect "OK  HTTP 200" and a "[HTTPS] ... -> 2 TLS records" log line
python verify_lolps.py [host]
```

No test suite or linter is configured.

## Config (`dohproxy/config.py`, env overrides need no rebuild)

- `FREEGSM_DOH_URL` — upstream. Default `https://1.0.0.1/dns-query` (Cloudflare's
  secondary IP; many networks block `1.1.1.1` *specifically*). Connect to a
  literal IP so resolving the DoH host never needs DNS — the cert's IP SAN covers
  it. Alternatives: `8.8.8.8` (Google), `9.9.9.9` (Quad9). `DOH_SERVER_IP` is
  derived from this to exclude our own channel from capture/fragmentation.
- `FREEGSM_DPI=0` — disable the SNI/443 relay (DoH only).
- `SPLIT_MIN`/`SPLIT_MAX` (6/64) — first-record size bounds, before the SNI.
- Ports: `TCP_PROXY_PORT=53533`, `HTTPS_PROXY_PORT=53444`. `FAIL_OPEN`,
  `WORKER_THREADS=32`, timeouts.
- `FREEGSM_BLOCK_PLAINTEXT_DNS=1` (macOS, default off) — DPI-off fail-closed:
  drops outbound UDP/TCP :53 to non-loopback via pf so a hardcoded-DNS app can't
  leak plaintext. No-op when DPI is on (the tunnel upgrades that traffic instead).
- `FREEGSM_BLOCK_PLAINTEXT_QUIC=1` (macOS, default off) — DPI-off only: pf drops
  outbound UDP/443 (QUIC/HTTP-3) to non-loopback so HTTP/3 falls back to TCP/443.
  TCP/443 is never blocked. Shares `pf_control` with the DNS block; no-op with DPI
  on (SOCKS already drops QUIC). Doesn't hide SNI DPI-off — forces TCP / fail-closed.
- `FREEGSM_DNS_CACHE=0` (default **on**, both ports) — disable the TTL-aware DNS
  cache (`dnscache.py`). `FREEGSM_DNS_CACHE_MAX` (4096 entries),
  `FREEGSM_DNS_CACHE_MAX_TTL` (86400s) bound it.

## Tests

```bash
# stdlib unittest, no extra deps; run from repo root
python -m unittest discover -s tests -v
```

`tests/` covers the macOS port's pure/parsing logic (DPI split, DNS utils,
config, `dnscache` TTL/keying/eviction, `netutil.recv_exactly` framing + `pump`,
`recv_full_hello` multi-segment ClientHello reassembly, and `split_relay`
end-to-end over real socketpairs — a ClientHello fragments into two records while
non-TLS / non-443 traffic stays byte-identical)
and the systemy modules whose shell-outs / sockets are faked: `tunnel` IPv6
device-redirect lifecycle + device-route hijack detection, `pf_control` kill
switch (DNS + QUIC rules), `netmonitor` route-change trigger + route-socket loop
+ hijack warn-once, `dns_control` parsing, `test_vpn` (primary-resolver leak
detection + device-route hijack), `resolver` (UDP/TCP loopback DNS: fail-closed,
TC-truncation, length-prefixed framing — DoH faked at `dnscache.resolve`), and
`socks_proxy` (`_parse_dst`, iface pin/detect `set_bound_iface`/`physical_iface`,
and the hardcoded-DNS `_dns_over_doh` path: fail-closed + truncation + no permit
leak). Tests that import `socks_proxy`/`resolver`/`netmonitor`/`dnscache` pull in
`httpx` and **skip** if it's absent — run in the project venv to exercise them.

The **Windows** WinDivert path is covered too. `test_windows_handlers`:
`udp_handler` in-place query→reply swap + INBOUND inject + fail-closed/`FAIL_OPEN`,
and `tcp_proxy`/`https_proxy` redirect-to-relay-port + reply-src-rewrite + RST/FIN
`_conn_map` cleanup + unknown-reply drop. `test_divert_dispatch`: `Diverter._dispatch`
routing (UDP/53→pool, outbound :443 / relay-reply→HTTPS relay only when `DPI_BYPASS`,
other TCP→DNS proxy, else pass-through) via a bare `__new__` Diverter with a
synchronous stand-in pool. pydivert is pure-Python (the WinDivert kernel driver
only loads when a handle is opened), so these import and their logic runs on macOS
with a faked Packet; the modules **skip** only if pydivert isn't installed. No
linter is configured.

**Live verification** (the parts unit tests can't reach — real utun/network):
`./verify_macos.sh [status|doh|cache|sni|ipv6|netchange|killswitch|vpn|all]`.
Start FreeGSM first; the script only reads state + sends `dig` probes. `killswitch`
covers both the DNS and QUIC pf blocks; `vpn` auto-checks the primary resolver +
default-override routes (then guides you through toggling the VPN); `netchange` is
guided (you switch the link, it confirms the re-apply).

## Known gaps

QUIC/HTTP-3 (UDP/443): DPI-on drops it (`BLOCK_QUIC`) so HTTP/3 falls back to the
fragmented TCP path; DPI-off it's untouched by default but opt-in
`FREEGSM_BLOCK_PLAINTEXT_QUIC=1` drops it via pf (forces TCP; doesn't hide SNI).
443 relay pipes through userspace Python (fine for browsing, slow for bulk). A
ClientHello that spans multiple TCP segments (modern post-quantum/ECH hellos
exceed one ~1460-byte segment) is now reassembled before splitting —
`netutil.recv_full_hello` reads up to the record boundary (capped at
`MAX_CLIENT_HELLO`, the 2^14 spec limit) so the split always fires instead of
forwarding the hello un-split and leaking the SNI. Both relays share it (macOS
`split_relay`; the Windows `https_proxy` relay was migrated onto `split_relay`
too). The DNS cache (`dnscache.py`) is now used by **both ports** (macOS
resolver + SOCKS UDP/53, and the Windows `udp_handler`/`tcp_proxy`).

**macOS DoH coverage differs from Windows.** Windows captures *all* outbound
UDP/53 + TCP/53 regardless of destination, so apps with a hardcoded DNS server
are intercepted too. The macOS port repoints the *system* resolver at loopback
(covers system-resolver apps) **and**, when DPI is on, the SOCKS5 proxy now
implements **UDP ASSOCIATE**: every outbound UDP datagram reaches it via
tun2socks, so a UDP/53 query to an app's hardcoded plaintext DNS server is
re-resolved over DoH there too (`socks_proxy._dns_over_doh`). UDP/443 (QUIC) is
dropped when `BLOCK_QUIC` so HTTP/3 falls back to the SNI-fragmented TCP path;
other UDP is relayed to its real destination (pinned off the utun). So with DPI
on, hardcoded-DNS apps are covered. **DPI-off** (DoH-only, no tunnel) can't
*upgrade* hardcoded DNS (pf `rdr` can't catch locally-originated traffic), but
opt-in `FREEGSM_BLOCK_PLAINTEXT_DNS=1` (`macos/pf_control.py`) *fail-closes* it: a
pf rule drops outbound :53 to non-loopback so the query is dropped, not leaked.
Off by default (it can break apps that need a specific external DNS server). The
same module optionally drops UDP/443 (`FREEGSM_BLOCK_PLAINTEXT_QUIC=1`) DPI-off.

**macOS VPN coexistence.** A full-tunnel VPN can silently defeat FreeGSM two ways;
`netmonitor` now *detects and warns* on each (it doesn't auto-fight — battling a
VPN's routes/resolver risks bricking DNS): (1) a VPN setting DNS via configd
(invisible to `networksetup`) makes the effective primary resolver stop being
`127.0.0.1` — `dns_control.verify_primary_resolver` (via `scutil --dns`, run from
`reconcile`) warns that lookups may bypass DoH; (2) a VPN using the same
`0/1`+`128/1` default-override trick steals our device routes — `tunnel.device_routes_intact`
(via `netstat -rn`) reports it and the monitor warns the SNI splitter is bypassed.
`./verify_macos.sh vpn` surfaces both.

The **reverse** also happens and is *not* warned: with DPI on, FreeGSM's own
`0/1`+`128/1` are more specific than a VPN's `0/0` default, so they shadow it, and
the SOCKS upstream is pinned to the *physical* iface (`IP_BOUND_IF`) — so app TCP
exits via the real link, **bypassing the VPN tunnel and exposing the real IP**
(SNI is still fragmented; a full-tunnel VPN run for anonymity is silently
defeated). `netmonitor` treats a gateway-less VPN default (`route get default` →
`via utunN` with no gateway) as "link down" and keeps the SOCKS pin on the
physical iface rather than chasing the VPN's utun (which would loop / has no usable
scoped gateway), so this is the intended route-war outcome, not a re-pin bug.
Running two full-tunnel tools at once is the fundamental conflict; FreeGSM does not
fight it. Confirmed live (ProtonVPN + DPI on): traffic kept exiting `en0`.

**macOS IPv6.** When the host has an IPv6 default route, the tunnel redirects
IPv6 too (`::/1` + `8000::/1` → utun, plus a v6 ifscope default and v6 DoH
host-route), so IPv6 HTTPS gets the same SNI fragmentation. Disable with
`FREEGSM_TUNNEL_IPV6=0`. IPv6 acquired *mid-session* (e.g. a VPN coming up after
start) is now brought up by `netmonitor` without a restart: `tunnel.reapply_routes`
calls `_enable_v6_device` (utun v6 addr + `::/1`/`8000::/1` device routes) when a
v6 default appears and `_disable_v6_device` when it's lost.

**macOS network-change handling.** `macos/netmonitor.py` is **event-driven**: it
reads the kernel `PF_ROUTE` socket (`AF_ROUTE`) and reconciles within a fraction
of a second of a route add/change/delete, with `FREEGSM_MONITOR_INTERVAL`
(default 10s) only as a *floor* that catches drift a route message can't signal
(e.g. a DHCP renew that changes only a service's DNS). If the routing socket
can't be opened it degrades to pure interval polling. On a change (Wi-Fi↔Ethernet,
DHCP renew) it re-applies the tunnel's ifscope/DoH-exclude routes, re-pins the
SOCKS upstream (`socks_proxy.set_bound_iface`), brings the v6 device redirect
up/down to match, and re-asserts the local resolver across services
(`dns_control.reconcile`). `stop()` wakes the `select()` via a self-pipe; teardown
stops the monitor FIRST so it can't re-add what teardown is removing. A **link
bounce back to the same gateway** (Wi-Fi off→on on the same network) still flushes
the interface-scoped routes with the interface, so `_tick` forgets the last-applied
route whenever the default drops to none — otherwise the unchanged gateway on
recovery would read as "nothing moved" and the flushed ifscope route would never be
rebuilt, leaving the SOCKS upstream `ENETUNREACH` (only cached DNS answering) until
a restart. `verify_macos.sh netchange` forces a fresh through-tunnel HTTPS fetch to
catch exactly this (a cached DNS lookup passes even when the data plane is broken).
