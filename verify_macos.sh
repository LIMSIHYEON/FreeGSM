#!/usr/bin/env bash
#
# verify_macos.sh -- live verification harness for the FreeGSM macOS port.
#
# Unit tests cover the pure/parsing logic; this script verifies the parts that
# can only be checked against a real utun + a real network: that DoH is live, the
# DNS cache speeds up repeats, SNI/443 fragments, IPv6 is redirected, the network
# -change monitor re-applies routes on a link switch, and the pf plaintext-DNS
# kill switch actually drops. Start FreeGSM in another terminal first, then run
# this. It only reads state and sends harmless `dig` probes -- it changes nothing.
#
#   ./verify_macos.sh              # status + all automatic checks, then guidance
#   ./verify_macos.sh status       # snapshot the current state
#   ./verify_macos.sh doh          # DoH active + resolving
#   ./verify_macos.sh cache        # DNS cache hit is faster than the miss
#   ./verify_macos.sh sni          # TLS ClientHello fragmentation (verify_lolps.py)
#   ./verify_macos.sh ipv6         # IPv6 redirect (if the host has a v6 default)
#   ./verify_macos.sh netchange    # GUIDED: switch the link, confirm re-apply
#   ./verify_macos.sh killswitch   # pf drop of plaintext DNS / QUIC (DPI-off opt-in)
#   ./verify_macos.sh vpn          # VPN coexistence: DNS-leak + route-hijack checks
#
set -uo pipefail

TUN_DEV="${FREEGSM_TUN_DEVICE:-utun123}"
TUN_ADDR6="${FREEGSM_TUN_ADDR6:-fd00:6f73:6d00::1}"
STATE_DIR="/Library/Application Support/FreeGSM"
PF_MARKER="$STATE_DIR/pf_state.json"

if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
  C_G=$(tput setaf 2); C_R=$(tput setaf 1); C_Y=$(tput setaf 3)
  C_B=$(tput bold); C_0=$(tput sgr0)
else
  C_G=""; C_R=""; C_Y=""; C_B=""; C_0=""
fi

PASS=0; FAIL=0; SKIP=0
pass() { printf "  ${C_G}PASS${C_0}  %s\n" "$1"; PASS=$((PASS+1)); }
fail() { printf "  ${C_R}FAIL${C_0}  %s\n" "$1"; FAIL=$((FAIL+1)); }
skip() { printf "  ${C_Y}SKIP${C_0}  %s\n" "$1"; SKIP=$((SKIP+1)); }
info() { printf "        %s\n" "$1"; }
hdr()  { printf "\n${C_B}== %s ==${C_0}\n" "$1"; }

# Pick the python that has httpx (the project venv if present).
PY="python3"
[ -x ".venv/bin/python" ] && PY=".venv/bin/python"

have() { command -v "$1" >/dev/null 2>&1; }

# ----- shared probes -------------------------------------------------------- #
first_nameserver() { scutil --dns 2>/dev/null | awk '/nameserver\[0\]/{print $3; exit}'; }
default_gw()   { route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}'; }
default_if()   { route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}'; }
default_gw6()  { route -n get -inet6 default 2>/dev/null | awk '/gateway:/{print $2; exit}'; }
default_if6()  { route -n get -inet6 default 2>/dev/null | awk '/interface:/{print $2; exit}'; }
ifscope_gw()   { route -n get -ifscope "$1" default 2>/dev/null | awk '/gateway:/{print $2; exit}'; }
tunnel_up()    { ifconfig "$TUN_DEV" >/dev/null 2>&1; }
killswitch_armed() { [ -f "$PF_MARKER" ]; }
dig_qtime() { # $1=server $2=name -> "Query time" msec, or empty on failure
  dig "@$1" +tries=1 +timeout=3 "$2" 2>/dev/null | awk -F': ' '/Query time/{print $2}' | awk '{print $1}'
}
# First real A record from a `dig +short`, ignoring dig's own diagnostics: on a
# timeout/refusal `dig +short` prints ";; connection timed out ..." to STDOUT, so
# a bare `tail -n1` would mistake that error line for an answer. Filtering to a
# literal IPv4 means a dropped/failed query yields empty (the real signal).
first_ipv4() { grep -Eo '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' | tail -n1; }

require_running() {
  if ! dig @127.0.0.1 +tries=1 +timeout=3 +short example.com >/dev/null 2>&1; then
    printf "${C_R}FreeGSM does not appear to be running${C_0} (127.0.0.1:53 is not answering).\n"
    printf "Start it first in another terminal:  sudo %s -m dohproxy.macos.main\n" "$PY"
    return 1
  fi
  return 0
}

# ----- status --------------------------------------------------------------- #
cmd_status() {
  hdr "status"
  local ns gw4 if4 gw6 if6
  ns=$(first_nameserver); gw4=$(default_gw); if4=$(default_if)
  gw6=$(default_gw6); if6=$(default_if6)
  info "system resolver (nameserver[0]) : ${ns:-<none>}"
  info "default route (v4)              : ${gw4:-<none>} via ${if4:-<none>}"
  if [ -n "$gw6" ]; then
    info "default route (v6)              : $gw6 via ${if6:-<none>}"
  else
    info "default route (v6)              : <none>"
  fi
  if tunnel_up; then
    info "tunnel device ${TUN_DEV}          : UP"
    if netstat -rn 2>/dev/null | grep -qE "^(0/1|0\.0\.0\.0/1)[[:space:]].*$TUN_DEV"; then
      info "  v4 default override (0/1)     : -> $TUN_DEV"
    fi
    if ifconfig "$TUN_DEV" 2>/dev/null | grep -q "$TUN_ADDR6"; then
      info "  v6 address on tunnel          : present ($TUN_ADDR6)"
    fi
    if netstat -rnf inet6 2>/dev/null | grep -qE "::/1.*$TUN_DEV"; then
      info "  v6 default override (::/1)    : -> $TUN_DEV"
    fi
  else
    info "tunnel device ${TUN_DEV}          : not present (DoH-only / DPI off)"
  fi
  if killswitch_armed; then
    info "pf plaintext-DNS kill switch    : ARMED"
  else
    info "pf plaintext-DNS kill switch    : not armed"
  fi
}

# ----- DoH ------------------------------------------------------------------ #
cmd_doh() {
  hdr "DoH (system resolver -> loopback -> DoH)"
  local ns; ns=$(first_nameserver)
  if [ "$ns" = "127.0.0.1" ]; then
    pass "system resolver points at the local DoH resolver (127.0.0.1)"
  else
    fail "system resolver is '${ns:-<none>}', expected 127.0.0.1 (is FreeGSM running?)"
  fi
  local ip; ip=$(dig @127.0.0.1 +tries=1 +timeout=4 +short example.com 2>/dev/null | first_ipv4)
  if [ -n "$ip" ]; then
    pass "loopback resolver answers (example.com -> $ip) -- DoH path live"
  else
    fail "loopback resolver did not answer (DoH round-trip failed / fail-closed)"
  fi
  local iptcp; iptcp=$(dig @127.0.0.1 +tcp +tries=1 +timeout=4 +short example.com 2>/dev/null | first_ipv4)
  if [ -n "$iptcp" ]; then
    pass "TCP/53 path answers too (example.com -> $iptcp)"
  else
    fail "TCP/53 path did not answer"
  fi
}

# ----- DNS cache ------------------------------------------------------------ #
cmd_cache() {
  hdr "DNS cache (repeat lookup served from memory)"
  local name="www.wikipedia.org"
  local t1 t2
  t1=$(dig_qtime 127.0.0.1 "$name")   # likely a miss -> DoH round-trip
  t2=$(dig_qtime 127.0.0.1 "$name")   # should be a cache hit
  if [ -z "$t1" ] || [ -z "$t2" ]; then
    skip "could not measure query times (resolver not answering?)"
    return
  fi
  info "first lookup (miss) : ${t1} msec"
  info "second lookup (hit) : ${t2} msec"
  # A hit should be markedly faster than a network round-trip and near-instant.
  if [ "$t2" -le "$t1" ] && [ "$t2" -le 5 ]; then
    pass "repeat lookup is a fast cache hit (${t2} msec <= ${t1} msec)"
  elif [ "$t2" -lt "$t1" ]; then
    pass "repeat lookup faster than the miss (${t2} < ${t1} msec)"
  else
    skip "inconclusive (${t2} vs ${t1} msec) -- cache may be disabled (FREEGSM_DNS_CACHE=0) or the miss was already warm"
  fi
}

# ----- SNI/443 -------------------------------------------------------------- #
cmd_sni() {
  hdr "SNI/443 fragmentation"
  if ! tunnel_up; then
    skip "tunnel ($TUN_DEV) not up -- DPI is off, nothing to fragment"
    return
  fi
  if [ ! -f verify_lolps.py ]; then
    skip "verify_lolps.py not found"
    return
  fi
  local out
  out=$("$PY" verify_lolps.py 2>&1)
  printf "%s\n" "$out" | sed 's/^/        /'
  if printf "%s" "$out" | grep -qiE "HTTP 200|2 TLS records|OK"; then
    pass "ClientHello fragmented and the request succeeded"
  else
    fail "verify_lolps.py did not report success (see output above)"
  fi
}

# ----- IPv6 ----------------------------------------------------------------- #
cmd_ipv6() {
  hdr "IPv6 redirect"
  if [ -z "$(default_gw6)" ]; then
    skip "host has no IPv6 default route -- nothing to redirect (expected on v4-only nets)"
    return
  fi
  if ! tunnel_up; then
    skip "tunnel not up (DPI off) -- IPv6 SNI is not fragmented in this mode"
    return
  fi
  if [ "${FREEGSM_TUNNEL_IPV6:-1}" = "0" ]; then
    skip "FREEGSM_TUNNEL_IPV6=0 -- IPv6 redirect intentionally disabled"
    return
  fi
  local ok=1
  if ifconfig "$TUN_DEV" 2>/dev/null | grep -q "$TUN_ADDR6"; then
    pass "tunnel has its IPv6 address ($TUN_ADDR6)"
  else
    fail "tunnel is missing its IPv6 address"; ok=0
  fi
  if netstat -rnf inet6 2>/dev/null | grep -qE "::/1.*$TUN_DEV"; then
    pass "IPv6 default override (::/1 + 8000::/1) -> $TUN_DEV"
  else
    fail "IPv6 ::/1 override not pointing at $TUN_DEV (v6 SNI exposed)"; ok=0
  fi
  local ip6; ip6=$(dig @127.0.0.1 +tries=1 +timeout=4 +short AAAA cloudflare.com 2>/dev/null | tail -n1)
  [ -n "$ip6" ] && info "AAAA resolves (cloudflare.com -> $ip6)"
  [ "$ok" = 1 ] && return 0 || return 1
}

# ----- network change (guided) --------------------------------------------- #
cmd_netchange() {
  hdr "network-change re-apply (GUIDED)"
  if ! tunnel_up; then
    skip "tunnel not up (DPI off): only the DNS re-assert runs DoH-only; re-run with DPI on to test route re-apply"
  fi
  local gw0 if0; gw0=$(default_gw); if0=$(default_if)
  info "current default route: ${gw0:-<none>} via ${if0:-<none>}"
  if [ -n "$if0" ]; then
    local sc; sc=$(ifscope_gw "$if0")
    info "current ifscope default for $if0: ${sc:-<none>}  (this is the SOCKS upstream's path off the utun)"
  fi
  printf "\n%sSwitch the active link now%s, then press ENTER:\n" "$C_B" "$C_0"
  info "e.g. toggle Wi-Fi off then on, plug/unplug Ethernet, or:"
  info "    sudo networksetup -setairportpower $if0 off ; sleep 3 ; sudo networksetup -setairportpower $if0 on"
  read -r _
  info "waiting a few seconds for the monitor to react (route-socket wake is sub-second)..."
  sleep 4
  local gw1 if1; gw1=$(default_gw); if1=$(default_if)
  info "new default route: ${gw1:-<none>} via ${if1:-<none>}"
  if [ -z "$gw1" ] || [ -z "$if1" ]; then
    fail "no default route after the switch -- network still down?"
    return
  fi
  # The monitor should have rebuilt the ifscope default + DoH host-route for the
  # new gateway/interface. The ifscope default for the *new* interface should now
  # point at the new gateway.
  local sc1; sc1=$(ifscope_gw "$if1")
  if [ "$sc1" = "$gw1" ]; then
    pass "ifscope default for $if1 re-applied to new gateway $gw1 (SOCKS upstream path restored)"
  else
    fail "ifscope default for $if1 is '${sc1:-<none>}', expected $gw1 -- monitor did not re-apply (or it is mid-poll)"
  fi
  # NB: a cached DNS name resolves from memory even when the tunnel's data plane
  # is broken, so this alone is a weak signal -- the through-tunnel fetch below is
  # the real test. Use a random label so it can't be a cache hit / masked.
  if dig @127.0.0.1 +tries=1 +timeout=5 +short "verify-$$.example.com" A >/dev/null 2>&1; then
    pass "DNS still resolves after the switch (fresh, un-cached name)"
  else
    fail "DNS broken after the switch"
  fi
  # The bug a same-gateway link bounce can cause is that the SOCKS upstream's
  # ifscope route gets flushed with the interface and never rebuilt, so cached DNS
  # keeps working but every NEW connection through the tunnel fails (ENETUNREACH).
  # Force a fresh HTTPS connection THROUGH the tunnel to catch exactly that.
  if tunnel_up; then
    if have curl; then
      local code
      code=$(curl -4 --max-time 12 -sS -o /dev/null -w '%{http_code}' https://example.com/ 2>/dev/null)
      if [ -n "$code" ] && [ "$code" != "000" ]; then
        pass "fresh HTTPS through the tunnel works after the switch (HTTP $code -- SOCKS upstream route intact)"
      else
        fail "fresh HTTPS through the tunnel FAILED after the switch -- SOCKS upstream route not restored (scoped route flushed and not rebuilt)"
      fi
    else
      info "install curl to auto-check a fresh through-tunnel connection; meanwhile load a new HTTPS site in a browser"
    fi
  fi
}

# ----- kill switch ---------------------------------------------------------- #
cmd_killswitch() {
  hdr "pf DPI-off kill switch (plaintext DNS + QUIC, opt-in)"
  local rules="$STATE_DIR/freegsm.pf.conf"
  local dns_armed=0 quic_armed=0
  if killswitch_armed; then
    grep -q "port = 53"  "$rules" 2>/dev/null && dns_armed=1
    grep -q "port = 443" "$rules" 2>/dev/null && quic_armed=1
  fi
  local probe; probe=$(dig @8.8.8.8 +tries=1 +timeout=3 +short example.com 2>/dev/null | first_ipv4)
  if killswitch_armed; then
    info "kill switch marker present -> armed (DPI off). DNS block: $([ $dns_armed = 1 ] && echo on || echo off), QUIC block: $([ $quic_armed = 1 ] && echo on || echo off)"
    if [ "$dns_armed" = 1 ]; then
      if [ -z "$probe" ]; then
        pass "plaintext DNS to 8.8.8.8 is DROPPED (fail-closed; no leak)"
      else
        fail "LEAK: 8.8.8.8 answered (example.com -> $probe) despite the kill switch"
      fi
      if dig @127.0.0.1 +tries=1 +timeout=4 +short example.com >/dev/null 2>&1; then
        pass "loopback DoH resolver still works (loopback :53 is exempt from the block)"
      else
        fail "loopback resolver blocked too -- the 127.0.0.0/8 exemption is wrong"
      fi
    fi
    if [ "$quic_armed" = 1 ]; then
      info "QUIC block armed: UDP/443 to non-loopback is dropped -> HTTP/3 apps fall back to TCP/443."
      info "verify in a browser: open chrome://net-internals/#quic on an HTTP/3 site; connections should show no active QUIC session."
    fi
  else
    skip "kill switch not armed. To test it, run DoH-only with a switch on:"
    info "    sudo FREEGSM_DPI=0 FREEGSM_BLOCK_PLAINTEXT_DNS=1 $PY -m dohproxy.macos.main   # DNS"
    info "    sudo FREEGSM_DPI=0 FREEGSM_BLOCK_PLAINTEXT_QUIC=1 $PY -m dohproxy.macos.main  # QUIC (add to force HTTP/3->TCP)"
    info "    then re-run: ./verify_macos.sh killswitch"
    if [ -n "$probe" ]; then
      info "(sanity) 8.8.8.8 currently answers (example.com -> $probe) -- expected when not armed"
    fi
  fi
}

# ----- VPN (guided + auto-checks) ------------------------------------------- #
cmd_vpn() {
  hdr "VPN coexistence"
  # Auto-check 1: is the effective primary resolver still ours? A full-tunnel VPN
  # can set DNS via configd (invisible to networksetup), leaking lookups past DoH.
  local ns; ns=$(first_nameserver)
  if [ "$ns" = "127.0.0.1" ]; then
    pass "primary DNS resolver is the local DoH resolver (127.0.0.1) -- no VPN DNS leak"
  elif [ -z "$ns" ]; then
    skip "could not read the primary resolver (scutil --dns)"
  else
    fail "primary DNS resolver is '$ns', not 127.0.0.1 -- a VPN/scoped resolver owns DNS; lookups may bypass DoH"
    info "point the VPN's DNS at 127.0.0.1 (or split-tunnel its DNS) for DoH coverage there"
  fi
  # Auto-check 2: do our default-override routes still point at the tunnel? A VPN
  # using the same 0/1+128/1 trick can steal them and bypass the SNI splitter.
  if tunnel_up; then
    if netstat -rn 2>/dev/null | grep -qE "^(0/1|0\.0\.0\.0/1)[[:space:]].*$TUN_DEV"; then
      pass "v4 default override (0/1) still -> $TUN_DEV -- SNI splitter in the path"
    else
      local owner; owner=$(netstat -rn 2>/dev/null | awk '$1=="0/1"||$1=="0.0.0.0/1"{print $4; exit}')
      fail "v4 default override (0/1) is -> ${owner:-<gone>}, not $TUN_DEV -- a VPN hijacked the default; SNI fragmentation BYPASSED"
      info "disable the conflicting VPN tunnel, or FreeGSM's DPI, to avoid the route war"
    fi
  else
    skip "tunnel not up (DPI off): no default override to check"
  fi
  # Auto-check 3: the REVERSE conflict -- is FreeGSM shadowing a full-tunnel VPN?
  # A gateway-less default via a FOREIGN utun means a VPN is up but our /1
  # overrides win, so app TCP exits the physical link and BYPASSES the VPN (real
  # IP exposed). Mirrors netmonitor._check_reverse_vpn_bypass.
  if tunnel_up; then
    local droute dgw diface foreign_tun=0
    droute=$(route -n get default 2>/dev/null || true)
    dgw=$(printf '%s\n' "$droute" | awk '/gateway:/{print $2; exit}')
    diface=$(printf '%s\n' "$droute" | awk '/interface:/{print $2; exit}')
    case "$diface" in utun*|ipsec*) foreign_tun=1 ;; esac
    if [ -z "$dgw" ] && [ -n "$diface" ] && [ "$diface" != "$TUN_DEV" ] && [ "$foreign_tun" = 1 ]; then
      fail "default is gateway-less via $diface (a full-tunnel VPN) but FreeGSM's /1 overrides shadow it -- app TCP BYPASSES the VPN and your real IP is exposed (SNI still fragmented)"
      info "disable FreeGSM's DPI to let the VPN carry traffic, or stop the VPN if you want FreeGSM's path"
    else
      pass "FreeGSM is not shadowing a full-tunnel VPN (default via ${diface:-<none>}${dgw:+, gw $dgw})"
    fi
  fi
  # Guided steps for the parts that need you to toggle the VPN.
  printf "\n%sGuided%s: to exercise the mid-session transitions:\n" "$C_B" "$C_0"
  info "  1. With FreeGSM running, connect your VPN, then re-run: ./verify_macos.sh vpn status ipv6"
  info "     - the two checks above should stay PASS (or tell you exactly what leaked)."
  info "     - if the VPN brought up an IPv6 default, 'ipv6' should show ::/1 on $TUN_DEV"
  info "       (netmonitor brings the v6 redirect up mid-session)."
  info "  2. Browse an HTTPS site to confirm traffic still flows."
  info "  3. Disconnect the VPN and re-run 'status' to confirm clean fallback."
}

summary() {
  printf "\n${C_B}== summary ==${C_0}  ${C_G}%d passed${C_0}, ${C_R}%d failed${C_0}, ${C_Y}%d skipped${C_0}\n" \
    "$PASS" "$FAIL" "$SKIP"
  [ "$FAIL" -eq 0 ]
}

main() {
  local cmds=("$@")
  [ ${#cmds[@]} -eq 0 ] && cmds=(all)
  for c in "${cmds[@]}"; do
    case "$c" in
      all)
        cmd_status
        require_running || { summary; exit 1; }
        cmd_doh; cmd_cache; cmd_sni; cmd_ipv6
        printf "\n${C_B}Guided scenarios${C_0} (run individually, they need you to act):\n"
        info "  ./verify_macos.sh netchange    # switch Wi-Fi/Ethernet"
        info "  ./verify_macos.sh killswitch   # needs DPI-off + FREEGSM_BLOCK_PLAINTEXT_DNS=1"
        info "  ./verify_macos.sh vpn          # connect/disconnect a VPN"
        ;;
      status)      cmd_status ;;
      doh)         require_running && cmd_doh ;;
      cache)       require_running && cmd_cache ;;
      sni)         cmd_sni ;;
      ipv6)        cmd_ipv6 ;;
      netchange)   require_running && cmd_netchange ;;
      killswitch)  cmd_killswitch ;;
      vpn)         cmd_vpn ;;
      *) printf "unknown check: %s\n" "$c"; printf "valid: status doh cache sni ipv6 netchange killswitch vpn all\n"; exit 2 ;;
    esac
  done
  summary
}

main "$@"
