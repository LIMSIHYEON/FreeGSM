"""pf-based DPI-off kill switch for the macOS port (plaintext DNS + QUIC).

The macOS DoH coverage has one residual gap versus Windows. Windows captures
*all* outbound UDP/53 + TCP/53 regardless of destination, so an app with a
hardcoded plaintext DNS server is intercepted and upgraded too. macOS closes that
gap **when the DPI tunnel is on** (every UDP datagram reaches the SOCKS proxy via
UDP ASSOCIATE and a UDP/53 query is re-resolved over DoH -- see socks_proxy). But
with **DPI off** there is no tunnel, so a hardcoded-DNS app still talks straight
to its plaintext server, bypassing the local resolver entirely.

There is no way to transparently *upgrade* that traffic without the tunnel: pf's
``rdr`` does not match locally-originated connections (spike A, see
docs/MACOS_PORT.md appendix), and macOS has no ``divert-to``. pf *filtering*,
however, DOES apply to locally-originated outbound packets. So the best we can do
DPI-off is **fail closed**: drop plaintext DNS to anything but the loopback
resolver, exactly mirroring the project's fail-closed stance (a dropped query is
strictly better than a leaked one). The hardcoded-DNS app loses that DNS path
rather than leaking it; well-behaved apps then fall back to the system resolver
(127.0.0.1 -> DoH).

The same lever covers a second DPI-off gap: QUIC/HTTP-3 (UDP/443). With DPI on the
SOCKS proxy drops it so HTTP/3 falls back to the SNI-fragmented TCP path; DPI-off
there is no splitter, so an optional UDP/443 drop at least forces HTTP/3 apps back
to plain TCP/443 (useful where QUIC is blocked/throttled wholesale) and keeps the
fail-closed posture. TCP/443 is never dropped -- that would kill all HTTPS -- and
the DoH channel rides TCP, so neither block touches it.

Both blocks are **opt-in** (FREEGSM_BLOCK_PLAINTEXT_DNS / _QUIC, default off) and
only take effect when DPI is off. Dropping plaintext DNS can break an app that
*only* ever uses a specific external DNS (some VPN clients, split-horizon
corporate DNS, Tailscale's 100.100.100.100); with DPI on the tunnel already
upgrades the same traffic and a pf block would instead break that upgrade by
dropping UDP/53 inside utun.

Lifecycle (mirrors dns_control / tunnel): the original pf ruleset is restored
from /etc/pf.conf and pf's enabled state is restored via the ``-E``/``-X``
reference-count token, so a machine whose pf was disabled ends up disabled again.
A marker file records that we touched pf so a crashed run is reconciled on the
next start. All steps are best-effort and idempotent -- a pf failure must never
block the DNS/route restore that the rest of teardown depends on.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path

from .. import config

log = logging.getLogger("dohproxy.macos.pf")

# The system's default main ruleset; restore() reloads this to drop our rules.
SYSTEM_PF_CONF = "/etc/pf.conf"

# Where we write the ruleset we load and the crash-recovery marker.
_STATE_DIR = Path("/Library/Application Support/FreeGSM")
RULES_FILE = _STATE_DIR / "freegsm.pf.conf"
MARKER_FILE = _STATE_DIR / "pf_state.json"

# In-memory record of whether we are active and the enable-reference token from
# ``pfctl -E`` (used by ``pfctl -X`` to release on restore).
_active = False
_token: str | None = None


def build_ruleset(block_dns: bool = True, block_quic: bool = False) -> str:
    """The pf main ruleset we load: re-declare Apple's anchors (so system features
    like Internet Sharing keep working) then, per the requested blocks, drop
    plaintext DNS and/or QUIC to any non-loopback destination, for both families.

    ``block_dns`` drops outbound :53 (UDP+TCP) -- the plaintext-DNS kill switch.
    ``block_quic`` drops outbound UDP :443 (QUIC/HTTP-3) so HTTP/3 falls back to
    TCP/443; TCP :443 is deliberately NOT blocked (that would kill all HTTPS).

    pf evaluates by rule class, so the translation anchors (nat/rdr) must precede
    our filter (block) rules. ``quick`` makes the drop take effect on first match
    regardless of any later (default-pass) behaviour. Loopback is excluded so the
    local resolver on 127.0.0.1:53 -- and any user-run local resolver -- is never
    blocked; the DoH channel itself rides TCP :443 (HTTP/2), never UDP or :53, so
    it is unaffected by either block."""
    rules = [
        "# FreeGSM DPI-off kill switch (fail-closed). Auto-generated; removed and",
        "# pf restored from /etc/pf.conf when FreeGSM stops.",
        'scrub-anchor "com.apple/*"',
        'nat-anchor "com.apple/*"',
        'rdr-anchor "com.apple/*"',
        'dummynet-anchor "com.apple/*"',
        'anchor "com.apple/*"',
        'load anchor "com.apple" from "/etc/pf.anchors/com.apple"',
        "",
    ]
    if block_dns:
        rules += [
            "block drop out quick proto udp from any to !127.0.0.0/8 port = 53",
            "block drop out quick proto tcp from any to !127.0.0.0/8 port = 53",
            "block drop out quick proto udp from any to !::1 port = 53",
            "block drop out quick proto tcp from any to !::1 port = 53",
        ]
    if block_quic:
        # UDP/443 only -- blocking TCP/443 would take down all HTTPS.
        rules += [
            "block drop out quick proto udp from any to !127.0.0.0/8 port = 443",
            "block drop out quick proto udp from any to !::1 port = 443",
        ]
    return "\n".join(rules) + "\n"


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(["pfctl", *args], capture_output=True, text=True, check=False)


def _parse_token(stderr: str) -> str | None:
    """Extract the reference token from ``pfctl -E`` output ('Token : 12345...')."""
    m = re.search(r"Token\s*:\s*(\d+)", stderr)
    return m.group(1) if m else None


def _write_marker() -> None:
    try:
        _STATE_DIR.mkdir(parents=True, exist_ok=True)
        MARKER_FILE.write_text(json.dumps({"token": _token}), encoding="utf-8")
    except OSError as exc:
        log.warning("could not persist pf marker: %s", exc)


def _clear_marker() -> None:
    try:
        MARKER_FILE.unlink(missing_ok=True)
    except OSError:
        pass


def _reconcile_leftover() -> None:
    """If a previous run died without restoring pf, reload the system ruleset and
    release its enable token. Best-effort: pf state does not survive a reboot, so
    a stale token simply fails to release, which is harmless."""
    try:
        state = json.loads(MARKER_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    log.warning("Found leftover pf state from a previous run; restoring pf.")
    _run(["-f", SYSTEM_PF_CONF])
    tok = state.get("token")
    if tok:
        _run(["-X", str(tok)])
    _clear_marker()


def install(block_dns: bool = True, block_quic: bool = False) -> bool:
    """Load the kill-switch ruleset and enable pf (reference-counted). ``block_dns``
    drops plaintext :53, ``block_quic`` drops UDP/443 (QUIC). Returns True if the
    block is now active, False if it could not be set up (in which case nothing is
    left changed) or if neither block was requested. Idempotent via ``_active``."""
    global _active, _token
    if _active:
        return True
    if not (block_dns or block_quic):
        return False  # nothing to arm

    _reconcile_leftover()

    try:
        _STATE_DIR.mkdir(parents=True, exist_ok=True)
        RULES_FILE.write_text(build_ruleset(block_dns, block_quic), encoding="utf-8")
    except OSError as exc:
        log.error("could not write pf ruleset (%s); DPI-off kill switch not active.", exc)
        return False

    load = _run(["-f", str(RULES_FILE)])
    if load.returncode != 0:
        # Loading failed (syntax/permission). Restore the system ruleset in case a
        # partial load took, and give up -- never leave pf in our half-state.
        log.error("pf rule load failed (%s); restoring system ruleset, block not active.",
                  load.stderr.strip())
        _run(["-f", SYSTEM_PF_CONF])
        return False

    enable = _run(["-E"])
    if enable.returncode != 0:
        log.error("pf enable failed (%s); restoring system ruleset, block not active.",
                  enable.stderr.strip())
        _run(["-f", SYSTEM_PF_CONF])
        return False

    _token = _parse_token(enable.stderr)
    _active = True
    _write_marker()
    blocked = []
    if block_dns:
        blocked.append("UDP/TCP :53 (plaintext DNS)")
    if block_quic:
        blocked.append("UDP :443 (QUIC/HTTP-3)")
    log.info("DPI-off kill switch active (pf): %s to non-loopback dropped "
             "(fail-closed). DPI is off, so this traffic can't leak.",
             " + ".join(blocked))
    return True


def restore() -> None:
    """Reload the system pf ruleset (dropping our block) and release our enable
    reference so pf returns to its original on/off state. Idempotent and
    best-effort: safe from a finally block, a signal handler, and atexit."""
    global _active, _token
    # Never touch pf if we never set it up: with no in-memory active flag and no
    # leftover marker, there is nothing of ours to undo, and reloading the system
    # ruleset here would disturb pf for a user who never opted in.
    if not _active and not MARKER_FILE.exists():
        return
    # Reload system rules first so the block is gone even if pf stays enabled
    # (because something else also enabled it).
    reload = _run(["-f", SYSTEM_PF_CONF])
    if reload.returncode != 0 and (_active or MARKER_FILE.exists()):
        log.error("could not reload %s (%s); plaintext-DNS block may persist.",
                  SYSTEM_PF_CONF, reload.stderr.strip())
    if _token:
        _run(["-X", _token])
    elif MARKER_FILE.exists():
        # Restoring after a crash (no in-memory token): use the persisted one.
        try:
            tok = json.loads(MARKER_FILE.read_text(encoding="utf-8")).get("token")
        except (OSError, ValueError):
            tok = None
        if tok:
            _run(["-X", str(tok)])
    _clear_marker()
    if _active:
        log.info("plaintext-DNS kill switch removed; pf restored.")
    _active = False
    _token = None
