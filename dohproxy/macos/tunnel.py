"""utun + tun2socks tunnel manager (macOS DPI bypass plumbing).

Brings the host's outbound TCP into userspace so the SOCKS5 splitting proxy can
fragment TLS ClientHellos:

  1. launch tun2socks on a utun device, forwarding flows to the local SOCKS5
     proxy (socks_proxy.py);
  2. give the utun a point-to-point address;
  3. exclude the DoH upstream IP (host route via the real gateway) so the DoH
     channel stays direct -- never tunnelled/fragmented (the invariant);
  4. override the default route with 0.0.0.0/1 + 128.0.0.0/1 pointing at the
     utun, so all other outbound TCP enters the tunnel.

The proxy's own upstream sockets bypass the tunnel via IP_BOUND_IF (see
socks_proxy.py), so they need no route exclusion -- only the DoH httpx client,
which can't easily set IP_BOUND_IF, gets the host-route exclusion above.

Teardown deletes every route it added and stops tun2socks (which makes the utun
vanish); it is best-effort and idempotent so it can run from a finally block, a
signal handler, and atexit. Interface routes are not persistent, so a reboot
also clears anything left behind.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

from .. import config

log = logging.getLogger("dohproxy.macos.tunnel")

# Persists the live tun2socks pid + the routes we added, so a crashed run (one
# killed before stop() could run) can be reconciled on the next start: the
# orphaned tun2socks is terminated and its leftover routes deleted, the same way
# dns_control recovers a leftover DNS backup. Without this, a SIGKILLed run
# leaves a utun + default-override routes blackholing all traffic with no record
# to clean them up.
STATE_FILE = Path("/Library/Application Support/FreeGSM/tunnel_state.json")


def _run(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=check)


def default_route() -> tuple[str | None, str | None]:
    """(gateway, interface) of the real default route, or (None, None)."""
    try:
        out = _run(["route", "-n", "get", "default"]).stdout
    except subprocess.CalledProcessError:
        return None, None
    gw = iface = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("gateway:"):
            gw = line.split()[1]
        elif line.startswith("interface:"):
            iface = line.split()[1]
    return gw, iface


def resolve_tun2socks() -> str | None:
    """Locate the tun2socks binary: configured path, PATH, or ./bin."""
    cand = config.TUN2SOCKS_PATH
    if cand and (Path(cand).is_file() or shutil.which(cand)):
        return shutil.which(cand) or cand
    for p in (Path.cwd() / "bin" / "tun2socks",
              Path(__file__).resolve().parent.parent.parent / "bin" / "tun2socks"):
        if p.is_file():
            return str(p)
    return None


def default_route6() -> tuple[str | None, str | None]:
    """(gateway, interface) of the real IPv6 default route, or (None, None).

    The gateway is often a link-local address with a zone id (fe80::1%en0);
    ``route`` accepts it verbatim, so it is used as-is."""
    out = _run(["route", "-n", "get", "-inet6", "default"], check=False)
    if out.returncode != 0:
        return None, None
    gw = iface = None
    for line in out.stdout.splitlines():
        line = line.strip()
        if line.startswith("gateway:"):
            gw = line.split()[1]
        elif line.startswith("interface:"):
            iface = line.split()[1]
    return gw, iface


def _iface_exists(dev: str) -> bool:
    return _run(["ifconfig", dev], check=False).returncode == 0


# --------------------------------------------------------------------------- #
# Crash-recovery state (pid + routes), persisted across runs
# --------------------------------------------------------------------------- #
def _save_state(pid: int, routes: list[list[str]]) -> None:
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps({"pid": pid, "routes": routes}), encoding="utf-8")
    except OSError as exc:
        log.warning("could not persist tunnel state: %s", exc)


def _clear_state() -> None:
    try:
        STATE_FILE.unlink(missing_ok=True)
    except OSError:
        pass


def _is_tun2socks(pid: int) -> bool:
    """True if pid is a live process whose command is tun2socks (guards against
    killing an unrelated process that reused the pid)."""
    out = _run(["ps", "-p", str(pid), "-o", "command="], check=False)
    return out.returncode == 0 and "tun2socks" in out.stdout


def _reconcile_leftover() -> bool:
    """Clean up after a crashed run: kill its orphaned tun2socks and delete the
    routes it left behind. Idempotent and best-effort.

    Returns True if it just SIGTERMed a live orphan (whose utun may not be
    reclaimed yet). If the orphan is still alive but can't be killed, the state
    file is kept so a later run can retry rather than abandoning a live tunnel
    with no recovery record."""
    try:
        state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False

    log.warning("Found leftover tunnel state from a previous run; cleaning up.")
    for dest_args in reversed(state.get("routes", [])):
        _run(["route", "-n", "delete", *dest_args], check=False)

    killed = False
    pid = state.get("pid")
    if isinstance(pid, int) and _is_tun2socks(pid):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as exc:
            # Orphan is alive but we couldn't signal it (e.g. EPERM). Keep the
            # state file so the next run can retry; clearing it now would strand
            # a live tun2socks holding the utun with no record to clean it up.
            log.error("could not terminate orphaned tun2socks pid %d (%s); "
                      "keeping state for retry.", pid, exc)
            return False
        log.info("terminated orphaned tun2socks pid %d", pid)
        killed = True
        # Escalate to SIGKILL if it ignores SIGTERM: this is the only reaper for
        # this orphan, and start() refuses to claim the fixed-name utun until the
        # device vanishes, so a SIGTERM-ignoring process would otherwise block the
        # tunnel until reboot.
        for _ in range(30):
            time.sleep(0.1)
            if not _is_tun2socks(pid):
                break
        else:
            try:
                os.kill(pid, signal.SIGKILL)
                log.warning("orphaned tun2socks pid %d ignored SIGTERM; sent SIGKILL", pid)
            except OSError:
                pass  # already gone (or unsignalable); _clear_state proceeds
    _clear_state()
    return killed


class Tunnel:
    def __init__(self, tun2socks_path: str) -> None:
        self._bin = tun2socks_path
        self._dev = config.TUN_DEVICE
        self._addr = config.TUN_ADDR
        self._proc: subprocess.Popen | None = None
        self._gw: str | None = None
        self._iface: str | None = None
        self._gw6: str | None = None
        self._iface6: str | None = None
        self._routes: list[list[str]] = []  # add-arg lists, deleted in reverse
        # Subset of self._routes that depend on the default gateway/interface
        # (ifscope defaults + DoH host-routes). These are torn down and rebuilt
        # by reapply_routes() when the network changes; the device routes
        # (0/1, 128/1, ::/1, 8000/1 -> utun) stay valid across such changes.
        self._scoped: list[list[str]] = []

    # -- routes -------------------------------------------------------------- #
    def _add_route(self, dest_args: list[str], required: bool = False,
                   scoped: bool = False) -> None:
        cp = _run(["route", "-n", "add", *dest_args], check=False)
        # Record the route BEFORE checking the result so stop()/reconcile always
        # deletes whatever the kernel may have created, even on a partial failure.
        self._routes.append(dest_args)
        if scoped:
            self._scoped.append(dest_args)
        if self._proc is not None:
            _save_state(self._proc.pid, self._routes)
        if required and cp.returncode != 0:
            raise RuntimeError(
                f"failed to add required route {dest_args}: {cp.stderr.strip()}"
            )

    def _add_scoped_routes(self, strict: bool) -> None:
        """Add the gateway/interface-dependent routes: an ifscope default per
        family (so IP_BOUND_IF upstream sockets have a route off the utun) and a
        host-route excluding the DoH upstream (so our own resolver channel is
        never tunnelled/fragmented). ``strict`` raises on a required IPv4 failure
        (startup); reapply passes False so a transient failure is just logged."""
        self._add_route(["-ifscope", self._iface, "default", self._gw],
                        required=strict, scoped=True)
        log.info("scoped default added: default via %s (ifscope %s)", self._gw, self._iface)
        if config.DOH_SERVER_IP:
            self._add_route(["-host", config.DOH_SERVER_IP, self._gw],
                            required=strict, scoped=True)
            log.info("DoH upstream %s excluded via %s", config.DOH_SERVER_IP, self._gw)
        # IPv6 is always best-effort: a failure here leaves IPv6 SNI exposed but
        # must never take down the working IPv4 tunnel.
        if self._gw6 and self._iface6:
            try:
                self._add_route(["-inet6", "-ifscope", self._iface6, "default", self._gw6],
                                scoped=True)
                if config.DOH_SERVER_IP6:
                    self._add_route(["-inet6", "-host", config.DOH_SERVER_IP6, self._gw6],
                                    scoped=True)
                log.info("scoped IPv6 default added: default via %s (ifscope %s)",
                         self._gw6, self._iface6)
            except Exception:  # noqa: BLE001
                log.exception("IPv6 scoped route setup failed; IPv6 upstream may break")

    # -- lifecycle ----------------------------------------------------------- #
    def start(self) -> None:
        # Recover from a crashed run before touching anything: kill any orphaned
        # tun2socks and delete its leftover routes, so we start from a clean slate
        # and never stack a second default-override on top of an old one.
        killed_orphan = _reconcile_leftover()

        self._gw, self._iface = default_route()
        if not self._gw or not self._iface:
            raise RuntimeError("no default route; refusing to set up tunnel")
        log.info("real default route: %s via %s", self._gw, self._iface)

        # The device name is fixed (config.TUN_DEVICE); if it still exists now
        # -- after reconciling our own leftovers -- something else owns it and our
        # ifconfig/route setup would target the wrong interface. Refuse rather
        # than blackhole traffic into a foreign device. But if we just killed an
        # orphan, its utun is torn down asynchronously, so give it a moment to
        # vanish before deciding the device is foreign.
        if _iface_exists(self._dev):
            if killed_orphan:
                for _ in range(30):
                    time.sleep(0.1)
                    if not _iface_exists(self._dev):
                        break
            if _iface_exists(self._dev):
                raise RuntimeError(
                    f"{self._dev} already exists and is not ours; refusing to set up tunnel"
                )

        # IPv6: redirect it too (so v6 HTTPS gets the same SNI fragmentation) when
        # enabled AND the host actually has a v6 default route. Best-effort -- a v6
        # failure later must never break the v4 tunnel, so we only note the gw/iface
        # here and let _add_scoped_routes / the device-route block degrade quietly.
        if config.TUNNEL_IPV6:
            self._gw6, self._iface6 = default_route6()
            if self._gw6 and self._iface6:
                log.info("real IPv6 default route: %s via %s", self._gw6, self._iface6)
        if config.TUNNEL_IPV6 and not (self._gw6 and self._iface6):
            log.info("no IPv6 default route; IPv6 not redirected (nothing to cover).")
        elif not config.TUNNEL_IPV6 and default_route6()[0]:
            log.warning("FREEGSM_TUNNEL_IPV6 is off but the host has an IPv6 default "
                        "route; IPv6 HTTPS bypasses the SNI splitter (SNI exposed).")

        self._proc = subprocess.Popen(
            [self._bin, "-device", self._dev,
             "-proxy", f"socks5://{config.SOCKS_PROXY_HOST}:{config.SOCKS_PROXY_PORT}",
             "-loglevel", "warn"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        # Persist the pid IMMEDIATELY (before route setup). If we are SIGKILLed in
        # the window before the routes go in, the next run's _reconcile_leftover()
        # can still find and reap this tun2socks instead of it being an orphan
        # holding the fixed-name utun forever. _add_route re-saves as routes land.
        _save_state(self._proc.pid, self._routes)

        # Wait for the device tun2socks creates.
        for _ in range(50):
            if self._proc.poll() is not None:
                raise RuntimeError("tun2socks exited during startup")
            if _iface_exists(self._dev):
                break
            time.sleep(0.1)
        else:
            raise RuntimeError(f"{self._dev} did not appear")

        _run(["ifconfig", self._dev, self._addr, self._addr, "up"])
        log.info("tunnel device %s up (%s) via tun2socks", self._dev, self._addr)

        # Give the utun an IPv6 address so tun2socks can carry v6 flows. If this
        # fails, drop v6 redirection entirely (keep v4 working) rather than adding
        # v6 routes that black-hole into an interface with no usable v6 address.
        if self._gw6 and self._iface6:
            cp = _run(["ifconfig", self._dev, "inet6", config.TUN_ADDR6,
                       "prefixlen", str(config.TUN_PREFIX6)], check=False)
            if cp.returncode != 0:
                log.warning("could not add IPv6 addr to %s (%s); IPv6 not redirected",
                            self._dev, cp.stderr.strip())
                self._gw6 = self._iface6 = None

        # Scoped defaults on the physical interface, so the SOCKS proxy's upstream
        # sockets (pinned with IP_BOUND_IF) have a route off the utun. Without
        # this, an ifscope lookup finds nothing and connects fail with
        # ENETUNREACH. App sockets (no IP_BOUND_IF) still use the global 0/1 (and
        # ::/1) route into the utun, so they remain fragmented. The IPv4 routes
        # here are required: any failure raises so main.py degrades cleanly to
        # DoH-only (calling stop(), which deletes the partial routes) rather than
        # running a half-built tunnel that bypasses the splitter or breaks DNS.
        self._add_scoped_routes(strict=True)

        # Override the default route with two /1 halves pointing at the utun.
        self._add_route(["-net", "0.0.0.0/1", "-interface", self._dev], required=True)
        self._add_route(["-net", "128.0.0.0/1", "-interface", self._dev], required=True)
        log.info("default route now via %s (0/1 + 128/1)", self._dev)

        # IPv6 default override (best-effort): a failure leaves v6 SNI exposed but
        # must not disturb the working v4 tunnel.
        if self._gw6 and self._iface6:
            cp1 = _run(["route", "-n", "add", "-inet6", "-net", "::/1",
                        "-interface", self._dev], check=False)
            self._routes.append(["-inet6", "-net", "::/1", "-interface", self._dev])
            cp2 = _run(["route", "-n", "add", "-inet6", "-net", "8000::/1",
                        "-interface", self._dev], check=False)
            self._routes.append(["-inet6", "-net", "8000::/1", "-interface", self._dev])
            if self._proc is not None:
                _save_state(self._proc.pid, self._routes)
            if cp1.returncode == 0 and cp2.returncode == 0:
                log.info("IPv6 default route now via %s (::/1 + 8000::/1)", self._dev)
            else:
                log.warning("IPv6 default override incomplete (%s / %s); v6 SNI may "
                            "stay exposed", cp1.stderr.strip(), cp2.stderr.strip())

    def reapply_routes(self, gw: str, iface: str,
                       gw6: str | None = None, iface6: str | None = None) -> None:
        """Re-point the gateway/interface-dependent routes after a network change.
        Deletes the old ifscope/DoH-exclude routes and rebuilds them for the new
        default route; the device routes (.../1 -> utun) are left untouched, so
        app traffic keeps flowing into the tunnel throughout. Best-effort: a
        failure is logged so the next poll can retry."""
        for dest_args in list(self._scoped):
            _run(["route", "-n", "delete", *dest_args], check=False)
            try:
                self._routes.remove(dest_args)
            except ValueError:
                pass
        self._scoped.clear()
        self._gw, self._iface = gw, iface
        self._gw6, self._iface6 = gw6, iface6
        try:
            self._add_scoped_routes(strict=False)
        finally:
            if self._proc is not None:
                _save_state(self._proc.pid, self._routes)
        log.info("tunnel scoped routes re-applied for %s via %s", gw, iface)

    def current(self) -> tuple[str | None, str | None, str | None, str | None]:
        """Last-applied (gw, iface, gw6, iface6); the monitor compares this to
        the live default route to decide whether to reapply."""
        return self._gw, self._iface, self._gw6, self._iface6

    def stop(self) -> None:
        # Delete routes first (reverse order), so traffic falls back to the real
        # default the moment tun2socks goes away.
        for dest_args in reversed(self._routes):
            _run(["route", "-n", "delete", *dest_args], check=False)
        if self._routes:
            log.info("tunnel routes removed")
        self._routes.clear()

        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None
            log.info("tun2socks stopped; %s gone", self._dev)

        # Clean teardown done -- drop the crash-recovery state.
        _clear_state()
