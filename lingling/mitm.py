"""Per-request MITM for opencode.ai: a local CA terminates TLS so each model call is visible, then ..."""

from __future__ import annotations

import datetime
import json
import os
import select
import socket
import ssl
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from . import netutil
from .lanes import Lane

#: unwrapped hosts
MITM_HOSTS = ("opencode.ai",)

#: the dial
_FIRST_BYTE_TIMEOUT = float(os.environ.get("LINGLING_FIRST_BYTE_S", "30"))
#: the send
_SEND_TIMEOUT = float(os.environ.get("LINGLING_SEND_S", "120"))
#: pre-commit idle
_READ_TIMEOUT = float(os.environ.get("LINGLING_STREAM_TIMEOUT", "1800"))
#: post-commit idle
_STREAM_IDLE_TIMEOUT = float(os.environ.get("LINGLING_STREAM_IDLE_S", "1800"))
#: slow exit
_SLOW_EXIT_S = float(os.environ.get("LINGLING_SLOW_EXIT_S", "20"))
#: first event
_FIRST_EVENT = b"data:"
#: idle tunnel
_KEEPALIVE_S = float(os.environ.get("LINGLING_KEEPALIVE_S", "600"))

#: retryable
_RETRYABLE = frozenset({429, 502, 503, 504})
#: 5xx attempts
_5XX_ATTEMPTS = 2
#: note bytes
_NOTE_BYTES = 512

#: cut capture
_CAPTURE = os.environ.get("LINGLING_CAPTURE", "")
#: capture bytes
_CAPTURE_MAX = int(os.environ.get("LINGLING_CAPTURE_BYTES", "8192"))

#: pre-commit cap
_PRE_COMMIT_MAX = 65536

_ca_lock = threading.Lock()
_ca_ctx: Dict[Path, "tuple"] = {}  #: ca cache


def crypto_available() -> bool:
    """True when the crypto stack the MITM needs actually imports."""
    try:
        from cryptography import x509  # noqa: F401
        from cryptography.hazmat.primitives import hashes  # noqa: F401
        from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: F401
        return True
    except ImportError:
        return False


def _ensure_ca(mitm_dir: Path):
    """Create (or load) the local root CA."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    mitm_dir.mkdir(parents=True, exist_ok=True)
    cert_path = mitm_dir / "ca.pem"
    key_path = mitm_dir / "ca-key.pem"
    if cert_path.exists() and key_path.exists():
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(
            key_path.read_bytes(), password=None)
        return cert, key, cert_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                         "lingling local proof CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    return cert, key, cert_path


class CertShop:
    """Mints per-host certs signed by the local CA, cached on disk."""

    def __init__(self, mitm_dir: Path) -> None:
        with _ca_lock:
            self._ca_cert, self._ca_key, self.ca_pem_path = _ensure_ca(mitm_dir)
        self._dir = mitm_dir / "certs"
        self._dir.mkdir(parents=True, exist_ok=True)

    def context_for(self, host: str) -> ssl.SSLContext:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        safe = host.replace("*", "wildcard")
        cert_path = self._dir / f"{safe}.pem"
        key_path = self._dir / f"{safe}-key.pem"
        if not cert_path.exists():
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            now = datetime.datetime.now(datetime.timezone.utc)
            san = x509.SubjectAlternativeName([x509.DNSName(host)])
            cert = (x509.CertificateBuilder()
                    .subject_name(x509.Name([x509.NameAttribute(
                        NameOID.COMMON_NAME, host)]))
                    .issuer_name(self._ca_cert.subject)
                    .public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - datetime.timedelta(days=1))
                    .not_valid_after(now + datetime.timedelta(days=825))
                    .add_extension(san, critical=False)
                    .add_extension(x509.BasicConstraints(ca=False,
                                                         path_length=None),
                                   critical=True)
                    .sign(self._ca_key, hashes.SHA256()))
            cert_path.write_bytes(cert.public_bytes(
                serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert_path), str(key_path))
        return ctx


def _read_head(f, on_first=None, sock=None, ceiling=None) -> Optional[bytes]:
    """Read one HTTP head (request or status line + headers) through CRLFCRLF."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = f.read(1)
        if not chunk:
            return None
        if on_first is not None:
            # first arrival
            on_first()
            on_first = None
        if sock is not None and ceiling is not None:
            # arm again
            sock.settimeout(ceiling)
        buf += chunk
        if len(buf) > 65536:
            return None
    return buf


def _read_exact(f, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = f.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _read_body(cf, headers) -> Optional[bytes]:
    """The client's request body, or None if it did not arrive whole."""
    cl = headers.get("content-length")
    if not cl:
        return b""
    try:
        want = int(cl)
        body = _read_exact(cf, want)
    except (ValueError, OSError):
        return None
    if len(body) != want:
        return None
    return body


def _model_of(body: bytes) -> str:
    """The model, reasoning effort, and output cap of one request body."""
    try:
        head = json.loads(body.decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001
        return ""
    model = str(head.get("model", ""))
    reasoning = head.get("reasoning") or {}
    effort = reasoning.get("effort", "") if isinstance(reasoning, dict) else ""
    effort = effort or head.get("reasoning_effort", "")
    cap = head.get("max_output_tokens", "")
    if effort or cap:
        return f"{model} effort={effort or '-'} cap={cap or '-'}"
    return model


def _force_connection_close(head: bytes) -> bytes:
    """Always advertise ``Connection: close``: safest contract for a proxy that may drop the tunnel ..."""
    lines = head.split(b"\r\n")
    out = [lines[0]]
    replaced = False
    i = 1
    while i < len(lines) and lines[i]:
        ln = lines[i]
        if ln[:10].lower() == b"connection" and b":" in ln:
            out.append(b"Connection: close")
            replaced = True
        else:
            out.append(ln)
        i += 1
    if not replaced:
        out.append(b"Connection: close")
    out.extend(lines[i:])  # terminator verbatim
    return b"\r\n".join(out)


def _dump_cut(seq: int, call_n: int, lane, err: str, cap: bytes,
              total: int) -> None:
    """Write a cut stream's bytes, so the dying point can be read."""
    if not _CAPTURE:
        return
    try:
        out = Path(_CAPTURE)
        out.mkdir(parents=True, exist_ok=True)
        stem = f"n{seq}-c{call_n}-lane{lane.index}-{int(time.time())}"
        (out / f"{stem}.bin").write_bytes(cap)
        (out / f"{stem}.txt").write_text(
            f"err={err}\nlane={lane.index} cc={lane.exit_country} "
            f"ip={lane.exit_ip}\nkb={total / 1024:.1f}\n"
            f"captured={len(cap)}\n", encoding="utf-8")
    except OSError:
        pass


def _grab_lane(relay, tried: set):
    """The sticky favorite, else the least-loaded lane we have not tried."""
    sticky = getattr(relay.tor, "sticky", None)
    if sticky is not None:
        lane = sticky.next_lane(tried)
        if lane is not None:
            return lane
    return relay.pick_lane(exclude=tried)


def _race_lanes(relay, tried: set) -> List[Lane]:
    """Every lane that can still serve this call, the favorite first.

    Racing all of them is the point: a request used to ride one lane and
    wait behind that lane's queue while the other four sat idle.
    """
    lanes: List[Lane] = []
    taken = set(tried)
    first = _grab_lane(relay, taken)
    if first is not None:
        lanes.append(first)
        taken.add(first.index)
    while True:
        lane = relay.pick_lane(exclude=taken)
        if lane is None or lane.index in taken:
            break
        taken.add(lane.index)
        if lane.limited_until > time.time():
            """Burnt: leave it out, and keep looking for a live lane."""
            continue
        lanes.append(lane)
    return lanes


class _Copy:
    """One lane's go at one call: cuttable from the thread that won."""

    def __init__(self, lane: Lane) -> None:
        self.lane = lane
        self.race: Optional[_Race] = None
        self.thread: Optional[threading.Thread] = None
        self.sock = None
        self.beaten = False
        self._lock = threading.Lock()

    def arm(self, sock) -> bool:
        """Hand over the socket to cut on a loss; False once beaten."""
        with self._lock:
            if self.beaten:
                return False
            self.sock = sock
            return True

    def beat(self) -> None:
        """Another copy has the client: cut this upstream, and stop it."""
        with self._lock:
            self.beaten = True
            sock, self.sock = self.sock, None
        if sock is not None:
            _abort_quiet(sock)

    def stands(self) -> bool:
        """True while this copy may still speak for itself, or charge."""
        return self.race is not None and self.race.speak(self)

    def owns(self) -> bool:
        """True once this copy is the one that took the client."""
        return self.race is not None and self.race.winner is self

    def claim(self) -> bool:
        """Take the client for this copy, or lose to one already there."""
        return self.race is None or self.race.claim(self)


class _Beaten(Exception):
    """A copy that lost, raised where it would have written to the client."""


class _Race:
    """One call over every lane: the first answer to commit takes the client.

    Nothing reaches the client until a copy commits, so a loser is cut
    before it says a word -- and a loser is never a verdict about its lane,
    because a hand of ours closed it.
    """

    def __init__(self, copies: List[_Copy]) -> None:
        self.copies = copies
        self.winner: Optional[_Copy] = None
        self._lock = threading.Lock()
        for copy in copies:
            copy.race = self

    def speak(self, copy: _Copy) -> bool:
        """A copy may speak until one wins, and after that only the winner."""
        with self._lock:
            return self.winner is None or self.winner is copy

    def claim(self, copy: _Copy) -> bool:
        """Take the client for this copy, or lose to one already there."""
        with self._lock:
            if self.winner is None:
                self.winner = copy
                others = [c for c in self.copies if c is not copy]
            elif self.winner is copy:
                return True
            else:
                return False
        for other in others:
            try:
                other.beat()
            except Exception:  # noqa: BLE001
                """Cutting a loser is housekeeping: a loser that cannot be
                cut must never cost the winner the client."""
        return True

    def raced(self) -> int:
        """How many lanes this call went out on."""
        return len(self.copies)


class _Round:
    """What one race came back with: the client's answer, or the reason."""

    def __init__(self) -> None:
        self.committed = False
        self.held = b""
        self.retryable = False
        self.limits: List[tuple] = []
        self.refused = False
        self.fivexx = False


def _race_call(client, lanes: List[Lane], host: str, port: int, method: str,
               path: str, headers: dict, body: bytes, emit, seq: int,
               call_n: int, t0: float, relay, model: str = "") -> _Round:
    """Fire one call at every lane at once; the first answer takes the client.

    The copies only talk to the pane through the race, so a loser is
    silent. A dead exit is charged once per call -- by the first copy, or
    by the copy that won and then had its own stream cut.
    """
    copies = [_Copy(lane) for lane in lanes]
    race = _Race(copies)
    plain = len(lanes) == 1
    emit({
        "type": "call", "t": t0, "n": seq, "c": call_n,
        "lane": lanes[0].index if plain else 0,
        "cc": lanes[0].exit_country if plain else "",
        "ip": lanes[0].exit_ip if plain else "",
        "lanes": [l.index for l in lanes],
        "ccs": [l.exit_country for l in lanes],
        "method": method, "path": path, "model": model, "host": host,
        # request size
        "bytes": len(body),
    })
    out: List[tuple] = []
    lock = threading.Lock()

    def run(copy: _Copy) -> None:
        def say(ev: Dict) -> None:
            """A copy that lost has nothing to say in the pane."""
            if race.speak(copy):
                emit(ev)
        got = _roundtrip(client, copy.lane, host, port, method, path,
                         headers, body, say, seq, call_n, t0, relay,
                         charge_timeout=copy is copies[0], model=model,
                         copy=copy)
        with lock:
            out.append((copy, got))

    for copy in copies:
        with copy.lane.lock:
            copy.lane.active += 1
    threads = [threading.Thread(target=run, args=(c,), daemon=True,
                                name=f"race-{seq}-{c.lane.index}")
               for c in copies]
    for copy, thread in zip(copies, threads):
        copy.thread = thread
        thread.start()
    try:
        """A round ends when a copy wins, or when every copy has given up.
        Only the winner is waited on to the end; a loser is cut loose, and
        a copy still dialling is left to notice on its own."""
        while race.winner is None and any(t.is_alive() for t in threads):
            time.sleep(0.05)
        winner = race.winner
        if winner is None:
            for thread in threads:
                thread.join()
        else:
            winner.thread.join()
            for thread in threads:
                if thread is not winner.thread:
                    thread.join(timeout=1.0)
    finally:
        for copy in copies:
            with copy.lane.lock:
                copy.lane.active -= 1
    return _tally(race, out, relay)


def _tally(race: _Race, out: List[tuple], relay) -> _Round:
    """Judge a race: the client's answer, or what the copies earned."""
    got = _Round()
    for copy, (err, status, body, retryable) in out:
        if race.winner is copy:
            """The copy that reached the client: score the exit it rode."""
            relay.tor.note_result(copy.lane.exit_country, status)
            continue
        if err:
            if copy.beaten:
                """A hand of ours cut it: never a verdict, never a retry."""
                continue
            got.retryable = got.retryable or retryable
            continue
        if status == 429:
            limit, wait = _limit_of(body)
            if limit:
                got.limits.append((copy.lane, wait))
                got.retryable = True
                if not got.held:
                    got.held = body
                continue
            """The far end's own 429: no lane will do better at all."""
            got.refused = True
            got.held = body
            continue
        if status in _RETRYABLE:
            got.fivexx = True
            got.retryable = True
            if not got.held:
                got.held = body
    """The copy that claimed owns the client, even when its own outcome
    never came back: a second round would answer one request twice."""
    got.committed = race.winner is not None
    return got


def _sticky_ceiling(relay, lane) -> float:
    """While stuck on a lane, its release ceiling replaces the slow one."""
    sticky = getattr(relay.tor, "sticky", None)
    if sticky is not None and sticky.stuck_on(lane.index):
        return sticky.release_s
    return _SLOW_EXIT_S


def _sticky_verdict(relay, lane) -> None:
    """A verdict on the stuck lane wakes the others."""
    sticky = getattr(relay.tor, "sticky", None)
    if sticky is not None:
        sticky.on_verdict(lane.index)


def _sticky_sample(relay, lane, t0: float, first_byte_at, first_event_at,
                   model: str = "") -> None:
    """Donate this attempt's latency to the round -- model calls only.

    Only an answer to a real model call may elect a lane. opencode fetches
    its models registry (``GET /api.json`` on models.opencode.ai) the moment
    it starts, and that fast metadata fetch used to win the round before the
    user typed anything -- so the proof pane announced a lane had "answered"
    a request nobody made.
    """
    sticky = getattr(relay.tor, "sticky", None)
    if sticky is None or not model:
        return
    stamp = first_event_at or first_byte_at
    if stamp is not None:
        sticky.record(lane.index, round(stamp - t0, 2))


def _note_timeout(relay, lane, emit, seq: int, call_n: int) -> None:
    """A timeout means a dead exit: move the lane at once, as a 429 does."""
    moved = relay.tor.note_timeout(lane)
    _sticky_verdict(relay, lane)
    if not moved:
        return
    emit({"type": "lane", "kind": "timeout", "t": time.time(),
          "lane": lane.index, "cc": lane.exit_country, "ip": lane.exit_ip,
          "msg": moved})


def _note_ssl(relay, lane, emit, seq: int, call_n: int) -> None:
    """An SSL cut means a dead exit: the timeout verdict, at once."""
    moved = relay.tor.note_ssl_error(lane)
    _sticky_verdict(relay, lane)
    if not moved:
        return
    emit({"type": "lane", "kind": "ssl", "t": time.time(),
          "lane": lane.index, "cc": lane.exit_country, "ip": lane.exit_ip,
          "msg": moved})


def _note_slow(relay, lane, emit, seq: int, call_n: int,
               elapsed: float) -> None:
    """A slow first event is a bad exit: the timeout verdict, at once."""
    moved = relay.tor.note_slow_exit(lane, elapsed)
    _sticky_verdict(relay, lane)
    if not moved:
        return
    emit({"type": "lane", "kind": "slow", "t": time.time(),
          "lane": lane.index, "cc": lane.exit_country, "ip": lane.exit_ip,
          "msg": moved})


def handle_conn(raw: socket.socket, host: str, port: int, seq: int,
                shop: CertShop, emit: Callable[[Dict], None],
                relay) -> None:
    """Own one intercepted TLS connection end to end (blocking thread)."""
    try:
        # non-blocking
        raw.setblocking(True)
        raw.settimeout(300)  # idle ceiling
        ctx = shop.context_for(host)
        client = ctx.wrap_socket(raw, server_side=True)
    except (ssl.SSLError, OSError):
        try:
            raw.close()
        except OSError:
            pass
        return
    try:
        _serve(client, host, port, seq, emit, relay)
    except (OSError, ssl.SSLError, TimeoutError):
        # idle ceiling
        pass
    finally:
        try:
            client.close()
        except OSError:
            pass


def _serve(client: ssl.SSLSocket, host: str, port: int, seq: int,
           emit: Callable[[Dict], None], relay) -> None:
    """Serve model calls on one client TLS connection; a lane per call."""
    cf = client.makefile("rb")
    call_n = 0
    while True:
        head = _read_head(cf)
        if head is None:
            return
        try:
            line = head.split(b"\r\n", 1)[0].decode("latin1")
            method, path, _ = line.split(" ", 2)
        except ValueError:
            return
        headers = {}
        for raw in head.split(b"\r\n")[1:]:
            if not raw or b":" not in raw:
                continue
            k, v = raw.split(b":", 1)
            headers[k.strip().lower().decode("latin1")] = v.strip()

        expect = headers.get("expect", b"")
        if isinstance(expect, str):
            expect = expect.encode("latin1")
        if b"100-continue" in expect.lower():
            client.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")

        body = _read_body(cf, headers)
        if body is None:
            return
        model = _model_of(body) if body and method == "POST" else ""
        call_n += 1

        held = b""
        tried = set()
        bad5xx = 0
        while True:
            """Every lane at once: the first answer takes the client."""
            lanes = _race_lanes(relay, tried)
            if not lanes:
                # last body
                if held:
                    client.sendall(held)
                else:
                    client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n"
                                   b"Content-Length: 0\r\n\r\n")
                return
            tried.update(l.index for l in lanes)
            got = _race_call(client, lanes, host, port, method, path, headers,
                             body, emit, seq, call_n, time.time(), relay,
                             model)
            for lane, wait in got.limits:
                # burnt here
                relay.tor.note_limited(lane, wait)
                relay.report_refused(lane, 429)
                _sticky_verdict(relay, lane)
            if got.held:
                # freshest verdict
                held = got.held
            if got.committed:
                """The client has its answer; the winner is streaming it."""
                return
            if got.refused:
                """opencode is down, not the exit: moving cannot help"""
                client.sendall(held)
                return
            if got.limits and not relay.any_unlimited(tried):
                # none left
                if held:
                    client.sendall(held)
                return
            if got.fivexx:
                # far edge
                bad5xx += 1
                if bad5xx >= _5XX_ATTEMPTS:
                    # last verdict
                    if held:
                        client.sendall(held)
                    return
            if not got.retryable:
                """Nothing left to say: the connection is the failure."""
                return
            # free retry
            continue


def _close_quiet(sock) -> None:
    """Close without caring whether it was already gone."""
    try:
        sock.close()
    except OSError:
        pass


def _abort_quiet(sock) -> None:
    """Cut a connection loose, so a read blocked on it lets go at once."""
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except (OSError, AttributeError):
        pass
    _close_quiet(sock)


def _peer_closed(sock) -> bool:
    """True when the far end has hung up on a socket we left idle."""
    try:
        return bool(select.select([sock], [], [], 0)[0])
    except (OSError, ValueError):
        return True


class TunnelPool:
    """Idle upstream connections, kept per lane."""

    def __init__(self, ttl: float = _KEEPALIVE_S) -> None:
        self.ttl = ttl
        self._idle: Dict[int, List[Tuple[float, str, object, object]]] = {}
        self._lock = threading.Lock()

    def take(self, lane: Lane) -> Optional[Tuple[object, object]]:
        """Newest usable idle tunnel for a lane, or None."""
        with self._lock:
            slots = self._idle.get(lane.index)
            if not slots:
                return None
            when, ip, up, fil = slots.pop()
        if time.monotonic() - when > self.ttl:
            _close_quiet(up)  # too old
            return None
        if ip != lane.exit_ip:
            _close_quiet(up)  # wrong country
            return None
        if _peer_closed(up):
            _close_quiet(up)  # hung up
            return None
        return up, fil

    def give(self, lane: Lane, up, fil) -> None:
        """Hand a tunnel back after a response that ended cleanly."""
        now = time.monotonic()
        with self._lock:
            slots = self._idle.setdefault(lane.index, [])
            keep = []
            for when, ip, old_up, _old_fil in slots:
                if (now - when) > self.ttl or ip != lane.exit_ip:
                    _close_quiet(old_up)  # prune
                    continue
                keep.append((when, ip, old_up, _old_fil))
            keep.append((now, lane.exit_ip, up, fil))
            self._idle[lane.index] = keep


def _note_of(raw: bytes) -> str:
    """The error body as one readable line, for the pane."""
    text = " ".join(raw.decode("utf-8", "replace").split())
    return text[:200]


def _retry_after(rheaders: dict) -> float:
    """Seconds the far end says to wait, or 0 when it did not say."""
    try:
        return max(0.0, float(rheaders.get(b"retry-after", b"0")))
    except (TypeError, ValueError):
        return 0.0


def _limit_of(held: bytes) -> "tuple[bool, float]":
    """Whether a held 429 is the exit's own limit, and the wait it asks for.

    opencode also answers "Endpoint is unavailable" as a 429. That one is not
    the exit, so rotating lanes cannot fix it and it is not benched.
    """
    if netutil.UPSTREAM_DOWN in held:
        return False, 0.0
    rheaders = {}
    for raw in held.split(b"\r\n\r\n", 1)[0].split(b"\r\n")[1:]:
        if b":" in raw:
            k, v = raw.split(b":", 1)
            rheaders[k.strip().lower()] = v.strip()
    return True, _retry_after(rheaders)


def _lat(t0: float, first_byte: Optional[float],
         first_event: Optional[float]) -> Dict:
    """Offset from request start to first upstream byte / first SSE event."""
    return {
        "first_byte_s": round(first_byte - t0, 2) if first_byte else 0,
        "first_event_s": round(first_event - t0, 2) if first_event else 0,
    }


def _roundtrip(client: ssl.SSLSocket, lane: Lane, host: str, port: int,
               method: str, path: str, headers: dict, body: bytes,
               emit, seq: int, call_n: int, t0: float, relay: "object",
               charge_timeout: bool = False,
               model: Optional[str] = None, copy: Optional[_Copy] = None
               ) -> "tuple[str, int, bytes, bool]":
    """One upstream attempt; 429s buffer into ``held`` for a lane retry.

    With a ``copy``, this is one lane's go in a race: it claims the client
    at its first content byte, and loses silently to a faster lane.
    """
    if copy is not None and copy.beaten:
        """A lane that answered first has the client: nothing to dial for."""
        return "", 0, b"", False
    if model is None:
        # model calls
        model = _model_of(body) if body else ""
    first_byte_at = None   # byte one
    first_event_at = None  # event one
    # above dial
    max_wait = 0.0         # longest wait
    client_wait = 0.0      # longest client
    send_wait = 0.0        # longest push
    sent = 0               # client bytes
    peer_close = False     # far end
    last_op = "upstream"   # which side
    status = 0             # upstream status
    pool = getattr(relay, "tunnels", None)

    def _may() -> bool:
        """True while this copy may still charge its lane: unbeaten, or won."""
        return copy is None or copy.stands()

    def _witness() -> bool:
        """True when this copy's lane carries this call's dead-exit verdict.

        The first copy speaks for a pool-wide failure, so one dead pool
        cannot retire six exits; the copy that won and then lost its own
        stream is the only voice left for that exit.
        """
        return charge_timeout or (copy is not None and copy.owns())

    def _keys() -> Dict:
        """The keys every callend carries, in one place."""
        return {**_lat(t0, first_byte_at, first_event_at),
                "send_s": round(send_wait, 1),
                "peer_close": peer_close,
                "client_kb": round(sent / 1024, 1),
                "raced": copy.race.raced() if copy is not None
                and copy.race is not None else 0}

    kept = pool.take(lane) if pool is not None else None
    uf = None
    if kept is not None:
        up, uf = kept
        if copy is not None and not copy.arm(up):
            """Beaten before the first byte, so the tunnel is still clean."""
            pool.give(lane, up, uf)
            return "", 0, b"", False
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # cold lane
        sock.settimeout(_FIRST_BYTE_TIMEOUT)
        try:
            sock.connect(("127.0.0.1", lane.socks_port))
            err = netutil.socks5_open(
                sock, host, port,
                cred=netutil.lane_cred(lane.index))
            if err:
                # lane dead
                _close_quiet(sock)
                if copy is not None and copy.beaten:
                    """Our own cut: not a failure, and not this lane's."""
                    return "", 0, b"", False
                if err == "timed out" and charge_timeout and _may():
                    # dead exit
                    _note_timeout(relay, lane, emit, seq, call_n)
                emit({"type": "callend", "t": time.time(), "n": seq,
                      "c": call_n, "lane": lane.index,
                      "cc": lane.exit_country, "status": 0, "kb": 0,
                      "secs": round(time.time() - t0, 1), "err": err,
                      "cut": True,
                      "note": "",
                      "max_wait_s": round(max_wait, 1),
                      "client_wait_s": round(client_wait, 1),
                      "reused": kept is not None,
                      **_keys()})
                return err, 0, b"", True
            up = ssl.create_default_context().wrap_socket(
                sock, server_hostname=host)
            if copy is not None and not copy.arm(up):
                """Beaten while dialling: this copy never says a word."""
                _close_quiet(up)
                return "", 0, b"", False
        except (ssl.SSLError, OSError) as exc:
            sock.close()
            if copy is not None and copy.beaten:
                """Our own cut: not a failure, and not this lane's."""
                return "", 0, b"", False
            err = f"{type(exc).__name__}"
            if err == "ConnectionRefusedError":
                # lane down
                lane.healthy = False
            if charge_timeout and isinstance(exc, ssl.SSLError) and _may():
                # dead exit
                _note_ssl(relay, lane, emit, seq, call_n)
            emit({"type": "callend", "t": time.time(), "n": seq, "c": call_n,
                  "lane": lane.index, "cc": lane.exit_country, "status": 0,
                  "kb": 0, "secs": round(time.time() - t0, 1), "err": err,
                  "cut": True,
                  "note": "",
                  "max_wait_s": round(max_wait, 1),
                  "client_wait_s": round(client_wait, 1),
                  "reused": kept is not None,
                  **_keys()})
            return err, 0, b"", True

    total = 0
    held = bytearray()
    note_buf = bytearray()  # error body
    want_note = False       # error capture
    clean_end = False       # terminator seen
    keep = False            # tunnel reusable
    retry_after = 0.0       # server reset
    is_sse = False          # event stream
    _tail = b""             # split-read guard
    _open = bytearray()     # pre-commit bytes
    _cap = bytearray()      # cut capture
    _committed = False      # client content

    def _stamp_byte() -> None:
        nonlocal first_byte_at
        first_byte_at = time.time()

    def _timed(fn, *args, **kwargs):
        """One blocking upstream read, timed."""
        nonlocal max_wait, last_op
        last_op = "upstream"
        t = time.monotonic()
        try:
            return fn(*args, **kwargs)
        finally:
            # even raising
            waited = time.monotonic() - t
            if waited > max_wait:
                max_wait = waited

    def _to_client(data: bytes) -> None:
        """One send to the client, timed apart from the upstream reads."""
        nonlocal client_wait, last_op, sent
        last_op = "client"
        t = time.monotonic()
        try:
            client.sendall(data)
            # after success
            sent += len(data)
        finally:
            # even raising
            waited = time.monotonic() - t
            if waited > client_wait:
                client_wait = waited

    def _flush() -> None:
        # commit both
        nonlocal _committed
        if not _committed:
            if copy is not None and not copy.claim():
                """A lane that answered first already has the client."""
                raise _Beaten
            _committed = True
            _to_client(bytes(_open))
            _open.clear()
            # widen ceiling
            up.settimeout(_STREAM_IDLE_TIMEOUT)

    def _send(data: bytes, body: bool = True) -> None:
        nonlocal total, _tail, first_event_at
        total += len(data)
        if _CAPTURE and len(_cap) < _CAPTURE_MAX:
            _cap.extend(data)
        if held is not None:
            held.extend(data)
            if want_note and body:
                # first bytes
                room = _NOTE_BYTES - len(note_buf)
                if room > 0:
                    note_buf.extend(data[:room])
            return
        # first event
        if body and first_event_at is None and is_sse:
            window = _tail + data
            if _FIRST_EVENT in window:
                first_event_at = time.time()
            _tail = window[-64:]
        if _committed:
            _to_client(data)
            return
        # pre-content hold
        _open.extend(data)
        # unbounded framing
        if first_event_at is not None or len(_open) > _PRE_COMMIT_MAX:
            _flush()

    try:
        # rebuild head
        out_head = f"{method} {path} HTTP/1.1\r\n".encode("latin1")
        # we answer
        skip = {"connection", "keep-alive", "proxy-authenticate",
                "proxy-authorization", "te", "trailer", "transfer-encoding",
                "upgrade", "content-length", "expect"}
        for k, v in headers.items():
            if k in skip:
                continue
            vv = v.decode("latin1") if isinstance(v, bytes) else v
            out_head += f"{k}: {vv}\r\n".encode("latin1")
        out_head += f"content-length: {len(body)}\r\n".encode()
        out_head += (b"connection: keep-alive\r\n\r\n" if pool is not None
                     else b"connection: close\r\n\r\n")
        # send window
        up.settimeout(_SEND_TIMEOUT)
        _push = time.monotonic()
        try:
            _timed(up.sendall, out_head + body)
        finally:
            # even raising
            send_wait = time.monotonic() - _push

        if uf is None:
            uf = up.makefile("rb")
        # head window
        up.settimeout(_READ_TIMEOUT)
        # head counts
        rhead = _timed(_read_head, uf, _stamp_byte, sock=up,
                       ceiling=_READ_TIMEOUT)
        if rhead is None:
            err = "upstream closed"
            emit({"type": "callend", "t": time.time(), "n": seq, "c": call_n,
                  "lane": lane.index, "cc": lane.exit_country, "status": 0,
                  "kb": 0, "secs": round(time.time() - t0, 1), "err": err,
                  "cut": True,
                  "note": "",
                  "max_wait_s": round(max_wait, 1),
                  "client_wait_s": round(client_wait, 1),
                  "reused": kept is not None,
                  **_keys()})
            return err, 0, b"", True
        try:
            status = int(rhead.split(b" ", 2)[1])
        except (IndexError, ValueError):
            pass
        rheaders = {}
        for raw in rhead.split(b"\r\n")[1:]:
            if raw and b":" in raw:
                k, v = raw.split(b":", 1)
                rheaders[k.strip().lower()] = v.strip()

        if status == 429:
            retry_after = _retry_after(rheaders)

        if status not in _RETRYABLE:
            held = None  # stream out
        is_sse = b"text/event-stream" in rheaders.get(b"content-type", b"")
        # error body
        want_note = status >= 400
        # head joins
        head_out = _force_connection_close(rhead)
        _open.extend(head_out)
        if held is not None:
            # keep head
            held.extend(head_out)
        if not is_sse and held is None:
            # plain body
            _flush()

        # honour close
        upstream_close = b"close" in rheaders.get(b"connection", b"").lower()
        peer_close = upstream_close

        if b"chunked" in rheaders.get(b"transfer-encoding", b""):
            # verbatim
            while True:
                size_line = _timed(uf.readline)
                if not size_line:
                    break
                try:
                    size = int(size_line.strip().split(b";")[0], 16)
                except ValueError:
                    _send(size_line, body=False)
                    break
                _send(size_line, body=False)
                if size == 0:
                    # trailer
                    while True:
                        tl = _timed(uf.readline)
                        if not tl:
                            break
                        _send(tl, body=False)
                        if tl in (b"\r\n", b"\n"):
                            break
                    clean_end = True
                    keep = not upstream_close
                    break
                chunk = _timed(_read_exact, uf, size + 2)
                _send(chunk)
                if len(chunk) < size + 2:
                    break  # died mid-chunk
        elif b"content-length" in rheaders:
            remaining = int(rheaders[b"content-length"])
            while remaining > 0:
                chunk = _timed(uf.read, min(65536, remaining))
                if not chunk:
                    break
                _send(chunk)
                remaining -= len(chunk)
            clean_end = remaining <= 0
            keep = clean_end and not upstream_close
        else:
            while True:
                chunk = _timed(uf.read, 65536)
                if not chunk:
                    break
                _send(chunk)
            clean_end = True  # eof ends

        # empty body
        if not _committed and held is None:
            emit({"type": "callend", "t": time.time(), "n": seq, "c": call_n,
                  "lane": lane.index, "cc": lane.exit_country, "status": 0,
                  "kb": 0, "secs": round(time.time() - t0, 1),
                  "err": "no body", "cut": True,
                  "note": "",
                  "max_wait_s": round(max_wait, 1),
                  "client_wait_s": round(client_wait, 1),
                  "reused": kept is not None,
                  **_keys()})
            return "no body", 0, b"", True

        if keep and held is None and pool is not None:
            # reuse tunnel
            pool.give(lane, up, uf)
            up = None

        if not clean_end:
            # dump capture
            _dump_cut(seq, call_n, lane, "eof-mid-body", bytes(_cap), total)

        # sample first
        _sticky_sample(relay, lane, t0, first_byte_at, first_event_at, model)

        # then judge
        if (first_event_at is not None
                and first_event_at - t0 >= min(_sticky_ceiling(relay, lane),
                                               _SLOW_EXIT_S)):
            _note_slow(relay, lane, emit, seq, call_n,
                       round(first_event_at - t0, 1))

        emit({"type": "callend", "t": time.time(), "n": seq, "c": call_n,
              "lane": lane.index, "cc": lane.exit_country, "status": status,
              "kb": round(total / 1024, 1),
              "secs": round(time.time() - t0, 1), "err": "",
              "cut": not clean_end,
              "reused": kept is not None,
              "retry_after": round(retry_after),
              "note": _note_of(bytes(note_buf)),
              "max_wait_s": round(max_wait, 1),
              "client_wait_s": round(client_wait, 1),
              **_keys()})
        return "", status, bytes(held or b""), False
    except _Beaten:
        """A copy that lost: the winner has the client, so say nothing."""
        return "", 0, b"", False
    # bad length
    except (ssl.SSLError, OSError, ValueError) as exc:
        err = f"{type(exc).__name__}"
        # unseen retries
        retryable = held is not None or not _committed
        # held only
        seen = total if _committed else len(_open)
        # upstream only
        if (_witness() and err.endswith("TimeoutError")
                and last_op == "upstream" and _may()):
            # charged here
            _note_timeout(relay, lane, emit, seq, call_n)
        elif (_witness() and isinstance(exc, ssl.SSLError)
                and last_op == "upstream" and _may()):
            # dead exit
            _note_ssl(relay, lane, emit, seq, call_n)
        if _committed and _cap:
            # dump capture
            _dump_cut(seq, call_n, lane, err, bytes(_cap), seen)
        emit({"type": "callend", "t": time.time(), "n": seq, "c": call_n,
              "lane": lane.index, "cc": lane.exit_country,
              # delivered status
              "status": status if _committed else 0,
              "kb": round(seen / 1024, 1),
              "secs": round(time.time() - t0, 1), "err": err,
              "cut": True,
              "max_wait_s": round(max_wait, 1),
              "client_wait_s": round(client_wait, 1),
              "stalled": last_op,
              "note": _note_of(bytes(note_buf)),
              "reused": kept is not None,
              **_keys()})
        return err, 0, b"", retryable
    finally:
        if up is not None:
            _close_quiet(up)
