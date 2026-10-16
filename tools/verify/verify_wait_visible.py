"""Measured 2026-10-15: seven calls on lane 1, head delivered, no body."""
import io
import ssl
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lingling import mitm, proof  # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    """Detail is the failure reason, so only show it when it failed."""
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name}" + (f" -- {detail}" if (detail and not ok) else ""))
    if not ok:
        FAILS.append(name)


HEAD = (b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n"
        b"transfer-encoding: chunked\r\n\r\n")


class ParkedReader:
    """Delivers the response head, then a body that never starts."""

    def __init__(self, head, park, err):
        self._buf = io.BytesIO(head)
        self.park = park
        self.err = err
        self.parks = 0

    def _wait(self):
        self.parks += 1
        time.sleep(self.park)
        raise self.err

    def read(self, n=1):
        got = self._buf.read(n)
        return got or self._wait()

    def readline(self):
        got = self._buf.readline()
        return got or self._wait()


class FakeSock:
    def __init__(self, reader):
        self._reader = reader
        self.sent = b""

    def settimeout(self, _t):
        pass

    def connect(self, _a):
        pass

    def sendall(self, d):
        self.sent += d

    def makefile(self, _m):
        return self._reader

    def close(self):
        pass


class FakeCtx:
    def wrap_socket(self, sock, server_hostname=None):
        return sock


class Lane:
    index = 4
    exit_country = "us"
    exit_ip = "104.167.241.4"
    exit_fingerprint = "F" * 40
    socks_port = 9050
    lock = threading.Lock()
    active = 0
    streams: dict = {}

    def track_stream(self, sock, progress, hangup=None) -> None:
        """Register an open stream, so a dead exit can reach it."""
        with self.lock:
            self.streams[id(sock)] = (sock, progress, None)

    def drop_stream(self, sock) -> None:
        """Forget a stream that ended, or went into the pool."""
        with self.lock:
            self.streams.pop(id(sock), None)


class Tor:
    """The pool's one recorder; a parked copy still charges the dead exit."""

    def __init__(self):
        self.timeouts = []

    def note_timeout(self, lane):
        self.timeouts.append(lane.index)
        return ""


class Client:
    def __init__(self):
        self.got = b""

    def sendall(self, data):
        self.got += data

    def settimeout(self, _t):
        pass


def run(park=1.0, pulse=0.2):
    """Drive one real `_roundtrip` against a head that is never followed."""
    reader = ParkedReader(HEAD, park, TimeoutError("timed out"))
    events = []
    client = Client()
    tor = Tor()
    relay = type("R", (), {"tor": tor, "tunnels": None})()
    saved = (mitm._PULSE_S, mitm.netutil.socks5_open,
             mitm.ssl.create_default_context, mitm.socket.socket)
    mitm._PULSE_S = pulse
    mitm.netutil.socks5_open = lambda *a, **k: ""
    mitm.ssl.create_default_context = lambda: FakeCtx()
    mitm.socket.socket = lambda *a, **k: FakeSock(reader)
    try:
        err, status, _held, _retry = mitm._roundtrip(
            client, Lane(), "opencode.ai", 443, "POST", "/zen/v1/responses",
            {}, b'{"model":"m"}', events.append, 164, 1, time.time(), relay,
            charge_timeout=True)
    finally:
        (mitm._PULSE_S, mitm.netutil.socks5_open,
         mitm.ssl.create_default_context, mitm.socket.socket) = saved
    return err, status, events, tor


def main():
    print("=== floors: the pulse is a heartbeat, not a flood ===")
    check("the shipped pulse is at least 5s", mitm._PULSE_S >= 5.0,
          f"_PULSE_S={mitm._PULSE_S}s -- a log line a second per copy")
    check("a pause worth naming is at least 20s", proof._PARKED_S >= 20.0,
          f"_PARKED_S={proof._PARKED_S}s -- a token gap would be called a hang")

    print("\n=== a parked copy keeps the pane alive while it waits ===")
    err, status, events, tor = run()
    flows = [e for e in events if e.get("type") == "flow"]
    ends = [e for e in events if e.get("type") == "callend"]
    seats = {k: (flows[0].get(k) if flows else None) for k in
             ("n", "c", "lane", "cc", "ip", "kb", "waited_s")}
    print(f"  err={err!r} status={status} pulses={len(flows)} "
          f"parks={flows and [f['waited_s'] for f in flows]}")
    check("the parked copy pulsed at least twice", len(flows) >= 2,
          f"pulses={len(flows)} -- the pane was silent for the whole wait")
    check("every pulse names the call it belongs to",
          all(f.get("n") == 164 and f.get("c") == 1 for f in flows),
          str(seats))
    check("and the lane it is parked on",
          all(f.get("lane") == 4 and f.get("cc") == "us" for f in flows),
          str(seats))
    check("the reported wait grows while nothing arrives",
          len(flows) >= 2 and flows[-1]["waited_s"] > flows[0]["waited_s"],
          f"waited_s={[f.get('waited_s') for f in flows]}")
    check("a stalled copy still reports itself at the end",
          bool(ends) and ends[-1].get("stalled") == "upstream",
          str(ends[-1].get("stalled") if ends else "nothing emitted"))
    check("the dead exit is still charged", tor.timeouts == [4],
          f"timeouts={tor.timeouts}")

    print("\n=== the pane reads it as a wait, not as progress ===")
    proof._PARKED_S = 0.5  # proof parks
    line = proof._render(flows[-1]) if flows else ""
    proof._PARKED_S = 20.0
    print(f"  {line!r}")
    check("the line carries the traffic figure", "0.0 KB so far" in line,
          f"line={line!r}")
    check("and says how long the stream has been quiet",
          "no bytes for" in line, f"line={line!r}")

    print("\n=== the pulse stops with the copy ===")
    settled = len([e for e in events if e.get("type") == "flow"])
    time.sleep(1.0)
    later = len([e for e in events if e.get("type") == "flow"])
    check("no pulse outlives the call", later == settled,
          f"pulses {settled} -> {later} -- a watchdog leaked past the copy")

    print()
    if FAILS:
        print("A PARKED CALL IS VISIBLE: FAILED")
        for f in FAILS:
            print("  - " + f)
        return 1
    print("A PARKED CALL IS VISIBLE: CONFIRMED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
