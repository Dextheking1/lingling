"""A pool-wide 429 is retried on fresh exits, then delivered."""
import io
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lingling import mitm  # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name}" + (f" -- {detail}" if (detail and not ok) else ""))
    if not ok:
        FAILS.append(name)


# --------------------------------------------------------------------------

BODY = b'{"model":"muse-spark-1.3-contributor-free"}'
REQ = (b"POST /zen/v1/responses HTTP/1.1\r\n"
       b"host: opencode.ai\r\ncontent-type: application/json\r\n"
       b"content-length: %d\r\n\r\n" % len(BODY) + BODY)


def wall(note=b"rate"):
    """A 429 with the reset header the far end sends."""
    body = (b'{"error":{"type":"rate"}}' if note == b"rate"
            else b'{"error":{"type":"FreeUsageLimitError"}}')
    return (b"HTTP/1.1 429 Too Many Requests\r\n"
            b"content-type: application/json\r\nretry-after: 12373\r\n"
            b"content-length: %d\r\n\r\n" % len(body) + body)


EDGE = (b"HTTP/1.1 429 Too Many Requests\r\n"
        b"content-type: application/json\r\ncontent-length: 92\r\n\r\n"
        b'{"error":{"type":"server_error","message":"Endpoint is '
        b'unavailable"}}')

S429 = wall()
S429_FREE = wall(b"free")

SSE = b'data: {"type":"response.completed"}\n\n'
SSE_200 = (b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n"
           b"transfer-encoding: chunked\r\n\r\n"
           + b"%x\r\n" % len(SSE) + SSE + b"0\r\n\r\n")


class FakeSock:
    """A dialled upstream delivering one canned response."""

    def __init__(self, response):
        self._r = io.BytesIO(response)
        self.closed = False

    def settimeout(self, _t):
        pass

    def connect(self, _a):
        pass

    def sendall(self, _d):
        pass

    def makefile(self, _m):
        return self._r

    def shutdown(self, _how):
        self.closed = True

    def close(self):
        self.closed = True


class FakeCtx:
    def wrap_socket(self, sock, server_hostname=None):
        return sock


class ServeClient:
    """A client socket carrying one canned request, for driving `_serve`."""

    def __init__(self, head=REQ):
        self._r = io.BytesIO(head)
        self.got = b""

    def makefile(self, _m):
        return self._r

    def sendall(self, d):
        self.got += d


class FakeTor:
    """The notepad: a burnt exit is written down, and benches only that exit."""

    def __init__(self):
        self.limited = []

    def note_limited(self, lane, retry_after=0.0, reason="rate",
                     fingerprint=""):
        self.limited.append((lane.index, retry_after, reason))
        lane.limited_until = mitm.time.time() + (retry_after or 600.0)

    def note_result(self, country, status):
        pass

    def note_timeout(self, lane):
        return ""


class FakeLane:
    def __init__(self, index):
        self.index = index
        self.exit_country = "de"
        self.exit_ip = f"1.2.3.{index}"
        self.exit_fingerprint = f"{index:040X}"
        self.socks_port = 9050 + index
        self.lock = threading.Lock()
        self.active = 0
        self.streams = {}
        self.healthy = True
        self.healing = False
        self.limited_until = 0.0

    def track_stream(self, sock, progress, hangup=None):
        with self.lock:
            self.streams[id(sock)] = (sock, progress, None)

    def drop_stream(self, sock):
        with self.lock:
            self.streams.pop(id(sock), None)


class FakeRelay:
    """A relay whose refused lanes move to a fresh exit, as the daemon does."""

    def __init__(self, responses, n_lanes=3, move=True):
        self.responses = list(responses)
        self.dials = []
        self.refused = []
        self.moved = []
        self.move = move
        self.tor = FakeTor()
        self.tunnels = None
        self.lanes = [FakeLane(i + 1) for i in range(n_lanes)]

    def pick_lane(self, exclude=None):
        for lane in self.lanes:
            if (not exclude or lane.index not in exclude) \
                    and lane.healthy and not lane.healing:
                return lane
        return None

    def report_refused(self, lane, status, fingerprint=""):
        self.refused.append((lane.index, status))
        if not self.move:
            return
        # restart_lane: a fresh exit, and off the bench
        lane.exit_ip = f"9.9.9.{lane.index}"
        lane.limited_until = 0.0
        self.moved.append(lane.index)

    def any_unlimited(self, exclude):
        now = mitm.time.time()
        return any(l.index not in exclude and l.limited_until <= now
                   for l in self.lanes)


_real = (mitm.time, mitm.netutil.socks5_open, mitm.ssl.create_default_context,
         mitm.socket.socket)


def dial_from(relay):
    def dial(*_a, **_k):
        r = relay.responses.pop(0) if relay.responses else None
        sock = FakeSock(r if r is not None else b"")
        relay.dials.append(sock)
        return sock
    return dial


def _restore():
    (mitm.time, mitm.netutil.socks5_open,
     mitm.ssl.create_default_context, mitm.socket.socket) = _real


def serve(responses, n_lanes=3, move=True):
    """One real `_serve` request against canned upstream responses."""
    events = []
    client = ServeClient()
    relay = FakeRelay(responses, n_lanes, move)
    mitm.netutil.socks5_open = lambda sock, host, port, cred=None: None
    mitm.ssl.create_default_context = lambda: FakeCtx()
    mitm.socket.socket = dial_from(relay)
    t0 = time.monotonic()
    try:
        mitm._serve(client, "opencode.ai", 443, 7, events.append, relay)
    finally:
        _restore()
    return client, events, relay, time.monotonic() - t0


def ends(events):
    return [e for e in events if e.get("type") == "callend"]


def calls(events):
    return [e for e in events if e.get("type") == "call"]


print("=== the shipped budget ===")
print(f"  retries after a pool-wide 429: {mitm._LIMIT_WAVES} "
      f"(wait {mitm._LIMIT_WAIT_S}s)")
check("the client is told about a rate limit only after two retries or more",
      mitm._LIMIT_WAVES >= 2, f"waves={mitm._LIMIT_WAVES}")
check("and the wait leaves the moved lanes time to come up",
      mitm._LIMIT_WAIT_S >= 1.0, f"wait={mitm._LIMIT_WAIT_S}s")

print("\n=== A. a pool-wide 429 is retried on the fresh exits ===")
(client, events, relay, secs) = serve([S429] * 3 + [SSE_200] * 3, n_lanes=3)
print(f"  dials={len(relay.dials)} moved={relay.moved} "
      f"statuses={[e['status'] for e in ends(events)]} secs={secs:.1f}")
check("the client got the 200, not the wall",
      client.got.startswith(b"HTTP/1.1 200"), repr(client.got[:40]))
check("and never saw a 429", b"429" not in client.got, repr(client.got[:80]))
check("every burnt exit was written down",
      len(relay.tor.limited) == 3, str(relay.tor.limited))
check("every refused lane moved to a fresh exit",
      sorted(relay.moved) == [1, 2, 3], str(relay.moved))
check("the pool was walked a second time",
      len(calls(events)) == 2, f"waves={len(calls(events))}")
check("the retry waited for the moves",
      secs >= mitm._LIMIT_WAIT_S, f"{secs:.2f}s")
check("the pane still shows the wall, once per lane",
      [e["status"] for e in ends(events)].count(429) == 3,
      str([e["status"] for e in ends(events)]))

print("\n=== B. a wall that does not lift is delivered, after the retries ===")
(client, events, relay, secs) = serve([S429] * 40, n_lanes=3)
waves = len(relay.dials) // 3
print(f"  waves={waves} dials={len(relay.dials)} secs={secs:.1f}")
check("the far end was asked one wave plus the retries",
      waves == 1 + mitm._LIMIT_WAVES, f"waves={waves}")
check("the client finally got the far end's own 429",
      client.got.startswith(b"HTTP/1.1 429"), repr(client.got[:40]))
check("with the reset the far end named",
      b"retry-after: 12373" in client.got, repr(client.got[:120]))
check("and no invented 502", b"502" not in client.got, repr(client.got[:40]))
check("every wave's exit was written down",
      len(relay.tor.limited) == 3 * (1 + mitm._LIMIT_WAVES),
      f"{len(relay.tor.limited)}")

print("\n=== C. nothing moved, so nothing is waited for ===")
(client, events, relay, secs) = serve([S429] * 3, n_lanes=3, move=False)
print(f"  dials={len(relay.dials)} secs={secs:.2f}")
check("the wall went straight out", client.got.startswith(b"HTTP/1.1 429"),
      repr(client.got[:40]))
check("no wave was spent on exits that did not move",
      len(relay.dials) == 3, f"dials={len(relay.dials)}")
check("and the client was not made to wait",
      secs < mitm._LIMIT_WAIT_S, f"{secs:.2f}s")

print("\n=== D. opencode's own edge is not a limit ===")
(client, events, relay, secs) = serve([EDGE] * 3, n_lanes=3)
check("their edge went straight out",
      client.got.startswith(b"HTTP/1.1 429"), repr(client.got[:40]))
check("nothing was benched for it", not relay.tor.limited,
      str(relay.tor.limited))
check("and no lane was moved", not relay.moved, str(relay.moved))
check("one wave, no retry", len(calls(events)) == 1, str(len(calls(events))))

print("\n=== E. the day's wall retries the same way ===")
(client, events, relay, secs) = serve([S429_FREE] * 3 + [SSE_200] * 3,
                                      n_lanes=3)
check("the client got the 200", client.got.startswith(b"HTTP/1.1 200"),
      repr(client.got[:40]))
check("the wall was written into the free section",
      [r for _i, _w, r in relay.tor.limited] == ["free"] * 3,
      str(relay.tor.limited))
check("the pool was walked again", len(calls(events)) == 2,
      f"waves={len(calls(events))}")

print()
if FAILS:
    print("LIMIT RETRY: FAILED")
    for f in FAILS:
        print("  - " + f)
    sys.exit(1)
print("LIMIT RETRY: CONFIRMED")
sys.exit(0)
