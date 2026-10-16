"""A stream that has shown the client nothing is dropped at the deadline."""
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lingling import mitm, netutil  # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name}" + (f" -- {detail}" if detail else ""))
    if not ok:
        FAILS.append(name)


HEAD = (b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n"
        b"transfer-encoding: chunked\r\n\r\n")
EVENT = b'data: {"type":"response.output_text.delta"}\n\n'


def quiet(schedule):
    """A schedule whose hang-up is expected, not a failure."""

    def wrapped(c):
        try:
            schedule(c)
        except OSError:
            pass

    return wrapped


def start_upstream(schedule):
    """A SOCKS5-speaking upstream that runs `schedule` once connected."""
    holder = []
    ready = threading.Event()

    def serve():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        holder.append(srv.getsockname()[1])
        ready.set()
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=quiet(schedule), args=(c,),
                             daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    ready.wait(5)
    return holder[0]


def socks_hello(c):
    """Answer the SOCKS5 greeting and CONNECT, then read the request."""
    c.settimeout(180)
    c.recv(3)
    c.sendall(bytes([0x05, 0x00]))
    c.recv(64)
    c.sendall(bytes([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
    c.recv(65536)


def chunk(c, payload=EVENT):
    c.sendall(b"%x\r\n" % len(payload) + payload + b"\r\n")


def run(port, deadline=3.0, window=60.0, idle=60.0):
    """Drive the shipped `_roundtrip`; returns what it did and what it said."""
    real_socks = netutil.socks5_open
    real_ctx = ssl.create_default_context
    old_read = mitm._READ_TIMEOUT
    old_idle = mitm._STREAM_IDLE_TIMEOUT
    old_dead = mitm._FIRST_CONTENT_TIMEOUT

    class RawCtx:
        """The fake upstream speaks cleartext; skip the TLS wrap."""

        def wrap_socket(self, sock, server_hostname=None):  # noqa: ANN001
            return sock

    netutil.socks5_open = (lambda s, h, p, cred=None:
                           real_socks(s, h, p, cred))
    ssl.create_default_context = lambda *a, **k: RawCtx()
    mitm._READ_TIMEOUT = window
    mitm._STREAM_IDLE_TIMEOUT = idle
    mitm._FIRST_CONTENT_TIMEOUT = deadline

    class Lane:
        index = 1
        exit_country = "de"
        exit_ip = "1.2.3.4"
        exit_fingerprint = "F" * 40
        socks_port = port
        lock = threading.Lock()
        active = 0
        streams = {}

        def track_stream(self, sock, progress, hangup=None) -> None:
            with self.lock:
                self.streams[id(sock)] = (sock, progress, hangup)

        def drop_stream(self, sock) -> None:
            with self.lock:
                self.streams.pop(id(sock), None)

    class Tap:
        """Stands in for the client socket; records what reached it."""

        def __init__(self):
            self.got = bytearray()

        def sendall(self, data):
            self.got.extend(data)

        def settimeout(self, t):
            return None

    charged = []

    class Tor:
        def note_timeout(self, lane):
            charged.append(lane.index)
            return f"lane {lane.index} timed out -- moved to {{nl}}"

        def note_ssl_error(self, lane):
            charged.append(lane.index)
            return ""

        def note_slow_exit(self, lane, elapsed=0.0):
            charged.append(lane.index)
            return ""

    relay = type("R", (), {"tor": Tor()})()
    tap = Tap()
    events = []
    try:
        t0 = time.time()
        err, status, _h, _r = mitm._roundtrip(
            tap, Lane(), "opencode.ai", 443, "POST", "/zen/v1/responses",
            {}, b'{"model":"m"}', events.append, 1, 1, t0, relay,
            charge_timeout=True)
        secs = time.time() - t0
    finally:
        netutil.socks5_open = real_socks
        ssl.create_default_context = real_ctx
        mitm._READ_TIMEOUT = old_read
        mitm._STREAM_IDLE_TIMEOUT = old_idle
        mitm._FIRST_CONTENT_TIMEOUT = old_dead
    end = [e for e in events if e.get("type") == "callend"]
    return {"err": err, "status": status, "secs": secs,
            "kb": len(tap.got) / 1024.0, "end": end[-1] if end else {},
            "charged": list(charged), "events": events}


def case_nothing_after_head(c):
    """The head arrives, then the far end never speaks again."""
    socks_hello(c)
    c.sendall(HEAD)
    time.sleep(120.0)


def case_nothing_at_all(c):
    """The far end takes the request and answers nothing, not even a head."""
    socks_hello(c)
    time.sleep(120.0)


def case_just_in_time(c):
    """The first event lands just inside the deadline."""
    socks_hello(c)
    c.sendall(HEAD)
    time.sleep(2.0)
    chunk(c, b'data: {"delta":"' + b"y" * 2000 + b'"}\n\n')
    chunk(c, b'data: {"type":"response.completed"}\n\n')
    c.sendall(b"0\r\n\r\n")


def case_committed_then_thinks(c):
    """A committed answer (95 KB like the log) that then thinks past it."""
    socks_hello(c)
    c.sendall(HEAD)
    for _ in range(4):
        chunk(c, b'data: {"delta":"' + b"x" * 300 + b'"}\n\n')
    time.sleep(9.0)  # 3x
    chunk(c, b'data: {"type":"response.completed"}\n\n')
    c.sendall(b"0\r\n\r\n")


def main():
    deadline, window = 3.0, 60.0

    print("=== (A) a head, then nothing: the log's 0.0 KB stream ===")
    print(f"  first-content deadline {deadline:.0f}s, read window {window:.0f}s")
    got = run(start_upstream(case_nothing_after_head), deadline, window)
    e = got["end"]
    print(f"  result: err={got['err']!r}  wall={got['secs']:.1f}s  "
          f"client={got['kb']:.1f} KB  status={got['status']}  "
          f"charged={got['charged']}")
    check("a stream with no content is dropped at the deadline",
          got["err"] == "TimeoutError"
          and got["secs"] >= deadline * 0.8
          and got["secs"] < window / 2,
          f"err={got['err']!r} wall={got['secs']:.1f}s -- the idle window "
          f"({window:.0f}s) is what parked it before")
    check("it is dropped mid-stream, not after the answer's own window",
          got["secs"] < deadline + 1.5, f"wall={got['secs']:.1f}s")
    check("the client was shown nothing, so nothing is half-answered",
          got["kb"] == 0.0 and got["status"] == 0,
          f"kb={got['kb']} status={got['status']}")
    check("the lane takes the TIMEOUT verdict, so the country moves",
          got["charged"] == [1],
          f"charged={got['charged']} -- a stalled exit kept its seat")
    check("and the move is announced like a timeout's is",
          any(ev.get("type") == "lane" and ev.get("kind") == "timeout"
              for ev in got["events"]))
    check("the callend is the timeout shape, so the call retries",
          e.get("err") == "TimeoutError" and e.get("cut") is True
          and e.get("client_kb") == 0,
          f"err={e.get('err')!r} cut={e.get('cut')!r} "
          f"client_kb={e.get('client_kb')!r} -- the buffered head must not "
          f"read as delivered content")

    print("\n=== (B) the far end answers nothing at all, not even a head ===")
    got = run(start_upstream(case_nothing_at_all), deadline, window)
    print(f"  result: err={got['err']!r}  wall={got['secs']:.1f}s  "
          f"charged={got['charged']}")
    check("a silent head spends the same deadline",
          got["err"] == "TimeoutError" and got["secs"] < deadline + 1.5
          and got["secs"] >= deadline * 0.8,
          f"err={got['err']!r} wall={got['secs']:.1f}s")
    check("and is charged to the lane, as a timeout is",
          got["charged"] == [1], f"charged={got['charged']}")

    print("\n=== (C) content inside the deadline is not touched ===")
    got = run(start_upstream(case_just_in_time), deadline, window)
    print(f"  result: err={got['err']!r}  wall={got['secs']:.1f}s  "
          f"client={got['kb']:.2f} KB  status={got['status']}")
    check("an answer that arrives before the deadline is served whole",
          got["err"] == "" and got["status"] == 200 and got["kb"] > 0.5,
          f"err={got['err']!r} status={got['status']} kb={got['kb']:.2f}")
    check("and its lane is not blamed",
          got["charged"] == [], f"charged={got['charged']}")

    print("\n=== (D) a COMMITTED stream that thinks past the deadline ===")
    print(f"  ~1.5 KB delivered, then {9.0:.0f}s of thought "
          f"(3x the {deadline:.0f}s deadline)")
    got = run(start_upstream(case_committed_then_thinks), deadline, window)
    print(f"  result: err={got['err']!r}  wall={got['secs']:.1f}s  "
          f"client={got['kb']:.1f} KB  charged={got['charged']}")
    check("a committed answer is never cut by the first-content deadline",
          got["err"] == "" and got["secs"] > deadline * 2.5
          and got["kb"] > 1.0,
          f"err={got['err']!r} wall={got['secs']:.1f}s kb={got['kb']:.1f} -- "
          f"the think-pause was mistaken for a dead exit")
    check("and its lane keeps its seat",
          got["charged"] == [], f"charged={got['charged']}")

    print("\n=== (E) the shipped numbers ===")
    print(f"  first content {mitm._FIRST_CONTENT_TIMEOUT:.0f}s  "
          f"read {mitm._READ_TIMEOUT:.0f}s  idle {mitm._STREAM_IDLE_TIMEOUT:.0f}s "
          f"slow {mitm._SLOW_EXIT_S:.0f}s")
    check("the deadline is far under the idle window",
          mitm._FIRST_CONTENT_TIMEOUT < mitm._STREAM_IDLE_TIMEOUT / 10,
          f"{mitm._FIRST_CONTENT_TIMEOUT}s vs {mitm._STREAM_IDLE_TIMEOUT}s -- "
          f"a zero-content stream must never park for half an hour")
    check("and at or over the slow-exit line, so a real first token fits",
          mitm._FIRST_CONTENT_TIMEOUT >= mitm._SLOW_EXIT_S,
          f"{mitm._FIRST_CONTENT_TIMEOUT}s vs {mitm._SLOW_EXIT_S}s -- a first "
          f"event the slow rule tolerates would be cut early")

    print()
    if FAILS:
        print("FIRST CONTENT DEADLINE: FAILED")
        for f in FAILS:
            print("  - " + f)
        return 1
    print("FIRST CONTENT DEADLINE: CONFIRMED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
