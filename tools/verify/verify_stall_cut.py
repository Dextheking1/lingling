"""Five committed streams on one dead exit (2026-10-16) sat at 400-460s."""
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lingling import lanes as lanes_mod  # noqa: E402
from lingling import mitm, netutil  # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    """Detail is the failure reason, so only show it when it failed."""
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name}" + (f" -- {detail}" if (detail and not ok) else ""))
    if not ok:
        FAILS.append(name)


HEAD = (b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n"
        b"transfer-encoding: chunked\r\n\r\n")
EVENT = b'data: {"type":"response.reasoning.delta","delta":"xxxx"}\n\n'


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


def run(port, stall, idle, first_content, read_window=60.0, block_after=None):
    """Drive the shipped `_roundtrip`; returns what it did and what it said."""
    real_socks = netutil.socks5_open
    real_ctx = ssl.create_default_context
    saved = (mitm._READ_TIMEOUT, mitm._STREAM_IDLE_TIMEOUT,
             mitm._FIRST_CONTENT_TIMEOUT, mitm._STALL_CUT_S,
             lanes_mod._STREAM_STALL_S)

    class RawCtx:
        """The fake upstream speaks cleartext; skip the TLS wrap."""

        def wrap_socket(self, sock, server_hostname=None):  # noqa: ANN001
            return sock

    netutil.socks5_open = (lambda s, h, p, cred=None:
                           real_socks(s, h, p, cred))
    ssl.create_default_context = lambda *a, **k: RawCtx()
    mitm._READ_TIMEOUT = read_window
    mitm._STREAM_IDLE_TIMEOUT = idle
    mitm._FIRST_CONTENT_TIMEOUT = first_content
    mitm._STALL_CUT_S = stall
    #: lane's own
    lanes_mod._STREAM_STALL_S = 1.0

    #: REAL lane
    lane = lanes_mod.Lane(index=1, socks_port=port, control_port=port + 1,
                          exit_country="de", data_dir=Path("."))
    lane.exit_ip = "185.220.101.24"

    class Tap:
        """Stands in for the client socket; records what reached it"""

        def __init__(self, block_after=None):
            self.got = bytearray()
            self.sends = 0
            self.block_after = block_after
            self.hung_up = False
            self.sleeps = 0.0

        def sendall(self, data):
            self.sends += 1
            if self.block_after is not None and self.sends > self.block_after:
                self.sleeps += 2.0
                time.sleep(2.0)
                raise TimeoutError("timed out")
            self.got.extend(data)

        def settimeout(self, t):
            return None

        def shutdown(self, how):
            self.hung_up = True

        def close(self):
            self.hung_up = True

    charged = []

    class Tor:
        """The shipped verdict: write the lane off AND cut its quiet streams"""

        def note_timeout(self, lane):
            charged.append(lane.index)
            lane.cut_silent()
            return f"lane {lane.index} timed out -- moved to {{nl}}"

        def note_ssl_error(self, lane):
            charged.append(lane.index)
            return ""

        def note_slow_exit(self, lane, elapsed=0.0):
            charged.append(lane.index)
            return ""

    relay = type("R", (), {"tor": Tor()})()
    tap = Tap(block_after=block_after)
    #: block_after=None --
    events = []
    try:
        t0 = time.time()
        err, status, _h, _r = mitm._roundtrip(
            tap, lane, "opencode.ai", 443, "POST", "/zen/v1/responses",
            {}, b'{"model":"m"}', events.append, 1, 1, t0, relay,
            charge_timeout=True)
        secs = time.time() - t0
    finally:
        netutil.socks5_open = real_socks
        ssl.create_default_context = real_ctx
        (mitm._READ_TIMEOUT, mitm._STREAM_IDLE_TIMEOUT,
         mitm._FIRST_CONTENT_TIMEOUT, mitm._STALL_CUT_S,
         lanes_mod._STREAM_STALL_S) = saved
    end = [e for e in events if e.get("type") == "callend"]
    return {"err": err, "status": status, "secs": secs,
            "kb": len(tap.got) / 1024.0, "end": end[-1] if end else {},
            "charged": list(charged), "events": events,
            "hung_up": tap.hung_up, "lane": lane}


def case_committed_then_dead(c):
    """The owner's case: reasoning deltas, then the exit goes dark."""
    socks_hello(c)
    c.sendall(HEAD)
    chunk(c, EVENT)
    chunk(c, EVENT)
    time.sleep(120.0)  # never another


def case_pauses_under_the_cut(c):
    """A committed stream that keeps pausing, but under the cut."""
    socks_hello(c)
    c.sendall(HEAD)
    chunk(c, EVENT)
    for _ in range(4):
        time.sleep(1.5)  # each gap
        chunk(c, EVENT)
    chunk(c, b'data: {"type":"response.completed"}\n\n')
    c.sendall(b"0\r\n\r\n")


def case_never_commits(c):
    """Nothing at all reaches the client: the first-content rule owns this."""
    socks_hello(c)
    c.sendall(HEAD)
    time.sleep(120.0)


def main():
    stall, idle, first_content = 4.0, 60.0, 3.0

    print("=== (A) a committed stream the exit stopped talking to ===")
    print(f"  stall cut {stall:.0f}s, idle window {idle:.0f}s, "
          f"first-content {first_content:.0f}s")
    got = run(start_upstream(case_committed_then_dead), stall, idle,
              first_content)
    e = got["end"]
    print(f"  result: err={got['err']!r}  wall={got['secs']:.1f}s  "
          f"client={got['kb']:.2f} KB  stalled={e.get('stalled')!r}  "
          f"charged={got['charged']}  client_hung_up={got['hung_up']}")
    check("it ends at the stall cut, not at the idle window",
          got["err"] == "TimeoutError"
          and got["secs"] >= stall * 0.8 and got["secs"] < idle / 3,
          f"err={got['err']!r} wall={got['secs']:.1f}s -- the idle window "
          f"({idle:.0f}s) is what held it before")
    check("the blame lands on the exit (upstream), not the client",
          e.get("stalled") == "upstream", f"stalled={e.get('stalled')!r}")
    check("the answer already delivered is reported, not erased",
          got["kb"] > 0.1 and e.get("client_kb", 0) > 0,
          f"kb={got['kb']:.2f} client_kb={e.get('client_kb')!r}")
    check("the exit takes the timeout verdict, so the lane moves",
          got["charged"] == [1], f"charged={got['charged']}")
    check("the move is announced like a timeout's is",
          any(ev.get("type") == "lane" and ev.get("kind") == "timeout"
              for ev in got["events"]))
    check("the CLIENT is hung up, so the agent stops waiting",
          got["hung_up"] is True,
          "the client socket was left open -- the agent would wait forever")

    print("\n=== (B) a committed stream that pauses under the cut survives ===")
    got = run(start_upstream(case_pauses_under_the_cut), stall, idle,
              first_content)
    print(f"  result: err={got['err']!r}  wall={got['secs']:.1f}s  "
          f"client={got['kb']:.2f} KB  status={got['status']}  "
          f"charged={got['charged']}")
    check("the cut is a stall timer, not a total budget",
          got["err"] == "" and got["status"] == 200
          and got["secs"] > stall,
          f"err={got['err']!r} wall={got['secs']:.1f}s status={got['status']}")
    check("every byte of it reached the client",
          got["kb"] > 0.4, f"kb={got['kb']:.2f}")
    check("and its lane is not blamed",
          got["charged"] == [], f"charged={got['charged']}")

    print("\n=== (C) a CLIENT that stops reading is not the exit's fault ===")
    print("  the client takes the first write, then wedges")
    got = run(start_upstream(case_pauses_under_the_cut), stall, idle,
              first_content, block_after=1)
    e = got["end"]
    print(f"  result: err={got['err']!r}  stalled={e.get('stalled')!r}  "
          f"charged={got['charged']}  client_wait_s={e.get('client_wait_s')}")
    check("a wedged client does not retire a live exit",
          got["charged"] == [],
          f"charged={got['charged']} -- a slow reader cost the lane its seat")
    check("and it is reported as a client stall",
          e.get("stalled") == "client", f"stalled={e.get('stalled')!r}")

    print("\n=== (D) nothing ever committed still dies at the first-content cut ===")
    got = run(start_upstream(case_never_commits), stall, idle, first_content)
    print(f"  result: err={got['err']!r}  wall={got['secs']:.1f}s  "
          f"client={got['kb']:.2f} KB  charged={got['charged']}")
    check("the pre-commit rule still owns the quiet start",
          got["err"] == "TimeoutError" and got["secs"] < stall + 1.0,
          f"wall={got['secs']:.1f}s -- the stall cut masked the "
          f"{first_content:.0f}s first-content deadline")
    check("and it is still charged to the lane",
          got["charged"] == [1], f"charged={got['charged']}")

    print("\n=== (E) the shipped numbers ===")
    print(f"  first content {mitm._FIRST_CONTENT_TIMEOUT:.0f}s  "
          f"stall cut {mitm._STALL_CUT_S:.0f}s  "
          f"idle {mitm._STREAM_IDLE_TIMEOUT:.0f}s")
    check("the stall cut is far under the idle window",
          mitm._STALL_CUT_S < mitm._STREAM_IDLE_TIMEOUT / 3,
          f"{mitm._STALL_CUT_S:.0f}s vs {mitm._STREAM_IDLE_TIMEOUT:.0f}s -- "
          f"above a third of it, a dead exit still freezes agents for "
          f"minutes")
    check("and far above the longest healthy gap on record",
          mitm._STALL_CUT_S >= 60.0,
          f"{mitm._STALL_CUT_S:.0f}s -- a committed stream quiet 60s+ has "
          f"never delivered another byte in this project's log, and the "
          f"longest healthy gap measured is ~20s")
    check("and above the first-content deadline it backs up",
          mitm._STALL_CUT_S > mitm._FIRST_CONTENT_TIMEOUT,
          f"{mitm._STALL_CUT_S:.0f}s vs {mitm._FIRST_CONTENT_TIMEOUT:.0f}s")
    check("and at or above the lane's own stream-cut floor",
          mitm._STALL_CUT_S >= lanes_mod._STREAM_STALL_S,
          f"stall cut {mitm._STALL_CUT_S:.0f}s vs the lane's cut floor "
          f"{lanes_mod._STREAM_STALL_S:.0f}s -- if the verdict cut floor sat "
          f"above the stall cut, the exit would be retired and the client "
          f"left waiting on a stream nobody will finish")

    print()
    if FAILS:
        print("STALL CUT: FAILED")
        for f in FAILS:
            print("  - " + f)
        return 1
    print("STALL CUT: CONFIRMED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
