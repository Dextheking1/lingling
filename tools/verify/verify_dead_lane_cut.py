"""Measured 2026-10-15, one real session"""
import ast
import socket
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lingling import lanes as lanes_mod, mitm  # noqa: E402
from lingling.lanes import Lane  # noqa: E402

FAILS = []


def check(name, ok, detail="") -> bool:
    """Detail is the failure reason, so only show it when it failed."""
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name}" + (f" -- {detail}" if (detail and not ok) else ""))
    if not ok:
        FAILS.append(name)
    return ok


HEAD = (b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n"
        b"transfer-encoding: chunked\r\n\r\n")


def callers_with(tree, func: str, kw: str) -> set:
    """Functions that call ``func`` passing the keyword ``kw``."""
    out = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for n in ast.walk(node):
            if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and n.func.attr == func
                    and any(k.arg == kw for k in n.keywords)):
                out.add(node.name)
    return out


def lane_at(index: int = 3) -> Lane:
    """A real Lane, which is what _roundtrip is handed in the product."""
    return Lane(index=index, socks_port=9050, control_port=9051,
                exit_country="de", data_dir=ROOT / "data" / f"lane{index}")


class Dialed:
    """A real connected socket, minus the dial, so the head comes from here."""

    def __init__(self, real: socket.socket) -> None:
        self._real = real

    def connect(self, _addr) -> None:
        """Already connected: the pair is the tunnel."""

    def __getattr__(self, name):
        return getattr(self._real, name)


class Tor:
    """The pool's one recorder, as the copy sees it."""

    def __init__(self) -> None:
        self.timeouts = []

    def note_timeout(self, lane) -> str:
        self.timeouts.append(lane.index)
        return ""


class Client:
    """A client that keeps what it was sent, and stops when told."""

    def __init__(self) -> None:
        self.got = b""
        self.lock = threading.Lock()

    def sendall(self, data: bytes) -> None:
        with self.lock:
            self.got += data

    def settimeout(self, _t) -> None:
        pass


def drive(lane: Lane, park: float, cut_after: float, events: list, tor: Tor,
          drop_peer: bool = False):
    """Run one real `_roundtrip` whose body never starts, and cut the lane"""
    here, there = socket.socketpair()
    there.sendall(HEAD)
    near, far = socket.socketpair()
    client = near
    relay = type("R", (), {"tor": tor, "tunnels": None})()
    saved = (mitm.netutil.socks5_open, mitm.ssl.create_default_context,
             mitm.socket.socket, lanes_mod._STREAM_STALL_S)
    mitm.netutil.socks5_open = lambda *a, **k: ""
    mitm.ssl.create_default_context = lambda: type("Ctx", (), {
        "wrap_socket": staticmethod(
            lambda sock, server_hostname=None: sock)})()
    mitm.socket.socket = lambda *a, **k: Dialed(here)
    lanes_mod._STREAM_STALL_S = 0.2
    started = time.monotonic()
    try:
        thread = threading.Thread(
            target=mitm._roundtrip,
            args=(client, lane, "opencode.ai", 443, "POST",
                  "/zen/v1/responses", {}, b'{"model":"m"}', events.append,
                  164, 1, time.time(), relay),
            kwargs={"charge_timeout": True}, daemon=True)
        thread.start()
        deadline = time.monotonic() + park
        while time.monotonic() < deadline:
            if lane.streams:
                break
            time.sleep(0.05)
        check("the copy registered its stream on the lane", bool(lane.streams),
              f"streams={len(lane.streams)} -- the pool cannot reach what it "
              f"cannot see")
        if cut_after >= 0:
            time.sleep(cut_after)
            lane.cut_silent()
        far.settimeout(2.0)
        try:
            left = far.recv(64)
            hung_up = left == b""
        except socket.timeout:
            # quiet client
            hung_up = False
        except OSError:
            hung_up = True
        thread.join(timeout=2.0)
        took = time.monotonic() - started
        alive = thread.is_alive()
        gone = False
        if alive and drop_peer:
            there.close()  # exit
            thread.join(timeout=2.0)
            gone = not thread.is_alive()
        if thread.is_alive():
            here.shutdown(socket.SHUT_RDWR)
            thread.join(timeout=2.0)
        return took, alive, hung_up, events, gone
    finally:
        (mitm.netutil.socks5_open, mitm.ssl.create_default_context,
         mitm.socket.socket, lanes_mod._STREAM_STALL_S) = saved
        for sock in (here, there, near, far):
            sock.close()


def main() -> int:
    print("=== floors: the cut fires long before the idle ceiling ===")
    check("a quiet stream is defined at 20s or more",
          lanes_mod._STREAM_STALL_S >= 20.0,
          f"_STREAM_STALL_S={lanes_mod._STREAM_STALL_S}s -- a token gap would "
          f"be called a stall")
    check("and far under the committed idle ceiling",
          lanes_mod._STREAM_STALL_S < mitm._STREAM_IDLE_TIMEOUT,
          f"{lanes_mod._STREAM_STALL_S}s vs {mitm._STREAM_IDLE_TIMEOUT}s")
    check("the deferred move still has its own backstop",
          lanes_mod._DEFER_MAX_S >= lanes_mod._STREAM_STALL_S,
          f"_DEFER_MAX_S={lanes_mod._DEFER_MAX_S}s")

    print("\n=== only the quiet streams are cut ===")
    quiet_a, quiet_b = socket.socketpair()
    loud_a, loud_b = socket.socketpair()
    lane = lane_at()
    stale = {"bytes": 0, "at": time.time() - 300.0}
    fresh = {"bytes": 4096, "at": time.time()}
    lane.track_stream(Dialed(quiet_a), stale)
    lane.track_stream(Dialed(loud_a), fresh)
    print(f"  tracked streams: {len(lane.streams)}")
    cut = lane.cut_silent()
    quiet_b.settimeout(1.0)
    loud_b.settimeout(1.0)
    try:
        seen = quiet_b.recv(16)
    except OSError:
        seen = b""
    print(f"  cut={cut} streams left={len(lane.streams)} peer read={seen!r}")
    check("the quiet stream is cut", cut == 1, f"cut={cut}")
    check("the cut reaches the wire", seen == b"",
          f"the far end read {seen!r} -- the socket is still open")
    check("the quiet stream is forgotten",
          len(lane.streams) == 1, f"streams={len(lane.streams)}")
    check("a stream still moving bytes keeps its seat",
          lane.cut_silent() == 0, "a live answer was cut")
    check("and its socket is untouched", loud_b.send(b"x") == 1,
          "the live stream's wire was cut too")
    check("the lane is still tracked after a second pass",
          len(lane.streams) == 1, f"streams={len(lane.streams)}")
    quiet_a.close()
    quiet_b.close()
    loud_a.close()
    loud_b.close()

    print("\n=== the decision a written-off lane makes ===")
    wired = ast.parse((ROOT / "lingling" / "lanes.py").read_text("utf-8"))
    calls = {}
    for node in ast.walk(wired):
        if isinstance(node, ast.FunctionDef):
            names = [n.func.attr for n in ast.walk(node)
                     if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
            calls.setdefault(node.name, []).extend(names)
    for verdict in ("note_timeout", "note_ssl_error", "note_slow_exit"):
        check(f"{verdict} cuts the streams on the dead exit",
              "cut_silent" in calls.get(verdict, []), f"{calls.get(verdict)}")
    check("a spent allowance does NOT cut -- it drains",
          "cut_silent" not in calls.get("note_limited", []),
          f"{calls.get('note_limited')}")
    track = (ROOT / "lingling" / "mitm.py").read_text("utf-8")
    check("the copy offers its stream to the lane",
          "lane.track_stream(" in track, "no stream is registered")
    check("and takes it back when the tunnel is pooled or closed",
          track.count("lane.drop_stream(") >= 2,
          f"{track.count('lane.drop_stream(')} drop sites")

    print("\n=== a lane that owes nobody is retired now, not in 900s ===")
    owes = ast.parse((ROOT / "lingling" / "lanes.py").read_text("utf-8"))
    forced = callers_with(owes, "_rebuild_async", "now")
    print(f"  verdicts that force the retirement: {sorted(forced)}")
    for verdict in ("note_timeout", "note_ssl_error", "note_slow_exit"):
        check(f"{verdict} retires at once once the books are clear",
              verdict in forced, f"forced={sorted(forced)}")
    check("a spent allowance still waits for its live answers",
          "note_limited" not in forced, f"forced={sorted(forced)}")
    src = (ROOT / "lingling" / "lanes.py").read_text("utf-8")
    check("and the waiter honours that",
          "if lane.active > 0 and not now:" in src,
          "restart_lane does not check `now`")
    busy = lane_at()
    live = {"bytes": 12, "at": time.time()}
    held = socket.socketpair()
    busy.track_stream(Dialed(held[0]), live)
    check("a lane holding a live stream owes its answer",
          lanes_mod._owes_nobody(busy) is False, "it would retire under it")
    busy.cut_silent(0.0)
    check("a lane hung up on everything owes nobody",
          lanes_mod._owes_nobody(lane_at()) is True and
          lanes_mod._owes_nobody(busy) is True,
          f"streams={len(busy.streams)}")
    held[0].close()
    held[1].close()

    print("\n=== a written-off lane hangs up on the client ===")
    lane = lane_at()
    events = []
    took, alive, hung_up, events, _gone = drive(
        lane, park=3.0, cut_after=0.5, events=events, tor=Tor())
    ends = [e for e in events if e.get("type") == "callend"]
    print(f"  cut run: {took:.2f}s  client hung up={hung_up} "
          f"copy still parked={alive} streams left={len(lane.streams)}")
    check("the agent stops waiting at once, not at the idle ceiling", hung_up,
          "the client connection is still open -- the agent is still waiting")
    check("the lane forgets the stream, so the recook may proceed",
          not lane.streams, f"streams={len(lane.streams)}")
    check("and the cut stream says so if it does end",
          not ends or ends[-1].get("cut") is True,
          f"callend={ends[-1] if ends else 'nothing emitted'}")
    print(f"  (the copy itself is left to end when its exit is replaced: on "
          f"Windows a buffered read cannot be interrupted by closing our own "
          f"socket, measured -- shutdown and close both left it blocked)")

    print("\n=== control: with no cut, the agent keeps waiting ===")
    lane = lane_at()
    events = []
    took, alive, hung_up, _events, gone = drive(
        lane, park=3.0, cut_after=-1, events=events, tor=Tor(),
        drop_peer=True)
    print(f"  control run: after {took:.2f}s  client hung up={hung_up} "
          f"copy parked={alive}")
    check("the control client is still connected", not hung_up,
          "it hung up on its own -- this test cannot tell a cut from a wait")
    check("and its copy is still parked on the dead exit", alive,
          "the copy ended without being cut")
    print("\n=== and the copy lets go when its exit is replaced ===")
    check("replacing the exit releases the parked copy", gone,
          f"still parked {took:.1f}s after its peer went away -- nothing would "
          f"free it but the 1800s ceiling")
    for entry in list(lane.streams.values()):
        mitm._abort_quiet(entry[0])

    print()
    if FAILS:
        print("A DEAD LANE CUTS ITS STREAMS: FAILED")
        for f in FAILS:
            print("  - " + f)
        return 1
    print("A DEAD LANE CUTS ITS STREAMS: CONFIRMED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
