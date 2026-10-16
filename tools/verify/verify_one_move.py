"""One burst of verdicts on one lane is one move -- never ten."""
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lingling.health import HealthDaemon  # noqa: E402
from lingling.lanes import _MOVE_GUARD_S, Lane, TorManager  # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name}" + (f" -- {detail}" if (detail and not ok) else ""))
    if not ok:
        FAILS.append(name)


def build(count=2):
    """A TorManager with no tor and no disk: only the move machinery."""
    mgr = TorManager.__new__(TorManager)
    mgr.lanes = [
        Lane(index=i, socks_port=52000 + i, control_port=52300 + i,
             exit_country="de", data_dir=Path("."))
        for i in range(1, count + 1)
    ]
    for lane in mgr.lanes:
        lane.exit_fingerprint = "F" * 40
        lane.limited_until = 0.0
        lane.active = 0
    mgr._stopping = False
    #: one move per lane
    mgr._move_locks = {}
    mgr._move_locks_lock = threading.Lock()
    mgr._emit = lambda e: None
    mgr._rebuilds = []
    mgr._limited = {}
    mgr._write_json = lambda *a: None
    mgr._save_limited = lambda: None
    mgr._clear_lane_dir_owner = lambda l: False
    mgr._write_torrc = lambda l: None
    mgr._pin = lambda l: True
    mgr._launch_lane = lambda l: "started"
    mgr._stop_lane_process = lambda l: True
    return mgr


def burst(call, n=10):
    """Fire `call` from n threads at once; return how many didn't refuse."""
    gate = threading.Barrier(n)
    out = [None] * n

    def worker(i):
        gate.wait()
        try:
            out[i] = call(i)
        except Exception as exc:  # noqa: BLE001
            out[i] = exc

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    return out


def main():
    print(f"shipped: move guard {_MOVE_GUARD_S:.0f}s  "
          f"defer {TorManager.__init__.__doc__ or 'lanes'}")

    print("\n=== ten copies of one dead call move the lane once ===")
    mgr = build()
    lane = mgr.lanes[0]
    rotations, rebuilds, written = [], [], []
    mgr.rotate_exit_country = lambda l: (rotations.append(l.index), "nl")[1]
    mgr._rebuild_async = lambda l, repin=False, now=False: rebuilds.append(now)
    mgr.note_limited = lambda l, retry_after=0.0, reason="rate", \
        fingerprint="": (written.append(l.index), 1.0)[1]

    answers = burst(lambda i: mgr.note_timeout(lane))
    raised = [a for a in answers if isinstance(a, Exception)]
    moves = [a for a in answers if a]
    print(f"  rotations={len(rotations)} rebuilds={len(rebuilds)} "
          f"write-offs={len(written)} lines={len(moves)}")
    check("no copy blows up", not raised, f"{raised[:1]}")
    check("the lane is rotated exactly once", len(rotations) == 1,
          f"{len(rotations)} rotations -- one bad relay, one move")
    check("and recooked exactly once", len(rebuilds) == 1,
          f"{len(rebuilds)} rebuilds -- the echo is back")
    check("the exit is written off exactly once", len(written) == 1,
          f"{len(written)} write-offs")
    check("only the copy that moved it answers", len(moves) == 1,
          f"{len(moves)} verdict lines -- the pane would print ten")

    print("\n=== the guard re-arms, so a real second failure still moves ===")
    check("a second verdict inside the window is refused",
          mgr.claim_move(lane) is False,
          "the guard did not hold")
    lane.retired_at = time.time() - (_MOVE_GUARD_S + 1)
    check("a later verdict is allowed through again",
          mgr.claim_move(lane) is True,
          "the guard latched -- the lane could never move again")

    print("\n=== the guard is per lane, not per pool ===")
    other = mgr.lanes[1]
    check("another lane moves in the same breath",
          mgr.claim_move(other) is True,
          "one lane's burst blocked the whole pool")

    print("\n=== an SSL cut and a slow first event are the same verdict ===")
    for name, call in (("note_ssl_error", mgr.note_ssl_error),
                       ("note_slow_exit", lambda l, elapsed=0.0:
                        mgr.note_slow_exit(l, elapsed))):
        fresh = build().lanes[0]
        fresh.retired_at = time.time()
        fresh.retired_exit = fresh.exit_fingerprint
        check(f"{name} is gated by the same move", call(fresh) is None,
              "a verdict the guard refused still spoke")

    print("\n=== two moves on one lane never run together ===")
    mgr = build()
    lane = mgr.lanes[0]
    live = {"n": 0}
    overlaps = []
    done = []

    def slow_stop(_lane):
        live["n"] += 1
        if live["n"] > 1:
            overlaps.append(live["n"])
        time.sleep(0.25)
        live["n"] -= 1
        return True

    mgr._stop_lane_process = slow_stop

    def move(i):
        done.append(mgr.restart_lane(lane, now=True))

    burst(move, n=4)
    print(f"  teardowns in flight together: {max(overlaps) if overlaps else 1} "
          f"of 4 callers, all returned={len(done) == 4}")
    check("no two teardowns of one lane overlap", not overlaps,
          f"overlap={overlaps} -- the lock is not held across the move")
    check("and every caller still got its answer", len(done) == 4,
          f"{len(done)} of 4 returned")

    print("\n=== a fan-out of 429s is one move too ===")
    mgr = build()
    lane = mgr.lanes[0]
    rotations, benches = [], []
    mgr.rotate_exit_country = lambda l: (rotations.append(l.index), "nl")[1]
    mgr.restart_lane = lambda l, repin=False, now=False: True
    mgr.note_limited = lambda l, retry_after=0.0, reason="rate", \
        fingerprint="": (
        benches.append(reason), lane.__setattr__("limited_until",
                                                 time.time() + 600), 1.0)[2]
    daemon = HealthDaemon(mgr, log=lambda *a: None)

    burst(lambda i: daemon.refuse(lane, 429), n=8)
    print(f"  rotations={len(rotations)} benches={len(benches)}")
    check("eight copies of one 429 move the lane once",
          len(rotations) == 1,
          f"{len(rotations)} rotations -- a 429 fan-out cost a move each")
    check("and the exit is still benched", len(benches) >= 1,
          "the spent exit went back into the pool")

    print("\n=== the transport tolerates the refusal ===")
    src = (ROOT / "lingling" / "mitm.py").read_text(encoding="utf-8")
    for wrapper in ("_note_timeout", "_note_ssl", "_note_slow"):
        body = src.split(f"def {wrapper}(", 1)[-1].split("\ndef ", 1)[0]
        check(f"{wrapper} handles a refused verdict",
              "if not moved:" in body and "return" in body,
              "a None verdict would be printed as a move")

    print()
    if FAILS:
        print("ONE MOVE PER LANE: FAILED")
        for f in FAILS:
            print("  - " + f)
        return 1
    print("ONE MOVE PER LANE: CONFIRMED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
