"""30 concurrent callers (2026-10-15): every call rode all six lanes."""
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lingling import mitm  # noqa: E402
from lingling.lanes import Lane  # noqa: E402
from lingling.relay import Relay  # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name}" + (f" -- {detail}" if (detail and not ok) else ""))
    if not ok:
        FAILS.append(name)


class FakeProc:
    def poll(self):
        return None


class Sticky:
    """A favorite that always nominates the lane we name."""

    def __init__(self, lane):
        self.lane = lane

    def next_lane(self, tried):
        return None if self.lane.index in tried else self.lane


class FakeTor:
    def __init__(self, n=6, benched=(), exits=None, fps=None):
        self.lanes = [
            Lane(index=i, socks_port=52000 + i, control_port=52300 + i,
                 exit_country="xx", data_dir=Path("."),
                 process=FakeProc(), healthy=True, wanted=True)
            for i in range(1, n + 1)
        ]
        for i, ip in (exits or {}).items():
            self.lanes[i - 1].exit_ip = ip
        for i, fp in (fps or {}).items():
            self.lanes[i - 1].exit_fingerprint = fp
        for i in benched:
            self.lanes[i - 1].limited_until = time.time() + 600.0
        self.sticky = None

    def healthy_lanes(self):
        return [l for l in self.lanes if l.healthy and not l.healing]

    def score_of(self, country):
        return 0


def race(tor, tried=None):
    return mitm._race_lanes(Relay(tor), set(tried or ()))


def main():
    print("=== floors: the shipped shape ===")
    #: Racing
    check("the shipped race is not narrowed", mitm._RACE_WIDTH == 0,
          f"_RACE_WIDTH={mitm._RACE_WIDTH} -- 0 means every live lane")

    print("\n=== A. the whole live pool, favorite first ===")
    tor = FakeTor(6)
    tor.sticky = Sticky(tor.lanes[1])
    lanes = race(tor)
    picked = [l.index for l in lanes]
    print(f"  raced={picked}")
    check("every live lane is raced", len(lanes) == len(tor.lanes),
          f"raced {len(lanes)} of {len(tor.lanes)} lanes")
    check("the favorite leads", picked and picked[0] == 2, str(picked))
    check("no lane is raced twice",
          len(picked) == len(set(picked)), str(picked))

    print("\n=== B. a spent exit loses its seat ===")
    tor = FakeTor(6, benched=(1, 3, 4, 5))
    tor.sticky = Sticky(tor.lanes[0])  # favorite
    lanes = race(tor)
    picked = [l.index for l in lanes]
    print(f"  benched=1,3,4,5  favorite=1  raced={picked}")
    check("no benched lane is raced while a live one remains",
          all(not l.limited_until > time.time() for l in lanes), str(picked))
    check("the benched favorite does not lead", picked[:1] != [1], str(picked))
    check("the call goes to the live lanes instead",
          sorted(picked) == [2, 6], f"{picked} -- live lanes are 2 and 6")

    print("\n=== C. a burnt pool still races its last resort ===")
    tor = FakeTor(3, benched=(1, 2, 3))
    lanes = race(tor)
    picked = [l.index for l in lanes]
    print(f"  benched=1,2,3  raced={picked}")
    check("the call is still attempted, not dropped",
          len(lanes) == 1, str(picked))
    check("and the refusal is what comes back", picked == [1], str(picked))

    print("\n=== D. a round never re-races a lane it already tried ===")
    tor = FakeTor(6)
    lanes = race(tor, tried={l.index for l in tor.lanes[:4]})
    picked = [l.index for l in lanes]
    print(f"  tried=1,2,3,4  raced={picked}")
    check("a lane that already answered is left out",
          all(i not in (1, 2, 3, 4) for i in picked), str(picked))
    check("the retry still has lanes to use",
          sorted(picked) == [5, 6], str(picked))

    print("\n=== E. distinct exits matter once a wave is narrowed ===")
    # shipped shape
    tor = FakeTor(4, exits={1: "10.0.0.1", 2: "10.0.0.1",
                            3: "10.0.0.2", 4: "10.0.0.3"})
    tor.sticky = Sticky(tor.lanes[0])  # lane 1
    picked = [l.index for l in race(tor)]
    print(f"  shipped: lanes 1&2 share 10.0.0.1  raced={picked}")
    check("racing everything still includes the shared exit",
          2 in picked and len(picked) == 4, str(picked))

    # Narrowed,
    was = mitm._RACE_WIDTH
    try:
        mitm._RACE_WIDTH = 2
        tor = FakeTor(4, exits={1: "10.0.0.1", 2: "10.0.0.1",
                                3: "10.0.0.2", 4: "10.0.0.3"})
        tor.sticky = Sticky(tor.lanes[0])
        picked = [l.index for l in race(tor)]
        print(f"  narrowed: lanes 1&2 share 10.0.0.1  raced={picked}")
        check("the favourite keeps its seat", picked[:1] == [1], str(picked))
        check("the lane sharing its exit is left out", 2 not in picked,
              str(picked))
        check("and a lane on another exit takes the seat", 3 in picked,
              str(picked))

        tor = FakeTor(3, exits={1: "10.0.0.9", 2: "10.0.0.9", 3: "10.0.0.9"})
        tor.sticky = Sticky(tor.lanes[0])
        picked = [l.index for l in race(tor)]
        print(f"  narrowed, whole pool on one exit  raced={picked}")
        check("one exit is still raced twice, not once -- a second circuit",
              len(picked) >= 2,
              f"raced={picked} -- the wave shrank to one lane")

        tor = FakeTor(3)  # no exit
        tor.sticky = Sticky(tor.lanes[0])
        picked = [l.index for l in race(tor)]
        print(f"  narrowed, exits unknown  raced={picked}")
        check("two unknown exits are never treated as one",
              len(picked) >= 2,
              f"raced={picked} -- a lane was dropped on a guess")

        tor = FakeTor(3, fps={1: "A" * 40, 2: "A" * 40, 3: "B" * 40})
        tor.sticky = Sticky(tor.lanes[0])
        picked = [l.index for l in race(tor)]
        print(f"  narrowed, no ip but a known fingerprint  raced={picked}")
        check("a pinned relay still separates two lanes with no ip",
              2 not in picked and 3 in picked, str(picked))
    finally:
        mitm._RACE_WIDTH = was

    print("\n=== F. the knob narrows the wave when a pool needs stretching ===")
    #: Not
    was = mitm._RACE_WIDTH
    try:
        mitm._RACE_WIDTH = 2
        tor = FakeTor(6)
        tor.sticky = Sticky(tor.lanes[1])
        picked = [l.index for l in race(tor)]
        print(f"  LINGLING_RACE_WIDTH=2  raced={picked}")
        check("a narrowed wave holds to its width", len(picked) == 2,
              str(picked))
        check("and still leads with the favorite", picked[:1] == [2],
              str(picked))
        mitm._RACE_WIDTH = 1
        tor = FakeTor(4)
        picked = [l.index for l in race(tor)]
        print(f"  LINGLING_RACE_WIDTH=1  raced={picked}")
        check("one lane is still a valid wave", len(picked) == 1, str(picked))
    finally:
        mitm._RACE_WIDTH = was
    check("and the shipped shape is restored", mitm._RACE_WIDTH == was,
          f"_RACE_WIDTH={mitm._RACE_WIDTH}")

    print()
    if FAILS:
        print("RACE SHAPE: FAILED")
        for f in FAILS:
            print("  - " + f)
        return 1
    print("RACE SHAPE: CONFIRMED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
