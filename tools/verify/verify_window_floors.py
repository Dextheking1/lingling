"""A committed stream is never cut for thinking: the long windows keep their floor."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lingling import mitm  # noqa: E402

FAILS = []

#: see
STREAM_FLOOR = 600.0
COLD_FLOOR = 10.0
#: first-content deadline
CONTENT_FLOOR = 20.0
#: committed stall
STALL_FLOOR = 60.0


def check(name, ok, detail=""):
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name}" + (f" -- {detail}" if (detail and not ok) else ""))
    if not ok:
        FAILS.append(name)


def main():
    print(f"shipped: cold={mitm._FIRST_BYTE_TIMEOUT}s  "
          f"read={mitm._READ_TIMEOUT}s  idle={mitm._STREAM_IDLE_TIMEOUT}s  "
          f"first content={mitm._FIRST_CONTENT_TIMEOUT}s  "
          f"stall={mitm._STALL_CUT_S}s")

    print("\n=== the two stream windows: a silent peer is never cut ===")
    for name, val in (("pre-commit read", mitm._READ_TIMEOUT),
                      ("post-commit idle", mitm._STREAM_IDLE_TIMEOUT)):
        check(f"the {name} window is at least {STREAM_FLOOR:.0f}s",
              val >= STREAM_FLOOR,
              f"{name}={val}s -- the head read IS the model's time-to-first-"
              f"token, and 20s was measured cutting real xhigh answers at "
              f"0.0 KB; a shrink here is that bug returning")

    print("\n=== the first-content deadline: the only short window ===")
    check(f"it is at least {CONTENT_FLOOR:.0f}s, the slow-exit line",
          mitm._FIRST_CONTENT_TIMEOUT >= CONTENT_FLOOR,
          f"_FIRST_CONTENT_TIMEOUT={mitm._FIRST_CONTENT_TIMEOUT}s -- below "
          f"_SLOW_EXIT_S ({mitm._SLOW_EXIT_S}s) it cuts the very first events "
          f"the slow rule tolerates, and every lane gets moved for being "
          f"slow while none is dead")
    check("and far under the idle window, so nothing parks for half an hour",
          mitm._FIRST_CONTENT_TIMEOUT < mitm._STREAM_IDLE_TIMEOUT / 10,
          f"{mitm._FIRST_CONTENT_TIMEOUT}s vs {mitm._STREAM_IDLE_TIMEOUT}s -- "
          f"that is the whole point of it")

    print("\n=== the committed stall cut: what unfreezes a stuck agent ===")
    check(f"it is at least {STALL_FLOOR:.0f}s, over every healthy gap on record",
          mitm._STALL_CUT_S >= STALL_FLOOR,
          f"_STALL_CUT_S={mitm._STALL_CUT_S:.0f}s -- below the longest gap a "
          f"real answer has been seen to pause, this cuts live answers")
    check("and under a third of the idle window, so it actually fires",
          mitm._STALL_CUT_S < mitm._STREAM_IDLE_TIMEOUT / 3,
          f"{mitm._STALL_CUT_S:.0f}s vs {mitm._STREAM_IDLE_TIMEOUT:.0f}s -- "
          f"the idle window is where a dead exit used to sit unnoticed")
    check("and it still sits above the first-content deadline",
          mitm._STALL_CUT_S > mitm._FIRST_CONTENT_TIMEOUT,
          f"{mitm._STALL_CUT_S:.0f}s vs {mitm._FIRST_CONTENT_TIMEOUT:.0f}s")

    print("\n=== the cold-connect budget ===")
    check(f"the cold connect is at least {COLD_FLOOR:.0f}s",
          mitm._FIRST_BYTE_TIMEOUT >= COLD_FLOOR,
          f"_FIRST_BYTE_TIMEOUT={mitm._FIRST_BYTE_TIMEOUT}s -- the warm dial "
          f"alone measures 546ms + 723ms; single seconds would fail circuits "
          f"that succeed today")

    print()
    if FAILS:
        print("WINDOW FLOORS: FAILED")
        for f in FAILS:
            print("  - " + f)
        return 1
    print("WINDOW FLOORS: CONFIRMED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
