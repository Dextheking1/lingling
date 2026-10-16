"""Per-exit accounting for one session: who answered, and who was asked twice.

A session is judged by its exits, not by its calls.  Every attempt carries
`exit`, so this reads one session and says, relay by relay, what the far end
did with it -- and how much of the session was spent on relays already known
to be spent, which is the number that decides whether a pool is being used or
merely walked.

    python tools/soak/exit_ledger.py            # the newest session
    python tools/soak/exit_ledger.py --session 3f9c1a2b04d1
    python tools/soak/exit_ledger.py --top 20
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from lingling import data_dir  # noqa: E402

DEFAULT = data_dir() / "proof.log"


def load(path: pathlib.Path) -> list:
    """Every JSON line in the log, in order."""
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return [e for e in out if "t" in e]


def last_session(evs: list, wanted: str = "") -> tuple:
    """The newest session's start and its end, or the named one."""
    marks = [e for e in evs if e.get("type") == "start"]
    for i in range(len(marks) - 1, -1, -1):
        if wanted and marks[i].get("session") != wanted:
            continue
        end = (marks[i + 1]["t"] if i + 1 < len(marks) else float("inf"))
        return marks[i], end
    return None, 0.0


def verdict(e: dict) -> str:
    """What one attempt did: the status it delivered, or why it never did."""
    if e.get("status") == 200 and e.get("err") == "":
        return "200"
    return str(e.get("err") or e.get("status"))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default=str(DEFAULT))
    ap.add_argument("--session", default="")
    ap.add_argument("--top", type=int, default=12)
    args = ap.parse_args()

    evs = load(pathlib.Path(args.log))
    start, end = last_session(evs, args.session)
    if start is None:
        print("no session in that log")
        return 1
    cur = [e for e in evs if start["t"] <= e.get("t", 0) < end]
    ends = sorted((e for e in cur if e.get("type") == "callend"),
                  key=lambda e: e["t"])

    print(f"session {start.get('session')}  {start.get('lanes')} lanes  "
          f"{start.get('countries')}")
    print(f"  started {time.strftime('%m-%d %H:%M:%S', time.localtime(start['t']))}"
          f"  attempts {len(ends)}")

    per = collections.defaultdict(collections.Counter)
    first_refused = {}
    for e in ends:
        fp = e.get("exit") or "?"
        per[fp][verdict(e)] += 1
        if verdict(e) == "429" and fp not in first_refused:
            first_refused[fp] = e["t"]

    #: an attempt after the first refusal
    late = sum(c["429"] for fp, c in per.items() if fp in first_refused) \
        - len(first_refused)
    print(f"  exits touched {len(per)}  attempts/exits "
          f"{len(ends) / max(1, len(per)):.1f}")
    print(f"  429s after that exit's first refusal: {late} of "
          f"{sum(c['429'] for c in per.values())} "
          f"({100 * late / max(1, sum(c['429'] for c in per.values())):.0f}%)")

    lanes = collections.Counter(e.get("lane") for e in ends)
    print(f"  attempts per lane {dict(sorted(lanes.items()))}")
    kinds = collections.Counter(e.get("kind") for e in cur
                                if e.get("type") == "lane")
    print(f"  lane events {dict(kinds) if kinds else 'none'}")

    print()
    print(f"  {'exit':16}{'att':>5}{'200':>6}{'429':>6}{'other':>7}  kinds")
    print("  " + "-" * 62)
    def weight(item):
        fp, c = item
        return (-c["429"], -sum(c.values()))
    for fp, c in sorted(per.items(), key=weight)[:args.top]:
        other = sum(v for k, v in c.items() if k not in ("200", "429"))
        kinds = ",".join(f"{k}={n}" for k, n in c.most_common()
                         if k not in ("200", "429"))[:24]
        print(f"  {fp[:14]:16}{sum(c.values()):>5}{c['200']:>6}{c['429']:>6}"
              f"{other:>7}  {kinds}")

    clean = [fp for fp, c in per.items() if c["200"] and not c["429"]]
    only429 = [fp for fp, c in per.items() if c["429"] and not c["200"]]
    both = [fp for fp, c in per.items() if c["200"] and c["429"]]
    print()
    print(f"  exits that only answered 200 : {len(clean)}")
    print(f"  exits that only refused       : {len(only429)}")
    print(f"  exits that answered and refused: {len(both)}")
    print("  (a relay named by an attempt that was already in flight when its "
          "lane moved")
    print("   is still the relay that attempt went through, so a repeat here "
          "is a slow")
    print("   verdict landing late, not necessarily a relay asked twice.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
