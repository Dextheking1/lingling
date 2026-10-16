"""The stall needed two things at once, and one only happens while you work."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOAK = ROOT / "tools" / "soak" / "live_soak.py"

#: run's own
DEFERRED = "streams in flight"
TRACKED = ("lingling", "tools/soak/live_soak.py")

#: Each run
COUNTRY_POOLS = (
    os.environ.get("REPRO_A_COUNTRIES", "nl,de,fr"),
    os.environ.get("REPRO_B_COUNTRIES", "us,se,gb"),
)


def old_build(dest: Path) -> Path:
    """The committed package and soak, from git, as a runnable tree."""
    listing = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", "HEAD", "--", *TRACKED],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    for rel in [r for r in listing.splitlines() if r.strip()]:
        blob = subprocess.run(["git", "show", f"HEAD:{rel}"], cwd=ROOT,
                              capture_output=True, check=True).stdout
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(blob)
    return dest


def run(tree: Path, data: Path, target: int, conc: int, budget: int,
        flags: list, countries: str) -> Path:
    """One soak run in its own data dir; returns that run's proof log"""
    data.mkdir(parents=True, exist_ok=True)
    (data / "countries.txt").write_text(countries + "\n", encoding="utf-8")
    env = dict(os.environ)
    env.update(LINGLING_DATA_DIR=str(data), SOAK_CONCURRENCY=str(conc),
               SOAK_BUDGET_S=str(budget), PYTHONIOENCODING="utf-8",
               PYTHONUNBUFFERED="1")
    log = data.parent / f"{data.name}-stdout.txt"
    print(f"\n=== driving {target} calls, {conc} at a time, on "
          f"{'the committed build' if tree != ROOT else 'the working tree'}"
          f" {' '.join(flags)}  [{countries}] ===", flush=True)
    t0 = time.monotonic()
    with log.open("w", encoding="utf-8") as out:
        subprocess.run([sys.executable, str(tree / "tools/soak/live_soak.py"),
                        str(target), *flags], cwd=str(tree), env=env,
                       stdout=out, stderr=subprocess.STDOUT)
    print(f"    load finished in {time.monotonic() - t0:.0f}s", flush=True)
    return data / "proof.log"


def read(log: Path) -> dict:
    """What one run's pane says it did."""
    recs = []
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                recs.append(json.loads(line))
            except ValueError:
                pass
    starts = [r["t"] for r in recs if r.get("type") == "start"]
    run = [r for r in recs if r.get("t", 0) >= starts[-1]] if starts else recs

    by: dict = {}
    widths: Counter = Counter()
    for r in run:
        if r.get("type") == "call":
            widths[len(r.get("lanes") or [])] += 1
            by.setdefault((r.get("n"), r.get("c")), []).append(r)
        elif r.get("type") == "callend":
            by.setdefault((r.get("n"), r.get("c")), []).append(r)

    rows = [r for v in by.values() for r in v]
    wins = sorted(r["secs"] for r in rows if r.get("type") == "callend"
                  and 200 <= (r.get("status") or 0) < 300 and not r.get("err"))
    events = [r for r in run if r.get("type") == "lane"]
    deferred = [r for r in events if r.get("kind") == "heal"
                and DEFERRED in (r.get("msg") or "")]

    #: move
    moved, pending = [], {}
    for r in events:
        if r.get("kind") in ("limited", "heal", "timeout"):
            pending.setdefault(r.get("lane"), r["t"])
        elif r.get("kind") == "up" and r.get("lane") in pending:
            moved.append(r["t"] - pending.pop(r["lane"]))

    answered = sum(1 for v in by.values()
                   if any(r.get("type") == "callend"
                          and 200 <= (r.get("status") or 0) < 300
                          and not r.get("err") for r in v))
    return dict(
        calls=len(by), answered=answered,
        refusals=sum(1 for r in rows if r.get("type") == "callend"
                     and r.get("status") == 429),
        raced=sum(k * v for k, v in widths.items()) / max(1, sum(widths.values())),
        widths=dict(sorted(widths.items())),
        deferred=len(deferred),
        deferred_lanes=sorted({r.get("lane") for r in deferred}),
        moved=len(moved), move_s=[round(x, 1) for x in sorted(moved)],
        p50=round(wins[len(wins) // 2], 1) if wins else 0.0)


def main() -> int:
    argv = [a for a in sys.argv[1:] if not a.startswith("-")]
    flags = [a for a in sys.argv[1:] if a.startswith("-")]
    target = int(argv[0]) if argv else 60
    conc = int(argv[1]) if len(argv) > 1 else 20
    budget = int(os.environ.get("REPRO_BUDGET_S", "600"))
    if shutil.which("opencode") is None:
        raise SystemExit("opencode is not on PATH -- install it first")

    scratch = Path(tempfile.mkdtemp(prefix="lingling-repro-"))
    print(f"[repro] scratch {scratch}")
    tree = old_build(scratch / "old")
    print(f"[repro] the committed build is at {tree}")

    runs = {}
    runs["committed (unfixed)"] = read(
        run(tree, scratch / "old-data", target, conc, budget, flags,
            COUNTRY_POOLS[0]))
    runs["working tree (fixed)"] = read(
        run(ROOT, scratch / "new-data", target, conc, budget, flags,
            COUNTRY_POOLS[1]))

    print("\n" + "=" * 66)
    print(f"{'':<22}{'committed (unfixed)':>22}{'working tree (fixed)':>22}")
    print("=" * 66)
    a, b = runs["committed (unfixed)"], runs["working tree (fixed)"]
    for label, key, fmt in (
            ("model calls placed", "calls", "{:d}"),
            ("answered", "answered", "{:d}"),
            ("lanes raced per attempt", "raced", "{:.2f}"),
            ("waves per call", "widths", "{}"),
            ("free-tier refusals", "refusals", "{:d}"),
            ("refusals per call", "refusals_per", "{:.2f}"),
            ("moves that DEFERRED", "deferred", "{:d}"),
            ("moves that completed", "moved", "{:d}"),
            ("slowest move (s)", "move_max", "{}"),
            ("winner p50 (s)", "p50", "{:.1f}")):
        for d in (a, b):
            if key == "refusals_per":
                d[key] = d["refusals"] / max(1, d["calls"])
            elif key == "move_max":
                d[key] = round(max(d["move_s"]), 1) if d["move_s"] else 0.0
        print(f"{label:<22}{fmt.format(a[key]):>22}{fmt.format(b[key]):>22}")

    print("\nlane moves that never happened, per run:")
    for name, d in runs.items():
        print(f"  {name:<22} deferred={d['deferred']} on lanes "
              f"{d['deferred_lanes']}   completed={d['move_s']}")

    print("\nverdict")
    print(f"  the unfixed build deferred {a['deferred']} recook(s) behind busy "
          f"lanes; the fixed build deferred {b['deferred']}")
    print(f"  the two runs drew different countries ({COUNTRY_POOLS[0]} vs "
          f"{COUNTRY_POOLS[1]}), so neither waited on exits the other spent")
    print("  comparable across the two runs: the deferrals (the wave rows "
          "agree by construction -- both builds ship the whole-pool race; "
          "only the recook differs)")
    print("  not comparable: refusals and latency -- an exit's allowance stays "
          "spent for hours, so even separate pools differ in how fresh they "
          "started")
    if max(a["deferred"], b["deferred"]):
        print("  REPRODUCED: a recook sat behind a busy lane, which is the "
              "freeze the pane showed")
    else:
        print("  NOT SEEN THIS RUN: no recook had to wait. The freeze needs a "
              "lane to still be streaming when its exit is refused -- drive "
              "more calls, longer prompts (--hard), or more at once")
    print(f"  logs left in {scratch}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
