"""Every number that crosses in from outside is held inside a safe range."""
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lingling import bounds  # noqa: E402

FAILS = []


def check(name, ok, detail="") -> None:
    """Detail is the failure reason, so only show it when it failed."""
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name}" + (f" -- {detail}" if detail and not ok else ""))
    if not ok:
        FAILS.append(name)


def probe(env: dict, code: str) -> str:
    """Run code in a fresh interpreter: the knobs are read at import time."""
    fresh = {k: v for k, v in os.environ.items() if not k.startswith("LINGLING_")}
    fresh.update(env)
    res = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), env=fresh,
                         capture_output=True, text=True, timeout=90)
    return (res.stdout + res.stderr).strip()


def knob(env: dict, expr: str) -> str:
    return probe(env, f"import lingling.mitm as m; print({expr})").splitlines()[-1]


def main() -> int:
    print("\n=== a window inside its range is left alone ===")
    check("a working timeout passes through",
          knob({"LINGLING_SEND_S": "45"}, "m._SEND_TIMEOUT") == "45.0",
          knob({"LINGLING_SEND_S": "45"}, "m._SEND_TIMEOUT"))
    check("and the tick floor does not bite a short window",
          knob({"LINGLING_STALL_CUT_S": "2"}, "m._STALL_CUT_S") == "2.0",
          knob({"LINGLING_STALL_CUT_S": "2"}, "m._STALL_CUT_S"))

    print("\n=== above the ceiling: clamp, and say so ===")
    out = knob({"LINGLING_SEND_S": "999999999"}, "m._SEND_TIMEOUT")
    check("a timeout over a day is held at a day", out == "86400.0", out)
    check("a count over its ceiling is held",
          knob({"LINGLING_SOCKS_SLOTS": "1000"}, "m._RACE_WIDTH") in ("5", "5.0"),
          "the wrong knob moved")
    both = probe({"LINGLING_SEND_S": "999999999"},
                 "import lingling.mitm, lingling.bounds as b; print(b.notes)")
    check("and the note names the knob, the value and the one used",
          "LINGLING_SEND_S=999999999" in both and "86400" in both, both)

    print("\n=== below the floor: clamp, and say so ===")
    out = knob({"LINGLING_FIRST_BYTE_S": "0.001"}, "m._FIRST_BYTE_TIMEOUT")
    check("a window shorter than a tick is raised", out == "0.05", out)
    out = probe({"LINGLING_SOCKS_SLOTS": "-3"},
                "import lingling.netutil as n; print(n.SOCKS_SLOTS)")
    check("a count below one is raised", out.splitlines()[-1] == "1", out)

    print("\n=== junk is not a crash ===")
    for raw in ("abc", "", "??", "1e999x"):
        out = knob({"LINGLING_SEND_S": raw}, "m._SEND_TIMEOUT")
        check(f"a timeout of {raw!r} falls back to the shipped default",
              out == "120.0", out)
    for raw in ("nan", "inf", "-inf"):
        out = knob({"LINGLING_SEND_S": raw}, "m._SEND_TIMEOUT")
        check(f"a timeout of {raw!r} is refused",
              out in ("120.0", "86400.0"), out)

    print("\n=== a knob whose range allows a negative keeps its sign ===")
    out = probe({"LINGLING_LOSING_SCORE": "-500"},
                "import lingling.relay as r; print(r._LOSING)")
    check("a losing-country score of -500 survives", out.splitlines()[-1] == "-500",
          out)
    out = probe({"LINGLING_LOSING_SCORE": "-999999"},
                "import lingling.relay as r; print(r._LOSING)")
    check("and one past the floor is held", out.splitlines()[-1] == "-1000", out)

    print("\n=== nothing reads a number from the environment behind its back ===")
    plain = []
    for p in sorted((ROOT / "lingling").glob("*.py")):
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"(int|float)\(\s*os\.environ", line):
                plain.append(f"{p.name}:{i}")
    check("every numeric knob goes through bounds", not plain, "; ".join(plain))

    print("\n=== the CLI says what it clamped ===")
    out = probe({"LINGLING_TOR_COUNT": "0"},
                "from lingling import cli; print(cli._parse_args([])['lanes'])")
    check("a lane count of 0 is raised to 1", out.splitlines()[-1] == "1", out)
    out = probe({}, "from lingling import cli; print(cli._lane_count('99999'))")
    check("--lanes 99999 is held at the ceiling",
          out.splitlines()[-1] == "64", out)
    check("and it says the number is too big",
          "above 64" in out and "99999" in out, out)
    #: the fallback is the shipped default, whichever number that is today
    out = probe({}, "from lingling import cli; print(cli._lane_count('abc'));"
                    " print(cli.DEFAULT_LANES)")
    lines = out.splitlines()
    check("--lanes abc is refused, not ignored",
          len(lines) >= 2 and lines[-1] == lines[-2] and "not a number" in out,
          out)
    out = probe({}, "from lingling import cli; print(cli._lane_count('3'))")
    check("--lanes 3 is taken as asked", out.splitlines()[-1] == "3", out)

    print("\n=== and the notice reaches the console once ===")
    out = probe({}, "import lingling.bounds as b; b.notes.append('X=1 is above 0');"
                    " from lingling import cli; cli._report_bounds()")
    check("_report_bounds prints every note", "lingling: X=1 is above 0" in out, out)
    check("bounds is importable on its own", bounds.WINDOW_S == 86400.0,
          str(bounds.WINDOW_S))

    print()
    if FAILS:
        print("BOUNDS: FAILED")
        for f in FAILS:
            print("  - " + f)
        return 1
    print("BOUNDS: CONFIRMED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
