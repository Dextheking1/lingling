"""Numbers that cross in from outside, held inside a range we can survive.

Every knob here is meant to be tuned by hand, and a bad one used to mean a
traceback at import or a value that hangs a stream forever. One reader, one
range, and a note the CLI can print, so a clamped value is never silent.
"""

from __future__ import annotations

import os
from typing import List

TICK_S = 0.05

WINDOW_S = 86400.0

notes: List[str] = []


def number(name: str, default: float, low: float, high: float) -> float:
    """``name`` from the environment as a number, held inside ``low``..``high``."""
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return float(default)
    try:
        value = float(raw)
    except ValueError:
        return _note(name, raw, default, "not a number")
    if value != value or value in (float("inf"), float("-inf")):
        return _note(name, raw, default, "not a number")
    if value < low:
        return _note(name, raw, low, f"below {low:g}")
    if value > high:
        return _note(name, raw, high, f"above {high:g}")
    return value


def count(name: str, default: int, low: int, high: int) -> int:
    """The same, for a whole number of things: lanes, slots, copies."""
    return int(number(name, default, low, high))


def _note(name: str, raw: str, used: float, why: str) -> float:
    """Say what was wrong and what we used instead, once per name."""
    line = f"{name}={raw} is {why} -- using {used:g}"
    if line not in notes:
        notes.append(line)
    return float(used)
