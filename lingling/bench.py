"""The limit bench: what a limited exit earned, and how long it sits out."""

from __future__ import annotations

import json
import time
from typing import Dict, Optional

from . import bounds, exits

RATE_LIMIT_FALLBACK_S = 1500.0

_LIMIT_CEILING_S = 24 * 3600 + 300

FREE_LIMIT = "free"
RATE_LIMIT = "rate"

LIMITED_PATH = "limited-exits.json"

USED_PATH = "used-exits.json"

SCORE_PATH = "country-scores.json"

VERIFIED_PATH = "verified-exits.json"

USED_TTL_S = bounds.number("LINGLING_FRESH_S", 86400,
                           0.0, 30 * bounds.WINDOW_S)

VERIFIED_TTL_S = bounds.number("LINGLING_VERIFIED_S", 1800,
                               0.0, 30 * bounds.WINDOW_S)


def next_free_reset(now: Optional[float] = None) -> float:
    """The free tier's next 00:00 UTC, as an epoch second."""
    moment = time.time() if now is None else now
    return moment + (86400 - (moment % 86400))


def bench_span(reason: str, retry_after: float = 0.0,
               now: Optional[float] = None) -> float:
    """How long a limit benches an exit: the far end's reset, within the rule."""
    moment = time.time() if now is None else now
    if reason == RATE_LIMIT:
        return (min(retry_after, RATE_LIMIT_FALLBACK_S) if retry_after > 0
                else RATE_LIMIT_FALLBACK_S)
    if retry_after > 0:
        return min(retry_after, _LIMIT_CEILING_S)
    return min(next_free_reset(moment) - moment, _LIMIT_CEILING_S)


class BenchMixin:
    """Held by a lane manager: reads ``self.root``, carries the ledgers.

    ``self._score``, ``self._limited``, ``self._used`` and ``self._verified``
    are filled in by the owner's constructor. Every write is best effort:
    bookkeeping never breaks a run.
    """

    def score_of(self, country: str) -> int:
        """How this country has actually done: 200s minus everything else."""
        return self._score.get(country, 0)

    def note_result(self, country: str, status: int) -> None:
        """Score a country by what the EXIT did: a 200, or a 429."""
        if not country or country == "*":
            return
        if status not in (200, 429):
            return
        self._score[country] = self._score.get(country, 0) + (
            1 if status == 200 else -1)
        self._save_score()

    def note_limited(self, lane, retry_after: float = 0.0,
                     reason: str = RATE_LIMIT,
                     fingerprint: str = "") -> float:
        """Write a limited exit into the notepad: the section, and until when.

        ``fingerprint`` names the exit the verdict is about, which is not always
        the one the lane rides by the time the verdict is read: a copy already
        in flight when its lane was moved keeps reporting on the exit it
        dialled.  The notepad always takes that exit, and the lane's clock is
        only set while it still rides it -- a lane that has been re-pinned is
        never left sitting out a wall that belongs to an exit it no longer
        uses, which is exactly how a whole lane used to sit out a session.
        """
        exit_fp = fingerprint or lane.exit_fingerprint
        if not exit_fp:
            return 0.0
        until = self.note_exit(exit_fp, reason, retry_after)
        if exit_fp == lane.exit_fingerprint:
            lane.limited_until = until
            lane.limit_reason = reason
        return until

    def note_exit(self, fingerprint: str, reason: str = RATE_LIMIT,
                  retry_after: float = 0.0) -> float:
        """Bench one fingerprint, and take back any 200 it earned."""
        if not fingerprint:
            return 0.0
        now = time.time()
        until = now + bench_span(reason, retry_after, now)
        self._limited[fingerprint] = {"until": until, "reason": reason}
        self._verified.pop(fingerprint, None)
        self._save_stamps(VERIFIED_PATH, self._verified)
        self._save_limited()
        return until

    def note_verified(self, fingerprint: str) -> None:
        """Remember an exit that answered 200, so a race can lead with it."""
        if not fingerprint:
            return
        self._verified[fingerprint] = time.time() + VERIFIED_TTL_S
        self._save_stamps(VERIFIED_PATH, self._verified)

    def _save_score(self) -> None:
        """Best effort: a restart should not forget which countries worked."""
        self._write_json(SCORE_PATH, self._score)

    def _load_score(self) -> Dict[str, int]:
        """Integer running totals, so a restart keeps the ranking."""
        raw = self._read_json(SCORE_PATH)
        if not isinstance(raw, dict):
            return {}
        out: Dict[str, int] = {}
        for cc, val in raw.items():
            try:
                out[str(cc)] = int(val)
            except (TypeError, ValueError):
                continue
        return out

    def _load_limited(self) -> Dict[str, Dict]:
        """The notepad from disk: ``{fingerprint: {until, reason}}``, fresh only."""
        raw = self._read_json(LIMITED_PATH)
        if not isinstance(raw, dict):
            return {}
        now = time.time()
        fresh: Dict[str, Dict] = {}
        for fingerprint, entry in raw.items():
            if isinstance(entry, dict):
                until = entry.get("until")
                reason = str(entry.get("reason") or "")
            else:
                until, reason = entry, ""
            try:
                until = float(until)
            except (TypeError, ValueError):
                continue
            if until > now:
                fresh[str(fingerprint)] = {"until": until, "reason": reason}
        return fresh

    def _load_stamps(self, name: str) -> Dict[str, float]:
        """``{fingerprint: valid_until}`` from disk, dropping expired entries."""
        raw = self._read_json(name)
        if not isinstance(raw, dict):
            return {}
        now = time.time()
        fresh: Dict[str, float] = {}
        for fp, until in raw.items():
            try:
                until = float(until)
            except (TypeError, ValueError):
                continue
            if until > now:
                fresh[str(fp)] = until
        return fresh

    def _read_json(self, name: str):
        """What ``name`` holds, or None when it is missing, unreadable or junk."""
        try:
            raw = (self.root / name).read_text(encoding="utf-8")
        except OSError:
            return None
        try:
            return json.loads(raw)
        except ValueError:
            return None

    def _write_json(self, name: str, payload) -> None:
        """Best effort: never let bookkeeping break a run."""
        try:
            self.root.mkdir(parents=True, exist_ok=True)
            (self.root / name).write_text(
                json.dumps(payload), encoding="utf-8")
        except OSError:
            pass

    def _save_stamps(self, name: str, stamps: Dict[str, float]) -> None:
        """Best effort: persist ``{fingerprint: valid_until}``."""
        self._write_json(name, stamps)

    def _save_limited(self) -> None:
        """Best effort: persist the notepad, dropping what has expired."""
        now = time.time()
        self._limited = {fp: rec for fp, rec in self._limited.items()
                         if exits.limited_until(rec) > now}
        self._write_json(LIMITED_PATH, self._limited)
