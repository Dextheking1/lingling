"""Exit relays: pick distinct, country-filtered exits and pin them."""
from __future__ import annotations

import ipaddress
import pathlib
import random
from typing import Any, Dict, List, NamedTuple, Optional, Sequence, Tuple

#: worldwide exits
WORLD_CC = frozenset([
    "us", "de", "nl", "fr", "se", "ch", "at", "ca", "gb", "ro",
    "fi", "pl", "cz", "hu", "bg", "lt", "lv", "ee", "dk", "no",
    "ie", "es", "it", "pt", "gr", "ua", "md", "rs", "hr", "si",
    "sk", "is", "lu", "be", "au", "nz", "jp", "kr", "sg", "hk",
    "tw", "th", "in", "id", "my", "za", "br", "ar", "cl", "mx",
    "il", "ae", "tr", "mt", "cy", "uy", "pe", "co", "ke", "mu",
])


class Exit(NamedTuple):
    fingerprint: str
    ip: str
    nickname: str
    bandwidth: int


def random_countries(n: int,
                     restrict: Optional[Sequence[str]] = None) -> List[str]:
    """``n`` distinct countries drawn at random from anywhere with exits."""
    pool = sorted(set(restrict) & WORLD_CC if restrict else WORLD_CC)
    if not pool:
        pool = sorted(WORLD_CC)
    k = max(1, min(int(n), len(pool)))
    return random.sample(pool, k)


def load_geoip(path: pathlib.Path) -> List[Tuple[int, int, str]]:
    """Tor's GeoIP CSV as sorted ``(start, end, country)`` ranges."""
    rows: List[Tuple[int, int, str]] = []
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.strip().split(",")
            if len(parts) != 3:
                continue
            try:
                rows.append((int(parts[0]), int(parts[1]), parts[2]))
            except ValueError:
                continue
    rows.sort()
    return rows


def country_of(ranges: Sequence[Tuple[int, int, str]], ip: str) -> str:
    """Country for an IPv4 address, or "??" when the database has no answer."""
    try:
        n = int(ipaddress.IPv4Address(ip))
    except ValueError:
        return "??"
    lo, hi = 0, len(ranges) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        start, end, cc = ranges[mid]
        if n < start:
            hi = mid - 1
        elif n > end:
            lo = mid + 1
        else:
            return cc
    return "??"


def load_relays(path: pathlib.Path,
                ranges: Sequence[Tuple[int, int, str]]
                ) -> Dict[str, List[Exit]]:
    """Usable exits from a microdesc consensus, grouped by country."""
    import stem.descriptor

    by_country: Dict[str, List[Exit]] = {}
    with path.open("rb") as f:
        for desc in stem.descriptor.parse_file(
                f, descriptor_type="network-status-microdesc-consensus-3 1.0",
                validate=False):
            flags = set(desc.flags)
            if "Exit" not in flags or "BadExit" in flags:
                continue
            cc = country_of(ranges, desc.address)
            if cc == "??":
                continue
            by_country.setdefault(cc, []).append(
                Exit(desc.fingerprint, desc.address, desc.nickname,
                     int(desc.bandwidth or 0)))
    #: best first
    for exits in by_country.values():
        exits.sort(key=lambda e: -e.bandwidth)
    return by_country


def find_consensus(lanes_dir: pathlib.Path) -> Optional[pathlib.Path]:
    """Any lane's cached microdesc consensus; the first boot has none."""
    if not lanes_dir.exists():
        return None
    for path in sorted(lanes_dir.glob("tor-*/cached-microdesc-consensus")):
        return path
    return None


def limited_until(entry: Any) -> float:
    """A notepad entry's expiry, in either the current or the older shape."""
    if isinstance(entry, dict):
        entry = entry.get("until")
    try:
        return float(entry)
    except (TypeError, ValueError):
        return 0.0


def _open(relays: Sequence[Exit], avoid: Sequence[str],
          limited: Dict[str, Any], now: float) -> List[Exit]:
    """The relays no lane holds, and nothing has written off."""
    held = set(avoid)
    return [e for e in relays
            if e.fingerprint not in held
            and limited_until(limited.get(e.fingerprint, 0.0)) <= now]


def claim(by_country: Dict[str, List[Exit]], country: str,
          avoid: Sequence[str], limited: Dict[str, Any],
          used: Dict[str, float], now: float,
          verified: Optional[Dict[str, float]] = None) -> Optional[Exit]:
    """A relay in ``country`` that no lane holds and nothing has limited."""
    fresh = verified or {}
    pool = _open(by_country.get(country.upper(), ()), avoid, limited, now)
    if not pool:
        return None
    #: verified lead
    pool.sort(key=lambda e: (0 if fresh.get(e.fingerprint, 0.0) > now else 1,
                             used.get(e.fingerprint, 0.0), -e.bandwidth))
    return pool[0]


def sweep_order(by_country: Dict[str, List[Exit]], country: str,
                avoid: Sequence[str], limited: Dict[str, Any],
                used: Dict[str, float], verified: Dict[str, float],
                now: float) -> List[Exit]:
    """Relays in ``country`` worth rotating onto, a verified one first."""
    pool = _open(by_country.get(country.upper(), ()), avoid, limited, now)
    #: verified first
    return sorted(pool,
                  key=lambda e: (0 if verified.get(e.fingerprint, 0.0) > now
                                  else 1,
                                  used.get(e.fingerprint, 0.0),
                                  random.random()))  # spread tiebreak
