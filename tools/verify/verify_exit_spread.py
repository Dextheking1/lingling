"""Exits are picked by what the day has spent, not by who is biggest.

The free tier counts its day against the exit IP, and an exit IP is shared
ground: the biggest relays in the biggest countries are the ones everyone else
is leaning on too.  So a lane that always takes the head of the pool walks into
a wall somebody else paid for.  These are the ledgers and the choices that keep
a session out of that corner.
"""
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lingling import bench, exits, health  # noqa: E402
from lingling.cli import DATA_DIR, load_countries  # noqa: E402
from lingling.lanes import Lane, TorManager  # noqa: E402
from lingling.mitm import _Copy, _Race, _tally  # noqa: E402

FAILS = []

#: scratch root
SCRATCH = Path(tempfile.mkdtemp(prefix="lingling-spread-"))


def check(name, ok, detail=""):
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name}" + (f" -- {detail}" if (detail and not ok) else ""))
    if not ok:
        FAILS.append(name)


def relay(fp, ip, bw=100):
    """One relay: the pool only ever reads these three fields."""
    return exits.Exit(fp, ip, "relay", bw)


def draw(pool, country, limited=None, used=None, verified=None, spent=None,
         avoid=(), avoid_ip=(), cap=bench.EXIT_DAY_CAP):
    """``exits.claim`` with the day's ledger; None when it has no such shape."""
    try:
        return exits.claim(pool, country, list(avoid), limited or {},
                           used or {}, time.time(), verified, spent,
                           list(avoid_ip), cap)
    except TypeError:
        return None


def manager(countries=("aa", "bb"), lanes=2):
    """A real manager on a scratch root, wired to a pool we hand it."""
    root = Path(tempfile.mkdtemp(prefix="lingling-spread-"))
    mgr = TorManager(root, count=lanes, exit_countries=list(countries),
                     socks_base=54001, control_base=54401, log=lambda *a: None)
    mgr.lanes = [
        Lane(index=i + 1, socks_port=54001 + i * 2, control_port=54401 + i * 2,
             exit_country="", data_dir=root, exit_fingerprint="")
        for i in range(lanes)]
    mgr._load_exits = lambda: True
    return mgr


def lane_at(root, fp="", country="de"):
    return Lane(index=1, socks_port=52001, control_port=52301,
                exit_country=country, data_dir=root, exit_fingerprint=fp)


print("The knobs under test:")
print(f"  EXIT_DAY_CAP   = {bench.EXIT_DAY_CAP} requests, per exit, per day")
print(f"  EXIT_SOFT_CAP  = {bench.EXIT_SOFT_CAP} requests before a lane moves on")
print(f"  sample drawn from a country pool = {exits.EXIT_SAMPLE_K}")

print("\n=== A. the day's spend is written down, per exit ===")
root = SCRATCH / "ledger"
root.mkdir(parents=True, exist_ok=True)
mgr = TorManager(root, count=1, exit_countries=["de"], log=lambda *a: None)
fp = "A" * 40
check("nothing spent on an exit we never used", mgr.spent_of(fp) == 0,
      str(mgr.spent_of(fp)))
for _ in range(3):
    mgr.note_spend(fp)
check("three requests are three", mgr.spent_of(fp) == 3, str(mgr.spent_of(fp)))
check("an empty fingerprint is not a ledger entry",
      mgr.note_spend("") is None and "" not in mgr._spent, str(list(mgr._spent)))
check("the ledger reaches the disk",
      (root / bench.SPENT_PATH).is_file(), "nothing was written")
again = TorManager(root, count=1, exit_countries=["de"], log=lambda *a: None)
check("a restart remembers the day", again.spent_of(fp) == 3,
      str(again.spent_of(fp)))

#: yesterday's ledger belongs to yesterday
(root / bench.SPENT_PATH).write_text(
    '{"day": %d, "spent": {"%s": 175}}' % (bench.day_of() - 1, "B" * 40),
    encoding="utf-8")
rolled = TorManager(root, count=1, exit_countries=["de"], log=lambda *a: None)
check("another day's spend is dropped on the way in",
      rolled.spent_of("B" * 40) == 0 and rolled._spent == {},
      str(rolled._spent))
check("the two caps sit where they should",
      0 < bench.EXIT_SOFT_CAP < bench.EXIT_DAY_CAP,
      f"soft={bench.EXIT_SOFT_CAP} day={bench.EXIT_DAY_CAP}")

class TallyTor:
    """The ledgers one tally writes to, and nothing else."""

    def __init__(self, spend=True):
        self.scored, self.stamped, self.spent = [], [], []
        if spend:
            self.note_spend = self.spent.append

    def note_result(self, country, status):
        self.scored.append((country, status))

    def note_verified(self, fingerprint):
        self.stamped.append(fingerprint)


class TallyRelay:
    """The one thing a tally reads off a relay: its tor."""

    def __init__(self, tor):
        self.tor = tor


def tallied(status, tor, ip="203.0.113.7"):
    """One verdict through the real tally, handing back the ledgers it fed."""
    lane = lane_at(SCRATCH / "tally", "T" * 40)
    lane.exit_ip = ip
    copy = _Copy(lane)
    race = _Race([copy])
    race.claim(copy)
    _tally(race, [(copy, ("", status, b"body", False))], TallyRelay(tor))
    return tor


print("\n=== A2. the ledger is fed by a call that landed ===")
tor = tallied(200, TallyTor())
check("a 200 through an exit is counted against the exit's address",
      tor.spent == ["203.0.113.7"], str(tor.spent))
check("and the score and the stamp are untouched by it",
      tor.scored == [("de", 200)] and tor.stamped == ["T" * 40],
      f"{tor.scored} {tor.stamped}")
check("a lane with no address yet is counted against its relay",
      tallied(200, TallyTor(), ip="").spent == ["T" * 40],
      "a lane that has not been probed keyed on nothing")
check("a refusal counts too: that request landed as well",
      tallied(429, TallyTor()).spent == ["203.0.113.7"],
      "a 429 went uncounted")
raised = None
try:
    tallied(200, TallyTor(spend=False))
except Exception as exc:  # noqa: BLE001
    raised = exc
check("a tor that keeps no ledger is not a crash", raised is None, repr(raised))

print("\n=== B. the least-spent exit wins, not the biggest relay ===")
now = time.time()
big = relay("C" * 40, "10.0.0.1", 1000)
small = relay("D" * 40, "10.0.0.2", 10)
pool = {"DE": [big, small]}

fresh = draw(pool, "de", spent={})
check("with nothing spent, bandwidth still decides in a narrow pool",
      fresh is not None and fresh.fingerprint == big.fingerprint,
      str(fresh))
worn = draw(pool, "de", spent={big.fingerprint: 150})
check("an exit the day has leaned on is passed over",
      worn is not None and worn.fingerprint == small.fingerprint,
      f"picked {worn.nickname if worn else 'nothing'}")
over = draw(pool, "de", spent={small.fingerprint: bench.EXIT_DAY_CAP,
                               big.fingerprint: bench.EXIT_DAY_CAP - 1})
check("an exit that has spent its day is not handed out at all",
      over is not None and over.fingerprint == big.fingerprint,
      f"picked {over.nickname if over else 'nothing'}")
spent_out = draw(pool, "de", spent={big.fingerprint: bench.EXIT_DAY_CAP,
                                    small.fingerprint: bench.EXIT_DAY_CAP})
check("a country spent all through hands out nothing, so the hunt goes on",
      spent_out is None, f"picked {spent_out.nickname if spent_out else '-'}")

print("\n=== B2. the wall belongs to the address, not the relay ===")
twin = relay("T" * 40, big.ip, 5)
check("a relay behind an address we have carried to the cap is not handed out",
      draw({"DE": [big, twin]}, "de",
           spent={big.ip: bench.EXIT_DAY_CAP}) is None,
      "a second relay on a spent address was offered")
same_ip = {"DE": [relay("U" * 40, "10.9.9.9", 100),
                   relay("V" * 40, "10.9.9.9", 50)]}
check("a wall met behind an address writes off every relay on it",
      draw(same_ip, "de", limited={"10.9.9.9": now + 600}) is None,
      "a relay on a refused address was offered")
picked = draw(same_ip, "de", limited={"U" * 40: now + 600})
check("and a wall met behind one relay writes off that relay",
      picked is not None and picked.fingerprint == "V" * 40,
      f"picked {picked.fingerprint[:8] if picked else 'nothing'}")

print("\n=== C. a wide country is drawn from, not tapped at its head ===")
wide = {"DE": [relay(f"{i:040d}", f"10.0.{i // 250}.{i % 250}", 1000 - i)
               for i in range(300)]}
biggest = wide["DE"][0].fingerprint
draws = [draw(wide, "de", spent={}) for _ in range(200)]
hits = sum(1 for d in draws if d is not None and d.fingerprint == biggest)
seen = {d.fingerprint for d in draws if d is not None}
print(f"  over 200 draws of a 300-exit country: the biggest relay came back "
      f"{hits} time(s), and {len(seen)} distinct exits were used")
check("every draw still names an exit", all(d is not None for d in draws),
      "a draw came back empty")
check("the single biggest relay is no longer the answer to everything",
      hits < 40, f"{hits}/200 draws landed on it (200/200 before)")
check("200 draws cover a good part of the country", len(seen) > 20,
      f"{len(seen)} distinct exits out of 300")

print("\n=== D. a session spreads over the country instead of sitting on one exit ===")
session = {"DE": [relay(f"{i:040d}", f"10.1.{i // 250}.{i % 250}", 1000 - i)
                  for i in range(300)]}
spent, used = {}, {}
requests = 500
for n in range(requests):
    pick = draw(session, "de", used=used, spent=spent)
    if pick is None:
        print(f"  [note] draw {n} came back empty -- stopping the session here")
        break
    spent[pick.fingerprint] = spent.get(pick.fingerprint, 0) + 1
    used[pick.fingerprint] = time.time() + bench.USED_TTL_S
carried = sum(spent.values())
check("the session ran to the end", carried == requests,
      f"{carried} of {requests} requests were placed")
check("no exit carried more than its share of the session",
      max(spent.values(), default=0) <= 4, f"worst exit carried {max(spent.values(), default=0)}")
check("the session used the whole country, not a corner of it",
      len(spent) >= 250, f"{len(spent)} exits carried those {requests} requests")

print("\n=== E. no two lanes share an exit IP ===")
twin_a = relay("E" * 40, "10.2.0.1", 900)
twin_b = relay("F" * 40, "10.2.0.1", 800)
other = relay("G" * 40, "10.2.0.2", 10)
shared = {"DE": [twin_a, twin_b, other]}
picked = draw(shared, "de", avoid_ip=["10.2.0.1"])
check("a relay behind an address another lane holds is not handed out",
      picked is not None and picked.ip == "10.2.0.2",
      f"picked {picked.ip if picked else 'nothing'}")

mgr = manager(lanes=2)
mgr._by_country = shared
for lane in mgr.lanes:
    lane.exit_country = "de"
mgr._pin(mgr.lanes[0])
mgr._pin(mgr.lanes[1])
check("two lanes on one pool end up on different relays",
      mgr.lanes[0].exit_fingerprint != mgr.lanes[1].exit_fingerprint,
      f"{mgr.lanes[0].exit_fingerprint[:8]} {mgr.lanes[1].exit_fingerprint[:8]}")
check("and never on one address",
      mgr.lanes[0].exit_ip != mgr.lanes[1].exit_ip,
      f"both on {mgr.lanes[0].exit_ip}")

print("\n=== F. rotation ranks a country by what it can still give ===")


def pool_of(spent_to):
    """A country whose exits have each carried ``spent_to`` requests."""
    return {"AA": [relay("H" * 40, "10.3.0.1", 900),
                   relay("I" * 40, "10.3.0.2", 800)],
            "BB": [relay("J" * 40, "10.3.1.1", 700),
                   relay("K" * 40, "10.3.1.2", 600)]}


mgr = manager(countries=("aa", "bb"), lanes=2)
mgr._quiet, mgr._preferred, mgr._fallback, mgr._expand = ["aa", "bb"], [], [], []
mgr._by_country = pool_of(0)
mgr._spent = {"H" * 40: bench.EXIT_DAY_CAP, "I" * 40: bench.EXIT_DAY_CAP}
mgr._score = {"aa": 50, "bb": 0}
pick = mgr.rotate_exit_country(mgr.lanes[0])
check("a spent country loses to a fresh one, whatever it scored today",
      pick == "bb", f"picked {pick} (score said aa)")
mgr = manager(countries=("aa", "bb"), lanes=2)
mgr._quiet, mgr._preferred, mgr._fallback, mgr._expand = ["aa", "bb"], [], [], []
mgr._by_country = pool_of(0)
mgr._spent = {"J" * 40: bench.EXIT_DAY_CAP, "K" * 40: bench.EXIT_DAY_CAP}
#: read before the pin, which takes the picked relay out of the open pool
headroom = (mgr._headroom("aa"), mgr._headroom("bb"))
pick = mgr.rotate_exit_country(mgr.lanes[0])
check("and the same choice flips when the other country is the spent one",
      pick == "aa", f"picked {pick}")
check("the headroom it ranked on is the real count of open exits",
      headroom == (2, 0), f"aa={headroom[0]} bb={headroom[1]}")


class FakeTor:
    """The sweep's whole world: idle lanes, candidates, and a move."""

    def __init__(self, lanes, candidates, spent=None, stuck=()):
        self._lanes = list(lanes)
        self._candidates = list(candidates)
        self.spent = dict(spent or {})
        self.stuck = set(stuck)
        self.moves = []
        self.moved_lanes = []

    def idle_lanes(self):
        return list(self._lanes)

    def sweep_candidates(self, country):
        return list(self._candidates)

    def move_exit(self, lane, candidate):
        self.moved_lanes.append(lane.index)
        self.moves.append(candidate.fingerprint)
        return lane.index not in self.stuck

    def spent_of(self, fingerprint):
        return self.spent.get(fingerprint, 0)


class BareTor(FakeTor):
    """A tor that keeps no ledger: the sweep must behave as it always did."""

    spent_of = None


print("\n=== F2. the hunt widens before it ever settles for a spent exit ===")

def pool_of_countries(*codes):
    """One country each, two exits apiece, nothing spent yet."""
    out = {}
    for n, cc in enumerate(codes):
        out[cc.upper()] = [relay(f"{n}{i}".ljust(40, 'X'), f"10.{n}.0.{i}",
                                 900 - i)
                           for i in range(2)]
    return out


mgr = manager(countries=("aa", "bb"), lanes=2)
mgr._quiet, mgr._preferred, mgr._fallback, mgr._expand = ["aa", "bb"], [], [], []
mgr._by_country = pool_of_countries("aa", "bb", "zz")
mgr._spent = {e.fingerprint: bench.EXIT_DAY_CAP
              for cc in ("AA", "BB") for e in mgr._by_country[cc]}
pick = mgr.rotate_exit_country(mgr.lanes[0])
check("the hunt widens to the consensus once the ladder is spent",
      pick == "zz", f"picked {pick}")
check("and lands on an exit with room left",
      mgr.lanes[0].exit_fingerprint in
      {e.fingerprint for e in mgr._by_country["ZZ"]},
      mgr.lanes[0].exit_fingerprint[:10])

mgr._spent = {e.fingerprint: bench.EXIT_DAY_CAP
              for cc in mgr._by_country for e in mgr._by_country[cc]}
held = mgr.lanes[0].exit_country
check("with nothing left anywhere it refuses to move, rather than guess",
      mgr.rotate_exit_country(mgr.lanes[0]) is None,
      "a spent exit was handed out anyway")
check("and the lane keeps the pin it had",
      mgr.lanes[0].exit_country == held, mgr.lanes[0].exit_country)

print("\n=== G. the sweep leaves a hard-used exit before it walls ===")
target = relay("L" * 40, "10.4.0.9", 500)
worn_lane = lane_at(SCRATCH / "sweep", "M" * 40)
worn_lane.index = 1
spare_lane = lane_at(SCRATCH / "sweep", "L" * 40)
spare_lane.index = 2
events = []
tor = FakeTor([worn_lane, spare_lane], [target],
              spent={"M" * 40: bench.EXIT_SOFT_CAP})
health.ExitSweep(tor, event=events.append).step()
check("the lane on the hard-used exit is the one moved",
      tor.moved_lanes == [1], str(tor.moved_lanes))
check("and the pane says why", any("had carried" in e.get("msg", "")
                                  for e in events), str(events))

tor = FakeTor([lane_at(SCRATCH / "sweep", "M" * 40), spare_lane], [target],
              spent={"M" * 40: bench.EXIT_SOFT_CAP,
                     target.ip: bench.EXIT_SOFT_CAP})
health.ExitSweep(tor, event=events.append).step()
check("a fresher exit that is no fresher is not worth a circuit",
      tor.moves == [], str(tor.moves))

tor = BareTor([lane_at(SCRATCH / "sweep", "M" * 40)], [target])
health.ExitSweep(tor).step()
check("a tor that keeps no ledger still sweeps as it always did",
      tor.moves == ["L" * 40], str(tor.moves))

print("\n=== H. the pool this machine actually has ===")
consensus = exits.find_consensus(DATA_DIR / "lanes")
geoip = DATA_DIR / "geoip"
if consensus and geoip.exists():
    by_country = exits.load_relays(consensus, exits.load_geoip(geoip))
    countries, fallback, preferred = load_countries()
    fresh = {cc: (len(by_country.get(cc.upper(), ())),
                  exits.headroom(by_country, cc, [], {}, {}, time.time(), (),
                                 bench.EXIT_DAY_CAP))
             for cc in dict.fromkeys(countries + fallback + preferred)}
    print("  country   exits   open on a fresh day")
    for cc, (total, free) in fresh.items():
        print(f"  {cc}       {total:6d}   {free:8d}")
    check("a fresh day leaves every configured country wide open",
          all(free == total for total, free in fresh.values()),
          str([(cc, t, f) for cc, (t, f) in fresh.items() if f != t]))
    first = draw(by_country, countries[0])
    check("a real country hands out a real exit",
          first is not None and bool(first.ip), str(first))
    second = draw(by_country, countries[0], avoid=(first.fingerprint,),
                  avoid_ip=(first.ip,))
    check("and a second lane on that country lands on another address",
          second is not None and second.ip != first.ip,
          f"{first.ip} / {second.ip if second else 'nothing'}")
    mgr = manager(countries=("de",), lanes=2)
    mgr._by_country = by_country
    for lane in mgr.lanes:
        lane.exit_country = "de"
    mgr.lanes[0].exit_fingerprint = first.fingerprint
    mgr.lanes[0].exit_ip = first.ip
    candidates = mgr.sweep_candidates("de")
    check("the sweep hands out an unspent exit on a free address",
          bool(candidates) and all(e.ip != first.ip for e in candidates)
          and mgr.spent_of(exits.exit_key(candidates[0])) == 0,
          f"{len(candidates)} candidates")
else:
    print("  [SKIP] no cached consensus on this machine yet")

shutil.rmtree(SCRATCH, ignore_errors=True)

print("\n" + "=" * 52)
if FAILS:
    print(f"EXIT SPREAD: FAILED ({len(FAILS)})")
    for f in FAILS:
        print("  - " + f)
    sys.exit(1)
print("EXIT SPREAD: CONFIRMED")
