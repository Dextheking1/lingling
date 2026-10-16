"""Idle lanes rotate onto fresh exits, and a real 200 is what counts as good."""
import ast
import json
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
SCRATCH = Path(tempfile.mkdtemp(prefix="lingling-sweep-"))


def check(name, ok, detail=""):
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name}" + (f" -- {detail}" if (detail and not ok) else ""))
    if not ok:
        FAILS.append(name)


def relay(fp, ip, bw=100):
    """One relay: the pool only ever reads these three fields."""
    return exits.Exit(fp, ip, "relay", bw)


def manager(root):
    """A real manager on a scratch root: the ledgers are the thing under test."""
    root.mkdir(parents=True, exist_ok=True)
    return TorManager(root, count=1, exit_countries=["de"], log=lambda *a: None)


def lane_at(root, fp="", country="de"):
    return Lane(index=1, socks_port=52001, control_port=52301,
                exit_country=country, data_dir=root, exit_fingerprint=fp)


print("\n=== A. a 200 on an exit is remembered, with an expiry ===")
root = SCRATCH / "registry"
mgr = manager(root)
fp = "A" * 40
mgr.note_verified(fp)
check("the exit is stamped", mgr._verified.get(fp, 0) > time.time(),
      str(mgr._verified.get(fp)))
saved = json.loads((root / bench.VERIFIED_PATH).read_text(encoding="utf-8"))
check("and the stamp reaches the disk", fp in saved, str(list(saved))[:60])

#: shipped window
old_ttl = bench.VERIFIED_TTL_S
bench.VERIFIED_TTL_S = 0.0
stale = "B" * 40
mgr.note_verified(stale)
bench.VERIFIED_TTL_S = old_ttl
check("a stamp past its window is not fresh",
      mgr._verified.get(stale, 0) <= time.time(), "a zero window still stamped")

(root / bench.VERIFIED_PATH).write_text(json.dumps({
    stale: time.time() - 10, fp: time.time() + 600}), encoding="utf-8")
reloaded = manager(root)
check("an expired stamp is dropped on the way in",
      stale not in reloaded._verified and fp in reloaded._verified,
      str(list(reloaded._verified))[:60])

print("\n=== B. an exit the far end spent loses its stamp ===")
mgr = manager(SCRATCH / "spent")
fp = "C" * 40
mgr.note_verified(fp)
mgr.note_exit(fp)
check("the exit is benched", mgr._limited[fp]["until"] > time.time(),
      str(mgr._limited.get(fp)))
check("and its 200 is taken back", fp not in mgr._verified,
      str(list(mgr._verified)))
spent_lane = lane_at(SCRATCH / "spent", fp)
until = mgr.note_limited(spent_lane, 0.0, bench.FREE_LIMIT)
check("note_limited still sets the lane's clock",
      spent_lane.limited_until == until > time.time(),
      f"{spent_lane.limited_until} vs {until}")
check("and still writes the section it was hit by",
      mgr._limited[fp]["reason"] == bench.FREE_LIMIT, str(mgr._limited[fp]))

print("\n=== C. the sweep rotates within one country ===")
now = time.time()
de = {"DE": [relay("D" * 40, "1.1.1.1", 900), relay("E" * 40, "2.2.2.2", 500)]}
order = exits.sweep_order(de, "de", [], {}, {}, {}, now)
check("both relays are candidates",
      {e.fingerprint for e in order} == {"D" * 40, "E" * 40},
      str([e.fingerprint[:6] for e in order]))
check("a benched relay is not handed out",
      [e.fingerprint for e in exits.sweep_order(
          de, "de", [], {"D" * 40: now + 600}, {}, {}, now)] == ["E" * 40],
      "a spent relay came back")
check("a relay another lane holds is not handed out",
      [e.fingerprint for e in exits.sweep_order(
          de, "de", ["D" * 40], {}, {}, {}, now)] == ["E" * 40],
      "a held relay came back")
check("a verified relay leads the candidates",
      [e.fingerprint for e in exits.sweep_order(
          de, "de", [], {}, {}, {"E" * 40: now + 600}, now)]
      == ["E" * 40, "D" * 40],
      "a verified relay was not preferred")
check("a relay we have been through comes last",
      [e.fingerprint for e in exits.sweep_order(
          de, "de", [], {}, {"D" * 40: now + 600}, {}, now)]
      == ["E" * 40, "D" * 40], "a used relay led the rotation")
check("another country is not rotated onto",
      exits.sweep_order(de, "se", [], {}, {}, {}, now) == [],
      "the sweep left the lane's country")

print("\n=== D. a verified exit leads the next pin ===")
pool = {"DE": [relay("F" * 40, "3.3.3.3", 1000), relay("G" * 40, "4.4.4.4", 10)]}
plain = exits.claim(pool, "de", [], {}, {}, now)
check("bandwidth decides when nothing is verified",
      plain.fingerprint == "F" * 40, str(plain))
lead = exits.claim(pool, "de", [], {}, {}, now, {"G" * 40: now + 600})
check("a verified exit leads anyway", lead.fingerprint == "G" * 40, str(lead))
benched = exits.claim(pool, "de", [], {"G" * 40: now + 600}, {}, now,
                      {"G" * 40: now + 600})
check("a benched exit is never handed out, verified or not",
      benched.fingerprint == "F" * 40, str(benched))

print("\n=== E. a lane moves to one relay without a boot ===")


class FakeCtl:
    """A control connection that only remembers what it was told."""

    def __init__(self):
        self.calls = []
        self.closed = False

    def set_conf(self, key, value):
        self.calls.append(("conf", key, value))

    def signal(self, sig):
        self.calls.append(("signal", str(sig)))

    def close(self):
        self.closed = True


move_root = SCRATCH / "move"
#: geoip pins
(move_root / "tools" / "data").mkdir(parents=True, exist_ok=True)
(move_root / "tools" / "data" / "geoip").write_text("", encoding="utf-8")
mgr = manager(move_root)
lane = mgr.lanes[0]
ctl = FakeCtl()
mgr._control = lambda l: ctl
target = relay("H" * 40, "5.5.5.5", 700)
check("the move is accepted", mgr.move_exit(lane, target) is True,
      "move_exit refused")
check("the exit is pinned by fingerprint",
      ("conf", "ExitNodes", "$" + "H" * 40) in ctl.calls, str(ctl.calls))
check("and strictly, so tor does not wander",
      ("conf", "StrictNodes", "1") in ctl.calls, str(ctl.calls))
check("a fresh circuit is asked for",
      any(c[0] == "signal" and "NEWNYM" in c[1] for c in ctl.calls),
      str(ctl.calls))
check("the connection is let go", ctl.closed, "control left open")
check("the lane knows its new exit",
      lane.exit_fingerprint == "H" * 40 and lane.exit_ip == "5.5.5.5",
      f"{lane.exit_fingerprint[:8]} {lane.exit_ip}")
check("and it is unconfirmed until it is asked", lane.asked is False,
      str(lane.asked))
check("the relay is remembered as one we have been through",
      mgr._used.get("H" * 40, 0) > time.time(), str(mgr._used.get("H" * 40)))
seen = json.loads((move_root / bench.USED_PATH).read_text(encoding="utf-8"))
check("and that memory reaches the disk", "H" * 40 in seen,
      str(list(seen))[:40])
torrc = lane.torrc_path().read_text(encoding="utf-8")
check("the torrc on disk names the new relay", "ExitNodes $" + "H" * 40
      in torrc, torrc.splitlines()[-1:])
mgr._control = lambda l: None
check("no control connection means no move",
      mgr.move_exit(lane, relay("I" * 40, "6.6.6.6")) is False
      and lane.exit_fingerprint == "H" * 40, str(lane.exit_fingerprint))

src = (ROOT / "lingling" / "lanes.py").read_text(encoding="utf-8")
check("the move reaches tor through stem", "Controller.from_port" in src,
      "no control port")
check("the cookie proves the lane is ours",
      "authenticate_safecookie" in src, "no cookie auth")
check("the exit is set, then the circuit is rebuilt",
      'set_conf("ExitNodes"' in src and "NEWNYM" in src, "the recipe drifted")

print("\n=== F. the sweep rotates an idle lane, and only an idle one ===")


class FakeTor:
    """Only what a sweep asks its manager for."""

    def __init__(self, lanes, candidates, stuck=()):
        self._lanes = list(lanes)
        self._candidates = list(candidates)
        self.stuck = set(stuck)     # lanes tor will not move
        self.countries = []
        self.moves = []
        self.moved_lanes = []
        self.healing_at_move = []

    def idle_lanes(self):
        return list(self._lanes)

    def sweep_candidates(self, country):
        self.countries.append(country)
        return list(self._candidates)

    def move_exit(self, lane, candidate):
        self.healing_at_move.append(lane.healing)
        self.moved_lanes.append(lane.index)
        self.moves.append(candidate.fingerprint)
        return lane.index not in self.stuck


pair = [relay("J" * 40, "7.7.7.7"), relay("K" * 40, "8.8.8.8")]

events = []
lane = lane_at(SCRATCH / "sweep", "K" * 40)
tor = FakeTor([lane], pair)
health.ExitSweep(tor, event=events.append).step()
check("the lane is moved to the best candidate", tor.moves == ["J" * 40],
      str(tor.moves))
check("and it was out of the race for the move",
      tor.healing_at_move == [True], str(tor.healing_at_move))
check("the lane is back in service", lane.healing is False, str(lane.healing))
check("the lane's own country was the pool", tor.countries == ["de"],
      str(tor.countries))
check("the pane hears about it",
      any(e.get("kind") == "spread" and "7.7.7.7" in e.get("msg", "")
          for e in events), str(events))

events = []
tor = FakeTor([lane_at(SCRATCH / "sweep", "J" * 40)], pair)
health.ExitSweep(tor, event=events.append).step()
check("a lane already on the best exit is left alone", tor.moves == [],
      str(tor.moves))
check("so the pane stays quiet", events == [], str(events))

tor = FakeTor([], pair)
health.ExitSweep(tor).step()
check("no idle lane, no move", tor.moves == [], str(tor.moves))
tor = FakeTor([lane_at(SCRATCH / "sweep", "J" * 40)], [])
health.ExitSweep(tor).step()
check("an empty country is skipped, never forced", tor.moves == [],
      str(tor.moves))
tor = FakeTor([lane_at(SCRATCH / "sweep", "K" * 40)], pair)
health.ExitSweep(tor, interval=0).step()
check("a zero interval turns the sweep off", tor.moves == [], str(tor.moves))
check("and the shipped interval sweeps", health.SWEEP_S > 0, str(health.SWEEP_S))

print("\n=== G. a real 200 stamps its exit for free ===")


class TallyTor:
    """A tor that only reports what a tally hands it."""

    def __init__(self, stamps=True):
        self.scored = []
        self.stamped = []
        if stamps:
            self.note_verified = self.stamped.append

    def note_result(self, country, status):
        self.scored.append((country, status))


class FakeRelay:
    """The one thing a tally reads off a relay: its tor."""

    def __init__(self, tor):
        self.tor = tor


def tallied(status, tor):
    lane = lane_at(SCRATCH / "tally", "L" * 40)
    copy = _Copy(lane)
    race = _Race([copy])
    race.claim(copy)
    _tally(race, [(copy, ("", status, b"body", False))], FakeRelay(tor))
    return tor


tor = tallied(200, TallyTor())
check("a 200 stamps the exit it came through", tor.stamped == ["L" * 40],
      str(tor.stamped))
check("and the country is still scored", tor.scored == [("de", 200)],
      str(tor.scored))
check("a 429 stamps nothing", tallied(429, TallyTor()).stamped == [],
      "a refusal verified an exit")
raised = None
try:
    tallied(200, TallyTor(stamps=False))
except Exception as exc:  # noqa: BLE001
    raised = exc
check("a tor without the stamp is not a crash", raised is None, repr(raised))

print("\n=== H. the sweep never asks the far end anything ===")
#: A hand-rolled request
#: is refused by the gate (403 FreeTierError) whatever headers it carries,
#: so a probe can never be a verdict. Only a real call can stamp an exit.
hsrc = (ROOT / "lingling" / "health.py").read_text(encoding="utf-8")
node = next((n for n in ast.walk(ast.parse(hsrc))
             if isinstance(n, ast.ClassDef) and n.name == "ExitSweep"), None)
body = ast.unparse(node) if node is not None else ""
check("the sweep sends no request of its own",
      node is not None and "https_via_socks" not in body,
      "the sweep started probing the far end again")
check("health.py still has exactly one probe call",
      hsrc.count("netutil.https_via_socks(") == 1,
      f"{hsrc.count('netutil.https_via_socks(')} call sites")

print("\n=== I. a session starts and stops the sweep ===")
cli = (ROOT / "lingling" / "cli.py").read_text(encoding="utf-8")
check("the sweep starts with the lanes",
      "ExitSweep(" in cli and "sweep.start()" in cli, "nothing starts it")
check("and stops with the rest of the kitchen", "sweep.stop()" in cli,
      "nothing stops it")


print("\n=== J. a lane that has moved is not sitting out any more ===")
#: The clock a 429 sets belongs to the EXIT.  Hand the lane a different relay
#: and the clock has to go with it, or one refusal benches a whole lane for
#: the rest of the day while its new relay has a full allowance -- measured
#: 2026-10-16: lane 1 carried 3 of 500 calls in a real session for exactly
#: this reason, and the other five carried the session between them.
clock_root = SCRATCH / "clocks"
mgr = manager(clock_root)
lane = mgr.lanes[0]
lane.exit_fingerprint = "X" * 40
lane.limited_until = time.time() + 3600
lane.limit_reason = bench.FREE_LIMIT
ctl = FakeCtl()
mgr._control = lambda l: ctl
mgr.move_exit(lane, relay("Y" * 40, "9.9.9.9"))
check("a moved lane is back in the race", lane.limited_until == 0.0,
      f"{lane.limited_until}")
check("and the reason went with it", lane.limit_reason == "",
      repr(lane.limit_reason))
check("the lane's own relay is the one it names",
      lane.exit_fingerprint == "Y" * 40, lane.exit_fingerprint[:8])

moved_on = lane_at(SCRATCH / "clocks", "Y" * 40)
until = mgr.note_limited(moved_on, 0.0, bench.FREE_LIMIT, fingerprint="X" * 40)
check("a verdict about the old exit still reaches the notepad",
      mgr._limited.get("X" * 40, {}).get("reason") == bench.FREE_LIMIT,
      str(mgr._limited.get("X" * 40)))
check("and it is the exit it writes down, not the lane's",
      "Y" * 40 not in mgr._limited, str(list(mgr._limited))[:60])
check("but it never benches the relay the lane rides now",
      moved_on.limited_until == 0.0, f"{moved_on.limited_until}")
check("the deadline it returns is the one it recorded",
      until == mgr._limited["X" * 40]["until"], f"{until}")
check("a verdict about its own exit still benches it",
      mgr.note_limited(moved_on, 0.0, bench.FREE_LIMIT) > time.time()
      and moved_on.limited_until > time.time(),
      f"{moved_on.limited_until}")

print("\n=== K. the guard dedups one exit, and never strands a lane ===")
#: The 10s window exists so ten copies of one dead call cost one move.  It is
#: not a reason to leave a lane parked on an exit that was spent as well: a
#: verdict about a DIFFERENT relay is news, and refusing it is how a lane
#: disappeared from the race for the rest of a session.
guard = manager(SCRATCH / "guard")
lane = guard.lanes[0]
lane.exit_fingerprint = "M" * 40
check("the first verdict moves the lane", guard.claim_move(lane) is True,
      "the guard latched")
check("the same exit in the same breath does not",
      guard.claim_move(lane) is False, "the burst was charged twice")
lane.exit_fingerprint = "N" * 40
check("a verdict about the new exit is news", guard.claim_move(lane) is True,
      "a lane on a second spent exit could never move again")
check("and that exit is deduped in turn", guard.claim_move(lane) is False,
      "the second burst was charged twice")
lane.healing = True
lane.exit_fingerprint = "P" * 40
check("a lane mid-launch is never moved", guard.claim_move(lane) is False,
      "a move ran into a lane that was already launching")
lane.healing = False

print("\n=== L. a lane sitting out a spent exit is rescued first ===")
rescue = SCRATCH / "rescue"
benched = lane_at(rescue, "K" * 40, "de")
benched.limited_until = time.time() + 3600
spare = lane_at(rescue, "J" * 40, "de")
spare.index = 2
pool = [relay("J" * 40, "7.7.7.7"), relay("K" * 40, "8.8.8.8")]
events = []
tor = FakeTor([spare, benched], pool)
health.ExitSweep(tor, event=events.append).step()
check("the lane that is sitting out is the one moved",
      tor.moved_lanes == [1], str(tor.moved_lanes))
check("and the pane says the lane was out, not that it spread",
      any("sitting out" in e.get("msg", "") for e in events), str(events))

events = []
benched = lane_at(rescue, "K" * 40, "de")
benched.limited_until = time.time() + 3600
other = lane_at(rescue, "M" * 40, "de")
other.index = 2
tor = FakeTor([benched, other], pool, stuck=(1,))
health.ExitSweep(tor, event=events.append).step()
check("a lane tor will not move does not hold up the rest",
      tor.moved_lanes == [1, 2], str(tor.moved_lanes))
check("and the one that did move is the one the pane hears",
      len(events) == 1 and events[0].get("lane") == 2
      and "7.7.7.7" in events[0].get("msg", ""), str(events))
check("with the lane back in service either way",
      benched.healing is False and other.healing is False,
      f"{benched.healing} {other.healing}")


def live_session():
    """True when a lingling or opencode process is already running."""
    import subprocess
    try:
        out = subprocess.check_output(["tasklist"], text=True, timeout=15)
    except Exception:  # noqa: BLE001
        return False
    low = out.lower()
    return "lingling.exe" in low or "opencode.exe" in low


def live():
    """Boot one lane, rotate it by hand, and watch the exit really change."""
    print("\n=== LIVE. a real tor moves a lane onto another relay ===")
    if live_session():
        print("  a lingling/opencode session is running -- refusing to touch "
              "the lanes. Close it and re-run.")
        return
    countries, fallback, preferred = load_countries()
    mgr = TorManager(DATA_DIR, count=1, exit_countries=countries,
                     fallback_countries=fallback,
                     preferred_countries=preferred, log=lambda *a: None)
    err = mgr.setup_lanes()
    check("tor is ready to boot a lane", not err, str(err))
    if err:
        return
    lane = mgr.lanes[0]
    daemon = health.HealthDaemon(mgr, log=lambda *a: None)
    events = []
    sweeper = health.ExitSweep(mgr, event=events.append, log=lambda *a: None)
    try:
        mgr.start_lanes([lane])
        check("the lane boots", lane.running(), "tor did not start")
        if not lane.running():
            return
        code = 0
        deadline = time.time() + 180
        while time.time() < deadline and not code:
            code = daemon.reachable(lane)
            if not code:
                time.sleep(3)
        check("the lane answers", code in (200, 403),
              f"the probe got {code or 'nothing'}")
        before = (lane.exit_fingerprint, lane.exit_ip)
        print(f"  before: {before[0][:12]} {before[1]}")
        sweeper.step()
        moved = (lane.exit_fingerprint, lane.exit_ip)
        print(f"  after : {moved[0][:12]} {moved[1]}")
        check("the sweep moved the lane to another relay",
              moved[0] != before[0], f"{before[0][:12]} -> {moved[0][:12]}")
        seen = ""
        deadline = time.time() + 90
        while time.time() < deadline:
            daemon.reachable(lane)
            seen = lane.exit_ip
            if seen and seen == moved[1]:
                break
            time.sleep(3)
        check("the lane's traffic exits through the relay it was moved to",
              seen == moved[1], f"observed {seen or '?'}, pinned {moved[1]}")
        verdict = [e.get("msg", "") for e in events]
        print(f"  pane: {verdict[-1] if verdict else '(silent)'}")
        check("the pane said what the sweep did", bool(verdict),
              "the sweep found nothing to say")
    finally:
        mgr.stop_all()
        print("[stop] lane down")


if "--live" in sys.argv:
    live()
else:
    print("\n=== the live half ===")
    print("  [SKIP] run with --live to watch a real tor move a lane")

shutil.rmtree(SCRATCH, ignore_errors=True)

print("\n" + "=" * 52)
if FAILS:
    print(f"EXIT SWEEP: FAILED ({len(FAILS)})")
    for f in FAILS:
        print("  - " + f)
    sys.exit(1)
print("EXIT SWEEP: CONFIRMED")
