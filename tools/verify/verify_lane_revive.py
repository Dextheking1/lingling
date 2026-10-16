"""A lane that is down must be brought back, not skipped forever"""
import socket
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lingling import health  # noqa: E402
from lingling.lanes import Lane  # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    """Detail is the failure reason, so only show it when it failed."""
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name}" + (f" -- {detail}" if (detail and not ok) else ""))
    if not ok:
        FAILS.append(name)


class FakeProc:
    def __init__(self, alive=True):
        self._alive = alive

    def poll(self):
        return None if self._alive else 1


class FakeTor:
    def __init__(self, lanes):
        self.lanes = lanes
        self.restarted = []

    def restart_lane(self, lane, repin=False):
        self.restarted.append(lane.index)
        return True


def lane(i, *, process, healthy, wanted, healing=False, socks_port=None):
    return Lane(index=i, socks_port=socks_port or (50000 + i),
                control_port=51000 + i,
                exit_country="de", data_dir=Path("."),
                process=process, healthy=healthy, wanted=wanted,
                healing=healing)


def drive(lanes):
    tor = FakeTor(lanes)
    events = []
    d = health.HealthDaemon(tor, event=events.append, log=lambda *a: None)
    d.check_once()
    return tor, events


def main():
    print("=== a lane whose launch FAILED (no process) ===")
    tor, events = drive([lane(1, process=None, healthy=False, wanted=True)])
    print(f"  restarted={tor.restarted}  events={len(events)}")
    check("it is brought back",
          tor.restarted == [1],
          f"restarted={tor.restarted} -- a failed launch was terminal")
    check("and the log says so",
          any(e.get("type") == "lane" and e.get("kind") == "up" for e in events),
          f"no lane event: {events}")

    print("\n=== a lane that went UNHEALTHY with a live process ===")
    tor, events = drive([lane(2, process=FakeProc(alive=True), healthy=False,
                              wanted=True)])
    print(f"  restarted={tor.restarted}  events={len(events)}")
    check("it is brought back",
          tor.restarted == [2],
          f"restarted={tor.restarted} -- an unhealthy lane was never "
          f"re-probed")

    print("\n=== a lane the CLI has NOT started yet must be left alone ===")
    tor, events = drive([lane(3, process=None, healthy=None, wanted=False)])
    print(f"  restarted={tor.restarted}  events={len(events)}")
    check("it is not touched",
          tor.restarted == [],
          f"restarted={tor.restarted} -- reviving it would race the CLI's own "
          f"staggered boot")
    check("and nothing is reported about it", events == [], str(events))

    print("\n=== a lane that is MID-LAUNCH must not be restarted ===")
    # `_launch_lane` sets
    tor, events = drive([lane(5, process=FakeProc(alive=True), healthy=False,
                              wanted=True, healing=True)])
    print(f"  restarted={tor.restarted}  events={len(events)}")
    check("the in-flight launch is left to finish",
          tor.restarted == [],
          f"restarted={tor.restarted} -- the daemon killed a booting lane")

    print("\n=== a lane that is up AND listening is left alone ===")
    # has
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        tor, events = drive([lane(4, process=FakeProc(alive=True), healthy=True,
                                  wanted=True,
                                  socks_port=srv.getsockname()[1])])
        print(f"  restarted={tor.restarted}")
        check("left alone", tor.restarted == [], f"restarted={tor.restarted}")

    print("\n=== a lane whose own port is GONE is brought back ===")
    # tor died
    tor, events = drive([lane(6, process=FakeProc(alive=True), healthy=True,
                              wanted=True)])
    print(f"  restarted={tor.restarted}  events={len(events)}")
    check("it is brought back",
          tor.restarted == [6],
          f"restarted={tor.restarted} -- a lane with no listener was left "
          f"to fail its requests forever")
    check("and the log says so",
          any(e.get("type") == "lane" and e.get("kind") == "up" for e in events),
          f"no lane event: {events}")

    print("\n=== a lane that CANNOT be brought back must say so ===")
    # tor outlived
    class Failing(FakeTor):
        def restart_lane(self, lane, repin=False):
            self.restarted.append(lane.index)
            return False

    events = []
    stuck = lane(7, process=None, healthy=False, wanted=True)
    tor = Failing([stuck])
    d = health.HealthDaemon(tor, event=events.append, log=lambda *a: None)
    d.check_once()
    downs = [e for e in events if e.get("kind") == "down"]
    print(f"  down events={len(downs)}")
    check("a failed revive is reported",
          len(downs) == 1 and downs[0].get("lane") == 7,
          f"events={[e.get('msg') for e in events]} -- a lane that cannot "
          f"come back stayed silent")
    d.check_once()
    d.check_once()
    downs = [e for e in events if e.get("kind") == "down"]
    check("and reported once, not every sweep",
          len(downs) == 1,
          f"down events={len(downs)} -- the pane would be flooded")

    print("\n=== orphaned tor processes are reaped before any lane launches ===")
    # tor
    from lingling import netutil
    from lingling.lanes import TorManager

    seen = {}
    real_pids = netutil.pids_on_ports
    real_run = netutil.subprocess.run

    class Mgr:
        socks_base = 52001
        control_base = 52301

        def _stop_orphan(self, pid, ports=None):
            killed.append(pid)
            offered.append(list(ports or []))
            return True

    def fake_pids(ports):
        ports = list(ports)
        seen["asked"] = ports
        # Only ports
        want = set(ports)
        return {p: pid for p, pid in ((52003, 111), (9999, 222)) if p in want}

    killed = []
    offered = []
    netutil.pids_on_ports = fake_pids
    netutil.subprocess.run = lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("port ownership must not authorize a kill"))
    try:
        n = TorManager._reap_orphans(Mgr())
    finally:
        netutil.pids_on_ports = real_pids
        netutil.subprocess.run = real_run

    asked = seen.get("asked", [])
    print(f"  asked for {len(asked)} ports; killed={killed}")
    check("it sweeps the whole lane port range",
          len(asked) > 100,
          f"only asked about {len(asked)} ports")
    check("it asks the authenticated shutdown helper about the leftover",
          killed == [111],
          f"killed={killed}")
    # 52003
    check("and it offers the control port that stray is actually on",
          offered == [[52303]],
          f"offered={offered} -- the stray's own port was never offered, so "
          f"it could never be authenticated")
    # scoping guarantee
    lo = min(asked) if asked else 0
    hi = max(asked) if asked else 0
    check("and it only ever asks about ports in the lane range",
          lo >= Mgr.socks_base and hi <= Mgr.control_base + 4000,
          f"asked about {lo}..{hi} -- outside the lane range")

    print("\n=== lane dirs for lanes the pool does not have are pruned ===")
    # lane dir
    import tempfile
    from lingling.lanes import TorManager as _TM

    tmp = Path(tempfile.mkdtemp(prefix="lingling-prune-"))
    for n in range(1, 6):
        (tmp / f"tor-{n}").mkdir()
        (tmp / f"tor-{n}" / "cached-microdescs").write_text("x" * 100)
    (tmp / "keepme").mkdir()  # not
    (tmp / "tor-notanumber").mkdir()       # matches nothing

    class Mgr2:
        lanes_dir = tmp

        def __init__(self):
            class L:
                pass
            self.lanes = [L(), L()]
            self.lanes[0].index, self.lanes[1].index = 1, 2

    pruned = _TM._prune_lane_dirs(Mgr2())
    left = sorted(p.name for p in tmp.iterdir())
    print(f"  pruned={pruned}  left={left}")
    check("the unconfigured lane dirs are removed",
          pruned == 3 and not (tmp / "tor-3").exists(),
          f"pruned={pruned}, left={left}")
    check("the live lanes' dirs are kept",
          (tmp / "tor-1").exists() and (tmp / "tor-2").exists(),
          f"left={left} -- a running lane's data was deleted")
    check("nothing that is not a lane dir is touched",
          (tmp / "keepme").exists() and (tmp / "tor-notanumber").exists(),
          f"left={left}")

    print("\n=== a smaller pool must not wipe the other lanes' caches ===")
    # lane dir
    tmp2 = Path(tempfile.mkdtemp(prefix="lingling-keep-"))
    for n in range(1, 6):
        d = tmp2 / "lanes" / f"tor-{n}"
        d.mkdir(parents=True)
        (d / "cached-microdescs").write_text("x" * 100, encoding="utf-8")

    probe = _TM(tmp2, count=1, exit_countries=["de"], log=lambda *a: None)
    # setup_lanes()
    check("a fresh manager does not opt into pruning",
          probe.prune_orphans is False,
          "prune_orphans defaulted to True -- a probe would delete lanes")

    kept = sorted(p.name for p in (tmp2 / "lanes").iterdir())
    check("and so the other lanes are still on disk",
          kept == [f"tor-{n}" for n in range(1, 6)],
          f"kept={kept} -- a smaller pool wiped a bigger install")

    # product opts
    owner = _TM(tmp2, count=2, exit_countries=["de"], log=lambda *a: None,
                prune_orphans=True)
    check("the product can still opt in", owner.prune_orphans is True)
    owner._prune_lane_dirs()
    after = sorted(p.name for p in (tmp2 / "lanes").iterdir())
    check("an opted-in shrink reclaims the extra lanes",
          after == ["tor-1", "tor-2"], f"after={after}")

    print("\n=== a loaded lane is not torn down under its streams ===")
    # One thirty-second
    from lingling.lanes import TorManager
    droot = Path(tempfile.mkdtemp(prefix="lingling-drain-"))
    mgr = TorManager(droot, count=1, exit_countries=["de"],
                     log=lambda *a: None)
    busy = mgr.lanes[0]
    events = []
    mgr.attach(events.append)
    order = []
    mgr._stop_lane_process = lambda ln: order.append("stop") or True
    mgr._launch_lane = lambda ln: order.append("launch") or "started"
    mgr._write_torrc = lambda ln: order.append("torrc")

    busy.active = 30
    moved = mgr.restart_lane(busy)
    msgs = [e.get("msg", "") for e in events]
    print(f"  active=30 -> moved={moved} order={order} events={msgs}")
    check("a loaded lane is not stopped while its streams are open",
          moved is False and order == [],
          f"order={order} -- the recook ran under 30 live streams")
    check("and one line says why, not thirty",
          len(msgs) == 1 and "30 streams in flight" in msgs[0],
          f"events={msgs}")

    busy.active = 0
    deadline = time.time() + 8
    while time.time() < deadline and not any(
            "recooked" in e.get("msg", "") for e in events):
        time.sleep(0.05)
    msgs = [e.get("msg", "") for e in events]
    print(f"  once idle -> order={order} events={msgs}")
    check("the move runs as soon as the lane is idle",
          order[:1] == ["stop"], f"order={order}")
    check("and the lane says it came back",
          any("recooked" in m for m in msgs), f"events={msgs}")

    print("\n=== a tear-down that does lose streams reports one line ===")
    cut = []
    mgr.attach(cut.append)
    busy.active = 2
    mgr._drain(busy, timeout=0.05)
    cut_msgs = [e.get("msg", "") for e in cut]
    print(f"  events={cut_msgs}")
    check("the drain gives up with one summary line",
          len(cut_msgs) == 1 and "2 streams cut" in cut_msgs[0],
          f"events={cut_msgs}")
    busy.active = 0

    print()
    if FAILS:
        print("LANE REVIVE: FAILED")
        for f in FAILS:
            print("  - " + f)
        return 1
    print("LANE REVIVE: CONFIRMED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
