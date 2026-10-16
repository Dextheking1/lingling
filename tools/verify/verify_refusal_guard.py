"""The health probe's 429 actually reaches the refusal handler"""
import pathlib
import socket
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lingling import health  # noqa: E402
from lingling import relay as relay_mod  # noqa: E402
from lingling.lanes import Lane  # noqa: E402

FAILS = []


def check(name, ok, detail=""):
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name}" + (f" -- {detail}" if detail else ""))
    if not ok:
        FAILS.append(name)


class FakeProc:
    """A tor process that is alive, so check_once does not restart it."""

    def poll(self):
        return None


class StubTor:
    """Records what the daemon asked for, and does nothing else."""

    def __init__(self):
        self.rotations = 0
        self.restarts = 0
        self.limited = 0
        self.limit_hook = None
        self.lanes = []

    def note_limited(self, lane, retry_after=0.0, reason="rate",
                     fingerprint=""):
        self.limited += 1
        lane.limited_until = time.time() + 600.0
        return lane.limited_until

    def claim_move(self, lane):
        """One burst on one lane is one move; one probe is asking here."""
        return True

    def rotate_exit_country(self, lane):
        self.rotations += 1
        lane.exit_country = "zz"
        return "zz"

    def restart_lane(self, lane):
        self.restarts += 1
        lane.limited_until = 0.0
        return True

    def note_result(self, country, status):
        pass


def sweep(reply):
    """Run the real `check_once` once with the probe forced to `reply`."""
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="lingling-wire-"))
    tor = StubTor()
    daemon = health.HealthDaemon(tor)
    # lane has
    with socket.socket() as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        lane = Lane(index=1, socks_port=srv.getsockname()[1], control_port=0,
                    exit_country="de", data_dir=tmp)
        lane.exit_fingerprint = "A" * 40
        lane.process = FakeProc()
        lane.healthy = True
        # asked
        lane.wanted = True
        lane.asked = False
        tor.lanes = [lane]
        daemon.reachable = lambda _lane: reply
        daemon.check_once()
    return tor, lane


class HookTor:
    """The relay's view of the pool: scoring, and a move that may blow up."""

    def __init__(self, hook):
        self.limit_hook = hook
        self.scored = []
        self.lanes = []

    def note_result(self, country, status):
        self.scored.append((country, status))


def relay_sees(hook, status=429):
    """Run the real `report_refused` with the pool's hook set to `hook`."""
    tor = HookTor(hook)
    events = []
    relay = relay_mod.Relay.__new__(relay_mod.Relay)
    relay.tor = tor
    relay._emit = events.append
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="lingling-refused-"))
    lane = Lane(index=3, socks_port=0, control_port=0, exit_country="se",
                data_dir=tmp)
    lane.healthy = True
    raised = ""
    try:
        relay.report_refused(lane, status)
    except Exception as exc:  # noqa: BLE001
        raised = f"{type(exc).__name__}: {exc}"
    return tor, lane, events, raised


def main():
    print("=== a 429 probe moves the lane in a single sweep ===")
    tor, lane = sweep(429)
    print(f"  rotations={tor.rotations} restarts={tor.restarts} "
          f"asked={lane.asked}")
    check("check_once hands a probe 429 to on_refused",
          tor.rotations == 1 and tor.restarts == 1,
          f"rotations={tor.rotations} restarts={tor.restarts} -- the probe's "
          f"429 did not reach the refusal handler")

    print("\n=== a 403 probe leaves the lane in service ===")
    # 403 means
    tor, lane = sweep(403)
    print(f"  rotations={tor.rotations} restarts={tor.restarts} "
          f"asked={lane.asked}")
    check("a 403 probe marks the lane asked and moves nothing",
          tor.rotations == 0 and tor.restarts == 0 and lane.asked is True,
          f"rotations={tor.rotations} asked={lane.asked}")

    print("\n=== a 429 the relay sees survives a move that blows up ===")
    # refusal arrives
    boom = TypeError("AuthChallengeFailed.__init__() takes 3 positional "
                    "arguments but 4 were given")

    def exploding_move(lane, status, fingerprint=""):
        raise boom

    tor, lane, events, raised = relay_sees(exploding_move)
    msgs = [e.get("msg", "") for e in events]
    print(f"  raised={raised!r} events={msgs}")
    check("a refusal whose move raises is reported, not thrown",
          not raised and msgs and "moving it failed" in msgs[0],
          f"raised={raised!r} events={msgs}")
    check("the report names the lane, the status and the reason",
          bool(msgs) and "lane 3" in msgs[0] and "(429)" in msgs[0]
          and "AuthChallengeFailed" in msgs[0],
          f"events={msgs}")
    check("the refusal still scores the exit",
          tor.scored == [("se", 429)], f"scored={tor.scored}")

    print("\n=== with no health daemon the relay re-cooks the lane itself ===")
    tor, lane, events, raised = relay_sees(None)
    msgs = [e.get("msg", "") for e in events]
    print(f"  healthy={lane.healthy} events={msgs}")
    check("a refusal with no hook takes the lane out of service",
          lane.healthy is False and not raised, f"healthy={lane.healthy}")
    check("and says it is re-cooking it",
          any("re-cooking it" in m for m in msgs), f"events={msgs}")

    print()
    if FAILS:
        print("PROBE REFUSAL WIRING: FAILED")
        return 1
    print("PROBE REFUSAL WIRING: CONFIRMED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
