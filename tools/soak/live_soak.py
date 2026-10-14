"""Live soak: boot the real stack, then drive the REAL opencode client through the relay until ~N ..."""
import json
import os
import shutil
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from lingling import cli, mitm, netutil, proof
from lingling.cli import DATA_DIR, load_countries
from lingling.health import HealthDaemon
from lingling.lanes import TorManager
from lingling.relay import Relay

MODEL = "muse-spark-1.3-contributor-free"
PROOF_LOG = DATA_DIR / "proof.log"
#: A hung run must not outlive this.
RUN_TIMEOUT = 180.0

#: Two prompt pools, because the stall needs LONG reasoning answers.
PROMPTS = [
    "Reply with exactly: PROOF_OK",
    "Reply with exactly: LANE_1",
    "Reply with exactly: ALIVE",
    "Reply with exactly: OK_2",
    "Reply with exactly: PING",
    "Reply with exactly: TEST_A",
    "Reply with exactly: TEST_B",
    "Reply with exactly: GOOD",
    "Reply with exactly: READY",
    "Reply with exactly: FINE",
]

#: Long-reasoning prompts: each wants a real derivation, not a token.
HARD_PROMPTS = [
    "Derive the time complexity of a red-black tree insertion, proving each "
    "step, then compare it against a B-tree with the same key count.",
    "Design a rate limiter for 10 million requests per second across three "
    "regions. Give the algorithm, its failure modes, and the tradeoffs.",
    "Prove that every finite integral domain is a field, then explain where "
    "the argument breaks for infinite domains.",
    "Write a correct LRU cache in Python with O(1) operations, then prove "
    "the amortised bound of each method. Answer in your reply only; do not "
    "create or edit any files.",
    "Explain why TCP congestion control converges, deriving the AIMD "
    "equilibrium from first principles and noting the assumptions.",
    "Given a stream of integers, design a structure returning the median in "
    "O(log n) with O(n) memory. Prove both bounds.",
]


def boot(wait_healthy=4, timeout=420):
    countries, fallback, preferred = load_countries()
    mgr = TorManager(DATA_DIR, count=6, exit_countries=countries,
                     fallback_countries=fallback,
                     preferred_countries=preferred, log=lambda *a: None)
    err = mgr.setup_lanes()
    assert not err, f"setup_lanes: {err}"
    emit = proof.make_emitter(PROOF_LOG)
    #: session marker, as the CLI emits -- without it a soak run cannot be
    emit({"type": "start", "t": time.time(), "session": os.urandom(6).hex(),
          "lanes": len(mgr.lanes), "countries": list(mgr.countries),
          "version": "soak"})
    daemon = HealthDaemon(mgr, event=emit, log=lambda *a: None)

    def _report_boot(lane, status) -> None:
        """Put the launch outcome in the LOG, not just on stdout."""
        if status in ("started", "already_running"):
            return
        emit({"type": "lane", "kind": "fail", "t": time.time(),
              "lane": lane.index, "cc": lane.exit_country, "ip": "",
              "msg": f"lane {lane.index} {{{lane.exit_country}}} did not come "
                     f"up ({status})"})

    mgr.start_all(on_lane=_report_boot)
    daemon.start()
    deadline = time.time() + timeout
    while time.time() < deadline:
        if len(mgr.healthy_lanes()) >= wait_healthy:
            break
        time.sleep(3)
    print(f"[boot] healthy lanes: {len(mgr.healthy_lanes())}", flush=True)
    relay = Relay(mgr, event=emit)
    port = relay.start()
    relay.cert_shop = mitm.CertShop(DATA_DIR / "mitm")
    relay.tunnels = mitm.TunnelPool()
    print(f"[boot] relay port: {port}", flush=True)
    return mgr, daemon, relay, port


class LogTail:
    """Incremental reader so we can watch model calls land without re-parsing a multi-megabyte log on ..."""

    def __init__(self, path):
        self.path = path
        self.start_off = path.stat().st_size if path.exists() else 0
        self.off = self.start_off
        self.buf = b""
        self.calls = 0
        self.call_lanes = []
        self.ends = []
        self.lanes = []

    def poll(self):
        try:
            with open(self.path, "rb") as f:
                f.seek(self.off)
                data = f.read()
                self.off = f.tell()
        except OSError:
            return
        if not data:
            return
        self.buf += data
        *lines, self.buf = self.buf.split(b"\n")
        for raw in lines:
            raw = raw.strip()
            if not raw:
                continue
            try:
                r = json.loads(raw)
            except Exception:  # noqa: BLE001
                continue
            if not isinstance(r, dict):
                continue
            t = r.get("type")
            if t == "call":
                self.calls += 1
                # a raced call names every lane it went out on
                self.call_lanes.extend(r.get("lanes") or [r.get("lane")])
            elif t == "callend":
                self.ends.append(r)
            elif t == "lane":
                self.lanes.append(r)


def kill_tree(pid):
    """Kill children too."""
    try:
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)],
                       capture_output=True, timeout=15)
    except Exception:  # noqa: BLE001
        pass


class Killer:
    """One hard kill, mid-soak: the revive path, exercised on every run.

    A tor that dies while the session is up used to leave nothing behind --
    no revive, no line in the pane, and a lane that never served again.
    Killing one on purpose is how a soak proves that path still works, with
    nobody watching.
    """

    # The kill has to land well inside the run: a soak that reaches its
    # target in under a minute never fired it at 60s, so the revive path
    # went untested in exactly the short, fast runs.
    def __init__(self, mgr, lane_index=2, at_s=12.0):
        self.mgr = mgr
        self.lane_index = lane_index
        self.at_s = at_s
        self.fired = False
        self.result = "not fired"

    def maybe(self, elapsed):
        if self.fired or elapsed < self.at_s:
            return
        self.fired = True
        lane = next((l for l in self.mgr.lanes if l.index == self.lane_index),
                    None)
        if lane is None:
            self.result = f"no lane {self.lane_index}"
            return
        held = netutil.pids_on_ports({lane.socks_port, lane.control_port})
        pid = held.get(lane.socks_port) or held.get(lane.control_port) or 0
        if not pid:
            self.result = f"lane {lane.index} had no tor listening"
            return
        try:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                           capture_output=True, timeout=15)
        except Exception as exc:  # noqa: BLE001
            self.result = f"kill failed: {type(exc).__name__}"
            return
        self.result = (f"killed tor pid {pid} on lane {lane.index} at "
                       f"{elapsed:.0f}s")
        print(f"[soak] {self.result}", flush=True)


def warmup(oc, env, timeout=150.0):
    """One proxied model call, so the load never measures a cold server.

    Returns the first status the relay saw, or the failure in words. A
    server that has just been restarted refuses the first calls with 403
    for about ten seconds; the pool is not involved in that at all.
    """
    spec = "opencode/" + MODEL
    spec += "#" + os.environ.get("SOAK_VARIANT", "high")
    mark = LogTail(PROOF_LOG)
    try:
        subprocess.run([oc, "run", "-m", spec, "Reply with exactly: OK"],
                       env=env, capture_output=True, timeout=timeout,
                       text=True, encoding="utf-8", errors="replace",
                       cwd=str(Path.home()))
    except Exception as exc:  # noqa: BLE001
        return f"raised {type(exc).__name__}"
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        mark.poll()
        if mark.calls:
            break
        time.sleep(1)
    statuses = [str(e.get("status")) for e in mark.ends]
    return ",".join(statuses) if statuses else "no model call reached the relay"


def run_once(oc, env, i, pool=None):
    t0 = time.monotonic()
    prompts = pool or PROMPTS
    prompt = prompts[i % len(prompts)]
    hard = prompts is HARD_PROMPTS
    try:
        # The effort rides the MODEL string: opencode's `-m` is
        # `provider/model#variant`, and `opencode run` has no --variant flag,
        # so asking for it as a flag made every hard run exit before a
        # single model call.
        spec = "opencode/" + MODEL
        if hard:
            spec += "#" + os.environ.get("SOAK_VARIANT", "high")
        cmd = [oc, "run", "-m", spec]
        cmd.append(prompt)
        # opencode's output is UTF-8: `text=True` alone decodes it as cp1252
        # on Windows and the reader thread dies on the first box character,
        # which killed every run before its model call could be logged.
        proc = subprocess.Popen(
            cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
            cwd=str(Path.home()))
    except Exception as exc:  # noqa: BLE001
        return i, -2, time.monotonic() - t0, type(exc).__name__
    try:
        out, _ = proc.communicate(timeout=RUN_TIMEOUT)
        return i, proc.returncode, time.monotonic() - t0, (out or "").strip()
    except subprocess.TimeoutExpired:
        kill_tree(proc.pid)
        return i, -1, time.monotonic() - t0, "timeout"


def main():
    argv = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    #: created before the boot, so one reader owns the whole run: the launch
    #: lines, the warm-up, the load and every lane event in between.
    tail = LogTail(PROOF_LOG)
    target = int(argv[0]) if argv else 400
    conc = int(os.environ.get("SOAK_CONCURRENCY", "5"))
    budget = float(os.environ.get("SOAK_BUDGET_S", "2700"))
    # `--hard` is what makes the soak able to
    pool = HARD_PROMPTS if "--hard" in flags else PROMPTS
    print(f"[soak] prompt pool: "
          f"{'HARD (long reasoning)' if pool is HARD_PROMPTS else 'short'}"
          f"  target={target}", flush=True)

    mgr, daemon, relay, port = boot()
    ca = str(DATA_DIR / "mitm" / "ca.pem")
    oc = shutil.which("opencode")
    if oc is None:
        raise SystemExit("opencode is not on PATH -- install it first")
    env = dict(os.environ)
    env["HTTPS_PROXY"] = f"http://127.0.0.1:{port}"
    env["HTTP_PROXY"] = f"http://127.0.0.1:{port}"
    env["NO_PROXY"] = "localhost,127.0.0.1"
    env["NODE_EXTRA_CA_CERTS"] = ca
    """From opencode 2.0.26 the call is made by a background server that
    keeps the environment it was born with, so a proxy handed to the client
    never reaches the model. This is the product's own handoff: the server
    is restarted under our environment, and stopped again on the way out so
    no server is left holding a relay port that no longer exists."""
    server = cli._uses_background_server(oc)
    if server:
        cli._server(oc, env, "restart")

    """A server restarted under the proxy answers its first model calls
    with 403 ("the free tier can only be used from within OpenCode") until
    it is warm -- measured: 34 of 34 calls refused between 7s and 17s after
    a restart, none after. That is the server's own startup, not the pool,
    so one call is sent and waited out before the load begins."""
    warm = warmup(oc, env)
    print(f"[soak] first call after the restart: {warm}", flush=True)

    killer = None
    if "--kill" in flags:
        killer = Killer(mgr, int(os.environ.get("SOAK_KILL_LANE", "2")),
                        float(os.environ.get("SOAK_KILL_AT", "12")))
    print(f"[soak] target={target} model calls  concurrency={conc}  "
          f"budget={budget:.0f}s"
          + (f"  hard-kill lane {killer.lane_index} at {killer.at_s:.0f}s"
             if killer else ""), flush=True)
    t0 = time.monotonic()
    results = []
    runs = 0
    with ThreadPoolExecutor(max_workers=conc) as ex:
        pending = set()
        while True:
            elapsed = time.monotonic() - t0
            tail.poll()
            if killer is not None:
                killer.maybe(elapsed)
            if tail.calls >= target:
                print(f"[soak] target reached: {tail.calls} calls", flush=True)
                break
            if elapsed > budget:
                print(f"[soak] budget hit at {tail.calls} calls", flush=True)
                break
            while len(pending) < conc:
                pending.add(ex.submit(run_once, oc, env, runs, pool))
                runs += 1
            done, pending = wait(pending, timeout=1.0,
                                 return_when=FIRST_COMPLETED)
            for f in done:
                results.append(f.result())
            if runs % 10 == 0 and done:
                print(f"  runs={runs} calls={tail.calls} "
                      f"elapsed={elapsed:.0f}s ({tail.calls / max(elapsed, 1):.2f} calls/s)",
                      flush=True)
        for f in pending:
            f.cancel()
        # Short drain: a long one only waits on
        done, _ = wait(pending, timeout=30)
        for f in done:
            if not f.cancelled():
                try:
                    results.append(f.result())
                except Exception:  # noqa: BLE001
                    pass
    elapsed = time.monotonic() - t0
    tail.poll()

    codes = Counter(str(e.get("status")) for e in tail.ends)
    secs = sorted(e.get("secs") or 0 for e in tail.ends)
    kbs = [e.get("kb") or 0 for e in tail.ends]
    rcs = Counter(str(r[1]) for r in results)
    oks = sum(1 for r in results if "PROOF_OK" in r[3] or r[1] == 0)

    print("\n" + "=" * 60, flush=True)
    print(f"LIVE SOAK   runs={runs}  model calls={tail.calls}  wall={elapsed:.0f}s")
    print("=" * 60, flush=True)
    print(f"opencode rc  : {dict(rcs)}   (rc=0 = {oks}/{len(results)})")
    print(f"call statuses: {dict(codes)}")
    # A 200 that the far end cut mid-body
    ok200 = sum(1 for e in tail.ends
                if e.get("status") == 200 and e.get("err") == "")
    tot = max(1, len(tail.ends))
    print(f"success rate : {100 * ok200 / tot:.1f}%  ({ok200}/{tot})")

    def pct(vals, p):
        return vals[min(len(vals) - 1, int(len(vals) * p))]

    if secs:
        print(f"latency      : p50={pct(secs, 0.5):.1f}s "
              f"p90={pct(secs, 0.9):.1f}s max={secs[-1]:.1f}s")
    # 0 means the attempt never got that far,
    fbs = sorted(e.get("first_byte_s") for e in tail.ends
                 if e.get("first_byte_s"))
    fes = sorted(e.get("first_event_s") for e in tail.ends
                 if e.get("first_event_s"))
    if fbs:
        print(f"first byte   : p50={pct(fbs, 0.5):.2f}s "
              f"p90={pct(fbs, 0.9):.2f}s max={fbs[-1]:.2f}s (n={len(fbs)})")
    if fes:
        print(f"first event  : p50={pct(fes, 0.5):.2f}s "
              f"p90={pct(fes, 0.9):.2f}s max={fes[-1]:.2f}s (n={len(fes)})")
    # A reused tunnel skips the SOCKS5 CONNECT and
    reuse = [e for e in tail.ends if e.get("reused")]
    if reuse:
        print(f"tunnel reuse : {len(reuse)} of {len(tail.ends)} calls "
              f"({100 * len(reuse) / len(tail.ends):.0f}%)")
        rb = sorted(e["first_byte_s"] for e in reuse if e.get("first_byte_s"))
        if rb:
            print(f"  reused first byte p50={pct(rb, 0.5):.2f}s  "
                  f"vs {pct(fbs, 0.5):.2f}s overall")
    if kbs:
        small = sum(1 for k in kbs if k < 2)
        print(f"payload      : median={sorted(kbs)[len(kbs) // 2]}KB  "
              f"under 2KB={100 * small / len(kbs):.0f}%  max={max(kbs)}KB")
    #: dispatched, not finished -- a callend can be lost if the tail starts
    lanes_used = Counter(tail.call_lanes)
    print(f"lane spread  : {dict(sorted(lanes_used.items()))}")
    print(f"throughput   : {elapsed / max(1, tail.calls):.2f}s per model call")

    print("\n--- health daemon activity during the soak ---", flush=True)
    kinds = Counter(e.get("kind") for e in tail.lanes)
    print(f"lane events: {dict(kinds) if kinds else 'none'}")
    for e in tail.lanes:
        # `probe` is included deliberately: it means the health
        if e.get("kind") in ("limited", "rotate", "up", "fail", "probe"):
            print(f"  [{e.get('kind')}] {e.get('msg')}", flush=True)

    if server:
        cli._server(oc, env, "stop")
    daemon.stop()
    relay.stop()
    mgr.stop_all()

    # Did anything survive? A straggler holds its lane's
    import subprocess as _sp
    _tl = _sp.run(["tasklist", "/FO", "CSV", "/NH"],
                  capture_output=True, text=True).stdout
    _tor = [r for r in _tl.splitlines() if "tor.exe" in r.lower()]
    print(f"\n[teardown] tor.exe still alive: {len(_tor)}", flush=True)
    if _tor:
        print("           ^ a straggler survived stop_all -- it will block a "
              "lane next run", flush=True)

    """The soak judges itself.

    Counters alone let a silent failure through, and a silent failure is
    what cost four lanes a whole session: nothing in the pane said they
    were gone. These checks fail the run instead of leaving it to a reader.
    """
    print("\n--- verdict ---", flush=True)
    try:
        text = PROOF_LOG.read_bytes()[tail.start_off:].decode(
            "utf-8", "replace")
    except OSError:
        text = ""
    tracebacks = text.count("Traceback")
    used = {l for l in tail.call_lanes if l}
    spoken = {e.get("lane") for e in tail.lanes}
    silent = sorted(used - spoken)
    fails = [e for e in tail.lanes if e.get("kind") == "fail"]
    checks = [
        ("no traceback in the run", tracebacks == 0, f"{tracebacks} found"),
        ("every lane that carried a call is reported on", not silent,
         f"lanes {silent} served traffic and said nothing"),
        ("no lane failure went unexplained", not fails,
         "; ".join(str(e.get("msg")) for e in fails[:3]) or "none"),
        ("no tor survived the session", not _tor, f"{len(_tor)} left"),
    ]
    if killer is not None:
        revived = [e.get("msg") for e in tail.lanes
                   if "brought it back" in (e.get("msg") or "")]
        checks.append(("a killed lane came back", bool(revived),
                       killer.result + " -> "
                       + ("; ".join(revived) or "no revive in the pane")))
    failed = 0
    for name, ok, detail in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}   ({detail})",
              flush=True)
        failed += not ok
    print(f"\nSOAK {'FAILED' if failed else 'PASSED'}: "
          f"{len(checks) - failed}/{len(checks)} checks", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
