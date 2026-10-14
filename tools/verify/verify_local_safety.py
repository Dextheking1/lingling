"""Local regressions for ownership, session lifecycle, SOCKS and handoff safety."""
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from lingling import cli, demo, lanes, netutil, update
from lingling.lanes import TorManager


class LocalSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ll-safety-")
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def child(self, code, *args):
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        return subprocess.run([sys.executable, "-c", code, *map(str, args)],
                              cwd=self.root, env=env, capture_output=True,
                              text=True, timeout=10)

    def test_lock_creation_window_and_crash(self):
        code = '''import os,sys,time
from pathlib import Path
from lingling import netutil
p=Path(sys.argv[1]); original=Path.write_text
def delayed(self,*a,**k):
 if self.name=='session.lock':
  original(p/'ready','1')
  while not (p/'resume').exists(): time.sleep(.01)
 return original(self,*a,**k)
Path.write_text=delayed
print(netutil.session_lock(p),flush=True)
sys.stdin.read()
'''
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        proc = subprocess.Popen([sys.executable, "-c", code, str(self.root)],
                                cwd=self.root, env=env, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        try:
            deadline = time.monotonic() + 5
            while not (self.root / "ready").exists() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue((self.root / "ready").exists())
            rival = self.child("from lingling import netutil; import sys; "
                               "r=netutil.session_lock(sys.argv[1]); "
                               "print(r); assert r is not None", self.root)
            self.assertEqual(rival.returncode, 0, rival.stderr)
            (self.root / "resume").write_text("1")
            self.assertEqual(proc.stdout.readline().strip(), "None")
            stable = self.child("from lingling import netutil; import sys; "
                                "assert netutil.session_lock(sys.argv[1]) == int(sys.argv[2])",
                                self.root, proc.pid)
            self.assertEqual(stable.returncode, 0, stable.stderr)
        finally:
            proc.kill()
            proc.communicate(timeout=5)
        self.assertIsNone(netutil.session_lock(self.root))
        netutil.release_session_lock(self.root)

    def test_lock_io_errors_fail_closed(self):
        (self.root / "session.lock").mkdir()
        with patch.object(cli, "DATA_DIR", self.root), self.assertRaises(OSError):
            cli._other_lingling()
        with patch.object(cli, "_other_lingling", side_effect=OSError("denied")), \
                patch.object(cli.shutil, "which", return_value=sys.executable), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["--no-tor", "--no-proof"]), 1)

    def test_demo_refused_while_owned(self):
        self.assertIsNone(netutil.session_lock(self.root))
        try:
            with patch.object(cli, "DATA_DIR", self.root), \
                    patch.object(demo, "run_demo") as run, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["--demo"]), 1)
                run.assert_not_called()
        finally:
            netutil.release_session_lock(self.root)
        with patch.object(cli, "DATA_DIR", self.root), \
                patch.object(demo, "run_demo", return_value=0) as run:
            self.assertEqual(cli.main(["--demo"]), 0)
            run.assert_called_once()
        self.assertFalse((self.root / "session.lock").exists())

    def test_lock_held_until_teardown_even_on_errors(self):
        for failure in (False, True):
            observed = []
            test = self
            class Manager:
                lanes = [SimpleNamespace()]
                countries = ["de"]
                sticky = SimpleNamespace(attach=lambda e: None)
                def __init__(self, *a, **k): pass
                def attach(self, emit): pass
                def setup_lanes(self): return None
                def start_lanes(self, *a, **k): pass
                def stop_all(self):
                    rival = test.child("from lingling import netutil; import sys; "
                                       "assert netutil.session_lock(sys.argv[1]) is not None",
                                       test.root)
                    test.assertEqual(rival.returncode, 0, rival.stderr)
                    observed.append("stopped")
            class Daemon:
                def __init__(self, *a, **k): pass
                def start(self): pass
                def stop(self):
                    if failure: raise RuntimeError("daemon stop")
            class Relay:
                def __init__(self, *a, **k): pass
                def start(self): return 59000
                def stop(self): observed.append("relay")
            class Emitter:
                def __call__(self, e): pass
                def close(self): pass
            with contextlib.ExitStack() as stack:
                for obj, name, value in (
                    (cli, "DATA_DIR", self.root), (cli, "PROOF_LOG", self.root / "proof.log"),
                    (cli, "_migrate_countries", lambda: None),
                    (cli, "_spawn_geoip_fallback", lambda: None),
                    (cli.shutil, "which", lambda _: sys.executable),
                    (cli, "TorManager", Manager), (cli, "HealthDaemon", Daemon),
                    (cli, "Relay", Relay), (cli, "_boot_gate", lambda *a: True),
                    (cli, "_run_opencode", lambda *a: 0),
                    (cli.proof, "make_emitter", lambda *a: Emitter()),
                    (cli.update, "start", lambda *a: None),
                ):
                    stack.enter_context(patch.object(obj, name, value))
                stack.enter_context(patch.dict(os.environ, {"LINGLING_NO_MITM": "1"}))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                if failure:
                    with self.assertRaisesRegex(RuntimeError, "daemon stop"):
                        cli.main(["--no-proof"])
                else:
                    self.assertEqual(cli.main(["--no-proof"]), 0)
            self.assertEqual(observed, ["relay", "stopped"])
            self.assertFalse((self.root / "session.lock").exists())

    def test_reaper_uses_verified_control_not_port_kills(self):
        manager = TorManager(self.root, count=1, exit_countries=["de"])
        with patch.object(netutil, "pids_on_ports", return_value={52001: 123}), \
                patch.object(netutil.subprocess, "run", side_effect=AssertionError("unsafe kill")), \
                patch.object(manager, "_stop_orphan", return_value=False) as stop:
            self.assertEqual(manager._reap_orphans(), 0)
            # 52001 is lane 1's SOCKS port, so 52301 is the control port the
            # stray must be answering on. Offering it is what makes a tor
            # whose torrc was rewritten reachable again.
            stop.assert_called_once_with(123, [52301])
        config = manager.lanes[0].torrc_path()
        config.parent.mkdir(parents=True)
        config.write_text("ControlPort 127.0.0.1:52301\n")
        cookie = config.parent / "control_auth_cookie"
        cookie.write_bytes(b"fixture")
        control = SimpleNamespace(get_pid=lambda: 123,
                                  get_conf=lambda key: str(config.parent),
                                  signal=lambda value: signals.append(value),
                                  close=lambda: None)
        signals = []
        import stem.connection
        import stem.control
        with patch.object(stem.control.Controller, "from_port", return_value=contextlib.nullcontext(control)), \
                patch.object(stem.connection, "authenticate_safecookie") as auth:
            self.assertTrue(manager._stop_orphan(123))
            auth.assert_called_once()
            self.assertFalse(manager._stop_orphan(124))
            control.get_conf = lambda key: str(self.root / "foreign")
            self.assertFalse(manager._stop_orphan(123))
        self.assertEqual(len(signals), 1)
        with patch.object(stem.control.Controller, "from_port", return_value=contextlib.nullcontext(control)), \
                patch.object(stem.connection, "authenticate_safecookie",
                             side_effect=stem.connection.CookieAuthRejected("bad cookie", str(cookie), True)):
            self.assertFalse(manager._stop_orphan(123))

    def test_stray_is_reachable_on_the_port_it_still_holds(self):
        """A stray whose torrc was rewritten must still be askable."""
        held = {52003: 111, 52303: 111, 52009: 222, 9999: 333}
        self.assertEqual(
            lanes._leftover_ports(111, held, 52001, 52301), [52303])
        self.assertEqual(
            lanes._leftover_ports(222, held, 52001, 52301), [52309])
        self.assertEqual(
            lanes._leftover_ports(333, held, 52001, 52301), [])

    def test_abandoned_launch_leaves_no_tor_behind(self):
        """A tor that arrives after its boot window must be killed."""
        mgr = TorManager(self.root, count=1, exit_countries=["de"],
                         boot_timeout=1, log=lambda *a: None)
        mgr._tor_path = lambda: Path(sys.executable)
        lane = mgr.lanes[0]
        killed = []

        class Proc:
            def kill(self): killed.append("kill")
            def wait(self, timeout=None): killed.append("wait")
            def poll(self): return None

        released = threading.Event()

        class Stem:
            class process:
                @staticmethod
                def launch_tor_with_config(**kw):
                    released.wait(10)
                    return Proc()

        def late():
            # still starting when the boot window closes
            time.sleep(1.5)
            released.set()

        threading.Thread(target=late, daemon=True).start()
        with self.assertRaises(RuntimeError):
            mgr._launch_tor_process(Stem, lane, {}, lambda line: None)
        deadline = time.monotonic() + 5
        while not killed and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(
            killed[:1], ["kill"],
            "a launch abandoned at the boot window left a tor running on the "
            "lane's own port, with nobody holding a handle to it")

    def test_stop_reports_a_tor_that_will_not_die(self):
        """A tor that refuses to exit must be reported, not assumed gone."""
        mgr = TorManager(self.root, count=1, exit_countries=["de"],
                         log=lambda *a: None)
        lane = mgr.lanes[0]

        class Stubborn:
            def terminate(self): pass
            def kill(self): pass
            def wait(self, timeout=None): raise RuntimeError("still running")
            def poll(self): return None          # never exits

        lane.process = Stubborn()
        self.assertFalse(
            mgr._stop_lane_process(lane),
            "a tor that never exits was reported as stopped -- the next "
            "launch would then be locked out of the lane's directory")
        self.assertIsNone(lane.process)
        self.assertFalse(lane.healthy)

    def test_locked_lane_dir_is_cleared_before_relaunch(self):
        """A stray holding the lane directory is stopped before relaunch."""
        mgr = TorManager(self.root, count=1, exit_countries=["de"],
                         log=lambda *a: None)
        lane = mgr.lanes[0]
        order = []
        mgr._stop_lane_process = lambda ln: order.append("stop") or True
        mgr._launch_lane = lambda ln: order.append("launch") or "started"
        mgr._write_torrc = lambda ln: order.append("torrc")
        with patch.object(netutil, "pids_on_ports",
                          return_value={52001: 4242}), \
                patch.object(mgr, "_stop_orphan",
                             side_effect=lambda *a, **k:
                             order.append("clear") or True) as stop:
            self.assertTrue(mgr.restart_lane(lane))
        # stop -> clear the holder -> write the torrc -> launch
        self.assertEqual(order, ["stop", "clear", "torrc", "launch"], order)
        stop.assert_called_once()
        self.assertEqual(stop.call_args.args[0], 4242)
        self.assertEqual(stop.call_args.kwargs.get("only"), lane.data_dir,
                         "the clear was not narrowed to this lane")

    def test_ownership_can_be_narrowed_to_one_lane(self):
        """`only` must refuse a tor that belongs to a different lane."""
        mgr = TorManager(self.root, count=2, exit_countries=["de", "nl"],
                         log=lambda *a: None)
        for i in (1, 2):
            d = mgr.lanes_dir / f"tor-{i}"
            d.mkdir(parents=True, exist_ok=True)
            (d / "control_auth_cookie").write_bytes(b"x")
        control = SimpleNamespace(
            get_pid=lambda: 77,
            get_conf=lambda key: str(mgr.lanes_dir / "tor-2"),
            signal=lambda value: None, close=lambda: None)
        import stem.connection
        import stem.control
        with patch.object(stem.control.Controller, "from_port",
                          return_value=contextlib.nullcontext(control)), \
                patch.object(stem.connection, "authenticate_safecookie"):
            self.assertFalse(
                mgr._stop_orphan(77, [52301], only=mgr.lanes_dir / "tor-1"),
                "a tor owning another lane's directory was shut down")
            self.assertTrue(
                mgr._stop_orphan(77, [52301], only=mgr.lanes_dir / "tor-2"))

    def test_orphan_probe_survives_a_broken_auth(self):
        """A probe that blows up means "not ours", never a crash.

        stem 1.8.2 builds AuthChallengeFailed with a third argument its
        constructor does not take, so an endpoint that fails mid-probe --
        a SOCKS port dialled as a control port, a tor that just died --
        arrives as a TypeError. That escaped this probe and killed the
        request whose refusal triggered the relaunch.
        """
        mgr = TorManager(self.root, count=1, exit_countries=["de"],
                         log=lambda *a: None)
        own = mgr.lanes_dir / "tor-1"
        own.mkdir(parents=True, exist_ok=True)
        (own / "control_auth_cookie").write_bytes(b"x")
        signals = []
        control = SimpleNamespace(
            get_pid=lambda: 55, get_conf=lambda key: str(own),
            signal=signals.append, close=lambda: None)
        import stem.connection
        import stem.control
        with patch.object(stem.control.Controller, "from_port",
                          return_value=contextlib.nullcontext(control)), \
                patch.object(stem.connection, "authenticate_safecookie",
                             side_effect=TypeError(
                                 "AuthChallengeFailed.__init__() takes 3 "
                                 "positional arguments but 4 were given")) as auth:
            self.assertFalse(
                mgr._stop_orphan(55, [52301], only=own),
                "a failed auth attempt was read as proven ownership")
            self.assertEqual(signals, [], "something was shut down anyway")
            # the endpoint is asked the honest way, so a socket that fails
            # arrives as the caught ControllerError and not as a TypeError
            self.assertIs(auth.call_args.kwargs.get("suppress_ctl_errors"),
                          False, str(auth.call_args))

    def test_a_dead_endpoint_cannot_arrive_as_a_typeError(self):
        """The flag is not cosmetic: ask stem honestly, for real.

        The test above stubs the auth call out, so it proves the flag we
        pass and never what the library does with it. Here the endpoint is
        a real socket that accepts and hangs up -- a SOCKS port dialled as
        a control port, or a tor that just died -- and the ask is stem's
        own code. The default path, which reports a failed socket as an
        auth rejection, builds AuthChallengeFailed with a third argument
        its constructor does not take, so it arrives as a TypeError. Asking
        for the honest error keeps it a caught ControllerError: that is the
        whole reason a probe like this can never reach the thread boundary
        as a traceback. (If an upgrade fixes stem itself, the assertion
        below still holds.)
        """
        import stem.connection
        import stem.control

        srv = socket.socket()
        self.addCleanup(srv.close)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        port = srv.getsockname()[1]
        stop = threading.Event()
        self.addCleanup(stop.set)

        def hang_up():
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                conn.close()

        threading.Thread(target=hang_up, daemon=True).start()
        cookie = self.root / "control_auth_cookie"
        cookie.write_bytes(os.urandom(32))      # a SAFECOOKIE is 32 bytes

        def ask(suppress):
            ctl = stem.control.Controller.from_port(port=port)
            try:
                stem.connection.authenticate_safecookie(
                    ctl, cookie_path=str(cookie),
                    suppress_ctl_errors=suppress)
                return None
            except Exception as exc:  # noqa: BLE001
                return exc
            finally:
                ctl.close()

        print(f"  stem's suppressing default -> {ask(True)!r}")
        honest = ask(False)
        print(f"  asked honestly           -> {honest!r}")
        self.assertNotIsInstance(
            honest, TypeError,
            "a dead endpoint still arrives as a TypeError, so the probe can "
            "escape its own except clause again")
        self.assertIsInstance(honest, stem.ControllerError)

    def test_unrelated_real_listener_survives(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            manager = TorManager(self.root, count=1, socks_base=port,
                                 control_base=port + 1, exit_countries=["de"])
            with patch.object(netutil.subprocess, "run", side_effect=AssertionError("unsafe kill")):
                self.assertEqual(manager._reap_orphans(), 0)
            self.assertTrue(netutil.port_is_open("127.0.0.1", port))

    def test_fragmented_socks_and_deadline(self):
        def exact(sock, size):
            data = b""
            while len(data) < size:
                chunk = sock.recv(size - len(data))
                if not chunk: return data
                data += chunk
            return data
        for auth in (False, True):
            for slow in (False, True):
                left, right = socket.socketpair()
                left.settimeout(.2 if slow else 2)
                right.settimeout(3)
                errors = []
                def server():
                    try:
                        head = exact(right, 2)
                        exact(right, head[1])
                        right.sendall(b"\x05")
                        time.sleep(.02)
                        right.sendall(b"\x02" if auth else b"\x00")
                        if auth:
                            header = exact(right, 2)
                            exact(right, header[1])
                            size = exact(right, 1)[0]
                            exact(right, size)
                            right.sendall(b"\x01\x00")
                        req = exact(right, 5)
                        exact(right, req[4] + 2)
                        for part in (b"\x05", b"\x00", b"\x00", b"\x01", b"\x00" * 6):
                            if slow: time.sleep(.08)
                            right.sendall(part)
                    except (ConnectionError, OSError) as exc:
                        if not slow: errors.append(repr(exc))
                    finally:
                        right.close()
                thread = threading.Thread(target=server)
                thread.start()
                start = time.monotonic()
                result = netutil.socks5_open(left, "opencode.ai", 443,
                                            cred=netutil.lane_cred(1) if auth else None)
                elapsed = time.monotonic() - start
                self.assertEqual(result, "timed out" if slow else "")
                self.assertEqual(left.gettimeout(), .2 if slow else 2)
                if slow: self.assertLess(elapsed, .35)
                left.close()
                thread.join(4)
                self.assertFalse(thread.is_alive())
                self.assertEqual(errors, [])

    def test_malformed_update_fields_and_cache(self):
        current = update.current_version()
        for bad in (999, ["9.9.9"], {"version": "9.9.9"}, "junk999"):
            self.assertFalse(update.behind({"latest": bad}))
            self.assertEqual(update.notice_lines({"latest": bad}), [])
        self.assertEqual(len(update.notice_lines(
            {"latest": "9.9.9", "notice": ["bad"]}, mode_name="notify")), 1)
        cache = self.root / update.CACHE_NAME
        cache.write_text(json.dumps({"latest": 999, "notice": ["bad"],
                                     "checked_at": time.time()}))
        self.assertIsNone(update.read_cache(self.root)["latest"])
        with patch.object(update, "_get_json", side_effect=[
                {"schema": 1, "latest": 999, "notice": ["bad"]},
                {"info": {"version": current}}]):
            self.assertEqual(update.check(self.root, force=True)["latest"], current)
        with patch.object(cli, "DATA_DIR", self.root), \
                patch.dict(os.environ, {"LINGLING_UPDATE": "auto"}), \
                patch.object(update, "spawn_deferred") as install:
            cli._say_update(SimpleNamespace(info={"latest": 999, "notice": ["bad"]}))
            install.assert_not_called()

    def test_service_stopped_after_spawn_error(self):
        for failure in (False, True):
            actions = []
            def run(cmd, **kw):
                if cmd[-1] == "--help":
                    return SimpleNamespace(stdout="--standalone", returncode=0)
                actions.append(cmd[-1])
                return SimpleNamespace(stdout="", returncode=0)
            def popen(*a, **k):
                if failure: raise FileNotFoundError("fixture")
                return SimpleNamespace(wait=lambda: 0)
            with patch.object(cli, "_SERVER_ERA", None), \
                    patch.object(cli.subprocess, "run", side_effect=run), \
                    patch.object(cli.subprocess, "Popen", side_effect=popen), \
                    contextlib.redirect_stdout(io.StringIO()):
                result = cli._run_opencode("fake", [], {"HTTPS_PROXY": "http://127.0.0.1:1"})
            self.assertEqual(actions, ["restart", "stop"])
            self.assertEqual(result, 1 if failure else 0)


if __name__ == "__main__":
    unittest.main()
