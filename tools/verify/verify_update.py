"""`lingling update`, and the check that rides a launch.

Two properties matter more than any other, and both are about what does
*not* happen.

The launch must not wait. A stale build is a nuisance; a boot that hangs
on a dead endpoint is a bug. So the check is a thread with a deadline, and
these tests run it against a local server, including a black hole that
accepts connections and never answers.

The install must not land under a running lingling. On Windows the console
launcher is the running image and `pip install --upgrade` wants to replace
it, so the default path hands the install to a helper that waits for the
process to exit. The test for that is the two-sided one in section 8: no
install while a process is alive, install once it is gone. Both halves
have to hold, or the fix is worse than the bug.

Everything is local: a throwaway data dir via LINGLING_DATA_DIR, a manifest
served from a thread on 127.0.0.1, and the registry redirected at it too --
except in section 9, where a real PyPI answer is the point.

    python tools/verify/verify_update.py
"""
import contextlib
import io
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from lingling import update  # noqa: E402

FAILS = []
DIRS = []
CURRENT = update.current_version()
PAYLOAD = {}
HITS = []


def check(name, ok, detail=""):
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name}" + (f" -- {detail}" if (detail and not ok) else ""))
    if not ok:
        FAILS.append(name)


def scratch() -> pathlib.Path:
    d = pathlib.Path(tempfile.mkdtemp(prefix="ll-upd-"))
    DIRS.append(d)
    return d


def cleanup() -> None:
    for d in DIRS:
        shutil.rmtree(d, ignore_errors=True)
    for d in pathlib.Path(tempfile.gettempdir()).glob("ll-upd-*"):
        shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# a manifest, on this machine
# ---------------------------------------------------------------------------

class _Server(BaseHTTPRequestHandler):
    def do_GET(self):
        HITS.append(self.path)
        if self.path.startswith("/pypi"):
            body = {"info": {"version": PAYLOAD.get("pypi")}}
        else:
            body = PAYLOAD.get("manifest") or {}
        raw = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        return


def serve() -> str:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Server)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_address[1]}"


def blackhole() -> str:
    """A listener that accepts and never replies -- the hang, by name."""
    held = []
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)

    def eat():
        while True:
            try:
                conn, _ = srv.accept()
                held.append(conn)
            except OSError:
                return

    threading.Thread(target=eat, daemon=True).start()
    return f"http://127.0.0.1:{srv.getsockname()[1]}"


def manifest(latest=None, notice=None, floor=None, schema=1):
    return {"schema": schema, "package": "lingling", "latest": latest,
            "min_supported": floor, "notice": notice,
            "url": "https://pypi.org/project/lingling/"}


def env_for(url, extra=None):
    env = dict(os.environ)
    env["LINGLING_UPDATE_URL"] = url
    for key in ("LINGLING_UPDATE", "LINGLING_UPDATE_CMD",
                "LINGLING_NO_UPDATE_CHECK", "LINGLING_DATA_DIR"):
        env.pop(key, None)
    env.update(extra or {})
    return env


def run_cli(args, data_dir, env):
    env = dict(env, LINGLING_DATA_DIR=str(data_dir))
    res = subprocess.run([sys.executable, "-m", "lingling", *args],
                         cwd=str(ROOT), env=env, stdin=subprocess.DEVNULL,
                         capture_output=True, text=True, timeout=180)
    return res.returncode, res.stdout + res.stderr


@contextlib.contextmanager
def patched(**attrs):
    old = {k: getattr(update, k) for k in attrs}
    for k, v in attrs.items():
        setattr(update, k, v)
    try:
        yield
    finally:
        for k, v in old.items():
            setattr(update, k, v)


@contextlib.contextmanager
def argv(values):
    old = sys.argv
    sys.argv = list(values)
    try:
        yield
    finally:
        sys.argv = old


@contextlib.contextmanager
def env_swap(**vars):
    old = {k: os.environ.get(k) for k in vars}
    for k, v in vars.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def captures(fn):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = fn()
    return code, buf.getvalue()


# ---------------------------------------------------------------------------
# sections
# ---------------------------------------------------------------------------

def section_versions():
    print("=== 1. ordering: a post release sorts after its release ===")
    cases = [
        ("2.1.21", "2.1.20.post23", True),
        ("2.1.20.post24", "2.1.20.post23", True),
        ("2.1.20.post10", "2.1.20.post9", True),
        ("2.1.20.post23", "2.1.20", True),
        ("2.1.20", "2.1.20.post23", False),
        ("2.1.20.post23", "2.1.20.post23", False),
        ("2.1.19.post5", "2.1.20", False),
        ("2.2.0", "2.1.99", True),
        ("v2.1.21", "2.1.20", True),
        ("", "2.1.20", False),
        (None, "2.1.20", False),
        ("garbage", "2.1.20", False),
    ]
    bad = [f"{a} > {b} should be {w}" for a, b, w in cases
           if update.is_newer(a, b) is not w]
    check("every ordering case holds", not bad, "; ".join(bad))
    check("a post release does not outrank a higher patch",
          update.key("2.1.20.post23") < update.key("2.1.21"))


def section_check(url):
    print("\n=== 2. the check: manifest first, registry as the fallback ===")
    data = scratch()
    # PYPI_URL is patched too, not just the manifest URL: leaving it alone
    # would let the fallback reach the real registry, so "both sources are
    # down" would quietly mean "PyPI answered" and the negative cases below
    # would pass or fail depending on whether this machine is online.
    with patched(PYPI_URL=url + "/pypi"), env_swap(LINGLING_UPDATE_URL=url):
        PAYLOAD["manifest"] = manifest(latest="9.9.9")
        PAYLOAD["pypi"] = "9.9.9"
        HITS.clear()
        info = update.check(data, force=True, timeout=3.0)
        check("a newer version is reported", info.get("latest") == "9.9.9",
              str(info))
        check("it came from the manifest", info.get("source") == "manifest",
              str(info.get("source")))
        check("the registry was not needed",
              not any(h.startswith("/pypi") for h in HITS), str(HITS))
        check("and it is behind", update.behind(info))

    print("\n=== 3. silence in every direction that is not an update ===")
    with patched(PYPI_URL=url + "/pypi"), env_swap(LINGLING_UPDATE_URL=url):
        PAYLOAD["manifest"] = manifest(latest=CURRENT)
        PAYLOAD["pypi"] = CURRENT
        info = update.check(data, force=True, timeout=3.0)
        check("up to date is not behind", not update.behind(info))
        check("up to date says nothing",
              update.notice_lines(info, mode_name="auto") == [])

        PAYLOAD["manifest"] = manifest(latest="9.9.9", schema=2)
        PAYLOAD["pypi"] = "9.9.9"
        HITS.clear()
        info = update.check(data, force=True, timeout=3.0)
        check("an unknown schema is not guessed at",
              info.get("source") == "pypi"
              and any(h.startswith("/pypi") for h in HITS),
              f"source={info.get('source')} hits={HITS}")

        PAYLOAD["manifest"] = manifest(latest=None)
        PAYLOAD["pypi"] = None
        info = update.check(data, force=True, timeout=3.0)
        check("both sources down reports no version, not a version",
              info.get("latest") is None, str(info))
        check("and stays silent",
              update.notice_lines(info, mode_name="auto") == [])

    print("\n=== 4. a dead endpoint costs a launch nothing ===")
    dead = blackhole()
    data2 = scratch()
    with patched(TIMEOUT=1.0, BUDGET=2.0), env_swap(LINGLING_UPDATE_URL=dead):
        t0 = time.time()
        obj = update.start(data2)
        elapsed = time.time() - t0
        check("the check starts without waiting for the answer",
              elapsed < 0.5, f"start() took {elapsed:.2f}s")
        info = obj.wait(15) if obj else None
        # PyPI is still reachable from here, so what matters is not the
        # value but that a real answer arrived inside the budget.
        check("the thread finishes inside its budget", obj is not None
              and obj.done.is_set(), "the check thread never finished")
        check("a black-holed endpoint is never read as a version",
              (info or {}).get("source") != "manifest", str(info))

    print("\n=== 5. the cache: one request per window, negatives expire early ===")
    data3 = scratch()
    with env_swap(LINGLING_UPDATE_URL=url):
        PAYLOAD["manifest"] = manifest(latest="9.9.9")
        PAYLOAD["pypi"] = "9.9.9"
        HITS.clear()
        update.check(data3, force=True, timeout=3.0)
        first = len(HITS)
        for _ in range(4):
            update.check(data3, timeout=3.0)
        check("a cached answer is reused without asking again",
              len(HITS) == first, f"{len(HITS)} requests for 5 checks")

    good = {"latest": "9.9.9", "checked_at": time.time()}
    bad = {"latest": None, "checked_at": time.time()}
    check("a good answer lives for hours", update.fresh(good))
    check("a negative answer expires sooner",
          update.fresh(bad) and not update.fresh(
              bad, now=time.time() + update.FAIL_TTL + 1))
    check("a good answer eventually expires too",
          not update.fresh(good, now=time.time() + update.CACHE_TTL + 1))
    check("a timestamp from the future is not trusted",
          not update.fresh(bad, now=time.time() - 10))

    print("\n=== 6. the notice says what to do ===")
    newer = {"latest": "9.9.9", "min_supported": None, "notice": None}
    lines = update.notice_lines(newer, CURRENT, "notify")
    check("it names both versions",
          len(lines) == 1 and "9.9.9" in lines[0] and CURRENT in lines[0],
          str(lines))
    check("notify mode gives you the command",
          "lingling update" in lines[0], str(lines))
    auto = update.notice_lines(newer, CURRENT, "auto")
    check("auto mode says the install lands after the session",
          "installs when this session ends" in auto[0], str(auto))
    check("off mode says nothing at all",
          update.notice_lines(newer, CURRENT, "off") == [])

    floored = {"latest": "9.9.9", "min_supported": "9.0.0", "notice": None}
    lines = update.notice_lines(floored, CURRENT, "auto")
    check("a build below the floor is told to update, not offered it",
          any("needs 9.0.0 or newer" in ln for ln in lines), str(lines))

    noted = {"latest": "9.9.9", "min_supported": None,
             "notice": "opencode changed its server; update to ride."}
    lines = update.notice_lines(noted, CURRENT, "notify")
    check("a hand-written notice is shown",
          lines and lines[0].strip().startswith("opencode changed"), str(lines))
    same = {"latest": CURRENT, "min_supported": None, "notice": "stale note"}
    check("a notice never shows to a build that is already current",
          update.notice_lines(same, CURRENT, "auto") == [])


def section_install():
    print("\n=== 7. how this copy would install, and with what ===")
    cmd = update.upgrade_command()
    check("the default is pip against this interpreter",
          cmd[1:4] == ["-m", "pip", "install"] and cmd[-1] == "lingling",
          str(cmd))
    check("it upgrades rather than reinstalls", "--upgrade" in cmd, str(cmd))

    with env_swap(LINGLING_UPDATE_CMD='"/my python" -m thing --go',
                  LINGLING_UPDATE=None):
        got = update.upgrade_command()
        check("an override wins over pip",
              got == ["/my python", "-m", "thing", "--go"], str(got))

    print("\n=== 8. the decision: who gets scheduled, and who does not ===")
    spawned = []
    data = scratch()
    with patched(spawn_deferred=lambda dd, delay=None: (
            spawned.append(dd), 4242)[1]):
        with env_swap(LINGLING_UPDATE="notify"):
            got = update.auto_install(data, {"latest": "9.9.9"})
            check("notify mode never schedules an install",
                  got is None and not spawned, f"pid={got} spawned={spawned}")
        with env_swap(LINGLING_UPDATE="off"):
            got = update.auto_install(data, {"latest": "9.9.9"})
            check("off mode never schedules an install",
                  got is None and not spawned, f"pid={got} spawned={spawned}")
        with env_swap(LINGLING_UPDATE="auto"):
            got = update.auto_install(data, {"latest": "9.9.9"})
            check("auto mode schedules exactly one",
                  got == 4242 and len(spawned) == 1,
                  f"pid={got} spawned={spawned}")
            got = update.auto_install(data, {"latest": CURRENT})
            check("and an up-to-date build never schedules one",
                  got is None and len(spawned) == 1, str(spawned))
            got = update.auto_install(data, None)
            check("neither does a lookup that came back empty",
                  got is None and len(spawned) == 1, str(spawned))

    method = update.install_method()
    check("the install method is one we know how to upgrade",
          method in ("pip", "pipx", "uv"), method)

    section_launcher()


def section_launcher():
    """The one file an upgrade cannot replace while lingling runs.

    Both halves of this were wrong in the first cut, and both were found
    by running it rather than by reading it: a pip console script reports
    ``argv[0]`` with no extension, and ``sys.executable``'s directory is
    not the script directory in a global install. Either mistake makes
    the parking below dead code, which is invisible until pip has to move
    the running image itself.
    """
    print("\n=== 9. the launcher lock: which file, and when to park it ===")
    fake = scratch()
    real_dir = update.scripts_dir()
    check("the script directory is a real directory, and not the interpreter's",
          isinstance(real_dir, pathlib.Path) and real_dir.is_dir(),
          str(real_dir))
    check("it is the one sysconfig names, not sys.executable's parent",
          str(real_dir) != str(pathlib.Path(sys.executable).parent)
          or (real_dir / "lingling.exe").is_file(),
          f"scripts={real_dir} executable={pathlib.Path(sys.executable).parent}")

    with patched(scripts_dir=lambda: fake):
        check("nothing to park when there is no launcher there",
              update._running_launcher() is None)
        exe = fake / "lingling.exe"
        exe.write_bytes(b"MZ")

        with argv([str(fake / "lingling")]):
            check("a console script without the .exe suffix IS the launcher",
                  update._running_launcher() == exe,
                  "argv[0] without .exe was not recognised -- the measured "
                  "shape of a pip console script")
        with argv([str(exe)]):
            check("and with the suffix, too", update._running_launcher() == exe)
        with argv(["-c"]):
            check("a -c run holds no lock", update._running_launcher() is None)
        with argv([str(ROOT / "lingling" / "__main__.py")]):
            check("neither does `python -m lingling`",
                  update._running_launcher() is None)

    print("\n=== 10. sweeping what a previous upgrade could not delete ===")
    parked = fake / f"lingling.exe.old-12345"
    parked.write_bytes(b"MZ")
    (fake / "lingling.exe.old-999").mkdir()
    with patched(scripts_dir=lambda: fake):
        update.sweep_launcher_leftovers()
    check("a parked launcher is removed", not parked.exists())
    check("and a directory that merely shares the name does not raise",
          (fake / "lingling.exe.old-999").is_dir())
    check("nothing else in the script directory was touched",
          (fake / "lingling.exe").is_file())


def section_deferral():
    print("\n=== 11. the install waits for this process to die ===")
    data = scratch()
    marker = data / "installed.txt"
    script = data / "marker.py"
    # Writes its own argv, so the assertion can see *which* installer ran.
    script.write_text(
        "import pathlib, sys\n"
        "pathlib.Path(sys.argv[1]).write_text(' '.join(sys.argv))\n",
        encoding="utf-8")

    # The child stands in for a live session: it schedules the install and
    # then keeps running. That window is the one that must be safe.
    child = (
        "import sys, time\n"
        f"sys.path.insert(0, {str(ROOT)!r})\n"
        "from lingling import update\n"
        "pid = update.spawn_deferred(sys.argv[1])\n"
        "print('helper', pid, flush=True)\n"
        "time.sleep(5)\n"
    )
    env = env_for("", {"LINGLING_UPDATE_CMD":
                       f'"{sys.executable}" "{script}" "{marker}"'})
    proc = subprocess.Popen([sys.executable, "-c", child, str(data)],
                            cwd=str(ROOT), env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    try:
        time.sleep(2.0)
        check("no install lands while the process is alive",
              not marker.exists(), "the marker appeared mid-session")
        log = data / "update.log"
        check("it was scheduled all the same", log.exists(),
              "no update.log written")
        out = proc.communicate(timeout=60)[0] or ""
        check("the child ran cleanly", proc.returncode == 0,
              f"exit {proc.returncode}: {out}")
        check("a helper process was actually spawned",
              "helper" in out and "None" not in out.split("helper")[-1][:8],
              out[:160])
        deadline = time.time() + 30
        while time.time() < deadline and not marker.exists():
            time.sleep(0.25)
        check("and it installs once the process is gone", marker.exists(),
              "the marker never appeared")
    finally:
        if proc.poll() is None:
            proc.kill()

    text = (data / "update.log").read_text(encoding="utf-8",
                                           errors="replace") \
        if (data / "update.log").exists() else ""
    check("the log says who scheduled it",
          "scheduled by lingling" in text, text[:200])
    check("and what it ran", "running:" in text, text[:200])
    if marker.exists():
        check("the configured installer is what ran",
              "marker.py" in marker.read_text(encoding="utf-8"),
              marker.read_text(encoding="utf-8"))


def section_command(url):
    print("\n=== 12. `lingling update`, as the user runs it ===")
    data = scratch()
    PAYLOAD["manifest"] = manifest(latest="9.9.9")
    PAYLOAD["pypi"] = "9.9.9"

    code, out = run_cli(["update", "--help"], data, env_for(url))
    check("--help exits 0", code == 0, f"code={code}")
    check("it prints lingling's help, not opencode's",
          "move to the newest lingling" in out and "npm uninstall" not in out,
          out[:200])
    # Collapse the wrapping: the help is prose, and a phrase that reads as
    # one sentence on screen can straddle a newline in the captured text.
    flat = " ".join(out.split())
    check("the bootstrap truth is stated in the help",
          "cannot check can never learn it is stale" in flat, flat[:300])

    before = update.installed_version()
    code, out = run_cli(["update", "--check"], data, env_for(url))
    check("--check exits 0", code == 0, f"code={code} {out[:200]}")
    check("it reports what is installed and what is available",
          CURRENT in out and "9.9.9" in out, out[:300])
    # Compared against itself rather than against the source tree. On a
    # working copy the tree is normally one revision ahead of whatever pip
    # last installed, and demanding the two match failed for a reason that
    # had nothing to do with --check.
    check("--check changes nothing on this machine",
          update.installed_version() == before,
          f"{before} -> {update.installed_version()}")
    check("and schedules no install", not (data / "update.log").exists(),
          "update.log exists")

    code, out = run_cli(["update", "--check"], data,
                        env_for(url, {"LINGLING_UPDATE": "off"}))
    check("an explicit command is not gated by the launch switch",
          code == 0 and "9.9.9" in out, f"code={code} {out[:200]}")

    code, out = run_cli(["--version"], data, env_for(url))
    check("--version still prints just the version",
          code == 0 and f"lingling {CURRENT}" in out, out[:150])

    print("\n=== 13. a schedule really runs the configured installer ===")
    data2 = scratch()
    marker = data2 / "ran.txt"
    script = data2 / "fake_install.py"
    script.write_text(
        "import pathlib, sys\n"
        "pathlib.Path(sys.argv[1]).write_text(' '.join(sys.argv))\n",
        encoding="utf-8")
    env = env_for(url, {"LINGLING_UPDATE_CMD":
                        f'"{sys.executable}" "{script}" "{marker}"'})
    code, out = run_cli(["update"], data2, env)
    check("update schedules rather than installing in place",
          code == 0 and "scheduled" in out, f"code={code} {out[:250]}")
    check("and it says where the progress goes",
          "update.log" in out, out[:250])
    deadline = time.time() + 30
    while time.time() < deadline and not marker.exists():
        time.sleep(0.25)
    check("the scheduled command really ran after the process exited",
          marker.exists(), "the marker never appeared")
    if marker.exists():
        check("it was the configured installer, not pip",
              "fake_install.py" in marker.read_text(encoding="utf-8"),
              marker.read_text(encoding="utf-8"))

    print("\n=== 14. a server that answers nothing is not 'up to date' ===")
    data3 = scratch()
    nothing = {"latest": None, "min_supported": None, "notice": None,
               "url": None, "source": None}
    with patched(_lookup=lambda timeout: dict(nothing)), \
            env_swap(LINGLING_DATA_DIR=str(data3)):
        code, out = captures(lambda: update.update_command(["--check"]))
    check("it exits non-zero", code != 0, f"code={code}")
    check("it says it could not reach the servers",
          "could not reach" in out, out[:250])
    check("and never claims to be current",
          "newest" not in out, out[:250])
    check("it offers the command to do it by hand",
          "install by hand" in out, out[:250])


def section_wiring(url):
    print("\n=== 15. the launch path, by source ===")
    src = (ROOT / "lingling" / "cli.py").read_text(encoding="utf-8")
    check("`update` is routed beside `uninstall`",
          '("update", "--update")' in src
          and src.index('("update", "--update")')
          < src.index("opts = _parse_args"),
          "the route is missing or comes too late")
    check("the check starts before the loader is built",
          src.index("update.start(DATA_DIR)") < src.index("loader = _Loader()"),
          "the check would sit in front of the boot")
    check("the notice is held until the spinner is done",
          src.index("_say_update(update_check)")
          > src.index("loader.stop("),
          "a notice printed under a live spinner is erased by it")
    check("both handoff paths emit it",
          src.count("_say_update(update_check)") >= 2,
          f"{src.count('_say_update(update_check)')} call sites")
    check("the version line reads cache only",
          "update.cached_hint(DATA_DIR)" in src, "no cached hint wired in")
    body = src.split("def _say_update", 1)[1].split("\ndef ", 1)[0]
    check("one install is scheduled per session, from one place",
          body.count("auto_install") == 1 and src.count("auto_install") == 1,
          f"{src.count('auto_install')} call sites")
    check("the engine is not imported into the boot path twice",
          src.count("from . import update") == 1, "duplicate import")

    print("\n=== 16. `--version` never touches the network ===")
    data = scratch()
    HITS.clear()
    code, out = run_cli(["--version"], data, env_for(url))
    check("it prints the version", code == 0 and CURRENT in out,
          f"code={code} {out[:150]}")
    check("and made no request at all", not HITS, str(HITS))


def main() -> int:
    url = serve()
    print(f"local manifest at {url}   (lingling {CURRENT})\n")

    section_versions()
    section_check(url)
    section_install()
    section_deferral()
    section_command(url)
    section_wiring(url)

    print()
    cleanup()
    if FAILS:
        print(f"UPDATE: FAILED ({len(FAILS)})")
        for f in FAILS:
            print("  - " + f)
        return 1
    print("UPDATE: CONFIRMED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
