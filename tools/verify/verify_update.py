"""No install while a process is alive; install once it is gone."""
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
# local manifest
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
    # PYPI_URL
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
        # PyPI
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
    #: The answer every launch reads, and the one a release invalidates.
    current = {"latest": CURRENT, "checked_at": time.time()}
    check("being current is not remembered for hours",
          update.fresh(current)
          and not update.fresh(current, now=time.time() + update.UP_TTL + 1),
          f"UP_TTL={update.UP_TTL}, CACHE_TTL={update.CACHE_TTL}")
    check("a hint still lives longer than a stale all-clear",
          update.UP_TTL < update.CACHE_TTL
          and update.fresh(good, now=time.time() + update.UP_TTL + 1),
          f"UP_TTL={update.UP_TTL} CACHE_TTL={update.CACHE_TTL}")
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
    # argv[0] has
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
    # Writes
    script.write_text(
        "import pathlib, sys\n"
        "print('installer stdout line')\n"
        "print('installer stderr line', file=sys.stderr)\n"
        "pathlib.Path(sys.argv[1]).write_text(' '.join(sys.argv))\n"
        "raise SystemExit(7)\n",
        encoding="utf-8")

    # child stands
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

    log = data / "update.log"
    # exit line
    deadline = time.time() + 30
    text = ""
    while time.time() < deadline:
        text = log.read_text(encoding="utf-8", errors="replace") \
            if log.exists() else ""
        if "install exit:" in text:
            break
        time.sleep(0.25)
    lines = [ln.strip() for ln in text.splitlines()]
    check("the log says who scheduled it",
          "scheduled by lingling" in text, text[:200])
    check("and what it ran", "running:" in text, text[:200])
    check("the installer's own output reaches the log",
          "installer stdout line" in lines
          and "installer stderr line" in lines, text[-300:])
    check("and the exit code, so a failed install cannot pass as quiet",
          "install exit: 7" in lines, text[-300:])
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
    # Collapse
    flat = " ".join(out.split())
    check("the bootstrap truth is stated in the help",
          "cannot check can never learn it is stale" in flat, flat[:300])

    before = update.installed_version()
    code, out = run_cli(["update", "--check"], data, env_for(url))
    check("--check exits 0", code == 0, f"code={code} {out[:200]}")
    check("it reports what is installed and what is available",
          CURRENT in out and "9.9.9" in out, out[:300])
    # Compared against
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
    check("and never claims to be current", "newest" not in out, out[:250])
    check("it offers the command to do it by hand",
          "install by hand" in out, out[:250])


def section_job():
    """The bug that made the whole feature useless in the field"""
    print("\n=== 17. the installer escapes the Windows kill job ===")
    if os.name != "nt":
        print("  (not Windows -- no job object to escape)")
        return
    data = scratch()
    escaped = data / "escaped.txt"
    killed = data / "killed.txt"
    quick = data / "mark.py"
    slow = data / "slow.py"
    quick.write_text("import pathlib, sys\n"
                     "pathlib.Path(sys.argv[1]).write_text('ran')\n",
                     encoding="utf-8")
    slow.write_text("import pathlib, sys, time\n"
                    "time.sleep(6)\n"
                    "pathlib.Path(sys.argv[1]).write_text('ran')\n",
                    encoding="utf-8")
    # child joins
    child = (
        "import subprocess, sys\n"
        f"sys.path.insert(0, {str(ROOT)!r})\n"
        "from lingling import winjob, update\n"
        "print('job joined:', winjob.ensure_kill_job(), flush=True)\n"
        "subprocess.Popen([sys.executable, sys.argv[3], sys.argv[2]])\n"
        "print('helper pid:', update.spawn_deferred(sys.argv[1]), flush=True)\n"
    )
    env = env_for("", {"LINGLING_UPDATE_CMD":
                       f'"{sys.executable}" "{quick}" "{escaped}"'})
    res = subprocess.run(
        [sys.executable, "-c", child, str(data), str(killed), str(slow)],
        cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=180)
    print("   " + " | ".join(res.stdout.strip().splitlines())[:150])
    deadline = time.time() + 40
    while time.time() < deadline and not escaped.exists():
        time.sleep(0.25)
    check("the detached installer outlives the job that owns us",
          escaped.exists(),
          "the job killed it -- so no session would ever install an update")
    # Give
    waited = time.time() + 9
    while time.time() < waited:
        time.sleep(0.5)
    check("and an ordinary child of the same job really does die",
          not killed.exists(),
          "the control survived, so the kill job was not in force and the "
          "check above proves nothing")


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


def _visible_console_windows() -> int:
    """How many VISIBLE console windows this desktop has right now."""
    import ctypes

    user32 = ctypes.windll.user32
    n = [0]
    cb_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p,
                                 ctypes.c_void_p)

    def cb(hwnd, _lparam):
        if user32.IsWindowVisible(hwnd):
            buf = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, buf, 256)
            if "Console" in buf.value:
                n[0] += 1
        return True

    user32.EnumWindows(cb_type(cb), None)
    return n[0]


class _WindowWatcher(threading.Thread):
    """Peak count of visible console windows while this runs."""

    def __init__(self):
        super().__init__(daemon=True)
        self.baseline = _visible_console_windows()
        self.peak = self.baseline
        self._halt = False  # not _stop

    def run(self):
        while not self._halt:
            self.peak = max(self.peak, _visible_console_windows())
            time.sleep(0.02)

    def finish(self):
        self._halt = True
        self.join()


#: DETACHED_PROCESS |
_DETACHED = 0x00000008 | 0x00000200


#: CREATE_NO_WINDOW. Unflagged
_NO_FLAGS = 0


def _shake(data, flags, env):
    """Run one of the two spawners detached; return the window peak."""
    w = _WindowWatcher()
    w.start()
    proc = subprocess.Popen([sys.executable, *data], creationflags=_DETACHED,
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, env=env)
    proc.wait(timeout=180)
    time.sleep(0.3)
    w.finish()
    return w


def section_nowindow():
    """The helper must not flash a terminal twice a second"""
    print("\n=== 18. the installer helper cannot flash a console window ===")
    if os.name != "nt":
        print("  (not Windows -- no console allocation to suppress)")
        return
    data = scratch()
    helper = data / "helper.py"
    helper.write_text(update._HELPER, encoding="utf-8")
    env = dict(os.environ, LINGLING_HELPER_WAIT="6")

    w = _shake([str(helper), str(os.getpid())], _NO_FLAGS, env)
    print(f"   helper polled for 6s: baseline={w.baseline} peak={w.peak}")
    check("polling for a live lingling opens no window",
          w.peak == w.baseline,
          f"peaked at {w.peak} visible console windows from {w.baseline} -- "
          "a terminal flashing for the whole session")

    # installer
    touched = data / "installer-ran.txt"
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    run = _shake([str(helper), str(dead.pid), sys.executable, "-c",
                  f"import pathlib, time; "
                  f"pathlib.Path({str(touched)!r}).write_text('ran'); "
                  f"time.sleep(2)"], _NO_FLAGS, env)
    print(f"   helper installing for ~2s: baseline={run.baseline} "
          f"peak={run.peak}")
    check("the watcher saw the installer run", touched.exists(),
          "the stand-in installer never wrote its file")
    check("and running the installer opens no window either",
          run.peak == run.baseline,
          f"peaked at {run.peak} visible console windows from {run.baseline}")

    burst = data / "burst.py"
    burst.write_text(
        "import subprocess\n"
        "argv = ['tasklist', '/FI', 'PID eq 0', '/NH']\n"
        "for _ in range(20):\n"
        "    subprocess.Popen(argv, stdin=subprocess.DEVNULL,\n"
        "                     stdout=subprocess.DEVNULL,\n"
        "                     stderr=subprocess.DEVNULL).wait()\n",
        encoding="utf-8")
    ctl = _shake([str(burst)], _NO_FLAGS, env)
    check("control: the same poll without the flag DOES open one",
          ctl.peak > ctl.baseline,
          "the sampler saw nothing even without the flag, so the check "
          "above proves nothing")


def section_question():
    """Who gets asked, and -- the point -- who does not"""
    print("\n=== 19. an update is offered, and only to someone who can answer ===")
    newer = {"latest": "9.9.9", "min_supported": None, "notice": None}
    current = {"latest": CURRENT, "min_supported": None, "notice": None}

    with env_swap(LINGLING_UPDATE="auto"), \
            patched(_at_terminal=lambda: True, _pending_input=lambda: False):
        check("a terminal with an update waiting is asked", update.askable(newer))
        check("a terminal with nothing to install is not",
              not update.askable(current) and not update.askable(None),
              "silence in every direction that is not an update")
    with env_swap(LINGLING_UPDATE="auto"), \
            patched(_at_terminal=lambda: False, _pending_input=lambda: False):
        check("a launch nobody can be asked is not asked",
              not update.askable(newer),
              "a redirected launch must fall back to the silent install")
    with env_swap(LINGLING_UPDATE="auto"), \
            patched(_at_terminal=lambda: True, _pending_input=lambda: True):
        check("a line already typed ahead is never eaten by the question",
              not update.askable(newer),
              "reading it would hand opencode an empty first prompt")
    for mode_name in ("notify", "off"):
        with env_swap(LINGLING_UPDATE=mode_name), \
                patched(_at_terminal=lambda: True,
                        _pending_input=lambda: False):
            check(f"{mode_name} mode is never asked",
                  not update.askable(newer))

    class _Tty:
        """An isatty that says yes: the shape the console guard exists for."""

        def isatty(self):
            return True

    class _NotTty:
        def isatty(self):
            return False

    check("a redirected output is never asked",
          not update._at_terminal(_NotTty()))
    if os.name == "nt":
        check("a Windows terminal must have a real console behind it",
              update._at_terminal(_Tty()) == update._console_stdin(),
              f"at_terminal={update._at_terminal(_Tty())} "
              f"console={update._console_stdin()} -- isatty alone asks a "
              f"launch that can only answer with EOF, and the EOF is a no")
    else:
        check("a POSIX terminal is the one the OS calls a tty",
              update._at_terminal(_Tty()) == sys.stdin.isatty())
    src = (ROOT / "lingling" / "update.py").read_text(encoding="utf-8")
    guard = src.split("def _console_stdin", 1)[1].split("\ndef ", 1)[0]
    terminal = src.split("def _at_terminal", 1)[1].split("\ndef ", 1)[0]
    check("the Windows answer is the OS's own console check",
          "GetConsoleMode" in guard and "-10" in guard, guard[:160])
    check("and that is what the terminal test consults on Windows",
          "_console_stdin()" in terminal, terminal[:160])


def section_answers():
    """What each answer does, at the one place that schedules an install."""
    print("\n=== 20. Enter installs, n skips, and nothing else drops it ===")
    data = scratch()
    newer = {"latest": "9.9.9", "min_supported": None, "notice": None}

    def answer(text):
        """Drive one answer through the real scheduler, faking the read."""
        stream = io.StringIO()
        prompts = []

        def read(prompt, out):
            prompts.append(prompt)
            return text

        with patched(spawn_deferred=lambda dd, delay=None: 4242), \
                env_swap(LINGLING_UPDATE="auto"):
            pid = update.auto_install(data, newer, ask=True, read=read,
                                      stream=stream)
        return pid, prompts, stream.getvalue()

    pid, prompts, out = answer("")
    check("a bare Enter installs it", pid == 4242, f"pid={pid}")
    check("the question says which answer is the default",
          prompts == [update.PROMPT] and "[Y/n]" in prompts[0], str(prompts))
    check("and Enter declares nothing skipped", "skipped" not in out, out)

    for yes in ("y", "Y", "yes", "YES"):
        pid, _, out = answer(yes)
        check(f"`{yes}` installs it", pid == 4242, f"pid={pid}")

    for no in ("n", "N", "no", "  NO  "):
        pid, _, out = answer(no)
        check(f"`{no}` does not", pid is None, f"pid={pid}")
        check(f"and `{no}` says how to get it later",
              "lingling update" in out and "notify" in out, out)

    pid, _, out = answer("what?")
    check("an answer that is neither still installs, it never drops one quietly",
          pid == 4242 and "skipped" not in out, f"pid={pid} out={out!r}")

    asked = []

    def never(prompt, out):
        asked.append(prompt)
        return "n"

    with patched(spawn_deferred=lambda dd, delay=None: 4242), \
            env_swap(LINGLING_UPDATE="notify"):
        pid = update.auto_install(data, newer, ask=True, read=never,
                                  stream=io.StringIO())
    check("an offer in notify mode is never even read",
          pid is None and not asked, f"pid={pid} asked={asked}")
    with patched(spawn_deferred=lambda dd, delay=None: 4242), \
            env_swap(LINGLING_UPDATE="auto"):
        pid = update.auto_install(data, {"latest": CURRENT}, ask=True,
                                  read=never, stream=io.StringIO())
    check("and an up-to-date build is not asked either",
          pid is None and not asked, f"pid={pid} asked={asked}")


def section_read():
    """The read itself: prompt first, and every interruption is a no."""
    print("\n=== 21. the read: the question is written before anything waits ===")
    import builtins
    real_input = builtins.input
    try:
        for exc in (EOFError, KeyboardInterrupt):
            stream = io.StringIO()

            def raised(_exc=exc):
                raise _exc()

            builtins.input = raised
            got = update._ask("  q? [Y/n] ", stream)
            check(f"{exc.__name__} reads as no", got == "n", repr(got))
            check(f"and {exc.__name__} closes the line instead of gluing the "
                  f"next output to the question",
                  stream.getvalue() == "  q? [Y/n] \n", repr(stream.getvalue()))

        stream = io.StringIO()
        builtins.input = lambda: "y"
        check("an answered question still returns the answer",
              update._ask("  q? ", stream) == "y")
        check("and the prompt was written before the read, not after",
              stream.getvalue() == "  q? ", repr(stream.getvalue()))
    finally:
        builtins.input = real_input


def section_notice_ask():
    """The notice and the question must not contradict each other."""
    print("\n=== 22. the notice stops promising when it is about to ask ===")
    newer = {"latest": "9.9.9", "min_supported": None, "notice": None}
    asked = update.notice_lines(newer, CURRENT, "auto", ask=True)
    check("asked: it names the versions and stops",
          len(asked) == 1 and "9.9.9" in asked[0] and CURRENT in asked[0]
          and "installs when this session ends" not in asked[0], str(asked))
    plain = update.notice_lines(newer, CURRENT, "auto")
    check("unasked: it still says the install lands after the session",
          "installs when this session ends" in plain[0], str(plain))
    check("notify mode is untouched by the question",
          "lingling update" in update.notice_lines(newer, CURRENT, "notify")[0])

    class _Done:
        """A finished check: the handoff reads exactly one attribute."""

        info = newer

    stream = io.StringIO()
    with env_swap(LINGLING_UPDATE="auto"):
        update.emit(_Done(), stream=stream, ask=True)
        emitted = stream.getvalue()
    check("emit carries the decision into the notice",
          "9.9.9" in emitted
          and "installs when this session ends" not in emitted, emitted)


def section_handoff():
    """The one decision reaches both the notice and the question."""
    print("\n=== 23. the handoff: one decision, one notice, one question ===")
    from lingling import cli

    class _Check:
        def __init__(self, info):
            self.info = info

    newer = {"latest": "9.9.9", "min_supported": None, "notice": None}

    def handoff(can_ask, answer):
        asked, spawned, err = [], [], io.StringIO()

        def read(prompt, stream):
            asked.append(prompt)
            return answer

        with patched(askable=lambda info=None: can_ask,
                     spawn_deferred=lambda dd, delay=None: (
                         spawned.append(dd) or 4242),
                     _ask=read), \
                env_swap(LINGLING_UPDATE="auto"), \
                contextlib.redirect_stderr(err):
            cli._say_update(_Check(newer))
        return err.getvalue(), asked, spawned

    out, asked, spawned = handoff(True, "n")
    check("a person at the terminal is told, then asked",
          "9.9.9" in out and asked == [update.PROMPT], f"{out!r} {asked!r}")
    check("and the notice does not claim the install it is offering",
          "installs when this session ends" not in out, out)
    check("a no at the handoff schedules nothing", not spawned, str(spawned))

    out, _, spawned = handoff(True, "")
    check("Enter at the handoff schedules the deferred install",
          len(spawned) == 1, str(spawned))

    out, asked, spawned = handoff(False, "n")
    check("a launch that cannot be asked is not asked, and still installs",
          not asked and len(spawned) == 1, f"{asked} {spawned}")
    check("and that notice keeps saying the install lands after the session",
          "installs when this session ends" in out, out)

    src = (ROOT / "lingling" / "cli.py").read_text(encoding="utf-8")
    body = src.split("def _say_update", 1)[1].split("\ndef ", 1)[0]
    check("the decision is computed once and handed to both calls",
          body.count("update.askable(") == 1 and body.count("ask=ask") == 2,
          body[:200])
    check("and the question lives in the engine, not the launcher",
          "input(" not in body, body[:200])


def section_launch(url):
    """A real launch with a redirected stdin: no question, no hang"""
    print("\n=== 24. a launch nobody can be asked never waits on an answer ===")
    data = scratch()
    PAYLOAD["manifest"] = manifest(latest="9.9.9")
    ran = data / "installer-ran.txt"
    installer = data / "installer.py"
    installer.write_text("import pathlib, sys\n"
                         "pathlib.Path(sys.argv[1]).write_text('ran')\n",
                         encoding="utf-8")
    # console program
    bindir = data / "bin"
    bindir.mkdir()
    shutil.copyfile(sys.executable, bindir / "opencode.exe")

    env = env_for(url, {
        "LINGLING_UPDATE_CMD": f'"{sys.executable}" "{installer}" "{ran}"',
        "LINGLING_NO_MITM": "1",
        # env_for() deliberately
        "LINGLING_DATA_DIR": str(data),
    })
    key = next((k for k in env if k.upper() == "PATH"), "PATH")
    env[key] = str(bindir) + os.pathsep + env.get(key, "")

    try:
        res = subprocess.run(
            [sys.executable, "-m", "lingling", "--no-tor", "--no-proof"],
            cwd=str(ROOT), env=env, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        check("the launch came back on its own", False,
              "it is still running after 180s -- something is waiting on input")
        return
    out = res.stdout + res.stderr
    check("the launch came back on its own", res.returncode == 0,
          f"exit {res.returncode}: {out[-300:]}")
    check("it rode the direct path it was pointed at", "no lanes" in out,
          out[:200])
    check("it never wrote a question to a redirected launch", "[Y/n]" not in out,
          out[-200:])
    check("and it handed the terminal to opencode all the same",
          "handoff: starting opencode" in out, out[-200:])


def section_helper_python():
    """The helper must not be launched through a venv redirector stub"""
    print("\n=== 25. the helper runs on an interpreter that cannot flash ===")
    got = update.helper_python()
    check("the helper interpreter is a real file", pathlib.Path(got).is_file(),
          got)
    check("and this install needs no redirecting",
          got in (sys.executable, getattr(sys, "_base_executable", None)), got)

    decoy = scratch() / "python-decoy.exe"
    shutil.copyfile(sys.executable, decoy)
    had = getattr(sys, "_base_executable", None)
    try:
        sys._base_executable = str(decoy)
        check("a venv is stepped over to its base interpreter",
              update.helper_python() == str(decoy), update.helper_python())
        sys._base_executable = str(scratch() / "gone.exe")
        check("and a base interpreter that is not there is not trusted",
              update.helper_python() == sys.executable, update.helper_python())
        sys._base_executable = sys.executable
        check("a base that is this very interpreter changes nothing",
              update.helper_python() == sys.executable, update.helper_python())
    finally:
        if had is None:
            try:
                del sys._base_executable
            except AttributeError:
                pass
        else:
            sys._base_executable = had

    captured = []
    real_popen = update.subprocess.Popen

    def fake_popen(cmd, **kw):
        captured.append(cmd)
        raise OSError("stopped before the spawn, on purpose")

    update.subprocess.Popen = fake_popen
    try:
        update.spawn_deferred(scratch())
    finally:
        update.subprocess.Popen = real_popen
    check("the helper is started with it, never with a bare sys.executable",
          bool(captured) and captured[-1][0] == update.helper_python()
          and pathlib.Path(captured[-1][0]).is_file(),
          str(captured[-1])[:200] if captured else "Popen was never reached")


def main() -> int:
    url = serve()
    print(f"local manifest at {url}   (lingling {CURRENT})\n")

    section_versions()
    section_check(url)
    section_install()
    section_deferral()
    section_command(url)
    section_wiring(url)
    section_job()
    section_nowindow()
    section_question()
    section_answers()
    section_read()
    section_notice_ask()
    section_handoff()
    section_launch(url)
    section_helper_python()

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
