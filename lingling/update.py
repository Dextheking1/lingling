"""Notice a newer lingling, and install it -- without breaking a launch.

Three facts decide the shape of this module.

*Nothing already installed can update itself.* A copy of lingling on a
user's disk has exactly the code it was installed with, so a version
that shipped no checker can never learn it is stale; the only thing
that moves it is a person typing an upgrade. This module is therefore a
bootstrap: the release that carries it reaches nobody new, and the
release after it reaches everyone who took that one step by hand.

*lingling is a console script, not a standalone binary.* On Windows
``Scripts/lingling.exe`` is the file being executed at the same moment
``pip install --upgrade`` wants to replace it, and Windows will not
overwrite a running image. So the ordinary path does not install in
place: it hands the job to a small detached helper that waits for this
process to end and only then runs the installer. The upgrade therefore
lands between two launches -- the only moment it is safe -- and a
session in progress is never pulled out from under the user.

*A launch must not pay for any of it.* The check is a background thread
with hard timeouts, a disk cache with a TTL, and a negative cache so a
dead endpoint is asked once an hour rather than once a launch. Offline,
the thread dies quietly and the boot is exactly as long as it was
before this module existed.

The version comparison is hand-rolled because the only dependency this
package declares is stem and cryptography, and pulling in ``packaging``
to compare ``2.1.20.post23`` against ``2.1.21`` is not worth a new
dependency the user has to carry.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import Optional, Sequence

#: The manifest endpoint (a Vercel function, see tools/update-api/). It
#: carries human-controlled fields a plain release cannot: a one-line
#: notice, and the oldest build still known to work against current
#: opencode. A release is the only way to change *code*; this is the
#: only way to say something urgent before the next release lands.
MANIFEST_URL = "https://lingling-update.vercel.app/api/latest"

#: Fallback when the manifest is unreachable: the registry itself.
PYPI_URL = "https://pypi.org/pypi/lingling/json"

#: The manifest format this build understands. An unknown schema is
#: ignored rather than guessed at, so a future field cannot make an old
#: client misread a newer manifest.
SCHEMA = 1

#: How long a good answer is trusted, and how long a bad one is.
CACHE_TTL = 6 * 3600
FAIL_TTL = 3600

#: Bound on each request. The check rides a boot that takes minutes, so
#: a slow endpoint is only ever a late line, never a late launch.
TIMEOUT = 3.0

#: Bound on the whole check, so a pathological resolver cannot pin the
#: thread past the point where the notice is worth printing.
BUDGET = 8.0

#: How long the detached helper waits for us to exit before giving up.
#: A session can legitimately run all day; after a day the upgrade is
#: better left to the next launch than installed around a live kitchen.
HELPER_WAIT = 24 * 3600

CACHE_NAME = "update-check.json"
LOG_NAME = "update.log"

UPDATE_HELP = """
lingling update -- move to the newest lingling

The copy on your disk has the code it was installed with, and nothing
can change that from the outside: a build that cannot check can never
learn it is stale. So this is the one command worth knowing by name.

    lingling update            check, then install it safely
    lingling update --check    say what the newest version is, change nothing
    lingling update --now      install in this process, not after it

The default does not install while lingling is running. On Windows the
console launcher IS the running file, and `pip install --upgrade` wants
to replace it -- so the install is handed to a small helper that waits
for this process to end and only then runs pip. The upgrade lands
between two launches, which is the only moment it is safe.

The check on launch is unobtrusive: a background thread, a three second
timeout, and a six hour cache, so an offline machine is silent rather
than slow. It only ever prints when there is something to say.

    LINGLING_UPDATE=auto     check, notice, and install after the session (default)
    LINGLING_UPDATE=notify   check and notice only -- never install for me
    LINGLING_UPDATE=off      do not check at all
    LINGLING_UPDATE_URL=...  check a different manifest endpoint
    LINGLING_UPDATE_CMD=...  install with your own command, not pip

Nothing here is required: with the check off, lingling launches exactly
as it did before this command existed.
"""

#: The detached installer. It waits for the launcher that spawned it to
#: die -- the file lock is on the running image, not on the package --
#: and only then installs. ``os.kill(pid, 0)`` is deliberately not used:
#: on Windows that call TERMINATES the process it is asked about, so the
#: liveness check has to be the OS's own table.
_HELPER = r'''
import os, subprocess, sys, time

pid = int(sys.argv[1])
cmd = sys.argv[2:]
deadline = time.time() + float(os.environ.get("LINGLING_HELPER_WAIT", "86400"))


def alive(p):
    if os.name == "nt":
        try:
            out = subprocess.check_output(
                ["tasklist", "/FI", "PID eq %d" % p, "/NH"],
                text=True, timeout=10)
            return str(p) in out and "No tasks" not in out
        except Exception:
            return True
    try:
        os.kill(p, 0)
        return True
    except OSError:
        return False


while time.time() < deadline:
    if not alive(pid):
        break
    time.sleep(0.5)
else:
    print("launcher still alive after the wait budget -- not installing")
    sys.exit(0)

print("running: %s" % " ".join(cmd), flush=True)
sys.exit(subprocess.call(cmd))
'''


# ---------------------------------------------------------------------------
# versions
# ---------------------------------------------------------------------------

def key(version: str) -> tuple:
    """An ordering key for lingling's own scheme: ``X.Y.Z[.postN]``.

    PEP 440 puts a post release *after* the release it amends, so
    ``2.1.20.post23`` is newer than ``2.1.20`` and older than
    ``2.1.21``. A tuple does that in one comparison: the post release
    sets a flag in slot three, and only ever competes inside the same
    ``X.Y.Z``. Anything unparseable reads as zero, so a junk tag can
    never outrank a real release.
    """
    text = (version or "").strip().lstrip("vV").split("+", 1)[0].strip()
    post = 0
    if ".post" in text:
        text, _, tail = text.partition(".post")
        digits = re.sub(r"\D", "", tail)
        post = int(digits) if digits else 1
    parts = []
    for chunk in text.split("."):
        digits = re.sub(r"\D", "", chunk)
        parts.append(int(digits) if digits else 0)
    parts += [0] * (3 - len(parts))
    return (parts[0], parts[1], parts[2], 1 if post else 0, post)


def is_newer(candidate: Optional[str], than: str) -> bool:
    """True when ``candidate`` sorts after ``than`` under :func:`key`."""
    if not candidate or not than:
        return False
    return key(candidate) > key(than)


def current_version() -> str:
    """The version in this process, read per call so a test can swap it.

    Importing the attribute rather than the value is the whole point:
    a verify script can stand in a different version and exercise the
    notice without a network or a second install.
    """
    from . import __version__
    return __version__


# ---------------------------------------------------------------------------
# the knobs
# ---------------------------------------------------------------------------

def mode() -> str:
    """``auto`` (default), ``notify``, or ``off`` -- read per call.

    An explicit ``lingling update`` is not gated by this: asking for the
    command is a direct instruction, and refusing to answer it because
    the *launch* check is off would be a trap.
    """
    raw = (os.environ.get("LINGLING_UPDATE") or "").strip().lower()
    if raw in ("off", "0", "no", "false", "none", "disable", "disabled"):
        return "off"
    if raw in ("notify", "check", "notice", "warn", "only"):
        return "notify"
    if raw in ("auto", "1", "yes", "true", "on", ""):
        return "auto"
    return "auto"


def manifest_url() -> str:
    return (os.environ.get("LINGLING_UPDATE_URL") or "").strip() or MANIFEST_URL


def _override_cmd() -> list:
    """``LINGLING_UPDATE_CMD``, for installs that are not pip, pipx or uv.

    Whitespace separated, with quotes honoured on Windows where an
    interpreter path may contain a space.
    """
    raw = (os.environ.get("LINGLING_UPDATE_CMD") or "").strip()
    if not raw:
        return []
    parts = shlex.split(raw, posix=(os.name != "nt"))
    return [p.strip('"') for p in parts if p.strip('"')]


# ---------------------------------------------------------------------------
# the check
# ---------------------------------------------------------------------------

def _get_json(url: str, timeout: float):
    """A JSON GET, or None. Never raises -- a check is not a feature."""
    request = urllib.request.Request(
        url, headers={"User-Agent": f"lingling/{current_version()}"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except Exception:  # noqa: BLE001 -- offline, DNS, TLS, junk body, anything
        return None


def _lookup(timeout: float) -> dict:
    """Ask the manifest, then the registry. Either may fail alone."""
    info = {"latest": None, "min_supported": None, "notice": None,
            "url": None, "source": None}

    doc = _get_json(manifest_url(), timeout)
    if isinstance(doc, dict) and doc.get("schema") == SCHEMA:
        info["latest"] = doc.get("latest") or None
        info["min_supported"] = doc.get("min_supported") or None
        info["notice"] = doc.get("notice") or None
        info["url"] = doc.get("url") or None
        if info["latest"] or info["notice"]:
            info["source"] = "manifest"
            if info["latest"]:
                return info
    # A manifest that is unreachable, or a schema we do not understand,
    # still leaves the registry -- which is the version users get when
    # they follow the install line in the README anyway.
    doc = _get_json(PYPI_URL, timeout)
    if isinstance(doc, dict):
        latest = ((doc.get("info") or {}).get("version")) or None
        if latest:
            info["latest"] = latest
            info["source"] = "pypi"
    return info


def _cache_path(data_dir) -> Path:
    return Path(data_dir) / CACHE_NAME


def read_cache(data_dir) -> Optional[dict]:
    """The last answer, or None. No network, no side effects."""
    try:
        doc = json.loads(_cache_path(data_dir).read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 -- missing, unreadable, truncated
        return None
    return doc if isinstance(doc, dict) else None


def _write_cache(data_dir, info: dict) -> None:
    """Best effort: an unwritable cache costs a request, not a boot."""
    try:
        path = _cache_path(data_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = dict(info, checked_at=int(time.time()))
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, path)
    except Exception:  # noqa: BLE001
        pass


def fresh(info: Optional[dict], now: Optional[float] = None) -> bool:
    """Is this cached answer still worth acting on?

    A negative answer expires sooner than a positive one: a dead
    endpoint should be retried within the hour, while a version that is
    genuinely the newest need only be confirmed occasionally.
    """
    if not isinstance(info, dict):
        return False
    try:
        age = (now if now is not None else time.time()) - float(
            info.get("checked_at") or 0)
    except (TypeError, ValueError):
        return False
    return 0 <= age < (CACHE_TTL if info.get("latest") else FAIL_TTL)


def check(data_dir, force: bool = False, timeout: float = TIMEOUT) -> dict:
    """The newest version we know of, cached. Never raises."""
    if not force:
        cached = read_cache(data_dir)
        if fresh(cached):
            return dict(cached or {})
    info = _lookup(timeout)
    _write_cache(data_dir, info)
    return dict(info, checked_at=int(time.time()))


def behind(info: Optional[dict], current: Optional[str] = None) -> bool:
    """Should this build be asking the user to move? """
    if not isinstance(info, dict):
        return False
    current = current or current_version()
    if is_newer(info.get("latest"), current):
        return True
    floor = info.get("min_supported")
    return bool(floor) and not is_newer(current, str(floor)) \
        and str(floor) != current


def notice_lines(info: Optional[dict], current: Optional[str] = None,
                 mode_name: Optional[str] = None) -> list:
    """The lines worth printing, or an empty list to stay silent.

    Silence is the default in every direction: up to date, unreachable,
    unparseable, or switched off. The one case that is never silent is
    a build below the manifest's floor -- that is lingling saying the
    current opencode will not work with what you have.
    """
    if mode_name == "off" or not behind(info, current):
        return []
    current = current or current_version()
    latest = info.get("latest")
    lines = []
    notice = (info.get("notice") or "").strip()
    if notice:
        lines.append(f"  {notice}")
    floor = info.get("min_supported")
    if floor and not is_newer(current, str(floor)) and str(floor) != current:
        lines.append(
            f"  you are on {current}, and this opencode needs {floor} or "
            f"newer -- update before the next session")
    elif is_newer(latest, current):
        if mode_name == "auto":
            lines.append(
                f"  lingling {latest} is out (you are on {current}) -- it "
                f"installs when this session ends")
        else:
            lines.append(
                f"  lingling {latest} is out (you are on {current}) -- run: "
                f"lingling update")
    if not lines:
        return []
    return lines


# ---------------------------------------------------------------------------
# the launch-side check
# ---------------------------------------------------------------------------

class Check:
    """A background check, and the answer when it arrives.

    The spawn is deliberately dumb: one daemon thread, one deadline, and
    every failure swallowed. The launcher asks once, at the moment it
    hands the terminal over, and a check that has not finished by then
    simply says nothing -- a late notice is worth less than a clean
    handoff.
    """

    def __init__(self) -> None:
        self.info: Optional[dict] = None
        self.done = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self, data_dir) -> "Check":
        def run() -> None:
            deadline = time.time() + BUDGET
            try:
                # Housekeeping for a previous upgrade, off the boot path:
                # a launcher parked by an earlier install is still locked
                # until the process owning it exits, so the sweep belongs
                # to the next launch rather than the one that parked it.
                sweep_launcher_leftovers()
                cached = read_cache(data_dir)
                if fresh(cached):
                    self.info = dict(cached or {})
                    return
                remaining = max(0.5, min(TIMEOUT, deadline - time.time()))
                self.info = check(data_dir, force=True, timeout=remaining)
            except Exception:  # noqa: BLE001
                self.info = None
            finally:
                self.done.set()

        self._thread = threading.Thread(target=run, name="update-check",
                                        daemon=True)
        self._thread.start()
        return self

    def wait(self, timeout: Optional[float] = None) -> Optional[dict]:
        self.done.wait(timeout)
        return self.info


def start(data_dir) -> Optional[Check]:
    """Start the launch check, unless it is switched off."""
    if mode() == "off" or os.environ.get("LINGLING_NO_UPDATE_CHECK"):
        return None
    try:
        return Check().start(data_dir)
    except Exception:  # noqa: BLE001 -- a thread that will not start is not a launch failure
        return None


def emit(check_obj: Optional[Check], stream=None) -> None:
    """Say the one thing there is to say, or nothing at all.

    stderr, because a notice is not this program's output: a script
    reading stdout should not have to learn to ignore it.
    """
    if check_obj is None:
        return
    stream = stream or sys.stderr
    lines = notice_lines(check_obj.info, mode_name=mode())
    if not lines:
        return
    try:
        for line in lines:
            stream.write(line + "\n")
        stream.flush()
    except Exception:  # noqa: BLE001 -- a closed stderr must not kill a lane
        pass


def cached_hint(data_dir, stream=None) -> None:
    """The ``--version`` line, from cache only. Never touches the net."""
    stream = stream or sys.stderr
    lines = notice_lines(read_cache(data_dir), mode_name=mode())
    if not lines:
        return
    try:
        for line in lines:
            stream.write(line + "\n")
        stream.flush()
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# the install
# ---------------------------------------------------------------------------

def install_method() -> str:
    """How this copy was installed: ``pipx``, ``uv``, or ``pip``.

    Read off the running interpreter's prefix rather than off PATH: a
    machine can have every one of these on it, and only the prefix says
    which one owns the lingling being executed.
    """
    seen = []
    for attr in ("prefix", "base_prefix"):
        seen.append(str(getattr(sys, attr, "") or ""))
    seen.append(str(Path(sys.executable or "").parent))
    text = " ".join(seen).replace("\\", "/").lower()
    if "/pipx/" in text:
        return "pipx"
    if "/uv/tools/" in text or "/uv/python/" in text:
        return "uv"
    return "pip"


def upgrade_command() -> list:
    """The installer invocation for this copy, as an argv list."""
    override = _override_cmd()
    if override:
        return override
    method = install_method()
    if method == "pipx":
        exe = shutil.which("pipx")
        if exe:
            return [exe, "upgrade", "lingling"]
    if method == "uv":
        exe = shutil.which("uv")
        if exe:
            return [exe, "tool", "upgrade", "lingling"]
    return [sys.executable or "python", "-m", "pip", "install", "--upgrade",
            "lingling"]


def scripts_dir() -> Path:
    """Where pip put the console script.

    ``sys.executable``'s own directory is NOT it. In a global install the
    interpreter is ``...\\Python312\\python.exe`` and the launcher is in
    ``...\\Python312\\Scripts\\`` -- measured on a real global install,
    where the naive path resolved to a file that does not exist and the
    whole lock-avoidance below silently did nothing. ``sysconfig`` is the
    only thing that also gets a virtualenv right, because it answers in
    terms of ``sys.prefix`` rather than of the interpreter's filename.
    """
    try:
        import sysconfig
        path = sysconfig.get_path("scripts")
        if path:
            return Path(path)
    except Exception:  # noqa: BLE001
        pass
    return Path(sys.executable or "").parent


def _running_launcher() -> Optional[Path]:
    """``Scripts/lingling.exe`` when that file is *this* process's image.

    Windows will not overwrite a running executable, so it is the one
    file in the install that an in-place upgrade cannot replace. It can,
    however, be renamed while it runs -- so it is parked out of the way
    and the installer is free to write a fresh one.

    The test is the *name* of ``argv[0]``, not its path. A pip console
    script runs under a distlib launcher that reports the script without
    its extension -- measured, ``argv[0]`` is ``...\\Scripts\\lingling``,
    never ``...\\lingling.exe`` -- so comparing resolved paths never
    matched. ``python -m lingling`` reports ``__main__.py`` and a ``-c``
    run reports ``-c``, and both correctly skip parking: those processes
    hold no lock on the launcher and pip can replace it freely.
    """
    if os.name != "nt":
        return None
    exe = scripts_dir() / "lingling.exe"
    if not exe.is_file():
        return None
    name = Path(sys.argv[0] or "").name.lower()
    return exe if name in ("lingling", "lingling.exe") else None


def sweep_launcher_leftovers() -> None:
    """Drop launchers parked by an earlier upgrade.

    Best effort by design: a parked image is still locked until the
    process that owns it exits, so this is for the *next* launch, a
    failure is not worth a word to the user, and it runs on the check
    thread rather than in front of the boot.
    """
    if os.name != "nt":
        return
    try:
        for stale in scripts_dir().glob("lingling.exe.old-*"):
            try:
                stale.unlink()
            except OSError:
                pass
    except OSError:
        pass


def run_install(capture: bool = False, timeout: float = 600):
    """Run the installer in this process. Returns ``(ok, output)``.

    Only ``--now`` uses this. On Windows the launcher is parked first so
    the install can land, and restored if it does not -- a failure here
    must leave the user with exactly the machine they had, or with a
    fresh launcher, never with no launcher at all.
    """
    argv = upgrade_command()
    parked = None
    launcher = _running_launcher()
    if launcher is not None:
        target = launcher.with_name(f"{launcher.name}.old-{os.getpid()}")
        try:
            os.replace(launcher, target)
            parked = target
        except OSError:
            parked = None
            return False, (
                "could not park the running launcher -- Windows will not "
                "let the install replace it while it runs. Close lingling "
                "and run this from a fresh shell, or use the deferred "
                "install (lingling update).")
    try:
        result = subprocess.run(argv, capture_output=capture, text=True,
                                stdin=subprocess.DEVNULL, timeout=timeout)
        ok = result.returncode == 0
        output = (result.stdout or "") + (result.stderr or "") \
            if capture else ""
    except FileNotFoundError:
        ok, output = False, f"could not run {argv[0]}"
    except subprocess.TimeoutExpired:
        ok, output = False, f"{argv[0]} took longer than {timeout:.0f}s"
    except Exception as exc:  # noqa: BLE001
        ok, output = False, str(exc)

    if parked is not None:
        if launcher.exists():
            # An installer that wrote a fresh launcher has already done the
            # thing this parking existed for, so the parked one is dead
            # weight. Deleting it can still fail while it is the running
            # image; that is what the next launch's sweep is for.
            try:
                parked.unlink()
            except OSError:
                pass
        else:
            # Put it back, so a failed install is a no-op rather than a
            # machine where `lingling` no longer exists.
            try:
                os.replace(parked, launcher)
            except OSError:
                return False, (output + "\n\nthe installer wrote no launcher "
                               "and the previous one could not be moved "
                               f"back: {parked.name} is still in "
                               f"{parked.parent}")
            if ok:
                ok = False
                output += ("\nthe install reported success but wrote no "
                           "launcher -- the previous one has been restored")
    return ok, output


def installed_version() -> Optional[str]:
    """What the *installed* package says right now, after an install."""
    try:
        from importlib.metadata import version as _v
        return _v("lingling")
    except Exception:  # noqa: BLE001 -- not installed as a distribution
        return None


def _detach_kwargs() -> dict:
    if os.name == "nt":
        return {"creationflags": 0x00000008 | 0x00000200}  # DETACHED | NEW_GROUP
    return {"start_new_session": True}


def spawn_deferred(data_dir, delay: Optional[float] = None):
    """Hand the install to a helper that waits for us to exit.

    Returns the helper's pid, or None when nothing was scheduled. This
    is the default path precisely because of the lock described in
    :func:`_running_launcher`: the one file an upgrade must replace is
    the one file that cannot be replaced while lingling runs.
    """
    argv = upgrade_command()
    if not argv:
        return None
    log_path = Path(data_dir) / LOG_NAME
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log = open(log_path, "a", encoding="utf-8")
    except OSError:
        return None
    try:
        env = dict(os.environ)
        env["LINGLING_HELPER_WAIT"] = str(delay or HELPER_WAIT)
        proc = subprocess.Popen(
            [sys.executable or "python", "-c", _HELPER, str(os.getpid()), *argv],
            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            close_fds=True, env=env, **_detach_kwargs())
    except Exception:  # noqa: BLE001
        try:
            log.close()
        except Exception:  # noqa: BLE001
            pass
        return None
    try:
        log.write(f"\n--- scheduled by lingling {current_version()} at "
                  f"{time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
        log.flush()
        log.close()
    except Exception:  # noqa: BLE001
        pass
    return proc.pid


def auto_install(data_dir, info: Optional[dict]):
    """Schedule the deferred install when the mode says to.

    Called once per launch, so one upgrade per session at most.
    """
    if mode() != "auto" or not behind(info):
        return None
    return spawn_deferred(data_dir)


# ---------------------------------------------------------------------------
# the explicit command
# ---------------------------------------------------------------------------

def _report(current: str, info: dict, stream=None) -> None:
    stream = stream or sys.stdout
    latest = info.get("latest")
    source = info.get("source") or "unknown"
    if latest:
        stream.write(f"  installed  {current}\n")
        stream.write(f"  available  {latest}  ({source})\n")
    else:
        stream.write(f"  installed  {current}\n")
        stream.write(f"  available  unknown -- {manifest_url()} and PyPI both "
                     f"did not answer\n")
    stream.flush()


def update_command(rest: Sequence[str]) -> int:
    """``lingling update`` -- check, report, and install. Returns a code."""
    from . import data_dir as _data_dir

    args = list(rest)
    if "--help" in args or "-h" in args:
        print(UPDATE_HELP)
        return 0
    # Cheap housekeeping, and the right moment for it: a launcher parked by
    # an earlier `--now` was locked by the process that parked it, so this
    # run is the first that can actually delete it.
    sweep_launcher_leftovers()
    check_only = "--check" in args
    now = "--now" in args
    quiet = "-q" in args or "--quiet" in args

    data = _data_dir()
    current = current_version()
    info = check(data, force=True)
    _report(current, info)

    if not info.get("latest"):
        # Silence is right on a launch and a lie in an explicit command:
        # "nothing to do" must never stand in for "I could not look".
        print("  could not reach the update servers -- nothing was changed.")
        print("  install by hand:  " + " ".join(upgrade_command()))
        return 1

    if not behind(info, current):
        print("  you are on the newest lingling -- nothing to do.")
        return 0
    if check_only:
        print("  run `lingling update` to install it.")
        return 0

    latest = info.get("latest") or "the newest release"

    if now:
        print(f"  installing {latest} in this process ...")
        run_install()
        after = installed_version()
        if after and key(after) > key(current):
            print(f"  done -- {after} is installed. Relaunch to ride it.")
            return 0
        print(f"  the install did not take (still {after or current}).")
        print("  Run it from a fresh shell:\n    lingling update --now")
        return 1

    pid = spawn_deferred(data)
    if pid is None:
        print("  could not schedule the install.")
        print("  Run it yourself:\n    " + " ".join(upgrade_command()))
        return 1
    print(f"  scheduled -- {latest} installs when this lingling exits "
          f"(helper pid {pid}).")
    if not quiet:
        print(f"  progress: {Path(data) / LOG_NAME}")
    return 0
