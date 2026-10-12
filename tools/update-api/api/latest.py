"""GET /api/latest -- the manifest lingling reads on launch.

One function, one job, no state. Its whole reason to exist beside PyPI
is the two fields PyPI cannot carry: a one-line notice, and the oldest
build still known to work against current opencode. A release is the
only way to ship *code*; this is the only way to say something urgent
before the next release exists.

``latest`` is never pinned here. A constant would let a deploy advertise
a version nobody published, and every client that trusted it would ask
for that version forever. So the registry is the single source of that
field: if it cannot be reached the field is null, and the client falls
back to asking PyPI itself.

Everything below is the Python runtime's bare HTTP handler rather than
a framework -- a manifest needs no routing, no middleware and no
dependencies, and a function with no dependencies cannot be broken by
one being upgraded.
"""

import json
import re
import time
from http.server import BaseHTTPRequestHandler

#: Must match lingling.update.SCHEMA. A client that does not recognise
#: this number ignores the body rather than guessing at its meaning.
SCHEMA = 1

PYPI_URL = "https://pypi.org/pypi/lingling/json"
PROJECT_URL = "https://pypi.org/project/lingling/"

#: Bound on the registry lookup. The CDN caches the answer for five
#: minutes, so this runs rarely and a slow registry is a null field, not
#: a slow client.
PYPI_TIMEOUT = 3.0

#: Five minutes is short enough to publish something urgent within the
#: hour and long enough that a large install base costs one origin
#: request per five minutes rather than one per launch.
#:
#: The CDN directive goes in Vercel-CDN-Cache-Control, not Cache-Control:
#: measured on this deployment, Vercel rewrites Cache-Control to a bare
#: ``public`` and the response comes back X-Vercel-Cache: MISS every time
#: -- which would put every client's request through to the origin, and
#: every origin request through to PyPI. The platform-specific header is
#: the one it honours.
CDN_CACHE = "max-age=300, stale-while-revalidate=86400"
BROWSER_CACHE = "public, max-age=60"

#: Human-controlled. ``notice`` is one line shown verbatim, above the
#: version line, to every build that is behind. ``min_supported`` is the
#: oldest build that still works against current opencode; a client below
#: it is told to update rather than offered the choice. Both are null
#: today: nothing is forced and nothing is announced.
NOTICE = None
MIN_SUPPORTED = None

#: Versions we refuse to name, whatever the registry says.
#:
#: A published version name is permanent on PyPI: it cannot be reused and
#: it cannot be unpublished without its own release being re-uploaded.
#: Yanking is the standard retreat, but it hides a release from *new*
#: resolutions only -- and the manifest, which is what every installed
#: client actually reads, would go on announcing it. So the withdrawal
#: has to be recorded here too, or the whole install base keeps being
#: told to fetch something deliberately taken back.
#:
#: 2.1.20.post25 is withdrawn. Remove an
#: entry only if that version is genuinely meant to be reachable again.
RETIRED = {
    "2.1.20.post25",
}


def _key(version):
    """Ordering key for lingling's scheme: ``X.Y.Z[.postN]``.

    PEP 440 puts a post release after the release it amends, so
    ``2.1.20.post25`` sorts above ``2.1.20`` and below ``2.1.21``.
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


def newest_installable():
    """The version pip would actually pick, or None. Never raises.

    Deliberately not ``info.version``. That field names the newest
    *release*, and a release whose every file has been yanked is one pip
    will refuse to install -- so a manifest that repeated it would send
    the whole install base chasing a version that cannot be fetched, and
    keep sending them after the version was withdrawn. Measured: with
    post25 yanked, ``info.version`` still said post25 while a fresh
    ``pip download`` resolved post24.

    Scanning the release list for the newest version with at least one
    live file is the same rule pip applies, which is the only definition
    of "newest" this endpoint should ever publish.
    """
    try:
        import urllib.request
        request = urllib.request.Request(
            PYPI_URL, headers={"User-Agent": "lingling-update-api"})
        with urllib.request.urlopen(request, timeout=PYPI_TIMEOUT) as response:
            doc = json.load(response)
    except Exception:
        return None

    best = None
    for version, files in (doc.get("releases") or {}).items():
        if not files:
            continue
        if version in RETIRED:
            continue
        if all(f.get("yanked") for f in files):
            continue
        if best is None or _key(version) > _key(best):
            best = version
    if best is None:
        # A registry that answered with nothing usable still has the one
        # field this function exists to report, unless that version is
        # one we have withdrawn -- in which case saying nothing is the
        # honest answer.
        fallback = (doc.get("info") or {}).get("version")
        return None if fallback in RETIRED else fallback
    return best


def manifest():
    return {
        "schema": SCHEMA,
        "package": "lingling",
        "latest": newest_installable(),
        "min_supported": MIN_SUPPORTED,
        "notice": NOTICE,
        "url": PROJECT_URL,
        "checked_at": int(time.time()),
    }


class handler(BaseHTTPRequestHandler):
    def _send(self, code, payload):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Vercel-CDN-Cache-Control", CDN_CACHE)
        self.send_header("Cache-Control", BROWSER_CACHE)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        """One route. Vercel only ever dispatches /api/latest here, and a
        handler that also claimed "/" would be advertising a path the
        platform answers itself with a 404."""
        path = (self.path or "").split("?", 1)[0].rstrip("/")
        if path == "/api/latest":
            self._send(200, manifest())
        else:
            self._send(404, {"error": "not found", "try": "/api/latest"})

    def do_HEAD(self):
        self.do_GET()

    def log_message(self, fmt, *args):
        """Silence per-request stderr chatter; Vercel keeps the access log."""
        return
