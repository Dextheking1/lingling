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


def newest_on_pypi():
    """The published version, or None. Never raises."""
    try:
        import urllib.request
        request = urllib.request.Request(
            PYPI_URL, headers={"User-Agent": "lingling-update-api"})
        with urllib.request.urlopen(request, timeout=PYPI_TIMEOUT) as response:
            return (json.load(response).get("info") or {}).get("version")
    except Exception:
        return None


def manifest():
    return {
        "schema": SCHEMA,
        "package": "lingling",
        "latest": newest_on_pypi(),
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
