"""GET /api/latest -- the manifest lingling reads on launch"""

import json
import re
import time
from http.server import BaseHTTPRequestHandler

#: Must match
SCHEMA = 1

PYPI_URL = "https://pypi.org/pypi/lingling/json"
PROJECT_URL = "https://pypi.org/project/lingling/"

#: Bound
PYPI_TIMEOUT = 3.0

#: Five minutes
CDN_CACHE = "max-age=300, stale-while-revalidate=86400"
BROWSER_CACHE = "public, max-age=60"

#: Human-controlled. ``notice``
NOTICE = None
MIN_SUPPORTED = None

#: Versions
RETIRED = { "2.1.20.post25", }


def _key(version):
    """PEP 440 puts a post release after the release it amends."""
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
    """With post25 yanked, info.version still said post25 while pip resolved post24."""
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
        # registry
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
        """This handler only ever serves /api/latest."""
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
