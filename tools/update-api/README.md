# lingling update manifest

The endpoint `lingling` reads on launch to find out whether it is stale.

```
GET https://lingling-update.vercel.app/api/latest
```

```json
{"schema":1,"package":"lingling","latest":"2.1.20.post23",
 "min_supported":null,"notice":null,
 "url":"https://pypi.org/project/lingling/","checked_at":1760000000}
```

That is the whole API. One route, no state, no database, no auth.

## Why it exists next to PyPI

PyPI already answers "what is the newest version", and the client asks
PyPI directly when this endpoint is unreachable. What PyPI cannot carry
are two fields:

- **`notice`** — one line, shown verbatim to every build that is behind.
  For when opencode changes something and users need to move *now*,
  before a release with a fix exists.
- **`min_supported`** — the oldest build still known to work against
  current opencode. A client below it is told to update instead of being
  offered the choice.

`latest` is deliberately **not** pinned in code. A constant here would
let a deploy advertise a version nobody published, and every client that
trusted it would ask for that version forever. The registry stays the
single source of that field; if it cannot be reached the field is `null`
and the client falls back to PyPI itself.

## Changing the notice

Edit `NOTICE` (and/or `MIN_SUPPORTED`) in `api/latest.py`, then:

```bash
cd tools/update-api
vercel --prod
```

Clients pick it up within the five minute CDN window. No release, no
version bump, no user action.

## Deploying

```bash
cd tools/update-api
vercel link --yes --project lingling-update
vercel --prod --yes
```

Static, no dependencies — the function is standard library only, which
is the point: a manifest that cannot be broken by a dependency being
upgraded.

## Testing before anything is public

```bash
curl -sS https://lingling-update.vercel.app/api/latest
```

The response must have `schema: 1` and a `latest` equal to what
`https://pypi.org/pypi/lingling/json` reports. To point a local lingling
at a *staging* copy of this endpoint instead:

```bash
LINGLING_UPDATE_URL=http://127.0.0.1:8000/api/latest lingling --version
```
