# Lingling

### What even is this?

OpenCode gives away genuinely good models for free. The catch: they throttle
you by IP, so right when the conversation gets good — bam, wall. Very rude.

Lingling fixes this the fun way. It spins up a little kitchen of Tor exit
lanes on your machine, each one a different country, and sends every request
down **all** of them at once. The first answer takes it; the rest are cut
before they say a word. One exit gets throttled? Cute. Four of them do, and
you are answered by the fifth without ever noticing. You just keep typing.

```
pip install lingling

lingling               # = opencode, but the requests ride Tor
lingling --help        # anything after `lingling` goes to opencode untouched
lingling uninstall     # wipe the lanes, Tor bundle and logs (keeps countries.txt)
```

`pip uninstall lingling` removes the package only — the 15 modules in
site-packages. The lanes, the Tor bundle, the geoip database and the proof
logs live in the data dir, which pip does not know exists, so a plain pip
uninstall leaves a few hundred megabytes and a stale relay cache behind.
Run `lingling uninstall` first for a clean slate (it keeps your
`countries.txt`), then `pip uninstall lingling`.

State lives under the OS temp dir (`%LOCALAPPDATA%\Temp\lingling-data` on
Windows; override with `LINGLING_DATA_DIR`) — the OS's own cleanup owns any
residue. The first run downloads the Tor Expert Bundle (~30 MB) there, once.
Launching shows exactly one pinned line until the lanes are hot:

```
 ⠙ first run -- pulling the relay directory, a few minutes, once  47s
 served! lanes are hot -- proof is in the other window.
```

One session at a time: launching a second `lingling` while one is running
prints `lingling is already running (pid N) -- one kitchen, one session.`
and exits. A crashed session leaves nothing behind — the lock self-clears.

### "Sure, but how do I know it's not lying?"

Fair. That's what the proof window is for. A second console pops up next to
your editor and shows every single model call, live: which lanes raced it,
which one answered, which country and exit IP, what came back, how big, how
fast. A losing lane's 429 is shown too -- that is the pool working, not your
call failing.

```
14:19:24  #208.1  lanes 1,2,3,5,4 {us,nl,de,at,se}  ->  deepseek-v4.1-flash-free
14:19:24    | #208.1 lane 5 {at} 429 free limit -- exit out until 05:30 (00:00 UTC) -- moving it  0.1 KB in 7.4s
14:19:25    | #208.1 lane 4 {se} 200 29.7 KB in 7.7s  first 5.8s  event 7.44s
14:19:27  * lane 5 was refused (429) -- moved to {se}
14:19:29    | #259.1 lane 5 {ca} 429 rate limit -- exit out 25m -- moving it  0.1 KB in 2.9s
```

No gaslighting. If the pane says bytes are flowing through a German exit,
your tokens are flowing through a German exit. `--no-proof` if you trust us.
(You shouldn't trust anyone. That's the point of the window.)

### How a limit dies without you noticing

A lot of things can go wrong here, and they are kept strictly apart.

Two 429s, and they are not the same thing. The lane is moved to another exit
for both; what differs is which **notepad section** that exit is written into.

**The day's wall (`free limit`).** opencode's free tier allows **200 requests
a day, per exit IP, and resets at 00:00 UTC** — 05:30 IST for us. The 429
carries the reset it means, so that relay is written into the *free limit*
section until then, the lane is pinned to a **different** relay in the same
country, and your request is already elsewhere. Keep hitting the wall and the
lane changes country too; keep going and it gets re-cooked from scratch. The
proof window names the reset: `429 free limit -- exit out until 05:30
(00:00 UTC) -- moving it`. A handful of reports have the wall sticking past
midnight UTC, which is why no exit is ever written off for more than a day.

**The rate limit (`rate`).** A short burst ceiling (roughly 15–20 requests a
minute) that opencode neither documents nor puts a header on. It lifts within
minutes, so that exit goes into the *rate limit* section for 25 minutes —
long enough to stop re-dialling an exit we already know is cooling off:
`429 rate limit -- exit out 25m -- moving it`.

An exit that is spent is only ever the *exit's* problem, never the lane's. The
lane moves off it, and the moment it is on a different relay its clock is
clear again, so it is back in the race on the next call. A lane parked on a
spent exit with its move still waiting for its own streams to finish is the one
case the sweep picks up first: `lane 4 {se} was sitting out a spent exit --
back on 45.137.69.13`. And a refusal is charged to the relay it actually came
from: a copy that was already in flight when its lane moved keeps reporting on
the exit it dialled, so a fresh relay is never written off for a wall that
belongs to the one it replaced.

When a 429 catches **every** lane at once, that wall is not passed on to your
client yet. The refused lanes have already moved to fresh exits, so the call
waits 2s and walks the pool again — twice — and only then does the last 429
reach you. A pool with nothing left to move is not kept waiting at all.

**Their edge, not our exit.** A 429 whose body says `Endpoint is unavailable`
is opencode's own edge having a bad moment, so it is never written into the
notepad at all and the pane says so loudly: `429 OPENCODE EDGE UNAVAILABLE --
not this exit`.

**The gate's refusal (403).** Some exits are refused outright —
`FreeTierError`, the gate's answer to a client it will not credit for the free
tier through that address. Nothing about the lane or its tor is wrong, so no
lane moves. But it is not your answer either, and refusing is cheaper than
answering, so a gated lane always reaches the race *first*. It is held back
like a 429 is: the call goes on to the lanes that can still serve, and only a
pool where every exit is gated hands the 403 over. That exit is then sat out
for the rest of the free-tier day rather than raced on every call, and the
sweep moves its lane somewhere else: `lane 9 {fr} 403 -- the gate closed this
exit, sitting it out`. The pane still shows the attempt that found it, so you
can see which exits the gate has closed.

**Load.** How much a lane is carrying decides where it sits in the race,
never whether it keeps serving. A loaded lane is healthy and still ours, so
nothing is retired for it — and nothing queues either, because the request
already went out on every live lane at once. **The quickest 200 wins** — and
nothing but a 200 may take the call.

**The far end's bad moments.** A 502, 503 or 504 means opencode's edge is
unwell — not your client, and not that exit's quota. A different exit reaches
a different edge, so those are retried on another lane exactly like a 429. A
plain 500 is not allowed to take the call either, for the same reason a 403
isn't: it is the cheapest thing a bad lane can send, and the lane beside it
may still be one second away from your answer. An error only reaches you when
the whole pool answered with errors — and then it is the far end's own words,
not an invented one.

**A slow exit.** If a lane makes your answer wait 20s for its first token, it
is written off on the spot — the same treatment a 429 gets — and your next
call rides elsewhere. Your current answer is never taken away for it: that
verdict lands after the bytes were already yours.

**A stream that showed you nothing.** A call the client has seen no byte of —
not even a first one — for 30s is dropped on the spot and its lane moved, the
timeout verdict taken mid-stream. That is what stops a parked exit from holding
your client, and every answer queued behind it, for the half-hour idle window.
Nothing was delivered, so nothing is half-answered: the call retries on the
other lanes at once. Once a byte has reached you the long window is back — an
answer that pauses to think is never cut for it.

**A stream that goes quiet.** Once an answer is flowing, a pause is a pause: a
model thinking is not a dead exit, and cutting one costs you the rest of the
answer. But an exit that has said nothing at all for **two minutes** is dead,
and the stream is ended — your client is hung up, so the agent retries instead
of waiting forever, and that exit is written off and moved. Measured
2026-10-16: five committed streams on one exit sat at 400-460s of silence with
agent thinking blocks frozen mid-word, while every other lane kept delivering.

A Tor tunnel is end-to-end TLS, so a 429 can't be spotted in flight. Each lane
therefore probes the upstream periodically and reports on itself, and a lane
that just carried real traffic is left alone rather than probed. A lane that
merely falls over gets poked, restarted, and — if it is truly hopeless —
benched with a note. You'll see the whole drama live, which is half the fun.

### "Wait, how can it see each request? Isn't TLS encrypted?"

Very observant. opencode holds one TLS connection open for your whole
session, so a normal proxy sees one opaque pipe, not individual calls. So
Lingling does a magic trick: it mints a throwaway certificate authority **on
your own machine**, hands it to opencode (and only opencode), and unwraps
`opencode.ai` traffic just long enough to read the model name off each
request before re-encrypting it through a lane to the real server.

Everything stays end-to-end TLS over Tor. The only new thing that can see
your traffic is... your own computer, which could already see your traffic.
`LINGLING_NO_MITM=1` turns the trick off if it makes you itchy (you'll get
per-tunnel proof instead of per-request).

### Fresh every time

Every lane is pinned to its **own** exit relay, chosen from the live Tor
consensus, and no two lanes ever share one. Which relay each lane has used is
remembered, so a fresh start hands you exits you have not been through lately
instead of the same handful every launch — freshness is preferred over
bandwidth precisely because the busiest relays are the most heavily shared.
That memory expires on its own, so a relay always comes back.

The only thing carried over besides that is tor's cached copy of the public
relay directory, because re-downloading it every launch turns a five-second
boot into a two-minute one. Stale processes still holding a lane's port are
cleared before new lanes take it — scoped to our own ports, never a blanket
sweep that could catch an unrelated `tor.exe`.

### Pick your own countries

By default lanes rotate through a generic pool (us, de, nl, fr, ro, gb, ca,
se, pl, ch). Want different exits? Drop a `countries.txt` into Lingling's
data directory (`%LOCALAPPDATA%\Temp\lingling-data` on Windows):

```
# big pools first: the ten boot lanes take the first ten here
de,nl,se,at,lu,fr,us,no,ch,hu,it,fi
# fallback, used once the primary pool is exhausted
sg,ro,cz,pl,bg,is,dk,za,ca,gb
# optional preferred pool, blank to skip
```

Line 1 is the primary pool lanes boot and rotate through, line 2 is the
fallback pool used once every primary country is limited, and line 3 is an
optional preferred pool lanes stick to first. Two-letter country codes,
comma-separated, one pool per line. `#` starts a comment, and a comment-only
line is ignored entirely. Leave a line blank to skip that pool. No file, no
problem — the defaults are fine.

**Size your pools by relay count.** Each lane is pinned to its *own* exit
relay, so a country needs spare relays to rotate through when one gets
limited. From the live consensus: the Netherlands has 588 usable exits,
Germany 415, Sweden 339, the US 1166 — while Hong Kong has 7, Turkey 8 and
Ukraine 8. A ladder built only from small countries has almost no room to
move. If a country does run out, that lane falls back to letting Tor choose.

### Flags Lingling keeps for itself

| Flag | What it does |
|---|---|
| `--lanes N` | how many lanes to keep warm (default 10, env `LINGLING_TOR_COUNT`) |
| `--no-tor` | skip the lanes, run opencode on your own IP like a civilian |
| `--no-proof` | no proof window (coward's mode) |
| `--demo [question]` | fire one real request through a lane, show receipts (`LINGLING_DEMO_MODEL` picks the model) |
| `uninstall [--yes]` | wipe the lanes, Tor bundle, geoip and logs (keeps `countries.txt`) |

Everything else is handed to opencode byte-for-byte. We don't touch it,
we don't parse it, we don't want to know.

### Leaving an exit before it is spent

An exit IP's daily allowance belongs to whoever reaches it first, and the only
way to find out that somebody else got there is to be refused. So lanes leave
early instead: after `LINGLING_EXIT_SOFT_CAP` requests through one address
(default: half of `LINGLING_EXIT_CAP`), or after `LINGLING_EXIT_HOLD_S` seconds
riding it (default 600). The second one exists because the requests other
people put through that address show up in no ledger we keep. Each cycle the
sweep takes up to `LINGLING_SWEEP_MOVES` lanes (default 3), every
`LINGLING_SWEEP_S` seconds (default 20), longest-riding first.

### Under the hood

```
lingling/cli.py      entry point, loader, opencode launch
lingling/lanes.py    Tor lane lifecycle: boot, pin, rotate, re-cook
lingling/exits.py    exit relays from the consensus: fresh, distinct, country-filtered
lingling/relay.py    local CONNECT relay, lane ranking by load, MITM handoff
lingling/mitm.py     local CA, interception, and one call raced over every lane
lingling/health.py   probe daemon: limits, deaths, recoveries
lingling/proof.py    the proof window (event log + live tail)
lingling/netutil.py  raw SOCKS5 / HTTPS-over-SOCKS primitives
lingling/demo.py     lingling --demo
lingling/winjob.py   Windows Job Object so tor.exe dies with us

tools/verify/        the offline suites, a boot check, and a repo audit
tools/soak/          live soak: drives the real opencode client
tools/probe/         tunnel latency probe (no quota)
```

Runtime state (tor, lanes, proof log, local CA) lives in the per-user data
directory — never in the package, never in your project folder.

Requirements: Python 3.11+, Windows/macOS/Linux, and `opencode` on your PATH.
Runs entirely on your machine. Nothing calls home. The kitchen is local.
