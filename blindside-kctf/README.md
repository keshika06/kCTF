# The Blind Side — kCTF Execution Guide
# Category: Web — SSRF via HTTP Redirect Bypass
# Same execution pattern as currency-arbitrage-kctf / h2-smuggle-kctf
# (kCTF web template: waitress behind nsjail `LISTEN` mode).

## Vulnerability

**Category:** Web — SSRF (Server-Side Request Forgery) via redirect bypass
**Flag:** `CTF{ssrf_dns_yaml_bypass_iitm}` (from the spec)

**LinkAudit Pro** takes a URL, fetches it server-side, and hands back an
"audit report." Before fetching, it checks that the URL doesn't resolve
to a private/internal address — a completely reasonable-looking SSRF
defense. The bug is *when* that check runs: exactly once, against the
URL the player typed in. If the fetch comes back as an HTTP redirect,
the server follows it — straight to the `Location` header, no second
validation call. Whatever address the redirect points to, the server
will happily connect to it, because from the code's point of view the
request has "already been validated."

The internal target is `flag-service`, bound to `127.0.0.1:8080` —
unreachable from outside the container no matter what, but perfectly
reachable *from inside it*, which is exactly where LinkAudit Pro is
running.

## The chain, concretely

1. Submit a URL pointing at a server you control (in a real deployment:
   any public host you can stand up — a VPS, `webhook.site`, `ngrok`,
   whatever).
2. LinkAudit Pro resolves it, confirms it's not a private IP, and
   fetches it.
3. Your server responds `302 Found` with
   `Location: http://flag-service:8080/secret-message`.
4. LinkAudit Pro follows that `Location` header directly — no re-check.
   `flag-service` is on the *challenge's* internal network/localhost,
   so the *challenge itself* can reach it even though you never could.
5. The response — the flag — comes back in your "audit report."

## Verified, not just asserted

I built both services (`challenge/app/frontend`, the vulnerable
LinkAudit Pro; `challenge/app/flagservice`, the internal secret) exactly
as they ship, wired them together the same way the Dockerfile does, and
drove the real HTTP flow against them — no shortcuts, no directly
calling internal functions to skip the actual request/response cycle.
See `run_test.py`-equivalent logic folded into the description below;
the exact commands are under "What I actually tested."

Three things I specifically checked, because a broken version of this
challenge is easy to build by accident:

- **The validator itself is correct.** `validate_submitted_url()` was
  unit-tested against a real public IP (`8.8.8.8`, allowed) and several
  private/internal ranges — loopback, RFC1918, link-local/cloud-metadata
  (all blocked). If the validator itself didn't work, the "bypass"
  wouldn't mean anything.
- **Submitting the internal endpoint directly is still blocked.**
  `POST /audit` with `url=http://flag-service:8080/secret-message`
  returns `400` — you cannot just ask for the flag.
- **The redirect path recovers the flag, using the real HTTP route**
  (an actual `POST /audit` against a running Flask process, real
  template rendering, not a function call in a test harness) — and a
  direct check afterward confirms `flag-service:8080` would have been
  rejected by the exact same validator if it had ever been asked.

## A wrinkle I found (and fixed) while wiring up the healthcheck

The automated healthcheck needs to submit *some* URL that passes step 2
so it can exercise the redirect bypass, same as a real player's own
public server would. Since the healthcheck runs as a sidecar in the
*same pod* as the challenge (that's how kCTF wires up `healthcheck.image`
— see currency-arbitrage-kctf's README for the `:45281/healthz`
research this is built on), its redirector is also only reachable via
loopback, from the challenge's point of view indistinguishable in *IP*
from `flag-service` itself. So the challenge carries a narrow
allowlist, `TRUSTED_TEST_HOSTS`, that skips step 2 for exactly the
healthcheck's own redirector — a normal, common real-world pattern
(operators allowlist their own monitoring infrastructure against their
own SSRF defenses all the time).

My first version of that allowlist matched on **hostname only**. I
caught the problem by trying to break my own fix: `flag-service` and
the healthcheck's redirector both resolve to `127.0.0.1` (same pod,
shared network namespace), so allowlisting the bare hostname
`healthcheck-redirector` meant a player could submit
`http://healthcheck-redirector:8080/secret-message` directly —
same loopback IP as `flag-service`, different label, and the allowlist
would wave it straight through with **no redirect needed at all**,
trivializing the entire challenge.

Fixed by keying the allowlist on `host:port`
(`healthcheck-redirector:9001`, matching the redirector's actual
listening port — see `challenge/app/frontend/app.py`'s `_host_port()`)
instead of host alone. Re-tested directly:

```
POST /audit  url=http://healthcheck-redirector:8080/secret-message
  -> 400, "internal/private" (correctly blocked -- wrong port, not trusted)
POST /audit  url=http://healthcheck-redirector:9001/whatever
  -> passes validation (this IS the trusted healthcheck port)
```

## Directory Structure

```
blindside-kctf/
├── challenge/
│   ├── app/
│   │   ├── frontend/          ← LinkAudit Pro (the vulnerable app)
│   │   │   ├── app.py
│   │   │   ├── requirements.txt
│   │   │   └── templates/{index.html,report.html}
│   │   ├── flagservice/       ← internal-only secret endpoint
│   │   │   ├── app.py
│   │   │   └── requirements.txt
│   │   └── start.sh           ← runs both processes in one jail
│   ├── Dockerfile
│   └── web-servers.nsjail.cfg
├── healthcheck/
│   ├── healthcheck.py          ← drives the real exploit over HTTP
│   ├── redirector.py           ← healthcheck's own "player server" stand-in
│   ├── healthcheck_loop.sh
│   ├── healthz_webserver.py
│   ├── requirements.txt
│   └── Dockerfile
├── challenge.yaml
└── README.md
```

## What I actually tested (no Docker/kCTF, in this sandbox)

This sandbox has no Docker daemon, so instead of building the images I
ran the real `frontend/app.py` and `flagservice/app.py` as ordinary
processes, plus a small stand-in for "a player's own server"
(`attacker/server.py`, not shipped — just a test harness) returning a
302 to `flag-service`. `/etc/hosts` got the same two entries the
Dockerfile bakes in (`flag-service`, `healthcheck-redirector` →
`127.0.0.1`), so hostname resolution behaves exactly like it will in
the container.

```bash
# terminal 1
python3 challenge/app/flagservice/app.py

# terminal 2 (TRUSTED_TEST_HOSTS matches challenge.yaml's env var)
cd challenge/app/frontend
TRUSTED_TEST_HOSTS=healthcheck-redirector:9001 python3 -c "
from app import app
app.run(host='0.0.0.0', port=1337)
"

# terminal 3 -- the actual healthcheck, unmodified
cd healthcheck
python3 healthcheck.py
# -> recovered: CTF{ssrf_dns_yaml_bypass_iitm}
# -> exit 0
```

I also directly attempted the port-confusion trick described above
against the live server (`healthcheck-redirector:8080` instead of
`:9001`) and confirmed it's rejected with `400` after the fix, and
confirmed a direct `flag-service:8080` submission is rejected the same
way. Every one of these was a real HTTP request against a real running
Flask process — not a shortcut through the code.

**One real thing this setup can't fully exercise locally:** kCTF
deploys the healthcheck container in the same pod as the challenge —
confirmed by reading `kctf-operator`'s deployment code for the
`:45281/healthz` work in currency-arbitrage-kctf — so `127.0.0.1`
really is shared between them in production. In this single-process
sandbox I can only simulate that sharing via `/etc/hosts`, not prove
inter-pod loopback sharing directly; if you deploy this and the
healthcheck can't reach the challenge over `127.0.0.1`, that's the
first thing to check against your actual kCTF/k8s version.

## Wiring into kCTF

Same PHASE 1/2/6 steps as the other web challenges in this set
(currency-arbitrage-kctf, h2-smuggle-kctf) — `kctf chal create
the-blind-side --template web`, copy this repo's `challenge/` and
`healthcheck/` over the scaffold, build/push, `kubectl apply -f
challenge.yaml`.

**Don't forget:** `challenge.yaml`'s `TRUSTED_TEST_HOSTS` env var
(`healthcheck-redirector:9001`) must match `redirector.py`'s
`REDIRECTOR_PORT` (default `9001`) and the hostname baked into
`challenge/Dockerfile`'s `/etc/hosts` entry. If you change one, change
all three, or the automated healthcheck will start failing while the
challenge itself is still perfectly solvable by a real player.

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Re-validating the redirect target | Defeats the entire challenge — the point is that step 2 only runs once |
| Allowlisting the healthcheck by hostname alone | Same loopback IP as `flag-service` means a player can swap in `flag-service`'s port and skip the redirect entirely — key the allowlist on `host:port`, not host |
| Binding `flag-service` to `0.0.0.0` instead of `127.0.0.1` | Makes it reachable from outside the pod directly (if the pod's IP is ever exposed by anything else), removing the actual network boundary the challenge depends on |
| Using `requests.get(url)` with default redirect-following | `allow_redirects=True` would follow *chains* of redirects with no visibility into each hop at all — worse than this bug, not more realistic |
| UID mismatch between Dockerfile and nsjail.cfg | Both must use UID 1000 |
