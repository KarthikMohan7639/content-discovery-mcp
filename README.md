# cdmcp — content discovery for AI agents

`cdmcp` is a directory/file brute-force (content-discovery) tool exposed as
an **MCP server**, so an AI agent can drive it the way it would drive
`ffuf` or `gobuster` from a terminal — but without having to hand-tune
wordlists, eyeball the output for fake 404s, or remember to throttle
itself.

It does four things ffuf/gobuster leave to the human operator:

1. **Picks a wordlist for the target's stack** — probes the homepage,
   looks at headers/cookies/body for stack signals (WordPress, PHP,
   Django, Spring Boot, Express, bare JSON APIs), and auto-selects the
   matching bundled wordlist(s) instead of blasting one giant generic
   list at everything.
2. **Filters out noise, including soft-404s** — before the real scan it
   probes a few paths that are statistically guaranteed not to exist,
   learns what the target's "not found" response looks like (status +
   length + content signature), and drops anything in the real scan that
   matches it — even when the target returns `200 OK` for a missing page
   (common with SPA routers and lazy error handlers).
3. **Rate-limits itself** — a token-bucket limiter caps requests/second
   and concurrency, and backs off automatically on `429`/`503` or a
   `Retry-After` header.
4. **Returns only what's interesting, grouped and ranked** — hits are
   classified into categories (secrets, VCS exposure, backup/dump files,
   admin panels, debug endpoints, API surface, config, auth, static,
   info) and scored with an explainable heuristic, so an agent gets a
   short structured answer instead of a wall of URLs.

## Safety model

- **Scope allowlist is mandatory.** `set_scope` takes an explicit list of
  host patterns (exact hosts, `*` wildcards, or bare IPs/CIDRs). Every
  single outbound request — including the calibration probes and every
  path in a running scan — is checked against this allowlist immediately
  before it's sent. If no scope has been set, **everything is refused by
  default**. Any refusal is appended to `logs/scope_audit.jsonl`.
- **This tool makes real HTTP requests to whatever host you put in
  scope.** Only point it at infrastructure you own or control, or at a
  deliberately vulnerable target you run yourself (OWASP Juice Shop, DVWA,
  the bundled test app below). Don't put a host you don't control in the
  allowlist.
- Scans are rate-limited by default (5 req/s, concurrency 5) — gentle
  enough to be polite, slow enough that you should still only run it
  against things you're allowed to load-test.

## Install

```bash
pip install -e ".[dev]"   # the [dev] extra pulls in Flask, only needed for the local test target
```

Requires Python ≥ 3.10 and `mcp` ≥ 2.0 (the SDK renamed `FastMCP` to
`MCPServer` in 2.x — same API, different import path).

## Run it as an MCP server

```bash
python -m cdmcp.server
```

This speaks MCP over stdio. Point any MCP client at it, e.g. for
Claude Desktop / Claude Code (`mcp.json` / `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "content-discovery": {
      "command": "python",
      "args": ["-m", "cdmcp.server"],
      "cwd": "/absolute/path/to/content-discovery-mcp/src"
    }
  }
}
```

## Tools exposed

| Tool | Purpose |
|---|---|
| `set_scope(hosts: list[str])` | Replace the allowlist. Must be called before anything else will run. |
| `get_scope()` | See the current allowlist. |
| `list_wordlists()` | List bundled wordlist filenames. |
| `fingerprint(url)` | One GET request; reports detected stack + which wordlists would be chosen. Scope-checked. |
| `start_scan(url, wordlists=None, extra_paths=None, requests_per_second=5.0, max_concurrency=5, max_paths=2000)` | Starts a scan in the background, returns `scan_id` immediately. Auto-fingerprints if `wordlists` is omitted. |
| `get_scan_status(scan_id)` | Progress counts + current fingerprint — cheap to poll. |
| `get_results(scan_id, top_n=50)` | Grouped, ranked hits. Callable while still running for partial results. |
| `stop_scan(scan_id)` | Asks an in-progress scan to stop early. |

Every tool returns a small JSON-able dict — no prose, nothing an agent
has to parse out of free text.

### Example agent flow

```
set_scope(["127.0.0.1"])
start_scan("http://127.0.0.1:5055/")          -> {"scan_id": "96d641e91077", "status": "started"}
get_scan_status("96d641e91077")               -> {"status": "running", "progress": "47/112", ...}
get_results("96d641e91077")                   -> grouped hits, see below
```

## Design choices

**Wordlist selection is signal-based, not size-based.** Rather than
shipping one 50k-line list, `cdmcp` ships small, curated per-stack lists
(`php.txt`, `wordpress.txt`, `django.txt`, `java_spring.txt`,
`node_express.txt`, `api_common.txt`, plus a `generic.txt` baseline) and
picks which ones apply from `Server`/`X-Powered-By` headers, session
cookie names (`PHPSESSID`, `csrftoken`, `JSESSIONID`, `connect.sid`), and
body markers (`wp-content`, Spring's "Whitelabel Error Page", etc.). This
keeps scans fast and keeps the hit list dominated by plausible paths
instead of generic noise.

**Soft-404 detection is calibration, not a fixed rule.** A fixed "ignore
all 200s" rule would hide real hits (plenty of real admin panels and API
endpoints correctly return 200). Instead, before the real scan, `cdmcp`
requests a handful of paths built from random tokens — paths that are
astronomically unlikely to exist — and records their status, length, and
a normalized content signature as a baseline. During the scan, any
response matching a baseline's status *and* content closely (length
within tolerance and a `difflib` similarity ratio ≥ 0.92) is dropped,
regardless of its status code. This caught every one of ~100 "not found"
responses in testing (see below) without touching any of the 7 real
hidden paths.

**Rate limiting reacts to the target, not just a fixed cap.** The token
bucket enforces a baseline req/s and concurrency, but also watches every
response: a `429`/`503` or `Retry-After` header triggers an immediate
cooldown and halves the limiter's rate going forward (down to a floor),
so a scan degrades gracefully under load instead of hammering a
struggling target.

**Ranking is an explainable heuristic, not ML.** Hits are regex-matched
against category patterns (secrets > VCS exposure > backup/dump > admin
panel > debug > API surface > config > auth > static > info) and scored
with status-code weighting (401/403 "exists but gated" scores *higher*
than a plain 200 — it's often more interesting). Every hit carries a
`reasons` list explaining its score, because the consumer is an agent
that benefits from being able to see why something ranked where it did,
not just a black-box number.

**Scans run as background asyncio tasks.** `start_scan` returns
immediately with a `scan_id`; the agent polls `get_scan_status` /
`get_results` rather than blocking an MCP tool call for the duration of
a scan (which can be the whole point when a target is intentionally
rate-limited).

## Testing it yourself

A small deliberately-flawed Flask app is bundled for safe local testing
— it fakes an Express backend, returns a plausible **soft-404** page
(HTTP 200) for any unknown path, and hides a handful of real sensitive
paths (`.env`, `.git/HEAD`, `backup.sql`, `/admin`, `/login`,
`/api/health`, `robots.txt`) among them.

```bash
python tests/target_app.py            # starts on http://127.0.0.1:5055/
python tests/run_e2e.py               # drives the scanner directly, asserts correctness
```

Real output from a run against the bundled test app (112 requests, ~100
of them soft-404 noise, correctly reduced to the 7 real hits):

```json
{
  "fingerprint": { "stacks": ["express"], "evidence": ["X-Powered-By/cookie indicates Express (express)"] },
  "total_hits": 7,
  "groups": {
    "secrets":      [{ "url": ".../.env",        "status": 200, "score": 110 }],
    "vcs-exposure": [{ "url": ".../.git/HEAD",    "status": 200, "score": 105 }],
    "backup-dump":  [{ "url": ".../backup.sql",   "status": 200, "score": 95  }],
    "admin-panel":  [{ "url": ".../admin",        "status": 200, "score": 85  }],
    "api-surface":  [{ "url": ".../api/health",   "status": 200, "score": 65  }],
    "auth":         [{ "url": ".../login",        "status": 200, "score": 55  }],
    "info":         [{ "url": ".../robots.txt",   "status": 200, "score": 20  }]
  }
}
```

To test against OWASP Juice Shop or DVWA instead, run either locally
(e.g. `docker run -p 3000:3000 bkimminich/juice-shop`) and put its
*local* address in scope — e.g. `set_scope(["127.0.0.1"])` — never a
public host you don't control.

## Project layout

```
src/cdmcp/
  server.py        MCP server + tool definitions
  scanner.py        async scan engine tying everything together
  scope.py          allowlist enforcement + audit logging
  fingerprint.py    tech-stack detection + wordlist selection
  filters.py         soft-404 calibration/detection
  ratelimit.py       token-bucket rate limiter with backoff
  ranking.py        hit classification, scoring, grouping
  wordlists/*.txt   bundled per-stack wordlists
tests/
  target_app.py     local deliberately-flawed Flask app for safe testing
  run_e2e.py        end-to-end smoke test against it
```
