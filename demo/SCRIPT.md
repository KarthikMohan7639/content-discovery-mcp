# 2–3 minute demo script

Goal: show an agent driving `cdmcp` end-to-end against the bundled local
test target, hitting every ground rule along the way.

1. **(0:00–0:20) Setup shot.** Terminal 1: `python tests/target_app.py`
   running. Terminal 2 or an MCP-enabled chat client (Claude Code /
   Claude Desktop) with `content-discovery` configured as an MCP server.
   Say in one line what the tool is and that the target is a local,
   deliberately-flawed test app you built — not a live site.

2. **(0:20–0:40) Scope refusal.** Ask the agent to scan
   `http://127.0.0.1:5055/` *before* setting scope. Show the refusal
   (`"no scope has been set"`) and the matching line appended to
   `logs/scope_audit.jsonl`. This is the one thing to make sure is
   clearly on camera — it's the main safety guarantee.

3. **(0:40–1:10) Set scope, fingerprint.** Ask the agent to allow
   `127.0.0.1` and fingerprint the target. Point out the detected stack
   (`express`, via the `X-Powered-By` header and `connect.sid` cookie)
   and the wordlists it picked.

4. **(1:10–2:00) Run the scan, watch it rate-limit.** Start the scan,
   poll status a couple of times, note the req/s and concurrency caps in
   the request pacing. Let it finish.

5. **(2:00–2:40) Show the results.** Pull up `get_results` — point out:
   - the ~100 fake "not found" hits that got filtered out (mention the
     count from `get_scan_status`'s `progress` vs the final `total_hits`)
   - the 7 real hits, grouped by category and ranked, with `.env` and
     `.git/HEAD` at the top
   - that an out-of-scope URL typed into the same session is refused the
     same way as step 2

6. **(2:40–3:00) Wrap.** One sentence on what you'd add next (e.g. a
   bigger wordlist set, response-diffing across multiple soft-404
   samples, auth-aware scanning).

Recording tip: a terminal recording (asciinema / plain screen capture)
of the exact commands in `tests/run_e2e.py`'s flow, or the MCP-client
session in this README's "Example agent flow", covers all of the above
without needing to narrate much.
