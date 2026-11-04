"""End-to-end test through the real MCP transport.

Spawns `python -m cdmcp.server` over stdio exactly like an MCP client
(Claude Code / Claude Desktop) would, then calls every tool and checks the
results, including scope refusals and the audit log.

Prereq: the local target app must be running:
    python tests/target_app.py
Run:
    python tests/mcp_client_test.py
"""

import asyncio
import json
import sys
from pathlib import Path

from mcp import StdioServerParameters
from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent.parent
TARGET = "http://127.0.0.1:5055/"
AUDIT_LOG = ROOT / "logs" / "scope_audit.jsonl"


def payload(result) -> dict:
    """Pull the tool's JSON dict out of an MCP CallToolResult."""
    if getattr(result, "structuredContent", None):
        data = result.structuredContent
        return data.get("result", data) if isinstance(data, dict) else data
    return json.loads(result.content[0].text)


async def call(session: ClientSession, name: str, **args) -> dict:
    out = payload(await session.call_tool(name, args))
    print(f"-> {name}({', '.join(f'{k}={v!r}' for k, v in args.items())})")
    print("   ", json.dumps(out)[:300])
    return out


async def main() -> None:
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "cdmcp.server"],
        cwd=str(ROOT),
    )
    audit_before = AUDIT_LOG.read_text().count("\n") if AUDIT_LOG.exists() else 0

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = {t.name for t in (await session.list_tools()).tools}
            print("tools:", sorted(tools))
            expected = {"set_scope", "get_scope", "list_wordlists", "fingerprint",
                        "start_scan", "get_scan_status", "get_results", "stop_scan"}
            assert expected <= tools, f"missing tools: {expected - tools}"

            # 1. Refused by default: no scope set yet.
            r = await call(session, "start_scan", url=TARGET)
            assert "error" in r and "scope" in r["error"], r

            # 2. Set scope; an out-of-scope host must still be refused.
            await call(session, "set_scope", hosts=["127.0.0.1"])
            r = await call(session, "fingerprint", url="http://example.com/")
            assert "error" in r and "out of scope" in r["error"], r
            r = await call(session, "start_scan", url="http://10.0.0.5/")
            assert "error" in r, "10.0.0.5 is not in the allowlist, must be refused"
            # Note: "localhost" WOULD be allowed here, by design — hostnames
            # are resolved and accepted if they resolve to an allowlisted IP.

            # 3. In-scope fingerprint picks the Express wordlist.
            r = await call(session, "fingerprint", url=TARGET)
            assert "express" in r["stacks"], r

            await call(session, "list_wordlists")

            # 4. Scan, poll, get results.
            r = await call(session, "start_scan", url=TARGET,
                           requests_per_second=20, max_concurrency=10)
            scan_id = r["scan_id"]
            while True:
                s = payload(await session.call_tool("get_scan_status", {"scan_id": scan_id}))
                if s["status"] in ("done", "error", "stopped"):
                    break
                await asyncio.sleep(0.5)
            print("   final status:", json.dumps(s))
            assert s["status"] == "done", s

            res = await call(session, "get_results", scan_id=scan_id)
            paths = sorted(h["url"].replace(TARGET.rstrip("/"), "")
                           for g in res["groups"].values() for h in g)
            print("   hits:", paths)
            assert paths == sorted(["/.env", "/.git/HEAD", "/backup.sql", "/admin",
                                    "/login", "/api/health", "/robots.txt"]), paths
            top = max((h for g in res["groups"].values() for h in g), key=lambda h: h["score"])
            assert top["url"].endswith("/.env"), top

            r = await call(session, "get_results", scan_id="nope")
            assert "error" in r

    audit_after = AUDIT_LOG.read_text().count("\n") if AUDIT_LOG.exists() else 0
    assert audit_after >= audit_before + 3, "expected refusals in logs/scope_audit.jsonl"
    print(f"\naudit log: {audit_after - audit_before} new refusal(s) in {AUDIT_LOG}")
    print("ALL MCP ASSERTIONS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
