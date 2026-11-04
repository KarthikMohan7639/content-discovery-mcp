"""MCP server exposing the content-discovery tool to any MCP client.

Run with:
    python -m cdmcp.server
or point an MCP client's stdio config at this module.

All tool outputs are kept short and structured (small dicts/lists) so an
agent can read them directly without having to parse prose.
"""

from __future__ import annotations

import httpx
from mcp.server.mcpserver import MCPServer

from .fingerprint import available_wordlists, fingerprint_target as _fingerprint_target
from .scanner import ScanConfig, ScanManager
from .scope import Scope, ScopeViolation

mcp = MCPServer("content-discovery")

_scope = Scope()
_manager = ScanManager(_scope)


@mcp.tool()
def set_scope(hosts: list[str]) -> dict:
    """Set the allowlist of hosts this tool is permitted to scan.

    Patterns may include '*' wildcards (e.g. "*.lab.local") or bare
    IPs/CIDRs (e.g. "127.0.0.1", "10.0.0.0/24"). Replaces any previous
    scope. Every request the scanner makes is checked against this list;
    anything outside it is refused and logged, never sent.
    """
    _scope.set(hosts)
    return {"scope": list(_scope.patterns)}


@mcp.tool()
def get_scope() -> dict:
    """Return the currently configured scan allowlist."""
    return {"scope": list(_scope.patterns), "configured": _scope.is_configured()}


@mcp.tool()
def list_wordlists() -> dict:
    """List the built-in wordlists bundled with this tool, by filename."""
    return {"wordlists": available_wordlists()}


@mcp.tool()
async def fingerprint(url: str) -> dict:
    """Probe a single URL's homepage and report detected tech-stack signals.

    Does not brute-force anything — one GET request, used to decide which
    wordlist(s) a scan would pick. Still enforced by the scope allowlist.
    """
    try:
        _scope.check(url)
    except ScopeViolation as e:
        return {"error": str(e)}
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
        try:
            fp = await _fingerprint_target(client, url)
        except httpx.HTTPError as e:
            return {"error": f"could not reach target: {e}"}
    return fp.to_dict()


@mcp.tool()
async def start_scan(
    url: str,
    wordlists: list[str] | None = None,
    extra_paths: list[str] | None = None,
    requests_per_second: float = 5.0,
    max_concurrency: int = 5,
    max_paths: int = 2000,
) -> dict:
    """Start a content-discovery scan against `url` and return a scan_id.

    Runs in the background — poll `get_scan_status` / `get_results` with
    the returned scan_id. If `wordlists` is omitted, the tool fingerprints
    the target first and auto-picks matching wordlist(s). `url`'s host
    must already be in the allowlist set via `set_scope`, or this is
    refused immediately.
    """
    config = ScanConfig(
        base_url=url,
        wordlists=wordlists,
        extra_paths=extra_paths,
        requests_per_second=requests_per_second,
        max_concurrency=max_concurrency,
        max_paths=max_paths,
    )
    try:
        scan_id = await _manager.start(config)
    except ScopeViolation as e:
        return {"error": str(e)}
    return {"scan_id": scan_id, "status": "started"}


@mcp.tool()
def get_scan_status(scan_id: str) -> dict:
    """Return progress for a running or finished scan (counts, not hits)."""
    state = _manager.get(scan_id)
    if not state:
        return {"error": f"no such scan_id: {scan_id}"}
    return state.summary()


@mcp.tool()
def get_results(scan_id: str, top_n: int = 50) -> dict:
    """Return the interesting hits for a scan, grouped by category and
    ranked by an explainable interestingness score, with noise filtered.

    Call once a scan's status is 'done' (or anytime for partial results
    while it's still 'running').
    """
    results = _manager.results(scan_id, top_n=top_n)
    if not results:
        return {"error": f"no such scan_id: {scan_id}"}
    return results


@mcp.tool()
def stop_scan(scan_id: str) -> dict:
    """Request that an in-progress scan stop as soon as possible."""
    ok = _manager.stop(scan_id)
    return {"stopped": ok}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
