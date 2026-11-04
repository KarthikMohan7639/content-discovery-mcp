"""Drives the scanner's internals directly (bypassing the MCP transport,
which is just a thin wrapper) against the local target app, as an
end-to-end smoke test."""

import asyncio
import json
import sys
import time

sys.path.insert(0, "src")

from cdmcp.scanner import ScanConfig, ScanManager
from cdmcp.scope import Scope


async def main() -> None:
    scope = Scope(allow_private_ips=True)
    scope.set(["127.0.0.1", "localhost"])
    manager = ScanManager(scope)

    config = ScanConfig(
        base_url="http://127.0.0.1:5055/",
        requests_per_second=20,  # fast for local test; defaults are gentler
        max_concurrency=10,
    )
    scan_id = await manager.start(config)
    print("scan_id:", scan_id)

    while True:
        state = manager.get(scan_id)
        print("status:", state.summary())
        if state.status in ("done", "error", "stopped"):
            break
        await asyncio.sleep(0.3)

    results = manager.results(scan_id)
    print(json.dumps(results, indent=2))

    # Assertions for the smoke test
    assert results["fingerprint"]["stacks"] == ["express"], results["fingerprint"]
    categories = results["groups"]
    assert "secrets" in categories, "expected .env to be found"
    assert "vcs-exposure" in categories, "expected .git/HEAD to be found"
    assert "backup-dump" in categories, "expected backup.sql to be found"
    assert "admin-panel" in categories, "expected /admin to be found"

    found_paths = {
        hit["url"].replace("http://127.0.0.1:5055", "")
        for group in categories.values()
        for hit in group
    }
    print("\nFound paths:", sorted(found_paths))
    # The soft-404 catch-all must NOT appear for made-up paths.
    assert all(
        not p.startswith("/zzz") for p in found_paths
    ), "soft-404 filter failed to suppress noise"

    print("\nALL ASSERTIONS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
