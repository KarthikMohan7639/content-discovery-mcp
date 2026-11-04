"""The scan engine: ties scope enforcement, fingerprinting, soft-404
filtering, rate limiting, and ranking together into one async job.

A scan runs as a background asyncio task so the MCP server can return a
scan_id immediately and let the agent poll for status/results instead of
blocking a tool call for the whole scan.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from .filters import SoftNotFoundFilter
from .fingerprint import fingerprint_target, load_wordlist
from .ranking import Hit, classify_and_score, group_and_rank
from .ratelimit import RateLimiter
from .scope import Scope, ScopeViolation

DEFAULT_TIMEOUT = 8.0
INTERESTING_STATUSES = {200, 201, 204, 301, 302, 307, 401, 403, 500}


@dataclass
class ScanConfig:
    base_url: str
    wordlists: list[str] | None = None
    extra_paths: list[str] | None = None
    requests_per_second: float = 5.0
    max_concurrency: int = 5
    max_paths: int = 2000
    timeout: float = DEFAULT_TIMEOUT


@dataclass
class ScanState:
    scan_id: str
    config: ScanConfig
    status: str = "pending"  # pending -> fingerprinting -> running -> done/error/stopped
    total: int = 0
    completed: int = 0
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    error: str | None = None
    fingerprint: dict | None = None
    hits: list[Hit] = field(default_factory=list)
    _stop_requested: bool = False

    def summary(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target": self.config.base_url,
            "status": self.status,
            "progress": f"{self.completed}/{self.total}",
            "fingerprint": self.fingerprint,
            "hit_count": len(self.hits),
            "error": self.error,
        }


class ScanManager:
    """Holds in-memory state for scans launched in this server process."""

    def __init__(self, scope: Scope) -> None:
        self.scope = scope
        self._scans: dict[str, ScanState] = {}

    def get(self, scan_id: str) -> ScanState | None:
        return self._scans.get(scan_id)

    def stop(self, scan_id: str) -> bool:
        scan = self._scans.get(scan_id)
        if not scan:
            return False
        scan._stop_requested = True
        return True

    async def start(self, config: ScanConfig) -> str:
        # Fail fast and loudly if the target isn't in scope — don't even
        # spin up the background task.
        self.scope.check(config.base_url)

        scan_id = uuid.uuid4().hex[:12]
        state = ScanState(scan_id=scan_id, config=config)
        self._scans[scan_id] = state
        asyncio.create_task(self._run(state))
        return scan_id

    async def _run(self, state: ScanState) -> None:
        try:
            self.scope.check(state.config.base_url)
        except ScopeViolation as e:
            state.status = "error"
            state.error = str(e)
            return

        state.status = "fingerprinting"
        limits = httpx.Limits(max_connections=state.config.max_concurrency)
        async with httpx.AsyncClient(
            timeout=state.config.timeout, limits=limits, follow_redirects=False
        ) as client:
            try:
                fp = await fingerprint_target(client, state.config.base_url)
            except httpx.HTTPError as e:
                state.status = "error"
                state.error = f"could not reach target to fingerprint: {e}"
                return
            state.fingerprint = fp.to_dict()

            wordlist_files = state.config.wordlists or fp.wordlists
            paths: list[str] = []
            for wl in wordlist_files:
                paths.extend(load_wordlist(wl))
            if state.config.extra_paths:
                paths.extend(state.config.extra_paths)
            # de-dupe, cap
            paths = list(dict.fromkeys(paths))[: state.config.max_paths]

            soft404 = SoftNotFoundFilter()
            limiter = RateLimiter(
                requests_per_second=state.config.requests_per_second,
                max_concurrency=state.config.max_concurrency,
            )

            # --- calibrate against fake-404 pages before the real scan ---
            for calib_path in soft404.calibration_paths():
                self.scope.check(state.config.base_url)  # re-check every request
                url = urljoin(state.config.base_url, calib_path.lstrip("/"))
                try:
                    await limiter.acquire()
                    resp = await client.get(url)
                    limiter.note_response(resp.status_code, resp.headers.get("retry-after"))
                    soft404.learn(resp.status_code, resp.text)
                except httpx.HTTPError:
                    pass
                finally:
                    limiter.release()

            state.total = len(paths)
            state.status = "running"

            async def probe(path: str) -> None:
                if state._stop_requested:
                    return
                self.scope.check(state.config.base_url)
                url = urljoin(state.config.base_url, path.lstrip("/"))
                await limiter.acquire()
                try:
                    resp = await client.get(url)
                    limiter.note_response(resp.status_code, resp.headers.get("retry-after"))
                    if resp.status_code in INTERESTING_STATUSES:
                        body = resp.text if resp.status_code < 400 else ""
                        if resp.status_code == 200 and soft404.is_noise(resp.status_code, body):
                            pass  # filtered as a fake "not found" page
                        else:
                            hit = classify_and_score(
                                "/" + path.lstrip("/"),
                                resp.status_code,
                                len(resp.content),
                            )
                            hit.url = url
                            state.hits.append(hit)
                except httpx.HTTPError:
                    pass
                finally:
                    limiter.release()
                    state.completed += 1

            await asyncio.gather(*(probe(p) for p in paths))

        state.status = "stopped" if state._stop_requested else "done"
        state.finished_at = time.time()

    def results(self, scan_id: str, top_n: int = 50) -> dict | None:
        state = self._scans.get(scan_id)
        if not state:
            return None
        return {
            "scan_id": scan_id,
            "target": state.config.base_url,
            "status": state.status,
            "fingerprint": state.fingerprint,
            "total_hits": len(state.hits),
            "groups": group_and_rank(state.hits, top_n=top_n),
        }
