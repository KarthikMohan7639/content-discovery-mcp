"""A small async token-bucket rate limiter with adaptive backoff.

Keeps the scanner gentle on the target by default (conservative req/s),
and backs off automatically when the target signals it's under strain
(429 Too Many Requests, 503 Service Unavailable, or a Retry-After header).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass


@dataclass
class RateLimiter:
    requests_per_second: float = 5.0
    max_concurrency: int = 5
    _tokens: float = 0.0
    _last_refill: float = 0.0
    _backoff_until: float = 0.0
    _lock: asyncio.Lock | None = None
    _sem: asyncio.Semaphore | None = None

    def __post_init__(self) -> None:
        self._tokens = self.requests_per_second
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
        self._sem = asyncio.Semaphore(self.max_concurrency)

    async def acquire(self) -> None:
        await self._sem.acquire()
        async with self._lock:
            now = time.monotonic()
            if now < self._backoff_until:
                await asyncio.sleep(self._backoff_until - now)
                now = time.monotonic()

            elapsed = now - self._last_refill
            self._tokens = min(
                self.requests_per_second, self._tokens + elapsed * self.requests_per_second
            )
            self._last_refill = now

            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self.requests_per_second
                await asyncio.sleep(wait)
                self._tokens = 0.0
                self._last_refill = time.monotonic()
            else:
                self._tokens -= 1.0

    def release(self) -> None:
        self._sem.release()

    def note_response(self, status_code: int, retry_after: str | None) -> None:
        """Called after every response so the limiter can react to server pressure."""
        if status_code in (429, 503):
            delay = 2.0
            if retry_after:
                try:
                    delay = max(delay, float(retry_after))
                except ValueError:
                    pass
            self._backoff_until = max(self._backoff_until, time.monotonic() + delay)
            # halve our own rate going forward, down to a floor
            self.requests_per_second = max(0.5, self.requests_per_second / 2)
