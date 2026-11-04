"""Noise filtering: detect "soft 404s" — pages that return HTTP 200 but are
really a generic not-found / catch-all page (common on SPA routers, CMSes,
and custom error handlers that don't bother setting the status code).

Approach: before brute-forcing, probe a handful of paths that are
statistically very unlikely to exist (random tokens, several lengths and
extensions). Record their status code, content length, and a lightweight
content signature. During the real scan, any response that matches one of
these baseline signatures closely is treated as noise and dropped, even
if its status code is 200.
"""

from __future__ import annotations

import difflib
import random
import re
import string
from dataclasses import dataclass, field

_WORD_RE = re.compile(r"\s+")


def _normalize(text: str, limit: int = 4000) -> str:
    """Collapse whitespace and strip the sample down so diffing stays cheap."""
    return _WORD_RE.sub(" ", text[:limit]).strip()


def _random_token(n: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


@dataclass
class Baseline:
    status_code: int
    content_length: int
    signature: str


@dataclass
class SoftNotFoundFilter:
    """Learns what a target's "not found" response looks like, then filters it out."""

    similarity_threshold: float = 0.92
    length_tolerance: float = 0.05  # 5% length difference still counts as "same page"
    baselines: list[Baseline] = field(default_factory=list)

    def calibration_paths(self, extensions: list[str] | None = None) -> list[str]:
        """Paths to probe before the real scan, designed to almost certainly 404."""
        exts = extensions or ["", ".html", ".php", ".json"]
        paths = []
        for ext in exts:
            paths.append(f"/{_random_token()}{ext}")
        # also probe a couple of nested-looking paths, since some apps only
        # fake a 200 for "file-looking" top-level requests
        paths.append(f"/{_random_token()}/{_random_token()}")
        return paths

    def learn(self, status_code: int, body: str) -> None:
        self.baselines.append(
            Baseline(
                status_code=status_code,
                content_length=len(body),
                signature=_normalize(body),
            )
        )

    def is_noise(self, status_code: int, body: str) -> bool:
        if not self.baselines:
            return False
        norm = _normalize(body)
        length = len(body)
        for b in self.baselines:
            if b.status_code != status_code:
                continue
            if b.content_length == 0 and length == 0:
                return True
            if b.content_length > 0:
                abs_diff = abs(length - b.content_length)
                rel_diff = abs_diff / b.content_length
                # Skip this baseline only if the lengths differ by more than
                # both the relative tolerance AND a small absolute cushion
                # (so short pages with a few dynamic bytes still match).
                if rel_diff > self.length_tolerance and abs_diff > 50:
                    continue
            ratio = difflib.SequenceMatcher(None, norm, b.signature).quick_ratio()
            if ratio >= self.similarity_threshold:
                return True
        return False
