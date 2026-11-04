"""Groups and ranks raw hits into something an agent can act on without
having to re-derive what matters from a flat list of URLs.

Ranking is a simple, explainable heuristic score — not ML — because the
consumer is an agent that benefits from being able to see *why* something
ranked where it did.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_CATEGORY_RULES: list[tuple[str, re.Pattern, int]] = [
    ("secrets", re.compile(r"\.env($|\.)|secrets?\.json|credentials|id_rsa|\.ssh/"), 100),
    ("vcs-exposure", re.compile(r"\.git/|\.svn/|\.hg/"), 95),
    ("backup-dump", re.compile(r"\.(bak|old|sql|zip|tar\.gz|dump)$"), 85),
    ("admin-panel", re.compile(r"(^|/)(admin|wp-admin|wp-login|console|actuator|h2-console)"), 75),
    ("debug-diagnostics", re.compile(r"(debug|phpinfo|heapdump|threaddump|error_log|actuator/env)"), 70),
    ("api-surface", re.compile(r"(^|/)(api|graphql|swagger|openapi|api-docs)"), 55),
    ("config", re.compile(r"(config|settings|\.ini|\.properties|\.ya?ml)"), 50),
    ("auth", re.compile(r"(login|logout|auth|oauth|register|signup)"), 45),
    ("uploads-static", re.compile(r"(^|/)(uploads?|static|public|media|assets)"), 20),
    ("info", re.compile(r"(robots\.txt|sitemap|readme|license|changelog|favicon)"), 10),
]

STATUS_WEIGHT = {
    200: 10,
    201: 10,
    301: 4,
    302: 4,
    307: 4,
    401: 25,  # exists and is gated — often interesting
    403: 25,
    500: 15,  # triggered an error — worth a look
}


@dataclass
class Hit:
    url: str
    path: str
    status_code: int
    content_length: int
    category: str = "other"
    score: int = 0
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status": self.status_code,
            "length": self.content_length,
            "category": self.category,
            "score": self.score,
            "reasons": self.reasons,
        }


def classify_and_score(path: str, status_code: int, content_length: int) -> Hit:
    category = "other"
    score = 0
    reasons: list[str] = []

    for name, pattern, weight in _CATEGORY_RULES:
        if pattern.search(path):
            category = name
            score += weight
            reasons.append(f"path matches '{name}' pattern")
            break

    status_bonus = STATUS_WEIGHT.get(status_code, 5)
    score += status_bonus
    reasons.append(f"status {status_code} (+{status_bonus})")

    if content_length == 0:
        score -= 5
        reasons.append("empty body (-5)")

    return Hit(
        url=path,
        path=path,
        status_code=status_code,
        content_length=content_length,
        category=category,
        score=max(score, 0),
        reasons=reasons,
    )


def group_and_rank(hits: list[Hit], top_n: int = 50) -> dict:
    ranked = sorted(hits, key=lambda h: h.score, reverse=True)[:top_n]
    groups: dict[str, list[dict]] = {}
    for h in ranked:
        groups.setdefault(h.category, []).append(h.to_dict())
    # order categories by their highest-scoring member
    ordered = dict(
        sorted(groups.items(), key=lambda kv: max(item["score"] for item in kv[1]), reverse=True)
    )
    return ordered
