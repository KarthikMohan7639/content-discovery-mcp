"""Lightweight tech-stack fingerprinting.

Looks at response headers, cookies, and the homepage body for well-known
signals, then maps what it finds to one or more bundled wordlists. This
keeps a scan from blasting a generic 50k-line wordlist at every target —
most of the value in content discovery comes from a few hundred
stack-appropriate guesses, not a huge generic list.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

WORDLIST_DIR = __file__.rsplit("/", 1)[0] + "/wordlists"

# (signal description, wordlist file) pairs, most specific first.
_SIGNATURES: list[tuple[str, str]] = [
    ("wordpress", "wordpress.txt"),
    ("php", "php.txt"),
    ("django", "django.txt"),
    ("spring", "java_spring.txt"),
    ("express", "node_express.txt"),
]


@dataclass
class Fingerprint:
    stacks: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    wordlists: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "stacks": self.stacks,
            "evidence": self.evidence,
            "wordlists": self.wordlists,
        }


def _detect(headers: httpx.Headers, cookies: httpx.Cookies, body: str) -> Fingerprint:
    stacks: list[str] = []
    evidence: list[str] = []

    server = headers.get("server", "").lower()
    powered_by = headers.get("x-powered-by", "").lower()
    cookie_names = {c.lower() for c in cookies.keys()}
    body_lower = body[:20000].lower()

    def add(stack: str, why: str) -> None:
        if stack not in stacks:
            stacks.append(stack)
            evidence.append(why)

    if "php" in powered_by or "phpsessid" in cookie_names:
        add("php", f"X-Powered-By/cookie indicates PHP ({powered_by or 'PHPSESSID cookie'})")
    if "wp-content" in body_lower or "wp-json" in body_lower or "wordpress" in body_lower:
        add("wordpress", "homepage references wp-content/wp-json")
    if "csrftoken" in cookie_names or "django" in server:
        add("django", "csrftoken cookie / Server header suggests Django")
    if "jsessionid" in cookie_names or "spring" in body_lower or "whitelabel error page" in body_lower:
        add("spring", "JSESSIONID cookie or Spring Boot error page markers")
    if "express" in powered_by or "connect.sid" in cookie_names:
        add("express", f"X-Powered-By/cookie indicates Express ({powered_by or 'connect.sid cookie'})")
    if "application/json" in headers.get("content-type", "").lower() and not stacks:
        add("api", "homepage served as JSON with no other stack signal")

    wordlists = ["generic.txt"]
    for stack_name, wordlist_file in _SIGNATURES:
        if stack_name in stacks:
            wordlists.append(wordlist_file)
    if "api" in stacks or any(s in stacks for s in ("express", "spring", "django")):
        wordlists.append("api_common.txt")

    # de-dupe, keep order
    seen = set()
    deduped = []
    for w in wordlists:
        if w not in seen:
            seen.add(w)
            deduped.append(w)

    return Fingerprint(stacks=stacks or ["unknown"], evidence=evidence, wordlists=deduped)


async def fingerprint_target(client: httpx.AsyncClient, base_url: str) -> Fingerprint:
    resp = await client.get(base_url, follow_redirects=True)
    return _detect(resp.headers, resp.cookies, resp.text)


def load_wordlist(filename: str) -> list[str]:
    path = f"{WORDLIST_DIR}/{filename}"
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def available_wordlists() -> list[str]:
    import os

    return sorted(f for f in os.listdir(WORDLIST_DIR) if f.endswith(".txt"))
