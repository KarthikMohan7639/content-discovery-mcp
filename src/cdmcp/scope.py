"""Scope allowlist enforcement.

Every outbound request the scanner makes is checked against an explicit
allowlist of hosts before it is sent. Anything outside scope is refused
and the refusal is logged to an append-only JSONL audit log. There is no
override for this check from inside a scan: scope is set once via the
`set_scope` MCP tool and re-checked per request, so a wordlist entry or a
redirect can't walk the scanner off-target.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_AUDIT_LOG = Path("logs/scope_audit.jsonl")


@dataclass
class ScopeViolation(Exception):
    host: str
    reason: str

    def __str__(self) -> str:
        return f"host '{self.host}' is out of scope: {self.reason}"


@dataclass
class Scope:
    """An explicit allowlist of hosts (and optionally resolved IPs/CIDRs)."""

    patterns: list[str] = field(default_factory=list)
    allow_private_ips: bool = True
    audit_log: Path = DEFAULT_AUDIT_LOG

    def __post_init__(self) -> None:
        self.audit_log.parent.mkdir(parents=True, exist_ok=True)

    def set(self, hosts: list[str]) -> None:
        """Replace the allowlist. Patterns may use '*' wildcards, e.g. '*.example.com'."""
        self.patterns = [h.strip().lower() for h in hosts if h.strip()]

    def is_configured(self) -> bool:
        return bool(self.patterns)

    def _host_matches(self, host: str) -> bool:
        host = host.lower()
        for pattern in self.patterns:
            if fnmatch.fnmatch(host, pattern):
                return True
            # also allow a bare IP/CIDR pattern to match literal IPs
            try:
                if "/" in pattern:
                    if ipaddress.ip_address(host) in ipaddress.ip_network(pattern, strict=False):
                        return True
                elif host == pattern:
                    return True
            except ValueError:
                pass
        return False

    def check(self, url: str) -> str:
        """Raise ScopeViolation if `url`'s host isn't allowlisted. Returns the host on success."""
        host = (urlparse(url).hostname or "").lower()
        if not host:
            self._log_refusal(url, "unparseable host")
            raise ScopeViolation(url, "unparseable host")

        if not self.is_configured():
            self._log_refusal(host, "no scope configured; refusing by default")
            raise ScopeViolation(host, "no scope has been set — call set_scope first")

        if self._host_matches(host):
            return host

        # Also resolve and check literal IP in case the allowlist is IP-based
        # and the URL uses a hostname that resolves to an in-scope IP's alias.
        try:
            resolved = socket.gethostbyname(host)
            if self._host_matches(resolved):
                return host
        except OSError:
            pass

        self._log_refusal(host, "not in allowlist")
        raise ScopeViolation(host, "not in allowlist")

    def _log_refusal(self, host: str, reason: str) -> None:
        entry = {
            "ts": time.time(),
            "event": "scope_refused",
            "host": host,
            "reason": reason,
            "allowlist": list(self.patterns),
        }
        with self.audit_log.open("a") as f:
            f.write(json.dumps(entry) + "\n")
