"""Detects common attack signatures in web server access logs.

Covers three lightweight, explainable heuristics:
  1. Payload signatures — SQLi / XSS / path-traversal patterns in the
     request path.
  2. Scanner fingerprints — user agents associated with known scanning
     tools (sqlmap, nikto, nmap NSE http scripts, etc.).
  3. Recon bursts — a single IP generating many 4xx responses in a
     short time, indicating directory/endpoint brute-forcing.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable, List

from ..parsers.web_log import WebEvent

# Request paths in real access logs are URL-encoded, so patterns match
# both the literal character and its %-encoded form (space -> \s|%20, etc).
_SP = r"(?:\s|%20|\+)"
_PAYLOAD_PATTERNS = {
    "SQL Injection": re.compile(
        rf"(\bunion{_SP}+select\b|\bor{_SP}+1=1\b|--{_SP}|;--|\bdrop{_SP}+table\b|'{_SP}*or{_SP}*)",
        re.IGNORECASE,
    ),
    "XSS": re.compile(r"(<script|%3cscript|onerror=|onload=|javascript:)", re.IGNORECASE),
    "Path Traversal": re.compile(r"(\.\./|\.\.%2f|%2e%2e%2f)", re.IGNORECASE),
    "Command Injection": re.compile(rf"((;|\||%3b){_SP}*(cat|whoami|wget|curl|nc){_SP})", re.IGNORECASE),
}

_SCANNER_USER_AGENTS = re.compile(
    r"(sqlmap|nikto|nmap|nessus|acunetix|masscan|dirbuster|gobuster|wpscan)",
    re.IGNORECASE,
)


@dataclass
class WebAttackAlert:
    kind: str
    ip: str
    detail: str
    count: int = 1

    def summary(self) -> str:
        return f"[{self.kind}] {self.ip}: {self.detail} (x{self.count})"


def detect_web_attacks(
    events: Iterable[WebEvent],
    recon_threshold: int = 15,
) -> List[WebAttackAlert]:
    events = list(events)
    alerts: List[WebAttackAlert] = []

    payload_hits: dict[tuple[str, str], int] = defaultdict(int)
    scanner_hits: dict[str, int] = defaultdict(int)
    four_oh_x: dict[str, int] = defaultdict(int)

    for e in events:
        for name, pattern in _PAYLOAD_PATTERNS.items():
            if pattern.search(e.path):
                payload_hits[(name, e.ip)] += 1

        if _SCANNER_USER_AGENTS.search(e.user_agent):
            scanner_hits[e.ip] += 1

        if 400 <= e.status < 500:
            four_oh_x[e.ip] += 1

    for (name, ip), count in payload_hits.items():
        alerts.append(WebAttackAlert(kind=name, ip=ip, detail="malicious payload in request path", count=count))

    for ip, count in scanner_hits.items():
        alerts.append(WebAttackAlert(kind="Known Scanner", ip=ip, detail="scanner user-agent detected", count=count))

    for ip, count in four_oh_x.items():
        if count >= recon_threshold:
            alerts.append(WebAttackAlert(kind="Recon / Endpoint Brute-Force", ip=ip, detail="high volume of 4xx responses", count=count))

    return alerts
