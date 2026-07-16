"""Parser for Linux authentication logs (e.g. /var/log/auth.log).

Extracts SSH login attempts (failed, accepted, invalid-user) into
structured AuthEvent records that downstream detectors can consume.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator, Union

# Matches lines like:
#   Jul 14 03:22:11 server sshd[1234]: Failed password for invalid user admin from 192.168.1.5 port 51515 ssh2
#   Jul 14 03:22:15 server sshd[1234]: Accepted password for root from 192.168.1.5 port 51516 ssh2
#   Jul 14 03:22:20 server sshd[1234]: Failed password for root from 10.0.0.9 port 22334 ssh2
_AUTH_LINE_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<status>Failed|Accepted)\s+password\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<ip>[0-9a-fA-F:.]+)\s+port\s+(?P<port>\d+)"
)


@dataclass(frozen=True)
class AuthEvent:
    timestamp: datetime
    host: str
    status: str  # "Failed" or "Accepted"
    user: str
    ip: str
    port: int
    raw: str

    @property
    def success(self) -> bool:
        return self.status == "Accepted"


def _parse_timestamp(raw_ts: str, year: int | None = None) -> datetime:
    """Syslog timestamps have no year; assume current year unless given."""
    year = year or datetime.now().year
    dt = datetime.strptime(f"{year} {raw_ts}", "%Y %b %d %H:%M:%S")
    return dt


def parse_auth_log(path: Union[str, Path], year: int | None = None) -> Iterator[AuthEvent]:
    """Yield AuthEvent records parsed from an auth.log-style file.

    Lines that don't match the expected SSH login pattern are skipped
    silently — auth.log contains many unrelated entries (sudo, cron,
    systemd, etc.) that aren't relevant to login analysis.
    """
    path = Path(path)
    with path.open("r", errors="replace") as f:
        for line in f:
            match = _AUTH_LINE_RE.search(line)
            if not match:
                continue
            yield AuthEvent(
                timestamp=_parse_timestamp(match.group("timestamp"), year),
                host=match.group("host"),
                status=match.group("status"),
                user=match.group("user"),
                ip=match.group("ip"),
                port=int(match.group("port")),
                raw=line.rstrip("\n"),
            )
