"""Parser for web server access logs in Combined Log Format
(the default for Apache and Nginx).

Example line:
127.0.0.1 - - [14/Jul/2026:03:22:11 +0000] "GET /login?user=admin' OR 1=1-- HTTP/1.1" 200 512 "-" "Mozilla/5.0"
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator, Union

_COMBINED_LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+'
    r'"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
)


@dataclass(frozen=True)
class WebEvent:
    timestamp: datetime
    ip: str
    method: str
    path: str
    status: int
    user_agent: str
    raw: str


def _parse_timestamp(raw_ts: str) -> datetime:
    # e.g. 14/Jul/2026:03:22:11 +0000
    return datetime.strptime(raw_ts.split(" ")[0], "%d/%b/%Y:%H:%M:%S")


def parse_web_log(path: Union[str, Path]) -> Iterator[WebEvent]:
    """Yield WebEvent records parsed from a Combined Log Format file."""
    path = Path(path)
    with path.open("r", errors="replace") as f:
        for line in f:
            match = _COMBINED_LOG_RE.search(line)
            if not match:
                continue
            yield WebEvent(
                timestamp=_parse_timestamp(match.group("timestamp")),
                ip=match.group("ip"),
                method=match.group("method"),
                path=match.group("path"),
                status=int(match.group("status")),
                user_agent=match.group("user_agent"),
                raw=line.rstrip("\n"),
            )
