"""Detects brute-force SSH login attempts from parsed AuthEvents.

Heuristic: flag any source IP with >= `threshold` failed attempts within
a rolling `window_minutes` window. Also flags "failed-then-succeeded"
sequences, which often indicate a successful brute-force compromise.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Iterable, List

from ..parsers.auth_log import AuthEvent


@dataclass
class BruteForceAlert:
    ip: str
    failed_attempts: int
    users_tried: List[str]
    first_seen: object
    last_seen: object
    compromised: bool = False  # True if a later Accepted event followed the burst

    def summary(self) -> str:
        tag = "COMPROMISE SUSPECTED" if self.compromised else "brute-force attempt"
        return (
            f"[{tag}] {self.ip}: {self.failed_attempts} failed attempts "
            f"({', '.join(sorted(set(self.users_tried))[:5])}) "
            f"between {self.first_seen} and {self.last_seen}"
        )


def detect_brute_force(
    events: Iterable[AuthEvent],
    threshold: int = 5,
    window_minutes: int = 10,
) -> List[BruteForceAlert]:
    """Group auth events by IP and flag bursts of failed logins.

    This is a simple sliding-window count, not a full time-series
    analysis — good enough for log-file-sized inputs and easy to reason
    about / explain in an interview.
    """
    events = sorted(events, key=lambda e: e.timestamp)
    by_ip: dict[str, List[AuthEvent]] = defaultdict(list)
    for e in events:
        by_ip[e.ip].append(e)

    alerts: List[BruteForceAlert] = []
    window = timedelta(minutes=window_minutes)

    for ip, ip_events in by_ip.items():
        failed = [e for e in ip_events if not e.success]
        if len(failed) < threshold:
            continue

        # Slide a window across the failed attempts for this IP.
        start = 0
        for end in range(len(failed)):
            while failed[end].timestamp - failed[start].timestamp > window:
                start += 1
            count = end - start + 1
            if count >= threshold:
                burst = failed[start : end + 1]
                # Was there a successful login for this IP after the burst?
                compromised = any(
                    e.success and e.timestamp >= burst[-1].timestamp for e in ip_events
                )
                alerts.append(
                    BruteForceAlert(
                        ip=ip,
                        failed_attempts=count,
                        users_tried=[e.user for e in burst],
                        first_seen=burst[0].timestamp,
                        last_seen=burst[-1].timestamp,
                        compromised=compromised,
                    )
                )
                break  # one alert per IP is enough for a report

    return alerts
