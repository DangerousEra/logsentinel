"""LogSentinel CLI.

Usage:
    logsentinel analyze --type auth --file /var/log/auth.log
    logsentinel analyze --type web  --file access.log --json
"""
from __future__ import annotations

import argparse
import sys

from .detectors import detect_brute_force, detect_web_attacks
from .parsers import parse_auth_log, parse_web_log
from .report import to_json, to_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logsentinel",
        description="Lightweight log analysis and threat-detection toolkit.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze a log file for suspicious activity")
    analyze.add_argument("--file", required=True, help="Path to the log file")
    analyze.add_argument(
        "--type",
        required=True,
        choices=["auth", "web"],
        help="Log type: 'auth' for SSH/auth.log, 'web' for Apache/Nginx access logs",
    )
    analyze.add_argument(
        "--threshold",
        type=int,
        default=None,
        help="Failed-attempt threshold for brute-force detection (auth logs, default 5) "
        "or 4xx-count threshold for recon detection (web logs, default 15)",
    )
    analyze.add_argument("--json", action="store_true", help="Output machine-readable JSON instead of text")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        if args.type == "auth":
            events = list(parse_auth_log(args.file))
            threshold = args.threshold or 5
            alerts = detect_brute_force(events, threshold=threshold)
            title = "SSH Brute-Force Analysis"
        else:
            events = list(parse_web_log(args.file))
            threshold = args.threshold or 15
            alerts = detect_web_attacks(events, recon_threshold=threshold)
            title = "Web Attack Analysis"

        output = to_json(alerts) if args.json else to_text(alerts, title)
        print(output)
        return 1 if alerts else 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
