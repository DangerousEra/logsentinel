# LogSentinel

A lightweight, dependency-free log analysis and threat-detection toolkit written in Python. Point it at an SSH auth log or a web server access log and it flags brute-force attempts, injection payloads, known scanner tools, and endpoint-recon bursts.

Built as a companion to [NetScan](#) (a TCP port scanner) — where NetScan looks outward at open ports, LogSentinel looks inward at what already hit your logs.

## Why

Most "log analyzer" tutorials just `grep` for a keyword. LogSentinel instead:
- Parses logs into typed, structured records (`AuthEvent`, `WebEvent`) instead of working with raw strings
- Uses a real sliding-time-window algorithm for brute-force detection, not just a raw count
- Separates parsing, detection, and reporting into independent, testable modules
- Ships with unit tests and sample logs so it runs out of the box — no need to find real logs to try it

## Features

**Auth log analysis** (`--type auth`)
- Parses SSH login attempts from `/var/log/auth.log`-style files
- Detects brute-force bursts: N+ failed logins from one IP within a rolling time window
- Flags "compromise suspected" when a burst is followed by a successful login from the same IP

**Web log analysis** (`--type web`)
- Parses Combined Log Format (Apache/Nginx default)
- Detects SQL injection, XSS, path traversal, and command injection payloads in request paths
- Fingerprints known scanning tools (sqlmap, nikto, nmap, wpscan, etc.) by user agent
- Flags recon/endpoint brute-forcing: one IP generating a high volume of 4xx responses

## Installation

```bash
git clone https://github.com/<your-username>/logsentinel.git
cd logsentinel
pip install -e .
```

No external runtime dependencies — everything runs on the Python standard library.

## Usage

```bash
# Analyze an SSH auth log for brute-force attempts
logsentinel analyze --type auth --file /var/log/auth.log

# Analyze a web access log for attack payloads and scanners
logsentinel analyze --type web --file access.log

# Tune detection sensitivity
logsentinel analyze --type auth --file auth.log --threshold 3

# Machine-readable output for piping into other tools
logsentinel analyze --type web --file access.log --json
```

Try it immediately on the bundled sample logs:

```bash
logsentinel analyze --type auth --file tests/sample_logs/auth.log
logsentinel analyze --type web --file tests/sample_logs/access.log --threshold 5
```

Exit code is `1` if any alerts were found and `0` otherwise, so it drops straight into a CI pipeline or cron job.

## Example output

```
=== SSH Brute-Force Analysis ===
1 alert(s) found

[COMPROMISE SUSPECTED] 198.51.100.23: 5 failed attempts (admin, root, test) between 2026-07-14 03:20:01 and 2026-07-14 03:20:20
```

## Architecture

```
logsentinel/
├── parsers/          # Raw log lines -> structured dataclasses
│   ├── auth_log.py   # AuthEvent (SSH login attempts)
│   └── web_log.py    # WebEvent (Combined Log Format requests)
├── detectors/         # Structured events -> alerts
│   ├── brute_force.py # Sliding-window failed-login detection
│   └── web_attacks.py # Payload signatures, scanner UAs, recon bursts
├── report.py          # Alerts -> text or JSON output
└── cli.py             # argparse entry point
```

Each layer only depends on the one below it, so you can add a new log format (e.g. firewall logs) by writing a new parser, or a new detection rule by writing a new detector — without touching the rest of the codebase.

### How brute-force detection works

Rather than a flat "count failed logins per IP", it's a real sliding time window: failed attempts are sorted by timestamp, and a two-pointer window checks whether any `threshold`-sized cluster fits inside `window_minutes`. This avoids two failure modes of a naive counter — it won't flag an IP with 5 failed logins spread evenly across a week, and it will catch a fast burst even if the IP has other unrelated failed logins scattered before or after it.

## Testing

```bash
pip install -r requirements.txt
pytest tests/ -v
```

## Roadmap / ideas for extension

- [ ] Firewall log parser (iptables/ufw)
- [ ] GeoIP lookup for flagged IPs
- [ ] Slack/email alerting on detection
- [ ] Real-time `tail -f`-style streaming mode

## License

MIT — see [LICENSE](LICENSE).
