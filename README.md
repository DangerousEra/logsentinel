# LogSentinel

A Python CLI I built to dig through server logs and flag suspicious activity — SSH brute-force attempts on auth logs, and attack payloads (SQLi, XSS, scanner traffic) on web access logs.

I built this as a follow-up to [NetScan](#), my TCP port scanner. NetScan looks outward — what ports are open, what's exposed. LogSentinel looks inward — what's already showing up in the logs after the fact. Felt like the natural next piece for a small blue-team-style toolkit.

## Why I built it this way

I didn't want this to just be a script that `grep`s for "Failed password" and calls it a day — I wanted something I could actually explain properly in an interview. So:

- Logs get parsed into proper structured records (`AuthEvent`, `WebEvent`) instead of passing raw strings around everywhere
- Brute-force detection uses an actual sliding time window, not just a flat count — an IP with 5 failed logins spread across a week won't get flagged, but a fast burst will, even if there's unrelated noise before/after it
- Parsing, detection, and reporting are separate modules, so adding a new log type or detection rule doesn't mean touching everything else
- It comes with sample logs and tests, so you can run it and see it work without hunting down real server logs first

## What it does

**Auth logs** (`--type auth`) — reads SSH login attempts from `/var/log/auth.log`-style files, flags IPs with a burst of failed logins in a short window, and calls out "compromise suspected" if a burst is followed by a successful login from that same IP.

**Web logs** (`--type web`) — reads Apache/Nginx Combined Log Format, and checks for:
- SQL injection / XSS / path traversal / command injection patterns in request paths
- known scanner tools showing up in the user-agent (sqlmap, nikto, nmap, wpscan, etc.)
- one IP hammering a bunch of endpoints and getting mostly 404s (recon behavior)

## Install

```bash
git clone https://github.com/DangerousEra/logsentinel.git
cd logsentinel
pip install -e .
```

No external dependencies — it's all standard library.

## Usage

```bash
# check an SSH auth log
logsentinel analyze --type auth --file /var/log/auth.log

# check a web access log
logsentinel analyze --type web --file access.log

# adjust how sensitive it is
logsentinel analyze --type auth --file auth.log --threshold 3

# JSON output if you want to pipe it somewhere else
logsentinel analyze --type web --file access.log --json
```

If you just want to see it work first, it ships with sample logs:

```bash
logsentinel analyze --type auth --file tests/sample_logs/auth.log
logsentinel analyze --type web --file tests/sample_logs/access.log --threshold 5
```

It exits with `1` if it found anything and `0` if the log's clean, so it can slot into a cron job or a CI check.

Sample output:
```
=== SSH Brute-Force Analysis ===
1 alert(s) found

[COMPROMISE SUSPECTED] 198.51.100.23: 5 failed attempts (admin, root, test) between 2026-07-14 03:20:01 and 2026-07-14 03:20:20
```

## How it's structured

```
logsentinel/
├── parsers/           # raw log lines -> structured objects
│   ├── auth_log.py
│   └── web_log.py
├── detectors/          # structured events -> alerts
│   ├── brute_force.py
│   └── web_attacks.py
├── report.py           # alerts -> text or JSON
└── cli.py
```

Each piece only depends on the one below it. Want to add support for firewall logs? Write a new parser. Want a new detection rule? Write a new detector. Nothing else needs to change.

## Running the tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

## Things I'd add if I keep working on this

- Firewall log support (iptables/ufw)
- GeoIP lookups on flagged IPs
- Alerting to Slack/email instead of just console output
- A `tail -f`-style live mode instead of only static files

## License

MIT — see [LICENSE](LICENSE).
