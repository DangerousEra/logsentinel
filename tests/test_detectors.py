from pathlib import Path

from logsentinel.detectors import detect_brute_force, detect_web_attacks
from logsentinel.parsers import parse_auth_log, parse_web_log

SAMPLE_DIR = Path(__file__).parent / "sample_logs"


def test_detect_brute_force_flags_burst_ip():
    events = list(parse_auth_log(SAMPLE_DIR / "auth.log"))
    alerts = detect_brute_force(events, threshold=5, window_minutes=10)
    assert len(alerts) == 1
    assert alerts[0].ip == "198.51.100.23"
    assert alerts[0].compromised is True  # followed by an Accepted event


def test_detect_brute_force_ignores_low_volume_ip():
    events = list(parse_auth_log(SAMPLE_DIR / "auth.log"))
    alerts = detect_brute_force(events, threshold=5)
    ips_flagged = {a.ip for a in alerts}
    assert "192.0.2.44" not in ips_flagged  # only 1 failed attempt


def test_detect_web_attacks_finds_sqli_and_xss():
    events = list(parse_web_log(SAMPLE_DIR / "access.log"))
    alerts = detect_web_attacks(events)
    kinds = {a.kind for a in alerts}
    assert "SQL Injection" in kinds
    assert "XSS" in kinds


def test_detect_web_attacks_finds_scanner_ua():
    events = list(parse_web_log(SAMPLE_DIR / "access.log"))
    alerts = detect_web_attacks(events)
    scanner_alerts = [a for a in alerts if a.kind == "Known Scanner"]
    assert len(scanner_alerts) == 1
    assert scanner_alerts[0].ip == "192.0.2.77"


def test_detect_web_attacks_recon_threshold():
    events = list(parse_web_log(SAMPLE_DIR / "access.log"))
    alerts = detect_web_attacks(events, recon_threshold=5)
    recon_alerts = [a for a in alerts if a.kind == "Recon / Endpoint Brute-Force"]
    assert len(recon_alerts) == 1
    assert recon_alerts[0].ip == "203.0.113.99"
