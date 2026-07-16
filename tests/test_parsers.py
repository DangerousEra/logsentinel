from pathlib import Path

from logsentinel.parsers import parse_auth_log, parse_web_log

SAMPLE_DIR = Path(__file__).parent / "sample_logs"


def test_parse_auth_log_counts_events():
    events = list(parse_auth_log(SAMPLE_DIR / "auth.log"))
    assert len(events) == 9
    assert events[0].status == "Failed"
    assert events[0].ip == "198.51.100.23"


def test_parse_auth_log_success_flag():
    events = list(parse_auth_log(SAMPLE_DIR / "auth.log"))
    accepted = [e for e in events if e.success]
    assert len(accepted) == 2


def test_parse_web_log_counts_events():
    events = list(parse_web_log(SAMPLE_DIR / "access.log"))
    assert len(events) == 10
    assert events[0].method == "GET"
    assert events[0].status == 200
