import json
from datetime import datetime, timezone

from honeysiem.parsers import detect_format, parse_authlog, parse_cowrie, parse_file


def cowrie(eventid, **fields):
    base = {"eventid": eventid, "timestamp": "2026-10-20T13:45:12.123456Z",
            "src_ip": "198.51.100.7", "session": "abc123"}
    return json.dumps({**base, **fields})


def test_cowrie_maps_event_types():
    lines = [
        cowrie("cowrie.session.connect", src_port=50000),
        cowrie("cowrie.login.failed", username="root", password="123456"),
        cowrie("cowrie.login.success", username="root", password="admin"),
        cowrie("cowrie.command.input", input="uname -a"),
        cowrie("cowrie.session.file_download", url="http://x.example/a"),
        cowrie("cowrie.session.closed"),
        cowrie("cowrie.client.version", version="SSH-2.0-Go"),  # ignored
    ]
    events = list(parse_cowrie(lines))
    assert [e.event_type for e in events] == [
        "connect", "login_failed", "login_success", "command", "download", "disconnect"]
    assert events[0].src_port == 50000
    assert events[1].username == "root" and events[1].password == "123456"
    assert events[3].command == "uname -a"
    assert events[4].url == "http://x.example/a"
    assert events[0].timestamp == datetime(2026, 10, 20, 13, 45, 12, 123456, tzinfo=timezone.utc)


def test_cowrie_skips_malformed_lines():
    lines = ["not json", "", '{"eventid": "cowrie.login.failed"}',
             cowrie("cowrie.login.failed", username="admin", password="x")]
    events = list(parse_cowrie(lines))
    assert len(events) == 1 and events[0].username == "admin"


def test_cowrie_numeric_password_kept_as_string():
    events = list(parse_cowrie([cowrie("cowrie.login.failed", username="root", password=1234)]))
    assert events[0].password == "1234"


def test_authlog_classic_syslog():
    lines = [
        "Oct 20 13:45:12 web sshd[812]: Failed password for invalid user oracle from 203.0.113.9 port 51234 ssh2",
        "Oct 20 13:45:15 web sshd[812]: Failed password for root from 203.0.113.9 port 51235 ssh2",
        "Oct  3 08:01:02 web sshd[900]: Accepted publickey for deploy from 192.0.2.4 port 40000 ssh2",
        "Oct 20 13:45:16 web sshd[812]: Invalid user oracle from 203.0.113.9 port 51234",  # not double counted
        "Oct 20 13:45:16 web CRON[1]: pam_unix(cron:session): session opened",
    ]
    events = list(parse_authlog(lines, year=2026))
    assert [(e.event_type, e.username, e.src_ip) for e in events] == [
        ("login_failed", "oracle", "203.0.113.9"),
        ("login_failed", "root", "203.0.113.9"),
        ("login_success", "deploy", "192.0.2.4"),
    ]
    assert events[2].timestamp == datetime(2026, 10, 3, 8, 1, 2, tzinfo=timezone.utc)


def test_authlog_iso_timestamps_and_ipv6():
    line = ("2026-10-20T13:45:12.000000+02:00 web sshd-session[5]: Failed password for root "
            "from 2001:db8::1 port 4242 ssh2")
    (event,) = parse_authlog([line])
    assert event.src_ip == "2001:db8::1"
    assert event.timestamp == datetime(2026, 10, 20, 11, 45, 12, tzinfo=timezone.utc)


def test_format_detection_and_parse_file(tmp_path):
    assert detect_format('{"eventid": 1}') == "cowrie"
    assert detect_format("Oct 20 13:45:12 host sshd[1]: ...") == "authlog"
    path = tmp_path / "cowrie.json"
    path.write_text(cowrie("cowrie.login.failed", username="a", password="b") + "\n")
    assert parse_file(str(path))[0].source == "cowrie"
