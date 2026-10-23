"""Detection rules mapped to MITRE ATT&CK.

Every rule takes the full, time-ordered event list and returns Alerts aggregated
per (rule, source IP), so one noisy attacker produces one alert, not thousands.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import timedelta

from .models import SEVERITY_ORDER, Alert, Event, Technique

TECHNIQUES = {
    t.id: t
    for t in (
        Technique("T1110.001", "Brute Force: Password Guessing", "Credential Access"),
        Technique("T1110.003", "Brute Force: Password Spraying", "Credential Access"),
        Technique("T1078", "Valid Accounts", "Initial Access"),
        Technique("T1105", "Ingress Tool Transfer", "Command and Control"),
        Technique("T1082", "System Information Discovery", "Discovery"),
        Technique("T1087.001", "Account Discovery: Local Account", "Discovery"),
        Technique("T1098.004", "Account Manipulation: SSH Authorized Keys", "Persistence"),
        Technique("T1053.003", "Scheduled Task/Job: Cron", "Persistence"),
        Technique("T1222.002", "File and Directory Permissions Modification: Linux", "Defense Evasion"),
        Technique("T1070.003", "Indicator Removal: Clear Command History", "Defense Evasion"),
        Technique("T1496", "Resource Hijacking", "Impact"),
    )
}

# Kill-chain order used by the dashboard.
TACTIC_ORDER = ("Initial Access", "Credential Access", "Discovery", "Persistence",
                "Defense Evasion", "Command and Control", "Impact")


@dataclass(frozen=True)
class DetectionConfig:
    brute_force_threshold: int = 10
    brute_force_window: timedelta = timedelta(minutes=5)
    spray_min_users: int = 5
    compromise_min_failures: int = 3


def _by_ip(events: Sequence[Event], *types: str) -> dict[str, list[Event]]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        if e.event_type in types:
            grouped[e.src_ip].append(e)
    return grouped


def _top(values, n: int = 3) -> str:
    return ", ".join(f"{v!r} x{c}" for v, c in Counter(values).most_common(n))


def detect_brute_force(events: Sequence[Event], cfg: DetectionConfig) -> list[Alert]:
    """Many failed logins from one IP inside a sliding time window."""
    alerts = []
    for ip, fails in _by_ip(events, "login_failed").items():
        peak, start = 0, 0
        for end in range(len(fails)):
            while fails[end].timestamp - fails[start].timestamp > cfg.brute_force_window:
                start += 1
            peak = max(peak, end - start + 1)
        if peak < cfg.brute_force_threshold:
            continue
        minutes = int(cfg.brute_force_window.total_seconds() // 60)
        alerts.append(Alert(
            rule_id="HS-AUTH-001",
            title="SSH brute force",
            severity="high" if len(fails) >= 100 else "medium",
            technique=TECHNIQUES["T1110.001"],
            src_ip=ip,
            first_seen=fails[0].timestamp,
            last_seen=fails[-1].timestamp,
            count=len(fails),
            evidence=[
                f"peak of {peak} failed logins within {minutes} min",
                f"top usernames: {_top(e.username for e in fails)}",
            ],
        ))
    return alerts


def detect_password_spray(events: Sequence[Event], cfg: DetectionConfig) -> list[Alert]:
    """One IP trying the same password against many different accounts."""
    alerts = []
    for ip, fails in _by_ip(events, "login_failed").items():
        users_per_pw: dict[str, set[str]] = defaultdict(set)
        for e in fails:
            if e.password is not None and e.username:
                users_per_pw[e.password].add(e.username)
        sprayed = {pw: users for pw, users in users_per_pw.items()
                   if len(users) >= cfg.spray_min_users}
        if not sprayed:
            continue
        alerts.append(Alert(
            rule_id="HS-AUTH-002",
            title="Password spraying",
            severity="medium",
            technique=TECHNIQUES["T1110.003"],
            src_ip=ip,
            first_seen=fails[0].timestamp,
            last_seen=fails[-1].timestamp,
            count=sum(len(u) for u in sprayed.values()),
            evidence=[f"password {pw!r} tried against {len(users)} accounts"
                      for pw, users in sorted(sprayed.items(), key=lambda kv: -len(kv[1]))[:3]],
        ))
    return alerts


def detect_compromise(events: Sequence[Event], cfg: DetectionConfig) -> list[Alert]:
    """A successful login from an IP that had already failed several times."""
    alerts = []
    for ip, auth in _by_ip(events, "login_failed", "login_success").items():
        failures = 0
        for e in auth:
            if e.event_type == "login_failed":
                failures += 1
            elif failures >= cfg.compromise_min_failures:
                alerts.append(Alert(
                    rule_id="HS-AUTH-003",
                    title="Successful login after repeated failures",
                    severity="critical",
                    technique=TECHNIQUES["T1078"],
                    src_ip=ip,
                    first_seen=auth[0].timestamp,
                    last_seen=e.timestamp,
                    count=failures + 1,
                    evidence=[f"logged in as {e.username!r} after {failures} failed attempts"],
                ))
                break
    return alerts


@dataclass(frozen=True)
class CommandRule:
    rule_id: str
    title: str
    severity: str
    technique_id: str
    pattern: re.Pattern


COMMAND_RULES = (
    CommandRule("HS-CMD-001", "Tool or malware download", "high", "T1105",
                re.compile(r"\b(?:wget|curl|tftp|ftpget)\b", re.I)),
    CommandRule("HS-CMD-002", "System information discovery", "low", "T1082",
                re.compile(r"\buname\b|/proc/cpuinfo|\blscpu\b|\bnproc\b|\bfree\s+-[mgh]\b"
                           r"|/etc/(?:os-release|issue)\b")),
    CommandRule("HS-CMD-003", "Local account discovery", "low", "T1087.001",
                re.compile(r"\bwhoami\b|^\s*id\s*$|/etc/(?:passwd|shadow)\b|\blastlog\b")),
    CommandRule("HS-CMD-004", "SSH authorized_keys persistence", "critical", "T1098.004",
                re.compile(r"authorized_keys")),
    CommandRule("HS-CMD-005", "Cron persistence", "high", "T1053.003",
                re.compile(r"\bcrontab\b|/etc/cron")),
    CommandRule("HS-CMD-006", "Downloaded file made executable", "medium", "T1222.002",
                re.compile(r"\bchmod\s+(?:\+x|[0-7]*[1357][0-7]{0,2})\b")),
    CommandRule("HS-CMD-007", "Command history cleared", "medium", "T1070.003",
                re.compile(r"history\s+-c|unset\s+HISTFILE|HISTFILE=/dev/null"
                           r"|\brm\b[^;|&]*\.bash_history")),
    CommandRule("HS-CMD-008", "Cryptominer activity", "critical", "T1496",
                re.compile(r"xmrig|stratum\+(?:tcp|ssl)://|\bminerd\b|\bcpuminer\b", re.I)),
)


def detect_commands(events: Sequence[Event], cfg: DetectionConfig) -> list[Alert]:
    """Match post-login shell commands against known attacker behaviour."""
    hits: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in events:
        if e.event_type != "command" or not e.command:
            continue
        for rule in COMMAND_RULES:
            if rule.pattern.search(e.command):
                hits[(rule.rule_id, e.src_ip)].append(e)
    rules = {r.rule_id: r for r in COMMAND_RULES}
    alerts = []
    for (rule_id, ip), matched in hits.items():
        rule = rules[rule_id]
        unique_cmds = list(dict.fromkeys(e.command[:200] for e in matched))
        alerts.append(Alert(
            rule_id=rule.rule_id,
            title=rule.title,
            severity=rule.severity,
            technique=TECHNIQUES[rule.technique_id],
            src_ip=ip,
            first_seen=matched[0].timestamp,
            last_seen=matched[-1].timestamp,
            count=len(matched),
            evidence=unique_cmds[:5],
        ))
    return alerts


def detect_downloads(events: Sequence[Event], cfg: DetectionConfig) -> list[Alert]:
    """Files the honeypot actually captured (Cowrie file_download events)."""
    alerts = []
    for ip, dls in _by_ip(events, "download").items():
        alerts.append(Alert(
            rule_id="HS-DL-001",
            title="Payload captured by honeypot",
            severity="high",
            technique=TECHNIQUES["T1105"],
            src_ip=ip,
            first_seen=dls[0].timestamp,
            last_seen=dls[-1].timestamp,
            count=len(dls),
            evidence=list(dict.fromkeys(e.url or "(unknown url)" for e in dls))[:5],
        ))
    return alerts


RULES: tuple[Callable[[Sequence[Event], DetectionConfig], list[Alert]], ...] = (
    detect_brute_force,
    detect_password_spray,
    detect_compromise,
    detect_commands,
    detect_downloads,
)


def run_all(events: Sequence[Event], cfg: DetectionConfig | None = None) -> list[Alert]:
    """Run every rule. Results are sorted by severity, then time."""
    cfg = cfg or DetectionConfig()
    events = sorted(events, key=lambda e: e.timestamp)
    alerts = [a for rule in RULES for a in rule(events, cfg)]
    alerts.sort(key=lambda a: (SEVERITY_ORDER[a.severity], a.first_seen, a.src_ip))
    return alerts
