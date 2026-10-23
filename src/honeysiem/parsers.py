"""Parsers that turn raw honeypot / sshd logs into normalized Events.

Supported sources:
  * Cowrie SSH honeypot JSON logs (one JSON object per line)
  * OpenSSH ``auth.log`` / ``secure`` lines, in classic syslog or ISO-8601 format
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone

from .models import Event

log = logging.getLogger(__name__)

COWRIE_EVENT_MAP = {
    "cowrie.session.connect": "connect",
    "cowrie.login.failed": "login_failed",
    "cowrie.login.success": "login_success",
    "cowrie.command.input": "command",
    "cowrie.command.failed": "command",
    "cowrie.session.file_download": "download",
    "cowrie.session.file_upload": "download",
    "cowrie.session.closed": "disconnect",
}


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp and normalize it to UTC."""
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _opt_str(value) -> str | None:
    return None if value is None else str(value)


def parse_cowrie(lines: Iterable[str]) -> Iterator[Event]:
    """Parse Cowrie JSON lines. Malformed or irrelevant lines are skipped."""
    for lineno, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            event_type = COWRIE_EVENT_MAP.get(record.get("eventid", ""))
            if event_type is None:
                continue
            port = record.get("src_port")
            yield Event(
                timestamp=parse_timestamp(record["timestamp"]),
                src_ip=str(record["src_ip"]),
                event_type=event_type,
                src_port=int(port) if port is not None else None,
                username=_opt_str(record.get("username")),
                password=_opt_str(record.get("password")),
                command=_opt_str(record.get("input")),
                url=_opt_str(record.get("url")),
                session=_opt_str(record.get("session")),
                source="cowrie",
            )
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            log.warning("skipping malformed cowrie line %d: %s", lineno, exc)


_MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}

_PREFIX = (
    r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}T\S+)"
    r"|(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}))"
    r"\s+\S+\s+sshd(?:-session)?\[\d+\]:\s+"
)
_FAILED = re.compile(
    _PREFIX + r"Failed (?:password|publickey|keyboard-interactive/pam) for "
    r"(?:invalid user )?(?P<user>\S*) from (?P<ip>[0-9a-fA-F.:]+) port (?P<port>\d+)"
)
_ACCEPTED = re.compile(
    _PREFIX + r"Accepted (?:password|publickey|keyboard-interactive/pam) for "
    r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F.:]+) port (?P<port>\d+)"
)


def _syslog_time(match: re.Match, year: int) -> datetime:
    if match["iso"]:
        return parse_timestamp(match["iso"])
    hour, minute, second = (int(x) for x in match["time"].split(":"))
    return datetime(year, _MONTHS[match["month"]], int(match["day"]),
                    hour, minute, second, tzinfo=timezone.utc)


def parse_authlog(lines: Iterable[str], year: int | None = None) -> Iterator[Event]:
    """Parse OpenSSH auth.log lines.

    Classic syslog lines carry no year, so ``year`` (default: current UTC year) is used.
    Timestamps without a timezone are assumed to be UTC.
    """
    year = year or datetime.now(timezone.utc).year
    for line in lines:
        for pattern, event_type in ((_FAILED, "login_failed"), (_ACCEPTED, "login_success")):
            match = pattern.search(line)
            if match:
                yield Event(
                    timestamp=_syslog_time(match, year),
                    src_ip=match["ip"],
                    event_type=event_type,
                    src_port=int(match["port"]),
                    username=match["user"] or None,
                    source="authlog",
                )
                break


def detect_format(first_line: str) -> str:
    return "cowrie" if first_line.lstrip().startswith("{") else "authlog"


def parse_file(path: str, fmt: str = "auto", year: int | None = None) -> list[Event]:
    """Parse a log file, auto-detecting its format unless ``fmt`` is given."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    if fmt == "auto":
        first = next((ln for ln in lines if ln.strip()), "")
        fmt = detect_format(first)
    if fmt == "cowrie":
        return list(parse_cowrie(lines))
    if fmt == "authlog":
        return list(parse_authlog(lines, year=year))
    raise ValueError(f"unknown log format: {fmt}")
