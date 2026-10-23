"""Build dashboard statistics and render them into a self-contained HTML report.

Usernames, passwords and commands are attacker-controlled. The report therefore
embeds data as escaped JSON and the page renders it with textContent only, so a
username like ``<script>`` can never execute in the analyst's browser.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from importlib import resources

from .detections import TACTIC_ORDER, TECHNIQUES
from .models import SEVERITY_ORDER, Alert, Event


def _top(counter: Counter, n: int = 10, key: str = "value") -> list[dict]:
    return [{key: k, "count": c} for k, c in counter.most_common(n)]


def _timeline(events: Sequence[Event]) -> dict:
    auth = [e for e in events if e.event_type in ("login_failed", "login_success")]
    if not auth:
        return {"bucket": "hour", "points": []}
    span = auth[-1].timestamp - auth[0].timestamp
    hourly = span <= timedelta(days=14)
    step = timedelta(hours=1) if hourly else timedelta(days=1)

    def bucket(ts: datetime) -> datetime:
        return ts.replace(minute=0, second=0, microsecond=0) if hourly else \
            ts.replace(hour=0, minute=0, second=0, microsecond=0)

    counts: dict[datetime, Counter] = defaultdict(Counter)
    for e in auth:
        counts[bucket(e.timestamp)][e.event_type] += 1
    points, t, end = [], bucket(auth[0].timestamp), bucket(auth[-1].timestamp)
    while t <= end:
        c = counts.get(t, Counter())
        points.append({"t": t.isoformat(), "failed": c["login_failed"],
                       "success": c["login_success"]})
        t += step
    return {"bucket": "hour" if hourly else "day", "points": points}


def build_summary(events: Sequence[Event], alerts: Sequence[Alert]) -> dict:
    events = sorted(events, key=lambda e: e.timestamp)
    by_type = Counter(e.event_type for e in events)
    failed = [e for e in events if e.event_type == "login_failed"]
    success = [e for e in events if e.event_type == "login_success"]
    auth = failed + success

    attempts_per_ip = Counter(e.src_ip for e in auth)
    success_per_ip = Counter(e.src_ip for e in success)
    alerts_per_ip = Counter(a.src_ip for a in alerts)
    worst_per_ip: dict[str, str] = {}
    for a in alerts:
        cur = worst_per_ip.get(a.src_ip)
        if cur is None or SEVERITY_ORDER[a.severity] < SEVERITY_ORDER[cur]:
            worst_per_ip[a.src_ip] = a.severity

    top_ips = [
        {"ip": ip, "attempts": n, "successes": success_per_ip[ip],
         "alerts": alerts_per_ip[ip], "worst": worst_per_ip.get(ip)}
        for ip, n in attempts_per_ip.most_common(10)
    ]

    tech_alerts: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        tech_alerts[a.technique.id].append(a)
    techniques = [
        {"id": t.id, "name": t.name, "tactic": t.tactic, "url": t.url,
         "alerts": len(tech_alerts[t.id]), "ips": len({a.src_ip for a in tech_alerts[t.id]})}
        for t in sorted(TECHNIQUES.values(), key=lambda t: (TACTIC_ORDER.index(t.tactic), t.id))
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "period": {
            "start": events[0].timestamp.isoformat() if events else None,
            "end": events[-1].timestamp.isoformat() if events else None,
        },
        "totals": {
            "events": len(events),
            "unique_ips": len({e.src_ip for e in events}),
            "sessions": len({e.session for e in events if e.session}),
            "login_failed": by_type["login_failed"],
            "login_success": by_type["login_success"],
            "commands": by_type["command"],
            "downloads": by_type["download"],
            "alerts": len(alerts),
        },
        "severity": {s: sum(a.severity == s for a in alerts) for s in SEVERITY_ORDER},
        "timeline": _timeline(events),
        "top_ips": top_ips,
        "top_usernames": _top(Counter(e.username for e in auth if e.username)),
        "top_passwords": _top(Counter(e.password for e in auth if e.password is not None)),
        "top_credentials": _top(Counter(f"{e.username}:{e.password}" for e in auth
                                        if e.username and e.password is not None)),
        "top_commands": _top(Counter(e.command for e in events
                                     if e.event_type == "command" and e.command), 15),
        "tactics": list(TACTIC_ORDER),
        "techniques": techniques,
        "alerts": [a.to_dict() for a in alerts],
    }


def _safe_json(data: dict) -> str:
    """JSON that is safe to place inside a <script> element."""
    return (json.dumps(data, ensure_ascii=False)
            .replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def render_html(summary: dict, title: str = "HoneySIEM Threat Report") -> str:
    template = resources.files("honeysiem").joinpath("templates/dashboard.html").read_text("utf-8")
    title = title.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return template.replace("{{TITLE}}", title).replace("{{DATA}}", _safe_json(summary))


def write_report(path: str, events: Sequence[Event], alerts: Sequence[Alert],
                 title: str = "HoneySIEM Threat Report") -> dict:
    summary = build_summary(events, alerts)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render_html(summary, title))
    return summary
