"""Command-line interface: ``honeysiem <command>`` or ``python -m honeysiem <command>``."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import timedelta

from . import __version__
from .detections import DetectionConfig, run_all
from .models import SEVERITY_ORDER
from .parsers import parse_file
from .report import write_report
from .sample import write_sample
from .store import EventStore

SEV_COLORS = {"critical": "\033[91m", "high": "\033[33m", "medium": "\033[93m", "low": "\033[94m"}


def _config(args) -> DetectionConfig:
    return DetectionConfig(
        brute_force_threshold=args.threshold,
        brute_force_window=timedelta(minutes=args.window),
    )


def _print_alerts(alerts, min_severity: str) -> None:
    color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    limit = SEVERITY_ORDER[min_severity]
    shown = [a for a in alerts if SEVERITY_ORDER[a.severity] <= limit]
    for a in shown:
        sev = a.severity.upper().ljust(8)
        if color:
            sev = SEV_COLORS[a.severity] + sev + "\033[0m"
        print(f"{sev} {a.rule_id:<11} {a.technique.id:<10} {a.src_ip:<16} {a.title} (x{a.count})")
        for line in a.evidence[:2]:
            print(f"{'':>39}- {line}")
    print(f"\n{len(shown)} alert(s) at or above '{min_severity}' ({len(alerts)} total)")


def cmd_sample(args) -> int:
    n = write_sample(args.out, seed=args.seed, days=args.days)
    print(f"wrote {n} synthetic Cowrie events to {args.out}")
    return 0


def cmd_ingest(args) -> int:
    with EventStore(args.db) as store:
        for path in args.files:
            events = parse_file(path, fmt=args.format, year=args.year)
            added = store.add(events)
            print(f"{path}: parsed {len(events)} events, {added} new")
        print(f"{args.db}: {store.count()} events total")
    return 0


def cmd_detect(args) -> int:
    with EventStore(args.db) as store:
        alerts = run_all(store.events(), _config(args))
    if args.json:
        json.dump([a.to_dict() for a in alerts], sys.stdout, indent=2)
        print()
    else:
        _print_alerts(alerts, args.min_severity)
    return 0


def cmd_report(args) -> int:
    with EventStore(args.db) as store:
        events = store.events()
    alerts = run_all(events, _config(args))
    write_report(args.out, events, alerts)
    print(f"wrote dashboard with {len(alerts)} alert(s) to {args.out}")
    return 0


def cmd_demo(args) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "cowrie.json")
        write_sample(log_path, seed=args.seed, days=args.days)
        with EventStore(os.path.join(tmp, "demo.db")) as store:
            store.add(parse_file(log_path, fmt="cowrie"))
            events = store.events()
    alerts = run_all(events, _config(args))
    _print_alerts(alerts, "high")
    write_report(args.out, events, alerts, title="HoneySIEM Threat Report (demo data)")
    print(f"dashboard: {args.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="honeysiem",
        description="Mini-SIEM for SSH honeypots: ingest logs, detect attacks (MITRE ATT&CK), report.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def detection_opts(sp):
        sp.add_argument("--threshold", type=int, default=10,
                        help="failed logins that count as brute force (default: 10)")
        sp.add_argument("--window", type=int, default=5,
                        help="brute-force window in minutes (default: 5)")

    sp = sub.add_parser("sample", help="generate synthetic Cowrie logs")
    sp.add_argument("-o", "--out", default="sample-cowrie.json")
    sp.add_argument("--days", type=int, default=7)
    sp.add_argument("--seed", type=int, default=42)
    sp.set_defaults(func=cmd_sample)

    sp = sub.add_parser("ingest", help="parse log files into the event database")
    sp.add_argument("files", nargs="+")
    sp.add_argument("--db", default="honeysiem.db")
    sp.add_argument("--format", choices=("auto", "cowrie", "authlog"), default="auto")
    sp.add_argument("--year", type=int, help="year for syslog lines without one")
    sp.set_defaults(func=cmd_ingest)

    sp = sub.add_parser("detect", help="run detections and print alerts")
    sp.add_argument("--db", default="honeysiem.db")
    sp.add_argument("--json", action="store_true", help="output alerts as JSON")
    sp.add_argument("--min-severity", choices=tuple(SEVERITY_ORDER), default="low")
    detection_opts(sp)
    sp.set_defaults(func=cmd_detect)

    sp = sub.add_parser("report", help="write the HTML dashboard")
    sp.add_argument("--db", default="honeysiem.db")
    sp.add_argument("-o", "--out", default="report.html")
    detection_opts(sp)
    sp.set_defaults(func=cmd_report)

    sp = sub.add_parser("demo", help="run the whole pipeline on synthetic data")
    sp.add_argument("-o", "--out", default="report.html")
    sp.add_argument("--days", type=int, default=7)
    sp.add_argument("--seed", type=int, default=42)
    detection_opts(sp)
    sp.set_defaults(func=cmd_demo)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
