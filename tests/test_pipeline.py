import json
from datetime import datetime, timezone

from honeysiem.cli import main
from honeysiem.detections import COMMAND_RULES, run_all
from honeysiem.report import build_summary, render_html
from honeysiem.sample import generate
from honeysiem.store import EventStore

from conftest import ev

START = datetime(2026, 10, 1, tzinfo=timezone.utc)


def test_store_roundtrip_and_dedupe(tmp_path):
    events = [ev("login_failed", i, username="root", password="x") for i in range(5)]
    with EventStore(str(tmp_path / "t.db")) as store:
        assert store.add(events) == 5
        assert store.add(events) == 0  # idempotent re-ingest
        assert store.events() == events


def test_sample_is_deterministic():
    assert generate(seed=1, start=START) == generate(seed=1, start=START)
    assert generate(seed=1, start=START) != generate(seed=2, start=START)


def test_sample_data_triggers_every_rule(tmp_path):
    path = tmp_path / "cowrie.json"
    path.write_text("\n".join(json.dumps(r) for r in generate(seed=7, start=START)))
    db = str(tmp_path / "t.db")
    assert main(["ingest", str(path), "--db", db]) == 0
    with EventStore(db) as store:
        alerts = run_all(store.events())
    fired = {a.rule_id for a in alerts}
    expected = {"HS-AUTH-001", "HS-AUTH-002", "HS-AUTH-003", "HS-DL-001"}
    expected |= {r.rule_id for r in COMMAND_RULES}
    assert expected <= fired


def test_report_escapes_attacker_input():
    payload = "</script><script>alert(1)</script>"
    events = [ev("login_failed", i, username=payload, password="<img src=x onerror=alert(1)>")
              for i in range(12)]
    events.append(ev("command", 100, command=payload))
    html = render_html(build_summary(events, run_all(events)), title="<b>t</b>")
    assert payload not in html
    assert "<img src=x" not in html
    assert "<b>t</b>" not in html
    assert "\\u003c/script\\u003e" in html  # data survives, safely encoded


def test_cli_demo_writes_report(tmp_path, capsys):
    out = tmp_path / "report.html"
    assert main(["demo", "-o", str(out), "--seed", "3"]) == 0
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert "CRITICAL" in capsys.readouterr().out
